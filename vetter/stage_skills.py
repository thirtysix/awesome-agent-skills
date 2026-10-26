#!/usr/bin/env python3
"""Stage our own installed skills as one tar for the scanner guest (vm/vm.sh isolate).

Sources: every directory holding a SKILL.md in ClaudeSkills, every entry of ~/.claude/skills (most
are symlinks into ClaudeSkills, so trees are de-duplicated by real path), and the skills synced
from claude.ai under ~/.claude/skills/synced/ (Anthropic's). Origins in the ids: `cs`, `home`,
`synced`. This is the known-good set on which the scanners' false positives are measured. File
contents are hashed, never parsed.

Left out, and listed in the manifest by name only: VCS and cache directories (.git, __pycache__,
node_modules, virtualenvs), .env files, private keys, and files over 5 MB. __pycache__ is a local
artifact of running a skill, not part of it as written. Symlinks inside a skill are stored as
symlinks, never followed, so a scanner sees them as they are. The manifest holds paths relative to
each source root, never absolute ones.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import io
import json
import os
import tarfile
from pathlib import Path

HOME_SKILLS = Path.home() / ".claude" / "skills"
CLAUDE_SKILLS = Path(os.environ.get("AAS_CLAUDE_SKILLS", Path(__file__).resolve().parents[2] / "ClaudeSkills"))
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
SKIP_FILES = (".env", ".env.*", "*.pem", "*.key", "*.p12", "id_rsa*", "id_ed25519*", "id_ecdsa*")
MAX_BYTES = 5 * 1024 * 1024


def skill_dirs() -> list[tuple[str, Path, str]]:
    """(origin, real path, path relative to its root), de-duplicated, ClaudeSkills first."""
    found: list[tuple[str, Path, str]] = []
    seen: set[Path] = set()
    for skill_md in sorted(CLAUDE_SKILLS.rglob("SKILL.md")):
        if ".git" in skill_md.parts:
            continue
        d = skill_md.parent.resolve()
        if d not in seen:
            seen.add(d)
            found.append(("cs", d, str(skill_md.parent.relative_to(CLAUDE_SKILLS))))
    for entry in sorted(HOME_SKILLS.iterdir()):
        d = entry.resolve()
        if d in seen:
            continue
        if (d / "SKILL.md").is_file():
            seen.add(d)
            found.append(("home", d, entry.name))
            continue
        # Skills synced from claude.ai (Anthropic's) sit two levels down, under a directory named
        # by account ids: synced/<ids>/<name>/SKILL.md. Only <name> is recorded, never the ids.
        for skill_md in sorted(d.glob("*/*/SKILL.md")):
            s = skill_md.parent.resolve()
            if s not in seen:
                seen.add(s)
                found.append((entry.name, s, skill_md.parent.name))
    return found


def walk(root: Path):
    """Yield (path, relative path) for every file and symlink, skipping excluded directories."""
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        keep = []
        for name in sorted(dirnames):
            p = here / name
            if p.is_symlink():
                yield p, p.relative_to(root)      # a symlinked directory is kept as a link
            elif name not in SKIP_DIRS:
                keep.append(name)
            else:
                yield None, p.relative_to(root)   # an excluded directory, recorded by name
        dirnames[:] = keep
        for name in sorted(filenames):
            p = here / name
            yield p, p.relative_to(root)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run", type=Path, required=True, help="guest run.sh to put at the tar root")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--tools", default="", help="scan.py tools to run, comma-separated (default all)")
    a = ap.parse_args()

    manifest = []
    ids: set[str] = set()
    with tarfile.open(a.out, "w") as tar:
        tar.add(a.run, arcname="run.sh")
        tar.add(a.run.parent / "scan.py", arcname="scan.py")   # the scheduler run.sh calls
        tar.add(a.run.parent / "inventory.py", arcname="inventory.py")
        tar.add(a.run.parent / "telemetry.py", arcname="telemetry.py")
        tar.add(a.run.parent / "obfuscation.py", arcname="obfuscation.py")
        if a.tools:
            tools_b = (" ".join(a.tools.split(",")) + "\n").encode()
            info = tarfile.TarInfo("tools.txt")
            info.size = len(tools_b)
            tar.addfile(info, io.BytesIO(tools_b))
        for origin, root, rel in skill_dirs():
            sid = f"{origin}__{rel.replace('/', '__')}"
            while sid in ids:
                sid += "_"
            ids.add(sid)
            entry = {"id": sid, "origin": origin, "rel": rel, "files": 0, "bytes": 0,
                     "symlinks": 0, "excluded": []}
            lines = []
            for p, relp in walk(root):
                if p is None:
                    entry["excluded"].append(f"{relp}/")
                    continue
                if not p.is_symlink() and (any(fnmatch.fnmatch(p.name, g) for g in SKIP_FILES)
                                           or p.stat().st_size > MAX_BYTES):
                    entry["excluded"].append(str(relp))
                    continue
                # skills/<id>/<name>/...: the skill keeps the directory name Claude Code sees, since
                # scanners compare it with the frontmatter name (a renamed dir flagged all 77).
                info = tar.gettarinfo(str(p), arcname=f"skills/{sid}/{Path(rel).name}/{relp}")
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                info.mode &= 0o777
                if info.issym():
                    entry["symlinks"] += 1
                    lines.append(f"{relp} -> {info.linkname}")
                    tar.addfile(info)
                elif info.isfile():
                    data = p.read_bytes()
                    entry["files"] += 1
                    entry["bytes"] += len(data)
                    lines.append(f"{relp} {hashlib.sha256(data).hexdigest()}")
                    tar.addfile(info, io.BytesIO(data))
            entry["tree_sha256"] = hashlib.sha256("\n".join(sorted(lines)).encode()).hexdigest()
            manifest.append(entry)
        blob = json.dumps(manifest, indent=1).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(blob)
        tar.addfile(info, io.BytesIO(blob))
    n_ex = sum(len(e["excluded"]) for e in manifest)
    print(f"staged {len(manifest)} skills, {sum(e['files'] for e in manifest)} files, "
          f"{sum(e['bytes'] for e in manifest) / 1e6:.1f} MB, {n_ex} paths excluded -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
