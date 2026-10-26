#!/usr/bin/env python3
"""Stage a batch of harvested third-party skills as one tar for the scanner guest (vm/vm.sh isolate).

The batch is a slice of data/skills.json in a fixed pseudo-random order (sha1 of each skill id), so
consecutive batches are disjoint, each is an unbiased sample, and together they cover the core.

NETWORK for files not yet cached. The harvest fetched only SKILL.md; the scanners also read scripts,
so every file in each skill folder is fetched from raw.githubusercontent.com at the commit the
harvest pinned (no token, the harvest's pacing), checked against the tree's git blob sha, and kept
under ~/.cache/awesome-agent-skills/harvest/<run>/files/. Nothing here opens or runs those files:
they are bytes copied into a tar that is only ever unpacked inside the guest.

Layout, as stage_skills.py: skills/<sid>/<folder name>/... with sid = h__<skill id>, so the folder
keeps the name scanners compare with the frontmatter. Paths come from GitHub trees and are refused
if any part is empty, '.' or '..'. Symlinks stay symlinks (their blob is the target), submodules
are listed and left out, and a skill keeps at most MAX_FILES files and MAX_BYTES bytes, each file at
most MAX_FILE. The manifest (in the tar and beside it) maps each sid to repo, folder and tier.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import sys
import tarfile
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline"))
from harvest import CACHE, RAW, UA, Client, git_blob_sha, slug  # noqa: E402
from skills import skill_dir  # noqa: E402

MAX_FILES, MAX_BYTES, MAX_FILE = 300, 20 * 1024 * 1024, 5 * 1024 * 1024


def order(skills: list[dict]) -> list[dict]:
    return sorted(skills, key=lambda r: hashlib.sha1(r["id"].encode()).hexdigest())


def safe(rel: str) -> bool:
    parts = rel.split("/")
    return bool(rel) and not rel.startswith("/") and all(p not in ("", ".", "..") for p in parts)


def plan(run: Path, rec: dict, repos: dict) -> dict:
    """Which tree entries make up this skill's folder."""
    sha = rec["url"].split("/tree/" if "/tree/" in rec["url"] else "/blob/", 1)[1].split("/", 1)[0]
    rr = repos[(rec["repo"].lower(), sha)]
    tree = json.loads(gzip.decompress((run / "trees" / f"{slug(rr['repo'])}@{sha}.json.gz").read_bytes()))
    d = rec["dir"]
    nested = {skill_dir(s["path"]) for s in rr["skills"]} - {d}
    nested = {n for n in nested if not d or n.startswith(d + "/")}
    entries, skipped = [], []
    for e in tree.get("tree", []):
        p = e["path"]
        if d and not p.startswith(d + "/"):
            continue
        if any(p.startswith(n + "/") for n in nested) or e.get("type") == "tree":
            continue
        rel = p[len(d) + 1:] if d else p
        if not safe(rel):
            skipped.append(f"{rel} (unsafe path)")
        elif e.get("type") == "commit":
            skipped.append(f"{rel} (submodule)")
        elif e.get("size", 0) > MAX_FILE:
            skipped.append(f"{rel} (over {MAX_FILE // 2**20} MB)")
        else:
            entries.append({"path": p, "rel": rel, "blob": e["sha"], "mode": e.get("mode", "100644"),
                            "size": e.get("size", 0)})
    entries.sort(key=lambda x: (x["rel"] != "SKILL.md", x["rel"]))    # SKILL.md first, then by path
    kept, total = [], 0
    for x in entries:
        if len(kept) >= MAX_FILES or total + x["size"] > MAX_BYTES:
            skipped.append(f"{x['rel']} (skill over {MAX_FILES} files or {MAX_BYTES // 2**20} MB)")
            continue
        kept.append(x)
        total += x["size"]
    folder = PurePosixPath(d).name if d else rec["repo"].split("/")[1]
    return {"rec": rec, "repo_seed": rr["repo"], "sha": sha, "folder": folder, "files": kept, "skipped": skipped}


def plugin_plan(run: Path, rr: dict, sha: str, root: str) -> dict:
    """A plugin root as its own scan entry: every file under it that is not inside one of its skill folders
    (hooks/, .mcp.json, .claude-plugin/, settings, commands/, agents/, the scripts hooks call). Installing any
    skill of the plugin installs these too."""
    tree = json.loads(gzip.decompress((run / "trees" / f"{slug(rr['repo'])}@{sha}.json.gz").read_bytes()))
    skill_dirs = {skill_dir(s["path"]) for s in rr["skills"]}
    entries, skipped = [], []
    for e in tree.get("tree", []):
        p = e["path"]
        if (root and not p.startswith(root + "/")) or e.get("type") == "tree":
            continue
        if any(d == "" or p.startswith(d + "/") for d in skill_dirs if (not root or d.startswith(root + "/") or d == root)):
            continue
        rel = p[len(root) + 1:] if root else p
        if not safe(rel):
            skipped.append(f"{rel} (unsafe path)")
        elif e.get("type") == "commit":
            skipped.append(f"{rel} (submodule)")
        elif e.get("size", 0) > MAX_FILE:
            skipped.append(f"{rel} (over {MAX_FILE // 2**20} MB)")
        else:
            entries.append({"path": p, "rel": rel, "blob": e["sha"], "mode": e.get("mode", "100644"), "size": e.get("size", 0)})
    # The files Claude Code acts on first, so the caps cut docs and assets rather than hooks
    first = (".claude-plugin/", "hooks/", ".mcp.json", ".claude/", "settings", "commands/", "agents/", "scripts/")
    entries.sort(key=lambda x: (not x["rel"].startswith(first), x["rel"]))
    kept, total = [], 0
    for x in entries:
        if len(kept) >= MAX_FILES or total + x["size"] > MAX_BYTES:
            skipped.append(f"{x['rel']} (plugin over {MAX_FILES} files or {MAX_BYTES // 2**20} MB)")
            continue
        kept.append(x)
        total += x["size"]
    pid = hashlib.sha1(f"{rr['repo'].lower()}/{root}".encode()).hexdigest()[:12]
    folder = PurePosixPath(root).name if root else rr["repo"].split("/")[1]
    rec = {"id": "plugin-" + pid, "repo": (rr.get("meta") or {}).get("full_name", rr["repo"]), "dir": root, "tier": rr["tier"], "flags": []}
    return {"rec": rec, "repo_seed": rr["repo"], "sha": sha, "folder": folder, "files": kept, "skipped": skipped, "kind": "plugin"}


def plugin_root_of(paths: set[str], d: str) -> str | None:
    parts = PurePosixPath(d).parts if d else ()
    for i in range(len(parts), -1, -1):
        root = "/".join(parts[:i])
        if (f"{root}/" if root else "") + ".claude-plugin/plugin.json" in paths:
            return root
    return None


def fetch(client: Client, store: Path, seed: str, sha: str, f: dict) -> str:
    path = store / f["blob"]
    if path.exists():
        return "cached"
    code, data = client.get(f"https://{RAW}/{seed}/{sha}/{urllib.parse.quote(f['path'])}")
    if code != 200:
        return f"http {code}"
    if git_blob_sha(data) != f["blob"]:
        return "sha mismatch"
    store.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return "fetched"


CODELOAD = "codeload.github.com"
TARBALL_MIN_FILES, TARBALL_MAX_KB = 30, 1_500_000      # worth it for many files; not for 10 GB repos


def fetch_tarball(store: Path, seed: str, sha: str, wanted: dict[str, str]) -> int:
    """Stream the repo's tar.gz at `sha` from codeload (no token, neutral UA) and keep only the wanted
    files: each member's bytes (a symlink's target) must hash to the tree's blob sha, and are stored
    under that sha. Nothing is written by a name taken from the archive. Returns files kept."""
    url = f"https://{CODELOAD}/{seed}/tar.gz/{sha}"
    if urllib.parse.urlsplit(url).hostname != CODELOAD:
        raise ValueError(url)
    kept = 0
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as resp, tarfile.open(fileobj=resp, mode="r|gz") as tar:
        for m in tar:
            path = m.name.split("/", 1)[1] if "/" in m.name else ""
            blob = wanted.get(path)
            if not blob or (store / blob).exists():
                continue
            if m.issym():
                data = m.linkname.encode()
            elif m.isfile() and m.size <= MAX_FILE:
                data = tar.extractfile(m).read()
            else:
                continue
            if git_blob_sha(data) == blob:
                store.mkdir(parents=True, exist_ok=True)
                (store / blob).write_bytes(data)
                kept += 1
    return kept


def ss_cost(files: int, nbytes: int) -> float:
    """SkillSpector seconds for one skill inside a --recursive run: the per-skill fit
    (3.10 + 0.033*files + 0.0559*KB, 313 skills, mean abs error 1.3 s) less its ~2.7 s start-up."""
    return 0.4 + 0.033 * files + 0.0559 * nbytes / 1024


TOOL_CHUNKS = {   # tool: (max skills per chunk, start-up s, s per skill or None for the SkillSpector fit)
    "skillspector": (25, 2.7, None),       # --recursive details at most 30 skills per run
    "cisco-behavioral": (150, 5.0, 0.25),
    "sentry": (300, 0.5, 0.15),
    "agnix": (300, 0.5, 0.05),
    "aid": (300, 0.5, 0.02),               # second set: first guesses, refit from runs.tsv
    "skills-ref": (300, 0.5, 0.25),        # a loop: one interpreter start per skill
    "atr": (150, 2.0, 0.1),
    "bawbel": (150, 1.0, 0.2),
    "inventory": (300, 0.5, 0.05),
    "telemetry": (300, 0.5, 0.05),
    "obfuscation": (300, 0.5, 0.1),
    # second wave: first guesses, refit after the VM and 600-skill runs
    "guarddog": (100, 1.0, 1.5),           # per code-bearing folder ~3 s (semgrep start); most folders skipped
    "bandit": (600, 2.0, 0.05),
    "agentshield": (100, 1.0, 1.5),        # plugin roots only
    "holguard": (100, 1.0, 2.0),           # plugin roots only
    "osv": (2000, 10.0, 0.01),             # loads the offline DB once per call: few, large chunks
    "gitleaks": (1000, 1.0, 0.02),
    "clamav": (2000, 40.0, 0.03),          # ~1 GB of signatures per process: few, large chunks
    "yara": (1000, 15.0, 0.05),            # compiles the core rule set once per call
}
PLUGIN_ONLY = ("agentshield", "holguard")
# Tools that need a SKILL.md: on plugin roots they fail, and SkillSpector crawls (1,153 s on one 300-file
# root in the gate). Plugin roots get the plugin tools and the file-level ones instead.
SKILL_ONLY = ("skillspector", "cisco-behavioral", "atr", "skills-ref")
ALL_TOOLS = tuple(TOOL_CHUNKS)
SS_TARGET = 60.0                           # predicted seconds per SkillSpector chunk


def build_plan(entries: list[dict], tools: tuple = ALL_TOOLS) -> list[dict]:
    """Chunks per tool, each with no folder name twice; SkillSpector chunks balanced by predicted cost
    (heaviest skills first, first fit), the cheap tools by count. scan.py runs the jobs longest first."""
    jobs = []
    for tool, (cap, start, per) in TOOL_CHUNKS.items():
        if tool not in tools:
            continue
        pool = ([e for e in entries if e.get("kind") == "plugin"] if tool in PLUGIN_ONLY
                else [e for e in entries if e.get("kind") != "plugin"] if tool in SKILL_ONLY else entries)
        cost = {e["id"]: (ss_cost(e["files"], e["bytes"]) if per is None else per) for e in pool}
        target = SS_TARGET if per is None else float("inf")
        chunks: list[dict] = []
        for e in sorted(pool, key=lambda e: -cost[e["id"]]):
            c = next((c for c in chunks if e["folder"] not in c["names"] and len(c["names"]) < cap
                      and c["cost"] + cost[e["id"]] <= target), None)
            if c is None:
                c = {"names": {}, "cost": start}
                chunks.append(c)
            c["names"][e["folder"]] = e["id"]
            c["cost"] += cost[e["id"]]
        jobs += [{"tool": tool, "chunk": f"{tool}-{i:04d}", "names": c["names"], "cost": round(c["cost"], 1)}
                 for i, c in enumerate(chunks)]
    return jobs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--start", type=int, required=True, help="first position in the fixed order (0-based)")
    ap.add_argument("--stop", type=int, required=True, help="one past the last position")
    ap.add_argument("--run-sh", type=Path, default=ROOT / "vetter" / "vm" / "guest" / "run.sh")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--harvest", default=None, help="harvest run (default: the one data/skills.json names)")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--skills", type=Path, default=ROOT / "data" / "skills.json", help="parsed core to stage from")
    ap.add_argument("--plugins", action="store_true", help="also stage each plugin root the batch's skills sit in, as p__ entries")
    ap.add_argument("--skip-scanned", action="store_true", help="leave out skills already in data/scans.json")
    ap.add_argument("--tools", default=",".join(ALL_TOOLS),
                    help=f"comma-separated scan.py tools to plan and run (default all: {','.join(ALL_TOOLS)})")
    a = ap.parse_args(argv)
    tools = tuple(t for t in ALL_TOOLS if t in a.tools.split(","))
    if not tools or len(tools) != len(a.tools.split(",")):
        ap.error(f"--tools: choose from {','.join(ALL_TOOLS)}")
    data = json.loads(a.skills.read_text(encoding="utf-8"))
    run = CACHE / (a.harvest or data["run"])
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    repos = {((r.get("meta") or {}).get("full_name", r["repo"]).lower(), r["sha"]): r
             for r in manifest["repos"] if not r.get("error")}
    batch = order(data["skills"])[a.start:a.stop]
    if a.skip_scanned and (ROOT / "data" / "scans.json").exists():
        done = json.loads((ROOT / "data" / "scans.json").read_text(encoding="utf-8"))["skills"]
        batch = [r for r in batch if r["id"] not in done]
    plans = [plan(run, rec, repos) for rec in batch]
    if a.plugins:
        seen = set()
        for p in list(plans):
            rr = repos[(p["rec"]["repo"].lower(), p["sha"])]
            tree = json.loads(gzip.decompress((run / "trees" / f"{slug(rr['repo'])}@{p['sha']}.json.gz").read_bytes()))
            root = plugin_root_of({e["path"] for e in tree.get("tree", [])}, p["rec"]["dir"])
            if root is not None and (rr["repo"], p["sha"], root) not in seen:
                seen.add((rr["repo"], p["sha"], root))
                pp = plugin_plan(run, rr, p["sha"], root)
                if pp["files"]:
                    plans.append(pp)
    store = run / "files"
    client = Client(token=None)                      # raw.githubusercontent.com only: no token
    jobs = {}
    for p in plans:
        for f in p["files"]:
            jobs.setdefault(f["blob"], (p["repo_seed"], p["sha"], f))
    status: dict[str, int] = {}
    by_repo: dict[tuple, dict] = {}
    for blob, (seed, sha, f) in jobs.items():
        if not (store / blob).exists():
            by_repo.setdefault((seed, sha), {})[f["path"]] = blob
    for (seed, sha), wanted in by_repo.items():
        meta = run / "meta" / f"{slug(seed)}.json"
        kb = json.loads(meta.read_text()).get("size", 0) if meta.exists() else 0
        if len(wanted) >= TARBALL_MIN_FILES and kb <= TARBALL_MAX_KB:
            try:
                status["tarball"] = status.get("tarball", 0) + fetch_tarball(store, seed, sha, wanted)
            except (OSError, tarfile.TarError, ValueError) as e:
                print(f"stage: tarball {seed} failed ({type(e).__name__}); raw instead", file=sys.stderr)
    with ThreadPoolExecutor(max_workers=max(1, min(a.workers, 8))) as ex:
        for st in ex.map(lambda j: fetch(client, store, *j), jobs.values()):
            status[st] = status.get(st, 0) + 1
    out_manifest = []
    with tarfile.open(a.out, "w") as tar:
        tar.add(a.run_sh, arcname="run.sh")
        tar.add(a.run_sh.parent / "scan.py", arcname="scan.py")
        tar.add(a.run_sh.parent / "inventory.py", arcname="inventory.py")
        tar.add(a.run_sh.parent / "telemetry.py", arcname="telemetry.py")
        tar.add(a.run_sh.parent / "obfuscation.py", arcname="obfuscation.py")
        for p in plans:
            rec = p["rec"]
            sid = ("p__" + rec["id"][len("plugin-"):]) if p.get("kind") == "plugin" else "h__" + rec["id"]
            entry = {"id": sid, "skill": rec["id"], "kind": p.get("kind", "skill"), "repo": rec["repo"], "dir": rec["dir"], "tier": rec["tier"],
                     "flags": rec["flags"], "files": 0, "bytes": 0, "symlinks": 0, "excluded": list(p["skipped"])}
            for f in p["files"]:
                src = store / f["blob"]
                if not src.exists():
                    entry["excluded"].append(f"{f['rel']} (not fetched)")
                    continue
                data_b = src.read_bytes()
                info = tarfile.TarInfo(f"skills/{sid}/{p['folder']}/{f['rel']}")
                info.uid = info.gid = 0
                info.uname = info.gname = "root"
                if f["mode"] == "120000":
                    info.type, info.linkname, info.mode = tarfile.SYMTYPE, data_b.decode("utf-8", "replace"), 0o777
                    entry["symlinks"] += 1
                    tar.addfile(info)
                    continue
                info.size, info.mode = len(data_b), 0o755 if f["mode"] == "100755" else 0o644
                tar.addfile(info, io.BytesIO(data_b))
                entry["files"] += 1
                entry["bytes"] += len(data_b)
            entry["folder"] = p["folder"]
            out_manifest.append(entry)
        plan_b = json.dumps({"jobs": build_plan([e for e in out_manifest if e["files"] or e["symlinks"]], tools)}).encode()
        info = tarfile.TarInfo("plan.json")
        info.size = len(plan_b)
        tar.addfile(info, io.BytesIO(plan_b))
        tools_b = (" ".join(tools) + "\n").encode()
        info = tarfile.TarInfo("tools.txt")
        info.size = len(tools_b)
        tar.addfile(info, io.BytesIO(tools_b))
        blob = json.dumps(out_manifest, indent=1).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(blob)
        tar.addfile(info, io.BytesIO(blob))
    a.out.with_suffix(".manifest.json").write_bytes(blob)
    print(f"staged positions {a.start}-{a.stop - 1}: {len(out_manifest)} skills, "
          f"{sum(e['files'] for e in out_manifest)} files, {sum(e['bytes'] for e in out_manifest) / 1e6:.1f} MB, "
          f"{sum(len(e['excluded']) for e in out_manifest)} paths excluded; fetch {status} -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
