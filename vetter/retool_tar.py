#!/usr/bin/env python3
"""Rewrite a staged tar for another tool set, offline: retool_tar.py IN_TAR OUT_TAR --tools a,b

Keeps every skills/ member and the manifest of IN_TAR byte for byte, and replaces the guest scripts
(run.sh, scan.py and our fact scripts from vetter/vm/guest/), tools.txt and plan.json, so a new
check can run on an already-staged batch without re-fetching anything. Members are copied as tar
records; nothing is extracted or opened.
"""
from __future__ import annotations

import argparse
import io
import json
import sys
import tarfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from stage_harvest import ALL_TOOLS, build_plan  # noqa: E402

GUEST = HERE / "vm" / "guest"
SCRIPTS = ("run.sh", "scan.py", "inventory.py", "telemetry.py", "obfuscation.py")
REPLACED = set(SCRIPTS) | {"plan.json", "tools.txt"}


def add_bytes(tar: tarfile.TarFile, name: str, data: bytes, mode: int = 0o644) -> None:
    info = tarfile.TarInfo(name)
    info.size, info.mode = len(data), mode
    tar.addfile(info, io.BytesIO(data))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("src", type=Path)
    ap.add_argument("out", type=Path)
    ap.add_argument("--tools", required=True, help="comma list, from: " + ",".join(ALL_TOOLS))
    a = ap.parse_args(argv)
    tools = tuple(t for t in ALL_TOOLS if t in a.tools.split(","))
    unknown = set(a.tools.split(",")) - set(tools)
    if unknown:
        ap.error(f"unknown tools: {sorted(unknown)}")
    if a.out.resolve() == a.src.resolve():
        ap.error("OUT_TAR must differ from IN_TAR")
    with tarfile.open(a.src) as src, tarfile.open(a.out, "w") as out:
        manifest = json.load(src.extractfile("manifest.json"))
        n = 0
        for m in src:
            if m.name in REPLACED:
                continue
            out.addfile(m, src.extractfile(m) if m.isfile() else None)
            n += m.name.startswith("skills/") and m.isfile()
        for s in SCRIPTS:
            add_bytes(out, s, (GUEST / s).read_bytes(), 0o755 if s.endswith(".sh") else 0o644)
        add_bytes(out, "tools.txt", (" ".join(tools) + "\n").encode())
        plan = build_plan([e for e in manifest if e["files"] or e["symlinks"]], tools)
        add_bytes(out, "plan.json", json.dumps({"jobs": plan}).encode())
    a.out.with_suffix(".manifest.json").write_text(json.dumps(manifest, indent=1))
    print(f"retooled {a.src.name} -> {a.out}: {len(manifest)} entries, {n} files, tools {','.join(tools)}, {len(plan)} jobs")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
