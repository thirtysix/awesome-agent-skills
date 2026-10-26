#!/usr/bin/env python3
"""Newest freshness report -> data/freshness.json: per repo the scanned and current commit, per skill folder its drift.

Offline. Reads ~/.cache/awesome-agent-skills/freshness/<newest>/report.json (written by freshness.py, metadata
only) and keeps only shas, dates, counts and a state word per folder. Folders absent from `dirs` in a repo that was
checked are unchanged; a repo absent from `repos` was not checked.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "data" / "freshness.json"
REPORTS = Path.home() / ".cache" / "awesome-agent-skills" / "freshness"
STATES = {"skill_md_changed", "files_changed", "gone"}


def newest() -> Path:
    runs = sorted(REPORTS.glob("*/report.json"), key=lambda p: p.stat().st_mtime)
    if not runs:
        sys.exit("collect_freshness: no report; run pipeline/freshness.py first")
    return runs[-1]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("report", nargs="?", type=Path, help="report.json (default: newest)")
    a = ap.parse_args(argv)
    src = a.report or newest()
    r = json.loads(src.read_text(encoding="utf-8"))
    repos = {}
    for x in r["repos"]:
        if x.get("error") or not x.get("head"):
            continue
        c = x.get("compare") or {}
        repos[x["name"]] = {"sha": x["sha"], "head": x["head"], "branch": x["branch"],
                            "ahead": c.get("ahead_by", 0 if x["head"] == x["sha"] else None),
                            "sha_date": (c.get("base_date") or "")[:10]}
    dirs = {f"{f['repo']}\t{f['dir']}": f["state"] for f in r["folders"] if f["state"] in STATES and f["repo"] in repos}
    out = {"checked": r["checked"], "harvest_fetched": r["harvest_fetched"], "repos": repos, "dirs": dirs}
    OUT.write_text(json.dumps(out, indent=0, sort_keys=True) + "\n", encoding="utf-8")
    print(f"collect_freshness: {len(repos)} repos checked, {len(dirs)} folders changed or gone -> {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
