#!/usr/bin/env python3
"""Which skill folders changed between two harvest runs: offline, from the cached git trees only.

    python3 -I pipeline/diff_harvests.py OLD_RUN NEW_RUN    (run names under ~/.cache/awesome-agent-skills/harvest/)

Writes data/harvest-diff.json: per skill id (as skills.py computes it) of the NEW run, "same" when every
file in its folder has the same git blob as in OLD, "changed" otherwise, "new" when OLD had no such
folder. Results computed on OLD (the LLM review) apply to "same" skills only; the rest are the input for
the next re-review. No file contents are read: tree entries carry each file's blob sha.
"""
from __future__ import annotations

import argparse
import collections
import gzip
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline"))
from freshness import folders  # noqa: E402
from harvest import CACHE, slug  # noqa: E402
import withheld  # noqa: E402

OUT = ROOT / "data" / "harvest-diff.json"


def run_folders(run: Path) -> dict[tuple[str, str], dict]:
    """(full_name lower, skill dir) -> {relpath: (blob, mode)} for every harvested skill folder."""
    man = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    out = {}
    for rr in man["repos"]:
        if rr.get("error"):
            continue
        f = run / "trees" / f"{slug(rr['repo'])}@{rr['sha']}.json.gz"
        if not f.exists():
            continue
        tree = json.loads(gzip.decompress(f.read_bytes())).get("tree", [])
        name = ((rr.get("meta") or {}).get("full_name") or rr["repo"]).lower()
        for d, rec in folders(tree, rr.get("paths")).items():
            out[(name, d)] = rec["files"]
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("old")
    ap.add_argument("new")
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args(argv)
    old, new = run_folders(CACHE / a.old), run_folders(CACHE / a.new)
    state, held = {}, withheld.load()
    for (repo, d), files in new.items():
        sid = hashlib.sha1(f"{repo}/{d}".encode()).hexdigest()[:12]
        if sid in held:
            continue
        prev = old.get((repo, d))
        state[sid] = "new" if prev is None else "same" if prev == files else "changed"
    gone = len(old.keys() - new.keys())
    a.out.write_text(json.dumps({"old": a.old, "new": a.new, "gone": gone, "skills": state}, separators=(",", ":")) + "\n")
    print(f"diff_harvests: {dict(collections.Counter(state.values()))}, {gone} folders gone -> {a.out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
