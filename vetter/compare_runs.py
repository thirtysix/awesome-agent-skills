#!/usr/bin/env python3
"""Compare two scanner result directories skill by skill: compare_runs.py A B

For each tool, per skill present in both: the set of (rule, severity, file, line) findings. Used as
the gate when the scanners move to a new runtime (VM podman -> Roihu apptainer): same images, same
skills, so the sets should match. Prints counts and the first few differences, identifiers only.
"""
from __future__ import annotations

import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from summarise_scans import REPORTS, findings, rel  # noqa: E402


def sets(d: Path) -> dict:
    out: dict = defaultdict(set)
    for tool, sid, rule, sev, _cat, f, ln, _title in findings(d):
        out[(tool, sid)].add((rule, sev, rel(f, sid).lstrip("/"), ln))
    return out


def main() -> int:
    a, b = Path(sys.argv[1]), Path(sys.argv[2])
    sa, sb = sets(a), sets(b)
    bad = 0
    for t in [t for t in REPORTS if (a / t).is_dir() and (b / t).is_dir()]:
        rep = lambda d: {p.stem for p in (d / t).glob(f"*.{REPORTS[t]}")}  # noqa: E731
        skills = rep(a) & rep(b)
        if rep(a) ^ rep(b):
            print(f"{t:17} reports only in one run: {len(rep(a) ^ rep(b))}")
            bad += len(rep(a) ^ rep(b))
        same = [s for s in skills if sa.get((t, s), set()) == sb.get((t, s), set())]
        diff = sorted(skills - set(same))
        bad += len(diff)
        print(f"{t:17} identical {len(same):3} / {len(skills)}" + (f"  differ: {len(diff)}" if diff else ""))
        for s in diff[:3]:
            only_a = sorted(sa.get((t, s), set()) - sb.get((t, s), set()))[:2]
            only_b = sorted(sb.get((t, s), set()) - sa.get((t, s), set()))[:2]
            print(f"   {s}: only in A {only_a} | only in B {only_b}")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
