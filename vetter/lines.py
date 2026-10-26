#!/usr/bin/env python3
"""Print the one line each scanner finding points at, escaped: lines.py RESULTS STAGED_TAR [options]

For reading a finding before calling it anything (CLAUDE.md: every hit is a candidate false positive
until its line is read). RESULTS is a fetched results dir with findings.tsv (summarise_scans.py);
STAGED_TAR is the tar the run scanned (stage_skills.py / stage_harvest.py), read in memory and never
extracted. Each printed line is truncated and non-ASCII escaped, and a sample per rule keeps the
output small: third-party text is data to classify, one line at a time.

ATR reports a file and the index of the matched condition, not a line: with --atr-rules (the rules/
directory of the same ATR package) the condition's regex is re-run here (Python re; a JS-only pattern
is reported as such) and the first matching line printed. aid reports files only: skipped.
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import re
import sys
import tarfile
from pathlib import Path

RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def esc(s: str, n: int = 220) -> str:
    s = s.strip()[:n]
    return s.encode("ascii", "backslashreplace").decode("ascii")


def atr_conditions(rules_dir: Path, rule: str) -> list[str]:
    import yaml  # only needed for ATR
    for f in rules_dir.rglob(f"{rule}*.yaml"):
        d = yaml.safe_load(f.read_text(encoding="utf-8"))
        return [c.get("value", "") for c in (d.get("detection") or {}).get("conditions", [])]
    return []


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("results", type=Path)
    ap.add_argument("tar", type=Path)
    ap.add_argument("--tool", action="append", help="only these tools (repeatable)")
    ap.add_argument("--rule", action="append", help="only these rule ids (repeatable)")
    ap.add_argument("--min", default="HIGH", choices=list(RANK), help="lowest severity shown (default HIGH)")
    ap.add_argument("--per-rule", type=int, default=2, help="findings shown per (tool, rule); 0 = all")
    ap.add_argument("--atr-rules", type=Path, help="ATR rules/ directory, to locate ATR matches")
    a = ap.parse_args()

    rows = list(csv.DictReader((a.results / "findings.tsv").open(), delimiter="\t"))
    rows = [r for r in rows if RANK[r["severity"]] <= RANK[a.min]
            and (not a.tool or r["tool"] in a.tool) and (not a.rule or r["rule"] in a.rule)]
    rows.sort(key=lambda r: (r["tool"], RANK[r["severity"]], r["rule"], r["skill"]))
    seen: collections.Counter = collections.Counter()
    pick = []
    for r in rows:
        k = (r["tool"], r["rule"])
        if a.per_rule and seen[k] >= a.per_rule:
            continue
        seen[k] += 1
        pick.append(r)
    with tarfile.open(a.tar) as tar:
        names = tar.getnames()
        folder = {}
        for n in names:
            p = n.split("/")
            if len(p) >= 3 and p[0] == "skills":
                folder.setdefault(p[1], p[2])

        def text(sid: str, rel: str) -> list[str] | None:
            try:
                fh = tar.extractfile(f"skills/{sid}/{folder.get(sid, '')}/{rel.lstrip('/')}")
            except KeyError:
                return None
            return fh.read().decode("utf-8", "replace").splitlines() if fh else None

        cond_cache: dict = {}
        for r in pick:
            head = f"{r['tool']:12} {r['severity']:8} {r['rule'][:34]:34} {r['skill'][:44]}"
            lines = text(r["skill"], r["file"]) if r["file"] not in ("", ".") else None
            if r["tool"] == "atr" and a.atr_rules and lines is not None:
                rep = json.loads((a.results / "atr" / f"{r['skill']}.json").read_text())
                idx = [int(i) for it in rep["items"] for m in it.get("matches", [])
                       if m.get("rule_id") == r["rule"] for i in m.get("matched_conditions", []) if str(i).isdigit()]
                conds = cond_cache.setdefault(r["rule"], atr_conditions(a.atr_rules, r["rule"]))
                hit = None
                for i in idx:
                    for j in (i, i - 1):                # index base not documented: try both
                        if 0 <= j < len(conds):
                            try:
                                rx = re.compile(conds[j])
                            except re.error:
                                continue
                            hit = next(((n, ln) for n, ln in enumerate(lines, 1) if rx.search(ln)), None)
                            if hit:
                                break
                    if hit:
                        break
                print(f"{head}\n    {r['file']}:{hit[0] if hit else '?'}  {esc(hit[1]) if hit else '(no line matched in Python re)'}")
                continue
            if r["tool"] == "bawbel" and not r["line"].isdigit() and lines is not None:
                rep = json.loads((a.results / "bawbel" / f"{r['skill']}.json").read_text())
                ms = [x.get("match") or "" for it in rep["items"] if it.get("file_path") == r["file"]
                      for x in it.get("findings", []) if x.get("rule_id") == r["rule"]]
                m = ms[0] if ms else ""
                n = next((k for k, ln in enumerate(lines, 1) if m and m.lower() in ln.lower()), None)
                print(f"{head}\n    {r['file']}:{n or '?'}  match {esc(repr(m), 80)}  {esc(lines[n - 1]) if n else ''}")
                continue
            if lines is None or not r["line"].isdigit():
                print(f"{head}\n    {r['file']}:{r['line']}  (no line)")
                continue
            n = int(r["line"])
            print(f"{head}\n    {r['file']}:{n}  {esc(lines[n - 1]) if 0 < n <= len(lines) else '(past end of file)'}")
    print(f"\n{len(pick)} shown of {len(rows)} at {a.min} or above", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
