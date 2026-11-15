#!/usr/bin/env python3
"""NVIDIA SkillEvaluator Tier 1 results -> per-skill TSV + counts, and a comparison with our scanners.

    python3 -I vetter/summarise_skillevaluator.py RESULTS [--base RUN ...] [--out TSV] [--findings TSV]

RESULTS holds skillevaluator/<sid>.stdout files written by scan.py: {"exit": N, "report": <its JSON>}.
--findings writes the PII Scan and Secrets Detection findings as findings.tsv rows (tool skillevaluator,
rule = check name, title = validator; never the message or the line) for secrets_check.py and hit_review.py.
--base takes earlier results dirs that have a findings.tsv (summarise_scans.py output) for the same
skill ids; their per-tool ">= HIGH" flags are set beside SkillEvaluator's verdict.

Prints counts, enums and check names only: never a finding's message, line or suggestion (they can
quote a skill's own text).
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import os
import re
import sys

# Validators about safety. The rest (schema/governance, quality, licence, version, lint) are NVIDIA's
# publication policy: e.g. a missing `author` field is HIGH there.
SECURITY = ("Security Scan", "Code Risk Analysis", "Secrets Detection", "Unicode Smuggling Detection", "PII Scan",
            "Code Integrity & Hygiene")
FINDING_VALIDATORS = ("PII Scan", "Secrets Detection")
FINDING_COLS = ["tool", "skill", "rule", "severity", "category", "file", "line", "title"]
SEV = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
SAFE = re.compile(r"[^A-Za-z0-9 ._:/()+\-]")


def clean(s, n: int = 60) -> str:
    return SAFE.sub("?", str(s))[:n]


def quality_score(res: dict):
    q = res.get("quality") or {}
    for k in ("overall_score", "total_score", "score", "overall"):
        v = q.get(k)
        if isinstance(v, (int, float)):
            return float(v)
        if isinstance(v, dict) and isinstance(v.get("score"), (int, float)):
            return float(v["score"])
    return None


def parse(path: str) -> dict:
    try:
        wrap = json.load(open(path))
    except (OSError, ValueError):
        return {"state": "unreadable"}
    rep = wrap.get("report") or {}
    out = {"state": "ok", "exit": wrap.get("exit"), "status": rep.get("overall_status"),
           "passed": rep.get("overall_passed"), "incomplete": ",".join(rep.get("incomplete_scans") or []),
           "sev": rep.get("severity_counts") or {}, "validators": {}, "checks": collections.Counter(),
           "quality": None, "skillspector": None, "sec_high": 0}
    for r in rep.get("results") or []:
        name = clean(r.get("validator"), 40)
        out["validators"][name] = r.get("status") or ("skipped" if r.get("skipped") else "?")
        if r.get("skillspector_version"):
            out["skillspector"] = clean(r["skillspector_version"], 20)
        if out["quality"] is None:
            out["quality"] = quality_score(r)
        for f in r.get("findings") or []:
            if SEV.get(str(f.get("severity", "")).lower(), 0) >= 3:
                if r.get("validator") in SECURITY:
                    out["sec_high"] += 1
                out["checks"][(name, clean(f.get("check_name")), str(f.get("severity")).lower())] += 1
    return out


def finding_rows(sid: str, path: str) -> list[dict]:
    """PII Scan and Secrets Detection findings of one report as findings.tsv rows; [] when unreadable."""
    try:
        rep = json.load(open(path)).get("report") or {}
    except (OSError, ValueError):
        return []
    out = []
    for r in rep.get("results") or []:
        if r.get("validator") not in FINDING_VALIDATORS:
            continue
        for f in r.get("findings") or []:
            ln = f.get("line_number")
            out.append({"tool": "skillevaluator", "skill": sid, "rule": clean(f.get("check_name"), 40),
                        "severity": clean(f.get("severity"), 10).upper(), "category": clean(f.get("category"), 40),
                        "file": str(f.get("file_path") or "").replace("\t", " ").replace("\n", " "),
                        "line": str(ln) if isinstance(ln, int) and ln > 0 else "", "title": r["validator"]})
    return out


def high_flags(run_dir: str) -> dict:
    """{tool: set(sid)} with at least one HIGH or CRITICAL finding in a findings.tsv."""
    flags: dict = collections.defaultdict(set)
    tools = set()
    with open(os.path.join(run_dir, "findings.tsv")) as fh:
        for row in csv.DictReader(fh, delimiter="\t"):
            tools.add(row["tool"])
            if str(row.get("severity", "")).upper() in ("HIGH", "CRITICAL"):
                flags[row["tool"]].add(row["skill"])
    return {t: flags.get(t, set()) for t in tools}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("results")
    ap.add_argument("--base", nargs="*", default=[])
    ap.add_argument("--out")
    ap.add_argument("--findings")
    a = ap.parse_args()
    d = os.path.join(a.results, "skillevaluator")
    rows = {f[:-len(".stdout")]: parse(os.path.join(d, f)) for f in sorted(os.listdir(d)) if f.endswith(".stdout")}
    print(f"skills with a report: {len(rows)}")
    st = collections.Counter(r.get("status") for r in rows.values())
    print("overall_status:", dict(st))
    print("incomplete scans:", dict(collections.Counter(r.get("incomplete") or "-" for r in rows.values())))
    print("SkillSpector inside:", dict(collections.Counter(r.get("skillspector") for r in rows.values())))
    print("report states:", dict(collections.Counter(r["state"] for r in rows.values())))
    any_high = {s for s, r in rows.items() if (r.get("sev", {}).get("critical", 0) + r.get("sev", {}).get("high", 0)) > 0}
    print(f">= HIGH finding: {len(any_high)} / {len(rows)}")
    sec_high = {s for s, r in rows.items() if r.get("sec_high")}
    print(f">= HIGH from a security validator ({', '.join(SECURITY)}): {len(sec_high)} / {len(rows)}")
    vstat = collections.defaultdict(collections.Counter)
    for r in rows.values():
        for v, s in r.get("validators", {}).items():
            vstat[v][s] += 1
    print("\nvalidator statuses:")
    for v in sorted(vstat):
        print(f"  {v:40s} {dict(vstat[v])}")
    checks = collections.Counter()
    skills_per = collections.defaultdict(set)
    for s, r in rows.items():
        for k, n in r.get("checks", {}).items():
            checks[k] += n
            skills_per[k].add(s)
    print("\n>= HIGH findings by validator / check (findings, skills):")
    for k, n in checks.most_common(30):
        print(f"  {k[0][:30]:30s} {k[1][:40]:40s} {k[2]:8s} {n:4d} {len(skills_per[k]):3d}")
    qs = sorted(r["quality"] for r in rows.values() if r.get("quality") is not None)
    if qs:
        print(f"\nquality score: n={len(qs)} min={qs[0]:.1f} median={qs[len(qs)//2]:.1f} max={qs[-1]:.1f} "
              f"below 70: {sum(q < 70 for q in qs)}")
    flags: dict = {}
    for b in a.base:
        flags.update(high_flags(b))
    if flags:
        ids = set(rows)
        base_ids = set().union(*[v for v in flags.values()])
        print(f"\nagreement on >= HIGH, security validators only; skills in both runs: {len(ids)} here")
        print("  tool               SE  tool  both  SE-only  tool-only")
        for t in sorted(flags):
            f = flags[t] & ids
            se = sec_high
            print(f"  {t:18s} {len(se):3d} {len(f):5d} {len(se & f):5d} {len(se - f):7d} {len(f - se):9d}")
        union = set().union(*[flags[t] & ids for t in flags])
        print(f"  SE-only (no other tool >= HIGH): {len(sec_high - union)}; others-only: {len(union - sec_high)}")
    if a.out:
        with open(a.out, "w") as fh:
            w = csv.writer(fh, delimiter="\t", lineterminator="\n")
            w.writerow(["skill", "exit", "status", "critical", "high", "medium", "low", "quality", "incomplete", "sec_high",
                        "high_checks"] + [f"base_{t}" for t in sorted(flags)])
            for s, r in rows.items():
                sev = r.get("sev", {})
                w.writerow([s, r.get("exit"), r.get("status"), sev.get("critical", 0), sev.get("high", 0),
                            sev.get("medium", 0), sev.get("low", 0), r.get("quality"), r.get("incomplete"), r.get("sec_high"),
                            ";".join(sorted({k[1] for k in r.get("checks", {})}))]
                           + [int(s in flags[t]) for t in sorted(flags)])
    if a.findings:
        with open(a.findings, "w", newline="") as fh:
            w = csv.DictWriter(fh, FINDING_COLS, delimiter="\t", lineterminator="\n")
            w.writeheader()
            n = 0
            for s in rows:
                for row in finding_rows(s, os.path.join(d, s + ".stdout")):
                    w.writerow(row)
                    n += 1
        print(f"\n{n} PII / secrets findings -> {a.findings}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
