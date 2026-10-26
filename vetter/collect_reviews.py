#!/usr/bin/env python3
"""Fold one LLM-review run (llm_review.py --out dir) into data/reviews.json for the Skills tab.

Only enum and boolean fields are kept: the overall risk, the reviewer-manipulation flag, the
categories of findings at medium or above, and the capabilities the model reported. The model's
summary, evidence and explanations are free text written while reading untrusted skills, so none
of it leaves the cache. reviews.jsonl may hold several records per skill after a resume: the last
one wins, as in llm_review.py.

A risk here is a signal, not a verdict; curation/llm-verdicts.tsv holds the ones a person read.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "pipeline"))
from llm_review import CATEGORIES, RISK, SEVERITIES  # noqa: E402
import withheld  # noqa: E402

RUN = Path.home() / ".cache" / "awesome-agent-skills" / "llm-review" / "core-haiku-low"
OUT = ROOT / "data" / "reviews.json"
# capability -> the values that count as present (booleans, or the "undisclosed" level of the enums)
CAPS = {"network": {"undisclosed"}, "telemetry": {"undisclosed"}, "shell": {True}, "writes_outside_project": {True},
        "reads_credentials": {True}, "persistence": {True}, "permission_override": {True}}
MEDIUM = SEVERITIES.index("medium")


def collect(run: Path) -> dict:
    held = withheld.load()                          # left out until their author has had time to fix them
    last: dict[str, dict] = {}
    with (run / "reviews.jsonl").open(encoding="utf-8") as fh:
        for line in fh:
            r = json.loads(line)
            if r["skill"].removeprefix("h__") not in held:
                last[r["skill"]] = r
    skills, models, cost = {}, Counter(), 0.0
    for sid, r in last.items():
        risk = r.get("risk") if r.get("risk") in RISK else "unparsed"
        cats = []
        for f in r.get("findings", []):
            c, s = f.get("category"), f.get("severity")
            if c in CATEGORIES and s in SEVERITIES and SEVERITIES.index(s) >= MEDIUM and c not in cats:
                cats.append(c)
        caps = [k for k, ok in CAPS.items() if (r.get("capabilities") or {}).get(k) in ok]
        skills[sid.removeprefix("h__")] = [risk, int(bool(r.get("reviewer_manipulation"))), cats[:4], caps]
        models[f"{r.get('provider', '')}/{r.get('model', '')}"] += 1
        cost += r.get("cost_usd") or 0.0
    first = next(iter(last.values()), {})
    # the harvest whose files the review read: render keeps a review only while the skill's folder is unchanged
    harvest = json.loads((ROOT / "data" / "skills.json").read_text(encoding="utf-8")).get("run", "")
    return {"collected": dt.date.today().isoformat(), "run": run.name, "harvest": harvest, "models": dict(models),
            "settings": first.get("settings", ""), "prompt": first.get("prompt", ""), "cost_usd": round(cost, 2),
            "risk": dict(Counter(v[0] for v in skills.values())), "manipulation": sum(v[1] for v in skills.values()),
            "categories": CATEGORIES, "skills": skills}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("run", nargs="?", type=Path, default=RUN, help="llm_review.py output dir")
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args(argv)
    data = collect(a.run)
    a.out.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
    print(f"collect_reviews: {len(data['skills'])} skills from {a.run.name}, risk {data['risk']}, "
          f"manipulation {data['manipulation']}, ${data['cost_usd']} -> {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
