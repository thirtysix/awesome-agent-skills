"""Findings held back from the published data while their author has time to fix them.

`curation/withheld.local.tsv` is untracked (.git/info/exclude): columns skill (a skills.json id),
until (YYYY-MM-DD) and note. The whole row is held back, not only the finding: a skill with scanner
results but no LLM review stands out among the few unreviewed ones. Each producer leaves it out:
skills.py (data/skills.json, its counts included), collect_scans.py, diff_harvests.py, collect_reviews.py
and categorise_trial.py (labels), and render.py refuses data that still holds it. Once `until` has
passed, load() refuses: publish the finding (delete its row here, move its verdict back to
llm-verdicts.tsv, re-run those producers; categorise_trial.py --all labels it again) or extend the date.
"""
from __future__ import annotations

import csv
import datetime as dt
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILE = ROOT / "curation" / "withheld.local.tsv"


def load(path: Path = FILE, today: dt.date | None = None) -> dict[str, str]:
    """{skill id: until}; {} when there is no file."""
    if not path.exists():
        return {}
    today = today or dt.date.today()
    out, errors = {}, []
    with path.open(encoding="utf-8", newline="") as fh:
        for row in csv.DictReader((line for line in fh if not line.startswith("#")), delimiter="\t"):
            sid, until = row.get("skill", ""), row.get("until", "")
            if not re.fullmatch(r"[0-9a-f]{12}", sid):
                errors.append(f"{path.name}: skill '{sid}' is not a skills.json id")
            elif not re.fullmatch(r"\d{4}-\d{2}-\d{2}", until):
                errors.append(f"{path.name}: {sid} until '{until}' is not a date")
            elif dt.date.fromisoformat(until) < today:
                errors.append(f"{path.name}: {sid} was withheld until {until}: publish it or extend the date")
            else:
                out[sid] = until
    if errors:
        raise SystemExit("\n".join(errors))
    return out
