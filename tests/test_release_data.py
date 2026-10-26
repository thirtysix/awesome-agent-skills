"""The LLM-derived data that ships with the site holds labels only: no model prose (summaries, evidence,
quoted lines) may reach data/reviews.json or data/hit-reviews.json."""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
TOKEN = re.compile(r"^[a-z0-9_]{1,40}$")              # an enum value
RULE = re.compile(r"^[A-Za-z0-9_.:/ -]{1,80}$")       # a rule id or tool name (hol-guard puts a server name in some)


def strings(o, path=()):
    if isinstance(o, dict):
        for k, v in o.items():
            yield from strings(v, path + (k,))
    elif isinstance(o, list):
        for v in o:
            yield from strings(v, path)
    elif isinstance(o, str):
        yield path, o


def load(name):
    p = ROOT / "data" / name
    if not p.exists():
        pytest.skip(f"{name} not built")
    return json.loads(p.read_text(encoding="utf-8"))


def test_reviews_hold_enums_only():
    d = load("reviews.json")
    bad = [(p, s) for p, s in strings(d["skills"]) if not TOKEN.match(s)]
    assert not bad, bad[:3]


def test_hit_reviews_hold_enums_and_rule_ids_only():
    d = load("hit-reviews.json")
    bad = [(p[-1], s) for p, s in strings(d["entries"])
           if not (RULE if p[-1] in ("rule", "tool") else TOKEN).match(s)]
    assert not bad, bad[:3]


def test_withheld_skills_are_absent_from_published_data():
    import sys
    sys.path.insert(0, str(ROOT / "pipeline"))
    import withheld
    held = withheld.load()
    if not held:
        pytest.skip("nothing withheld")
    published = sorted((ROOT / "data").glob("*.json")) + sorted((ROOT / "docs").glob("*.js"))
    found = [(f.name, sid) for f in published for sid in held if sid in f.read_text(encoding="utf-8")]
    assert not found, found                         # the whole row, not only its review
    assert not held.keys() & {line.split("\t")[1] for line in (ROOT / "curation" / "llm-verdicts.tsv").read_text().splitlines()[1:] if "\t" in line}


def test_withheld_refuses_a_passed_date(tmp_path):
    import datetime as dt
    import sys
    sys.path.insert(0, str(ROOT / "pipeline"))
    import withheld
    f = tmp_path / "w.tsv"
    f.write_text("# c\nskill\tuntil\tnote\n0123456789ab\t2026-11-25\tx\n", encoding="utf-8")
    assert withheld.load(f, dt.date(2026, 11, 25)) == {"0123456789ab": "2026-11-25"}
    with pytest.raises(SystemExit):
        withheld.load(f, dt.date(2026, 11, 26))
