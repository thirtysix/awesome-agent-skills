#!/usr/bin/env python3
"""Validate the curated tables against curation/schema.yaml and write data/catalog.json.

Nothing is written unless every table passes. Rejected, naming the table, row and column: a
missing required value, a value outside the schema, a malformed or repeated id (ids are unique
across all tables, so an overview ref names exactly one row), a URL that is not http(s), a
coverage cell whose status word is unknown, an overview ref that names no row, and any invisible
character (Unicode Tags, zero-width, bidi, variation selectors: untrusted.INVISIBLE). Curated text is
ours, so a character a reader cannot see has no business in it.
Warned, without failing: an em-dash anywhere.

Everything in these tables came from the web, so render.py escapes every field; this file only
refuses values that could never be right.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import json
import re
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from untrusted import invisible  # noqa: E402
import withheld  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CURATION = ROOT / "curation"
OUT = ROOT / "data" / "catalog.json"
URL = re.compile(r"^https?://[^\s<>\"']+$")


class Invalid(Exception):
    pass


def read_tsv(path: Path) -> tuple[list[str], list[dict]]:
    with path.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.reader(fh, delimiter="\t"))
    if not rows:
        raise Invalid(f"{path.name}: empty file, expected a header row")
    head, out = rows[0], []
    for n, row in enumerate(rows[1:], 2):
        if not any(c.strip() for c in row):
            continue
        if len(row) != len(head):
            raise Invalid(f"{path.name} line {n}: {len(row)} fields, header has {len(head)}")
        out.append({k: v.strip() for k, v in zip(head, row)})
    return head, out


def check_invisible(where: str, rows: list[dict], errors: list[str]) -> None:
    for row in rows:
        for col, val in row.items():
            if (found := invisible(val)):
                errors.append(f"{where} {row.get('id') or row.get('check_class', '')[:30]} '{col}': "
                              f"invisible characters {', '.join(found)}")


def check_table(name: str, spec: dict, head: list[str], rows: list[dict], errors: list[str]) -> None:
    where = spec["file"]
    for col in spec["required"] + list(spec.get("enums", {})) + spec.get("urls", []):
        if col not in head:
            errors.append(f"{where}: no column '{col}'")
    if errors:
        return
    pattern = re.compile(spec["id_pattern"])
    for row in rows:
        rid = row.get("id", "")
        at = f"{where} {rid or '(no id)'}"
        if not pattern.match(rid):
            errors.append(f"{at}: id does not match {spec['id_pattern']}")
        for col in spec["required"]:
            if not row[col]:
                errors.append(f"{at}: '{col}' is empty")
        for col, allowed in spec.get("enums", {}).items():
            if row[col] not in allowed:
                errors.append(f"{at}: '{col}' is '{row[col]}', not one of {sorted(allowed)}")
        for col in spec.get("urls", []):
            if row[col] and not URL.match(row[col]):
                errors.append(f"{at}: '{col}' is not an http(s) URL: {row[col][:80]}")


def coverage_status(cell: str, statuses: dict) -> tuple[str, str] | None:
    """('partial', 'only *') from "partial: only '*'"; None if no known status word leads."""
    for key in sorted(statuses, key=len, reverse=True):
        if cell == key or cell.startswith(key + ":") or cell.startswith(key + " "):
            note = cell[len(key):].strip().lstrip(":").strip()
            if note.startswith("(") and note.endswith(")"):
                note = note[1:-1]
            return key, note
    return None


def walk(doc, key: str):
    """Every value stored under `key` anywhere in a parsed YAML document."""
    if isinstance(doc, dict):
        for k, v in doc.items():
            if k == key:
                yield v
            yield from walk(v, key)
    elif isinstance(doc, list):
        for v in doc:
            yield from walk(v, key)


def strings(doc):
    if isinstance(doc, str):
        yield doc
    elif isinstance(doc, dict):
        for v in doc.values():
            yield from strings(v)
    elif isinstance(doc, list):
        for v in doc:
            yield from strings(v)


EXTRA_DOCS = ("analysis", "practices")     # curated prose with refs: method and findings, best practice


def build(curation: Path = CURATION) -> dict:
    schema = yaml.safe_load((curation / "schema.yaml").read_text(encoding="utf-8"))
    errors: list[str] = []
    tables, owner = {}, {}
    for name, spec in schema["tables"].items():
        head, rows = read_tsv(curation / spec["file"])
        check_table(name, spec, head, rows, errors)
        check_invisible(spec["file"], rows, errors)
        for row in rows:
            if row.get("id") in owner:
                errors.append(f"id {row['id']} is used in both {owner[row['id']]} and {spec['file']}")
            owner[row.get("id")] = spec["file"]
        tables[name] = rows

    tool_ids = {r["id"] for r in tables.get("tools", [])}
    lit_ids = {r["id"] for r in tables.get("literature", [])}
    for row in tables.get("scores", []):
        if row["tool"] not in tool_ids:
            errors.append(f"tool-scores.tsv {row['id']}: tool {row['tool']} is not in vetting-tools.tsv")
        if row["ref"] not in lit_ids:
            errors.append(f"tool-scores.tsv {row['id']}: ref {row['ref']} is not in literature.tsv")

    try:
        held = withheld.load(curation / withheld.FILE.name)
    except SystemExit as e:                         # a date has passed: publish the finding or extend it
        errors.append(str(e))
        held = {}
    seen = set()
    for row in tables.get("verdicts", []):
        if row["skill"] in held:
            errors.append(f"llm-verdicts.tsv {row['id']}: skill {row['skill']} is withheld (withheld.local.tsv)")
        if not re.match(r"^[0-9a-f]{12}$", row["skill"]):
            errors.append(f"llm-verdicts.tsv {row['id']}: skill '{row['skill']}' is not a skills.json id")
        if (row["skill"], row["signal"]) in seen:
            errors.append(f"llm-verdicts.tsv {row['id']}: a second row for {row['skill']} {row['signal']}")
        seen.add((row["skill"], row["signal"]))

    cov = schema["coverage"]
    head, rows = read_tsv(curation / cov["file"])
    check_invisible(cov["file"], rows, errors)
    unknown_cols = [c for c in head if c != cov["row_key"] and c not in cov["columns"]]
    if unknown_cols:
        errors.append(f"{cov['file']}: columns not in schema.coverage.columns: {unknown_cols}")
    for key, col in cov["columns"].items():
        if col.get("tool") and col["tool"] not in tool_ids:
            errors.append(f"schema.coverage.columns.{key}: tool {col['tool']} is not in vetting-tools.tsv")
    matrix = []
    for row in rows:
        cells = {}
        for key in cov["columns"]:
            parsed = coverage_status(row.get(key, ""), cov["statuses"])
            if parsed is None:
                errors.append(f"{cov['file']} '{row[cov['row_key']][:40]}' / {key}: "
                              f"unknown status '{row.get(key, '')[:40]}'")
                continue
            cells[key] = {"status": parsed[0], "note": parsed[1]}
        matrix.append({"check": row[cov["row_key"]], "cells": cells})

    overview = yaml.safe_load((curation / "overview.yaml").read_text(encoding="utf-8"))
    for sec in overview["sections"]:
        for item in sec["items"]:
            for ref in item.get("refs") or []:
                if ref not in owner:
                    errors.append(f"overview.yaml '{item['text'][:40]}...': ref {ref} names no row")

    extras = {}
    for name in EXTRA_DOCS:
        path = curation / f"{name}.yaml"
        if not path.exists():
            continue
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        for refs in walk(doc, "refs"):
            for ref in refs or []:
                if ref not in owner:
                    errors.append(f"{name}.yaml: ref {ref} names no row")
        for text in strings(doc):
            if (found := invisible(text)):
                errors.append(f"{name}.yaml: invisible characters {', '.join(found)} in '{text[:40]}'")
        extras[name] = doc

    if errors:
        raise Invalid("\n".join(errors))
    return {"built": dt.date.today().isoformat(), "schema": schema, "overview": overview, **extras,
            "resources": tables["resources"], "tools": tables["tools"],
            "literature": tables["literature"], "scores": tables.get("scores", []), "verdicts": tables.get("verdicts", []), "coverage": matrix}


def warnings(catalog: dict) -> list[str]:
    out = []
    for name in ("resources", "tools", "literature"):
        for row in catalog[name]:
            for col, val in row.items():
                if "\u2014" in val:
                    out.append(f"{name} {row['id']} '{col}': em-dash")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--curation", type=Path, default=CURATION)
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args(argv)
    try:
        catalog = build(a.curation)
    except Invalid as e:
        print(f"build: refused\n{e}", file=sys.stderr)
        return 1
    for w in warnings(catalog):
        print(f"build: warning: {w}", file=sys.stderr)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(catalog, ensure_ascii=False, indent=1, default=str) + "\n", encoding="utf-8")
    print(f"build: {len(catalog['resources'])} resources, {len(catalog['tools'])} vetting tools and sources, "
          f"{len(catalog['coverage'])} check classes, {len(catalog['literature'])} papers -> {a.out.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
