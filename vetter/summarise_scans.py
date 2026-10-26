#!/usr/bin/env python3
"""Normalise the scanner guest's output (vm/vm.sh fetch) into one findings table and a summary.

Each tool's report was written by third-party code inside the guest, so it is parsed here as data:
only identifiers, severities, categories, file names and line numbers are kept, plus the tool's own
rule title (truncated, non-ASCII escaped). Snippets, matched text and free-form explanations are
dropped, so nothing quoted from a skill passes through. Writes findings.tsv next to the results.

Runs on our own and Anthropic's skills measure false positives (a known-good set). Runs on a batch
of harvested third-party skills (stage_harvest.py) take --manifest, so origins are tiers; there a
finding is a signal to read at its line, beside the tool's known-good flag rate, never a verdict.
"""
from __future__ import annotations

import argparse
import collections
import csv
import json
import re
from pathlib import Path

SEV = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "info": "INFO", "informational": "INFO",
       "error": "HIGH", "warning": "MEDIUM", "warn": "MEDIUM", "note": "LOW", "hint": "INFO"}
RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
# Every tool scan.py can run, in report order, with the extension of its per-skill report.
REPORTS = {"sentry": "stdout", "cisco": "json", "cisco-behavioral": "json", "skillspector": "json", "agnix": "stdout",
           "aid": "json", "skills-ref": "stdout", "atr": "json", "bawbel": "json",
           "guarddog": "stdout", "bandit": "json", "agentshield": "stdout", "holguard": "stdout", "osv": "json",
           "gitleaks": "json", "clamav": "json", "yara": "json"}
# Second wave: tools that report no severity get one here, by what the rule means:
# GuardDog threat-* rules HIGH, capability-* rules INFO (facts: "spawns a process", "reads a file");
# osv-scanner MAL- advisories (a known-malicious package) CRITICAL, other advisories MEDIUM;
# a gitleaks secret HIGH (rule, file and line only: the secret was redacted in the guest);
# a ClamAV signature CRITICAL; a YARA-Forge core rule HIGH. Bandit, agentshield and hol-guard keep their own.
# skills-ref has no rule ids or severities: its messages map to short ids here, and stay LOW (a
# conformance check, not a security finding). Values quoted from the skill are dropped.
REF_RULES = [("Unexpected fields", "unexpected-fields"), ("Missing required field in frontmatter: name", "missing-name"),
             ("Missing required field in frontmatter: description", "missing-description"),
             ("must be lowercase", "name-case"), ("start or end with a hyphen", "name-hyphen"),
             ("consecutive hyphens", "name-hyphens"), ("invalid characters", "name-chars"),
             ("Skill name", "name-length"), ("Directory name", "dir-name-mismatch"),
             ("Description exceeds", "description-length"), ("Compatibility exceeds", "compatibility-length"),
             ("must be a non-empty string", "field-empty"), ("must be a string", "field-type"),
             ("Invalid YAML", "invalid-yaml"), ("must start with YAML frontmatter", "no-frontmatter"),
             ("not properly closed", "frontmatter-unclosed"), ("must be a YAML mapping", "frontmatter-not-mapping"),
             ("Missing required file", "no-skill-md")]


def ref_finding(msg: str) -> tuple[str, str]:
    """(rule id, title) for one skills-ref message; quoted values and odd field names are dropped."""
    rule = next((r for k, r in REF_RULES if k in msg), "other")
    if rule == "unexpected-fields":
        names = msg.split(":", 1)[1].split(". Only")[0] if ":" in msg else ""
        keep = [n.strip() for n in names.split(",") if re.fullmatch(r"[A-Za-z0-9_-]{1,40}", n.strip())]
        return rule, "unexpected fields: " + ", ".join(keep)
    if rule == "invalid-yaml":
        return rule, "invalid YAML in frontmatter (strictyaml)"
    return rule, re.sub(r"'[^']*'", "'...'", msg)


def clean(s, n: int = 90) -> str:
    s = " ".join(str(s or "").split())[:n]
    return s.encode("ascii", "backslashreplace").decode("ascii").replace("\t", " ")


def sev(s) -> str:
    return SEV.get(str(s or "").lower(), "INFO")


def loc(v) -> tuple[str, str]:
    """(file, line) from 'file:line', a dict, or None."""
    if isinstance(v, dict):
        return clean(v.get("file") or v.get("path") or v.get("file_path"), 120), str(v.get("line") or v.get("start_line") or "")
    s = str(v or "")
    if ":" in s and s.rsplit(":", 1)[1].isdigit():
        f, ln = s.rsplit(":", 1)
        return clean(f, 120), ln
    return clean(s, 120), ""


def rel(path: str, sid: str) -> str:
    """Strip the mount prefix so files read as paths in the skill: /skills/<id>/<name>/ (one skill per
    run) or skills/<name>/ (a chunk, where the tools report paths from the chunk root)."""
    return re.sub(rf"^/?skills/(?:{re.escape(sid)}/)?[^/]+/?", "", path) or "."


UNPARSED: list[tuple[str, str]] = []     # (tool, skill) whose report was empty or not JSON: a tool error


def load(tool: str, sid: str, f: Path) -> dict:
    try:
        d = json.loads(f.read_text(errors="replace"))
        return d if isinstance(d, dict) else {}
    except (json.JSONDecodeError, OSError):
        UNPARSED.append((tool, sid))
        return {}


def findings(results: Path):
    for f in sorted((results / "sentry").glob("*.stdout")):
        sid = f.stem
        for x in load("sentry", sid, f).get("findings", []):
            fl, ln = loc(x.get("location"))
            yield "sentry", sid, clean(x.get("type"), 40), sev(x.get("severity")), clean(x.get("category"), 30), fl, ln, clean(x.get("description"))
    for tool in ("cisco", "cisco-behavioral"):
        for f in sorted((results / tool).glob("*.json")):
            sid = f.stem
            for x in load(tool, sid, f).get("findings", []):
                yield (tool, sid, clean(x.get("rule_id"), 60), sev(x.get("severity")), clean(x.get("category"), 40),
                       clean(x.get("file_path"), 120), str(x.get("line_number") or ""), clean(x.get("title")))
    for f in sorted((results / "skillspector").glob("*.json")):
        sid = f.stem
        for x in load("skillspector", sid, f).get("issues", []):
            fl, ln = loc(x.get("location"))
            yield ("skillspector", sid, clean(x.get("id"), 40), sev(x.get("severity")), clean(x.get("category"), 40),
                   fl, ln, clean(x.get("pattern")))
    for f in sorted((results / "agnix").glob("*.stdout")):
        sid = f.stem
        for x in load("agnix", sid, f).get("diagnostics", []):
            yield ("agnix", sid, clean(x.get("rule"), 40), sev(x.get("level")), clean(x.get("category"), 40),
                   clean(x.get("file"), 120), str(x.get("line") or ""), clean(x.get("message")))
    for f in sorted((results / "aid").glob("*.json")):
        sid = f.stem
        for x in load("aid", sid, f).get("items", []):
            yield ("aid", sid, "invisible-" + clean(x.get("suspicion_level"), 10), sev(x.get("suspicion_level")), "unicode",
                   clean(x.get("file_path"), 120), "",
                   clean(f"{x.get('total_invisible_code_points')} code points, longest run {x.get('longest_consecutive_run')}, "
                         f"tag run {x.get('longest_unicode_tag_run')}"))
    for f in sorted((results / "skills-ref").glob("*.stdout")):
        sid = f.stem
        if "Valid skill:" in f.read_text(errors="replace"):
            continue
        err = f.with_suffix(".stderr")
        text = err.read_text(errors="replace") if err.exists() else ""
        msgs = [ln[4:] for ln in text.splitlines() if ln.startswith("  - ")]
        if not msgs:                                 # no verdict either way: a crash or an empty report
            UNPARSED.append(("skills-ref", sid))
        for m in msgs:
            rule, title = ref_finding(m)
            if rule == "invalid-yaml" and "JSONesque flow" in text:   # strictyaml refuses [a, b] on principle
                rule, title = "flow-style", "flow-style YAML ([a, b] or {k: v}), refused by strictyaml"
            yield "skills-ref", sid, rule, "LOW", "spec", "SKILL.md", "", clean(title)
    for f in sorted((results / "atr").glob("*.json")):
        sid = f.stem
        for it in load("atr", sid, f).get("items", []):
            for m in it.get("matches", []):
                yield ("atr", sid, clean(m.get("rule_id"), 40), sev(m.get("severity")), clean(m.get("decided_by") or "pattern", 20),
                       clean(it.get("file"), 120), "", clean(m.get("title")))
    for f in sorted((results / "bawbel").glob("*.json")):
        sid = f.stem
        for it in load("bawbel", sid, f).get("items", []):
            for x in it.get("findings", []):
                yield ("bawbel", sid, clean(x.get("rule_id"), 60), sev(x.get("severity")), clean(x.get("engine"), 20),
                       clean(it.get("file_path"), 120), str(x.get("line") or ""), clean(x.get("title")))
    yield from findings_wave2(results)


def _items(tool: str, sid: str, f: Path) -> list:
    return load(tool, sid, f).get("items", [])


def findings_wave2(results: Path):
    for f in sorted((results / "guarddog").glob("*.stdout")) + sorted((results / "guarddog").glob("*.npm.json")):
        sid = f.name.split(".")[0]
        d = load("guarddog", sid, f)
        for rule, hits in (d.get("results") or {}).items():
            if not hits or not isinstance(hits, list):
                continue
            level = "HIGH" if rule.startswith("threat-") else "INFO"
            for h in hits[:20]:                     # the "code" field is the skill's own text: dropped
                fl, ln = loc(h.get("location") if isinstance(h, dict) else None)
                yield "guarddog", sid, clean(rule, 60), level, rule.split("-", 1)[0], fl, ln, clean((h or {}).get("message") if isinstance(h, dict) else "")
    for f in sorted((results / "bandit").glob("*.json")):
        sid = f.stem
        for x in _items("bandit", sid, f):
            yield ("bandit", sid, clean(x.get("test_id"), 10), sev(x.get("issue_severity")), "construct",
                   clean(x.get("_file"), 120), str(x.get("line_number") or ""), clean(x.get("test_name")))
    for f in sorted((results / "agentshield").glob("*.stdout")):
        sid = f.stem
        for x in load("agentshield", sid, f).get("findings", []):
            rule = re.sub(r"-\d+$", "", str(x.get("id") or ""))            # ids end in a per-finding counter
            # "prompt-defense-missing-*" (an agent prompt without defensive wording) is rated CRITICAL by the tool;
            # read at the line (2026-10-25) it is hygiene, so LOW here
            level = "LOW" if rule.startswith("prompt-defense-missing") else sev(x.get("severity"))
            if rule.startswith("secrets-") and re.search(r"(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|uv\.lock)$", str(x.get("file") or "")):
                continue                                # lockfile integrity hashes read as keys (1,834 in 10 roots)
            yield ("agentshield", sid, clean(rule, 60), level, clean(x.get("category"), 30),
                   clean(x.get("file"), 120), str(x.get("line") or ""), clean(x.get("title")))
    for f in sorted((results / "holguard").glob("*.stdout")):
        sid = f.stem
        for x in (load("holguard", sid, f).get("contributorReview") or {}).get("groups", []):
            ln = str(x.get("lineNumber") or "")
            yield ("holguard", sid, clean(x.get("ruleId"), 60), sev(x.get("severity")), clean(x.get("category"), 30),
                   clean(x.get("filePath"), 120), "" if ln == "None" else ln, clean(x.get("title")))
    for f in sorted((results / "osv").glob("*.json")):
        sid = f.stem
        for x in _items("osv", sid, f):
            ids = [str(i) for i in x.get("ids") or []]
            mal = any(i.startswith("MAL-") for i in ids)
            yield ("osv", sid, "osv-malicious" if mal else "osv-vulnerable", "CRITICAL" if mal else "MEDIUM", "dependency",
                   clean(x.get("_file"), 120), "", clean(f"{x.get('ecosystem')} {x.get('package')} {x.get('version')}: {len(ids)} advisories"))
    for f in sorted((results / "gitleaks").glob("*.json")):
        sid = f.stem
        for x in _items("gitleaks", sid, f):
            # generic-api-key fires on example keys in docs (1,854 of 1,969 hits, mostly llms-full.md and MDX):
            # LOW; a provider-specific rule (AWS, GCP, Stripe, ...) stays HIGH and is checked privately
            level = "LOW" if str(x.get("RuleID") or "").startswith("generic") else "HIGH"
            yield ("gitleaks", sid, clean(x.get("RuleID"), 40), level, "secret", clean(x.get("_file"), 120),
                   str(x.get("StartLine") or ""), clean(x.get("Description"), 60))
    for f in sorted((results / "clamav").glob("*.json")):
        sid = f.stem
        for x in _items("clamav", sid, f):
            yield "clamav", sid, clean(x.get("signature"), 60), "CRITICAL", "malware", clean(x.get("_file"), 120), "", "signature match"
    for f in sorted((results / "yara").glob("*.json")):
        sid = f.stem
        for x in _items("yara", sid, f):
            yield "yara", sid, clean(x.get("rule"), 60), "HIGH", "yara", clean(x.get("_file"), 120), "", clean(x.get("namespace"), 40)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("results", type=Path)
    ap.add_argument("--manifest", type=Path, help="stage_harvest.py manifest: origin = tier, not the id prefix")
    a = ap.parse_args()
    tier = {e["id"]: e["tier"] for e in json.loads(a.manifest.read_text())} if a.manifest else {}
    origin = lambda sid: tier.get(sid) or sid.split("__", 1)[0]  # noqa: E731
    rows = [(t, s, r, v, c, rel(f, s), ln, title) for t, s, r, v, c, f, ln, title in findings(a.results)]
    out = a.results / "findings.tsv"
    with out.open("w", newline="") as fh:
        w = csv.writer(fh, delimiter="\t", lineterminator="\n")
        w.writerow(["tool", "skill", "rule", "severity", "category", "file", "line", "title"])
        w.writerows(rows)

    tools = [t for t in REPORTS if (a.results / t).is_dir()]
    reported = {t: {p.stem for p in (a.results / t).glob(f"*.{REPORTS[t]}")} for t in tools}
    skills = sorted(set().union(*reported.values())) if tools else []
    print(f"{len(rows)} findings over {len(skills)} skills -> {out}")
    print("reports per tool: " + ", ".join(f"{t} {len(reported[t])}" for t in tools))
    print("unparsed reports (tool errors): " + (", ".join(f"{t} {s}" for t, s in UNPARSED) or "none") + "\n")
    print(f"{'tool':17} {'findings':>8} {'skills>=HIGH':>12} {'skills>=MED':>11} {'any':>11}  by severity")
    for t in tools:
        tr = [r for r in rows if r[0] == t]
        worst = collections.defaultdict(lambda: 9)
        for r in tr:
            worst[r[1]] = min(worst[r[1]], RANK[r[3]])
        mine = sorted(reported[t]) or [""]
        hi = sum(1 for s in mine if worst[s] <= 1)
        med = sum(1 for s in mine if worst[s] <= 2)
        anyf = sum(1 for s in mine if worst[s] <= 4)
        bys = collections.Counter(r[3] for r in tr)
        n = len(mine)
        print(f"{t:17} {len(tr):8} {hi:5} ({100 * hi / n:3.0f}%) {med:4} ({100 * med / n:3.0f}%) {anyf:4} ({100 * anyf / n:3.0f}%)  "
              + " ".join(f"{k}={bys[k]}" for k in RANK if bys[k]))
    origins = sorted({origin(s) for s in skills})
    print("\nskills >=HIGH by origin (cs = ClaudeSkills, home = other local, synced = Anthropic's; or tier):")
    print(f"{'tool':17} " + " ".join(f"{o:>14}" for o in origins))
    for t in tools:
        worst = collections.defaultdict(lambda: 9)
        for r in rows:
            if r[0] == t:
                worst[r[1]] = min(worst[r[1]], RANK[r[3]])
        cells = []
        for o in origins:
            mine = [s for s in reported[t] if origin(s) == o]
            k = sum(1 for s in mine if worst[s] <= 1)
            cells.append(f"{k:>3}/{len(mine):<3} ({100 * k / max(1, len(mine)):3.0f}%)")
        print(f"{t:17} " + " ".join(f"{c:>14}" for c in cells))
    print("\ntop rules per tool (count of skills, severity, title):")
    for t in tools:
        per_skill = {(r[1], r[2], r[3], r[7][:60]) for r in rows if r[0] == t}
        c = collections.Counter((rule, v, title) for _, rule, v, title in per_skill)
        print(f"  {t}")
        for (rule, v, title), n in sorted(c.items(), key=lambda kv: (-kv[1], RANK[kv[0][1]]))[:8]:
            print(f"    {n:3}  {v:8} {rule[:34]:34} {title}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
