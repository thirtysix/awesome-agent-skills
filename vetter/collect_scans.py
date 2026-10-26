#!/usr/bin/env python3
"""Fold the scanner results of every harvested batch into data/scans.json for the Skills tab.

Input: results directories from vm/vm.sh fetch, each holding the batch's stage_harvest.py manifest
as manifest.json (copied in after the fetch). Only identifiers and severities are kept, through
summarise_scans.findings(), which already drops snippets and free text. Per skill and tool: the
worst severity, how many findings are HIGH or above, and up to five of those rule ids. Our own
skills' runs (no manifest) are not batches and are skipped.

A finding here is a signal, shown beside the tool's flag rate on known-good skills; a person reads
the line before anything is called a problem.

Plugin roots (stage_harvest.py --plugins, ids p__...) are scanned as their own entries and kept under
`plugins`; every skill records the plugin it ships in (the deepest root above it in the same repo),
because installing the skill installs that root's hooks, MCP servers and settings too. The content
inventory (vm/guest/inventory.py: counts, names and hosts only) is kept per entry under `inventory`, with the
telemetry facts (vm/guest/telemetry.py: hosts, silent senders, hooked senders, disclosure) merged in as tel_* keys,
and obfuscation facts (vm/guest/obfuscation.py: decoder-to-sink flows outside bundles, decoded call names) as obf_* keys.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import posixpath
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "pipeline"))
from summarise_scans import RANK, REPORTS, UNPARSED, findings  # noqa: E402
import withheld  # noqa: E402

RESULTS = Path.home() / ".cache" / "awesome-agent-skills" / "vm" / "results"
OUT = ROOT / "data" / "scans.json"
# Coverage is per tool: a skill has a tool's record only when that tool left its report for it, in any
# batch (a later batch replaces an earlier one for the same tool). An absent report means "not
# scanned by that tool", never "no findings": SkillSpector --recursive silently details at most 30
# skills per run. A crash leaves an unparsable report, recorded as an error.
# Rules that fire because of staging, not the skill: one folder is staged, so links to sibling skills break.
STAGING_ARTIFACTS = {("agnix", "REF-002")}
# agnix REF-001 ("Import target not found: @x") also fires on decorators, npm packages and `skill:` names, and on
# repo files outside the one staged folder. Kept only when the target is a file path absent from the repo tree
# at the scanned commit (harvest trees/); a repo without a tree keeps every REF-001.
HARVEST = Path.home() / ".cache" / "awesome-agent-skills" / "harvest"
FILE_EXT = re.compile(r"\.(md|mdx|markdown|txt|ya?ml|json|toml|py|js|mjs|cjs|ts|tsx|jsx|sh|ps1|html|css|csv|xml|ini|cfg|sql|rb|go|rs|java)$", re.I)


class Trees:
    """Repo file paths from the newest harvest run that has trees, loaded per repo on first use."""

    def __init__(self, root: Path = HARVEST):
        runs = sorted((p for p in root.glob("*/trees") if any(p.glob("*.json.gz"))), key=lambda d: d.stat().st_mtime)
        self.files = {f.name.split("@")[0].replace("__", "/", 1).lower(): f for f in runs[-1].glob("*.json.gz")} if runs else {}
        self.cache: dict[str, tuple[set, set] | None] = {}

    def get(self, repo: str):
        repo = repo.lower()
        if repo not in self.cache:
            f = self.files.get(repo)
            paths = {x["path"] for x in json.load(gzip.open(f))["tree"]} if f else None
            self.cache[repo] = (paths, {posixpath.dirname(x) for x in paths}) if paths else None
        return self.cache[repo]


def ref_unresolved(trees: Trees, entry: dict, file: str, message: str) -> bool:
    """True when a REF-001 target is a file path missing from the repo (a real broken reference)."""
    t = trees.get(entry["repo"])
    if t is None:
        return True
    paths, dirs = t
    tgt = message.split("not found: ", 1)[-1].lstrip("@").split("#")[0].strip()
    rest = file.split("/", 2)[2] if file.count("/") >= 2 else ""      # chunk path: skills/<folder>/<rest>
    here = posixpath.dirname(posixpath.join(entry["dir"], rest))
    for c in (posixpath.join(here, tgt), tgt, posixpath.join(entry["dir"], tgt)):
        c = posixpath.normpath(c)
        if c in paths or c in dirs:
            return False
    return bool(FILE_EXT.search(tgt))
# Tools without meaningful severities: keep their rule ids at any level (skills-ref: which spec checks fail).
ALL_RULES = {"skills-ref"}


INV_KEYS = ("deps", "unpinned", "lifecycle", "pep723", "docker_loose", "fetch_run", "n_code_hosts", "links_out",
            "active_docs", "html_comments", "b64", "sensitive", "manifests")


def compact_inventory(r: dict) -> dict:
    """Nonzero facts only; hosts kept as a short list (names, not URLs)."""
    out = {k: r[k] for k in INV_KEYS if r.get(k)}
    if r.get("code_hosts"):
        out["hosts"] = [h for h in r["code_hosts"] if len(h) <= 60][:8]
    return out


def compact_telemetry(r: dict) -> dict:
    """Telemetry facts (vm/guest/telemetry.py) as inventory keys; nothing when there is nothing to say."""
    out = {}
    if r.get("hosts"):
        out["tel_hosts"] = [h for h in r["hosts"] if len(h) <= 60][:6]
    if r.get("silent_senders"):
        out["silent_sender"] = r["silent_senders"]
    if r.get("hooked_senders"):
        out["hooked_sender"] = r["hooked_senders"]
    if out and not r.get("disclosed_in"):
        out["tel_undisclosed"] = 1
    if out and r.get("opt_out_env"):
        out["tel_opt_out"] = [e for e in r["opt_out_env"] if len(e) <= 40][:4]
    return out


def compact_obfuscation(r: dict) -> dict:
    """Obfuscation facts (vm/guest/obfuscation.py): decoder-to-sink flows outside minified bundles (a flow in a
    bundle is a window over unrelated code) and call names that are themselves decoded. Counts of integer
    sequences, sinks and blobs stay out: on their own they say nothing."""
    out = {}
    flows = [n for n in r.get("notes") or [] if n.get("fact") == "flow" and not n.get("minified")]
    if flows:
        out["obf_flow"] = len(flows)
        out["obf_ops"] = sorted({f"{'+'.join(n.get('decoders') or ['?'])}>{n.get('sink', '?')}" for n in flows})[:4]
        out["obf_lines"] = sorted({f"{n['file'][-80:]}:{n['line']}" for n in flows})[:4]
    hidden = sum((r.get("hidden_names") or {}).values())
    if hidden:
        out["obf_hidden"] = hidden
    return out


def collect(dirs: list[Path], trees: Trees | None = None) -> dict:
    trees = trees or Trees()
    held = withheld.load()                          # left out, batch counts included, until their date
    skills: dict[str, dict] = {}
    inventory: dict[str, dict] = {}
    plugin_of: dict[str, str] = {}
    batches = []
    for d in dirs:
        man = d / "manifest.json"
        if not man.exists():
            continue
        manifest = [e for e in json.loads(man.read_text()) if e["skill"] not in held]
        tools = [t for t in REPORTS if (d / t).is_dir() and any((d / t).iterdir())]
        sid_to_skill = {e["id"]: e["skill"] for e in manifest}
        by_id = {e["id"]: e for e in manifest}
        have = {t: {e["id"] for e in manifest if (d / t / f"{e['id']}.{REPORTS[t]}").exists()} for t in tools}
        for t in tools:
            for sid in have[t]:
                skills.setdefault(sid_to_skill[sid], {})[t] = {"worst": "", "high": 0, "rules": []}
        for tool, sid, rule, sev, _, file, _, msg in findings(d):
            if sid not in have.get(tool, ()) or (tool, rule) in STAGING_ARTIFACTS:
                continue
            if (tool, rule) == ("agnix", "REF-001") and not ref_unresolved(trees, by_id[sid], file, msg):
                continue
            rec = skills[sid_to_skill[sid]][tool]
            if not rec["worst"] or RANK[sev] < RANK[rec["worst"]]:
                rec["worst"] = sev
            if RANK[sev] <= 1:
                rec["high"] += 1
            if (RANK[sev] <= 1 or tool in ALL_RULES) and rule not in rec["rules"] and len(rec["rules"]) < 5:
                rec["rules"].append(rule)
        for tool, sid in UNPARSED:
            if sid in have.get(tool, ()):
                skills[sid_to_skill[sid]][tool]["error"] = True
        UNPARSED.clear()
        for e in manifest:                              # the inventory: facts, not findings
            f = d / "inventory" / f"{e['id']}.json"
            if f.exists():
                try:
                    inventory[e["skill"]] = compact_inventory(json.loads(f.read_text()))
                except ValueError:
                    pass
            f = d / "telemetry" / f"{e['id']}.json"
            if f.exists():
                try:
                    tel = compact_telemetry(json.loads(f.read_text()))
                except ValueError:
                    tel = {}
                if tel:
                    inventory.setdefault(e["skill"], {}).update(tel)
            f = d / "obfuscation" / f"{e['id']}.json"
            if f.exists():
                try:
                    obf = compact_obfuscation(json.loads(f.read_text()))
                except ValueError:
                    obf = {}
                if obf:
                    inventory.setdefault(e["skill"], {}).update(obf)
        roots = {}
        for e in manifest:
            if e.get("kind") == "plugin":
                roots.setdefault(e["repo"].lower(), []).append((e["dir"], e["skill"]))
        for e in manifest:
            if e.get("kind", "skill") != "skill":
                continue
            under = [(r, pid) for r, pid in roots.get(e["repo"].lower(), []) if r == "" or e["dir"] == r or e["dir"].startswith(r + "/")]
            if under:
                plugin_of[e["skill"]] = max(under, key=lambda x: len(x[0]))[1]
        complete = sum(1 for e in manifest if all(e["id"] in have[t] for t in tools))
        facts = [t for t in ("inventory", "telemetry", "obfuscation") if (d / t).is_dir()]
        batches.append({"results": d.name, "tools": tools, "facts": facts,
                        "skills": complete if tools else 0, "incomplete": len(manifest) - complete if tools else 0})
    plugins = {k: skills.pop(k) for k in [k for k in skills if k.startswith("plugin-")]}
    return {"collected": dt.date.today().isoformat(), "batches": batches, "skills": skills, "plugins": plugins,
            "plugin_of": plugin_of, "inventory": inventory}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dirs", nargs="*", type=Path, help="results dirs (default: every one under the cache with a manifest)")
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args(argv)
    dirs = a.dirs or sorted(p.parent for p in RESULTS.glob("*/manifest.json"))
    data = collect(dirs)
    a.out.write_text(json.dumps(data, separators=(",", ":")) + "\n", encoding="utf-8")
    n = len(data["skills"])
    hi = sum(1 for s in data["skills"].values() if any(RANK.get(t["worst"], 9) <= 1 for t in s.values()))
    per_tool = {t: sum(1 for s in data["skills"].values() if t in s) + sum(1 for s in data["plugins"].values() if t in s)
                for t in REPORTS}
    print(f"collect: {len(data['plugins'])} plugin roots, {len(data['plugin_of'])} skills inside one, "
          f"{len(data['inventory'])} inventories")
    print(f"collect: {len(data['batches'])} batches, {n} skills, {hi} with a HIGH+ finding from any tool -> {a.out}")
    print("skills with a report, per tool: " + ", ".join(f"{t} {k}" for t, k in per_tool.items() if k))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
