#!/usr/bin/env python3
"""Parse a harvest run into data/skills.json: one record per distinct skill, with structural flags.

Offline. Reads ~/.cache/awesome-agent-skills/harvest/<run>/ (manifest, trees, blobs). All of it is
untrusted text, and none of it is printed: the output is the JSON file plus aggregate counts. Run
with `python3 -I`.

A record holds the name, a short description with invisible characters stripped, links, tier,
repo licence and stars, what the skill folder contains (from the tree; scripts are not fetched), a
keyword category, and flags from curation/schema.yaml `skills.flags`. It holds no skill body.
Flags are facts about the file (a frontmatter key, a syntax, a code point), not verdicts.

Copies: SKILL.md files that are byte-identical (same git blob) or identical after normalising
whitespace and case form one cluster. The canonical member is the best tier, then most stars, then
the shortest path; the others become a count and an "also in" list.
"""
from __future__ import annotations

import argparse
import bisect
import gzip
import hashlib
import json
import re
import sys
import urllib.parse
from collections import Counter
from pathlib import Path, PurePosixPath

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from untrusted import addressed_to_agents, invisible, strip_invisible  # noqa: E402
import withheld  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CACHE = Path.home() / ".cache" / "awesome-agent-skills" / "harvest"
OUT = ROOT / "data" / "skills.json"
LLM_CATS = ROOT / "data" / "llm-categories.json"   # pipeline/categorise.py
LLM_LABELS = ROOT / "data" / "llm-labels.json"     # pipeline/categorise_trial.py --all
DRAFT = ROOT / "curation" / "taxonomy-draft.yaml"
TIER_ORDER = ["official", "anthropic-marketplace", "marketplace-source"]

FM_LINE = re.compile(r"^([A-Za-z][\w-]*):[ \t]?(.*)$")
BARE_BASH = re.compile(r"(?<![\w(])Bash(?![\w(])|Bash\(\s*\*?\s*(?::\s*\*)?\s*\)")
BANG_SHELL = re.compile(r"(?:^|(?<=\s))!`[^`\n]+`|^\s*```!", re.MULTILINE)   # `!` at line start or after space
PUSHY = re.compile(r"\b(?:always|must) use this\b|\byou must use\b|\bproactively\b|\b(?:must|should) always\b")
PIPE_TO_SHELL = re.compile(r"\b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")
SANDBOX_OFF = re.compile(r"dangerouslyDisableSandbox\W{0,3}\s*(?:[:=]|to)\s*\W?true", re.I)
FIXTURE = re.compile(r"(?:^|/)(?:tests?|__tests__|fixtures?|examples?|samples?|testdata|test-data)(?:/|$)", re.I)
# File inventory from the git tree alone (names, modes, sizes; no contents): what a skill ships that a text
# scanner cannot read, or that runs or installs something on its own.
BINARY_EXT = {"so", "dll", "dylib", "exe", "bin", "wasm", "pyc", "pyo", "jar", "class", "node", "o", "a", "msi", "dmg", "apk", "elf"}
ARCHIVE_EXT = {"zip", "tar", "gz", "tgz", "bz2", "xz", "7z", "rar", "whl", "egg", "nupkg", "vsix", "crx"}
ACTIVE_EXT = {"svg", "html", "htm", "xhtml", "pdf", "hta", "xsl"}
MANIFESTS = {"requirements.txt", "package.json", "pyproject.toml", "setup.py", "setup.cfg", "pipfile", "dockerfile",
             "docker-compose.yml", "compose.yaml", "go.mod", "cargo.toml", "gemfile", "environment.yml", "makefile", "uv.lock"}
STDLIB_SHADOW = {"json", "os", "sys", "re", "subprocess", "typing", "pathlib", "logging", "random", "socket", "ssl", "http",
                 "urllib", "base64", "hashlib", "shutil", "tempfile", "time", "datetime", "collections", "functools", "requests"}
BIG_FILE = 1_000_000
SCRIPT_EXT = {"py", "sh", "bash", "zsh", "js", "mjs", "cjs", "ts", "rb", "pl", "ps1", "go", "rs", "php", "lua"}
# Code a skill ships, by file extension (the folder's files from the tree; contents are not fetched)
LANG_EXT = {"py": "Python", "sh": "Shell", "bash": "Shell", "zsh": "Shell", "js": "JavaScript", "mjs": "JavaScript",
            "cjs": "JavaScript", "ts": "TypeScript", "tsx": "TypeScript", "jsx": "JavaScript", "rb": "Ruby", "pl": "Perl",
            "ps1": "PowerShell", "go": "Go", "rs": "Rust", "php": "PHP", "lua": "Lua", "java": "Java", "kt": "Kotlin",
            "swift": "Swift", "cs": "C#", "r": "R", "sql": "SQL", "c": "C", "cpp": "C++", "dart": "Dart"}
# Secrets a SKILL.md names: environment-variable style identifiers ending in a credential word
SECRET_VAR = re.compile(r"\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:API_KEY|KEY|TOKEN|SECRET|PASSWORD|PAT|CREDENTIALS?)\b")
NOT_SECRET = {"PRIMARY_KEY", "FOREIGN_KEY", "SORT_KEY", "PARTITION_KEY", "UNIQUE_KEY", "CACHE_KEY", "IDEMPOTENCY_KEY"}
URL_HOST = re.compile(r"https?://([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
# Hosts inside fenced code or on a line that fetches something are ones the agent may be told to contact;
# the rest are documentation links. SKILL.md text only: shipped scripts are not read here.
FENCE = re.compile(r"```.*?```", re.S)
FETCH_LINE = re.compile(r"^.*\b(?:curl|wget|fetch|requests\.(?:get|post)|urllib|httpx|axios|Invoke-WebRequest|iwr|git clone|npx|pip install)\b.*$", re.M | re.I)
# Writing system of the description, by the first matching code point range (Latin covers most languages)
SCRIPTS = [("zh", 0x4E00, 0x9FFF), ("ja", 0x3040, 0x30FF), ("ko", 0xAC00, 0xD7AF), ("cyrillic", 0x0400, 0x04FF),
           ("arabic", 0x0600, 0x06FF), ("devanagari", 0x0900, 0x097F)]


def writing_system(text: str) -> str:
    """Script of the description: ja if any kana (kanji alone reads as zh), else the first non-Latin script found."""
    found = {k for ch in text for k, lo, hi in SCRIPTS if lo <= ord(ch) <= hi}
    for k in ["ja"] + [k for k, _, _ in SCRIPTS]:
        if k in found:
            return k
    return "latin"


PLATFORM_DIRS = [(".claude/skills/", "claude-code"), (".codex/skills/", "codex"), (".github/skills/", "copilot"),
                 (".cursor/", "cursor"), (".gemini/", "gemini-cli"), (".agents/skills/", "agents-dir")]
PLATFORM_OWNERS = {"openai": "codex", "google-gemini": "gemini-cli", "openclaw": "openclaw",
                   "nousresearch": "hermes", "github": "copilot"}


def skill_dir(path: str) -> str:
    d = str(PurePosixPath(path).parent)
    return "" if d == "." else d


def split_frontmatter(text: str) -> tuple[str | None, str]:
    """(frontmatter text or None, body). The frontmatter is between a first line `---` and the next."""
    text = text.lstrip("\ufeff")
    if not text.startswith("---"):
        return None, text
    lines = text.split("\n")
    if lines[0].strip() != "---":
        return None, text
    for i in range(1, len(lines)):
        if lines[i].rstrip() == "---":
            return "\n".join(lines[1:i]), "\n".join(lines[i + 1:])
    return None, text


def parse_frontmatter(fm: str) -> tuple[dict, bool]:
    """(fields, strict) where strict says yaml.safe_load accepted it. Otherwise read top-level
    `key: value` lines leniently, as Claude Code does, so the record still has a name."""
    try:
        d = yaml.safe_load(fm)
        if isinstance(d, dict):
            return d, True
    except yaml.YAMLError:
        pass
    out = {}
    for line in fm.split("\n"):
        m = FM_LINE.match(line)
        if m:
            v = m[2].strip()
            if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
                v = v[1:-1]
            out[m[1]] = v
    return out, False


def text_field(v, n: int) -> str:
    """A frontmatter value as display text: str, invisible characters stripped, whitespace
    collapsed, at most n characters."""
    if v is None:
        return ""
    if isinstance(v, (list, tuple)):
        v = " ".join(str(x) for x in v)
    s, _ = strip_invisible(str(v))
    s = re.sub(r"\s+", " ", s).strip()
    return s if len(s) <= n else s[: n - 1] + "\u2026"


def compile_categories(cats: dict) -> list[tuple[str, list[re.Pattern]]]:
    out = []
    for key, c in cats.items():
        pats = []
        for w in c.get("words") or []:
            w = str(w).lower()
            prefix = w.endswith("*")
            w = w.rstrip("*")
            pats.append(re.compile(r"(?<!\w)" + re.escape(w) + ("" if prefix else r"(?:e?s)?(?!\w)")))   # plural too
        out.append((key, pats))
    return out


def categorise(cats, name: str, plugin: str, desc: str) -> str:
    """Keyword category from the name, the plugin name and the description (not the path, whose
    `plugins/` and `skills/` segments say nothing about the subject)."""
    name_l = name.lower().replace("-", " ").replace("_", " ")
    text = f"{name_l} {plugin.lower().replace('-', ' ').replace('_', ' ')} {desc.lower()}"
    best, score = "uncategorised", 0
    for key, pats in cats:
        s = sum(1 + (1 if p.search(name_l) else 0) for p in pats if p.search(text))
        if s > score:
            best, score = key, s
    return best


def platform(repo: str, path: str, plugin_dir: str | None) -> str:
    p = "/" + path
    for marker, plat in PLATFORM_DIRS:
        if "/" + marker in p:
            return plat
    if plugin_dir is not None:
        return "claude-plugin"
    return PLATFORM_OWNERS.get(repo.split("/")[0].lower(), "generic")


class Tree:
    """A repo tree with prefix lookups (paths sorted; '0' is the character after '/')."""

    def __init__(self, entries: list[dict]):
        blobs = sorted((e["path"], e.get("size", 0), e.get("mode", "")) for e in entries if e.get("type") == "blob")
        self.paths = [p for p, _, _ in blobs]
        self.sizes = [s for _, s, _ in blobs]
        self.modes = [m for _, _, m in blobs]
        self.all = set(self.paths)

    def under(self, d: str):
        if not d:
            return range(len(self.paths))
        return range(bisect.bisect_left(self.paths, d + "/"), bisect.bisect_left(self.paths, d + "0"))

    def plugin_root(self, d: str) -> str | None:
        parts = PurePosixPath(d).parts if d else ()
        for i in range(len(parts), -1, -1):
            root = "/".join(parts[:i])
            if (f"{root}/" if root else "") + ".claude-plugin/plugin.json" in self.all:
                return root
        return None


def skill_record(repo_rec: dict, tree: Tree, skill_dirs: set[str], sk: dict, text: str, cats) -> dict:
    repo, sha = repo_rec["meta"]["full_name"] or repo_rec["repo"], repo_rec["sha"]
    d = skill_dir(sk["path"])
    folder = PurePosixPath(d).name if d else repo.split("/")[1]
    fm_text, body = split_frontmatter(text)
    fields, strict = parse_frontmatter(fm_text) if fm_text is not None else ({}, True)
    name = text_field(fields.get("name"), 80) or folder
    desc = text_field(fields.get("description"), 200)
    tools = fields.get("allowed-tools", fields.get("allowed_tools"))
    tools_s = " ".join(str(x) for x in tools) if isinstance(tools, (list, tuple)) else str(tools or "")
    # A lone VS15/VS16 is presentation noise (GitHub anchor slugs keep it after the emoji: "](#\ufe0f-x)").
    flags, cps = [], [c for c in invisible(text) if c not in ("U+FE0E", "U+FE0F")]
    if any(c.startswith("U+E00") for c in cps):
        flags.append("tag_chars")
    if cps:
        flags.append("invisible")
    if BANG_SHELL.search(body):
        flags.append("bang_shell")
    if "hooks" in fields:
        flags.append("fm_hooks")
    if BARE_BASH.search(tools_s):
        flags.append("bare_bash")
    plug = tree.plugin_root(d)
    if plug is not None:
        pre = f"{plug}/" if plug else ""
        if pre + "hooks/hooks.json" in tree.all:
            flags.append("plugin_hooks")
        if pre + ".mcp.json" in tree.all:
            flags.append("plugin_mcp")
    if PIPE_TO_SHELL.search(text):
        flags.append("pipe_to_shell")
    if SANDBOX_OFF.search(text):
        flags.append("sandbox_off")
    phrases = [x for x in addressed_to_agents(str(fields.get("description") or "")) if PUSHY.search(x)]
    if phrases:
        flags.append("agent_directed")
    if fm_text is None:
        flags.append("no_frontmatter")
    elif not strict:
        flags.append("yaml_invalid")
    if fm_text is not None and str(fields.get("name") or "").strip() not in ("", folder):
        flags.append("name_mismatch")
    if FIXTURE.search(d):
        flags.append("fixture")
    files = n_bytes = 0
    exts, scripts = Counter(), False
    inv, man, shadow = Counter(), set(), set()
    nested = {s for s in skill_dirs if s != d and (not d or s.startswith(d + "/"))}
    for i in tree.under(d):
        p = tree.paths[i]
        if any(p.startswith(n + "/") for n in nested):
            continue
        files += 1
        n_bytes += tree.sizes[i] or 0
        rel = p[len(d) + 1:] if d else p
        ext = rel.rsplit(".", 1)[-1].lower() if "." in rel.rsplit("/", 1)[-1] else ""
        if ext:
            exts[ext] += 1
        if ext in SCRIPT_EXT or rel.startswith("scripts/"):
            scripts = True
        base, mode = rel.rsplit("/", 1)[-1].lower(), tree.modes[i]
        if mode == "120000":
            inv["link"] += 1
        elif mode == "100755":
            inv["exec"] += 1
        if ext in BINARY_EXT or "__pycache__/" in rel:
            inv["bin"] += 1
        if ext in ARCHIVE_EXT:
            inv["arc"] += 1
        if ext in ACTIVE_EXT:
            inv["active"] += 1
        if base in MANIFESTS or base.startswith("requirements") and ext == "txt":
            man.add(base)
        if ext == "pth" or base in ("sitecustomize.py", "usercustomize.py") or (ext == "py" and base[:-3] in STDLIB_SHADOW):
            shadow.add(base)
        if (tree.sizes[i] or 0) > BIG_FILE:
            inv["big"] += 1
        if ext == "md" and base != "skill.md":
            inv["md"] += 1
    langs = sorted({LANG_EXT[e] for e in exts if e in LANG_EXT})
    secrets = [v for v in dict.fromkeys(SECRET_VAR.findall(text)) if v not in NOT_SECRET][:5]
    hosts = list(dict.fromkeys(h.lower() for h in URL_HOST.findall(text)))
    code_text = "\n".join(FENCE.findall(text) + FETCH_LINE.findall(text))
    code_hosts = list(dict.fromkeys(h.lower() for h in URL_HOST.findall(code_text)))
    path_q = urllib.parse.quote(d)
    url = f"https://github.com/{repo}/tree/{sha}/{path_q}" if d else f"https://github.com/{repo}/blob/{sha}/{urllib.parse.quote(sk['path'])}"
    body_norm = re.sub(r"\s+", " ", body).strip().lower()
    return {
        "id": hashlib.sha1(f"{repo.lower()}/{d}".encode()).hexdigest()[:12],
        "name": name, "desc": desc, "repo": repo, "dir": d, "url": url,
        "tier": repo_rec["tier"], "source": repo_rec["source"],
        "category": categorise(cats, name, PurePosixPath(plug).name if plug else "", desc),
        "platform": platform(repo, d + "/", plug),
        "plugin": (PurePosixPath(plug).name or repo.split("/")[1]) if plug is not None else "",
        "licence": repo_rec["meta"].get("licence") or "", "fm_licence": text_field(fields.get("license"), 40),
        "stars": repo_rec["meta"].get("stars") or 0, "pushed": (repo_rec["meta"].get("pushed_at") or "")[:10],
        "files": files, "bytes": n_bytes, "scripts": scripts, "exts": [e for e, _ in exts.most_common(6)],
        "inv": {k: v for k, v in inv.items() if v}, "manifests": sorted(man)[:6], "shadow": sorted(shadow)[:4],
        "langs": langs, "desc_lang": writing_system(desc), "secrets": [x[:48] for x in secrets],
        "hosts": [h[:60] for h in hosts[:6]], "n_hosts": len(hosts), "n_code_hosts": len(code_hosts),
        "flags": flags, "allowed_tools": text_field(tools_s, 160), "phrases": phrases[:3], "codepoints": cps[:6],
        "_blob": sk["blob"], "_norm": hashlib.sha256(body_norm.encode()).hexdigest()[:16] if len(body_norm) >= 200 else None,
    }


def cluster(records: list[dict]) -> list[dict]:
    """Union records sharing a blob or a normalised body; keep one canonical per cluster."""
    parent = list(range(len(records)))

    def find(i):
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i
    first: dict[str, int] = {}
    for i, r in enumerate(records):
        for key in (f"b:{r['_blob']}", f"n:{r['_norm']}" if r["_norm"] else None):
            if key is None:
                continue
            if key in first:
                parent[find(i)] = find(first[key])
            else:
                first[key] = i
    groups: dict[int, list[dict]] = {}
    for i, r in enumerate(records):
        groups.setdefault(find(i), []).append(r)
    out = []
    for members in groups.values():
        members.sort(key=lambda r: (TIER_ORDER.index(r["tier"]), -r["stars"], len(r["dir"]), r["repo"].lower(), r["dir"]))
        canon = dict(members[0])
        others = members[1:]
        canon["copies"] = len(others)
        canon["also_in"] = sorted({m["repo"] for m in others if m["repo"] != canon["repo"]})[:8]
        out.append(canon)
    for r in out:
        r.pop("_blob"), r.pop("_norm")
    return out


def parse_run(run: Path, schema: dict) -> dict:
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    cats = compile_categories(schema["skills"]["categories"])
    records, repos = [], []
    for rr in manifest["repos"]:
        repos.append({"repo": (rr.get("meta") or {}).get("full_name") or rr["repo"], "tier": rr["tier"],
                      "source": rr["source"], "sha": rr.get("sha"), "error": rr.get("error"),
                      "truncated": rr.get("truncated", False), "skill_files": len(rr.get("skills", [])),
                      "stars": (rr.get("meta") or {}).get("stars"), "plugins": len(rr.get("plugins") or [])})
        if rr.get("error"):
            continue
        tree_path = run / "trees" / f"{rr['repo'].replace('/', '__')}@{rr['sha']}.json.gz"
        tree = Tree(json.loads(gzip.decompress(tree_path.read_bytes())).get("tree", []))
        dirs = {skill_dir(s["path"]) for s in rr["skills"]}
        for sk in rr["skills"]:
            blob = run / "blobs" / f"{sk['blob']}.md"
            if not blob.exists():
                continue
            text = blob.read_bytes().decode("utf-8", errors="replace")
            records.append(skill_record(rr, tree, dirs, sk, text, cats))
    found = len(records)
    skills = cluster(records)
    held = withheld.load()                  # the whole row stays out until its date, counts included
    for r in [r for r in skills if r["id"] in held]:
        skills.remove(r)
        found -= 1 + r["copies"]
        for rp in repos:
            if rp["repo"] == r["repo"]:
                rp["skill_files"] -= 1 + r["copies"]
    llm = LLM_CATS.exists() and json.loads(LLM_CATS.read_text(encoding="utf-8")).get("labels", {})
    for r in skills:          # categorise.py labels only what the keyword rules left uncategorised
        c = (llm or {}).get(r["id"])
        if r["category"] == "uncategorised" and c and c != "none" and c in schema["skills"]["categories"]:
            r["category"], r["cat_src"] = c, "llm"
    # categorise_trial.py --all: the draft label set (1-3 subjects, main first) plus vendor, audience, actions and
    # the languages a skill is about, from its name and description. Kept beside `category` until the set is adopted.
    # cat_change compares them: "same" (main subject is what the old category maps to), "secondary" (it is
    # among the other subjects) or "moved".
    lab = json.loads(LLM_LABELS.read_text(encoding="utf-8"))["labels"] if LLM_LABELS.exists() else {}
    tax = yaml.safe_load(DRAFT.read_text(encoding="utf-8")) if lab else {}
    merge, old_map = tax.get("merge", {}), tax.get("old_map", {})
    for r in skills:
        if (v := lab.get(r["id"])):
            subj = list(dict.fromkeys(merge.get(c, c) for c in v["cats"]))
            was = set(old_map.get(r["category"], []))
            r.update(subjects=subj, vendor=v["vendor"], audience=v.get("audience", ""),
                     actions=v.get("actions", []), about_langs=v.get("langs", []),
                     cat_change="same" if subj[0] in was else "secondary" if was & set(subj) else "moved")
    skills.sort(key=lambda r: (TIER_ORDER.index(r["tier"]), -r["stars"], r["repo"].lower(), r["dir"]))
    summary = {"skill_files": found, "distinct": len(skills),
               "by_tier": dict(Counter(r["tier"] for r in skills)),
               "by_category": dict(Counter(r["category"] for r in skills).most_common()),
               "by_platform": dict(Counter(r["platform"] for r in skills).most_common()),
               "by_flag": dict(Counter(f for r in skills for f in r["flags"]).most_common()),
               "with_scripts": sum(r["scripts"] for r in skills),
               "repos": len(repos), "repo_errors": sum(bool(r["error"]) for r in repos),
               "truncated_trees": sum(r["truncated"] for r in repos)}
    out = {"run": manifest["run"], "fetched": manifest["fetched"], "summary": summary, "repos": repos, "skills": skills}
    if lab:     # labels for the page, and how the new subjects line up with the old categories
        out["subjects_meta"] = {"model": json.loads(LLM_LABELS.read_text(encoding="utf-8")).get("model", ""),
                                "subjects": {k: c["label"] for k, c in tax["categories"].items() if k not in merge}
                                | {"other": "Other"}, **tax["labels"]}
        summary["cat_change"] = dict(Counter(r.get("cat_change", "") for r in skills))
        summary["by_subject"] = dict(Counter(r["subjects"][0] for r in skills if r.get("subjects")).most_common())
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run", help="run directory under the cache (default: the newest with a manifest)")
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args(argv)
    if a.run:
        run = CACHE / a.run
    else:
        # newest by manifest time, not by name: a probe run ("probe-limit3") sorts after "20261023"
        runs = sorted((p.parent for p in CACHE.glob("*/manifest.json")), key=lambda d: (d / "manifest.json").stat().st_mtime)
        if not runs:
            print("skills: no harvest run found; run pipeline/harvest.py first", file=sys.stderr)
            return 1
        run = runs[-1]
    schema = yaml.safe_load((ROOT / "curation" / "schema.yaml").read_text(encoding="utf-8"))
    data = parse_run(run, schema)
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")
    s = data["summary"]
    print(f"skills: {s['skill_files']} SKILL.md -> {s['distinct']} distinct skills from {s['repos']} repos "
          f"({s['repo_errors']} errors, {s['truncated_trees']} truncated trees) -> {a.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
