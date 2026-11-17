#!/usr/bin/env python3
"""Sort credential findings into buckets without printing a value: secrets_check.py RESULTS STAGED_TAR [--out TSV]

gitleaks (every rule), hol-guard HARDCODED_SECRET and agentshield's secrets category point at a line
that may hold a live credential, so lines.py (which prints the line) is the wrong tool for them. This
reads each pointed line from the staged tar in memory (never extracted), finds the value again from the
rule's shape, and keeps only features of it: length, character classes, entropy, a documented public
prefix, a short hash (to see one value reused across skills) and the line with the value and any other
long high-entropy token masked. Buckets, first match wins:

  unlocated     no line, no value found on it, or only a URL
  unlocated     ... or the value is part of a URL that is not in a credential field (?token=, user:pass@)
  placeholder   YOUR_/xxx/<...>/example/dummy/redacted/securepassword123..., repeated or sequential characters,
                an ARN with an AWS documentation account id (123456789012, 111122223333, ...)
  reference     an env var, template or code expression ($X, ${X}, {{x}}, {x.y}, .Values.x, process.env,
                UPPER_SNAKE, a.b)
  public        a test or publishable key format (Stripe sk_test_/pk_, PostHog phc_, Datadog pub client
                token) or a value the
                issuer publishes (KNOWN_PUBLIC, by hash only)
  low-entropy   shorter than 16, entropy below 3.0, joined or camelCase words or a path of words
                (dsb-key-name, collection/primitives, generated_32_byte_hex),
                or shorter than the issuer's format (a Stripe key under 32 characters)
  doc-context   the rest of the line says example/sample/emulator/well-known/redact/mock
  allowlisted   the file is a scanner allowlist (.gitallowed, .gitleaksignore, .secrets.baseline)
  test-path     the file is a test, fixture, mock, spec, example or sample
  identifier    an ARN or a piece of one, a CLI flag or CSS variable (--x), name=value where the name is not
                a credential name (sslmode=..., spring.datasource.url=...)
  identifier    gitleaks generic or hol-guard rule, and a UUID or a name that is not a credential name
                (fileKey, GlobalKey; `key` in .mdx/.jsx/.tsx): Figma file keys, record ids, React keys
  plausible     a real-looking value; look at its masked line, never test it against the issuer

Nothing here calls a network service: using someone else's key to see whether it works is not ours to do.
"""
from __future__ import annotations

import argparse
import collections
import csv
import hashlib
import math
import re
import sys
import tarfile
from pathlib import Path

BUCKETS = ["unlocated", "placeholder", "reference", "public", "low-entropy", "doc-context", "allowlisted", "test-path", "identifier",
           "plausible"]

# Shapes gitleaks' own rules describe; the group is the value.
SHAPES = {
    "aws-access-token": re.compile(r"\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b"),
    "gcp-api-key": re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})"),
    "stripe-access-token": re.compile(r"\b((?:sk|rk|pk)_(?:test|live|prod)_[0-9A-Za-z]{10,99})"),
    "curl-auth-user": re.compile(r"""(?:-u|-U|--user|--proxy-user)\s*['"]?[^\s:'"]*:([^\s'"]+)"""),
    "curl-auth-header": re.compile(
        r"""(?i)(?:authorization\s*:\s*(?:(?:bearer|basic|token)\s+)?|(?:bearer|token)\s+|(?:api[-_]?key|x-[\w-]*(?:key|token))\s*:\s*)"""
        r"""([^\s'"\\]+)"""),
}
ASSIGN = re.compile(r"""(?i)([\w.-]*(?:key|token|secret|passw(?:or)?d|pwd|auth|credential|bearer)[\w.-]*)['"]?\s*(?:[:=]|=>|:=)+\s*"""
                    r"""(?:[rbf]?['"`])?([^\s'"`,;)}\]]+)""")
TOKEN = re.compile(r"[A-Za-z0-9_\-+/=.~]{16,}")
PREFIXES = ["sk_live_", "sk_test_", "rk_live_", "rk_test_", "pk_live_", "pk_test_", "sk-ant-", "sk-proj-", "sk-",
            "AKIA", "ASIA", "AIza", "ghp_", "gho_", "ghs_", "github_pat_", "glpat-", "xoxb-", "xoxp-", "ATATT", "hf_", "phc_"]
# sha256[:10] of values their issuer documents as public, so the value itself never sits in this file
KNOWN_PUBLIC = {"aa65474395": "Azure Cosmos DB emulator well-known key"}
REFERENCE = re.compile(r"""^(?:\$|%|\{|<%|\.[A-Za-z]\w*\.|process\.env|os\.environ|os\.getenv|env\.|getenv|secrets\.|vars\.)|^[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+$|^[A-Z]{3,12}$"""
                       r"""|^[a-z_][\w]*(?:\.[a-z_][\w]*)+(?:\(\))?$|^[a-z_]\w*\(|\$\{""")
PLACEHOLDER = re.compile(r"""(?i)your|xxx|placeholder|example|dummy|fake|sample|changeme|change[-_]me|redacted|replace|insert"""
                         r"""|todo|<|>|\*\*\*|securepass|passw(?:or)?d\d+|[-_]here\b|\.\.\.|\bmy[-_]?(?:api|key|token|secret)|abc123|demo|foobar|lorem|test[-_]?(?:key|token)"""
                         r"""|^(?:secret|token|password|apikey|api_key|key)$""")
TEST_PATH = re.compile(r"(?i)(?:^|/)[\w-]*(?:tests?|fixtures?|mocks?|testdata|spec|examples?|samples?)[\w-]*/|_test\.|\.test\."
                       r"|\.spec\.|(?:^|/)test_[^/]*$|[-_.](?:sample|example)s?\.\w+$")
SEQUENCES = ("0123456789", "abcdefghijklmnopqrstuvwxyz")
DOC_LINE = re.compile(r"(?i)\b(?:examples?|samples?|emulator|well[- ]known|placeholder|dummy|fake|mock|redact\w*|never (?:acquire|use) a real)\b")
UUID = re.compile(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
CRED_NAME = re.compile(r"(?i)secret|passw|pwd|token|api[-_ ]?key|access[-_ ]?key|private[-_ ]?key|credential|auth|bearer|(?-i:^[A-Z0-9_]*KEY$)")
JSX = re.compile(r"\.(?:mdx|jsx|tsx|vue|svelte)$")
ALLOWLIST_FILE = re.compile(r"(?:^|/)(?:\.gitallowed|\.gitleaksignore|\.secrets\.baseline|\.trufflehogignore)$")
NAMELESS = {"generic-api-key", "HARDCODED_SECRET"}
# The account ids AWS documentation uses in examples (ARNs, policies).
AWS_DOC_ACCOUNTS = {"123456789012", "111122223333", "444455556666", "777788889999", "999988887777", "210987654321",
                    "000000000000", "012345678901"}
ARN = re.compile(r"""arn:aws[\w-]*:[\w-]*:[\w-]*:(\d{12})?:[^\s'"`,;)}\]]+""")
URL = re.compile(r"""[a-z][\w+.-]*://[^\s'"`<>)\]]+""")
URL_CRED = re.compile(r"(?i)[?&;][\w.-]*(?:key|token|secret|passw|pwd|auth|sig|signature|credential|code)[\w.-]*=$|://[^/@]*:$")
KEYED = re.compile(r"^-{0,2}([A-Za-z_][\w.-]*)=(.*)$")
# A word: lower, UPPER, Capitalised or camelCase with humps of 3+ lower-case letters (random base64 mixes
# case inside a run), up to 3 digits after it.
WORD_PART = re.compile(r"(?:[A-Z]?[a-z]+(?:[A-Z][a-z]{2,})*|[A-Z]+)\d{0,3}|\d{1,5}")


def words(s: str, seps: str = "-_./~") -> bool:
    parts = [x for x in re.split(f"[{re.escape(seps)}]", s) if x]
    return len(parts) >= 2 and all(WORD_PART.fullmatch(x) for x in parts) and any(len(x) >= 3 and x.isalpha() for x in parts)


def arn_of(value: str, line: str) -> re.Match | None:
    """The ARN on the line that holds the value, if any."""
    return next((m for m in ARN.finditer(line) if value in m.group(0)), None)


def in_plain_url(value: str, line: str) -> bool:
    """The value sits inside a URL on the line, and not right after a credential parameter or in user:pass@."""
    for m in URL.finditer(line):
        i = m.group(0).find(value)
        if i >= 0 and not URL_CRED.search(m.group(0)[:i]):
            return True
    return False


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = collections.Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


def charset(s: str) -> str:
    return "".join(k for k, rx in (("a", "[a-z]"), ("A", "[A-Z]"), ("9", "[0-9]"), ("_", r"[^A-Za-z0-9]")) if re.search(rx, s))


def prefix(s: str) -> str:
    return next((p for p in PREFIXES if s.startswith(p)), "")


def esc(s: str, n: int = 180) -> str:
    return s.strip().encode("ascii", "backslashreplace").decode("ascii")[:n]


def find_value(rule: str, line: str) -> tuple[str, str]:
    """(value, name it is assigned to): by the rule's shape; else an assignment; else the most random long token."""
    rx = SHAPES.get(rule)
    if rx:
        m = rx.search(line)
        if m:
            return next(g for g in m.groups() if g), rule
    m = ASSIGN.search(line)
    if m and len(m.group(2)) >= 4:
        return m.group(2), m.group(1)
    toks = TOKEN.findall(line)
    toks = [t for t in toks if "/" not in t] or toks    # a URL path is the last resort
    return (max(toks, key=entropy), "") if toks else ("", "")


def curl_window(lines: list[str], n: int) -> list[int]:
    """Line numbers to search for a curl credential: n and the next 11 (gitleaks' curl rules span lines)."""
    return list(range(n, min(len(lines), n + 11) + 1))


def is_sequential(v: str) -> bool:
    low = v.lower()
    return any(low[i:i + 6] in seq for seq in SEQUENCES for i in range(0, max(1, len(low) - 5)))


def bucket(value: str, path: str, rule: str = "", line: str = "", name: str = "") -> tuple[str, str]:
    if not value:
        return "unlocated", "no value on the line"
    if value.startswith("//") or "://" in value:
        return "unlocated", "only a URL on the line"
    arn = arn_of(value, line) or (re.match(r"arn:", value) and ARN.match(value))
    if arn:
        if arn.group(1) in AWS_DOC_ACCOUNTS:
            return "placeholder", "ARN with an AWS documentation account id"
        return "identifier", "ARN"
    if in_plain_url(value, line):
        return "unlocated", "part of a URL, not a credential field"
    m = KEYED.match(value)
    if m and not m.group(2).strip("=") and not words(m.group(1), "-_."):
        m = None                              # base64 padding, not name=
    if m and not CRED_NAME.search(m.group(1)):
        return "identifier", f"value of {esc(m.group(1), 30)!r}" if m.group(2) else "a name with an empty value"
    if m and m.group(2).strip("="):
        value = m.group(2)                    # --password=X, api_key=X: judge X
    if value.startswith("--"):
        return "identifier", "CLI flag or CSS variable"
    m = PLACEHOLDER.search(value)
    if m:
        return "placeholder", f"marker {esc(m.group(0), 12)!r}"
    if REFERENCE.search(value):
        return "reference", "env/template/code reference"
    if re.search(r"(.)\1{5,}", value) or is_sequential(value) or len(set(value)) <= 4:
        return "placeholder", "repeated or sequential characters"
    if re.match(r"(?:sk|rk)_test_|pk_(?:test|live)_|phc_", value) or re.fullmatch(r"pub[0-9a-f]{32}", value):
        return "public", "issuer test or publishable key format"
    if hashlib.sha256(value.encode()).hexdigest()[:10] in KNOWN_PUBLIC:
        return "public", KNOWN_PUBLIC[hashlib.sha256(value.encode()).hexdigest()[:10]]
    if re.match(r"(?:sk|rk)_live_", value) and len(value) < 32:
        return "low-entropy", "shorter than the issuer's format"
    camel = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])", value)
    if value.isalpha() and 2 <= len(camel) <= 6 and min(map(len, camel)) >= 2 and len(value) / len(camel) >= 3.5:
        return "low-entropy", "camelCase words"
    if len(value) < 16 or entropy(value) < 3.0:
        return "low-entropy", f"len {len(value)}, H {entropy(value):.1f}"
    if words(value):
        return "low-entropy", "joined words" if "/" not in value else "path of words"
    m = DOC_LINE.search(line.replace(value, " "))
    if m:
        return "doc-context", f"line says {m.group(0).lower()!r}"
    if ALLOWLIST_FILE.search(path):
        return "allowlisted", "scanner allowlist file"
    if TEST_PATH.search(path):
        return "test-path", "test/fixture file"
    if rule in NAMELESS and not prefix(value):
        if UUID.match(value):
            return "identifier", "UUID"
        last = re.split(r"[.\s]", name.strip("-_. "))[-1] if name else ""
        if last == "key" and JSX.search(path):
            return "identifier", "React key prop"
        if last and last.lower() != "key" and not CRED_NAME.search(last):
            return "identifier", f"name {esc(last, 30)!r}"
    return "plausible", ""


def mask(line: str, value: str) -> str:
    """The line with the value, and any other long high-entropy token, replaced by its features."""
    if value:
        line = line.replace(value, f"<V len={len(value)} H={entropy(value):.1f}>")
    line = TOKEN.sub(lambda m: m.group(0) if entropy(m.group(0)) < 3.5 or m.group(0).startswith("<V")
                     else f"<T len={len(m.group(0))}>", line)
    return esc(line)


def load_words(path: str = "/usr/share/dict/words") -> set[str]:
    try:
        return {w for w in Path(path).read_text(errors="replace").split() if w.isascii() and w.isalpha() and w.islower()
                and len(w) >= 3}
    except OSError:
        return set()


def skeleton(value: str, words: set[str]) -> str:
    """The value with every run shown as class and length, except lower-case runs that split wholly or partly into
    dictionary words of 3+ letters: those words are shown (securepassword<9x3>, <a2>sagemakerrole). For judging
    a masked value by eye; it reveals words, so it is opt-in (--skeleton) and never written by default."""
    def run(r: str) -> str:
        n = len(r)
        best = [(0, "")] + [(-1, "")] * n          # (letters covered, rendering) for r[:i]
        for i in range(1, n + 1):
            cov, txt = best[i - 1]
            best[i] = (cov, txt + "\0")            # \0 marks an uncovered letter
            for j in range(max(0, i - 24), i - 2):
                if r[j:i] in words and best[j][0] + i - j > best[i][0]:
                    best[i] = (best[j][0] + i - j, best[j][1] + r[j:i])
        return re.sub("\0+", lambda m: f"<a{len(m.group(0))}>", best[n][1])
    out = []
    for m in re.finditer(r"[a-z]+|[A-Z]+|[0-9]+|[^A-Za-z0-9]", value):
        g = m.group(0)
        out.append(run(g) if g.islower() else f"<A{len(g)}>" if g.isupper() else f"<9x{len(g)}>" if g.isdigit()
                   else esc(g))
    return "".join(out)


def private_key_value(lines: list[str], n: int) -> str:
    """For a PEM header, the base64 body that follows (empty if it is elided or absent)."""
    body = []
    for ln in lines[n:n + 60]:
        s = re.sub(r"(?:\\n)+$", "", ln.strip().strip("\"',")).strip("\"',")
        if s.startswith("-----END"):
            break
        if re.fullmatch(r"[A-Za-z0-9+/=]{16,}", s):
            body.append(s)
        elif s and body:
            break
    return "".join(body)


SE_CREDENTIAL_RULES = {"generic-api-key", "database_credentials", "hardcoded_secrets", "private_keys", "jwt_tokens",
                       "aws_identifiers"}


def selected(r: dict) -> bool:
    return (r["tool"] == "gitleaks" or (r["tool"] == "holguard" and r["rule"] == "HARDCODED_SECRET")
            or (r["tool"] == "agentshield" and r["category"] == "secrets")
            or (r["tool"] == "skillevaluator" and (r.get("title") == "Secrets Detection" or r["rule"] in SE_CREDENTIAL_RULES)))


def check(rows: list[dict], text, words: set[str] | None = None) -> list[dict]:
    out = []
    for r in rows:
        lines = text(r["skill"], r["file"]) if r["file"] not in ("", ".") else None
        n = int(r["line"]) if r["line"].isdigit() else 0
        if lines is None or not 0 < n <= len(lines):
            out.append({**r, "bucket": "unlocated", "reason": "no line", "len": 0, "charset": "", "entropy": 0.0,
                        "prefix": "", "vhash": "", "masked": ""})
            continue
        line = lines[n - 1]
        if r["rule"] == "private-key" or "PRIVATE KEY" in line:
            value, name = private_key_value(lines, n), "private-key"
        elif r["rule"].startswith("curl-"):
            value, name = "", ""
            for k in curl_window(lines, n):
                m = SHAPES[r["rule"]].search(lines[k - 1]) if r["rule"] in SHAPES else None
                if m:
                    line, value, name = lines[k - 1], next(g for g in m.groups() if g), r["rule"]
                    break
        else:
            value, name = find_value(r["rule"], line)
        b, why = bucket(value, r["file"], r["rule"], line, name)
        out.append({**r, "bucket": b, "reason": why, "len": len(value), "charset": charset(value),
                    "entropy": round(entropy(value), 2), "prefix": prefix(value),
                    "vhash": hashlib.sha256(value.encode()).hexdigest()[:10] if value else "",
                    "masked": mask(line, value) if "PRIVATE KEY" not in line else esc(line),
                    **({"skeleton": skeleton(value, words) if "PRIVATE KEY" not in line else "<private key>"}
                       if words is not None else {})})
    reuse = collections.defaultdict(set)
    for o in out:
        if o["vhash"]:
            reuse[o["vhash"]].add(o["skill"])
    for o in out:
        o["entries_same_value"] = len(reuse[o["vhash"]]) if o["vhash"] else 0
    return out


def tar_reader(tar: tarfile.TarFile):
    folder = {}
    for name in tar.getnames():
        p = name.split("/")
        if len(p) >= 3 and p[0] == "skills":
            folder.setdefault(p[1], p[2])

    def text(sid: str, rel: str) -> list[str] | None:
        try:
            fh = tar.extractfile(f"skills/{sid}/{folder.get(sid, '')}/{rel.lstrip('/')}")
        except KeyError:
            return None
        return fh.read().decode("utf-8", "replace").splitlines() if fh else None
    return text


COLS = ["tool", "skill", "rule", "severity", "file", "line", "bucket", "reason", "len", "charset", "entropy",
        "prefix", "vhash", "entries_same_value", "masked"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("results", type=Path, help="results dir with findings.tsv")
    ap.add_argument("tar", type=Path, help="the staged tar that run scanned")
    ap.add_argument("--out", type=Path, help="TSV of every checked finding (default RESULTS/secrets-check.tsv)")
    ap.add_argument("--show", default="plausible", help="comma list of buckets whose masked lines are printed")
    ap.add_argument("--skeleton", action="store_true",
                    help="add a skeleton column (dictionary words shown, other runs as class+length) and print it")
    a = ap.parse_args()

    rows = [r for r in csv.DictReader((a.results / "findings.tsv").open(), delimiter="\t") if selected(r)]
    with tarfile.open(a.tar) as tar:
        out = check(rows, tar_reader(tar), load_words() if a.skeleton else None)
    dest = a.out or a.results / "secrets-check.tsv"
    with dest.open("w", newline="") as f:
        w = csv.DictWriter(f, COLS + ["skeleton"] * a.skeleton, delimiter="\t", extrasaction="ignore")
        w.writeheader()
        w.writerows(out)

    by = collections.Counter((o["tool"], o["rule"], o["bucket"]) for o in out)
    print(f"{'tool':12} {'rule':36} " + " ".join(f"{b[:11]:>11}" for b in BUCKETS))
    for tool, rule in sorted({(t, r) for t, r, _ in by}):
        print(f"{tool:12} {rule[:36]:36} " + " ".join(f"{by[(tool, rule, b)] or '':>11}" for b in BUCKETS))
    show = set(a.show.split(","))
    for o in out:
        if o["bucket"] in show:
            print(f"\n{o['bucket']:10} {o['tool']} {o['rule']} {o['skill']} {esc(o['file'], 80)}:{o['line']}  "
                  f"len {o['len']} {o['charset']} H {o['entropy']} {o['prefix'] or '-'} x{o['entries_same_value']} {o['vhash']}"
                  f"\n    {o['masked']}" + (f"\n    skeleton {o['skeleton']}" if a.skeleton else ""))
    print(f"\n{len(out)} findings -> {dest}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
