"""Offline tests for vetter/secrets_check.py. Key-shaped values are built at run time so this file
holds nothing a secret scanner would match."""
from __future__ import annotations

import random
import string
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vetter"))
import secrets_check as sc  # noqa: E402

RNG = random.Random(7)


def rand(n: int, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(RNG.choice(alphabet) for _ in range(n))


def row(rule: str, file: str = "SKILL.md", line: str = "1", tool: str = "gitleaks", category: str = "secret") -> dict:
    return {"tool": tool, "skill": "h__x", "rule": rule, "severity": "HIGH", "category": category,
            "file": file, "line": line, "title": ""}


def run(rule: str, text: str, **kw) -> dict:
    return sc.check([row(rule, **kw)], lambda sid, rel: text.splitlines())[0]


def test_bearer_placeholder_and_reference():
    assert run("curl-auth-header", 'curl -H "Authorization: Bearer YOUR_TOKEN" x')["bucket"] == "placeholder"  # gitleaks:allow (placeholder fixture)
    assert run("curl-auth-header", 'curl -H "Authorization: Bearer $API_TOKEN" x')["bucket"] == "reference"
    assert run("curl-auth-header", "curl -H 'Authorization: Bearer ${TOKEN}' x")["bucket"] == "reference"


def test_real_looking_value_is_masked_everywhere():
    v = rand(40)
    o = run("curl-auth-header", f'curl -H "Authorization: Bearer {v}" https://api.acme.io')
    assert o["bucket"] == "plausible" and o["len"] == 40
    assert v not in o["masked"] and v[:12] not in "".join(str(x) for x in o.values())
    # a second high-entropy token the extractor did not pick is masked too
    w = rand(32)
    o = run("generic-api-key", f"api_key = 'abc' # see {w}")
    assert w not in o["masked"]


def test_shapes_and_prefixes():
    aws = "AK" + "IA" + rand(16, string.ascii_uppercase + "234567")
    o = run("aws-access-token", f"aws_access_key_id = {aws}")
    assert o["prefix"] == "AK" + "IA" and o["len"] == 20 and o["bucket"] == "plausible"
    doc = "AK" + "IA" + "IOSFODNN7" + "EXAMPLE"
    assert run("aws-access-token", f"id={doc}")["bucket"] == "placeholder"
    stripe = "sk" + "_test_" + rand(24)
    assert run("stripe-access-token", f"key: {stripe}")["bucket"] == "public"


def test_low_entropy_test_path_and_repeats():
    assert run("generic-api-key", 'password = "hunter2"')["bucket"] == "low-entropy"
    v = rand(30)
    assert run("HARDCODED_SECRET", f'token := "{v}"', tool="holguard", file="internal/x_test.go")["bucket"] == "test-path"
    assert run("generic-api-key", 'secret = "aaaaaaaaaaaaaaaaaaaa"')["bucket"] == "placeholder"
    assert run("generic-api-key", 'api_key = "0123456789abcdef0123"')["bucket"] == "placeholder"  # gitleaks:allow (placeholder fixture)


def test_unlocated_and_private_key_body():
    assert run("generic-api-key", "x", line="9")["bucket"] == "unlocated"
    head = "-----BEGIN " + "RSA PRIVATE KEY-----"
    elided = f"{head}\n...\n-----END RSA PRIVATE KEY-----"
    assert run("private-key", elided)["bucket"] == "unlocated"
    body = "\n".join(rand(64, string.ascii_letters + string.digits + "+/") for _ in range(4))
    o = run("private-key", f"{head}\n{body}\n-----END RSA PRIVATE KEY-----")
    assert o["bucket"] == "plausible" and o["len"] == 256


def test_reuse_count_and_selection():
    v = rand(36)
    rows = [dict(row("generic-api-key"), skill=s) for s in ("a", "b")]
    out = sc.check(rows, lambda sid, rel: [f"token = {v}"])
    assert [o["entries_same_value"] for o in out] == [2, 2]
    assert sc.selected(row("x", tool="agentshield", category="secrets"))
    assert not sc.selected(row("SHELL_INJECTION_PATTERN", tool="holguard"))


def test_source_is_ascii():
    for f in (ROOT / "vetter" / "secrets_check.py", Path(__file__)):
        assert f.read_bytes().isascii()


def test_identifier_doc_context_and_words():
    u = "-".join(rand(n, "0123456789abcdef") for n in (8, 4, 4, 4, 12))
    assert run("generic-api-key", f'"GlobalKey__c": "{u}"')["bucket"] == "identifier"
    v = rand(46)
    assert run("generic-api-key", f'key: "{v}",', file="docs/blocks/scroll.mdx")["reason"] == "React key prop"
    assert run("generic-api-key", f'key: "{v}",', file="config.md")["bucket"] == "plausible"
    assert run("generic-api-key", f"fileKey=`{rand(22)}`")["bucket"] == "identifier"
    assert run("generic-api-key", f"OPENAI_KEY={rand(40)}")["bucket"] == "plausible"
    assert run("generic-api-key", f"The emulator's well-known key is: `{rand(88)}`")["bucket"] == "doc-context"
    assert run("generic-api-key", "const DSB_KEY = 'design-system-button';")["reason"] == "joined words"
    # a real-format prefix is never an identifier
    assert run("generic-api-key", f"fileKey = sk-proj-{rand(40)}")["bucket"] == "plausible"


def test_curl_header_on_continuation_line_and_allowlist():
    v = rand(40)
    o = run("curl-auth-header", f'curl -X POST "https://api.acme.io/v1/items" \\\n  -H "Authorization: Bearer {v}" \\\n  -d @x')
    assert o["bucket"] == "plausible" and o["len"] == 40 and "Authorization" in o["masked"]
    o = run("curl-auth-header", 'curl -X POST "https://api.acme.io/v1/items" \\\n  -H "Authorization: Bearer $TOKEN"')
    assert o["bucket"] == "reference"
    assert run("curl-auth-header", 'curl "https://api.acme.io/v1/items/abcdefXYZ123"')["bucket"] == "unlocated"
    assert run("gcp-api-key", "AI" + "za" + rand(35), file=".gitallowed")["bucket"] == "allowlisted"


def test_public_formats_and_proxy_user():
    assert run("generic-api-key", f'const POSTHOG_API_KEY = "phc_{rand(43)}";')["bucket"] == "public"
    o = run("curl-auth-user", f'curl -x 1.2.3.4:60000 -U "user:{rand(24)}" https://ip.acme.io')
    assert o["bucket"] == "plausible" and o["len"] == 24
    v = rand(40)
    o = run("curl-auth-header", f'curl https://api.acme.io/x\n```\n\nThen send:\n-H "Authorization: Bearer {v}"'.replace("\\n", "\n"))
    assert o["len"] == 40


def test_more_formats_words_and_paths():
    assert run("HARDCODED_SECRET", f'let t = "pub{rand(32, "0123456789abcdef")}"', tool="holguard")["bucket"] == "public"
    assert run("stripe-access-token", "secretKey: 'sk" + "_live_" + rand(11) + "'")["reason"] == "shorter than the issuer's format"
    assert run("atlassian-api-token", '"confluenceSpaceKey": "x"')["reason"] == "camelCase words"
    assert run("generic-api-key", f"api_key: {rand(20)}", file="test-fixtures/server.py")["bucket"] == "test-path"
    assert run("generic-api-key", f"api_key: {rand(20)}", file="res/export-sample.json")["bucket"] == "test-path"
    assert run("secrets-openai-legacy-api-key", "- Windows: https://" + rand(30, "abcdefgh") + "/x",
               tool="agentshield", category="secrets")["reason"] == "only a URL on the line"
