"""Offline tests for vetter/hit_review.py with the fake provider. Built strings keep this file ASCII and
free of anything a secret scanner would match."""
from __future__ import annotations

import io
import json
import random
import string
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vetter"))
import hit_review as hr  # noqa: E402

COLS = ["tool", "skill", "rule", "severity", "category", "file", "line", "title"]


def make_tar(tmp: Path, files: dict[str, str]) -> Path:
    p = tmp / "in.tar"
    with tarfile.open(p, "w") as t:
        for name, text in files.items():
            data = text.encode()
            ti = tarfile.TarInfo(name)
            ti.size = len(data)
            t.addfile(ti, io.BytesIO(data))
    return p


def make_results(tmp: Path, rows: list[dict]) -> Path:
    d = tmp / "out"
    d.mkdir()
    lines = ["\t".join(COLS)] + ["\t".join(r.get(c, "") for c in COLS) for r in rows]
    (d / "findings.tsv").write_text("\n".join(lines) + "\n")
    return d


def fixture(tmp: Path):
    rng = random.Random(3)
    blob = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(40))
    script = "\n".join([f"x{i} = {i}" for i in range(1, 20)] + [f"k = '{blob}'", "os.system(cmd)"] + ["pass"] * 10)
    tar = make_tar(tmp, {
        "skills/h__a/demo/SKILL.md": "---\nname: demo\ndescription: Formats tables.\n---\nbody\n",
        "skills/h__a/demo/scripts/run.py": script,
        "skills/p__b/plug/.mcp.json": '{"mcpServers": {"x": {"url": "http://example.org/mcp"}}}\n',
        "skills/p__b/plug/.claude-plugin/plugin.json": '{"name": "plug", "description": "Talks to X."}\n'})
    res = make_results(tmp, [
        {"tool": "bandit", "skill": "h__a", "rule": "B605", "severity": "HIGH", "category": "construct",
         "file": "scripts/run.py", "line": "21", "title": "start_process_with_a_shell"},
        {"tool": "holguard", "skill": "p__b", "rule": "MCP_REMOTE_URL_INSECURE", "severity": "HIGH",
         "category": "security", "file": ".mcp.json", "line": "", "title": "insecure URL"},
        {"tool": "holguard", "skill": "p__b", "rule": "HARDCODED_SECRET", "severity": "HIGH",
         "category": "security", "file": ".mcp.json", "line": "1", "title": "secret"},
        {"tool": "guarddog", "skill": "h__a", "rule": "threat-x", "severity": "MEDIUM",
         "category": "threat", "file": "scripts/run.py", "line": "2", "title": "t"}])
    return tar, res, blob


def test_groups_bundle_and_masking(tmp_path):
    tar, res, blob = fixture(tmp_path)
    groups = hr.rows_for(res)
    assert list(groups) == [("h__a", "bandit", "B605"), ("p__b", "holguard", "MCP_REMOTE_URL_INSECURE")]
    with tarfile.open(tar) as t:
        read = hr.Reader(t)
        msg, info = hr.bundle(("h__a", "bandit", "B605"), groups[("h__a", "bandit", "B605")], read)
        assert "Formats tables." in msg and ">  21| os.system(cmd)" in msg
        assert blob not in msg and "<T len=40>" in msg
        assert info["shown_lines"]["scripts/run.py"] == list(range(15, 28))
        msg2, info2 = hr.bundle(("p__b", "holguard", "MCP_REMOTE_URL_INSECURE"),
                                groups[("p__b", "holguard", "MCP_REMOTE_URL_INSECURE")], read)
        assert "Talks to X." in msg2 and "no line reported" in msg2 and info2["shown_lines"][".mcp.json"] == [1]
        assert msg.count("nonce=") == 2


def test_validate_checks_cited_line():
    info = {"shown_lines": {"scripts/run.py": [20, 21, 22]}}
    ok, _ = hr.validate({"verdict": "real_risk", "escalation": "none", "disclosed": "no", "file": "scripts/run.py",
                         "line": 21, "reviewer_manipulation": False, "reason": "r"}, info)
    assert ok["verified"] and ok["verdict"] == "real_risk"
    bad, problems = hr.validate({"verdict": "dangerous", "file": "scripts/run.py", "line": 99}, info)
    assert bad["verdict"] == "unparsed" and not bad["verified"] and problems == ["verdict"]
    m, _ = hr.validate({"verdict": "false_match", "file": "scripts/run.py", "line": 21, "reviewer_manipulation": True,
                        "manipulation_line": 500}, info)
    assert m["reviewer_manipulation"] and not m["manipulation_verified"]
    m, _ = hr.validate({"verdict": "code_bug", "file": "scripts/run.py", "line": 21, "reviewer_manipulation": True,
                        "manipulation_line": 22}, info)
    assert m["manipulation_verified"] and hr.coarse(m["verdict"]) == "bug"


def test_fake_run_cache_score_and_data(tmp_path):
    tar, res, _ = fixture(tmp_path)
    gold = tmp_path / "gold.tsv"
    gold.write_text("# hand-read\nskill\ttool\trule\tverdict\nh__a\tbandit\tB605\tcapability_as_described\n")
    reads = tmp_path / "reads.tsv"
    reads.write_text("skill\ttool\trule\tverdict\np__b\tholguard\tMCP_REMOTE_URL_INSECURE\tcode_bug\n")
    out, data = tmp_path / "rv", tmp_path / "hit-reviews.json"
    args = [str(res), str(tar), "--out", str(out), "--provider", "fake", "--mode", "live", "--gold", str(gold),
            "--gold", str(reads), "--data", str(data)]
    assert hr.main(args) == 0
    s = json.loads((out / "summary.json").read_text())
    assert s["reviewed"] == 2 and s["verdict"] == {"unclear": 2}
    assert s["score"]["gold.tsv"]["reviewed"] == 1 and s["score"]["gold.tsv"]["coarse"] == {"benign->unclear": 1}
    assert s["positives"] == {"positives": 1, "reviewed": 1, "flagged": 0,
                              "missed": ["p__b|holguard|MCP_REMOTE_URL_INSECURE"]}
    d = json.loads(data.read_text())
    assert set(d["entries"]) == {"h__a", "p__b"} and "reason" not in d["entries"]["h__a"][0]
    assert hr.main(args) == 0                                     # second run: all from cache
    assert json.loads((out / "summary.json").read_text())["fresh_usd"] == 0


def test_source_is_ascii():
    for f in (ROOT / "vetter" / "hit_review.py", Path(__file__)):
        assert f.read_bytes().isascii()
