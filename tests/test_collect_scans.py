"""Offline tests for vetter/collect_scans.py: which agnix REF-001 findings count as real broken references."""
from __future__ import annotations

import gzip
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vetter"))
import collect_scans as cs  # noqa: E402


def trees(tmp_path: Path) -> cs.Trees:
    d = tmp_path / "20261025" / "trees"
    d.mkdir(parents=True)
    tree = [{"path": p} for p in ("skills/a/SKILL.md", "skills/a/card.yaml", "skills/b/SKILL.md", "docs/x.md")]
    with gzip.open(d / "Org__repo@abc.json.gz", "wt") as f:
        json.dump({"sha": "abc", "tree": tree}, f)
    return cs.Trees(tmp_path)


def test_ref001_kept_only_for_missing_file_paths(tmp_path):
    t, e = trees(tmp_path), {"repo": "org/repo", "dir": "skills/a"}
    ref = lambda target: cs.ref_unresolved(t, e, "skills/a/SKILL.md", "Import target not found: @" + target)
    assert not ref("card.yaml")                    # beside the skill
    assert not ref("skills/b/SKILL.md")            # repo-root path to a sibling (staging artifact)
    assert not ref("docs/x.md")
    assert not ref("triton.jit")                   # decorator, not a path
    assert not ref("microsoft/teams.ai")           # npm package
    assert ref("docs/missing.md")                  # a file absent at the scanned commit
    assert ref("./workflows/SKILL.md")


def test_ref001_kept_when_repo_has_no_tree(tmp_path):
    t = trees(tmp_path)
    assert cs.ref_unresolved(t, {"repo": "other/repo", "dir": ""}, "skills/r/AGENTS.md", "Import target not found: @triton.jit")
