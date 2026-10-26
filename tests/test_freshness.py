"""Offline tests for pipeline/freshness.py: folder digests and their diff between two trees."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline"))
import freshness  # noqa: E402


def blobs(files: dict[str, str]) -> list[dict]:
    return [{"path": p, "type": "blob", "sha": s, "mode": "100644"} for p, s in files.items()]


def test_folder_states_between_two_trees():
    old = blobs({"a/SKILL.md": "1", "a/run.py": "2", "b/SKILL.md": "3", "b/x.md": "4", "c/SKILL.md": "5", "d/SKILL.md": "6"})
    new = blobs({"a/SKILL.md": "1", "a/run.py": "9", "b/SKILL.md": "7", "b/x.md": "4", "d/SKILL.md": "6", "e/SKILL.md": "8"})
    d = freshness.diff_folders(freshness.folders(old, None), freshness.folders(new, None))
    assert d == {"a": "files_changed", "b": "skill_md_changed", "c": "gone", "d": "unchanged", "e": "new"}


def test_nested_and_root_skills_own_their_subtrees_and_paths_limit_scope():
    t = [{"path": "SKILL.md", "type": "blob", "sha": "r"}, {"path": "lib/x.py", "type": "blob", "sha": "x"},
         {"path": "p/s/SKILL.md", "type": "blob", "sha": "s"}, {"path": "p/s/deep/y.sh", "type": "blob", "sha": "y"},
         {"path": "q/t/SKILL.md", "type": "blob", "sha": "t"}]
    f = freshness.folders(t, None)
    assert set(f[""]["files"]) == {"SKILL.md", "lib/x.py", "p/s/SKILL.md", "p/s/deep/y.sh", "q/t/SKILL.md"}
    assert set(f["p/s"]["files"]) == {"SKILL.md", "deep/y.sh"}
    assert set(freshness.folders(t, ["p"])) == {"p/s"}
