#!/usr/bin/env python3
"""Before a commit: no denylisted string, no em-dash and no invisible character in any tracked or
about-to-be-tracked text file.

`.denylist.local` (gitignored) holds one term per line, `#` for comments: local paths, personal
details, unrelated project names. A hit is reported by file, line and the entry NUMBER, never the
term itself, so the report is safe to paste anywhere.

Invisible characters (untrusted.INVISIBLE) are refused because they once got into this repo by
accident: writing the detector's own pattern put the real zero-width and Tag characters into its
source instead of escape sequences (2026-10-23). Write them as \\uXXXX escapes.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "pipeline"))
from untrusted import invisible  # noqa: E402
TEXT = {".md", ".py", ".tsv", ".yaml", ".yml", ".txt", ".js", ".html", ".json", ".cff", ".toml", ""}
HARVESTED = {"data/skills.json", "docs/skills.js"}    # strangers' text: their em-dashes are theirs; denylist and invisible still apply


def files() -> list[Path]:
    out = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout.split("\n")
    return [ROOT / f for f in out if f and (ROOT / f).is_file() and (ROOT / f).suffix in TEXT]


def main() -> int:
    deny = ROOT / ".denylist.local"
    terms = [t.strip() for t in deny.read_text().splitlines() if t.strip() and not t.startswith("#")] if deny.exists() else []
    if not terms:
        print("check: no .denylist.local, so only em-dashes are checked", file=sys.stderr)
    bad = 0
    for f in files():
        harvested = str(f.relative_to(ROOT)) in HARVESTED
        for n, line in enumerate(f.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            for i, t in enumerate(terms, 1):
                if t in line:
                    print(f"{f.relative_to(ROOT)}:{n}: denylist entry {i}")
                    bad += 1
            if not harvested and "\u2014" in line:
                print(f"{f.relative_to(ROOT)}:{n}: em-dash")
                bad += 1
            if (hidden := invisible(line)):
                print(f"{f.relative_to(ROOT)}:{n}: invisible characters {', '.join(hidden)}")
                bad += 1
    print(f"check: {'FAILED, ' + str(bad) + ' hits' if bad else 'clean'} in {len(files())} files")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
