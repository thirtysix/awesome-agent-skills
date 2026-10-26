#!/usr/bin/env python3
"""docs/og.png: the social preview image (1200x630), a screenshot of the site's Overview tab in light mode.

Needs Playwright with Chromium (not in requirements-dev.txt). Offline: it opens docs/index.html from disk.
Run `make curate` again afterwards so the page's og:image tags appear.
"""
from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "og.png"


def main() -> int:
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1200, "height": 630}, color_scheme="light")
        pg.goto((ROOT / "docs" / "index.html").as_uri() + "#overview")
        pg.wait_for_timeout(1500)
        pg.screenshot(path=str(OUT))
        b.close()
    print(f"og_image: {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
