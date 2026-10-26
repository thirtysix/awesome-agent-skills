#!/usr/bin/env python3
"""docs/screenshots/*.png: the README's views of the site (light mode), from docs/index.html on disk.

Needs Playwright with Chromium (not in requirements-dev.txt), like og_image.py. Pillow, if present, cuts each
file to a 256-colour palette. Run `make curate` afterwards only if the README text changed.
"""
from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "screenshots"
# (file, hash, element to hover so one tooltip shows)
VIEWS = [("overview", "#overview", None), ("skills", "#skills", "#p-skills thead th:nth-child(5)"),
         ("tools", "#tools", None), ("coverage", "#coverage", "#p-coverage tbody tr:nth-child(3) td:nth-child(2)")]


def shrink(path: Path) -> None:
    try:
        from PIL import Image
    except ImportError:
        return
    with Image.open(path) as im:
        im.convert("RGB").quantize(colors=256, method=Image.Quantize.MEDIANCUT).save(path, optimize=True)


def main() -> int:
    OUT.mkdir(exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch()
        pg = b.new_page(viewport={"width": 1600, "height": 900}, device_scale_factor=1.25, color_scheme="light")
        for name, frag, hover in VIEWS:
            pg.goto((ROOT / "docs" / "index.html").as_uri() + frag)
            pg.wait_for_timeout(1500)
            if hover and pg.locator(hover).count():
                pg.locator(hover).first.hover()
                pg.wait_for_timeout(400)
            f = OUT / f"{name}.png"
            pg.screenshot(path=str(f))
            shrink(f)
            print(f"screenshots: {f.relative_to(ROOT)} ({f.stat().st_size // 1024} KB)")
        b.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
