#!/usr/bin/env python3
"""How far the harvested core is behind what its authors publish now: metadata only, no skill text.

NETWORK (api.github.com and one raw file), under harvest.py's rules: neutral User-Agent, the token
only to api.github.com as an unredirected header. It reads commit shas, comparisons and file trees,
never a skill's text; patches in compare responses are dropped before caching.

For the newest harvest run it records:
- the official marketplace now against the copy the harvest read: plugins added, removed, re-pinned;
- per harvested repo: the head of the branch the harvest would follow (the marketplace `ref` if it
  gave one, else the default branch), how many commits it is ahead of the harvested sha, and the
  date of the harvested commit;
- per skill folder, comparing the harvested tree with the tree at that head: unchanged, SKILL.md
  changed, other files changed, gone; plus skill folders that are new at the head.

Caches and the report go to ~/.cache/awesome-agent-skills/freshness/<date>/ (not under harvest/,
so `make skills` never mistakes it for a run).
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import json
import re
import subprocess
import sys
import urllib.parse
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from harvest import API, CACHE, OFFICIAL_MARKETPLACE, RAW, Client, _ok, cached, gh_repo, slug  # noqa: E402
from skills import skill_dir  # noqa: E402

OUT = CACHE.parent / "freshness"
SHA = re.compile(r"[0-9a-f]{40}")


def newest_run() -> Path:
    runs = sorted((p.parent for p in CACHE.glob("*/manifest.json")), key=lambda d: (d / "manifest.json").stat().st_mtime)
    return runs[-1]


def head(client: Client, out: Path, repo: str, ref: str) -> str | None:
    data = cached(out / "heads" / f"{slug(repo)}@{slug(ref)}.txt",
                  lambda: _ok(client.get(f"https://{API}/repos/{repo}/commits/{urllib.parse.quote(ref, safe='')}",
                                         accept="application/vnd.github.sha")))
    sha = (data or b"").decode().strip()
    return sha if SHA.fullmatch(sha) else None


def _slim_compare(raw: bytes | None) -> bytes | None:
    if raw is None:
        return None
    c = json.loads(raw)
    base = ((c.get("base_commit") or {}).get("commit") or {}).get("committer", {}).get("date")
    return json.dumps({"status": c.get("status"), "ahead_by": c.get("ahead_by"), "behind_by": c.get("behind_by"),
                       "base_date": base, "files": len(c.get("files") or [])}).encode()


def compare(client: Client, out: Path, repo: str, base: str, tip: str) -> dict | None:
    raw = cached(out / "compare" / f"{slug(repo)}@{base[:12]}...{tip[:12]}.json",
                 lambda: _slim_compare(_ok(client.get(f"https://{API}/repos/{repo}/compare/{base}...{tip}?per_page=1"))))
    return json.loads(raw) if raw else None


def tree(client: Client, out: Path, run: Path, repo: str, sha: str) -> dict | None:
    old = run / "trees" / f"{slug(repo)}@{sha}.json.gz"
    if old.exists():
        return json.loads(gzip.decompress(old.read_bytes()))
    raw = cached(out / "trees" / f"{slug(repo)}@{sha}.json.gz",
                 lambda: _ok(client.get(f"https://{API}/repos/{repo}/git/trees/{sha}?recursive=1")))
    return json.loads(raw) if raw else None


def folders(entries: list[dict], paths: list[str] | None) -> dict[str, dict]:
    """Skill folder -> {'skill': SKILL.md blob, 'files': {relpath: blob}} for the folders in scope."""
    blobs = [e for e in entries if e.get("type") == "blob"]
    dirs = {skill_dir(e["path"]) for e in blobs
            if e["path"].rsplit("/", 1)[-1].lower() == "skill.md"
            and (paths is None or any(e["path"].startswith(p + "/") for p in paths))}
    out = {d: {"skill": None, "files": {}} for d in dirs}
    for e in blobs:
        p = e["path"]
        parts = p.split("/")[:-1]
        for d in {"/".join(parts[:k]) for k in range(len(parts) + 1)} & dirs:   # every skill folder above p
            rel = p[len(d) + 1:] if d else p
            out[d]["files"][rel] = (e["sha"], e.get("mode"))
            if rel.lower() == "skill.md":
                out[d]["skill"] = e["sha"]
    return out


def diff_folders(old: dict, new: dict) -> dict[str, str]:
    res = {}
    for d, o in old.items():
        n = new.get(d)
        if n is None or n["skill"] is None:
            res[d] = "gone"
        elif n["skill"] != o["skill"]:
            res[d] = "skill_md_changed"
        elif n["files"] != o["files"]:
            res[d] = "files_changed"
        else:
            res[d] = "unchanged"
    for d in new.keys() - old.keys():
        res[d] = "new"
    return res


def marketplace_entries(raw: bytes) -> dict[str, dict]:
    out = {}
    for p in json.loads(raw or b"{}").get("plugins", []):
        src = p.get("source")
        name = str(p.get("name", ""))[:80]
        if isinstance(src, dict):
            out[name] = {"repo": gh_repo(src.get("url", "")), "sha": src.get("sha"), "ref": src.get("ref"),
                         "path": src.get("path"), "kind": src.get("source")}
        else:
            out[name] = {"repo": None, "sha": None, "ref": None, "path": src, "kind": "relative"}
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run", help="harvest run directory name (default: newest by manifest time)")
    ap.add_argument("--limit", type=int, default=0, help="only the first N repos (testing)")
    ap.add_argument("--out", default=dt.date.today().strftime("%Y%m%d"), help="directory name under freshness/")
    a = ap.parse_args(argv)
    run = CACHE / a.run if a.run else newest_run()
    out = OUT / a.out
    out.mkdir(parents=True, exist_ok=True)
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    token = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True).stdout.strip() or None
    client = Client(token)

    old_mp_file = next((run / "marketplace").glob("*.json"))
    old_mp = marketplace_entries(old_mp_file.read_bytes())
    mp_head = head(client, out, OFFICIAL_MARKETPLACE, "HEAD")
    new_raw = cached(out / "marketplace" / f"{slug(OFFICIAL_MARKETPLACE)}@{mp_head}.json",
                     lambda: _ok(client.get(f"https://{RAW}/{OFFICIAL_MARKETPLACE}/{mp_head}/.claude-plugin/marketplace.json")))
    new_mp = marketplace_entries(new_raw)
    mp = {"old_file": old_mp_file.name, "head": mp_head,
          "added": sorted(new_mp.keys() - old_mp.keys()), "removed": sorted(old_mp.keys() - new_mp.keys()),
          "repinned": sorted(n for n in old_mp.keys() & new_mp.keys() if old_mp[n]["sha"] != new_mp[n]["sha"]),
          "plugins_then": len(old_mp), "plugins_now": len(new_mp)}
    refs = {}
    for e in old_mp.values():
        if e["repo"] and e["sha"] and e["ref"]:
            refs.setdefault((e["repo"].lower(), e["sha"]), e["ref"])

    repos, folder_rows = [], []
    for i, rr in enumerate(manifest["repos"][:a.limit or None], 1):
        if rr.get("error"):
            continue
        repo, sha = rr["repo"], rr["sha"]
        ref = refs.get((repo.lower(), sha)) if rr["tier"] == "marketplace-source" else None
        branch = ref or (rr.get("meta") or {}).get("default_branch") or "HEAD"
        tip = head(client, out, repo, branch)
        name = (rr.get("meta") or {}).get("full_name") or repo     # skills.json keys on the name after renames
        rec = {"repo": repo, "name": name, "tier": rr["tier"], "sha": sha, "branch": branch, "branch_from": "ref" if ref else "default",
               "head": tip, "plugins": rr.get("plugins") or []}
        if tip and tip != sha:
            rec["compare"] = compare(client, out, repo, sha, tip)
            new_tree = tree(client, out, run, repo, tip)
            old_tree = tree(client, out, run, repo, sha)
            if new_tree and old_tree:
                rec["truncated_now"] = bool(new_tree.get("truncated"))
                d = diff_folders(folders(old_tree.get("tree", []), rr.get("paths")),
                                 folders(new_tree.get("tree", []), rr.get("paths")))
                rec["folders"] = dict(Counter(d.values()))
                folder_rows += [{"repo": name, "dir": k, "state": v} for k, v in d.items()]
            else:
                rec["error"] = "tree missing"
        elif tip:
            rec["folders"] = {"unchanged": len({skill_dir(s["path"]) for s in rr.get("skills", [])})}
            folder_rows += [{"repo": name, "dir": k, "state": "unchanged"} for k in {skill_dir(s["path"]) for s in rr.get("skills", [])}]
        else:
            rec["error"] = "no head"
        repos.append(rec)
        if i % 25 == 0:
            print(f"freshness: {i}/{len(manifest['repos'])} repos, {client.api_calls} API calls", file=sys.stderr)

    report = {"harvest_run": manifest["run"], "harvest_fetched": manifest["fetched"],
              "checked": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
              "api_calls": client.api_calls, "marketplace": mp, "repos": repos, "folders": folder_rows}
    (out / "report.json").write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")
    print(f"freshness: {len(repos)} repos, {client.api_calls} API calls -> {out}/report.json", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
