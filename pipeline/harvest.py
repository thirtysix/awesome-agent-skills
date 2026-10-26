#!/usr/bin/env python3
"""Fetch the curated core of skills from GitHub: repo metadata, file trees and SKILL.md text.

NETWORK. Everything fetched is untrusted text. It is stored under ~/.cache/awesome-agent-skills/
harvest/<run>/ (outside synced folders and ~/.claude), never executed, and read only by pipeline/skills.py.
Outbound requests carry nothing about the user: a neutral User-Agent, no cookies, and the GitHub
token goes only to api.github.com. It is sent as an unredirected header, because urllib copies
ordinary headers onto a redirect, to whatever host that is; a redirect gets the token back only
when it points at api.github.com again. raw.githubusercontent.com never sees it.

Seeds (curation/resources.tsv plus one marketplace file):
- official: every `official-repo` row, read at its default branch head;
- anthropic-marketplace: Anthropic's own marketplace repos (MARKETPLACES), same;
- marketplace-source: the external plugin sources that claude-plugins-official lists, read at the
  commit sha the marketplace pins (all 262 carry one, 2026-10-23), limited to `path` for git-subdir.

Resumable: every response is cached on disk and reused. Blobs are checked against their git sha.
"""
from __future__ import annotations

import argparse
import datetime as dt
import gzip
import hashlib
import json
import re
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from build import read_tsv  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CACHE = Path.home() / ".cache" / "awesome-agent-skills" / "harvest"
API, RAW = "api.github.com", "raw.githubusercontent.com"
UA = "catalog-harvester/0.1"
MARKETPLACES = ["PLM001", "PLM002", "PLM003", "PLM004", "PLM005"]     # Anthropic's five
OFFICIAL_MARKETPLACE = "anthropics/claude-plugins-official"
MAX_BLOB = 256 * 1024
GH_REPO = re.compile(r"^https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?/?$")


class _Redirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is not None and urllib.parse.urlsplit(newurl).hostname == API and req.unredirected_hdrs.get("Authorization"):
            new.add_unredirected_header("Authorization", req.unredirected_hdrs["Authorization"])
        return new


OPENER = urllib.request.build_opener(_Redirect)


class Client:
    def __init__(self, token: str | None, raw_interval: float = 0.2):
        self.token, self.raw_interval = token, raw_interval
        self._lock, self._next_raw = threading.Lock(), 0.0
        self.api_calls = 0

    def get(self, url: str, accept: str | None = None) -> tuple[int, bytes]:
        host = urllib.parse.urlsplit(url).hostname
        if host not in (API, RAW):
            raise ValueError(f"refusing host {host}")
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        if accept:
            req.add_header("Accept", accept)
        if host == API:
            req.add_header("X-GitHub-Api-Version", "2022-11-28")
            if self.token:
                req.add_unredirected_header("Authorization", f"Bearer {self.token}")
        else:
            with self._lock:                       # polite: one raw request per interval, all threads
                wait = self._next_raw - time.monotonic()
                self._next_raw = max(time.monotonic(), self._next_raw) + self.raw_interval
            if wait > 0:
                time.sleep(wait)
        for attempt in range(4):
            try:
                with OPENER.open(req, timeout=60) as r:
                    body = r.read()
                    if host == API:
                        self.api_calls += 1
                        self._pace(r.headers)
                    return r.status, body
            except urllib.error.HTTPError as e:
                if host == API:
                    self.api_calls += 1
                if e.code in (403, 429) and host == API and e.headers.get("X-RateLimit-Remaining") == "0":
                    self._sleep_until(e.headers.get("X-RateLimit-Reset"))
                    continue
                if e.code == 429 and host == RAW and attempt < 3:     # raw has no rate headers; back off
                    time.sleep(min(int(e.headers.get("Retry-After") or 0) or 30 * (attempt + 1), 300))
                    continue
                if e.code in (500, 502, 503, 504) and attempt < 3:
                    time.sleep(2 ** attempt * 2)
                    continue
                return e.code, b""
            except (urllib.error.URLError, TimeoutError):
                if attempt < 3:
                    time.sleep(2 ** attempt * 2)
                    continue
                raise
        return 599, b""

    def _pace(self, headers) -> None:
        left = headers.get("X-RateLimit-Remaining")
        if left is not None and int(left) < 50:
            self._sleep_until(headers.get("X-RateLimit-Reset"))

    @staticmethod
    def _sleep_until(reset: str | None) -> None:
        wait = max(5, int(reset or 0) - int(time.time()) + 5)
        print(f"harvest: rate limit, sleeping {wait}s", file=sys.stderr)
        time.sleep(min(wait, 3700))


def gh_repo(url: str) -> str | None:
    m = GH_REPO.match(url or "")
    return f"{m[1]}/{m[2]}" if m else None


def cached(path: Path, fetch) -> bytes | None:
    """Return the cached file, or fetch and cache it. `fetch` returns bytes or None (not cached)."""
    if path.exists():
        data = path.read_bytes()
        return gzip.decompress(data) if path.suffix == ".gz" else data
    data = fetch()
    if data is not None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(gzip.compress(data) if path.suffix == ".gz" else data)
    return data


def slug(repo: str) -> str:
    return repo.replace("/", "__")


def seeds(client: Client, run: Path) -> list[dict]:
    _, rows = read_tsv(ROOT / "curation" / "resources.tsv")
    out = []
    for r in rows:
        tier = "official" if r["kind"] == "official-repo" else ("anthropic-marketplace" if r["id"] in MARKETPLACES else None)
        repo = gh_repo(r["url"]) if tier else None
        if repo:
            out.append({"repo": repo, "tier": tier, "source": r["id"], "sha": None, "paths": None, "plugins": []})
    known = {s["repo"].lower() for s in out}
    head = commit_sha(client, run, OFFICIAL_MARKETPLACE, None)
    raw = cached(run / "marketplace" / f"{slug(OFFICIAL_MARKETPLACE)}@{head}.json",
                 lambda: _ok(client.get(f"https://{RAW}/{OFFICIAL_MARKETPLACE}/{head}/.claude-plugin/marketplace.json")))
    by_key: dict[tuple, dict] = {}
    for p in json.loads(raw or b"{}").get("plugins", []):
        src = p.get("source")
        if not isinstance(src, dict) or src.get("source") not in ("url", "git-subdir"):
            continue
        repo, sha = gh_repo(src.get("url", "")), src.get("sha")
        if not repo or not re.fullmatch(r"[0-9a-f]{40}", sha or ""):
            continue
        name = str(p.get("name", ""))[:80]
        if repo.lower() in known:                      # already harvested at head as official/anthropic
            next(s for s in out if s["repo"].lower() == repo.lower())["plugins"].append(name)
            continue
        s = by_key.setdefault((repo.lower(), sha), {"repo": repo, "tier": "marketplace-source", "source": "PLM001",
                                                    "sha": sha, "paths": [], "plugins": []})
        s["plugins"].append(name)
        path = str(src.get("path", "")).strip("/") if src.get("source") == "git-subdir" else ""
        if not path:
            s["paths"] = None                          # a whole-repo source wins over subdirs
        elif s["paths"] is not None:
            s["paths"].append(path)
    out += list(by_key.values())
    return out


def _ok(resp: tuple[int, bytes]) -> bytes | None:
    return resp[1] if resp[0] == 200 else None


def commit_sha(client: Client, run: Path, repo: str, branch: str | None) -> str | None:
    ref = branch or "HEAD"
    data = cached(run / "heads" / f"{slug(repo)}.txt",
                  lambda: _ok(client.get(f"https://{API}/repos/{repo}/commits/{urllib.parse.quote(ref)}",
                                         accept="application/vnd.github.sha")))
    sha = (data or b"").decode().strip()
    return sha if re.fullmatch(r"[0-9a-f]{40}", sha) else None


def harvest_repo(client: Client, run: Path, seed: dict) -> dict:
    repo = seed["repo"]
    meta_raw = cached(run / "meta" / f"{slug(repo)}.json", lambda: _ok(client.get(f"https://{API}/repos/{repo}")))
    if not meta_raw:
        return {**seed, "error": "repo not found"}
    meta = json.loads(meta_raw)
    sha = seed["sha"] or commit_sha(client, run, repo, meta.get("default_branch"))
    if not sha:
        return {**seed, "error": "no commit"}
    tree_raw = cached(run / "trees" / f"{slug(repo)}@{sha}.json.gz",
                      lambda: _ok(client.get(f"https://{API}/repos/{repo}/git/trees/{sha}?recursive=1")))
    if not tree_raw:
        return {**seed, "sha": sha, "error": "no tree"}
    tree = json.loads(tree_raw)
    lic = (meta.get("license") or {}).get("spdx_id") or ""
    return {**seed, "sha": sha, "truncated": bool(tree.get("truncated")),
            "meta": {"full_name": meta.get("full_name"), "stars": meta.get("stargazers_count"),
                     "forks": meta.get("forks_count"), "pushed_at": meta.get("pushed_at"), "licence": lic,
                     "fork": meta.get("fork"), "archived": meta.get("archived"),
                     "default_branch": meta.get("default_branch")},
            "skills": [{"path": e["path"], "blob": e["sha"], "size": e.get("size", 0)}
                       for e in tree.get("tree", [])
                       if e.get("type") == "blob" and e["path"].rsplit("/", 1)[-1].lower() == "skill.md"
                       and (seed["paths"] is None or any(e["path"].startswith(p + "/") for p in seed["paths"]))]}


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def fetch_blob(client: Client, run: Path, repo: str, sha: str, sk: dict) -> str:
    path = run / "blobs" / f"{sk['blob']}.md"
    if path.exists():
        return "cached"
    if sk["size"] > MAX_BLOB:
        return "too big"
    url = f"https://{RAW}/{repo}/{sha}/{urllib.parse.quote(sk['path'])}"
    code, data = client.get(url)
    if code != 200:
        return f"http {code}"
    if git_blob_sha(data) != sk["blob"]:
        return "sha mismatch"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return "fetched"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--run", default=dt.date.today().strftime("%Y%m%d"), help="run directory name under the cache")
    ap.add_argument("--workers", type=int, default=4, help="threads for raw fetches (paced together)")
    ap.add_argument("--limit", type=int, default=0, help="only the first N seeds (testing)")
    a = ap.parse_args(argv)
    token = subprocess.run(["gh", "auth", "token"], capture_output=True, text=True).stdout.strip() or None
    client = Client(token)
    run = CACHE / a.run
    run.mkdir(parents=True, exist_ok=True)
    sd = seeds(client, run)
    if a.limit:
        sd = sd[:a.limit]
    print(f"harvest: {len(sd)} seeds ({sum(s['tier'] == 'official' for s in sd)} official, "
          f"{sum(s['tier'] == 'anthropic-marketplace' for s in sd)} anthropic, "
          f"{sum(s['tier'] == 'marketplace-source' for s in sd)} marketplace sources)", file=sys.stderr)
    repos = []
    for i, s in enumerate(sd, 1):
        repos.append(harvest_repo(client, run, s))
        if i % 25 == 0:
            print(f"harvest: {i}/{len(sd)} repos, {client.api_calls} API calls", file=sys.stderr)
    jobs = {}
    for r in repos:
        for sk in r.get("skills", []):
            jobs.setdefault(sk["blob"], (r["repo"], r["sha"], sk))
    print(f"harvest: {sum(len(r.get('skills', [])) for r in repos)} SKILL.md, {len(jobs)} unique blobs", file=sys.stderr)
    status: dict[str, int] = {}
    with ThreadPoolExecutor(max_workers=max(1, min(a.workers, 8))) as ex:
        for st in ex.map(lambda j: fetch_blob(client, run, *j), jobs.values()):
            status[st] = status.get(st, 0) + 1
    manifest = {"run": a.run, "fetched": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
                "api_calls": client.api_calls, "blob_status": status, "repos": repos}
    (run / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n", encoding="utf-8")
    errors = [r for r in repos if r.get("error")]
    print(f"harvest: blobs {status}; {len(errors)} repo errors; {client.api_calls} API calls -> {run}/manifest.json",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
