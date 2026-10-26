#!/usr/bin/env python3
"""Content inventory of staged skills: facts code reads from each file, no verdicts. Standard library only.

Runs INSIDE a scanner container (no network, the chunk mounted read-only), never on a host:
    python inventory.py /skills /out/report.json
For every skill folder under /skills it records what a person deciding to install it would want listed:
- dependency manifests and how many declared packages are not pinned to an exact version;
- npm lifecycle scripts (preinstall/install/postinstall/prepare), which run on install;
- inline script metadata (PEP 723) blocks, Dockerfile base images without a digest or with :latest;
- lines that fetch and run something (curl|sh, wget|sh, npx, uvx, pipx run, pip install, git clone);
- web hosts named in code files (not markdown), symlinks and whether their target leaves the folder;
- SVG/HTML files carrying <script> or on* handlers, HTML comments in markdown, long base64-like runs;
- mentions of credential and agent-configuration paths (~/.ssh, ~/.aws, .env, CLAUDE.md, settings.json,
  shell rc files, crontab, systemd units, .git/hooks).
Only counts, names (truncated) and hosts leave the container; no file text.
"""
from __future__ import annotations

import json
import os
import re
import sys

MAX_READ = 2 * 1024 * 1024
CODE_EXT = {"py", "sh", "bash", "zsh", "js", "mjs", "cjs", "ts", "rb", "pl", "ps1", "go", "rs", "php", "lua"}
URL_HOST = re.compile(rb"https?://([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
FETCH_RUN = re.compile(rb"(?:curl|wget)[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\bnpx\s+(?:-y\s+)?[@\w]|\buvx\s+\w|"
                       rb"\bpipx\s+run\b|\bpip3?\s+install\b|\bgit\s+clone\b|\biex\s*\(|Invoke-Expression")
PEP723 = re.compile(rb"^# /// script\s*$", re.M)
SVG_ACTIVE = re.compile(rb"<script\b|\son[a-z]+\s*=", re.I)
HTML_COMMENT = re.compile(rb"<!--(?!\s*(?:prettier|markdownlint|toc|eslint)).{20,}?-->", re.S)
B64_RUN = re.compile(rb"[A-Za-z0-9+/]{400,}={0,2}")
SENSITIVE = {
    "ssh": rb"~/\.ssh\b|\.ssh/id_|id_rsa\b|id_ed25519\b",
    "cloud_creds": rb"~/\.aws\b|\.aws/credentials|gcloud/credentials|\.azure/|\.kube/config",
    "dotenv": rb"(?<![\w.])\.env(?:\.\w+)?\b",
    "agent_config": rb"CLAUDE\.md|AGENTS\.md|\.claude/settings|settings\.local\.json|\.mcp\.json|\.cursor/",
    "shell_rc": rb"\.bashrc|\.zshrc|\.profile\b|\.bash_profile",
    "scheduler": rb"\bcrontab\b|/etc/cron|systemctl\s+(?:--user\s+)?enable|\.config/systemd|LaunchAgents",
    "git_hooks": rb"\.git/hooks|core\.hooksPath",
}
SENS = {k: re.compile(v) for k, v in SENSITIVE.items()}
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")
REQ_PIN = re.compile(r"^\s*[A-Za-z0-9_.\-\[\],]+\s*===?\s*[\w.*+!-]+")


def read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(MAX_READ)


def requirements(b: bytes) -> tuple[int, int]:
    n = unpinned = 0
    for line in b.decode("utf-8", "replace").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith(("-", "git+", "http")):
            unpinned += bool(line.startswith(("git+", "http")))
            n += bool(line.startswith(("git+", "http")))
            continue
        n += 1
        unpinned += not REQ_PIN.match(line)
    return n, unpinned


def package_json(b: bytes) -> tuple[int, int, list[str]]:
    try:
        d = json.loads(b.decode("utf-8", "replace"))
    except ValueError:
        return 0, 0, []
    deps = {}
    for k in ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies"):
        if isinstance(d.get(k), dict):
            deps.update(d[k])
    unpinned = sum(1 for v in deps.values() if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][\w.]+)?", str(v).strip()))
    scripts = d.get("scripts") if isinstance(d.get("scripts"), dict) else {}
    return len(deps), unpinned, [k for k in LIFECYCLE if k in scripts]


def pyproject(b: bytes) -> tuple[int, int]:
    try:
        import tomllib
        d = tomllib.loads(b.decode("utf-8", "replace"))
    except Exception:
        return 0, 0
    deps = list((d.get("project") or {}).get("dependencies") or [])
    return len(deps), sum(1 for x in deps if "==" not in str(x))


def dockerfile(b: bytes) -> int:
    loose = 0
    for m in re.finditer(rb"^\s*FROM\s+(\S+)", b, re.M | re.I):
        img = m.group(1)
        loose += b"@sha256:" not in img and (b":" not in img.split(b"/")[-1] or img.endswith(b":latest"))
    return loose


def skill(root: str) -> dict:
    r = {"files": 0, "manifests": {}, "deps": 0, "unpinned": 0, "lifecycle": [], "pep723": 0, "docker_loose": 0,
         "fetch_run": 0, "code_hosts": set(), "links": 0, "links_out": 0, "active_docs": 0, "html_comments": 0,
         "b64": 0, "sensitive": set()}
    real = os.path.realpath(root)
    for dp, dns, fns in os.walk(root, followlinks=False):
        for fn in fns + [d for d in dns if os.path.islink(os.path.join(dp, d))]:
            p = os.path.join(dp, fn)
            if os.path.islink(p):
                r["links"] += 1
                tgt = os.path.realpath(p)
                r["links_out"] += not (tgt == real or tgt.startswith(real + os.sep))
                continue
            if not os.path.isfile(p):
                continue
            r["files"] += 1
            low = fn.lower()
            ext = low.rsplit(".", 1)[-1] if "." in low else ""
            try:
                b = read(p)
            except OSError:
                continue
            if low.startswith("requirements") and ext == "txt":
                n, u = requirements(b)
                r["manifests"]["requirements"] = r["manifests"].get("requirements", 0) + 1
                r["deps"] += n; r["unpinned"] += u
            elif low == "package.json":
                n, u, lc = package_json(b)
                r["manifests"]["package.json"] = r["manifests"].get("package.json", 0) + 1
                r["deps"] += n; r["unpinned"] += u; r["lifecycle"] += lc
            elif low == "pyproject.toml":
                n, u = pyproject(b)
                r["manifests"]["pyproject"] = r["manifests"].get("pyproject", 0) + 1
                r["deps"] += n; r["unpinned"] += u
            elif low == "dockerfile" or low.endswith(".dockerfile"):
                r["manifests"]["dockerfile"] = r["manifests"].get("dockerfile", 0) + 1
                r["docker_loose"] += dockerfile(b)
            if ext == "py":
                r["pep723"] += bool(PEP723.search(b))
            if ext in CODE_EXT or ext == "md":
                r["fetch_run"] += len(FETCH_RUN.findall(b))
            if ext in CODE_EXT:
                r["code_hosts"].update(h.decode("ascii", "replace").lower() for h in URL_HOST.findall(b))
            if ext in ("svg", "html", "htm", "xhtml"):
                r["active_docs"] += bool(SVG_ACTIVE.search(b))
            if ext == "md":
                r["html_comments"] += len(HTML_COMMENT.findall(b))
            if ext not in ("png", "jpg", "jpeg", "gif", "webp", "ico", "pdf", "woff", "woff2", "ttf", "otf", "zip", "gz"):
                r["b64"] += len(B64_RUN.findall(b))
                for k, rx in SENS.items():
                    if rx.search(b):
                        r["sensitive"].add(k)
    r["code_hosts"] = sorted(r["code_hosts"])[:20]
    r["n_code_hosts"] = len(r["code_hosts"])
    r["sensitive"] = sorted(r["sensitive"])
    r["lifecycle"] = sorted(set(r["lifecycle"]))
    return r


def main() -> int:
    src, out = sys.argv[1], sys.argv[2]
    report = {}
    for name in sorted(os.listdir(src)):
        p = os.path.join(src, name)
        if os.path.isdir(p) and not os.path.islink(p):
            try:
                report[name] = skill(p)
            except Exception as e:              # one bad folder must not lose the chunk
                report[name] = {"error": type(e).__name__}
    with open(out, "w") as fh:
        json.dump(report, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
