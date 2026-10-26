#!/usr/bin/env python3
"""Telemetry facts of staged skills and plugin roots: what code sends where, no verdicts. Standard library only.

Runs INSIDE a scanner container (no network, the chunk mounted read-only), never on a host:
    python telemetry.py /skills /out/report.json
For every folder under /skills it records:
- analytics and error-reporting hosts named in code files (a fixed list: PostHog, Segment, Amplitude,
  Mixpanel, Sentry ingest, Google Analytics, Datadog intake, Scarf, ... and any telemetry.* host);
- analytics SDKs imported by code (posthog, @segment/analytics-node, sentry_sdk, ...);
- detached, silent process launches (spawn with detached + stdio ignore, Popen with a new session and
  DEVNULL, nohup/setsid/disown in shell), and which of those files also make a network call or name a
  telemetry host: a "silent sender" outlives the agent's turn and shows the user nothing;
- whether a hook configuration names a sender file (hooks run on every matching event, unasked);
- opt-out environment variables the code reads (DO_NOT_TRACK, *_TELEMETRY*, *_ANALYTICS*);
- whether the folder's markdown or manifest says anything about telemetry or usage data.
Only counts, file names (truncated), hosts, SDK names and env var names leave the container; no file text.
"""
from __future__ import annotations

import json
import os
import re
import sys

MAX_READ = 2 * 1024 * 1024
CODE_EXT = {"py", "sh", "bash", "zsh", "js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx", "rb", "ps1", "go", "rs", "php"}
URL_HOST = re.compile(rb"https?://([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)")
TELEMETRY_HOSTS = ("posthog.com", "segment.io", "segment.com", "amplitude.com", "mixpanel.com", "ingest.sentry.io",
                   "ingest.us.sentry.io", "ingest.de.sentry.io", "google-analytics.com", "analytics.google.com",
                   "googletagmanager.com", "plausible.io", "statsigapi.net", "statsig.com", "events.launchdarkly.com",
                   "browser-intake-datadoghq.com", "datadoghq.com", "datadoghq.eu", "honeycomb.io", "bugsnag.com",
                   "rollbar.com", "heapanalytics.com", "hotjar.com", "nr-data.net", "logrocket.io", "fullstory.com",
                   "umami.is", "rudderstack.com", "dataplane.rudderstack.com", "pendo.io", "scarf.sh", "pirsch.io",
                   "usefathom.com", "clarity.ms", "applicationinsights.azure.com", "visualstudio.com/v2/track")
SDK_NAMES = (rb"""(posthog(?:[-_](?:node|js|python))?|@segment/analytics[\w-]*|"""
             rb"""analytics-node|mixpanel(?:-browser)?|@amplitude/[\w-]+|amplitude[\w-]*|@sentry/[\w-]+|sentry_sdk|"""
             rb"""statsig[\w-]*|@datadog/[\w-]+|ddtrace|applicationinsights|@rudderstack/[\w-]+|rudder[\w-]*sdk|"""
             rb"""@scarf/[\w-]+|@vercel/analytics|universal-analytics|@google-analytics/[\w-]+)""")
# JS/TS: a quoted module name after require( / from / import; Python: a bare name at line start.
SDK = re.compile(rb"""(?:require\s*\(\s*|\bfrom\s+|\bimport\s*\(?\s*)['"]""" + SDK_NAMES + rb"""(?=['"/])""")
SDK_PY = re.compile(rb"^\s*(?:import|from)\s+" + SDK_NAMES + rb"\b", re.M)
# A detached child with every output channel discarded, in JS, Python and shell.
JS_DETACHED = re.compile(rb"detached\s*:\s*true")
JS_SILENT = re.compile(rb"""stdio\s*:\s*['"]ignore['"]|stdio\s*:\s*\[\s*['"]ignore['"]\s*,\s*['"]ignore['"]\s*,\s*['"]ignore['"]""")
PY_DETACHED = re.compile(rb"start_new_session\s*=\s*True|preexec_fn\s*=\s*os\.setsid|DETACHED_PROCESS|CREATE_NEW_PROCESS_GROUP")
PY_SILENT = re.compile(rb"stdout\s*=\s*(?:subprocess\.)?DEVNULL")
SH_DETACHED = re.compile(rb"^\s*(?:nohup|setsid)\b[^\n]*(?:>\s*/dev/null|&\s*$)|&\s*disown\b|\)\s*&\s*>\s*/dev/null", re.M)
NETWORK = re.compile(rb"\bfetch\s*\(|https?\.request\s*\(|\baxios\b|\bgot\s*\(|XMLHttpRequest|sendBeacon|requests\.(?:post|get|put)\s*\(|"
                     rb"urllib\.request|\bhttpx\.|http\.client|\bcurl\s+-|\bwget\s+|Invoke-WebRequest|Invoke-RestMethod|net/http")
OPT_OUT = re.compile(rb"\b(DO_NOT_TRACK|[A-Z][A-Z0-9_]*(?:TELEMETRY|ANALYTICS|TRACKING|NO_TRACK)[A-Z0-9_]*)\b")
DISCLOSE = re.compile(rb"(?i)\btelemetry\b|\busage (?:data|statistics|metrics)\b|\banonymous(?:ly)? (?:usage|statistics|metrics|data)\b|"
                      rb"\bopt[- ]out of\b|\bDO_NOT_TRACK\b|\bcollects? (?:anonymous|usage|basic)\b")
WINDOW = 600


def read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(MAX_READ)


def telemetry_host(h: str) -> bool:
    return h.startswith("telemetry.") or any(h == t or h.endswith("." + t) for t in TELEMETRY_HOSTS if "/" not in t)


def detached_silent(b: bytes, ext: str) -> int:
    """Launches that detach and discard all output: a window around each detach marker must also silence it."""
    n = 0
    if ext in ("js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx"):
        for m in JS_DETACHED.finditer(b):
            n += bool(JS_SILENT.search(b, max(0, m.start() - WINDOW), m.end() + WINDOW))
    elif ext == "py":
        for m in PY_DETACHED.finditer(b):
            n += bool(PY_SILENT.search(b, max(0, m.start() - WINDOW), m.end() + WINDOW))
    elif ext in ("sh", "bash", "zsh"):
        n += len(SH_DETACHED.findall(b))
    return n


def folder(root: str) -> dict:
    r = {"code_files": 0, "hosts": set(), "sdks": set(), "detached_silent": 0, "senders": [], "opt_out_env": set(),
         "disclosed_in": set(), "hook_configs": 0}
    hook_text = b""
    senders = []
    for dp, dns, fns in os.walk(root, followlinks=False):
        dns[:] = [d for d in dns if d not in ("node_modules", ".git") and not os.path.islink(os.path.join(dp, d))]
        for fn in fns:
            p = os.path.join(dp, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            rel = os.path.relpath(p, root)
            low = fn.lower()
            ext = low.rsplit(".", 1)[-1] if "." in low else ""
            try:
                b = read(p)
            except OSError:
                continue
            if ext == "json" and (low == "hooks.json" or "/hooks/" in "/" + rel.replace(os.sep, "/") or low == "settings.json"
                                  or low == "plugin.json"):
                if b'"hooks"' in b or low == "hooks.json":
                    r["hook_configs"] += 1
                    hook_text += b"\n" + b
            if ext in ("md", "txt") or low in ("plugin.json", "package.json", "readme"):
                if DISCLOSE.search(b):
                    r["disclosed_in"].add("SKILL.md" if low == "skill.md" else "README" if low.startswith("readme")
                                          else "manifest" if ext == "json" else "other docs")
            if ext not in CODE_EXT:
                continue
            r["code_files"] += 1
            hosts = {h.decode("ascii", "replace").lower() for h in URL_HOST.findall(b)}
            thosts = {h for h in hosts if telemetry_host(h)}
            r["hosts"] |= thosts
            r["sdks"].update(s.decode("ascii", "replace") for s in (SDK_PY if ext == "py" else SDK).findall(b))
            r["opt_out_env"].update(e.decode("ascii", "replace") for e in OPT_OUT.findall(b))
            ds = detached_silent(b, ext)
            r["detached_silent"] += ds
            if ds:
                senders.append({"file": rel[:120], "launches": ds, "network": bool(NETWORK.search(b)),
                                "telemetry": bool(thosts or SDK.search(b) or SDK_PY.search(b) or re.search(rb"(?i)telemetry|analytics|posthog", b))})
    for s in senders:
        stem = os.path.basename(s["file"]).rsplit(".", 1)[0].encode()
        s["hooked"] = bool(hook_text) and stem in hook_text
    r["senders"] = senders[:20]
    r["silent_senders"] = sum(1 for s in senders if s["network"] or s["telemetry"])
    r["hooked_senders"] = sum(1 for s in senders if s["hooked"] and (s["network"] or s["telemetry"]))
    for k in ("hosts", "sdks", "opt_out_env", "disclosed_in"):
        r[k] = sorted(r[k])[:20]
    return r


def main() -> int:
    src, out = sys.argv[1], sys.argv[2]
    report = {}
    for name in sorted(os.listdir(src)):
        p = os.path.join(src, name)
        if os.path.isdir(p) and not os.path.islink(p):
            try:
                report[name] = folder(p)
            except Exception as e:              # one bad folder must not lose the chunk
                report[name] = {"error": type(e).__name__}
    with open(out, "w") as fh:
        json.dump(report, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
