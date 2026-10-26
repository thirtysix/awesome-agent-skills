"""Offline tests for vetter/vm/guest/telemetry.py on synthetic folders (our own fixture text)."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vetter" / "vm" / "guest"))
import telemetry as tm  # noqa: E402

JS_SENDER = """import { spawn } from "node:child_process";
const DEFAULT_KEY = "phc_x";
const KEY = process.env.ACME_TELEMETRY_KEY ?? DEFAULT_KEY;
if (process.env.DO_NOT_TRACK) process.exit(0);
const child = spawn(process.execPath, [file, "--emit", payload], { detached: true, stdio: "ignore" });
child.unref();
await fetch("https://us.i.posthog.com/capture/", { method: "POST", body });
"""
PY_SENDER = """import subprocess, requests
subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
requests.post("https://telemetry.acme.dev/v1", json=data)
"""
PY_QUIET_LOCAL = """import subprocess
subprocess.Popen(["xdg-open", path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
"""
JS_NOT_SILENT = """spawn("server", [], { detached: true, stdio: "inherit" });\n"""


def write(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def test_hooked_js_sender_with_host_opt_out_and_no_disclosure(tmp_path):
    d = write(tmp_path / "plug", {
        "hooks/hooks.json": '{"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "node ${CLAUDE_PLUGIN_ROOT}/hooks/track.mjs"}]}]}}',
        "hooks/track.mjs": JS_SENDER,
        "README.md": "A plugin that lints your code.\n"})
    r = tm.folder(str(d))
    assert r["hosts"] == ["us.i.posthog.com"] and r["detached_silent"] == 1
    assert r["silent_senders"] == 1 and r["hooked_senders"] == 1
    assert r["senders"][0] == {"file": "hooks/track.mjs", "launches": 1, "network": True, "telemetry": True, "hooked": True}
    assert set(r["opt_out_env"]) == {"ACME_TELEMETRY_KEY", "DO_NOT_TRACK"} and r["disclosed_in"] == []


def test_python_sender_disclosed_and_quiet_local_launch(tmp_path):
    d = write(tmp_path / "skill", {
        "SKILL.md": "---\nname: s\n---\nThis skill sends anonymous usage data; set DO_NOT_TRACK=1 to opt out of it.\n",
        "scripts/send.py": PY_SENDER, "scripts/open.py": PY_QUIET_LOCAL, "scripts/serve.js": JS_NOT_SILENT})
    r = tm.folder(str(d))
    assert r["hosts"] == ["telemetry.acme.dev"] and r["disclosed_in"] == ["SKILL.md"]
    assert r["detached_silent"] == 2 and r["silent_senders"] == 1 and r["hooked_senders"] == 0
    files = {s["file"]: s for s in r["senders"]}
    assert files["scripts/open.py"]["network"] is False and files["scripts/open.py"]["telemetry"] is False


def test_shell_sdk_and_main(tmp_path):
    d = write(tmp_path / "chunk" / "one", {
        "run.sh": "nohup ./ping.sh > /dev/null 2>&1 &\n",
        "lib/a.ts": 'import posthog from "posthog-node";\nimport * as Sentry from "@sentry/node";\n',
        "docs/links.md": "See https://posthog.com/docs\n"})
    out = tmp_path / "report.json"
    assert tm.main.__code__.co_argcount == 0
    sys.argv = ["telemetry.py", str(tmp_path / "chunk"), str(out)]
    assert tm.main() == 0
    r = json.loads(out.read_text())["one"]
    assert r["sdks"] == ["@sentry/node", "posthog-node"] and r["hosts"] == []      # markdown links are not code
    assert r["detached_silent"] == 1 and r["silent_senders"] == 0


def test_source_is_ascii():
    for f in (ROOT / "vetter" / "vm" / "guest" / "telemetry.py", Path(__file__)):
        assert f.read_bytes().isascii()


def test_python_sdk_import():
    assert tm.SDK_PY.findall(b"import sentry_sdk\nfrom posthog import Posthog\nx = 'import mixpanel'\n") == [b"sentry_sdk", b"posthog"]
    assert not tm.SDK.findall(b"import posthog from 'lodash'\n")
