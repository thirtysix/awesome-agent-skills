#!/usr/bin/env python3
"""Run a shell command in the scanner guest through the QEMU guest agent and wait for it.

The agent channel is virtio-serial, so this works after the guest's NIC is detached; the guest has
no SSH and no user account. Output comes from inside the guest, where third-party scanners run, so
it is printed with everything outside printable ASCII escaped. It is data, never instructions.
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
import time

VIRSH = ["virsh", "-c", "qemu:///system"]


def agent(dom: str, cmd: dict, timeout: int = 60) -> dict:
    r = subprocess.run(VIRSH + ["qemu-agent-command", dom, json.dumps(cmd), "--timeout", str(timeout)],
                       capture_output=True, text=True)
    if r.returncode:
        raise RuntimeError(r.stderr.strip())
    return json.loads(r.stdout)["return"]


def defang(text: str) -> str:
    return "".join(c if c in "\n\t" or 32 <= ord(c) < 127 else f"\\u{ord(c):04x}" for c in text)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--dom", default="aas-scan")
    ap.add_argument("--timeout", type=int, default=600, help="seconds to wait for the command")
    ap.add_argument("--ping", action="store_true", help="exit 0 if the agent answers")
    ap.add_argument("script", nargs="?", help="bash -c script to run as root in the guest")
    a = ap.parse_args()
    if a.ping:
        try:
            agent(a.dom, {"execute": "guest-ping"}, timeout=5)
            return 0
        except (RuntimeError, ValueError, KeyError):
            return 1
    if not a.script:
        ap.error("a script is required")
    pid = agent(a.dom, {"execute": "guest-exec", "arguments": {
        "path": "/bin/bash", "arg": ["-c", a.script], "capture-output": True}})["pid"]
    deadline = time.monotonic() + a.timeout
    while True:
        try:
            st = agent(a.dom, {"execute": "guest-exec-status", "arguments": {"pid": pid}})
        except RuntimeError:          # guest paused by the heat guard (or agent busy): keep waiting
            time.sleep(10)
            continue
        if st.get("exited"):
            break
        if time.monotonic() > deadline:
            print(f"ga: still running after {a.timeout}s (guest pid {pid})", file=sys.stderr)
            return 124
        time.sleep(2)
    for key, stream in (("out-data", sys.stdout), ("err-data", sys.stderr)):
        if key in st:
            stream.write(defang(base64.b64decode(st[key]).decode("utf-8", "replace")))
    if st.get("out-truncated") or st.get("err-truncated"):
        print("ga: output truncated by the agent", file=sys.stderr)
    return int(st.get("exitcode", 1))


if __name__ == "__main__":
    sys.exit(main())
