#!/usr/bin/env bash
# One batch of harvested third-party skills through the scanner guest:
#   vetter/run_batch.sh START STOP [stage_harvest.py options, e.g. --skip-scanned]
#   (positions in stage_harvest.py's fixed order, STOP exclusive; AAS_VCPUS / AAS_MEM_MB size the guest)
# stage (network: raw files at the pinned commit) -> isolate (guest has no NIC) -> scan -> fetch ->
# manifest into the results dir -> summary. Logs to ~/.cache/awesome-agent-skills/vm/batch-START-STOP.log.
# Package temperature is logged before and after.
set -euo pipefail
HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
WORK=${AAS_VM_WORK:-$HOME/.cache/awesome-agent-skills/vm}
START=$1 STOP=$2
TAG=$(printf 'h-%05d-%05d' "$START" "$STOP")
temp() { sensors 2>/dev/null | awk '/^Package id 0:/ {print "package " $4; exit}'; }
echo "== $(date +%T) $TAG $(temp)"
python3 -I "$HERE/stage_harvest.py" --start "$START" --stop "$STOP" --out "$WORK/in-$TAG.tar" "${@:3}"
"$HERE/vm/vm.sh" isolate "$WORK/in-$TAG.tar"
"$HERE/vm/heat_guard.sh" >> "$WORK/heat-$TAG.log" 2>&1 &
guard=$!
trap 'kill $guard 2>/dev/null; virsh -q -c qemu:///system resume aas-scan >/dev/null 2>&1' EXIT
"$HERE/vm/vm.sh" scan | tail -3
kill $guard 2>/dev/null; virsh -q -c qemu:///system resume aas-scan >/dev/null 2>&1 || true
out=$("$HERE/vm/vm.sh" fetch | tail -1)
cp "$WORK/in-$TAG.manifest.json" "$out/manifest.json"
echo "== $(date +%T) fetched $out $(temp)"
python3 -I "$HERE/summarise_scans.py" "$out" --manifest "$out/manifest.json" > "$out/summary.txt" || true
head -12 "$out/summary.txt"
