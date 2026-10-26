#!/usr/bin/env bash
# Pause the scanner guest when the laptop runs hot: heat_guard.sh [PAUSE_AVG_C] [RESUME_AVG_C] [HARD_C]
# Decides on a 10-second rolling average of the package temperature, because the instantaneous
# reading swings by 20 C within a second under turbo (measured 62 -> 93 -> 72 C); a guard on single
# readings paused every few seconds. Pauses at an average of 85 C or any single reading of 96 C,
# resumes at an average of 75 C. virsh suspend freezes the guest's vCPUs (no work lost; ga.py waits
# through it). 92 C sustained under an 8-thread load is the thermal event on record.
# Runs until killed (run_batch.sh starts it around the scan). Logs each pause and resume.
set -uo pipefail
PAUSE=${1:-85} RESUME=${2:-75} HARD=${3:-96}
V=(virsh -q -c qemu:///system)
DOM=aas-scan
win=()
while true; do
    t=$(sensors 2>/dev/null | awk '/^Package id 0:/ {gsub(/[^0-9.]/, "", $4); print int($4); exit}')
    if [ -n "$t" ]; then
        win+=("$t"); [ "${#win[@]}" -gt 10 ] && win=("${win[@]:1}")
        sum=0; for x in "${win[@]}"; do sum=$((sum + x)); done; avg=$((sum / ${#win[@]}))
        state=$("${V[@]}" domstate "$DOM" 2>/dev/null)
        if [ "$state" = "running" ] && { [ "$avg" -ge "$PAUSE" ] || [ "$t" -ge "$HARD" ]; }; then
            "${V[@]}" suspend "$DOM" >/dev/null && echo "$(date +%T) paused (avg ${avg}C, now ${t}C)"
        elif [ "$state" = "paused" ] && [ "$avg" -le "$RESUME" ] && [ "$t" -lt "$HARD" ]; then
            "${V[@]}" resume "$DOM" >/dev/null && echo "$(date +%T) resumed (avg ${avg}C, now ${t}C)"
        fi
    fi
    sleep 1
done
