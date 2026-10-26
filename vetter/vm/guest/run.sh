#!/usr/bin/env bash
# Runs INSIDE the scanner guest after its NIC is detached: run.sh SKILLS_DIR OUT_DIR
# The work is scan.py's: one queue of (tool, chunk) jobs, longest first, one worker per vCPU, using
# plan.json when the stager wrote one (harvested batches) and count-based chunks otherwise.
# Kept as a separate step so `vm.sh salvage` can stop it by its command line.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
python3 "$HERE/scan.py" "$1" "$2" "$HERE/plan.json"
