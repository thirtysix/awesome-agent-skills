#!/bin/bash
#SBATCH --job-name=aas-scan
#SBATCH --partition=small
#SBATCH --time=02:00:00
#SBATCH --cpus-per-task=64
#SBATCH --mem=128G
# One batch of harvested third-party skills through the four static scanners on a Roihu compute node.
#   sbatch --account=$CSC_PROJECT --output=/scratch/$CSC_PROJECT/aas/runs/%x-%j.out --export=ALL,CSC_PROJECT,TAG=<batch tag> [--cpus-per-task=N --mem=2N G] scan.slurm
# Input: runs/$TAG/in.tar from vetter/stage_harvest.py (skills/, scan.py, plan.json, manifest.json).
# The skills are only ever unpacked here, on scratch, and only read inside the scanner containers:
# apptainer --containall --cleanenv --no-home --net --network none (loopback only), the chunk bound
# read-only and its output directory writable. LLM options stay off. Results go back as a tar.
# Everything between the input tar and the result tar lives in the node's RAM disk (/dev/shm), not on
# Lustre: unpacking, the per-chunk hard-link trees and the per-skill outputs are hundreds of thousands of
# small files, which hit the project's 500 K file quota (2026-10-25, job 2526670) and made setup slow.
set -uo pipefail
A=/scratch/${CSC_PROJECT:?set CSC_PROJECT to the CSC project, e.g. project_NNNNNNN}/aas
R=$A/runs/$TAG
[ -f "$R/in.tar" ] || exit 1
W=/dev/shm/aas-${SLURM_JOB_ID:-$$}
trap '[ -f "$R/out.tar" ] || tar -C "$W/out" -cf "$R/out-partial.tar" . 2>/dev/null; rm -rf "$W"' EXIT   # keep what finished if the job dies
mkdir -p "$W/in" "$W/work" "$W/out" && cd "$W" || exit 1
tar -xf "$R/in.tar" -C in --no-same-owner --no-same-permissions || exit 1
cd "$A/sif" && sha256sum -c --quiet SHA256SUMS || exit 1
cd "$W"
export AAS_RUNTIME=apptainer AAS_SIF_DIR=$A/sif AAS_WORK=$W/work AAS_PARALLEL=${SLURM_CPUS_PER_TASK:-8}
export APPTAINER_CACHEDIR=$A/.apptainer
t0=$SECONDS
python3 -u in/scan.py in/skills out in/plan.json > out/run.log 2>&1
rc=$?
echo "$rc" > out/exit-code
echo "scan rc=$rc in $((SECONDS - t0)) s with $AAS_PARALLEL workers"
rm -rf work in/skills
tar -C out -cf "$R/out.tar" . && echo "results: $R/out.tar"
exit $rc
