#!/bin/bash
#SBATCH --job-name=aas-sif
#SBATCH --partition=small
#SBATCH --time=00:45:00
#SBATCH --cpus-per-task=4
#SBATCH --mem=8G
# Convert the scanner images exported from the VM (vm.sh export: podman save, sha256-checked) into SIF
# files. Same image bytes as the VM ran; nothing is pulled from a registry here.
#   sbatch --account=$CSC_PROJECT --output=/scratch/$CSC_PROJECT/aas/sif/build-%j.out --export=ALL,CSC_PROJECT,IMAGES="aid skillsref atr bawbel" build_sif.slurm   (default: the first four)
# SIFs already in sif/ are checked against SHA256SUMS before the list is rewritten to include the new ones.
set -uo pipefail
A=/scratch/${CSC_PROJECT:?set CSC_PROJECT to the CSC project, e.g. project_NNNNNNN}/aas
IMAGES=${IMAGES:-sentry cisco skillspector agnix}
export APPTAINER_CACHEDIR=$A/.apptainer APPTAINER_TMPDIR=$A/.apptainer/tmp
mkdir -p "$APPTAINER_TMPDIR"
cd "$A/images" && sha256sum -c SHA256SUMS || exit 1
if [ -f "$A/sif/SHA256SUMS" ]; then (cd "$A/sif" && sha256sum -c --quiet SHA256SUMS) || exit 1; fi
fail=0
for i in $IMAGES; do
    apptainer build --force "$A/sif/$i.sif" "docker-archive://$A/images/$i.tar" || fail=1
done
(cd "$A/sif" && sha256sum ./*.sif | sed 's| \./| |' > SHA256SUMS && cat SHA256SUMS)
exit $fail
