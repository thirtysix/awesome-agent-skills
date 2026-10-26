#!/usr/bin/env bash
# Disposable KVM guest that runs third-party skill scanners: the only place CLAUDE.md lets them run.
#
#   vm.sh image     download the Ubuntu 24.04 cloud image, verify it against signed SHA256SUMS
#   vm.sh create    pool, network filter, fresh overlay disk; boot with the build inputs only
#   vm.sh build     prove the filter from inside (internet yes, host and LAN no), build the images
#                   (AAS_BUILD="aid atr ..." builds only those; default all)
#   vm.sh export    podman save the images (AAS_EXPORT, default all) to a disk attached live, copy
#                   them to WORK/images/<stamp>/ and check their sha256 on the host (for Roihu SIFs)
#   vm.sh isolate [TAR]  power off, detach the NIC and build disk, attach skills read-only + an output
#                   disk (our own skills via stage_skills.py, or a batch TAR from stage_harvest.py)
#   vm.sh scan      prove there is no NIC, run the scanners (AAS_VCPUS / AAS_MEM_MB size the guest at isolate)
#   vm.sh salvage   stop a running scan early; the scan step then packs what finished, fetch as usual
#   vm.sh fetch     power off, copy the output disk out, extract it with tarfile's 'data' filter
#   vm.sh destroy   remove the guest and every volume except the verified base image
#
# Data moves as raw tar streams on virtio disks identified by serial: no shared folders, no network
# at scan time, no SSH. Our skills are attached only after the NIC is gone. Commands run through the
# QEMU guest agent (ga.py). Work files live outside synced folders and ~/.claude.
set -euo pipefail
HERE=$(cd "$(dirname "$(readlink -f "$0")")" && pwd)
WORK=${AAS_VM_WORK:-$HOME/.cache/awesome-agent-skills/vm}
V=(virsh -q -c qemu:///system)
POOL=aas
POOL_DIR=/var/lib/libvirt/images/aas
DOM=aas-scan
IMG=noble-server-cloudimg-amd64.img
IMG_URL=https://cloud-images.ubuntu.com/noble/current
GA=(python3 -I "$HERE/ga.py" --dom "$DOM")
mkdir -p "$WORK"

say() { printf '== %s\n' "$*"; }

vol_upload() {  # file volume
    "${V[@]}" vol-delete "$2" --pool "$POOL" >/dev/null 2>&1 || true
    "${V[@]}" vol-create-as "$POOL" "$2" "$(stat -c %s "$1")" --format raw >/dev/null
    "${V[@]}" vol-upload "$2" "$1" --pool "$POOL"
}

wait_agent() {  # seconds
    local end=$((SECONDS + $1))
    until "${GA[@]}" --ping; do
        ((SECONDS < end)) || { echo "guest agent did not answer in $1 s" >&2; exit 1; }
        sleep 10
    done
}

wait_off() {
    local end=$((SECONDS + 180))
    until [ "$("${V[@]}" domstate "$DOM")" = "shut off" ]; do
        ((SECONDS < end)) || { echo "guest did not power off" >&2; exit 1; }
        sleep 3
    done
}

target_of() {  # volume name -> disk target (vdb, sda, ...)
    "${V[@]}" domblklist "$DOM" | awk -v v="$POOL_DIR/$1" '$2 == v {print $1}'
}

case "${1:-}" in
image)
    cd "$WORK"
    curl -fsSL -A "Mozilla/5.0" -o SHA256SUMS "$IMG_URL/SHA256SUMS"
    curl -fsSL -A "Mozilla/5.0" -o SHA256SUMS.gpg "$IMG_URL/SHA256SUMS.gpg"
    gpgv --keyring /usr/share/keyrings/ubuntu-cloudimage-keyring.gpg SHA256SUMS.gpg SHA256SUMS
    [ -f "$IMG" ] || { curl -fSL -A "Mozilla/5.0" -o "$IMG.part" "$IMG_URL/$IMG" && mv "$IMG.part" "$IMG"; }
    grep -E " \*?$IMG\$" SHA256SUMS | sha256sum -c -
    ;;
create)
    if ! "${V[@]}" pool-info "$POOL" >/dev/null 2>&1; then
        "${V[@]}" pool-define-as "$POOL" dir --target "$POOL_DIR"
        "${V[@]}" pool-build "$POOL"
    fi
    "${V[@]}" pool-start "$POOL" >/dev/null 2>&1 || true
    # Always from the files: a define over an existing filter needs its uuid, and a stale one could differ.
    for f in aas-build aas-build-ipv4; do "${V[@]}" nwfilter-undefine "$f" >/dev/null 2>&1 || true; done
    "${V[@]}" nwfilter-define "$HERE/nwfilter-aas-build-ipv4.xml"
    "${V[@]}" nwfilter-define "$HERE/nwfilter-aas-build.xml"
    if ! "${V[@]}" vol-info base-noble.img --pool "$POOL" >/dev/null 2>&1; then
        grep -E " \*?$IMG\$" "$WORK/SHA256SUMS" | (cd "$WORK" && sha256sum -c -)
        vol_upload "$WORK/$IMG" base-noble.img
    fi
    xorriso -as mkisofs -quiet -o "$WORK/seed.iso" -V cidata -J -r \
        "$HERE/cloud-init/user-data" "$HERE/cloud-init/meta-data"
    vol_upload "$WORK/seed.iso" seed.iso
    tar -C "$HERE/guest" -cf "$WORK/in-build.tar" .
    vol_upload "$WORK/in-build.tar" in-build.tar
    "${V[@]}" pool-refresh "$POOL" >/dev/null
    "${V[@]}" vol-delete "$DOM.qcow2" --pool "$POOL" >/dev/null 2>&1 || true
    "${V[@]}" vol-create-as "$POOL" "$DOM.qcow2" 30G --format qcow2 \
        --backing-vol base-noble.img --backing-vol-format qcow2 >/dev/null
    virt-install --connect qemu:///system --name "$DOM" --memory 4096 --vcpus 2 \
        --osinfo ubuntu24.04 --import \
        --disk "vol=$POOL/$DOM.qcow2,bus=virtio" \
        --disk "vol=$POOL/seed.iso,device=cdrom" \
        --disk "vol=$POOL/in-build.tar,bus=virtio,format=raw,serial=aasin,readonly=on" \
        --network network=default,model=virtio,filterref.filter=aas-build \
        --channel unix,target.type=virtio,target.name=org.qemu.guest_agent.0 \
        --graphics none --noautoconsole
    say "waiting for cloud-init to install the guest agent"
    wait_agent 900
    "${GA[@]}" --timeout 900 'cloud-init status --wait >/dev/null; test -f /var/lib/aas-ready && echo ready'
    ;;
build)
    lan_ip=$(ip -4 -o addr show "$(ip route show default | awk '{print $5; exit}')" | awk '{print $4}' | cut -d/ -f1)
    gw=$(ip route show default | awk '{print $3; exit}')
    say "filter check from inside the guest"
    "${GA[@]}" --timeout 120 "
        code=\$(curl -sS -m 10 -o /dev/null -w '%{http_code}' https://pypi.org/simple/ || echo fail)
        echo \"internet (pypi.org): \$code\"
        bad=0
        for t in 192.168.122.1:17500 192.168.122.1:22 $lan_ip:17500 $gw:80 $gw:443 $gw:53; do
            if timeout 5 bash -c \"</dev/tcp/\${t%:*}/\${t#*:}\" 2>/dev/null; then echo \"REACHABLE \$t\"; bad=1
            else echo \"blocked   \$t\"; fi
        done
        exit \$bad"
    build=${AAS_BUILD:-}
    [[ "$build" =~ ^[a-z\ ]*$ ]] || { echo "AAS_BUILD takes image names only" >&2; exit 1; }
    say "building scanner images ${build:-(all)} (log: /var/lib/aas/build.log in the guest)"
    "${GA[@]}" --timeout 3600 "
        mkdir -p /in /var/lib/aas && tar -xf /dev/disk/by-id/virtio-aasin -C /in
        AAS_BUILD='$build' /in/build.sh > /var/lib/aas/build.log 2>&1; rc=\$?
        tail -25 /var/lib/aas/build.log; exit \$rc"
    ;;
export)
    names=${AAS_EXPORT:-sentry cisco skillspector agnix aid skillsref atr bawbel}
    [[ "$names" =~ ^[a-z\ ]+$ ]] || { echo "AAS_EXPORT takes image names only" >&2; exit 1; }
    dest="$WORK/images/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$dest"
    "${V[@]}" vol-delete img.raw --pool "$POOL" >/dev/null 2>&1 || true
    "${V[@]}" vol-create-as "$POOL" img.raw 6G --format raw >/dev/null
    "${V[@]}" attach-disk "$DOM" "$POOL_DIR/img.raw" vde --live --targetbus virtio --subdriver raw --serial aasimg
    sleep 3
    say "saving $names"
    "${GA[@]}" --timeout 1800 "
        set -e; rm -rf /exp && mkdir -p /exp && cd /exp
        for n in $names; do
            podman save -q -o \$n.tar localhost/aas-\$n
            echo \"\$n \$(podman image inspect --format '{{.Id}}' localhost/aas-\$n)\" >> IMAGE_IDS
        done
        sha256sum *.tar > SHA256SUMS && cat SHA256SUMS
        tar -cf /dev/disk/by-id/virtio-aasimg . && sync
        cd / && rm -rf /exp"
    "${V[@]}" detach-disk "$DOM" vde --live
    "${V[@]}" vol-download img.raw "$WORK/img.raw" --pool "$POOL"
    python3 -I -c '
import sys, tarfile
with tarfile.open(sys.argv[1]) as t:
    t.extractall(sys.argv[2], filter="data")' "$WORK/img.raw" "$dest"
    rm -f "$WORK/img.raw"
    "${V[@]}" vol-delete img.raw --pool "$POOL" >/dev/null
    (cd "$dest" && sha256sum -c SHA256SUMS)
    echo "$dest"
    ;;
isolate)
    "${V[@]}" shutdown "$DOM" >/dev/null 2>&1 || true
    wait_off
    for mac in $("${V[@]}" domiflist "$DOM" | awk '{print $5}'); do
        "${V[@]}" detach-interface "$DOM" network --mac "$mac" --config
    done
    for vol in in-build.tar seed.iso; do
        t=$(target_of "$vol"); [ -z "$t" ] || "${V[@]}" detach-disk "$DOM" "$t" --config
    done
    [ -z "$("${V[@]}" domiflist "$DOM")" ] || { echo "guest still has a NIC" >&2; exit 1; }
    vcpus=${AAS_VCPUS:-4} mem=${AAS_MEM_MB:-8192}   # host budget: 8 threads default, 12 never (CLAUDE.md)
    ((vcpus <= 8)) || { echo "AAS_VCPUS=$vcpus is over the laptop's 8-thread default" >&2; exit 1; }
    "${V[@]}" setvcpus "$DOM" "$vcpus" --config --maximum
    "${V[@]}" setvcpus "$DOM" "$vcpus" --config
    "${V[@]}" setmaxmem "$DOM" "${mem}M" --config
    "${V[@]}" setmem "$DOM" "${mem}M" --config
    if [ -n "${2:-}" ]; then
        cp -- "$2" "$WORK/in-skills.tar"        # a third-party batch from stage_harvest.py
    else
        python3 -I "$HERE/../stage_skills.py" --run "$HERE/guest/run.sh" --out "$WORK/in-skills.tar" \
            ${AAS_TOOLS:+--tools "$AAS_TOOLS"}       # e.g. AAS_TOOLS=aid,skills-ref,atr,bawbel
    fi
    vol_upload "$WORK/in-skills.tar" in-skills.tar
    "${V[@]}" vol-delete out.raw --pool "$POOL" >/dev/null 2>&1 || true
    "${V[@]}" vol-create-as "$POOL" out.raw 2G --format raw >/dev/null
    # A re-stage replaces the volumes in place; the disks stay attached at the same paths.
    [ -n "$(target_of in-skills.tar)" ] || "${V[@]}" attach-disk "$DOM" "$POOL_DIR/in-skills.tar" vdc \
        --config --targetbus virtio --subdriver raw --mode readonly --serial aasskills
    [ -n "$(target_of out.raw)" ] || "${V[@]}" attach-disk "$DOM" "$POOL_DIR/out.raw" vdd \
        --config --targetbus virtio --subdriver raw --serial aasout
    "${V[@]}" start "$DOM"
    wait_agent 300
    ;;
scan)
    say "NIC check"
    "${GA[@]}" --timeout 30 '
        links=$(ip -o link | awk -F": " "{print \$2}" | grep -v "^lo$" || true)
        if [ -n "$links" ]; then echo "guest has interfaces: $links"; exit 1; fi; echo "only lo"'
    say "running scanners (log: /out/run.log in the guest)"
    "${GA[@]}" --timeout "${AAS_SCAN_TIMEOUT:-14400}" '
        rm -rf /in2 /out && mkdir -p /in2 /out && tar -xf /dev/disk/by-id/virtio-aasskills -C /in2
        bash /in2/run.sh /in2/skills /out > /out/run.log 2>&1; rc=$?
        cp -r /var/lib/aas/record /var/lib/aas/build.log /out/ 2>/dev/null
        echo "$rc" > /out/exit-code
        tar -C /out -cf /dev/disk/by-id/virtio-aasout . && sync
        tail -20 /out/run.log; exit $rc'
    ;;
salvage)
    # Kill only the scan loop (its cmdline starts with "bash /in2/run.sh"; the agent's wrapper does not),
    # then stop any container still running. The waiting `vm.sh scan` packs /out and returns non-zero.
    "${GA[@]}" --timeout 120 'pkill -f "^python3 /in2/scan.py"; pkill -f "^bash /in2/run.sh"; sleep 3; podman ps -q | xargs -r podman stop -t 5 >/dev/null; echo stopped'
    ;;
fetch)
    "${V[@]}" shutdown "$DOM" >/dev/null 2>&1 || true
    wait_off
    out="$WORK/results/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$out"
    "${V[@]}" vol-download out.raw "$WORK/out.raw" --pool "$POOL"
    python3 -I -c '
import sys, tarfile
with tarfile.open(sys.argv[1]) as t:
    t.extractall(sys.argv[2], filter="data")' "$WORK/out.raw" "$out"
    rm -f "$WORK/out.raw"
    echo "$out"
    ;;
destroy)
    "${V[@]}" destroy "$DOM" >/dev/null 2>&1 || true
    "${V[@]}" undefine "$DOM" >/dev/null 2>&1 || true
    for vol in "$DOM.qcow2" seed.iso in-build.tar in-skills.tar out.raw img.raw; do
        "${V[@]}" vol-delete "$vol" --pool "$POOL" >/dev/null 2>&1 || true
    done
    say "guest removed; base-noble.img kept"
    ;;
*)
    sed -n '2,10p' "$0"; exit 2
    ;;
esac
