#!/usr/bin/env bash
# Runs INSIDE the disposable guest during the build phase, while its network is on but filtered away
# from the host and the LAN (nwfilter aas-build). Builds one image per scanner from the pins in
# pins.env and records what was installed. Our skills are not in the guest yet: they are attached
# only after the NIC has been detached.
# AAS_BUILD (space-separated) picks the images; default all. Image names are those in scan.py.
set -euo pipefail
cd "$(dirname "$0")"
source ./pins.env
REC=/var/lib/aas/record
BUILD=${AAS_BUILD:-sentry cisco skillspector agnix aid skillsref atr bawbel guarddog bandit agentshield holguard osv gitleaks clamav yara}
want() { case " $BUILD " in *" $1 "*) return 0 ;; esac; return 1; }
mkdir -p "$REC"

fetch() {  # url sha256 dest: download, verify, or stop
    curl -fsSL --retry 3 -A "Mozilla/5.0" -o "$3" "$1"
    if ! echo "$2  $3" | sha256sum -c --quiet; then
        echo "CHECKSUM MISMATCH: $1" >&2; rm -f "$3"; exit 1
    fi
}

clone_at() {  # url sha dest. Refuse a ref named like a commit id (Plugin4Shell): checkout would
    rm -rf "$3"  # resolve the name, not the commit.
    git clone -q "$1" "$3"
    if git -C "$3" for-each-ref --format='%(refname:short)' | grep -qE '(^|/)[0-9a-f]{40}$'; then
        echo "a ref is named like a commit id; refusing" >&2; exit 1
    fi
    git -C "$3" -c advice.detachedHead=false checkout -q "$2"
    [ "$(git -C "$3" rev-parse HEAD)" = "$2" ]
}

fetch_sri() {  # url sri(sha512-...) dest: npm-style integrity
    curl -fsSL --retry 3 -A "Mozilla/5.0" -o "$3" "$1"
    if [ "sha512-$(openssl dgst -sha512 -binary "$3" | base64 -w0)" != "$2" ]; then
        echo "INTEGRITY MISMATCH: $1" >&2; rm -f "$3"; exit 1
    fi
}

podman pull -q "$PY_BASE" >/dev/null
podman tag "$PY_BASE" localhost/aas-base

# T01 Sentry
if want sentry; then
    mkdir -p /build/sentry
    fetch "https://raw.githubusercontent.com/getsentry/skills/$SENTRY_SHA/skills/skill-scanner/scripts/scan_skill.py" \
        "$SENTRY_SCRIPT_SHA256" /build/sentry/scan_skill.py
    fetch "$PYYAML_URL" "$PYYAML_SHA256" "/build/sentry/$(basename "$PYYAML_URL")"
    cp Containerfile.sentry /build/sentry/Containerfile
    podman build -q -t localhost/aas-sentry /build/sentry
fi

# T02 Cisco (dependencies resolve from PyPI; pip freeze below records what came)
if want cisco; then
    mkdir -p /build/cisco
    fetch "$CISCO_URL" "$CISCO_SHA256" "/build/cisco/$(basename "$CISCO_URL")"
    cp Containerfile.cisco /build/cisco/Containerfile
    podman build -q -t localhost/aas-cisco /build/cisco
fi

# T03 SkillSpector, from its own Dockerfile
if want skillspector; then
    clone_at https://github.com/NVIDIA/SkillSpector "$SKILLSPECTOR_SHA" /build/skillspector
    podman build -q -t localhost/aas-skillspector /build/skillspector
fi

# T17 agnix
if want agnix; then
    mkdir -p /build/agnix
    fetch "$AGNIX_URL" "$AGNIX_SHA256" /build/agnix/agnix.tar.gz
    tar -tzf /build/agnix/agnix.tar.gz > "$REC/agnix-tarball-listing.txt"
    tar -xzf /build/agnix/agnix.tar.gz -C /build/agnix
    find /build/agnix -type f -name agnix -exec install -m 0755 {} /build/agnix/agnix-bin \;
    cp Containerfile.agnix /build/agnix/Containerfile
    podman build -q -t localhost/aas-agnix /build/agnix
fi

# T05 aid: one stdlib script
if want aid; then
    mkdir -p /build/aid
    fetch "https://raw.githubusercontent.com/wunderwuzzi23/aid/$AID_SHA/aid" "$AID_SCRIPT_SHA256" /build/aid/aid.py
    cp Containerfile.aid /build/aid/Containerfile
    podman build -q -t localhost/aas-aid /build/aid
fi

# P01 skills-ref, from the spec repo at the pinned commit (dependencies from PyPI)
if want skillsref; then
    clone_at https://github.com/agentskills/agentskills "$SKILLSREF_SHA" /build/agentskills
    mkdir -p /build/skillsref
    rm -rf /build/skillsref/skills-ref && cp -r /build/agentskills/skills-ref /build/skillsref/skills-ref
    cp Containerfile.skillsref /build/skillsref/Containerfile
    podman build -q -t localhost/aas-skillsref /build/skillsref
fi

# T13 ATR: the npm tarball, install scripts off (its dependencies resolve from npm; npm ls records them)
if want atr; then
    podman pull -q "$NODE_BASE" >/dev/null
    podman tag "$NODE_BASE" localhost/aas-node
    mkdir -p /build/atr
    fetch "$ATR_URL" "$ATR_SHA256" /build/atr/atr.tgz
    cp Containerfile.atr /build/atr/Containerfile
    podman build -q -t localhost/aas-atr /build/atr
fi

# T19 bawbel: the PyPI wheel with the yara extra
if want bawbel; then
    mkdir -p /build/bawbel
    fetch "$BAWBEL_URL" "$BAWBEL_SHA256" "/build/bawbel/$(basename "$BAWBEL_URL")"
    cp Containerfile.bawbel /build/bawbel/Containerfile
    podman build -q -t localhost/aas-bawbel /build/bawbel
fi

# --- second wave ---
node_base() { podman pull -q "$NODE_BASE" >/dev/null; podman tag "$NODE_BASE" localhost/aas-node; }
if want guarddog; then
    mkdir -p /build/guarddog
    fetch "$GUARDDOG_URL" "$GUARDDOG_SHA256" "/build/guarddog/$(basename "$GUARDDOG_URL")"
    cp Containerfile.guarddog /build/guarddog/Containerfile
    podman build -q -t localhost/aas-guarddog /build/guarddog
fi
if want bandit; then
    mkdir -p /build/bandit
    fetch "$BANDIT_URL" "$BANDIT_SHA256" "/build/bandit/$(basename "$BANDIT_URL")"
    cp Containerfile.bandit /build/bandit/Containerfile
    podman build -q -t localhost/aas-bandit /build/bandit
fi
if want agentshield; then
    node_base
    mkdir -p /build/agentshield
    fetch_sri "$AGENTSHIELD_URL" "$AGENTSHIELD_SRI" /build/agentshield/agentshield.tgz
    cp Containerfile.agentshield /build/agentshield/Containerfile
    podman build -q -t localhost/aas-agentshield /build/agentshield
fi
if want holguard; then
    mkdir -p /build/holguard
    fetch "$HOLGUARD_URL" "$HOLGUARD_SHA256" "/build/holguard/$(basename "$HOLGUARD_URL")"
    cp Containerfile.holguard /build/holguard/Containerfile
    podman build -q -t localhost/aas-holguard /build/holguard
fi
if want osv; then
    mkdir -p /build/osv/osvdb/osv-scanner/PyPI /build/osv/osvdb/osv-scanner/npm
    fetch "$OSV_URL" "$OSV_SHA256" /build/osv/osv-scanner
    chmod 0755 /build/osv/osv-scanner
    for eco in PyPI npm; do   # the offline databases, dated by this build; sha256 recorded
        curl -fsSL --retry 3 -A "Mozilla/5.0" -o "/build/osv/osvdb/osv-scanner/$eco/all.zip" \
            "https://osv-vulnerabilities.storage.googleapis.com/$eco/all.zip"
        sha256sum "/build/osv/osvdb/osv-scanner/$eco/all.zip" >> "$REC/osvdb-sha256.txt"
        unzip -Z1 "/build/osv/osvdb/osv-scanner/$eco/all.zip" | grep -c '^MAL-' > "$REC/osvdb-$eco-mal-count.txt" || true
    done
    date -u +%FT%TZ > "$REC/osvdb-date.txt"
    cp Containerfile.osv /build/osv/Containerfile
    podman build -q -t localhost/aas-osv /build/osv
fi
if want gitleaks; then
    mkdir -p /build/gitleaks
    fetch "$GITLEAKS_URL" "$GITLEAKS_SHA256" /build/gitleaks/gitleaks.tar.gz
    tar -xzf /build/gitleaks/gitleaks.tar.gz -C /build/gitleaks gitleaks
    cp Containerfile.gitleaks /build/gitleaks/Containerfile
    podman build -q -t localhost/aas-gitleaks /build/gitleaks
fi
if want clamav; then
    podman pull -q "$CLAMAV_BASE" >/dev/null
    podman tag "$CLAMAV_BASE" localhost/aas-clamav-base
    mkdir -p /build/clamav
    cp Containerfile.clamav /build/clamav/Containerfile
    podman build -t localhost/aas-clamav /build/clamav > "$REC/clamav-build.txt" 2>&1
    date -u +%FT%TZ > "$REC/clamav-db-date.txt"
fi
if want yara; then
    mkdir -p /build/yara/rules
    fetch "$YARAX_URL" "$YARAX_SHA256" /build/yara/yarax.tar.gz
    tar -xzf /build/yara/yarax.tar.gz -C /build/yara
    find /build/yara -maxdepth 2 -type f -name yr -exec install -m 0755 {} /build/yara/yr \;
    fetch "$YARAFORGE_URL" "$YARAFORGE_SHA256" /build/yara/core.zip
    unzip -q -o /build/yara/core.zip -d /build/yara/rules
    cp Containerfile.yara /build/yara/Containerfile
    podman build -q -t localhost/aas-yara /build/yara
fi

# What was built, for the record
podman images --digests --format '{{.Repository}}:{{.Tag}} {{.Digest}} {{.ID}}' > "$REC/images.txt"
for t in sentry cisco skillspector skillsref bawbel; do
    want "$t" || continue
    podman run --rm --network none --entrypoint python localhost/aas-$t -m pip freeze > "$REC/pip-freeze-$t.txt"
done
if want agnix; then podman run --rm --network none localhost/aas-agnix --version > "$REC/agnix-version.txt" 2>&1 || true; fi
if want atr; then
    podman run --rm --network none --entrypoint npm localhost/aas-atr ls -g --all > "$REC/npm-ls-atr.txt" 2>&1 || true
    podman run --rm --network none localhost/aas-atr --version > "$REC/atr-version.txt" 2>&1 || true
fi
if want bawbel; then podman run --rm --network none localhost/aas-bawbel --version > "$REC/bawbel-version.txt" 2>&1 || true; fi
for t in guarddog bandit agentshield holguard osv gitleaks clamav yara; do   # versions and help text, to confirm flags
    want "$t" || continue
    podman run --rm --network none localhost/aas-$t --version > "$REC/$t-version.txt" 2>&1 || true
    podman run --rm --network none localhost/aas-$t --help > "$REC/$t-help.txt" 2>&1 || true
done
for t in guarddog bandit holguard; do want "$t" && podman run --rm --network none --entrypoint python localhost/aas-$t -m pip freeze > "$REC/pip-freeze-$t.txt" || true; done
if want agentshield; then podman run --rm --network none --entrypoint npm localhost/aas-agentshield ls -g --all > "$REC/npm-ls-agentshield.txt" 2>&1 || true; fi
echo "build ok: $BUILD"
