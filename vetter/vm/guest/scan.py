#!/usr/bin/env python3
"""Runs INSIDE the scanner guest (from run.sh) after its NIC is detached: scan.py SKILLS OUT [PLAN]

One queue of (tool, chunk) jobs, longest predicted first, on as many workers as vCPUs. Each job
starts its tool once for a chunk of skills (Cisco scan-all, SkillSpector --recursive, a loop for
Sentry and agnix), so start-up is paid per chunk, not per skill. Ordering by predicted cost puts the
big SkillSpector chunks first and the many short Cisco/Sentry/agnix chunks last, where they fill
the workers that would otherwise idle while the final long jobs finish.

PLAN (plan.json from stage_harvest.py) gives the chunks and predicted seconds per job; without it
(our own skills via stage_skills.py) chunks are built here by count. A chunk is hard links
/work/<chunk>/<folder name>/ -> skills/<sid>/<folder name>/, with no folder name twice in a chunk.
Chunk reports are split into the per-skill files the host parser reads (<tool>/<sid>.json|.stdout).
A chunk whose report is missing or unreadable is rescanned skill by skill by the same worker.

Every container: no network, read-only root, no capabilities, nobody, skills read-only, 1 CPU.
LLM, upload and lookup options stay off. Output is the tools' own, parsed later on the host.

Which tools run: AAS_TOOLS, else tools.txt beside this script (the stager writes it), else all. Jobs
in PLAN for other tools are skipped, so one staged batch can feed a run of any subset.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor

SKILLS, OUT = sys.argv[1], sys.argv[2]
PLAN = sys.argv[3] if len(sys.argv) > 3 and os.path.exists(sys.argv[3]) else None
WORK = os.environ.get("AAS_WORK", "/work/chunks")      # same filesystem as SKILLS: chunks are hard links
P = int(os.environ.get("AAS_PARALLEL") or os.cpu_count() or 1)
TOOLS = ("sentry", "cisco-behavioral", "skillspector", "agnix", "aid", "skills-ref", "atr", "bawbel", "inventory",
         "telemetry", "obfuscation", "guarddog", "bandit", "agentshield", "holguard", "osv", "gitleaks", "clamav", "yara")
LOOP = ("sentry", "agnix", "skills-ref", "guarddog", "agentshield", "holguard")     # one file per skill folder
CHUNK = ("bandit", "osv", "gitleaks", "clamav", "yara")                            # one report per chunk, split by path
PLUGIN_ONLY = ("agentshield", "holguard")                                           # run on p__ entries only
OWN = ("inventory", "telemetry", "obfuscation")                                     # our scripts: one report per chunk
_PICK = os.environ.get("AAS_TOOLS") or next(
    (open(f).read() for f in [os.path.join(os.path.dirname(os.path.abspath(__file__)), "tools.txt")]
     if os.path.exists(f)), "")
RUN = tuple(t for t in TOOLS if t in _PICK.replace(",", " ").split()) or TOOLS
BASE = ["podman", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--user", "65534:65534", "--cpus", "1", "--memory", "3g",
        "--tmpfs", "/tmp:rw,size=512m,mode=1777", "-e", "HOME=/tmp", "-e", "TERM=dumb", "-e", "NO_COLOR=1",
        "-e", "COLUMNS=120"]
TIMEOUT = {"sentry": 1800, "cisco-behavioral": 3600, "skillspector": 7200, "agnix": 1800,
           "aid": 1800, "skills-ref": 1800, "atr": 1800, "bawbel": 3600, "inventory": 1800, "telemetry": 1800, "obfuscation": 1800, "guarddog": 7200, "bandit": 1800,
           "agentshield": 1800, "holguard": 1800, "osv": 1800, "gitleaks": 1800, "clamav": 3600, "yara": 3600}
# AAS_RUNTIME=apptainer (CSC Roihu): the same images as SIF files in AAS_SIF_DIR, run with no network
# namespace beyond loopback (--net --network none; without it a Roihu container reaches the internet),
# no home, a clean environment and only the chunk (read-only) and its output directory bound.
RUNTIME = os.environ.get("AAS_RUNTIME", "podman")
SIF = os.environ.get("AAS_SIF_DIR", "")
APPT = ["apptainer", "exec", "--containall", "--cleanenv", "--no-home", "--net", "--network", "none",
        "--env", "HOME=/tmp,TERM=dumb,NO_COLOR=1,COLUMNS=120"]
IMAGE = {"localhost/aas-sentry": "sentry", "localhost/aas-cisco": "cisco",
         "localhost/aas-skillspector": "skillspector", "localhost/aas-agnix": "agnix",
         "localhost/aas-aid": "aid", "localhost/aas-skillsref": "skillsref", "localhost/aas-atr": "atr",
         "localhost/aas-bawbel": "bawbel", "localhost/aas-guarddog": "guarddog", "localhost/aas-bandit": "bandit",
         "localhost/aas-agentshield": "agentshield", "localhost/aas-holguard": "holguard", "localhost/aas-osv": "osv",
         "localhost/aas-gitleaks": "gitleaks", "localhost/aas-clamav": "clamav", "localhost/aas-yara": "yara"}
ENTRY = {"sentry": ["python", "/opt/sentry/scan_skill.py"], "skillspector": ["skillspector"],
         "agnix": ["/usr/local/bin/agnix"], "cisco": ["python3"], "aid": ["python", "/opt/aid/aid.py"],
         "skillsref": ["skills-ref"], "atr": ["atr"], "bawbel": ["bawbel"], "guarddog": ["guarddog"], "bandit": ["bandit"],
         "agentshield": ["agentshield"], "holguard": ["plugin-scanner"], "osv": ["osv-scanner"], "gitleaks": ["gitleaks"],
         "clamav": ["clamscan"], "yara": ["yr"]}


def to_apptainer(argv: list[str]) -> list[str]:
    """Translate one podman command built by cmd() into apptainer exec with the same image, binds,
    entrypoint and arguments."""
    binds, i, entry, rest = [], 2, None, None
    while i < len(argv):
        a = argv[i]
        if a == "-v":
            binds.append(argv[i + 1]); i += 2
        elif a == "--entrypoint":
            entry = [argv[i + 1]]; i += 2
        elif a in IMAGE:
            rest = argv[i + 1:]; img = IMAGE[a]; break
        elif a.startswith("--") or a in ("-e",):
            i += 2 if a in ("--network", "--cap-drop", "--security-opt", "--user", "--cpus", "--memory",
                            "--tmpfs", "-e", "--name") else 1
        else:
            i += 1
    b = []
    for spec in binds:
        b += ["-B", spec]
    return APPT + b + [os.path.join(SIF, f"{img}.sif")] + (entry or ENTRY[img]) + rest
LOCK = threading.Lock()


def log(*fields) -> None:
    with LOCK, open(os.path.join(OUT, "runs.tsv"), "a") as fh:
        fh.write("\t".join(str(f) for f in fields) + "\n")


def say(msg: str) -> None:
    with LOCK:
        print(f"{time.strftime('%H:%M:%S')} {msg}", flush=True)


def default_plan() -> list[dict]:
    """Our own skills: count-based chunks of 60, same chunks for every tool."""
    chunks: list[dict] = []
    for sid in sorted(os.listdir(SKILLS)):
        for name in sorted(os.listdir(os.path.join(SKILLS, sid))):
            c = next((c for c in chunks if name not in c and len(c) < 60), None)
            if c is None:
                c = {}
                chunks.append(c)
            c[name] = sid
    return [{"tool": t, "chunk": f"{t}-{i:04d}", "names": c, "cost": len(c)} for t in RUN for i, c in enumerate(chunks)]


def cmd(tool: str, chunk_dir: str, out_dir: str, single: str | None = None) -> list[str]:
    v = ["-v", f"{chunk_dir}:/skills:ro", "-v", f"{out_dir}:/out"]
    loop = lambda img, body: BASE + v + ["--entrypoint", "sh", img, "-c",
                                         'for s in /skills/*/; do n=$(basename "$s"); ' + body + ' > "/out/$n.stdout" 2> "/out/$n.stderr"; done']
    if single:                                   # the loop/chunk tools take one folder the same way
        v = ["-v", f"{chunk_dir}/{single}:/skills/{single}:ro", "-v", f"{out_dir}:/out"]
    # GuardDog: source rules only (metadata rules need registry data), Python rules everywhere, npm rules where
    # there is JS; skipped for folders with no code. --no-sandbox: its own seccomp sandbox cannot start in ours.
    CODE = "find \"$s\" -type f \\( -name '*.py' -o -name '*.sh' -o -name '*.js' -o -name '*.mjs' -o -name '*.cjs' -o -name '*.ts' -o -name package.json -o -name setup.py \\) | grep -q ."
    if tool == "guarddog":
        return BASE + v + ["--entrypoint", "sh", "localhost/aas-guarddog", "-c",
                           'for s in /skills/*/; do n=$(basename "$s"); ' + CODE + ' || { echo \'{"skipped": "no code files"}\' > "/out/$n.stdout"; continue; }; '
                           'guarddog pypi scan "$s" --no-sandbox --output-format json > "/out/$n.stdout" 2> "/out/$n.stderr"; '
                           'if find "$s" -type f \\( -name "*.js" -o -name "*.mjs" -o -name "*.cjs" -o -name "*.ts" -o -name package.json \\) | grep -q .; then '
                           'guarddog npm scan "$s" --no-sandbox --output-format json > "/out/$n.npm.json" 2>> "/out/$n.stderr"; fi; done']
    if tool == "agentshield":                    # static rules only: never --sandbox/--deep/--opus/--injection/--supply-chain-online
        return loop("localhost/aas-agentshield", 'agentshield scan -p "$s" -f json --supply-chain')
    if tool == "holguard":                       # Cisco sub-scans off (Cisco runs on its own); no verify/submit
        return loop("localhost/aas-holguard", 'plugin-scanner scan "$s" --format json --cisco-skill-scan off --cisco-mcp-scan off --ecosystem claude')
    if tool == "bandit":                         # six high-severity constructs only, shown as "construct present"
        return BASE + v + ["--entrypoint", "sh", "localhost/aas-bandit", "-c",
                           "bandit -r /skills -t B102,B307,B602,B605,B301,B506 -f json -o /out/report.json -q 2> /out/tool.stderr; true"]
    if tool == "osv":                            # offline database baked in at build; fails closed without it
        return BASE + v + ["--entrypoint", "sh", "localhost/aas-osv", "-c",
                           # v2.7 looks for <cache>/osv-scalibr/<ecosystem>/all.zip and wants the cache writable:
                           # a tmpfs directory whose osv-scalibr entry points at the read-only copy baked in at build
                           "mkdir -p /tmp/osvdb && ln -sfn /opt/osvdb/osv-scanner /tmp/osvdb/osv-scalibr && "
                           "OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/tmp/osvdb osv-scanner scan source --offline -r /skills --format json --output-file /out/report.json "
                           "--verbosity info 2> /out/tool.stderr; true"]
    if tool == "gitleaks":                       # --redact: the secret never reaches a report
        return BASE + v + ["--entrypoint", "sh", "localhost/aas-gitleaks", "-c",
                           "gitleaks dir /skills --report-format json --report-path /out/report.json --no-banner --redact --exit-code 0 2> /out/tool.stderr"]
    if tool == "clamav":                         # signatures baked in at build; PUA detection off (the default)
        return BASE + v + ["--entrypoint", "sh", "localhost/aas-clamav", "-c",
                           "clamscan -r --infected --no-summary /skills > /out/report.txt 2> /out/clamav.stderr; true"]
    if tool == "yara":
        return BASE + v + ["--entrypoint", "sh", "localhost/aas-yara", "-c",
                           "yr scan -r -w --disable-console-logs -o json /opt/yara-forge/packages/core/yara-rules-core.yar /skills "
                           "> /out/report.json 2> /out/yara.stderr; true"]
    if tool in OWN:                              # our own fact scripts, inside the skills-ref image's Python
        script = os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{tool}.py")
        return BASE + v + ["-v", f"{script}:/opt/{tool}.py:ro", "--entrypoint", "python", "localhost/aas-skillsref",
                           f"/opt/{tool}.py", "/skills", "/out/one.json" if single else "/out/report.json"]
    if tool == "sentry" and single:
        return BASE + v + ["localhost/aas-sentry", f"/skills/{single}"]
    if tool == "agnix" and single:
        return BASE + v + ["localhost/aas-agnix", f"/skills/{single}", "--target", "claude-code", "--format", "json"]
    if tool == "sentry":
        return BASE + v + ["--entrypoint", "sh", "localhost/aas-sentry", "-c",
                           'for s in /skills/*/; do n=$(basename "$s"); python /opt/sentry/scan_skill.py "$s" '
                           '> "/out/$n.stdout" 2> "/out/$n.stderr"; done']
    if tool == "agnix":
        return BASE + v + ["--entrypoint", "sh", "localhost/aas-agnix", "-c",
                           'for s in /skills/*/; do n=$(basename "$s"); agnix "$s" --target claude-code --format json '
                           '> "/out/$n.stdout" 2> "/out/$n.stderr"; done']
    if tool == "cisco-behavioral":
        if single:
            return BASE + v + ["--entrypoint", "skill-scanner", "localhost/aas-cisco", "scan", f"/skills/{single}",
                               "--use-behavioral", "--format", "json", "--output-json", "/out/one.json"]
        return BASE + v + ["--entrypoint", "skill-scanner", "localhost/aas-cisco", "scan-all", "/skills",
                           "--use-behavioral", "--format", "json", "--output-json", "/out/report.json"]
    if tool == "aid":
        return BASE + v + ["localhost/aas-aid", "--target", f"/skills/{single}" if single else "/skills",
                           "--format", "json", "--output", "/out/one.json" if single else "/out/report.json"]
    if tool == "skills-ref" and single:
        return BASE + v + ["localhost/aas-skillsref", "validate", f"/skills/{single}"]
    if tool == "skills-ref":
        return BASE + v + ["--entrypoint", "sh", "localhost/aas-skillsref", "-c",
                           'for s in /skills/*/; do n=$(basename "$s"); skills-ref validate "$s" '
                           '> "/out/$n.stdout" 2> "/out/$n.stderr"; done']
    if tool == "atr" and single:                 # prints its report; run() captures it
        return BASE + v + ["localhost/aas-atr", "scan", f"/skills/{single}", "--json"]
    if tool == "atr":
        return BASE + v + ["--entrypoint", "sh", "localhost/aas-atr", "-c", "atr scan /skills --json > /out/report.json"]
    if tool == "bawbel" and single:              # --no-ignore: a skill must not suppress its own findings
        return BASE + v + ["localhost/aas-bawbel", "scan", f"/skills/{single}", "--recursive", "--no-ignore",
                           "--format", "json"]
    if tool == "bawbel":
        return BASE + v + ["--entrypoint", "sh", "localhost/aas-bawbel", "-c",
                           "bawbel scan /skills --recursive --no-ignore --format json > /out/report.json"]
    if single:
        return BASE + v + ["localhost/aas-skillspector", "scan", f"/skills/{single}", "--no-llm",
                           "--format", "json", "--output", "/out/one.json"]
    return BASE + v + ["localhost/aas-skillspector", "scan", "/skills", "--recursive", "--no-llm",
                       "--format", "json", "--output", "/out/report.json"]


def run(argv: list[str], timeout: int, log_base: str, name: str) -> int:
    """Run one container named `name`; on timeout remove it (killing the podman client does not)."""
    if RUNTIME == "apptainer":
        argv = to_apptainer(argv)
    else:
        argv = argv[:2] + ["--name", name] + argv[2:]
    with open(f"{log_base}.stdout", "wb") as so, open(f"{log_base}.stderr", "wb") as se:
        try:
            return subprocess.run(argv, stdout=so, stderr=se, timeout=timeout).returncode
        except subprocess.TimeoutExpired:            # apptainer's process dies with subprocess's kill
            if RUNTIME != "apptainer":
                subprocess.run(["podman", "rm", "-f", name], capture_output=True)
            return 124


def load(path: str):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def split(tool: str, names: dict, d: str) -> list[str]:
    """Move the chunk's output into per-skill files; return the names it had no report for."""
    dest = os.path.join(OUT, tool)
    if tool in CHUNK:
        for f in (os.listdir(d) if os.path.isdir(d) else []):   # keep each chunk's stderr: a silent failure must be visible
            if f.endswith(".stderr") and os.path.getsize(os.path.join(d, f)):
                shutil.copy(os.path.join(d, f), os.path.join(dest, f"_{os.path.basename(d)}.{f}"))
        for name, items in chunk_items(tool, d, names).items():
            with open(os.path.join(dest, f"{names[name]}.json"), "w") as fh:
                json.dump({"items": items}, fh)
        return [] if os.path.exists(os.path.join(d, "report.txt" if tool == "clamav" else "report.json")) else list(names)
    if tool in LOOP:
        missing = []
        for name, sid in names.items():
            if not os.path.exists(os.path.join(d, f"{name}.stdout")):
                missing.append(name)          # e.g. a folder name starting with "." that the glob skips
            for ext in ("stdout", "stderr", "npm.json"):
                src = os.path.join(d, f"{name}.{ext}")
                if os.path.exists(src):
                    shutil.move(src, os.path.join(dest, f"{sid}.{ext}"))
        return missing
    rep = load(os.path.join(d, "report.json"))
    if rep is None:
        return list(names)
    if tool in OWN:
        for name, sid in names.items():
            if name in rep:
                with open(os.path.join(dest, f"{sid}.json"), "w") as fh:
                    json.dump(rep[name], fh)
        return [n for n in names if n not in rep]
    if tool in ("aid", "atr", "bawbel"):
        for name, items in by_skill(tool, rep, names).items():
            with open(os.path.join(dest, f"{names[name]}.json"), "w") as fh:
                json.dump({"items": items}, fh)
        return []
    entries = rep.get("results", []) if tool == "cisco-behavioral" else rep.get("skills", [])
    seen = set()
    for e in entries:
        name = (e.get("name") if tool == "skillspector" else None) or str(e.get("skill_path") or e.get("path") or "").rstrip("/").split("/")[-1]
        if name not in names:
            continue
        body = {"findings": e.get("findings", []), "skill_name": e.get("skill_name")} if tool == "cisco-behavioral" else e
        with open(os.path.join(dest, f"{names[name]}.json"), "w") as fh:
            json.dump(body, fh)
        seen.add(name)
    return [n for n in names if n not in seen]


GITLEAKS_KEEP = ("RuleID", "Description", "File", "StartLine", "EndLine", "Entropy", "Tags")


def chunk_items(tool: str, d: str, names: dict) -> dict:
    """A chunk report's items grouped by skill folder (path /skills/<name>/...), path made relative.
    gitleaks keeps rule, file and line only: never the secret or the line it sits on."""
    out: dict = {n: [] for n in names}
    def put(path: str, item: dict) -> None:
        parts = str(path).lstrip("/").split("/")
        if parts[:1] == ["skills"]:
            parts = parts[1:]
        if parts and parts[0] in out:
            out[parts[0]].append({**item, "_file": "/".join(parts[1:])})
    if tool == "clamav":
        try:
            lines = open(os.path.join(d, "report.txt"), errors="replace").read().splitlines()
        except OSError:
            return out
        for ln in lines:
            if ln.endswith(" FOUND") and ": " in ln:
                path, sig = ln.rsplit(": ", 1)
                put(path, {"signature": sig[:-len(" FOUND")]})
        return out
    rep = load(os.path.join(d, "report.json"))
    if rep is None:
        return out
    if tool == "bandit":
        for it in rep.get("results", []):
            put(it.get("filename", ""), {k: it.get(k) for k in ("test_id", "test_name", "issue_severity", "issue_confidence", "line_number")})
    elif tool == "gitleaks":
        for it in rep if isinstance(rep, list) else []:
            put(it.get("File", ""), {k: it.get(k) for k in GITLEAKS_KEEP})
    elif tool == "osv":
        for res in rep.get("results", []):
            for src in res.get("packages", []) and [res] or []:
                path = (src.get("source") or {}).get("path", "")
                for pk in src.get("packages", []):
                    pkg = pk.get("package") or {}
                    put(path, {"package": pkg.get("name"), "version": pkg.get("version"), "ecosystem": pkg.get("ecosystem"),
                               "ids": [x.get("id") for x in pk.get("vulnerabilities", [])][:20]})
    elif tool == "yara":
        for it in rep.get("matches", rep if isinstance(rep, list) else []):
            path = it.get("file") or it.get("path") or ""
            for rule in it.get("rules", [it]):
                put(path, {"rule": rule.get("identifier") or rule.get("rule"), "namespace": rule.get("namespace")})
    return out


def items_of(tool: str, rep) -> list:
    if tool == "aid":
        return rep.get("files", []) if isinstance(rep, dict) else []
    if tool == "atr":
        return rep.get("results", []) if isinstance(rep, dict) else []
    return rep if isinstance(rep, list) else []                       # bawbel: a list of file results


def by_skill(tool: str, rep, names: dict, single: str | None = None) -> dict:
    """A chunk report's entries grouped by skill folder, every skill of the chunk present (a skill the
    tool had nothing to say about gets an empty list). Paths are made relative to the skill folder:
    aid reports them from its target, ATR and bawbel absolutely (/skills/<name>/...)."""
    out: dict = {n: [] for n in names}
    for it in items_of(tool, rep):
        key = "file" if tool == "atr" else "file_path"
        path = str(it.get(key) or "")
        parts = path.lstrip("/").split("/")
        if tool != "aid" and parts[:1] == ["skills"]:
            parts = parts[1:]
        if single is not None:
            name = single
            if tool != "aid" and parts[:1] == [single]:
                parts = parts[1:]
        else:
            name, parts = (parts[0], parts[1:]) if parts else ("", [])
        if name in out:
            out[name].append({**it, key: "/".join(parts)})
    return out


def job(j: dict, k: int, n: int) -> None:
    tool, chunk, names = j["tool"], j["chunk"], j["names"]
    cdir, d = os.path.join(WORK, chunk), os.path.join(OUT, "c", chunk)
    os.makedirs(d, exist_ok=True)
    os.chmod(d, 0o777)
    t0 = time.monotonic()
    rc = run(cmd(tool, cdir, d), TIMEOUT[tool], f"{d}.job", f"aas-{chunk}")
    secs = round(time.monotonic() - t0)
    missing = split(tool, names, d)
    log(tool, chunk, rc, secs, len(names), round(j.get("cost", 0)))
    for name in missing:                      # fallback: one container per skill
        t1 = time.monotonic()
        sid = names[name]
        if tool in CHUNK:                     # a chunk report that failed outright: nothing to retry singly
            continue
        if tool in LOOP:                      # these print their report: the per-skill file
            r = run(cmd(tool, cdir, d, single=name), 900, os.path.join(OUT, tool, sid), f"aas-{chunk}-1")
        elif tool in ("aid", "atr", "bawbel"):
            r = run(cmd(tool, cdir, d, single=name), 900, f"{d}.one", f"aas-{chunk}-1")
            rep = load(os.path.join(d, "one.json")) if tool == "aid" else load(f"{d}.one.stdout")
            if rep is not None:
                with open(os.path.join(OUT, tool, f"{sid}.json"), "w") as fh:
                    json.dump({"items": by_skill(tool, rep, {name: sid}, single=name)[name]}, fh)
        else:
            r = run(cmd(tool, cdir, d, single=name), 900, f"{d}.one", f"aas-{chunk}-1")
            rep = load(os.path.join(d, "one.json"))
            if tool in OWN:
                rep = (rep or {}).get(name)
            if rep is not None:
                with open(os.path.join(OUT, tool, f"{sid}.json"), "w") as fh:
                    json.dump(rep, fh)
        log(f"{tool}-single", sid, r, round(time.monotonic() - t1), 1, 0)
        try:
            os.remove(os.path.join(d, "one.json"))
        except OSError:
            pass
    shutil.rmtree(d, ignore_errors=True)
    say(f"done {k}/{n} {tool} {chunk} {len(names)} skills {secs}s (predicted {round(j.get('cost', 0))}s)"
        + (f", rescanned {len(missing)} singly" if missing else ""))


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    os.chmod(OUT, 0o777)
    for t in RUN:
        os.makedirs(os.path.join(OUT, t), exist_ok=True)
        os.chmod(os.path.join(OUT, t), 0o777)
    with open(os.path.join(OUT, "runs.tsv"), "w") as fh:
        fh.write("tool\tskill\texit\tseconds\tskills\tpredicted\n")
    jobs = [j for j in json.load(open(PLAN))["jobs"] if j["tool"] in RUN] if PLAN else default_plan()
    shutil.rmtree(WORK, ignore_errors=True)
    for j in jobs:                             # one hard-link copy per chunk: chunk/<name> for each skill
        cdir = os.path.join(WORK, j["chunk"])
        os.makedirs(cdir, exist_ok=True)
        srcs = [os.path.join(SKILLS, sid, name) for name, sid in j["names"].items()]
        srcs = [x for x in srcs if os.path.isdir(x)]
        if srcs:
            subprocess.run(["cp", "-al", "--"] + srcs + [cdir + "/"])
    jobs.sort(key=lambda j: -j.get("cost", 0))          # longest predicted first (LPT)
    n = len(jobs)
    say(f"tools: {' '.join(RUN)}; {n} jobs over {len({s for j in jobs for s in j['names'].values()})} skills, {P} workers")
    with ThreadPoolExecutor(max_workers=P) as ex:
        for f in [ex.submit(job, j, k, n) for k, j in enumerate(jobs, 1)]:
            f.result()
    shutil.rmtree(os.path.join(OUT, "c"), ignore_errors=True)
    say("done")
    return 0


if __name__ == "__main__":
    sys.exit(main())
