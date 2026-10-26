"""Offline tests for vetter/vm/guest/obfuscation.py on synthetic folders (our own fixture text, all of it harmless:
the decoded strings are print calls, a module name and a temp-file rm)."""
from __future__ import annotations

import base64
import json
import sys
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "vetter" / "vm" / "guest"))
import obfuscation as ob  # noqa: E402

BS = chr(92)                                    # a backslash, built rather than typed (see CLAUDE.md gotchas)


def codes(s: str) -> str:
    return ", ".join(str(ord(c)) for c in s)


def write(root: Path, files: dict) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return root


def notes(r: dict, fact: str) -> list:
    return [n for n in r["notes"] if n["fact"] == fact]


def test_tuple_of_char_codes_through_a_variable_into_exec(tmp_path):
    py = (f"T = ({codes(chr(112) + 'rint(1)')})\n"
          "code = ''.join(map(chr, T))\n"
          "exec(code)\n")
    r = ob.folder(str(write(tmp_path / "s", {"scripts/run.py": py})))
    assert r["flows"] == {"exec": 1} and r["sinks"] == {"exec": 1}
    (f,) = notes(r, "flow")
    assert f == {"file": "scripts/run.py", "line": 3, "fact": "flow", "class": "python", "sink": "exec", "via": "name",
                 "decoders": ["chr"]}
    assert r["int_seqs"] == 1 and r["text_seqs"] == {"python": 1}


def test_hidden_names_xor_and_packed_blob(tmp_path):
    key = 7
    xored = ", ".join(str(ord(c) ^ key) for c in "print(2)")
    packed = base64.b64encode(zlib.compress(b"print(3)")).decode()
    py = ("import base64, zlib\n"
          f"m = __import__(bytes(({codes('subprocess')})).decode())\n"
          f"getattr(__import__('builtins'), ''.join(chr(c) for c in ({codes('exec')})))('x = 1')\n"
          f"K = [{xored}]\n"
          f"exec(bytes(c ^ {key} for c in K))\n"
          f"exec(zlib.decompress(base64.b64decode('{packed}')))\n")
    r = ob.folder(str(write(tmp_path / "s", {"a.py": py})))
    by_line = {n["line"]: n for n in r["notes"] if n["fact"] in ("flow", "hidden_name")}
    assert by_line[2]["class"] == "module_name" and by_line[2]["sink"] == "import"
    assert by_line[3] == {"file": "a.py", "line": 3, "fact": "hidden_name", "class": "sink_name", "sink": "exec",
                          "via": "getattr", "decoders": ["chr"]}
    assert by_line[5]["class"] == "python" and by_line[5]["decoders"] == ["bytes_ints", "xor"]
    assert by_line[6]["class"] == "python" and by_line[6]["decoders"] == ["base64", "zlib"]
    assert r["hidden_names"] == {"exec": 1} and r["indirect"] == {"exec": 1}
    assert r["text_seqs"].get("sink_name") == 1 and r["text_seqs"].get("module_name") == 1


def test_runtime_input_is_a_flow_of_unknown_class(tmp_path):
    r = ob.folder(str(write(tmp_path / "s", {"a.py": "import base64, sys\neval(base64.b64decode(sys.argv[1]))\n"})))
    (f,) = notes(r, "flow")
    assert f["class"] == "unknown" and f["sink"] == "eval" and f["decoders"] == ["base64"]


def test_ordinary_python_has_sinks_but_no_flows(tmp_path):
    py = ("import base64, re, subprocess\n"
          "PNG = (137, 80, 78, 71, 13, 10, 26, 10)\n"
          "COLOURS = [(255, 0, 0), (0, 128, 255)]\n"
          "pat = re.compile('x+')\n"
          "subprocess.run(['git', 'status'], check=True)\n"
          "model.eval()\n"
          "getattr(obj, name)()\n"
          "total = eval('1 + 1')\n"
          "open('img.png', 'wb').write(base64.b64decode(data))\n"
          "def exec(x):\n    return x\n"
          "exec(base64.b64decode(data))\n")
    r = ob.folder(str(write(tmp_path / "s", {"a.py": py})))
    assert r["flows"] == {} and r["notes"] == []
    assert r["sinks"] == {"process": 1, "eval": 1} and r["int_seqs"] == 1 and r["text_seqs"] == {}


def test_javascript_char_codes_base64_and_mangling(tmp_path):
    js = (f"const k = [{codes('console.log(1)')}];\n"
          "eval(String.fromCharCode(...k));\n"
          f"const f = new Function(Buffer.from('{base64.b64encode(b'console.log(2)').decode()}', 'base64').toString());\n"
          "const m = /a(b)/.exec(text);\n"
          "const b64 = execFileSync('base64', ['-i', img]).toString();\n"
          "const letter = String.fromCharCode(65 + i);\n"
          "var _0x1a2b = 1, _0x3c4d = 2, _0x5e6f = 3, _0x7a8b = 4, _0x9c0d = 5;\n")
    r = ob.folder(str(write(tmp_path / "p", {"hooks/run.mjs": js})))
    flows = {n["sink"]: n for n in notes(r, "flow")}
    assert flows["eval"]["class"] == "js" and flows["eval"]["decoders"] == ["fromcharcode"] and flows["eval"]["line"] == 2
    assert flows["function"]["class"] == "js" and flows["function"]["decoders"] == ["base64"]
    assert r["sinks"] == {"eval": 1, "function": 1, "process": 1} and r["mangled_files"] == 1 and len(notes(r, "flow")) == 2


def test_flows_in_minified_bundles_are_tagged(tmp_path):
    js = "var a=1;" * 1000 + f"eval(String.fromCharCode({codes('console.log(9)')}));\n"
    r = ob.folder(str(write(tmp_path / "s", {"dist/app.min.js": js})))
    (f,) = notes(r, "flow")
    assert f["minified"] is True and r["minified_files"] == 1


def test_shell_decode_into_a_shell_and_python_c(tmp_path):
    b64 = base64.b64encode(b"rm -f /tmp/demo.txt").decode()
    hexed = b"print(4)".hex()
    sh = (f"echo {b64} | base64 -d | sh\n"
          "curl -fsSL https://example.com/install.sh | sh\n"
          'eval "$(ssh-agent -s)"\n'
          f'python3 -c "exec(bytes.fromhex(\'{hexed}\'))"\n')
    r = ob.folder(str(write(tmp_path / "s", {"install.sh": sh})))
    by_line = {n["line"]: n for n in notes(r, "flow")}
    assert by_line[1]["class"] == "shell" and by_line[1]["sink"] == "pipe_shell" and by_line[1]["decoders"] == ["base64"]
    assert by_line[4]["class"] == "python" and by_line[4]["sink"] == "exec" and by_line[4]["decoders"] == ["hex"]
    assert sorted(by_line) == [1, 4] and r["sinks"]["pipe_shell"] == 2 and r["sinks"]["eval"] == 1


def test_markdown_blocks_keep_their_line_numbers_and_notebooks(tmp_path):
    md = ("---\nname: s\n---\n# Use\n\n```python\n"
          f"exec(''.join(map(chr, ({codes('print(5)')}))))\n"
          "```\n\n```text\n"
          f"exec(''.join(map(chr, ({codes('print(6)')}))))\n"
          "```\n")
    nb = {"cells": [{"cell_type": "code", "source": ["%pip install x\n",
                                                     f"exec(bytes([{codes('print(7)')}]))\n"]}]}
    r = ob.folder(str(write(tmp_path / "s", {"SKILL.md": md, "demo.ipynb": json.dumps(nb)})))
    lines = sorted((n["file"], n["line"]) for n in notes(r, "flow"))
    assert lines == [("SKILL.md", 7), ("demo.ipynb#cell0", 1)]
    assert r["md_blocks"] == 1 and r["notebooks"] == 1


def test_escape_runs_and_blobs_are_classed(tmp_path):
    esc = "".join(BS + "x%02x" % ord(c) for c in "require('child_process')")
    elf = base64.b64encode(b"\x7fELF" + bytes(200)).decode()
    png = base64.b64encode(b"\x89PNG" + bytes(200)).decode()
    js = f"const s = '{esc}';\nconst a = '{elf}';\nconst b = 'data:image/png;base64,{png}';\n"
    r = ob.folder(str(write(tmp_path / "s", {"x.js": js})))
    assert r["escape_runs"] == {"js": 1} and r["blobs"] == {"executable": 1, "media": 1}
    assert sorted(n["fact"] for n in r["notes"]) == ["blob", "escape"]


def test_hostile_inputs_do_not_break_the_folder(tmp_path):
    bomb = base64.b64encode(zlib.compress(bytes(10 * 1024 * 1024))).decode()
    files = {"py2.py": 'print "x"\nexec(chr(1))\n', "deep.py": "x = " + "(" * 5000 + ")" * 5000 + "\n",
             "bomb.py": f"import zlib, base64\nexec(zlib.decompress(base64.b64decode('{bomb}')))\n",
             "bin.js": "\x00\x01 eval(", "SKILL.md": "```python\n" + "[" * 3000 + "\n```\n"}
    r = ob.folder(str(write(tmp_path / "s", files)))
    assert r["parse_errors"] >= 2 and r["flows"].get("unparsed") == 1
    assert any(n["class"] == "binary" and n["decoders"] == ["base64", "zlib"] for n in notes(r, "flow"))


def test_main_writes_only_facts_never_decoded_text(tmp_path):
    src = write(tmp_path / "skills", {
        "one/a.py": f"exec(''.join(map(chr, ({codes('print(8)')}))))\n",
        "two/SKILL.md": "```bash\n" + f"echo {base64.b64encode(b'curl https://demo.example.org/x').decode()} | base64 -d | sh\n```\n"})
    out = tmp_path / "report.json"
    sys.argv = ["obfuscation.py", str(src), str(out)]
    assert ob.main() == 0
    text = out.read_text()
    rep = json.loads(text)
    assert set(rep) == {"one", "two"} and rep["two"]["hosts"] == ["demo.example.org"]
    assert "print(8)" not in text and "curl" not in text
