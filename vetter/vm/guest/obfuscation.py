#!/usr/bin/env python3
"""Obfuscation facts of staged skills and plugin roots: what code decodes out of constants, and where it goes. No verdicts.

Runs INSIDE a scanner container (no network, the chunk mounted read-only), never on a host:
    python obfuscation.py /skills /out/report.json
For every folder under /skills, in code files, notebooks and the fenced code blocks of its markdown, it records:
- literal integer sequences and whether they read as text when taken as character codes (numbers in a tuple
  that turn into code or into a name like "subprocess");
- calls that run or load code: exec, eval, compile, __import__, importlib, marshal/pickle loads, os.system,
  subprocess, new Function, vm, eval and pipes into a shell; and those reached through getattr(module, ...),
  globals()[...] or __import__(...).attr instead of by name ("indirect");
- flows: such a call whose argument, or whose own name, comes out of a decoder: chr or fromCharCode over numbers,
  bytes from integers, hex, base64/32/85, rot13, xor, reversal, unicode escapes, zlib/gzip/bz2/lzma. Constant
  inputs are undone here by a small evaluator of pure operations from a fixed table (it never calls exec, eval,
  compile or anything the code names), capped in steps and output size;
- long escape runs (backslash-x, backslash-u, octal) and base64/hex blobs in code, decoded and classed;
- files that look machine-obfuscated (_0x identifiers) or minified.
Decoded content is classed, never exported (CLASSES below). Only counts, classes, file names (truncated), line
numbers and the hosts named inside decoded content leave the container; no file text and no decoded text.
"""
from __future__ import annotations

import ast
import base64
import bisect
import binascii
import codecs
import json
import os
import re
import sys
import zlib
from collections import Counter

try:
    import bz2
except ImportError:                     # slim images normally have both
    bz2 = None
try:
    import lzma
except ImportError:
    lzma = None

MAX_READ = 2 * 1024 * 1024
MAX_OUT = 256 * 1024                    # largest value the evaluator may build
BUDGET = 20_000                         # evaluator steps per expression
FILE_BUDGET = 400_000                   # and per file
MIN_SEQ = 8                             # integers in a sequence before it is counted
MAX_NOTES = 30
MAX_MATCHES = 2000                      # regex matches looked at per file and pattern
CLASSES = ("python", "shell", "js", "url", "sink_name", "module_name", "identifier", "text", "executable", "bytecode",
           "archive", "media", "binary", "data", "empty", "unknown")
NOTABLE = {"python", "shell", "js", "url", "sink_name", "module_name", "executable", "bytecode"}
DECODE_OPS = {"chr", "fromcharcode", "bytes_ints", "hex", "base64", "base32", "base85", "rot13", "xor", "reverse",
              "unicode_escape", "escape", "zlib", "gzip", "bz2", "lzma", "codecs", "uri"}
PY_EXT = {"py", "pyw", "pyi", "pth"}
JS_EXT = {"js", "mjs", "cjs", "ts", "mts", "cts", "jsx", "tsx"}
SH_EXT = {"sh", "bash", "zsh", "ksh"}
MD_EXT = {"md", "mdx", "markdown"}
LANG = {"python": "py", "py": "py", "python3": "py", "ipython": "py", "pycon": "py",
        "js": "js", "javascript": "js", "node": "js", "nodejs": "js", "ts": "js", "typescript": "js", "jsx": "js",
        "tsx": "js", "mjs": "js", "bash": "sh", "sh": "sh", "shell": "sh", "zsh": "sh", "console": "sh",
        "shell-session": "sh", "shellscript": "sh", "": "sh"}

# --- Python sinks -------------------------------------------------------------------------------------------
SINKS = {"exec": "exec", "eval": "eval", "compile": "compile", "execfile": "exec", "__import__": "import",
         "builtins.exec": "exec", "builtins.eval": "eval", "builtins.compile": "compile",
         "builtins.__import__": "import", "importlib.import_module": "import", "importlib.__import__": "import",
         "marshal.loads": "deserialise", "pickle.loads": "deserialise", "_pickle.loads": "deserialise",
         "dill.loads": "deserialise", "cloudpickle.loads": "deserialise",
         "types.FunctionType": "code_object", "types.CodeType": "code_object",
         "os.system": "shell", "os.popen": "shell", "commands.getoutput": "shell",
         "asyncio.create_subprocess_shell": "shell", "asyncio.create_subprocess_exec": "process",
         "pty.spawn": "process", "runpy.run_path": "runpy", "runpy.run_module": "runpy"}
for _f in ("run", "call", "Popen", "check_output", "check_call", "getoutput", "getstatusoutput"):
    SINKS["subprocess." + _f] = "process"
SINK_PREFIX = (("os.exec", "process"), ("os.spawn", "process"), ("os.posix_spawn", "process"))
# Attribute names that are a sink when fetched from a module by getattr, globals()[...] or __import__(m).attr.
LEAF = {"exec": "exec", "eval": "eval", "compile": "compile", "__import__": "import", "import_module": "import",
        "system": "shell", "popen": "shell", "getoutput": "shell", "loads": "deserialise", "Popen": "process",
        "run": "process", "call": "process", "check_output": "process", "check_call": "process", "spawn": "process",
        "execv": "process", "execve": "process", "execl": "process", "execvp": "process", "execlp": "process",
        "FunctionType": "code_object", "CodeType": "code_object"}
MODULES = {"builtins", "__builtins__", "os", "posix", "nt", "subprocess", "importlib", "marshal", "pickle", "sys",
           "pty", "types", "runpy", "socket", "ctypes", "shutil", "urllib", "urllib.request", "requests", "http.client",
           "base64", "codecs", "zlib", "commands", "asyncio"}
# Decoded text that is exactly one of these is classed sink_name ("run", "call", "spawn" are too common as words).
SINK_WORDS = (set(LEAF) - {"run", "call", "spawn"}) | {"getattr", "globals", "setattr"}


def _inflate(data: bytes, wbits: int) -> bytes:
    return zlib.decompressobj(wbits).decompress(data, MAX_OUT)


def _bz2(data: bytes) -> bytes:
    if bz2 is None:
        raise ValueError
    return bz2.BZ2Decompressor().decompress(data, MAX_OUT)


def _lzma(data: bytes) -> bytes:
    if lzma is None:
        raise ValueError
    return lzma.LZMADecompressor().decompress(data, MAX_OUT)


def _ascii(v) -> bytes:
    return v.encode("ascii") if isinstance(v, str) else bytes(v)


DECODE_FUNCS = {
    "base64.b64decode": ("base64", lambda v: base64.b64decode(_ascii(v))),
    "base64.standard_b64decode": ("base64", lambda v: base64.standard_b64decode(_ascii(v))),
    "base64.urlsafe_b64decode": ("base64", lambda v: base64.urlsafe_b64decode(_ascii(v))),
    "base64.decodebytes": ("base64", lambda v: base64.decodebytes(_ascii(v))),
    "binascii.a2b_base64": ("base64", lambda v: binascii.a2b_base64(_ascii(v))),
    "base64.b32decode": ("base32", lambda v: base64.b32decode(_ascii(v))),
    "base64.b16decode": ("hex", lambda v: base64.b16decode(_ascii(v), casefold=True)),
    "base64.b85decode": ("base85", lambda v: base64.b85decode(_ascii(v))),
    "base64.a85decode": ("base85", lambda v: base64.a85decode(_ascii(v))),
    "binascii.unhexlify": ("hex", lambda v: binascii.unhexlify(_ascii(v))),
    "binascii.a2b_hex": ("hex", lambda v: binascii.a2b_hex(_ascii(v))),
    "bytes.fromhex": ("hex", lambda v: bytes.fromhex(v)),
    "bytearray.fromhex": ("hex", lambda v: bytes.fromhex(v)),
    "zlib.decompress": ("zlib", lambda v: _inflate(bytes(v), 47)),       # 47: zlib or gzip header, detected
    "gzip.decompress": ("gzip", lambda v: _inflate(bytes(v), 31)),
    "bz2.decompress": ("bz2", lambda v: _bz2(bytes(v))),
    "lzma.decompress": ("lzma", lambda v: _lzma(bytes(v))),
}
CODECS = {"rot13": "rot13", "rot_13": "rot13", "hex": "hex", "hex_codec": "hex", "base64": "base64",
          "base64_codec": "base64", "zlib": "zlib", "zlib_codec": "zlib", "bz2": "bz2", "bz2_codec": "bz2",
          "unicode_escape": "unicode_escape", "unicode-escape": "unicode_escape"}
TEXT_ENCODINGS = {"utf-8", "utf8", "ascii", "latin-1", "latin1", "iso-8859-1", "cp1252", "utf-16", "utf-16-le",
                  "utf-16-be", "unicode_escape", "unicode-escape", "raw_unicode_escape"}


class Unfoldable(Exception):
    pass


def dotted(node, aliases: dict) -> str | None:
    """`a.b.c` as written, with the head resolved through the file's imports (import x as y, from x import y)."""
    parts = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if not isinstance(node, ast.Name):
        return None
    parts.append(aliases.get(node.id, node.id))
    return ".".join(reversed(parts))


class Folder:
    """A tiny evaluator of pure expressions over constants: enough to undo chr/bytes/base64/xor tricks, no more.
    Every operation comes from a fixed table; names resolve only to constants assigned once in the same file."""

    def __init__(self, env: dict, aliases: dict):
        self.env, self.aliases = env, aliases
        self.busy: set = set()
        self.ops: set = set()
        self.steps = 0
        self.total = 0

    def fold(self, node) -> tuple:
        """(value or None, operations used). Never raises."""
        self.ops, self.steps = set(), 0
        try:
            v = self.ev(node, {})
        except Exception:                       # Unfoldable, a decoder's own error, recursion, memory
            return None, frozenset(self.ops)
        return v, frozenset(self.ops)

    def tick(self, v=None):
        self.steps += 1
        self.total += 1
        if self.steps > BUDGET or self.total > FILE_BUDGET:
            raise Unfoldable
        if isinstance(v, (str, bytes, list)) and len(v) > MAX_OUT:
            raise Unfoldable
        if isinstance(v, int) and not -(1 << 64) < v < (1 << 64):
            raise Unfoldable
        return v

    def ev(self, n, local: dict):
        self.tick()
        if isinstance(n, ast.Constant):
            v = n.value
            if isinstance(v, bool) or not isinstance(v, (str, bytes, int)):
                raise Unfoldable
            return v
        if isinstance(n, (ast.List, ast.Tuple)):
            return self.tick([self.ev(e, local) for e in n.elts])
        if isinstance(n, ast.Name):
            if n.id in local:
                return local[n.id]
            if n.id in self.env and n.id not in self.busy:
                self.busy.add(n.id)
                try:
                    return self.ev(self.env[n.id], {})
                finally:
                    self.busy.discard(n.id)
            raise Unfoldable
        if isinstance(n, ast.BinOp):
            return self.tick(self.binop(n.op, self.ev(n.left, local), self.ev(n.right, local)))
        if isinstance(n, ast.Subscript):
            return self.tick(self.subscript(n, local))
        if isinstance(n, ast.JoinedStr):
            parts = []
            for p in n.values:
                if isinstance(p, ast.Constant) and isinstance(p.value, str):
                    parts.append(p.value)
                elif isinstance(p, ast.FormattedValue) and p.conversion == -1 and p.format_spec is None:
                    x = self.ev(p.value, local)
                    if not isinstance(x, (str, int)):
                        raise Unfoldable
                    parts.append(str(x))
                else:
                    raise Unfoldable
            if len(parts) > 1:
                self.ops.add("concat")
            return self.tick("".join(parts))
        if isinstance(n, (ast.ListComp, ast.GeneratorExp)):
            return self.tick(self.comp(n, local))
        if isinstance(n, ast.Call):
            return self.tick(self.call(n, local))
        raise Unfoldable

    def binop(self, op, a, b):
        ints = isinstance(a, int) and isinstance(b, int)
        if isinstance(op, ast.Add):
            if ints:
                return a + b
            if type(a) is type(b) and isinstance(a, (str, bytes, list)):
                self.ops.add("concat")
                return a + b
        elif isinstance(op, ast.Sub) and ints:
            return a - b
        elif isinstance(op, ast.BitXor) and ints:
            self.ops.add("xor")
            return a ^ b
        elif isinstance(op, ast.Mod) and ints and b:
            return a % b
        elif isinstance(op, (ast.BitAnd, ast.BitOr)) and ints:
            return a & b if isinstance(op, ast.BitAnd) else a | b
        elif isinstance(op, (ast.LShift, ast.RShift)) and ints and 0 <= b < 64:
            return a << b if isinstance(op, ast.LShift) else a >> b
        elif isinstance(op, ast.Mult):
            if ints:
                return a * b
            if isinstance(a, int):
                a, b = b, a
            if isinstance(a, (str, bytes, list)) and isinstance(b, int) and 0 <= b and len(a) * b <= MAX_OUT:
                return a * b
        raise Unfoldable

    def subscript(self, n, local):
        v = self.ev(n.value, local)
        if not isinstance(v, (str, bytes, list)):
            raise Unfoldable
        s = n.slice
        if isinstance(s, ast.Slice):
            lo, hi, st = (None if x is None else self.ev(x, local) for x in (s.lower, s.upper, s.step))
            if not all(x is None or isinstance(x, int) for x in (lo, hi, st)) or st == 0:
                raise Unfoldable
            if st is not None and st < 0:
                self.ops.add("reverse")
            return v[lo:hi:st]
        i = self.ev(s, local)
        if not isinstance(i, int):
            raise Unfoldable
        return v[i]

    def seq(self, v) -> list:
        if isinstance(v, (str, bytes)):
            return list(v)
        if isinstance(v, list):
            return v
        raise Unfoldable

    def comp(self, n, local):
        if len(n.generators) != 1 or n.generators[0].ifs or n.generators[0].is_async:
            raise Unfoldable
        g = n.generators[0]
        out = []
        for x in self.seq(self.ev(g.iter, local)):
            inner = dict(local)
            self.bind(g.target, x, inner)
            out.append(self.ev(n.elt, inner))
            self.tick()
        return out

    def bind(self, target, x, scope: dict):
        if isinstance(target, ast.Name):
            scope[target.id] = x
        elif isinstance(target, (ast.Tuple, ast.List)) and isinstance(x, list) and len(x) == len(target.elts):
            for t, y in zip(target.elts, x):
                self.bind(t, y, scope)
        else:
            raise Unfoldable

    def apply(self, fn, x, local):
        """map(fn, ...): fn is chr/ord/str/int or a one-argument lambda."""
        if isinstance(fn, ast.Lambda) and len(fn.args.args) == 1 and not fn.args.vararg:
            return self.ev(fn.body, {**local, fn.args.args[0].arg: x})
        name = dotted(fn, self.aliases)
        if name is None:
            raise Unfoldable
        return self.builtin(name, [x], {})

    def call(self, n, local):
        f = n.func
        name = dotted(f, self.aliases)
        if name == "map" and len(n.args) == 2 and not n.keywords:
            return [self.apply(n.args[0], x, local) for x in self.seq(self.ev(n.args[1], local))]
        if any(isinstance(a, ast.Starred) for a in n.args) or any(k.arg is None for k in n.keywords):
            raise Unfoldable
        if isinstance(f, ast.Attribute) and (name is None or not (name in DECODE_FUNCS or name == "codecs.decode")):
            obj = self.ev(f.value, local)
            return self.method(obj, f.attr, [self.ev(a, local) for a in n.args],
                               {k.arg: self.ev(k.value, local) for k in n.keywords})
        if name is None:
            raise Unfoldable
        return self.builtin(name, [self.ev(a, local) for a in n.args], {k.arg: self.ev(k.value, local) for k in n.keywords})

    def builtin(self, name, args, kw):
        a0 = args[0] if args else None
        if name == "chr" and isinstance(a0, int):
            self.ops.add("chr")
            return chr(a0)
        if name == "ord" and isinstance(a0, str) and len(a0) == 1:
            return ord(a0)
        if name in ("bytes", "bytearray"):
            if isinstance(a0, list) and all(isinstance(x, int) for x in a0):
                self.ops.add("bytes_ints")
                return bytes(a0)
            if isinstance(a0, str):
                return a0.encode(self.encoding(args[1] if len(args) > 1 else kw.get("encoding", "utf-8")))
            if isinstance(a0, bytes):
                return a0
        if name == "str" and len(args) == 1 and isinstance(a0, (str, int)):
            return str(a0)
        if name == "str" and isinstance(a0, bytes) and (len(args) > 1 or "encoding" in kw):
            return self.decode(a0, args[1] if len(args) > 1 else kw.get("encoding"))
        if name in ("list", "tuple") and len(args) == 1:
            return self.seq(a0)
        if name == "reversed" and len(args) == 1:
            self.ops.add("reverse")
            return list(reversed(self.seq(a0)))
        if name == "len" and isinstance(a0, (str, bytes, list)):
            return len(a0)
        if name == "range" and all(isinstance(x, int) for x in args) and 1 <= len(args) <= 3:
            r = range(*args)
            if len(r) > MAX_OUT:
                raise Unfoldable
            return list(r)
        if name == "enumerate" and len(args) == 1:
            return [[i, x] for i, x in enumerate(self.seq(a0))]
        if name == "zip" and args:
            return [list(t) for t in zip(*(self.seq(x) for x in args))]
        if name == "int" and isinstance(a0, str) and len(args) <= 2:
            return int(a0, args[1] if len(args) > 1 else 10)
        if name in DECODE_FUNCS and isinstance(a0, (str, bytes)):
            tag, fn = DECODE_FUNCS[name]
            self.ops.add(tag)
            return fn(a0)
        if name == "codecs.decode" and isinstance(a0, (str, bytes)):
            enc = str(args[1] if len(args) > 1 else kw.get("encoding", "utf-8")).lower()
            tag = CODECS.get(enc)
            if tag is None:
                return self.decode(a0, enc) if isinstance(a0, bytes) else a0
            self.ops.add(tag)
            if tag == "rot13":
                return codecs.decode(a0 if isinstance(a0, str) else a0.decode("ascii"), "rot13")
            if tag == "unicode_escape":
                return (a0 if isinstance(a0, bytes) else a0.encode("latin-1")).decode("unicode_escape")
            fn = {"hex": lambda v: binascii.unhexlify(_ascii(v)), "base64": lambda v: base64.decodebytes(_ascii(v)),
                  "zlib": lambda v: _inflate(bytes(v), 47), "bz2": lambda v: _bz2(bytes(v))}[tag]
            return fn(a0)
        raise Unfoldable

    def encoding(self, enc) -> str:
        enc = str(enc).lower()
        if enc not in TEXT_ENCODINGS:
            raise Unfoldable
        if "unicode" in enc:
            self.ops.add("unicode_escape")
        return enc

    def decode(self, b: bytes, enc) -> str:
        return b.decode(self.encoding(enc or "utf-8"))

    def method(self, obj, attr, args, kw):
        if attr == "join" and isinstance(obj, (str, bytes)) and len(args) == 1:
            items = list(args[0]) if isinstance(args[0], str) and isinstance(obj, str) else args[0]
            if isinstance(items, list) and all(isinstance(x, type(obj)) for x in items):
                return obj.join(items)
        if attr == "decode" and isinstance(obj, bytes):
            return self.decode(obj, args[0] if args else kw.get("encoding"))
        if attr == "encode" and isinstance(obj, str):
            return obj.encode(self.encoding(args[0] if args else kw.get("encoding", "utf-8")))
        if attr == "replace" and isinstance(obj, (str, bytes)) and len(args) == 2 \
                and all(isinstance(x, type(obj)) for x in args):
            if len(args[0]) == 0:
                raise Unfoldable
            return obj.replace(args[0], args[1])
        if attr in ("lower", "upper", "strip", "lstrip", "rstrip", "swapcase") and not args \
                and isinstance(obj, (str, bytes)):
            return getattr(obj, attr)()
        if attr == "split" and isinstance(obj, (str, bytes)) and len(args) <= 1:
            return obj.split(*args)
        if attr == "hex" and isinstance(obj, bytes) and not args:
            return obj.hex()
        raise Unfoldable


# --- classing decoded content ---------------------------------------------------------------------------------
MAGIC = ((b"\x7fELF", "executable"), (b"\xcf\xfa\xed\xfe", "executable"), (b"\xce\xfa\xed\xfe", "executable"),
         (b"\xfe\xed\xfa\xcf", "executable"), (b"\xca\xfe\xba\xbe", "executable"), (b"\x00asm", "executable"),
         (b"PK\x03\x04", "archive"), (b"\x1f\x8b", "archive"), (b"BZh", "archive"), (b"\xfd7zXZ\x00", "archive"),
         (b"7z\xbc\xaf\x27\x1c", "archive"), (b"Rar!", "archive"), (b"\x89PNG", "media"), (b"\xff\xd8\xff", "media"),
         (b"GIF8", "media"), (b"RIFF", "media"), (b"%PDF", "media"), (b"wOFF", "media"), (b"wOF2", "media"),
         (b"OggS", "media"), (b"ID3", "media"), (b"\x00\x00\x01\x00", "media"))
SH_WORDS = re.compile(r"(?:^|[\s;|&(`$])(?:curl|wget|bash|sh|zsh|nc|ncat|socat|chmod|chown|rm|mkfifo|python[0-9.]*|perl|"
                      r"ruby|php|powershell|pwsh|iex|osascript|crontab|base64|eval|sudo|scp|ssh|nohup|/bin/[a-z]+|"
                      r"/dev/tcp/\S*)(?=$|[\s;|&)])")
# Checked before Python: "console.log(1)" also parses as Python. Only markers Python code does not carry.
JS_WORDS = re.compile(r"\brequire\s*\(|\bfunction\s*\(|=>|\bnew\s+Function\b|\bdocument\.|\bwindow\.|\bchild_process\b|"
                      r"\bmodule\.exports\b|\bconsole\.log\s*\(|\bprocess\.env\b")
URL = re.compile(r"\b(?:https?|ftp|wss?)://([A-Za-z0-9.-]{1,253})")
HOST_OK = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+")
IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,63}")
PY_NODES = (ast.Call, ast.Import, ast.ImportFrom, ast.Assign, ast.FunctionDef, ast.Lambda, ast.ClassDef)


def looks_python(s: str) -> bool:
    if len(s) > 65536:
        return False
    try:
        tree = ast.parse(s)
    except Exception:                           # SyntaxError, ValueError, RecursionError, MemoryError
        return False
    return any(isinstance(x, PY_NODES) for x in ast.walk(tree))


def classify(v) -> str:
    if v is None:
        return "unknown"
    if isinstance(v, list):
        if v and all(isinstance(x, str) for x in v):
            v = "".join(v) if all(len(x) <= 1 for x in v) else " ".join(v)
        elif v and all(isinstance(x, int) and 0 <= x < 256 for x in v):
            v = bytes(v)
        else:
            return "data"
    if isinstance(v, int):
        return "data"
    if isinstance(v, (bytes, bytearray)):
        v = bytes(v)
        for magic, cls in MAGIC:
            if v.startswith(magic):
                return cls
        if v.startswith(b"MZ") and (b"PE\x00\x00" in v[:1024] or b"This program" in v[:256]):
            return "executable"
        if len(v) >= 16 and v[2:4] == b"\r\n" and 2900 <= int.from_bytes(v[:2], "little") < 4000:
            return "bytecode"
        try:
            v = v.decode("utf-8")
        except UnicodeDecodeError:
            return "binary"
    s = v.strip()
    if not s:
        return "empty"
    if sum(c.isprintable() or c in "\t\n\r" for c in s) < 0.9 * len(s):
        return "binary"
    if s in SINK_WORDS or s in SINKS:
        return "sink_name"
    if s in MODULES or (IDENT.fullmatch(s) and s.split(".")[0] in MODULES):
        return "module_name"
    if URL.match(s) and not any(c.isspace() for c in s):
        return "url"
    if IDENT.fullmatch(s):
        return "identifier"
    if JS_WORDS.search(s):
        return "js"
    if looks_python(s):
        return "python"
    if SH_WORDS.search(s):
        return "shell"
    return "text"


def as_text(v) -> str:
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        return "".join(v)
    if isinstance(v, list) and all(isinstance(x, int) and 0 <= x < 256 for x in v):
        v = bytes(v)
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("utf-8", "replace")
    return v if isinstance(v, str) else ""


def new_report() -> dict:
    return {"code_files": 0, "md_blocks": 0, "notebooks": 0, "parse_errors": 0, "int_seqs": 0, "text_seqs": Counter(),
            "escape_runs": Counter(), "blobs": Counter(), "sinks": Counter(), "indirect": Counter(),
            "flows": Counter(), "hidden_names": Counter(), "mangled_files": 0, "minified_files": 0,
            "file_errors": Counter(), "hosts": set(), "notes": []}


def note(r: dict, rel: str, line: int, fact: str, cls: str, **kw) -> None:
    if len(r["notes"]) < MAX_NOTES:
        r["notes"].append({"file": rel[:120], "line": int(line), "fact": fact, "class": cls, **kw})


def hosts_of(v, r: dict) -> None:
    if v is None:
        return
    for h in URL.findall(as_text(v))[:5]:
        h = h.lower().strip(".")
        if HOST_OK.fullmatch(h) and len(h) <= 80 and len(r["hosts"]) < 10:
            r["hosts"].add(h)


_NL: dict = {"obj": None, "idx": []}


def line_of(b: bytes, pos: int) -> int:
    """1-based line of a byte offset; the newline index of the last text asked about is kept."""
    if _NL["obj"] is not b:
        _NL["obj"], _NL["idx"] = b, [m.start() for m in re.finditer(b"\n", b)]
    return bisect.bisect_left(_NL["idx"], pos) + 1


TEXT_CODES = set(range(32, 127)) | {9, 10, 13}


def seq_fact(vals: list, rel: str, line: int, r: dict) -> None:
    """An integer sequence: counted at MIN_SEQ items; classed when every item is a printable ASCII code. Shorter runs
    (4 to 7) are classed only when they spell a sink or module name exactly ("exec", "socket")."""
    if len(vals) < 4 or not all(isinstance(v, int) and not isinstance(v, bool) for v in vals):
        return
    text = all(v in TEXT_CODES for v in vals)
    if len(vals) < MIN_SEQ:
        if text:
            s = "".join(map(chr, vals))
            cls = classify(s)
            if cls in ("sink_name", "module_name"):
                r["text_seqs"][cls] += 1
                note(r, rel, line, "seq", cls)
        return
    r["int_seqs"] += 1
    if text:
        s = "".join(map(chr, vals))
        if sum(c.isalpha() for c in s) >= 3:
            cls = classify(s)
            r["text_seqs"][cls] += 1
            if cls in NOTABLE:
                note(r, rel, line, "seq", cls)
                hosts_of(s, r)


# --- generic facts: escape runs, blobs ------------------------------------------------------------------------
ESC_RUN = re.compile(rb"(?:\\x[0-9a-fA-F]{2}){16,}|(?:\\u[0-9a-fA-F]{4}){16,}|(?:\\[0-7]{3}){16,}")
ESC_TOK = re.compile(rb"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})|\\([0-7]{3})")
BLOB = re.compile(rb"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/]{200,}={0,2}")
HEXONLY = re.compile(rb"(?:[0-9a-fA-F]{2})+")


def unescape(run: bytes):
    vals, wide = [], False
    for m in ESC_TOK.finditer(run):
        x, u, o = m.groups()
        wide |= u is not None
        vals.append(int(x, 16) if x else int(u, 16) if u else int(o, 8))
    if not wide and all(v < 256 for v in vals):
        return bytes(vals)
    return "".join(chr(v) for v in vals if v < 0x110000)


def blob_decode(run: bytes):
    if len(run) % 2 == 0 and HEXONLY.fullmatch(run):
        return "hex", binascii.unhexlify(run[: 2 * MAX_OUT])
    run = run[: 4 * MAX_OUT // 3]
    return "base64", base64.b64decode(run + b"=" * (-len(run) % 4))


def generic_facts(b: bytes, rel: str, r: dict, base: int) -> None:
    for i, m in enumerate(ESC_RUN.finditer(b)):
        if i >= MAX_MATCHES:
            break
        v = unescape(m.group(0))
        cls = classify(v)
        r["escape_runs"][cls] += 1
        if cls in NOTABLE:
            note(r, rel, base + line_of(b, m.start()), "escape", cls, decoders=["escape"])
            hosts_of(v, r)
    for i, m in enumerate(BLOB.finditer(b)):
        if i >= 50:
            break
        try:
            kind, v = blob_decode(m.group(0))
        except (binascii.Error, ValueError):
            continue
        cls = classify(v)
        r["blobs"][cls] += 1
        if cls in NOTABLE:
            note(r, rel, base + line_of(b, m.start()), "blob", cls, decoders=[kind])
            hosts_of(v, r)


# --- Python ---------------------------------------------------------------------------------------------------
PY_SEQ_RX = re.compile(rb"[\[(]\s*(?:0[xX][0-9a-fA-F]{1,6}|\d{1,7})(?:\s*,\s*(?:0[xX][0-9a-fA-F]{1,6}|\d{1,7})){3,}\s*,?\s*[\])]")
PY_SINK_RX = re.compile(rb"(?<![\w.])(?:exec|eval|__import__)\s*\(|\bos\.system\s*\(|\bsubprocess\.\w+\s*\(")
PY_DECODER_RX = re.compile(rb"\bchr\s*\(|\bmap\s*\(\s*chr\b|b64decode|fromhex|unhexlify|decompress\s*\(|codecs\.decode|"
                           rb"\bbytes\s*\(\s*[\[(]|\^")
NUM = re.compile(rb"0[xX][0-9a-fA-F]+|\d+")


def nums(b: bytes) -> list:
    return [int(t, 16) if t[:2] in (b"0x", b"0X") else int(t) for t in NUM.findall(b)]


def is_module(node, aliases) -> bool:
    if isinstance(node, ast.Call) and dotted(node.func, aliases) in ("__import__", "builtins.__import__",
                                                                     "importlib.import_module"):
        return True
    if isinstance(node, ast.Subscript) and dotted(node.value, aliases) == "sys.modules":
        return True
    return dotted(node, aliases) in MODULES


def is_namespace(node, aliases) -> bool:
    """globals(), locals(), vars(x), <module>.__dict__ or __builtins__: places a sink can be looked up by key."""
    if isinstance(node, ast.Call) and dotted(node.func, aliases) in ("globals", "locals", "vars"):
        return True
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return is_module(node.value, aliases)
    return isinstance(node, ast.Name) and node.id in ("__builtins__", "builtins")


def sink_of(call: ast.Call, fo: Folder, aliases: dict, defined: set):
    """(kind, how it is reached, decoder ops behind the sink's name) or None."""
    f = call.func
    if isinstance(f, ast.Name) and f.id in defined:
        return None
    name = dotted(f, aliases)
    if name:
        kind = SINKS.get(name) or next((k for p, k in SINK_PREFIX if name.startswith(p)), None)
        return (kind, "name", frozenset()) if kind else None
    if isinstance(f, ast.Call) and dotted(f.func, aliases) == "getattr" and len(f.args) >= 2 \
            and is_module(f.args[0], aliases):
        attr, ops = fo.fold(f.args[1])
        if isinstance(attr, str):
            return (LEAF[attr], "getattr", ops) if attr in LEAF else None
        return "dynamic", "getattr", ops
    if isinstance(f, ast.Subscript) and is_namespace(f.value, aliases):
        key, ops = fo.fold(f.slice)
        if isinstance(key, str):
            return (LEAF[key], "subscript", ops) if key in LEAF else None
        return "dynamic", "subscript", ops
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Call) and f.value.args \
            and dotted(f.value.func, aliases) in ("__import__", "builtins.__import__", "importlib.import_module"):
        mod, ops = fo.fold(f.value.args[0])
        kind = SINKS.get(f"{mod}.{f.attr}") if isinstance(mod, str) else None
        if kind is None and f.attr in LEAF and (mod is None or mod in MODULES):
            kind = LEAF[f.attr]
        return (kind, "import_attr", ops) if kind else None
    return None


def syntactic_ops(node, aliases: dict, env: dict, depth: int = 0) -> set:
    """Decoders written inside an expression that could not be folded (input read at run time, say)."""
    ops = set()
    for x in ast.walk(node):
        if isinstance(x, ast.Call):
            name = dotted(x.func, aliases)
            if name in DECODE_FUNCS:
                ops.add(DECODE_FUNCS[name][0])
            elif name == "chr" or (name == "map" and x.args and dotted(x.args[0], aliases) == "chr"):
                ops.add("chr")
            elif name == "codecs.decode":
                ops.add("codecs")
            elif name in ("bytes", "bytearray") and x.args \
                    and isinstance(x.args[0], (ast.List, ast.Tuple, ast.ListComp, ast.GeneratorExp)):
                ops.add("bytes_ints")
        elif isinstance(x, ast.BinOp) and isinstance(x.op, ast.BitXor):
            ops.add("xor")
        elif isinstance(x, ast.Name) and depth < 3 and x.id in env and env[x.id] is not node:
            ops |= syntactic_ops(env[x.id], aliases, env, depth + 1)
    return ops


def py_facts(b: bytes, rel: str, r: dict, base: int = 0) -> None:
    try:
        tree = ast.parse(b)
    except Exception:                           # SyntaxError (Python 2, templates), ValueError, RecursionError
        r["parse_errors"] += 1
        py_fallback(b, rel, r, base)
        return
    aliases, assigns, defined = {}, {}, set()
    for x in ast.walk(tree):
        if isinstance(x, ast.Import):
            for a in x.names:
                aliases[a.asname or a.name.split(".")[0]] = a.name if a.asname else a.name.split(".")[0]
        elif isinstance(x, ast.ImportFrom) and x.module and not x.level:
            for a in x.names:
                aliases[a.asname or a.name] = f"{x.module}.{a.name}"
        elif isinstance(x, ast.Assign) and len(x.targets) == 1 and isinstance(x.targets[0], ast.Name):
            assigns.setdefault(x.targets[0].id, []).append(x.value)
        elif isinstance(x, ast.AnnAssign) and isinstance(x.target, ast.Name) and x.value is not None:
            assigns.setdefault(x.target.id, []).append(x.value)
        elif isinstance(x, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(x.name)
    env = {k: v[0] for k, v in assigns.items() if len(v) == 1}
    fo = Folder(env, aliases)
    for x in ast.walk(tree):
        if isinstance(x, (ast.List, ast.Tuple)) and len(x.elts) >= 4 and all(
                isinstance(e, ast.Constant) and isinstance(e.value, int) for e in x.elts):
            seq_fact([e.value for e in x.elts], rel, base + x.lineno, r)
            continue
        if not isinstance(x, ast.Call):
            continue
        s = sink_of(x, fo, aliases, defined)
        if not s:
            continue
        kind, via, name_ops = s
        line = base + x.lineno
        r["sinks"][kind] += 1
        if via != "name":
            r["indirect"][kind] += 1
            hidden = name_ops & (DECODE_OPS | {"concat"})
            if hidden:
                r["hidden_names"][kind] += 1
            note(r, rel, line, "hidden_name" if hidden else "indirect", "sink_name", sink=kind, via=via,
                 decoders=sorted(hidden))
        arg = x.args[0] if x.args else (x.keywords[0].value if x.keywords else None)
        if arg is None:
            continue
        v, ops = fo.fold(arg)
        if v is None:
            ops = ops | syntactic_ops(arg, aliases, env)
        dec = ops & DECODE_OPS
        if dec:
            cls = classify(v)
            r["flows"][kind] += 1
            note(r, rel, line, "flow", cls, sink=kind, via=via, decoders=sorted(dec))
            hosts_of(v, r)


def py_fallback(b: bytes, rel: str, r: dict, base: int) -> None:
    """Unparseable Python: integer sequences, and sink calls with a decoder on the same line."""
    for i, m in enumerate(PY_SEQ_RX.finditer(b)):
        if i >= MAX_MATCHES:
            break
        seq_fact(nums(m.group(0)), rel, base + line_of(b, m.start()), r)
    for i, m in enumerate(PY_SINK_RX.finditer(b)):
        if i >= MAX_MATCHES:
            break
        r["sinks"]["unparsed"] += 1
        lo, hi = b.rfind(b"\n", 0, m.start()) + 1, b.find(b"\n", m.end())
        if PY_DECODER_RX.search(b, lo, hi if hi >= 0 else len(b)):
            r["flows"]["unparsed"] += 1
            note(r, rel, base + line_of(b, m.start()), "flow", "unknown", sink="unparsed", via="line")


# --- JavaScript / TypeScript (regex: no parser in the standard library) -------------------------------------------
JS_ARR = re.compile(rb"\[\s*(?:0[xX][0-9a-fA-F]{1,6}|\d{1,7})(?:\s*,\s*(?:0[xX][0-9a-fA-F]{1,6}|\d{1,7})){3,}\s*,?\s*\]")
JS_NAMED_ARR = re.compile(rb"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(\[[0-9xXa-fA-F,\s]+\])")
JS_TAINT = re.compile(rb"\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,2000}?(?:fromCharCode|\batob\s*\(|"
                      rb"Buffer\s*\.\s*from\s*\(|\bunescape\s*\()[^;\n]{0,2000})")
JS_SINKS = (
    ("eval", re.compile(rb"(?<![\w$.])eval\s*\(")),
    ("function", re.compile(rb"\bnew\s+Function\s*\(|(?<![\w$.])Function\s*\(")),
    ("vm", re.compile(rb"\bvm\s*\.\s*(?:runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|"
                      rb"\bnew\s+vm\s*\.\s*Script\s*\(")),
    ("process", re.compile(rb"(?<![\w$])(?:execSync|spawnSync|spawn|execFileSync|execFile)\s*\(|(?<![\w$.])exec\s*\(|"
                           rb"\b(?:child_process|childProcess|cp)\s*\.\s*exec\s*\(")),
    ("import", re.compile(rb"\brequire\s*\(\s*(?![\s'\"`)])|(?<![\w$.])import\s*\(\s*(?![\s'\"`)])")),
    ("timer_string", re.compile(rb"\bset(?:Timeout|Interval)\s*\(\s*['\"`]")),
)
JS_DECODERS = (
    ("fromcharcode", re.compile(rb"\bfromCharCode\b|\bfromCodePoint\b")),
    # Decoding only: atob, or Buffer.from(x, "base64"|"hex"). A bare "base64" string is often a command or an encoder.
    ("base64", re.compile(rb"\batob\s*\(|Buffer\s*\.\s*from\s*\([^()]{0,400},\s*['\"]base64['\"]\s*\)")),
    ("hex", re.compile(rb"Buffer\s*\.\s*from\s*\([^()]{0,400},\s*['\"]hex['\"]\s*\)")),
    ("bytes_ints", re.compile(rb"Buffer\s*\.\s*from\s*\(\s*\[|new\s+Uint8Array\s*\(\s*\[")),
    ("uri", re.compile(rb"\bunescape\s*\(|decodeURIComponent\s*\(\s*escape\b")),
    ("zlib", re.compile(rb"\b(?:inflate|inflateRaw|gunzip|unzip|brotliDecompress)Sync\s*\(")),
    ("reverse", re.compile(rb"\.split\s*\(\s*['\"]['\"]\s*\)\s*\.\s*reverse\s*\(\s*\)")),
    ("escape", ESC_RUN),
)
JS_FCC_LIT = re.compile(rb"fromCharCode\s*\(\s*((?:0[xX][0-9a-fA-F]+|\d+)(?:\s*,\s*(?:0[xX][0-9a-fA-F]+|\d+))*)\s*\)")
JS_FCC_NAME = re.compile(rb"fromCharCode\s*(?:\(\s*\.\.\.\s*|\.\s*apply\s*\(\s*(?:null|undefined|String|this)\s*,\s*)"
                         rb"([A-Za-z_$][\w$]*)|([A-Za-z_$][\w$]*)\s*\.\s*map\s*\([^)]{0,80}fromCharCode")
JS_ATOB = re.compile(rb"\batob\s*\(\s*['\"]([A-Za-z0-9+/=]{4,})['\"]\s*\)")
JS_BUF = re.compile(rb"Buffer\s*\.\s*from\s*\(\s*['\"]([A-Za-z0-9+/=]{2,})['\"]\s*,\s*['\"](base64|hex)['\"]\s*\)")
JS_BUF_ARR = re.compile(rb"Buffer\s*\.\s*from\s*\(\s*(\[[0-9xXa-fA-F,\s]+\])\s*\)")
MANGLED = re.compile(rb"\b_0x[0-9a-fA-F]{4,6}\b")


def call_args(b: bytes, i: int, cap: int = 4000) -> bytes:
    """Text between the parenthesis at b[i] and its match (quotes not parsed: a window, not a parse)."""
    depth = 0
    for j in range(i, min(len(b), i + cap)):
        c = b[j]
        if c == 0x28:
            depth += 1
        elif c == 0x29:
            depth -= 1
            if depth == 0:
                return b[i + 1:j]
    return b[i + 1:i + cap]


def js_fold(arg: bytes, arrays: dict) -> tuple:
    """Constant inputs to the common JS decoders, undone: (value or None, ops)."""
    try:
        m = JS_FCC_LIT.search(arg)
        if m:
            return "".join(chr(v) for v in nums(m.group(1))), {"fromcharcode"}
        m = JS_FCC_NAME.search(arg)
        if m and (m.group(1) or m.group(2)) in arrays:
            return "".join(chr(v) for v in arrays[m.group(1) or m.group(2)]), {"fromcharcode"}
        m = JS_ATOB.search(arg)
        if m:
            s = m.group(1)
            return base64.b64decode(s + b"=" * (-len(s) % 4)), {"base64"}
        m = JS_BUF.search(arg)
        if m:
            s, kind = m.group(1), m.group(2).decode()
            if kind == "hex":
                return binascii.unhexlify(s), {"hex"}
            return base64.b64decode(s + b"=" * (-len(s) % 4)), {"base64"}
        m = JS_BUF_ARR.search(arg)
        if m:
            return bytes(nums(m.group(1))), {"bytes_ints"}
        m = ESC_RUN.search(arg)
        if m:
            return unescape(m.group(0)), {"escape"}
    except (ValueError, binascii.Error, OverflowError):
        pass
    return None, set()


def js_ops(text: bytes) -> set:
    return {k for k, rx in JS_DECODERS if rx.search(text)}


def js_facts(b: bytes, rel: str, r: dict, base: int = 0) -> None:
    lines = b.split(b"\n")
    mini = max(map(len, lines)) >= 5000 and len(b) / max(1, len(lines)) >= 500
    extra = {"minified": True} if mini else {}       # a flow in a bundle is a window over unrelated code
    arrays = {}
    for m in JS_NAMED_ARR.finditer(b):
        vals = nums(m.group(2))
        if vals and all(v < 0x110000 for v in vals):
            arrays[m.group(1)] = vals
    tainted = {}
    for _, m in zip(range(200), JS_TAINT.finditer(b)):
        tainted[m.group(1)] = (re.compile(rb"(?<![\w$])" + re.escape(m.group(1)) + rb"(?![\w$])"), m.group(2))
    for i, m in enumerate(JS_ARR.finditer(b)):
        if i >= MAX_MATCHES:
            break
        seq_fact(nums(m.group(0)), rel, base + line_of(b, m.start()), r)
    for kind, rx in JS_SINKS:
        for i, m in enumerate(rx.finditer(b)):
            if i >= 500:
                break
            r["sinks"][kind] += 1
            p = b.find(b"(", m.start())
            arg = call_args(b, p) if p >= 0 else b""
            v, ops = js_fold(arg, arrays)
            ops = set(ops) | js_ops(arg)
            for name_rx, expr in tainted.values():
                if name_rx.search(arg):
                    v2, o2 = js_fold(expr, arrays)
                    ops |= set(o2) | js_ops(expr)
                    v = v if v is not None else v2
            dec = ops & DECODE_OPS
            if dec:
                cls = classify(v)
                r["flows"][kind] += 1
                note(r, rel, base + line_of(b, m.start()), "flow", cls, sink=kind, via="name", decoders=sorted(dec), **extra)
                hosts_of(v, r)
    for m in list(JS_FCC_LIT.finditer(b))[:MAX_MATCHES]:       # fromCharCode(<numbers>) with no sink around it
        vals = nums(m.group(1))
        if len(vals) >= 4:
            seq_fact(vals, rel, base + line_of(b, m.start()), r)
    if len(set(MANGLED.findall(b))) >= 5:
        r["mangled_files"] += 1
        note(r, rel, base + 1, "mangled", "js")
    if mini:
        r["minified_files"] += 1


# --- shell -------------------------------------------------------------------------------------------------------
SH_DECODERS = (
    ("base64", re.compile(rb"\bbase64\s+(?:-\w*[dD]\w*|--decode)\b|\bopenssl\s+(?:enc\s+-base64|base64)\b[^\n|]*\s-d\b")),
    ("hex", re.compile(rb"\bxxd\s+(?:-\w+\s+)*-r\b|(?:\\x[0-9a-fA-F]{2}){8,}")),
    ("escape", re.compile(rb"(?:\\[0-7]{3}){8,}")),
    ("rot13", re.compile(rb"\btr\s+['\"]?(?:A-Za-z|a-zA-Z)['\"]?\s+['\"]?(?:N-ZA-Mn-za-m|n-za-mN-ZA-M)")),
    ("reverse", re.compile(rb"\|\s*rev\b")),
    ("gzip", re.compile(rb"\b(?:gunzip|zcat|gzip\s+-\w*d|gzip\s+--decompress)\b")),
)
SH_SINKS = (
    ("pipe_shell", re.compile(rb"\|\s*(?:sudo\s+(?:-\S+\s+)*)?(?:/usr)?(?:/bin/)?(?:ba|z|da|k)?sh\b(?![\w.-])")),
    ("pipe_interp", re.compile(rb"\|\s*(?:sudo\s+)?(?:python[0-9.]*|node|perl|ruby|php)\b(?:\s+-)?\s*(?:$|[|;&)])", re.M)),
    ("eval", re.compile(rb"(?:^|[;&|({`]\s*|\b(?:then|do|else)\s+)eval\s", re.M)),
    ("subshell", re.compile(rb"\b(?:ba|z)?sh\s+-c\s+[\"']?\$\(")),
    ("source", re.compile(rb"(?:\bsource|(?:^|[;&]\s*)\.)\s+<\(", re.M)),
)
SH_B64_LIT = re.compile(rb"(?:echo|printf)\s+(?:-\w+\s+)*['\"]?([A-Za-z0-9+/]{8,}={0,2})['\"]?\s*\|\s*base64\s+(?:-\w*[dD]\w*|--decode)"
                        rb"|base64\s+(?:-\w*[dD]\w*|--decode)\s*<<<\s*['\"]?([A-Za-z0-9+/]{8,}={0,2})")
SH_HEX_LIT = re.compile(rb"(?:echo|printf)\s+(?:-\w+\s+)*['\"]?((?:[0-9a-fA-F]{2}){8,})['\"]?\s*\|\s*xxd\s+(?:-\w+\s+)*-r")
SH_ESC_LIT = re.compile(rb"((?:\\x[0-9a-fA-F]{2}|\\[0-7]{3}){8,})")
SH_PY_C = re.compile(rb"\bpython[0-9.]*\s+(?:-\w+\s+)*-c\s+(?:\"((?:[^\"\\]|\\.){1,20000})\"|'([^']{1,20000})')")
SH_NODE_E = re.compile(rb"\bnode\s+(?:-\w+\s+)*-e\s+(?:\"((?:[^\"\\]|\\.){1,20000})\"|'([^']{1,20000})')")


def sh_fold(line: bytes) -> tuple:
    try:
        m = SH_B64_LIT.search(line)
        if m:
            s = m.group(1) or m.group(2)
            return base64.b64decode(s + b"=" * (-len(s) % 4)), {"base64"}
        m = SH_HEX_LIT.search(line)
        if m:
            return binascii.unhexlify(m.group(1)), {"hex"}
        m = SH_ESC_LIT.search(line)
        if m:
            return unescape(m.group(1)), {"escape"}
    except (ValueError, binascii.Error):
        pass
    return None, set()


def sh_facts(b: bytes, rel: str, r: dict, base: int = 0) -> None:
    logical, buf, start = [], b"", 0
    for i, ln in enumerate(b.split(b"\n")):
        if not buf:
            start = i
        if ln.endswith(b"\\"):
            buf += ln[:-1] + b" "
            continue
        logical.append((start + 1, buf + ln))
        buf = b""
    if buf:
        logical.append((start + 1, buf))
    for lineno, ln in logical[:20000]:
        if len(ln) > 100000:
            continue
        sinks = [k for k, rx in SH_SINKS if rx.search(ln)]
        for k in sinks:
            r["sinks"][k] += 1
        if sinks:
            ops = {k for k, rx in SH_DECODERS if rx.search(ln)}
            if ops:
                v, o2 = sh_fold(ln)
                cls = classify(v)
                for k in sinks:
                    r["flows"][k] += 1
                note(r, rel, base + lineno, "flow", cls, sink=sinks[0], via="line", decoders=sorted(ops | o2))
                hosts_of(v, r)
        for rx, fn in ((SH_PY_C, py_facts), (SH_NODE_E, js_facts)):
            for m in rx.finditer(ln):
                code = m.group(1)
                code = code.replace(b'\\"', b'"').replace(b"\\$", b"$").replace(b"\\\\", b"\\") if code else m.group(2)
                fn(code, rel, r, base + lineno - 1)


# --- markdown, notebooks, folders -------------------------------------------------------------------------------
FENCE = re.compile(rb"^ {0,3}(`{3,}|~{3,})\s*([A-Za-z0-9_+.-]*)")


def md_blocks(b: bytes) -> list:
    """Fenced code blocks: (language, line of the block's first line, text)."""
    out, lines, i = [], b.split(b"\n"), 0
    while i < len(lines):
        m = FENCE.match(lines[i])
        if not m:
            i += 1
            continue
        fence, lang = m.group(1), m.group(2).decode("ascii", "replace").lower()
        close = re.compile(rb"^ {0,3}" + re.escape(fence[:1]) + rb"{%d,}\s*$" % len(fence))
        j = i + 1
        while j < len(lines) and not close.match(lines[j]):
            j += 1
        out.append((lang, i + 1, b"\n".join(lines[i + 1:j])))
        i = j + 1
    return out


def scan_text(lang: str, b: bytes, rel: str, r: dict, base: int = 0) -> None:
    if lang == "py":
        py_facts(b, rel, r, base)
    elif lang == "js":
        js_facts(b, rel, r, base)
    elif lang == "sh":
        sh_facts(b, rel, r, base)
    generic_facts(b, rel, r, base)


def notebook(b: bytes, rel: str, r: dict) -> None:
    try:
        nb = json.loads(b)
        cells = [c for c in nb.get("cells", []) if isinstance(c, dict) and c.get("cell_type") == "code"]
    except (ValueError, AttributeError, RecursionError):
        return
    r["notebooks"] += 1
    for k, c in enumerate(cells[:500]):
        src = c.get("source", "")
        src = "".join(src) if isinstance(src, list) else str(src)
        src = "\n".join(ln for ln in src.split("\n") if not ln.lstrip().startswith(("%", "!")))
        scan_text("py", src.encode("utf-8", "replace"), f"{rel}#cell{k}", r)


def read(path: str) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(MAX_READ)


def folder(root: str) -> dict:
    r = new_report()
    for dp, dns, fns in os.walk(root, followlinks=False):
        dns[:] = [d for d in dns if d not in ("node_modules", ".git") and not os.path.islink(os.path.join(dp, d))]
        for fn in fns:
            p = os.path.join(dp, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            rel = os.path.relpath(p, root)
            low = fn.lower()
            ext = low.rsplit(".", 1)[-1] if "." in low else ""
            if ext not in PY_EXT | JS_EXT | SH_EXT | MD_EXT | {"ipynb"}:
                continue
            try:
                b = read(p)
            except OSError:
                continue
            try:
                if ext in MD_EXT:
                    for lang, line, text in md_blocks(b)[:500]:
                        if lang in LANG:
                            r["md_blocks"] += 1
                            scan_text(LANG[lang], text, rel, r, line)
                elif ext == "ipynb":
                    notebook(b, rel, r)
                else:
                    r["code_files"] += 1
                    scan_text("py" if ext in PY_EXT else "js" if ext in JS_EXT else "sh", b, rel, r)
            except Exception as e:              # one bad file must not lose the folder
                r["file_errors"][type(e).__name__] += 1
    for k in ("text_seqs", "escape_runs", "blobs", "sinks", "indirect", "flows", "hidden_names", "file_errors"):
        r[k] = dict(r[k])
    r["hosts"] = sorted(r["hosts"])
    return r


def main() -> int:
    src, out = sys.argv[1], sys.argv[2]
    report = {}
    for name in sorted(os.listdir(src)):
        p = os.path.join(src, name)
        if os.path.isdir(p) and not os.path.islink(p):
            try:
                report[name] = folder(p)
            except Exception as e:              # one bad folder must not lose the chunk
                report[name] = {"error": type(e).__name__}
    with open(out, "w") as fh:
        json.dump(report, fh)
    return 0


if __name__ == "__main__":
    sys.exit(main())
