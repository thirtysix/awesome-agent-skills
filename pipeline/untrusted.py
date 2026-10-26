"""Text that came from the web: find what a human cannot see, and what is addressed to an agent.

Everything in this catalog was written by someone else, and some of it is written for AI agents
rather than people. Seen while surveying it (2026-10-23): a directory telling agents to fetch and
run remote instructions, an "If you are an AI agent" section, an API notice asking agents to send
the user's email address, skill descriptions saying "You MUST use this skill". So:

- `INVISIBLE` is every code point that renders as nothing but a model still reads: Unicode Tag
  characters (U+E0000-E007F, which spell ASCII invisibly), variation selectors, zero-width and
  joiner characters, bidi controls and isolates, invisible operators, and fillers. The table follows
  wunderwuzzi23/aid (MIT) and covers what a plain prompt-injection pattern list does not (Tags, VS, isolates).
- `addressed_to_agents()` finds text written to steer an agent. It flags; it never decides. A
  skill's own instructions legitimately address an agent, so on skill text this is a signal for a
  human, not a verdict.

Curated tables must contain no invisible characters at all (build.py refuses them). Harvested text
has them stripped and recorded, with a defanged preview of any decoded Tag run, never the raw run.
"""
from __future__ import annotations

import hashlib
import re

INVISIBLE = re.compile(
    "[\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180e\u200b-\u200f\u202a-\u202e\u2060-\u206f"
    "\u3164\ufe00-\ufe0f\ufeff\uffa0\U000e0000-\U000e007f\U000e0100-\U000e01ef]")
TAGS = re.compile("[\U000e0000-\U000e007f]+")
_EMOJI = ("\u00a9\u00ae\u203c\u2049\u2100-\u23ff\u2460-\u27bf\u2900-\u2bff\u3030\u303d\u3297\u3299"
          "\U0001f000-\U0001faff")                                     # symbols that take emoji presentation
EMOJI_BEFORE_VS16 = re.compile(f"[{_EMOJI}]\ufe0f|[0-9#*]\ufe0f(?=\u20e3)")   # an emoji's own selector; keycaps
EMOJI_ZWJ = re.compile(f"(?<=[{_EMOJI}\ufe0f])\u200d(?=[{_EMOJI}])")   # a family emoji is three emoji joined

AGENT_DIRECTED = re.compile("|".join([
    r"\bif you(?:'re| are) an? (?:ai|llm|language model|agent|assistant|bot)\b",
    r"\b(?:ai |llm |coding )?agents? (?:should|must|can|may) (?:fetch|read|run|call|query|start|send|install)\b",
    r"\b(?:ignore|disregard|forget) (?:all |any )?(?:previous|prior|above|earlier) (?:instructions|rules|prompts?)\b",
    r"\byou (?:must|should) always (?:use|invoke|run)\b",
    r"\b(?:always|must) use this (?:skill|tool|plugin)\b",
    r"\byou must use this\b",
    r"\bproactively (?:offer|run|invoke|use)\b",
    r"\bdo not (?:tell|mention|inform|show)(?: this)? (?:to )?the user\b",
    r"\bwithout (?:telling|asking|informing) the user\b",
    r"\b(?:send|include|provide|share) (?:us |me )?(?:the |your )?user'?s? (?:e-?mail|name|identity|address)\b",
    r"\b(?:curl|wget)\s+[^|\n]{0,200}\|\s*(?:ba|z)?sh\b",
]), re.IGNORECASE)


def invisible(text: str) -> list[str]:
    """The invisible code points in `text`, as U+XXXX, ignoring an emoji's own VS16."""
    cleaned = EMOJI_BEFORE_VS16.sub("", EMOJI_ZWJ.sub("", text))
    return sorted({f"U+{ord(c):04X}" for c in INVISIBLE.findall(cleaned)})


def strip_invisible(text: str) -> tuple[str, dict]:
    """(text without invisible characters, what was removed). A Tag run is decoded to show what it
    said, but only as a defanged preview (length, sha256, letters with spaces between) so a reader
    or a model cannot take it as an instruction."""
    found = invisible(text)
    if not found:
        return text, {}
    report: dict = {"codepoints": found}
    runs = TAGS.findall(text)
    if runs:
        decoded = "".join(chr(ord(c) - 0xE0000) for c in "".join(runs) if 0x20 <= ord(c) - 0xE0000 < 0x7F)
        report["tag_run"] = {"chars": len(decoded), "sha256": hashlib.sha256(decoded.encode()).hexdigest()[:16],
                             "preview": " ".join(decoded[:40])}
    keep = EMOJI_ZWJ.sub("\x01", EMOJI_BEFORE_VS16.sub(lambda m: m[0][0] + "\x00", text))   # protect emoji
    out = INVISIBLE.sub("", keep).replace("\x00", "\ufe0f").replace("\x01", "\u200d")
    return out, report


def addressed_to_agents(text: str) -> list[str]:
    """The phrases in `text` that steer an agent (lowercased, de-duplicated)."""
    return sorted({m[0].lower() for m in AGENT_DIRECTED.finditer(text)})
