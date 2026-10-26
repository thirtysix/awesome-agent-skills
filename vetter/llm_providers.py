"""Model backends for llm_review.py: Anthropic (official SDK), DeepInfra or any OpenAI-compatible
server (raw HTTP), and a fake one for tests.

Every backend gets the same thing: a system prompt, one user message holding the skill as quoted
data, and a JSON schema. None of them is given tools, so a skill that talks the model round can
change a verdict but cannot make anything happen. Keys come from the environment only, are sent
only to their own provider's host, and are never logged.
"""
from __future__ import annotations

import collections
import datetime as dt
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

UA = "skill-review/0.1"


@dataclass
class Reply:
    text: str
    model: str                  # the model that actually served the request
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0
    stop: str = ""              # end | max_tokens | refusal | error
    note: str = ""
    raw_usage: dict = field(default_factory=dict)


class ProviderError(RuntimeError):
    """Not worth retrying: a bad key, an exhausted balance or spending cap, a bad request."""


# USD per million tokens (input, output). Used only when a provider reports no cost of its own
# (DeepInfra returns estimated_cost); check the price pages, these drift.
PRICES = {
    "claude-opus-5-5": (4.00, 20.00), "claude-sonnet-5-5": (2.00, 10.00), "claude-haiku-5-5": (0.10, 0.50),
    "deepseek-ai/DeepSeek-V4-Pro-0813": (0.50, 2.60), "deepseek-ai/DeepSeek-V4-Flash-0731": (0.10, 0.20),
    "deepseek-ai/DeepSeek-V4.1-Flash": (0.20, 0.60),
    "zai-org/GLM-5": (0.80, 2.08),
}

# Per-model call settings for OpenAI-compatible servers. One config for all models breaks some of
# them: thinking models must be told not to think before JSON, and DeepSeek flashes answer
# response_format=json_object on long output with "{}". Unknown models get the plain default.
OPENAI_COMPAT = {
    "deepseek-ai/DeepSeek-V4-Pro-0813": {"temperature": 0.3, "top_p": 0.9, "json_mode": False},
    "deepseek-ai/DeepSeek-V4-Flash-0731": {"temperature": 0.3, "top_p": 0.9, "enable_thinking": False, "json_mode": False},
    # thinking ON measured better here (2026-10-24, with --calibrate): known-good false alarms 2-5/91 vs 10-17/91
    "deepseek-ai/DeepSeek-V4.1-Flash": {"temperature": 0.3, "top_p": 0.9, "enable_thinking": True, "json_mode": False},
    "zai-org/GLM-5": {"temperature": 0.3, "top_p": 0.9, "enable_thinking": False, "json_mode": True},
}


def price(model: str, tin: int, tout: int, cache_read: int = 0, cache_write: int = 0, batch: bool = False) -> float:
    """tin: uncached input tokens. Cache reads bill at 0.1x input, cache writes (5-minute) at 1.25x;
    the Batch API halves everything."""
    p = PRICES.get(model)
    if not p:
        return 0.0
    usd = (tin * p[0] + cache_read * p[0] * 0.1 + cache_write * p[0] * 1.25 + tout * p[1]) / 1e6
    return usd * 0.5 if batch else usd


class Pacer:
    """Client-side input-token pacing for live runs: keep the tokens sent in any 60 s window under
    `itpm`, and pause until the reset time when the API's own counter says the minute is nearly spent.
    Shared by every worker thread; the per-minute limit is the organisation's, so stay well under it."""

    def __init__(self, itpm: int):
        self.itpm, self.sent, self.lock, self.until = itpm, collections.deque(), threading.Lock(), 0.0

    def acquire(self, tokens: int) -> None:
        while True:
            with self.lock:
                now = time.monotonic()
                while self.sent and now - self.sent[0][0] > 60:
                    self.sent.popleft()
                used = sum(n for _, n in self.sent)
                if now >= self.until and (used + tokens <= self.itpm or not self.sent):
                    self.sent.append((now, tokens))
                    return
                wait = max(self.until - now, (60 - (now - self.sent[0][0])) if self.sent else 1.0, 0.5)
            time.sleep(min(wait, 30))

    def observe(self, headers) -> None:
        """anthropic-ratelimit-input-tokens-remaining / -reset: pause everyone until the reset when
        under 10% of the minute's input tokens remain."""
        try:
            rem = int(headers.get("anthropic-ratelimit-input-tokens-remaining", ""))
            lim = int(headers.get("anthropic-ratelimit-input-tokens-limit", ""))
            reset = dt.datetime.fromisoformat(headers.get("anthropic-ratelimit-input-tokens-reset", "").replace("Z", "+00:00"))
        except (ValueError, TypeError):
            return
        if rem < lim * 0.1:
            secs = (reset - dt.datetime.now(dt.timezone.utc)).total_seconds()
            with self.lock:
                self.until = max(self.until, time.monotonic() + max(0.0, min(secs, 60)))


class Anthropic:
    """Claude through the official SDK, with structured output and server-side refusal fallback."""
    name = "anthropic"

    def __init__(self, model: str = "claude-opus-5-5", effort: str = "high", max_tokens: int = 16000,
                 itpm: int = 0, chars_per_token: float = 2.25):
        import anthropic                                      # optional dependency: only this backend needs it
        if not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
            raise ProviderError("set ANTHROPIC_API_KEY")
        self._sdk = anthropic
        self.client = anthropic.Anthropic(max_retries=4, default_headers={"User-Agent": UA})
        self.model, self.effort, self.max_tokens = model, effort, max_tokens
        self.pacer, self.cpt = (Pacer(itpm) if itpm else None), chars_per_token

    def params(self, system: str, user: str, schema: dict) -> dict:
        """One request's parameters, shared by live calls and the Batch API. The fixed review prompt is
        marked for caching: repeat calls read it at a tenth of the price, and cache reads do not count
        toward the input-tokens-per-minute limit (it caches only above the model's minimum prefix)."""
        return {"model": self.model, "max_tokens": self.max_tokens,
                "system": [{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                "messages": [{"role": "user", "content": user}],
                "output_config": {"effort": self.effort, "format": {"type": "json_schema", "schema": schema}}}

    def complete(self, system: str, user: str, schema: dict) -> Reply:
        a = self._sdk
        # server-side refusal fallback exists for Opus and Sonnet, not Haiku: a Haiku refusal is
        # recorded as "refused" and should be re-run on a larger model
        fb = {} if "haiku" in self.model else {"betas": ["server-side-fallback-2026-07-01"], "extra_body": {"fallbacks": "default"}}
        if self.pacer:
            self.pacer.acquire(int(len(user) / self.cpt))   # the cached system prompt does not count
        try:
            raw = self.client.beta.messages.with_raw_response.create(**self.params(system, user, schema), **fb)
        except (a.AuthenticationError, a.PermissionDeniedError, a.BadRequestError, a.NotFoundError) as e:
            raise ProviderError(f"anthropic {type(e).__name__}: {str(e)[:200]}") from None
        if self.pacer:
            self.pacer.observe(raw.headers)
        return self.reply(raw.parse())

    def reply(self, r, batch: bool = False) -> Reply:
        """A Message (live or from a batch result) as a Reply, with cache-aware cost."""
        text = "".join(b.text for b in r.content if getattr(b, "type", "") == "text")
        stop = {"end_turn": "end", "max_tokens": "max_tokens", "refusal": "refusal"}.get(r.stop_reason, r.stop_reason or "")
        note = ""
        if r.stop_reason == "refusal" and getattr(r, "stop_details", None):
            note = f"refusal category {getattr(r.stop_details, 'category', None)}"
        u = r.usage
        tin, tout = u.input_tokens or 0, u.output_tokens or 0
        cr, cw = getattr(u, "cache_read_input_tokens", 0) or 0, getattr(u, "cache_creation_input_tokens", 0) or 0
        return Reply(text, r.model, tin + cr + cw, tout, price(r.model, tin, tout, cr, cw, batch), stop, note,
                     {"input": tin, "cache_read": cr, "cache_write": cw, "output": tout, "batch": batch})


class OpenAICompatible:
    """DeepInfra by default; any OpenAI-compatible server (vLLM, Ollama, LM Studio) with base_url."""
    name = "openai-compatible"

    def __init__(self, model: str = "deepseek-ai/DeepSeek-V4-Pro-0813",
                 base_url: str = "https://api.deepinfra.com/v1/openai", key_env: str = "DEEPINFRA_API_KEY",
                 max_tokens: int = 16000):
        self.base = base_url.rstrip("/")
        u = urllib.parse.urlsplit(self.base)
        if u.scheme != "https" and u.hostname not in ("127.0.0.1", "localhost", "::1"):
            raise ProviderError("refusing a plain-http base URL that is not loopback")
        self.host = u.hostname
        self.key = os.environ.get(key_env, "")
        if not self.key and self.host not in ("127.0.0.1", "localhost", "::1"):
            raise ProviderError(f"set {key_env}")
        self.model, self.max_tokens = model, max_tokens
        self.params = OPENAI_COMPAT.get(model, {"temperature": 0.3, "top_p": 0.9, "json_mode": False})

    def complete(self, system: str, user: str, schema: dict) -> Reply:
        p = self.params
        body = {"model": self.model, "max_tokens": self.max_tokens, "temperature": p["temperature"], "top_p": p["top_p"],
                "messages": [{"role": "system", "content": system + "\n\nOutput schema (JSON Schema):\n" + json.dumps(schema)},
                             {"role": "user", "content": user}]}
        if "enable_thinking" in p:                            # only for models that accept the flag
            body["chat_template_kwargs"] = {"enable_thinking": p["enable_thinking"]}
        if p.get("json_mode"):
            body["response_format"] = {"type": "json_object"}
        req = urllib.request.Request(self.base + "/chat/completions", data=json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", "User-Agent": UA})
        if self.key:
            req.add_unredirected_header("Authorization", f"Bearer {self.key}")   # never follows a redirect elsewhere
        for attempt in range(5):
            try:
                with urllib.request.urlopen(req, timeout=600) as r:
                    data = json.loads(r.read())
                break
            except urllib.error.HTTPError as e:
                msg = e.read()[:300].decode("utf-8", "replace")
                if e.code in (400, 401, 403, 404, 402, 422):   # 402: balance or spending cap; never retry
                    raise ProviderError(f"http {e.code}: {msg}") from None
                if attempt == 4:
                    raise ProviderError(f"http {e.code} after retries: {msg}") from None
                time.sleep(min(int(e.headers.get("Retry-After") or 0) or 5 * 2 ** attempt, 120))
            except (urllib.error.URLError, TimeoutError):
                if attempt == 4:
                    raise
                time.sleep(5 * 2 ** attempt)
        ch = (data.get("choices") or [{}])[0]
        text = (ch.get("message") or {}).get("content") or ""
        u = data.get("usage") or {}
        tin, tout = u.get("prompt_tokens", 0), u.get("completion_tokens", 0)
        served = data.get("model") or self.model
        stop = {"stop": "end", "length": "max_tokens"}.get(ch.get("finish_reason"), ch.get("finish_reason") or "")
        note = f"served by {served}" if served != self.model else ""   # providers alias retired ids silently
        cost = u.get("estimated_cost") or price(self.model, tin, tout)
        return Reply(text, served, tin, tout, float(cost), stop, note, u)


class Fake:
    """Returns a canned answer; for tests and --dry-run."""
    name = "fake"

    def __init__(self, answer: dict | str | None = None, model: str = "fake"):
        self.answer, self.model, self.calls = answer, model, []

    def complete(self, system: str, user: str, schema: dict) -> Reply:
        self.calls.append((system, user))
        a = self.answer if self.answer is not None else {"summary": "", "risk": "none", "capabilities": {}, "findings": [],
                                                         "hints": [], "reviewer_manipulation": False}
        text = a if isinstance(a, str) else json.dumps(a)
        return Reply(text, self.model, len(user) // 4, len(text) // 4, 0.0, "end")


def make(provider: str, model: str | None = None, base_url: str | None = None, effort: str = "high",
         temperature: float | None = None, thinking: bool = False, itpm: int = 0, chars_per_token: float = 2.25):
    if provider == "anthropic":
        p = Anthropic(model or "claude-opus-5-5", effort, itpm=itpm, chars_per_token=chars_per_token)
        p.settings = f"effort={effort}"
        return p
    if provider == "deepinfra":
        p = OpenAICompatible(model or "deepseek-ai/DeepSeek-V4-Pro-0813")
        p.params = dict(p.params)
        if temperature is not None:
            p.params["temperature"] = temperature
        if thinking:
            p.params["enable_thinking"] = True
        if p.params.get("enable_thinking"):
            p.max_tokens = max(p.max_tokens, 32000)          # reasoning comes out of the same budget
        p.settings = json.dumps(p.params, sort_keys=True)
        return p
    if provider == "openai-compatible":
        if not base_url:
            raise ProviderError("--base-url is required for openai-compatible")
        return OpenAICompatible(model or "local", base_url, key_env="OPENAI_COMPAT_API_KEY")
    if provider == "fake":
        return Fake()
    raise ProviderError(f"unknown provider {provider}")


def extract_json(text: str) -> dict | None:
    """The first JSON object in a reply: bare, fenced, or wrapped in prose. If that fails, once more
    with the stray-quote typo below repaired (it also throws off the brace scan)."""
    got = _extract(text)
    if got is None and _STRAY_QUOTE.search(text):
        got = _extract(_STRAY_QUOTE.sub(r"\1", text))
    return got


def _extract(text: str) -> dict | None:
    t = text.strip()
    m = re.search(r"```(?:json)?\s*(\{.*\})\s*```", t, re.S)
    if m:
        t = m[1]
    start = t.find("{")
    if start < 0:
        return None
    depth, ins, esc = 0, False, False
    for i, c in enumerate(t[start:], start):
        if ins:
            if esc:
                esc = False
            elif c == "\\":
                esc = True
            elif c == '"':
                ins = False
            continue
        if c == '"':
            ins = True
        elif c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(t[start:i + 1])
                except json.JSONDecodeError:
                    return None
    return None


# A typo some models make in otherwise valid JSON: a stray quote after a number ("line": 10").
# DeepSeek-V4.1-Flash did it in 2-4 of 104 replies per run (2026-10-24).
_STRAY_QUOTE = re.compile(r'(:\s*-?\d+)"(?=\s*[,}\]])')

