import asyncio
import json
import os
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor as _ThreadPoolExecutor
from typing import Optional, Tuple

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Environment variables ─────────────────────────────────────────────────
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
DEEPSEEK_API_KEY = os.environ.get("DEEPSEEK_API_KEY", "")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
OLLAMA_URL: str = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
LLAMACPP_URL: str = os.environ.get("LLAMACPP_URL", "http://127.0.0.1:8033")

# ── Lazy imports ──────────────────────────────────────────────────────────
_anthropic_mod = None
_openai_mod = None
_gemini_mod = None

_ANTHROPIC_AVAILABLE: bool = False
_OPENAI_AVAILABLE: bool = False
_GEMINI_AVAILABLE: bool = False


def _init_anthropic():
    global _anthropic_mod, _ANTHROPIC_AVAILABLE
    if _anthropic_mod is None:
        try:
            import anthropic as m
            _anthropic_mod = m
            _ANTHROPIC_AVAILABLE = True
        except ImportError:
            _anthropic_mod = False
    return _anthropic_mod if _ANTHROPIC_AVAILABLE else None


def _init_openai():
    global _openai_mod, _OPENAI_AVAILABLE
    if _openai_mod is None:
        try:
            import openai as m
            _openai_mod = m
            _OPENAI_AVAILABLE = True
        except ImportError:
            _openai_mod = False
    return _openai_mod if _OPENAI_AVAILABLE else None


def _init_gemini():
    global _gemini_mod, _GEMINI_AVAILABLE
    if _gemini_mod is None:
        try:
            from google import genai as m
            _gemini_mod = m
            _GEMINI_AVAILABLE = True
        except ImportError:
            _gemini_mod = False
    return _gemini_mod if _GEMINI_AVAILABLE else None


# ── Lazy client globals ───────────────────────────────────────────────────
_anthropic_client = None
_openai_client = None
_deepseek_client = None
_copilot_client = None
_gemini_client = None

# ── Thread-pool executor for blocking HTTP calls (ollama / llama.cpp) ─────
_IO_EXECUTOR = _ThreadPoolExecutor(max_workers=4, thread_name_prefix="providers-io")


# ── Blocking HTTP helpers ─────────────────────────────────────────────────

def _ollama_blocking_call(model_id: str, prompt: str, max_tokens: int) -> Tuple[str, str]:
    """Synchronous HTTP call to a local Ollama server (run via asyncio executor).

    Uses only stdlib urllib so no extra package is required.
    Requires `ollama serve` running at OLLAMA_URL (default http://localhost:11434).
    Pull models first with e.g.: ollama pull gemma3:4b
    """
    body = json.dumps({
        "model":   model_id,
        "messages": [{"role": "user", "content": prompt}],
        "stream":  False,
        "options": {"num_predict": max_tokens},
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{OLLAMA_URL}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        answer = data.get("message", {}).get("content", "(empty response)")
        eval_c   = data.get("eval_count")
        prompt_c = data.get("prompt_eval_count", 0)
        tokens   = str(eval_c + prompt_c) if isinstance(eval_c, int) else "?"
        return answer, tokens
    except urllib.error.URLError as exc:
        return (
            f"[error] Ollama unreachable at {OLLAMA_URL} — "
            f"start it with: ollama serve  (then: ollama pull {model_id})\n"
            f"Detail: {exc}"
        ), "?"
    except Exception as exc:
        return f"[error] Ollama call failed: {exc}", "?"


def _llamacpp_blocking_call(model_id: str, prompt: str, max_tokens: int) -> Tuple[str, str]:
    """Synchronous HTTP call to a llama.cpp server (run via asyncio executor).

    Uses only stdlib urllib so no extra package is required.
    Requires `llama-server` running at LLAMACPP_URL (default http://127.0.0.1:8033).
    The model field is sent but ignored by llama.cpp — it serves whichever model was
    loaded at startup.  Uses the OpenAI-compatible /v1/chat/completions endpoint.
    """
    body = json.dumps({
        "model":      model_id,
        "messages":   [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "stream":     False,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{LLAMACPP_URL}/v1/chat/completions",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        answer = (data.get("choices", [{}])[0]
                      .get("message", {})
                      .get("content", "(empty response)"))
        usage  = data.get("usage", {})
        total  = usage.get("total_tokens")
        tokens = str(total) if isinstance(total, int) else "?"
        return answer, tokens
    except urllib.error.URLError as exc:
        return (
            f"[error] llama.cpp unreachable at {LLAMACPP_URL} — "
            f"start it with: llama-server -m <model.gguf>\n"
            f"Detail: {exc}"
        ), "?"
    except Exception as exc:
        return f"[error] llama.cpp call failed: {exc}", "?"


# ── Async provider call functions ─────────────────────────────────────────

async def call_claude(model_id: str, prompt: str, max_tokens: int) -> Tuple[str, str]:
    """Call Anthropic Claude. Returns (answer_text, tokens_str)."""
    global _anthropic_client

    mod = _init_anthropic()
    if mod is None:
        return ("[error] anthropic package not installed — "
                "run: pip install anthropic"), "?"
    if not ANTHROPIC_API_KEY:
        return ("[error] ANTHROPIC_API_KEY not set — "
                "set the environment variable and restart"), "?"
    try:
        if _anthropic_client is None:
            _anthropic_client = mod.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
        msg = await _anthropic_client.messages.create(
            model=model_id, max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        answer = msg.content[0].text if msg.content else "(empty response)"
        usage  = getattr(msg, "usage", None)
        tokens = str(usage.input_tokens + usage.output_tokens) if usage else "?"
        return answer, tokens
    except Exception as exc:
        _anthropic_client = None
        return f"[error] {exc}", "?"


async def call_openai(model_id: str, prompt: str, max_tokens: int) -> Tuple[str, str]:
    """Call OpenAI. Returns (answer_text, tokens_str)."""
    global _openai_client

    mod = _init_openai()
    if mod is None:
        return ("[error] openai package not installed — "
                "run: pip install openai"), "?"
    if not OPENAI_API_KEY:
        return ("[error] OPENAI_API_KEY not set — "
                "set the environment variable and restart"), "?"
    try:
        if _openai_client is None:
            _openai_client = mod.AsyncOpenAI(api_key=OPENAI_API_KEY)
        resp = await _openai_client.chat.completions.create(
            model=model_id, max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        answer = (resp.choices[0].message.content
                  if resp.choices else "(empty response)")
        usage  = getattr(resp, "usage", None)
        tokens = str(usage.total_tokens) if usage else "?"
        return answer, tokens
    except Exception as exc:
        _openai_client = None
        return f"[error] {exc}", "?"


async def call_deepseek(model_id: str, prompt: str, max_tokens: int) -> Tuple[str, str]:
    """Call DeepSeek. Returns (answer_text, tokens_str)."""
    global _deepseek_client

    mod = _init_openai()
    if mod is None:
        return ("[error] openai package not installed — "
                "run: pip install openai"), "?"
    if not DEEPSEEK_API_KEY:
        return ("[error] DEEPSEEK_API_KEY not set — "
                "set the environment variable and restart"), "?"
    try:
        if _deepseek_client is None:
            _deepseek_client = mod.AsyncOpenAI(
                api_key=DEEPSEEK_API_KEY,
                base_url="https://api.deepseek.com")
        resp = await _deepseek_client.chat.completions.create(
            model=model_id, max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        answer = (resp.choices[0].message.content
                  if resp.choices else "(empty response)")
        usage  = getattr(resp, "usage", None)
        tokens = str(usage.total_tokens) if usage else "?"
        return answer, tokens
    except Exception as exc:
        _deepseek_client = None
        return f"[error] {exc}", "?"


async def call_copilot(model_id: str, prompt: str, max_tokens: int) -> Tuple[str, str]:
    """Call GitHub Copilot. Returns (answer_text, tokens_str)."""
    global _copilot_client

    mod = _init_openai()
    if mod is None:
        return ("[error] openai package not installed — "
                "run: pip install openai"), "?"
    if not GITHUB_TOKEN:
        return ("[error] GITHUB_TOKEN not set — "
                "set the environment variable and restart"), "?"
    try:
        if _copilot_client is None:
            _copilot_client = mod.AsyncOpenAI(
                api_key=GITHUB_TOKEN,
                base_url="https://api.githubcopilot.com",
                default_headers={
                    "editor-version":        "eyearesee/1.0",
                    "editor-plugin-version": "eyearesee/1.0",
                    "copilot-integration-id": "eyearesee",
                })
        resp = await _copilot_client.chat.completions.create(
            model=model_id, max_tokens=max_tokens,
            messages=[{"role": "user", "content": prompt}],
        )
        answer = (resp.choices[0].message.content
                  if resp.choices else "(empty response)")
        usage  = getattr(resp, "usage", None)
        tokens = str(usage.total_tokens) if usage else "?"
        return answer, tokens
    except Exception as exc:
        _copilot_client = None
        return f"[error] {exc}", "?"


async def call_gemini(model_id: str, prompt: str, max_tokens: int) -> Tuple[str, str]:
    """Call Google Gemini. Returns (answer_text, tokens_str)."""
    global _gemini_client

    mod = _init_gemini()
    if mod is None:
        return ("[error] google-genai package not installed — "
                "run: pip install google-genai"), "?"
    if not GEMINI_API_KEY:
        return ("[error] GEMINI_API_KEY not set — "
                "set the environment variable and restart"), "?"
    try:
        if _gemini_client is None:
            _gemini_client = mod.aio.Client(api_key=GEMINI_API_KEY)
        resp = await _gemini_client.models.generate_content(
            model=model_id,
            contents=prompt,
            config=mod.types.GenerateContentConfig(max_output_tokens=max_tokens))
        answer = resp.text if resp.text else "(empty response)"
        usage  = getattr(resp, "usage_metadata", None)
        if usage:
            tokens = str(usage.prompt_token_count + usage.candidates_token_count)
        else:
            tokens = "?"
        return answer, tokens
    except Exception as exc:
        _gemini_client = None
        return f"[error] {exc}", "?"


async def call_ollama(model_id: str, prompt: str, max_tokens: int) -> Tuple[str, str]:
    """Call local Ollama server. Returns (answer_text, tokens_str)."""
    loop = asyncio.get_running_loop()
    answer, tokens = await loop.run_in_executor(
        _IO_EXECUTOR, _ollama_blocking_call, model_id, prompt, max_tokens)
    return answer, tokens


async def call_llamacpp(model_id: str, prompt: str, max_tokens: int) -> Tuple[str, str]:
    """Call local llama.cpp server. Returns (answer_text, tokens_str)."""
    loop = asyncio.get_running_loop()
    answer, tokens = await loop.run_in_executor(
        _IO_EXECUTOR, _llamacpp_blocking_call, model_id, prompt, max_tokens)
    return answer, tokens
