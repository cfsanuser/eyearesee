#!/usr/bin/env python3
import asyncio
import atexit
import base64
import getpass
import webbrowser
import importlib.util
import logging
import socket
import subprocess
import sys
import unicodedata
import urllib.parse
import urllib.request
import hashlib
import hmac
import heapq
import io
import json
import re
import ssl
import struct
import time
import os
import random
import uuid
import warnings
from collections import Counter, deque, OrderedDict
from concurrent.futures import ThreadPoolExecutor as _ThreadPoolExecutor
from math import log, log2
from typing import Optional, Dict, List, Tuple, Callable, Any

# =========================
# CLI flags — parsed before any optional imports or install code runs
# =========================
_NO_AI:         bool = "--no-ai"              in sys.argv
_NO_INSTALL:    bool = "--no-install"         in sys.argv
_REQUIRE_VENV:  bool = "--require-virtualenv" in sys.argv

# =========================
# Anthropic (optional)
# =========================
try:
    import anthropic as _anthropic_mod
    ANTHROPIC_AVAILABLE = True
except ImportError:
    _anthropic_mod = None  # type: ignore
    ANTHROPIC_AVAILABLE = False

# =========================
# OpenAI (optional)
# =========================
try:
    import openai as _openai_mod
    OPENAI_AVAILABLE = True
except ImportError:
    _openai_mod = None  # type: ignore
    OPENAI_AVAILABLE = False

# =========================
# Google Gemini (optional)
# =========================
try:
    from google import genai as _gemini_mod
    GEMINI_AVAILABLE = True
except ImportError:
    _gemini_mod = None  # type: ignore
    GEMINI_AVAILABLE = False

# =========================
# cryptography (optional — needed for SASL ECDSA-NIST256P-CHALLENGE)
# =========================
try:
    from cryptography.hazmat.primitives.asymmetric import ec as _ecdsa_ec
    from cryptography.hazmat.primitives import hashes as _ecdsa_hashes
    from cryptography.hazmat.primitives.serialization import load_pem_private_key as _load_pem_private_key
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    _ecdsa_ec = None            # type: ignore
    _ecdsa_hashes = None        # type: ignore
    _load_pem_private_key = None  # type: ignore
    CRYPTOGRAPHY_AVAILABLE = False

# =========================
# Curses (Windows-aware)
# =========================
try:
    import curses
except ModuleNotFoundError:
    # _curses is missing — typical on Windows builds that ship without it.
    # windows_curses may be installed in a site-packages directory not yet on
    # sys.path (user-site, a parallel Python install, etc.).  Widen the search
    # before giving up.
    import pathlib
    import site as _site
    _extra: list = []
    try:
        _extra.append(_site.getusersitepackages())
    except Exception:
        pass
    try:
        _extra.extend(_site.getsitepackages())
    except Exception:
        pass
    # Also scan sibling Lib/site-packages of the running interpreter
    _extra.append(str(pathlib.Path(sys.executable).parent / "Lib" / "site-packages"))
    _extra.append(str(pathlib.Path(sys.executable).parent.parent / "Lib" / "site-packages"))
    for _p in _extra:
        if _p and _p not in sys.path:
            sys.path.insert(0, _p)
    try:
        import windows_curses  # type: ignore
    except ImportError:
        if _NO_INSTALL:
            sys.exit("windows-curses not found and --no-install is set. "
                     "Run without --no-install or: pip install windows-curses")
        print("windows-curses not found — installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "windows-curses"])
    import curses

# =========================
# Config
# =========================
DEFAULT_SERVER = "irc.libera.chat"
DEFAULT_PORT = 6697
DEFAULT_NICK = "cfuser"
DEFAULT_CHANNEL = "##anime"
NICKSERV_PASSWORD = os.environ.get("IRC_NICKSERV_PASSWORD", "")
# SASL mechanism and credential paths.  Supported mechanisms:
#   PLAIN                    — password in IRC_NICKSERV_PASSWORD [default]
#   SCRAM-SHA-256            — RFC-5802 SCRAM (password in IRC_NICKSERV_PASSWORD)
#   EXTERNAL                 — TLS client certificate (IRC_SASL_CERT + IRC_SASL_KEY)
#   ECDSA-NIST256P-CHALLENGE — EC challenge-response (IRC_SASL_KEY; needs 'cryptography' pkg)
SASL_MECHANISM = os.environ.get("IRC_SASL_MECHANISM", "PLAIN").upper()
SASL_CERT      = os.environ.get("IRC_SASL_CERT", "")   # path to PEM client certificate
SASL_KEY       = os.environ.get("IRC_SASL_KEY", "")    # path to PEM private key

MAX_MESSAGES = 500
USER_HISTORY_WINDOW = 200
AI_SUSPECT_THRESHOLD = 70
# _NO_AI / _NO_INSTALL are defined early (before imports) — see top of file.
# AI detection logging: enabled by default.  Set IRC_AI_LOG=0 to disable at startup.
# Can also be toggled at runtime with /logtoggle.
_ai_logging_enabled: bool = os.environ.get("IRC_AI_LOG", "1") not in ("0", "false", "no", "off")
_AUTOJOIN_CHANNELS: set = set()

# All data files are placed next to the script so they are writable regardless
# of the working directory the user launches from (e.g. C:\Windows\system32).
_SCRIPT_DIR        = os.path.dirname(os.path.abspath(__file__))
AI_LOG_PATH        = os.path.join(_SCRIPT_DIR, "ai_scores.log")
INPUT_HISTORY_PATH = os.path.join(_SCRIPT_DIR, "irc_input_history.txt")
IRC_CONFIG_PATH    = os.path.join(_SCRIPT_DIR, "irc_config.json")
INPUT_HISTORY_MAX  = 500
CHAT_LOG_DIR       = os.path.join(_SCRIPT_DIR, "chat_logs")
LINK_LOG_DIR       = os.path.join(_SCRIPT_DIR, "link_logs")
DCC_DIR            = os.path.join(_SCRIPT_DIR, "dcc_downloads")
CHAT_LOG_LOAD      = 500
# User-contributed tell-phrases learned via /learn_tell
USER_TELL_PATH     = os.path.join(_SCRIPT_DIR, "user_tell_phrases.json")
# Sentence embedding model for semantic-drift detection
EMBEDDING_MODEL: str = os.environ.get("IRC_EMBEDDING_MODEL", "")  # e.g. "all-MiniLM-L6-v2"

# ── Built-in bouncer (BNC) ────────────────────────────────────────────────────
BNC_BUFFER_PATH    = os.path.join(_SCRIPT_DIR, "bouncer_buffer.jsonl")
BNC_CONFIG_PATH    = os.path.join(_SCRIPT_DIR, "bouncer_config.json")
# GPG
GPG_BINARY: str    = os.environ.get("IRC_GPG_BINARY", "gpg")
# Tor SOCKS5 proxy
TOR_PROXY_HOST: str = os.environ.get("IRC_TOR_PROXY_HOST", "127.0.0.1")
TOR_PROXY_PORT: int = int(os.environ.get("IRC_TOR_PROXY_PORT", "9050"))
# STS policy persistence
STS_POLICY_PATH    = os.path.join(_SCRIPT_DIR, "sts_policies.json")

# AI provider keys
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
OPENAI_API_KEY    = os.environ.get("OPENAI_API_KEY", "")
DEEPSEEK_API_KEY  = os.environ.get("DEEPSEEK_API_KEY", "")
GITHUB_TOKEN      = os.environ.get("GITHUB_TOKEN", "")
GEMINI_API_KEY    = os.environ.get("GEMINI_API_KEY", "")
# Ollama: local/offline LLM server.  Override with OLLAMA_URL env var if running elsewhere.
OLLAMA_URL: str    = os.environ.get("OLLAMA_URL",    "http://127.0.0.1:11434")
# llama.cpp: local server with OpenAI-compatible API.  Override with LLAMACPP_URL env var.
LLAMACPP_URL: str  = os.environ.get("LLAMACPP_URL",  "http://127.0.0.1:8033")
# Modern observer model for Binoculars — replaced distilgpt2 when set.
# Any HuggingFace causal LM works (e.g. "TinyLlama/TinyLlama-1.1B-Chat-v1.0").
# Falls back to distilgpt2 if loading fails.
OBSERVER_MODEL_ID: str = os.environ.get("IRC_OBSERVER_MODEL", "distilgpt2")

# Unified model registry — key is the short name used in /askai, /summarize, /model.
# Each entry: provider ("claude"|"openai"|"ollama"|"llamacpp"|"gemini"), api model id, human label.
# Ollama models require `ollama serve` running locally; no API key needed.
# Pull models with e.g.:  ollama pull gemma3:4b   or   ollama pull llama3.2
# llama.cpp models require `llama-server` running at LLAMACPP_URL; model field is advisory.
AI_MODELS: Dict[str, Dict[str, str]] = {
    # ── Cloud: Anthropic Claude ───────────────────────────────────────────
    "opus":    {"provider": "claude",   "id": "claude-opus-4-6",            "label": "Claude Opus 4"},
    "sonnet":  {"provider": "claude",   "id": "claude-sonnet-4-6",          "label": "Claude Sonnet 4"},
    "haiku":   {"provider": "claude",   "id": "claude-haiku-4-5-20251001",  "label": "Claude Haiku 4"},
    # ── Cloud: OpenAI GPT ─────────────────────────────────────────────────
    "gpt4o":   {"provider": "openai",   "id": "gpt-4o",                     "label": "GPT-4o"},
    "gpt4":    {"provider": "openai",   "id": "gpt-4-turbo",                "label": "GPT-4 Turbo"},
    "gpt35":   {"provider": "openai",   "id": "gpt-3.5-turbo",              "label": "GPT-3.5 Turbo"},
    # ── Cloud: DeepSeek ──────────────────────────────────────────────────
    "deepseek": {"provider": "deepseek", "id": "deepseek-chat",     "label": "DeepSeek-V3"},
    "dsr1":     {"provider": "deepseek", "id": "deepseek-reasoner", "label": "DeepSeek-R1"},
    # ── Cloud: GitHub Copilot ────────────────────────────────────────────
    "copilot":  {"provider": "copilot",  "id": "gpt-4o",            "label": "Copilot GPT-4o"},
    "copilot-mini": {"provider": "copilot", "id": "gpt-4o-mini",    "label": "Copilot GPT-4o-mini"},
    # ── Cloud: Google Gemini ─────────────────────────────────────────────
    "gemini":  {"provider": "gemini",   "id": "gemini-2.0-flash",           "label": "Gemini 2.0 Flash"},
    "gpro":    {"provider": "gemini",   "id": "gemini-2.5-pro",             "label": "Gemini 2.5 Pro"},
    # ── Local/offline: Ollama ─────────────────────────────────────────────
    "gemma":   {"provider": "ollama",   "id": "gemma3:4b",   "label": "Gemma 3 4B   (Ollama/offline)"},
    "llama3":  {"provider": "ollama",   "id": "llama3.2",    "label": "Llama 3.2    (Ollama/offline)"},
    # ── Local/offline: llama.cpp ─────────────────────────────────────────
    "gemma4":  {"provider": "llamacpp", "id": "gemma-4",     "label": "Gemma 4      (llama.cpp/offline)"},
    "qwen3":   {"provider": "llamacpp", "id": "qwen3",       "label": "Qwen 3       (llama.cpp/offline)"},
}
# Keep CLAUDE_MODELS as a filtered view so existing internal references still work.
CLAUDE_MODELS: Dict[str, str] = {
    k: v["id"] for k, v in AI_MODELS.items() if v["provider"] == "claude"
}
CLAUDE_DEFAULT_MODEL = "qwen3"    # default model key

# 12 built-in UI colour themes
# Each row: (name, pair1_fg, pair1_bg, pair2_fg, pair2_bg, pair3_fg, pair3_bg, pair8_fg, pair8_bg)
#   pair1 = chat title bar    pair2 = userlist header
#   pair3 = suspect nick      pair8 = /me action line
# Colours: 0=black 1=red 2=green 3=yellow 4=blue 5=magenta 6=cyan 7=white  -1=terminal default
THEMES: List[Tuple] = [
    ("Classic",   6, -1,  5, -1,  3, -1,  2, -1),  # cyan title / magenta users / yellow suspect / green action
    ("Hacker",    2,  0,  2,  0,  2, -1,  2, -1),  # matrix-green on black
    ("Ocean",     7,  4,  6,  4,  6, -1,  6, -1),  # white+cyan headers on blue
    ("Sunset",    0,  3,  1, -1,  1, -1,  3, -1),  # black-on-yellow title / red suspects / yellow action
    ("Neon",      0,  5,  5, -1,  5, -1,  6, -1),  # black-on-magenta title / magenta suspects / cyan action
    ("Nord",      6,  0,  4,  0,  1, -1,  2, -1),  # nord-inspired: cyan title / blue users / red suspect
    ("Dracula",   5,  0,  6,  0,  3, -1,  2, -1),  # dracula: magenta title / cyan users / yellow suspect
    ("Monokai",   3,  0,  2,  0,  1, -1,  6, -1),  # monokai: yellow title / green users / red suspect
    ("Solarized", 3,  0,  4,  0,  1, -1,  2, -1),  # solarized dark: yellow title / blue users / red suspect
    ("Gruvbox",   3,  0,  2,  0,  1, -1,  6, -1),  # gruvbox dark: yellow title / green users / cyan action
    ("Tokyo",     5,  0,  6,  0,  1, -1,  2, -1),  # tokyo night: magenta title / cyan users / red suspect
    ("Catppuccin",5,  0,  6,  0,  3, -1,  2, -1),  # catppuccin mocha: mauve title / teal users / yellow suspect
]

warnings.filterwarnings("ignore", category=UserWarning, module="transformers")

# =========================
# Chat & Input Persistence
# =========================
_UNSAFE_FILENAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_ACTION_LINE_RE     = re.compile(r'^\[\d{2}:\d{2}\] \* \S')  # "[HH:MM] * nick …"
_URL_RE             = re.compile(r'https?://[^\s\x00-\x1f\x7f<>"]+')  # bare URL in plain text

# Frozensets for O(1) IRC numeric-reply membership tests in process_line
_WHOIS_REPLIES = frozenset({"307", "311", "312", "313", "317", "318", "319", "330", "671"})
_WHO_REPLIES   = frozenset({"352", "314"})
_SERVER_INFO   = frozenset({"002", "003", "004", "005", "372", "375", "376"})
# Channel-join error replies — routed to the channel window with the error
_ERROR_REPLIES = frozenset({"471", "473", "474", "475", "477", "489"})
# Numeric replies that are safely discarded (end-of-list markers, stats, etc.)
_SILENT_NUMERICS = frozenset({"315", "333", "366", "265", "266"})

def _chat_log_path(window_name: str) -> str:
    safe = _UNSAFE_FILENAME_RE.sub("_", window_name) or "_"
    # Collapse dot-sequences to prevent directory traversal (e.g. ".." → "_")
    safe = re.sub(r'\.{2,}', '_', safe) or "_"
    return os.path.join(CHAT_LOG_DIR, safe + ".log")

def load_irc_config() -> dict:
    """Return saved server/nick/channel config, or {} if none exists."""
    try:
        with open(IRC_CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return {}

def save_irc_config(cfg: dict) -> None:
    """Persist all settings to irc_config.json."""
    try:
        with open(IRC_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except OSError:
        pass


def _save_autojoin_config() -> None:
    cfg = load_irc_config()
    cfg["autojoin"] = sorted(_AUTOJOIN_CHANNELS)
    save_irc_config(cfg)

def load_input_history() -> List[str]:
    """Return up to INPUT_HISTORY_MAX lines, most-recent first."""
    try:
        with open(INPUT_HISTORY_PATH, "r", encoding="utf-8") as f:
            lines = [l.rstrip("\n") for l in f if l.strip()]
    except FileNotFoundError:
        return []
    except Exception:
        return []
    recent = lines[-INPUT_HISTORY_MAX:]
    # Trim the file if it grew beyond the cap
    if len(lines) > INPUT_HISTORY_MAX:
        try:
            with open(INPUT_HISTORY_PATH, "w", encoding="utf-8") as f:
                f.write("\n".join(recent) + "\n")
        except Exception:
            pass
    return list(reversed(recent))

def save_input_history_line(line: str) -> None:
    global _input_hist_handle
    try:
        if _input_hist_handle is None or _input_hist_handle.closed:
            # buffering=1 → line-buffered: each \n triggers a real write,
            # so commands are persisted immediately even if the process crashes.
            _input_hist_handle = _open_append(INPUT_HISTORY_PATH, buffering=1)
        _input_hist_handle.write(line + "\n")
    except Exception:
        pass

def load_chat_history(window_name: str) -> List[str]:
    """Return last CHAT_LOG_LOAD lines for the window.

    Reads backwards from EOF in 8 KB chunks so large log files are never
    fully loaded — only enough bytes to produce CHAT_LOG_LOAD lines are read.
    """
    path = _chat_log_path(window_name)
    try:
        with open(path, "rb") as f:
            f.seek(0, 2)
            size = f.tell()
            if size == 0:
                return []

            buf  = b""
            pos  = size
            # +1 so a partial line at the start of the read buffer is discarded
            need = CHAT_LOG_LOAD + 1

            while pos > 0 and buf.count(b"\n") < need:
                step = min(8192, pos)
                pos -= step
                f.seek(pos)
                buf = f.read(step) + buf

            lines  = buf.decode("utf-8", errors="replace").splitlines()
            result = [l for l in lines if l.strip()]
            return result[-CHAT_LOG_LOAD:]
    except FileNotFoundError:
        return []
    except Exception:
        return []

def append_chat_line(window_name: str, line: str) -> None:
    global _chat_log_handles
    try:
        handle = _chat_log_handles.get(window_name)
        if handle is None or handle.closed:
            os.makedirs(CHAT_LOG_DIR, exist_ok=True)
            handle = _open_append(_chat_log_path(window_name))
            _chat_log_handles[window_name] = handle
        handle.write(line + "\n")
    except Exception:
        pass


# =========================
# AIVsAIDetector
# =========================

class AIVsAIDetector:
    """Detects when two AI/bot users are talking to each other.

    Correlates:
      • Both participants have high rolling AI scores
      • Frequent mutual mentions or replies between them
      • Formal/templated dialogue patterns (question→answer chains)
      • Timing regularity (uniform gaps between exchanges)

    Flags AI-vs-AI conversations with confidence levels.
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "aivsai_pairs.json")
    _AI_THRESHOLD = 60.0
    _MIN_EXCHANGES = 3

    def __init__(self):
        self._pairs: Dict[str, Dict] = {}
        self._recent_exchange: Dict[str, deque] = {}
        self._ui_queue: Optional[asyncio.Queue] = None
        self._alerts_issued: set = set()
        self._last_save: float = 0.0
        self.load()

    def set_ui_queue(self, queue: asyncio.Queue) -> None:
        self._ui_queue = queue

    def record_exchange(self, from_nick: str, to_nick: str, channel: str,
                        from_ai: float, to_ai: float) -> None:
        fn = from_nick.lower()
        tn = to_nick.lower()
        if fn == tn:
            return
        pair_key = f"{min(fn, tn)}:{max(fn, tn)}"
        self._recent_exchange.setdefault(pair_key, deque(maxlen=50))
        self._recent_exchange[pair_key].append({
            "from": fn, "to": tn, "channel": channel.lower(),
            "from_ai": from_ai, "to_ai": to_ai,
            "ts": time.time(),
        })
        self._evaluate_pair(pair_key, fn, tn, channel)

    def _evaluate_pair(self, pair_key: str, nick_a: str, nick_b: str,
                       channel: str) -> None:
        exchanges = self._recent_exchange.get(pair_key, [])
        if len(exchanges) < self._MIN_EXCHANGES:
            return
        recent = list(exchanges)[-20:]
        both_high = sum(1 for e in recent
                        if e["from_ai"] >= self._AI_THRESHOLD
                        and e["to_ai"] >= self._AI_THRESHOLD)
        if both_high < self._MIN_EXCHANGES:
            return
        avg_ai = sum((e["from_ai"] + e["to_ai"]) / 2 for e in recent) / len(recent)
        gaps = []
        for i in range(1, len(recent)):
            gaps.append(recent[i]["ts"] - recent[i - 1]["ts"])
        gap_uniformity = 0.0
        if gaps:
            mean_gap = sum(gaps) / len(gaps)
            if mean_gap > 0:
                cv = (sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)) ** 0.5 / mean_gap
                gap_uniformity = max(0.0, 1.0 - cv)
        confidence = min(1.0,
                         0.4 * (both_high / len(recent))
                         + 0.3 * (avg_ai / 100.0)
                         + 0.2 * gap_uniformity
                         + 0.1 * min(1.0, len(recent) / 10.0))
        self._pairs[pair_key] = {
            "nick_a": nick_a, "nick_b": nick_b,
            "channel": channel.lower(),
            "exchanges": len(recent),
            "both_high": both_high,
            "avg_ai": round(avg_ai, 1),
            "gap_uniformity": round(gap_uniformity, 3),
            "confidence": round(confidence, 3),
            "last_seen": time.time(),
        }
        if confidence >= 0.5 and pair_key not in self._alerts_issued:
            self._alerts_issued.add(pair_key)
            if self._ui_queue:
                try:
                    self._ui_queue.put_nowait(("status",
                        f"[ai-vs-ai] {nick_a} ↔ {nick_b} in {channel}: "
                        f"confidence={confidence:.0%} "
                        f"avg_ai={avg_ai:.0f}% exchanges={len(recent)}"))
                except Exception:
                    pass
        elif confidence < 0.3:
            self._alerts_issued.discard(pair_key)
        self._maybe_save()

    def get_active_pairs(self, min_confidence: float = 0.3) -> list:
        results = []
        for pair_key, data in self._pairs.items():
            if data["confidence"] >= min_confidence:
                results.append(data)
        results.sort(key=lambda x: -x["confidence"])
        return results

    def get_pair(self, nick_a: str, nick_b: str) -> Optional[Dict]:
        pair_key = f"{min(nick_a.lower(), nick_b.lower())}:{max(nick_a.lower(), nick_b.lower())}"
        return self._pairs.get(pair_key)

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 60:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(self._pairs, f, indent=2)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._pairs = data
        except Exception:
            pass


# =========================
# SentimentAICorrelator
# =========================

class SentimentAICorrelator:
    """Correlates sentiment scores with AI detection scores per nick and channel.

    Tracks:
      • Per-nick sentiment vs AI score distribution
      • Channel-level correlation (do AI messages cluster in specific sentiment ranges?)
      • Anomaly flags (nicks whose sentiment is unnaturally uniform given high AI scores)

    Provides /saicorr to inspect sentiment-AI correlation patterns.
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "sentiment_ai_corr.json")

    def __init__(self):
        self._nick_data: Dict[str, Dict] = {}
        self._channel_data: Dict[str, Dict] = {}
        self._last_save: float = 0.0
        self.load()

    def record(self, nick: str, channel: str, ai_score: float,
               sentiment: float, intensity: float = 0.0) -> None:
        nl = nick.lower()
        cl = channel.lower()
        entry = {
            "ai": ai_score, "sentiment": sentiment,
            "intensity": intensity, "ts": time.time(),
        }
        nd = self._nick_data.setdefault(nl, {"samples": [], "channel": cl})
        nd["samples"].append(entry)
        if len(nd["samples"]) > 200:
            nd["samples"] = nd["samples"][-200:]
        cd = self._channel_data.setdefault(cl, {"samples": []})
        cd["samples"].append(entry)
        if len(cd["samples"]) > 500:
            cd["samples"] = cd["samples"][-500:]
        self._maybe_save()

    def get_nick_correlation(self, nick: str) -> Dict:
        nl = nick.lower()
        nd = self._nick_data.get(nl, {})
        samples = nd.get("samples", [])
        if len(samples) < 3:
            return {"nick": nick, "samples": len(samples), "correlation": None,
                    "ai_sentiment_avg": None, "anomaly": False}
        ai_scores = [s["ai"] for s in samples]
        sent_scores = [s["sentiment"] for s in samples]
        high_ai = [s for s in samples if s["ai"] >= 60]
        low_ai = [s for s in samples if s["ai"] < 40]
        correlation = self._pearson_r(ai_scores, sent_scores)
        ai_sent_avg = (sum(s["sentiment"] for s in high_ai) / len(high_ai)) if high_ai else None
        human_sent_avg = (sum(s["sentiment"] for s in low_ai) / len(low_ai)) if low_ai else None
        sent_variance = self._variance(sent_scores)
        anomaly = len(high_ai) >= 3 and sent_variance < 0.02
        return {
            "nick": nick, "samples": len(samples),
            "correlation": round(correlation, 3) if correlation is not None else None,
            "ai_sentiment_avg": round(ai_sent_avg, 3) if ai_sent_avg is not None else None,
            "human_sentiment_avg": round(human_sent_avg, 3) if human_sent_avg is not None else None,
            "sentiment_variance": round(sent_variance, 4),
            "high_ai_count": len(high_ai),
            "anomaly": anomaly,
            "anomaly_reason": "uniform sentiment with high AI scores" if anomaly else "",
        }

    def get_channel_correlation(self, channel: str) -> Dict:
        cl = channel.lower()
        cd = self._channel_data.get(cl, {})
        samples = cd.get("samples", [])
        if len(samples) < 5:
            return {"channel": channel, "samples": len(samples), "correlation": None}
        ai_scores = [s["ai"] for s in samples]
        sent_scores = [s["sentiment"] for s in samples]
        high_ai = [s for s in samples if s["ai"] >= 60]
        low_ai = [s for s in samples if s["ai"] < 40]
        correlation = self._pearson_r(ai_scores, sent_scores)
        ai_sent_avg = (sum(s["sentiment"] for s in high_ai) / len(high_ai)) if high_ai else None
        human_sent_avg = (sum(s["sentiment"] for s in low_ai) / len(low_ai)) if low_ai else None
        ai_int_avg = (sum(s["intensity"] for s in high_ai) / len(high_ai)) if high_ai else None
        human_int_avg = (sum(s["intensity"] for s in low_ai) / len(low_ai)) if low_ai else None
        return {
            "channel": channel, "samples": len(samples),
            "correlation": round(correlation, 3) if correlation is not None else None,
            "ai_sentiment_avg": round(ai_sent_avg, 3) if ai_sent_avg is not None else None,
            "human_sentiment_avg": round(human_sent_avg, 3) if human_sent_avg is not None else None,
            "ai_intensity_avg": round(ai_int_avg, 3) if ai_int_avg is not None else None,
            "human_intensity_avg": round(human_int_avg, 3) if human_int_avg is not None else None,
            "high_ai_pct": round(len(high_ai) / len(samples) * 100, 1),
        }

    def get_top_anomalies(self, limit: int = 10) -> list:
        results = []
        for nick, data in self._nick_data.items():
            corr = self.get_nick_correlation(nick)
            if corr["anomaly"]:
                results.append(corr)
        results.sort(key=lambda x: -x.get("high_ai_count", 0))
        return results[:limit]

    @staticmethod
    def _pearson_r(xs: list, ys: list) -> Optional[float]:
        n = len(xs)
        if n < 3:
            return None
        mean_x = sum(xs) / n
        mean_y = sum(ys) / n
        cov = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
        var_x = sum((x - mean_x) ** 2 for x in xs)
        var_y = sum((y - mean_y) ** 2 for y in ys)
        denom = (var_x * var_y) ** 0.5
        if denom == 0:
            return None
        return cov / denom

    @staticmethod
    def _variance(xs: list) -> float:
        if not xs:
            return 0.0
        mean = sum(xs) / len(xs)
        return sum((x - mean) ** 2 for x in xs) / len(xs)

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump({"nicks": self._nick_data, "channels": self._channel_data}, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._nick_data = data.get("nicks", {})
            self._channel_data = data.get("channels", {})
        except Exception:
            pass


# =========================
# BehavioralBiometrics
# =========================

class BehavioralBiometrics:
    """Tracks user typing cadence, response latency, and keystroke dynamics.

    Monitors:
      • Key-to-key dwell times (typing rhythm)
      • Flight times (gap between key releases/presses)
      • Inter-message latency (time between receiving a message and replying)
      • Typing burst patterns (continuous typing vs pause-heavy)
      • Backspace/edit rate (self-correction frequency)
      • Message composition time (from first keystroke to Enter)

    Provides a per-session biometric profile that can be correlated with
    AI detection scores — humans exhibit variable, idiosyncratic typing
    patterns while bots/AI tend to have uniform timing or instant responses.
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "biometrics.json")

    def __init__(self):
        self._key_dwell_times: deque = deque(maxlen=500)
        self._flight_times: deque = deque(maxlen=500)
        self._composition_times: deque = deque(maxlen=200)
        self._response_latencies: deque = deque(maxlen=200)
        self._backspace_count: int = 0
        self._total_keystrokes: int = 0
        self._current_composition_start: float = 0.0
        self._last_key_time: float = 0.0
        self._last_incoming_msg_time: float = 0.0
        self._typing_bursts: deque = deque(maxlen=100)
        self._current_burst_start: float = 0.0
        self._current_burst_keys: int = 0
        self._burst_threshold: float = 0.5
        self._session_start: float = time.time()
        self._messages_sent: int = 0
        self._messages_edited: int = 0
        self.load()

    def record_keypress(self, is_backspace: bool = False) -> None:
        now = time.monotonic()
        self._total_keystrokes += 1
        if is_backspace:
            self._backspace_count += 1
            self._messages_edited += 1
        if self._last_key_time > 0:
            flight = now - self._last_key_time
            if flight < 2.0:
                self._flight_times.append(flight)
                if flight < self._burst_threshold:
                    if self._current_burst_start == 0:
                        self._current_burst_start = now
                        self._current_burst_keys = 0
                    self._current_burst_keys += 1
                else:
                    if self._current_burst_start > 0:
                        duration = now - self._current_burst_start
                        self._typing_bursts.append({
                            "duration": duration,
                            "keys": self._current_burst_keys,
                            "rate": self._current_burst_keys / duration if duration > 0 else 0,
                        })
                        self._current_burst_start = 0
                        self._current_burst_keys = 0
        self._last_key_time = now
        if self._current_composition_start == 0:
            self._current_composition_start = now

    def record_composition_complete(self) -> float:
        if self._current_composition_start > 0:
            comp_time = time.monotonic() - self._current_composition_start
            self._composition_times.append(comp_time)
            self._current_composition_start = 0
            self._messages_sent += 1
            if self._current_burst_start > 0:
                now = time.monotonic()
                duration = now - self._current_burst_start
                self._typing_bursts.append({
                    "duration": duration,
                    "keys": self._current_burst_keys,
                    "rate": self._current_burst_keys / duration if duration > 0 else 0,
                })
                self._current_burst_start = 0
                self._current_burst_keys = 0
            return comp_time
        return 0.0

    def record_incoming_message(self) -> None:
        self._last_incoming_msg_time = time.monotonic()

    def record_response(self) -> None:
        if self._last_incoming_msg_time > 0:
            latency = time.monotonic() - self._last_incoming_msg_time
            if latency < 300:
                self._response_latencies.append(latency)

    def get_typing_cadence_stats(self) -> Dict[str, float]:
        if len(self._flight_times) < 5:
            return {"mean": 0, "std": 0, "median": 0, "p10": 0, "p90": 0, "samples": 0}
        sorted_ft = sorted(self._flight_times)
        mean = sum(sorted_ft) / len(sorted_ft)
        std = (sum((x - mean) ** 2 for x in sorted_ft) / len(sorted_ft)) ** 0.5
        median = sorted_ft[len(sorted_ft) // 2]
        p10 = sorted_ft[max(0, int(len(sorted_ft) * 0.1))]
        p90 = sorted_ft[min(len(sorted_ft) - 1, int(len(sorted_ft) * 0.9))]
        return {
            "mean": round(mean * 1000, 1),
            "std": round(std * 1000, 1),
            "median": round(median * 1000, 1),
            "p10": round(p10 * 1000, 1),
            "p90": round(p90 * 1000, 1),
            "samples": len(sorted_ft),
        }

    def get_composition_stats(self) -> Dict[str, float]:
        if not self._composition_times:
            return {"mean": 0, "std": 0, "median": 0, "min": 0, "max": 0, "samples": 0}
        sorted_ct = sorted(self._composition_times)
        mean = sum(sorted_ct) / len(sorted_ct)
        std = (sum((x - mean) ** 2 for x in sorted_ct) / len(sorted_ct)) ** 0.5
        return {
            "mean": round(mean, 2),
            "std": round(std, 2),
            "median": round(sorted_ct[len(sorted_ct) // 2], 2),
            "min": round(sorted_ct[0], 2),
            "max": round(sorted_ct[-1], 2),
            "samples": len(sorted_ct),
        }

    def get_response_latency_stats(self) -> Dict[str, float]:
        if not self._response_latencies:
            return {"mean": 0, "std": 0, "median": 0, "min": 0, "max": 0, "samples": 0}
        sorted_rl = sorted(self._response_latencies)
        mean = sum(sorted_rl) / len(sorted_rl)
        std = (sum((x - mean) ** 2 for x in sorted_rl) / len(sorted_rl)) ** 0.5
        return {
            "mean": round(mean, 2),
            "std": round(std, 2),
            "median": round(sorted_rl[len(sorted_rl) // 2], 2),
            "min": round(sorted_rl[0], 2),
            "max": round(sorted_rl[-1], 2),
            "samples": len(sorted_rl),
        }

    def get_backspace_ratio(self) -> float:
        if self._total_keystrokes == 0:
            return 0.0
        return round(self._backspace_count / self._total_keystrokes, 4)

    def get_burst_stats(self) -> Dict[str, float]:
        if not self._typing_bursts:
            return {"avg_duration": 0, "avg_rate": 0, "avg_keys": 0, "count": 0}
        durations = [b["duration"] for b in self._typing_bursts]
        rates = [b["rate"] for b in self._typing_bursts]
        keys = [b["keys"] for b in self._typing_bursts]
        return {
            "avg_duration": round(sum(durations) / len(durations), 2),
            "avg_rate": round(sum(rates) / len(rates), 1),
            "avg_keys": round(sum(keys) / len(keys), 1),
            "count": len(self._typing_bursts),
        }

    def get_human_likelihood(self) -> float:
        score = 50.0
        comp = self.get_composition_stats()
        if comp["samples"] > 0:
            if comp["std"] > 0.5:
                score += 10
            if comp["mean"] > 1.0:
                score += 5
        resp = self.get_response_latency_stats()
        if resp["samples"] > 0:
            if resp["std"] > 1.0:
                score += 10
            if resp["mean"] > 2.0:
                score += 5
        bs_ratio = self.get_backspace_ratio()
        if bs_ratio > 0.02:
            score += 10
        elif bs_ratio > 0.005:
            score += 5
        cadence = self.get_typing_cadence_stats()
        if cadence["std"] > 20:
            score += 10
        bursts = self.get_burst_stats()
        if bursts["count"] > 5:
            rate_var = bursts["avg_rate"]
            if 2 < rate_var < 15:
                score += 5
        return min(100.0, max(0.0, score))

    def _save(self) -> None:
        try:
            data = {
                "session_start": self._session_start,
                "messages_sent": self._messages_sent,
                "backspace_count": self._backspace_count,
                "total_keystrokes": self._total_keystrokes,
                "flight_times": list(self._flight_times)[-100:],
                "composition_times": list(self._composition_times)[-50:],
                "response_latencies": list(self._response_latencies)[-50:],
                "typing_bursts": list(self._typing_bursts)[-30:],
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._session_start = data.get("session_start", time.time())
            self._messages_sent = data.get("messages_sent", 0)
            self._backspace_count = data.get("backspace_count", 0)
            self._total_keystrokes = data.get("total_keystrokes", 0)
            for ft in data.get("flight_times", [])[-100:]:
                self._flight_times.append(ft)
            for ct in data.get("composition_times", [])[-50:]:
                self._composition_times.append(ct)
            for rl in data.get("response_latencies", [])[-50:]:
                self._response_latencies.append(rl)
            for tb in data.get("typing_bursts", [])[-30:]:
                self._typing_bursts.append(tb)
        except Exception:
            pass



# IRC Formatting
# =========================
# Control codes used by IRC for inline text formatting.
_IRC_FMT_RE = re.compile(
    r'\x03(?:\d{1,2}(?:,\d{1,2})?)?'   # \x03[fg][,bg]  colour
    r'|[\x02\x0F\x16\x1D\x1F\x1E]'      # bold / reset / reverse / italic / underline / strikethrough
)

# Module-level parse cache: most IRC lines repeat across redraws
_FMT_PARSE_CACHE: OrderedDict = OrderedDict()
_FMT_CACHE_MAX = 512

def irc_strip_formatting(text: str) -> str:
    """Remove all IRC formatting codes, returning plain text."""
    return _IRC_FMT_RE.sub("", text)

# =========================
# Wide-character helpers
# =========================
# CJK and other "wide" Unicode characters occupy 2 terminal columns each.
# Python's len() and f-string alignment know nothing about this, so every
# column calculation must go through these helpers instead.

# Unicode zero-width / presentation constants
_ZWJ  = '‍'   # ZERO WIDTH JOINER
_VS15 = '︎'   # VARIATION SELECTOR-15 (text presentation)
_VS16 = '️'   # VARIATION SELECTOR-16 (emoji presentation)

def _char_width(ch: str) -> int:
    """Terminal display width of a single Unicode scalar value.

    Returns 0 for combining marks, enclosing marks, and Unicode format
    characters (categories Mn/Mc/Me/Cf — includes ZWJ U+200D and variation
    selectors U+FE0E/U+FE0F).  Returns 2 for wide/fullwidth East-Asian
    characters and for symbol/pictographic emoji in the SMP that Python's
    unicodedata may classify as EAW 'N' (e.g. U+1F3F3 WHITE FLAG).
    Returns 1 for everything else.

    Call _next_cluster() when iterating over strings so that ZWJ sequences
    are counted as one glyph instead of summing each component's width.
    """
    cat = unicodedata.category(ch)
    if cat in ('Mn', 'Mc', 'Me', 'Cf'):
        return 0
    eaw = unicodedata.east_asian_width(ch)
    if eaw in ('W', 'F'):
        return 2
    # Some Symbol/Other code points in the emoji blocks are not classified 'W'
    # by Python's unicodedata even though modern terminals display them as 2-wide.
    # Cover the Supplementary Multilingual Plane emoji ranges explicitly.
    if cat == 'So':
        cp = ord(ch)
        if 0x1F000 <= cp <= 0x1FAFF:   # Mahjong … Symbols & Pictographs Extended-A
            return 2
    return 1

def _next_cluster(s: str, i: int) -> tuple:
    """Consume one grapheme cluster from *s* starting at index *i*.

    Returns (new_index, visual_width).  Handles:
      • ZWJ sequences (multi-person emoji, flag sequences like 🏳️‍🌈)
      • Regional Indicator pairs (🇺🇸 = U+1F1FA U+1F1F8) — two adjacent RIs
        form one flag glyph; only the base character's width is counted
      • VS15 / VS16 variation selectors
      • Unicode combining / enclosing / format characters (Mn, Mc, Me, Cf)

    The cluster's visual width equals that of its base character; all absorbed
    code points contribute zero additional columns.
    """
    n    = len(s)
    base = s[i]
    w    = _char_width(base)
    i   += 1

    # Regional Indicator pair → single emoji flag (🇺🇸, 🇬🇧, …).
    # Two adjacent RIs together form one glyph; absorb the second RI.
    if 0x1F1E0 <= ord(base) <= 0x1F1FF:
        if i < n and 0x1F1E0 <= ord(s[i]) <= 0x1F1FF:
            i += 1
        return i, w   # flag clusters carry no further modifiers

    while i < n:
        nc  = s[i]
        cat = unicodedata.category(nc)
        if nc == _ZWJ:
            i += 1                          # absorb ZWJ itself
            if i < n and unicodedata.category(s[i]) not in ('Mn', 'Mc', 'Me', 'Cf'):
                i += 1                      # absorb the next base glyph
            while i < n and s[i] in (_VS16, _VS15):
                i += 1                      # absorb any trailing VS on that glyph
        elif nc in (_VS16, _VS15):
            i += 1
        elif cat in ('Mn', 'Mc', 'Me', 'Cf'):
            i += 1
        else:
            break
    return i, w

def _str_visual_width(s: str) -> int:
    """Total terminal column width of *s*.

    Wide/fullwidth East-Asian chars count as 2 columns.  ZWJ sequences,
    variation selectors, and combining marks are folded into their base
    glyph and contribute no extra columns.
    """
    total = 0
    i     = 0
    n     = len(s)
    while i < n:
        i, w  = _next_cluster(s, i)
        total += w
    return total

def _truncate_to_width(s: str, max_cols: int) -> str:
    """Return the longest prefix of *s* that fits within *max_cols* terminal columns.

    Never splits a grapheme cluster (ZWJ sequence, combining mark, etc.).
    """
    cols = 0
    i    = 0
    n    = len(s)
    while i < n:
        start    = i
        i, cw    = _next_cluster(s, i)
        if cols + cw > max_cols:
            return s[:start]
        cols += cw
    return s

def _skip_visual_cols(s: str, skip: int) -> str:
    """Return the substring of *s* that starts at visual column *skip*.

    Advances by grapheme cluster so ZWJ sequences are never split.
    """
    if skip <= 0:
        return s
    col = 0
    i   = 0
    n   = len(s)
    while i < n:
        start    = i
        i, cw    = _next_cluster(s, i)
        if col >= skip:
            return s[start:]
        col += cw
    return ""

def _irc_visual_pos(line: str, max_visual: int) -> int:
    """Return the raw-string index at which the visual column count reaches *max_visual*.

    IRC control codes are zero-width.  Non-control characters are advanced
    by grapheme cluster so that ZWJ sequences count as a single display cell.
    """
    vis = 0
    i   = 0
    n   = len(line)
    while i < n and vis < max_visual:
        ch = line[i]
        if ch in ("\x02", "\x1D", "\x1F", "\x16", "\x0F"):
            i += 1
        elif ch == "\x03":
            i += 1
            for _ in range(2):          # up to 2 fg digits
                if i < n and line[i].isdigit(): i += 1
                else: break
            if i < n and line[i] == ",":
                i += 1
                for _ in range(2):      # up to 2 bg digits
                    if i < n and line[i].isdigit(): i += 1
                    else: break
        else:
            ni, cw = _next_cluster(line, i)
            if vis + cw > max_visual:
                break                   # cluster would overflow — stop before it
            vis += cw
            i    = ni
    return i

# =========================
# CJK detection + translation
# =========================

def _is_cjk_char(cp: int) -> bool:
    """Return True if Unicode codepoint *cp* belongs to a CJK/East-Asian script block.

    Covers (Unicode 15.1):
      Hiragana, Katakana, Katakana Phonetic Extensions, Bopomofo (+Extended),
      Hangul Syllables, Hangul Jamo Extended A/B, CJK Symbols & Punctuation,
      CJK Radicals Supplement, Kangxi Radicals, Kanbun, CJK Strokes,
      Enclosed CJK Letters and Months, CJK Compatibility,
      CJK Unified Ideographs (main), CJK Compatibility Ideographs (+Supplement),
      CJK Compatibility Forms, CJK Extensions A–G.

    Integer range comparisons are faster than a compiled regex for the typical
    short IRC message (< 512 bytes) because there is no per-character regex
    engine dispatch overhead.
    """
    return (
        0x2E80 <= cp <= 0x2EFF or   # CJK Radicals Supplement
        0x2F00 <= cp <= 0x2FDF or   # Kangxi Radicals
        0x3000 <= cp <= 0x303F or   # CJK Symbols and Punctuation
        0x3040 <= cp <= 0x30FF or   # Hiragana + Katakana
        0x3100 <= cp <= 0x312F or   # Bopomofo
        0x3190 <= cp <= 0x319F or   # Kanbun
        0x31A0 <= cp <= 0x31BF or   # Bopomofo Extended
        0x31C0 <= cp <= 0x31EF or   # CJK Strokes
        0x31F0 <= cp <= 0x31FF or   # Katakana Phonetic Extensions
        0x3200 <= cp <= 0x32FF or   # Enclosed CJK Letters and Months
        0x3300 <= cp <= 0x33FF or   # CJK Compatibility
        0x3400 <= cp <= 0x4DBF or   # CJK Extension A
        0x4E00 <= cp <= 0x9FFF or   # CJK Unified Ideographs
        0xA960 <= cp <= 0xA97F or   # Hangul Jamo Extended-A
        0xAC00 <= cp <= 0xD7AF or   # Hangul Syllables (Korean)
        0xD7B0 <= cp <= 0xD7FF or   # Hangul Jamo Extended-B
        0xF900 <= cp <= 0xFAFF or   # CJK Compatibility Ideographs
        0xFE30 <= cp <= 0xFE4F or   # CJK Compatibility Forms
        0x20000 <= cp <= 0x2A6DF or # CJK Extension B
        0x2A700 <= cp <= 0x2B73F or # CJK Extension C
        0x2B740 <= cp <= 0x2B81F or # CJK Extension D
        0x2B820 <= cp <= 0x2CEAF or # CJK Extension E
        0x2CEB0 <= cp <= 0x2EBEF or # CJK Extension F
        0x2F800 <= cp <= 0x2FA1F or # CJK Compatibility Supplement
        0x30000 <= cp <= 0x3134F    # CJK Extension G (Unicode 13+)
    )


def _has_cjk(text: str, threshold: int = 2) -> bool:
    """Return True if *text* contains at least *threshold* CJK/East-Asian characters.
    Exits as soon as the threshold is met — O(threshold) in the common case."""
    count = 0
    for ch in text:
        if _is_cjk_char(ord(ch)):
            count += 1
            if count >= threshold:
                return True
    return False


# ── Dedicated thread-pool executors ──────────────────────────────────────────
# Two separate pools prevent ML inference and blocking HTTP calls from
# competing for the same threads and stalling each other during AI commands.
#   _ML_EXECUTOR  — transformer model inference (predict_detailed); kept small
#                   (2 workers) because each call is CPU-heavy and loading more
#                   just causes context-switching thrash.
#   _IO_EXECUTOR  — blocking HTTP calls (ollama, llama.cpp, translation); wider
#                   (4 workers) because calls block on network I/O, not CPU.
_ML_EXECUTOR = _ThreadPoolExecutor(max_workers=2, thread_name_prefix="eyrc-ml")
_IO_EXECUTOR = _ThreadPoolExecutor(max_workers=4, thread_name_prefix="eyrc-io")

# Semaphore created lazily in the async context.
_ML_SEM: Optional[asyncio.Semaphore] = None

# Cached classify clients (module-level so they survive across calls).
_classify_ac: Optional[object] = None
_classify_oc: Optional[object] = None

# ── Translation cache + concurrency control ───────────────────────────────────
# Cache: plain_text → Optional[str].  A cached None means "already English" or
# "previously failed" — we don't retry until the process restarts.
_TRANSLATION_CACHE: OrderedDict = OrderedDict()
_TRANSLATION_CACHE_MAX = 256
_CACHE_MISS = object()                        # sentinel: key absent from cache
_TRANSLATION_SEM: Optional[asyncio.Semaphore] = None   # created lazily in async context

# ── Link title / unfurl cache + concurrency ──────────────────────────────────
_LINK_CACHE: OrderedDict = OrderedDict()
_LINK_CACHE_MAX = 256
_LINK_SEM: Optional[asyncio.Semaphore] = None
_IMAGE_EXT_RE = re.compile(r'\.(jpe?g|png|gif|webp|bmp|avif|svg)(?:\?.*)?$', re.IGNORECASE)
# Domains commonly flagged for spam, tracking, or shorteners
_SPAM_DOMAINS = frozenset({
    "bit.ly", "tinyurl.com", "tiny.cc", "ow.ly", "is.gd", "buff.ly",
    "goo.gl", "shorturl.at", "rb.gy", "t.co", "adf.ly", "shorte.st",
    "bc.vc", "linktr.ee", "tr.ee", "cutt.ly", "rebrand.ly",
    "tracking." "doubleclick.net", "adservice.google.com",
    "click.googleadservices.com", "outbrain.com", "taboola.com",
})


# ── x0.at upload support ──────────────────────────────────────────────────
try:
    from PIL import Image as _PILImage
    PIL_AVAILABLE = True
except ImportError:
    _PILImage = None
    PIL_AVAILABLE = False

_IMAGE_EXTENSIONS = frozenset({".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".avif"})

def _compress_image(filepath: str, max_size: int = 1920, quality: int = 85) -> Optional[bytes]:
    """Compress an image file. Returns compressed JPEG bytes or None on failure."""
    if not PIL_AVAILABLE:
        return None
    try:
        img = _PILImage.open(filepath)
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGB")
        w, h = img.size
        if w > max_size or h > max_size:
            ratio = min(max_size / w, max_size / h)
            img = img.resize((int(w * ratio), int(h * ratio)), _PILImage.LANCZOS)
        buf = io.BytesIO()
        img.save(buf, format="JPEG", quality=quality, optimize=True)
        return buf.getvalue()
    except Exception:
        return None

def _upload_to_x0(filepath: str) -> Optional[str]:
    """Upload a file to x0.at. Returns the URL or None on failure."""
    try:
        compressed = _compress_image(filepath)
        data: bytes
        if compressed is not None:
            data = compressed
        else:
            with open(filepath, "rb") as f:
                data = f.read()
        boundary = uuid.uuid4().hex
        body = (
            b"--" + boundary.encode() + b"\r\n"
            b'Content-Disposition: form-data; name="file"; filename="image.jpg"\r\n'
            b"Content-Type: application/octet-stream\r\n\r\n"
            + data +
            b"\r\n--" + boundary.encode() + b"--\r\n"
        )
        req = urllib.request.Request(
            "https://x0.at/",
            data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            url = resp.read().decode("utf-8").strip()
            return url if url else None
    except Exception:
        return None


def _parse_server_time(ts: str) -> str:
    """Convert IRCv3 server-time tag value (ISO 8601 UTC) to local [HH:MM] string."""
    try:
        from datetime import datetime, timezone
        s = ts.rstrip("Z")
        fmt = "%Y-%m-%dT%H:%M:%S.%f" if "." in s else "%Y-%m-%dT%H:%M:%S"
        dt = datetime.strptime(s, fmt).replace(tzinfo=timezone.utc).astimezone(tz=None)
        return dt.strftime("[%H:%M]")
    except Exception:
        return time.strftime("[%H:%M]")


async def _translate_to_english(text: str) -> Optional[str]:
    """Translate *text* to English via Google Translate's free public endpoint.

    Improvements over naïve implementation:
    • IRC formatting codes are stripped before sending to the API.
    • The detected source-language field in the response is checked; text already
      in English is rejected without a string comparison.
    • Results are cached in an LRU OrderedDict (256 entries) — repeated phrases
      (greetings, bot announcements) are served from memory with no network round-trip.
    • A per-process asyncio.Semaphore caps concurrent HTTP calls at 3 to avoid
      flooding the endpoint when many CJK messages arrive at once.
    • Returns None on any failure; callers treat None as "do not display".
    """
    global _TRANSLATION_SEM
    if _TRANSLATION_SEM is None:
        _TRANSLATION_SEM = asyncio.Semaphore(3)

    # Strip IRC formatting codes — they confuse the translation model and add noise
    plain = irc_strip_formatting(text).strip()
    if not plain:
        return None

    # Fast path: cache hit
    cached = _TRANSLATION_CACHE.get(plain, _CACHE_MISS)
    if cached is not _CACHE_MISS:
        _TRANSLATION_CACHE.move_to_end(plain)  # LRU refresh
        return cached  # type: ignore[return-value]  # may be None

    try:
        url = (
            "https://translate.googleapis.com/translate_a/single"
            "?client=gtx&sl=auto&tl=en&dt=t&q=" + urllib.parse.quote(plain)
        )
        loop = asyncio.get_running_loop()
        async with _TRANSLATION_SEM:
            raw = await loop.run_in_executor(
                _IO_EXECUTOR, lambda: urllib.request.urlopen(url, timeout=6).read()
            )
        data = json.loads(raw)

        # data[2] = detected source language code (e.g. "zh-CN", "ja", "en")
        detected_lang = data[2] if len(data) > 2 and isinstance(data[2], str) else ""
        if detected_lang.startswith("en"):
            result: Optional[str] = None  # already English — nothing to show
        else:
            segs = data[0]
            result = "".join(seg[0] for seg in segs if seg and seg[0]) or None

    except Exception:
        result = None

    # Write to cache (evict LRU entry if at capacity)
    if len(_TRANSLATION_CACHE) >= _TRANSLATION_CACHE_MAX:
        _TRANSLATION_CACHE.popitem(last=False)
    _TRANSLATION_CACHE[plain] = result
    return result

def _fetch_page_title_blocking(url: str) -> Optional[str]:
    """Synchronously fetch a URL and extract its <title> tag.
    Returns None on any error or if no <title> is found."""
    try:
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (compatible; eyearesee/1.0)",
            "Accept": "text/html,application/xhtml+xml",
        })
        with urllib.request.urlopen(req, timeout=8) as resp:
            raw = resp.read(131072)  # 128 KB max — stop reading malicious payloads
        # Quick encoding sniff via Content-Type or BOM
        content_type = resp.headers.get("Content-Type", "")
        enc = "utf-8"
        if "charset=" in content_type:
            enc = content_type.split("charset=")[-1].split(";")[0].strip()
        text = raw.decode(enc, errors="replace")
        m = re.search(r'<title[^>]*>([^<]+)</title>', text, re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(1).strip()[:200]
    except Exception:
        pass
    return None


def _fetch_image_info_blocking(url: str) -> Optional[str]:
    """Synchronously HEAD an image URL and return dimensions + size.
    Returns None on error or non-image content type."""
    try:
        req = urllib.request.Request(url, method="HEAD", headers={
            "User-Agent": "Mozilla/5.0 (compatible; eyearesee/1.0)",
        })
        with urllib.request.urlopen(req, timeout=6) as resp:
            ct = resp.headers.get("Content-Type", "")
            if not ct.startswith("image/"):
                return None
            cl = resp.headers.get("Content-Length")
            size_str = ""
            if cl and cl.isdigit():
                kb = int(cl) / 1024
                if kb >= 1024:
                    size_str = f"  ({kb / 1024:.1f} MB)"
                else:
                    size_str = f"  ({kb:.0f} KB)"
            return f"[image{size_str}]"
    except Exception:
        return None


def _check_domain_reputation(url: str) -> Optional[str]:
    """Return a warning string if the domain is a known spam/tracking/shortener."""
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        if domain.startswith("www."):
            domain = domain[4:]
        for spam in _SPAM_DOMAINS:
            if domain == spam or domain.endswith("." + spam):
                return f"\u26a0 {domain}"
    except Exception:
        pass
    return None


async def _fetch_link_info(url: str) -> Dict[str, Optional[str]]:
    """Fetch metadata for a URL: title, image info, and domain warning.

    Returns dict with keys: title, image, domain_warn.
    Results are LRU-cached (256 entries).
    """
    global _LINK_SEM
    if _LINK_SEM is None:
        _LINK_SEM = asyncio.Semaphore(4)

    cached = _LINK_CACHE.get(url)
    if cached is not None:
        _LINK_CACHE.move_to_end(url)
        return cached

    domain_warn = _check_domain_reputation(url)
    is_image = bool(_IMAGE_EXT_RE.search(url))

    loop = asyncio.get_running_loop()
    async with _LINK_SEM:
        if is_image:
            title_task = loop.run_in_executor(_IO_EXECUTOR, _fetch_image_info_blocking, url)
            image_task = title_task
            title_result: Optional[str] = await title_task
            image_result: Optional[str] = title_result
        else:
            title_task = loop.run_in_executor(_IO_EXECUTOR, _fetch_page_title_blocking, url)
            image_task = loop.run_in_executor(_IO_EXECUTOR, _fetch_image_info_blocking, url)
            title_result = await title_task
            image_result = await image_task

    result: Dict[str, Optional[str]] = {
        "title": title_result if not is_image else None,
        "image": image_result if is_image else image_result,
        "domain_warn": domain_warn,
    }
    if len(_LINK_CACHE) >= _LINK_CACHE_MAX:
        _LINK_CACHE.popitem(last=False)
    _LINK_CACHE[url] = result
    return result


def _link_log_path(window_name: str) -> str:
    safe = _UNSAFE_FILENAME_RE.sub("_", window_name) or "_"
    safe = re.sub(r'\.{2,}', '_', safe) or "_"
    return os.path.join(LINK_LOG_DIR, safe + "_links.jsonl")


def _append_link_log(window_name: str, nick: str, url: str, title: str, domain: str) -> None:
    try:
        os.makedirs(LINK_LOG_DIR, exist_ok=True)
        entry = json.dumps({
            "ts": time.time(),
            "dt": time.strftime("%Y-%m-%d %H:%M:%S"),
            "nick": nick,
            "url": url,
            "title": title,
            "domain": domain,
        }, ensure_ascii=False)
        with open(_link_log_path(window_name), "a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception:
        pass


def _load_link_history(window_name: str, limit: int = 100) -> List[dict]:
    path = _link_log_path(window_name)
    entries: List[dict] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    entries.append(json.loads(raw))
                except (json.JSONDecodeError, ValueError):
                    pass
    except FileNotFoundError:
        pass
    except Exception:
        pass
    return entries[-limit:]


def irc_parse_formatting(text: str) -> List[Tuple[str, int]]:
    """Split *text* into (segment, curses_attr) pairs honouring IRC codes.

    Supports: \x02 bold, \x1D italic, \x1F underline, \x0F reset,
    \x16 reverse, \x1E strikethrough, \x03 colour
    (colour is stripped; only bold/italic/underline/reverse/strikethrough
    are mapped to curses attributes).

    Results are cached (up to 512 entries) since the same wrapped line is
    rendered on every frame until the window is scrolled or text changes.
    """
    cached = _FMT_PARSE_CACHE.get(text)
    if cached is not None:
        return cached

    segments: List[Tuple[str, int]] = []
    bold = italic = underline = reverse = strikethrough = False
    buf: List[str] = []
    i = 0

    def _flush():
        if buf:
            segments.append(("".join(buf), _irc_attr(bold, italic, underline, reverse, strikethrough)))
            buf.clear()

    while i < len(text):
        ch = text[i]
        if ch == "\x02":          # bold toggle
            _flush(); bold = not bold; i += 1
        elif ch == "\x1D":        # italic toggle
            _flush(); italic = not italic; i += 1
        elif ch == "\x1F":        # underline toggle
            _flush(); underline = not underline; i += 1
        elif ch == "\x16":        # reverse toggle
            _flush(); reverse = not reverse; i += 1
        elif ch == "\x1E":        # strikethrough toggle (draft/format)
            _flush(); strikethrough = not strikethrough; i += 1
        elif ch == "\x0F":        # reset all
            _flush(); bold = italic = underline = reverse = strikethrough = False; i += 1
        elif ch == "\x03":        # colour code — advance past digits, map nothing
            _flush()
            i += 1
            for _ in range(2):
                if i < len(text) and text[i].isdigit(): i += 1
                else: break
            if i < len(text) and text[i] == ",":
                i += 1
                for _ in range(2):
                    if i < len(text) and text[i].isdigit(): i += 1
                    else: break
        else:
            buf.append(ch); i += 1

    _flush()
    result = segments or [("", curses.A_NORMAL)]
    if len(_FMT_PARSE_CACHE) >= _FMT_CACHE_MAX:
        _FMT_PARSE_CACHE.popitem(last=False)
    _FMT_PARSE_CACHE[text] = result
    return result


def _irc_attr(bold: bool, italic: bool, underline: bool, reverse: bool,
              strikethrough: bool = False) -> int:
    attr = curses.A_NORMAL
    if bold:      attr |= curses.A_BOLD
    if underline: attr |= curses.A_UNDERLINE
    if reverse:   attr |= curses.A_REVERSE
    if italic:
        try:    attr |= curses.A_ITALIC
        except AttributeError: attr |= curses.A_DIM
    if strikethrough:
        try:    attr |= curses.A_STANDOUT  # closest curses has to strikethrough
        except AttributeError: attr |= curses.A_DIM
    return attr

# =========================
# AI Log  (JSONL format)
# =========================
# One JSON object per line.  Fields that are always present:
#   ts      – float unix timestamp (authoritative for sorting)
#   dt      – human-readable "YYYY-MM-DD HH:MM:SS"
#   sess    – 8-char session UUID (unique per process start)
#   seq     – monotone int per session; gaps indicate missing/injected lines
#   nick    – IRC nick
#   target  – channel or nick
#   u/m/a   – user / message / AI score  (0-100)
#   roll    – rolling AI score
#   msg     – the raw message text  (JSON encoding handles all escaping)
#
# Session-start records have type="session_start" and no nick/msg fields.
# Legacy tab-separated lines (from older versions) are silently skipped by
# load_nick_history() so old logs remain readable.

_LOG_SESSION_ID: str = uuid.uuid4().hex[:8]
_log_seq: int = 0

# ── Persistent write handles — kept open between calls so the OS page cache
#    does the batching instead of paying an open()/close() syscall per line.
#    buffering=8192 → up to ~8 KB accumulated before a real disk write.
#    Input history uses buffering=1 (line-buffered) for crash-safety.
_ai_log_handle:     Optional[io.TextIOWrapper] = None
_chat_log_handles:  Dict[str, io.TextIOWrapper] = {}
_input_hist_handle: Optional[io.TextIOWrapper] = None

def _open_append(path: str, buffering: int = 8192) -> io.TextIOWrapper:
    return open(path, "a", encoding="utf-8", buffering=buffering)  # type: ignore[return-value]


@atexit.register
def _flush_log_handles() -> None:
    """Ensure all buffered log data is written when the process exits."""
    for h in [_ai_log_handle, _input_hist_handle, *_chat_log_handles.values()]:
        if h and not h.closed:
            try:
                h.flush()
                h.close()
            except Exception:
                pass


def _ai_log_write(payload: str) -> None:
    """Append *payload* to ai_scores.log.

    Uses line-buffered mode (buffering=1) so every record lands on disk as
    soon as the terminating newline is written — no explicit flush() needed.
    On any I/O error the handle is discarded so the next call attempts a
    fresh open instead of retrying against a broken handle forever."""
    global _ai_log_handle
    try:
        if _ai_log_handle is None or _ai_log_handle.closed:
            _ai_log_handle = _open_append(AI_LOG_PATH, buffering=1)
        _ai_log_handle.write(payload)
    except Exception:
        _ai_log_handle = None  # force reopen next call; don't retry a broken handle


def log_session_start(server: str, nick: str) -> None:
    if not _ai_logging_enabled:
        return
    entry = {
        "type":   "session_start",
        "ts":     time.time(),
        "dt":     time.strftime("%Y-%m-%d %H:%M:%S"),
        "sess":   _LOG_SESSION_ID,
        "server": server,
        "nick":   nick,
    }
    _ai_log_write(json.dumps(entry, ensure_ascii=False) + "\n")


def log_ai_event(nick: str, target: str, msg: str,
                 u_score: int, m_score: int, a_score: int, rolling_ai: int,
                 heu_score: float = 0.0,
                 bino_score: float = 0.0,
                 cls_score: float = 0.0,
                 llama_score: float = 0.0,
                 adv_score: float = 0.0,
                 embed_score: float = 0.0,
                 watermark_score_val: float = 0.0,
                 styl_score: float = 0.0) -> None:
    """Write one JSONL detection record to ai_scores.log.

    Every record contains the full signal breakdown so any line can be
    independently analysed without referencing session state:

      ts / dt   – unix timestamp + human-readable datetime
      sess      – 8-char session UUID (unique per process start)
      seq       – monotone per-session counter; gaps indicate missing lines
      nick      – IRC nickname
      target    – channel or DM nick the message was sent to
      u         – user-history score (0-99, based on message count)
      m         – message-level score (reserved, currently 50)
      a         – ensemble AI score 0-100
      roll      – rolling per-nick AI average (last USER_HISTORY_WINDOW msgs)
      flag      – "suspect" if a >= AI_SUSPECT_THRESHOLD else "normal"
      msg_len   – byte length of the raw message
      heu       – combined heuristic sub-score (formality + Llama patterns)
      bino      – Binoculars cross-entropy ratio sub-score
      cls       – averaged classifier probability (ChatGPT-RoBERTa + general)
      llama     – Llama-specific structural/phrasing pattern sub-score
      adv       – adversarial-evasion sub-score (char n-gram entropy + spacing)
      embed     – embedding-variance sub-score (0 when no history)
      wm        – watermark-detection sub-score
      styl      – stylometric sub-score (burstiness + lexical diversity + punctuation)
      msg       – raw message text (JSON-escaped)
    """
    if not _ai_logging_enabled:
        return
    # Clamp every numeric field to its documented range so out-of-range values
    # from upstream bugs or floating-point edge cases never corrupt the log.
    a_score     = max(0,   min(100, int(a_score)))
    rolling_ai  = max(0,   min(100, int(rolling_ai)))
    u_score     = max(0,   min(99,  int(u_score)))
    m_score     = max(0,   min(100, int(m_score)))
    heu_score   = max(0.0, min(1.0, float(heu_score)))
    bino_score  = max(0.0, min(1.0, float(bino_score)))
    cls_score   = max(0.0, min(1.0, float(cls_score)))
    llama_score = max(0.0, min(1.0, float(llama_score)))
    adv_score   = max(0.0, min(1.0, float(adv_score)))
    embed_score = max(0.0, min(1.0, float(embed_score)))
    watermark_score_val = max(0.0, min(1.0, float(watermark_score_val)))
    styl_score  = max(0.0, min(1.0, float(styl_score)))
    # Cap the stored message at the IRC protocol line length to bound record size.
    msg_logged  = msg[:512]
    global _log_seq
    _log_seq += 1
    entry: dict = {
        "ts":      time.time(),
        "dt":      time.strftime("%Y-%m-%d %H:%M:%S"),
        "sess":    _LOG_SESSION_ID,
        "seq":     _log_seq,
        "nick":    nick,
        "target":  target,
        "u":       u_score,
        "m":       m_score,
        "a":       a_score,
        "roll":    rolling_ai,
        "flag":    "suspect" if a_score >= AI_SUSPECT_THRESHOLD else "normal",
        "msg_len": len(msg),
        "heu":     round(heu_score,   4),
        "bino":    round(bino_score,  4),
        "cls":     round(cls_score,   4),
        "llama":   round(llama_score, 4),
        "adv":     round(adv_score,   4),
        "embed":   round(embed_score, 4),
        "wm":      round(watermark_score_val, 4),
        "styl":    round(styl_score,  4),
        "msg":     msg_logged,
    }
    _ai_log_write(json.dumps(entry, ensure_ascii=False) + "\n")


def log_toggle_event(enabled: bool, nick: str) -> None:
    """Record a logging enable/disable event so log gaps are auditable."""
    entry = {
        "type": "log_toggle",
        "ts":   time.time(),
        "dt":   time.strftime("%Y-%m-%d %H:%M:%S"),
        "sess": _LOG_SESSION_ID,
        "enabled": enabled,
        "nick": nick,
    }
    _ai_log_write(json.dumps(entry, ensure_ascii=False) + "\n")


def load_nick_history(nick: str) -> dict:
    """Parse the JSONL log and return aggregated history for *nick*.

    Returns:
      total_msgs    – total log entries for this nick
      first_ts      – earliest unix timestamp or None
      last_ts       – most recent unix timestamp or None
      all_scores    – list[int] of every AI score, chronological
      all_lengths   – list[int] of every message length, chronological
      sessions      – dict  sess_id → {dt, scores, msgs, channels, lengths}
      channels      – sorted list of unique targets seen
      top_messages  – up to 5 highest-scored entries: {a, dt, target, msg}
      gaps          – list of (sess_id, expected_seq, got_seq)
    """
    nick_lower = nick.lower()
    all_scores: list  = []
    all_lengths: list = []
    all_ts: list      = []
    first_ts = None
    last_ts  = None
    sessions: dict       = {}
    sess_last_seq: dict  = {}
    gaps: list           = []
    channels: set        = set()
    _top_heap: list      = []   # min-heap of (score, entry_dict), capped at 5

    try:
        with open(AI_LOG_PATH, "r", encoding="utf-8") as f:
            for raw in f:
                raw = raw.strip()
                if not raw or not raw.startswith("{"):
                    continue
                try:
                    entry = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    continue

                if entry.get("type") == "session_start":
                    sess = entry.get("sess", "?")
                    if sess not in sessions:
                        sessions[sess] = {
                            "dt": entry.get("dt", ""), "scores": [],
                            "msgs": 0, "channels": set(), "lengths": [],
                        }
                    continue

                if entry.get("nick", "").lower() != nick_lower:
                    continue

                ts     = entry.get("ts", 0.0)
                a      = entry.get("a", 0)
                msg    = entry.get("msg", "")
                target = entry.get("target", "")
                sess   = entry.get("sess", "?")
                seq    = entry.get("seq")

                all_scores.append(a)
                all_lengths.append(len(msg))
                all_ts.append(ts)
                channels.add(target)

                if first_ts is None or ts < first_ts: first_ts = ts
                if last_ts  is None or ts > last_ts:  last_ts  = ts

                if sess not in sessions:
                    sessions[sess] = {
                        "dt": entry.get("dt", ""), "scores": [],
                        "msgs": 0, "channels": set(), "lengths": [],
                    }
                sd = sessions[sess]
                sd["scores"].append(a)
                sd["msgs"] += 1
                sd["channels"].add(target)
                sd["lengths"].append(len(msg))

                # Track top-5 highest-scored messages via min-heap (O(log 5) per entry)
                _entry = {"a": a, "dt": entry.get("dt", ""), "target": target, "msg": msg}
                if len(_top_heap) < 5:
                    heapq.heappush(_top_heap, (a, _entry))
                elif a > _top_heap[0][0]:
                    heapq.heapreplace(_top_heap, (a, _entry))

                # Gap detection
                if seq is not None:
                    prev = sess_last_seq.get(sess)
                    if prev is not None and seq != prev + 1:
                        gaps.append((sess, prev + 1, seq))
                    sess_last_seq[sess] = seq

    except FileNotFoundError:
        pass
    except Exception:
        pass

    top_messages = sorted([e for _, e in _top_heap], key=lambda x: x["a"], reverse=True)
    return {
        "total_msgs":   len(all_scores),
        "first_ts":     first_ts,
        "last_ts":      last_ts,
        "all_scores":   all_scores,
        "all_lengths":  all_lengths,
        "all_ts":       all_ts,
        "sessions":     sessions,
        "channels":     sorted(channels),
        "top_messages": top_messages,
        "gaps":         gaps,
    }


# Per-nick AI score history loaded from ai_scores.log at startup.
# Maps nick → list[int] of the last _NICK_AI_HISTORY_LIMIT 'a' scores, chronological.
_NICK_AI_HISTORY: Dict[str, List[int]] = {}
_NICK_AI_HISTORY_LIMIT = 50  # max prior scores seeded per nick per session


def _load_all_nick_ai_history() -> None:
    """Read ai_scores.log once at startup and populate _NICK_AI_HISTORY.

    Keeps only the last _NICK_AI_HISTORY_LIMIT scores per nick so historical
    evidence doesn't overwhelm new in-session observations.  Silently skips
    corrupt lines and missing files.
    """
    global _NICK_AI_HISTORY
    tmp: Dict[str, List[int]] = {}
    try:
        with open(AI_LOG_PATH, "r", encoding="utf-8") as f:
            for raw in f:
                raw = raw.strip()
                if not raw or not raw.startswith("{"):
                    continue
                try:
                    rec = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    continue
                if rec.get("type") == "session_start":
                    continue
                nick = rec.get("nick", "")
                a    = rec.get("a")
                if nick and isinstance(a, (int, float)):
                    tmp.setdefault(nick, []).append(int(a))
    except FileNotFoundError:
        pass
    except Exception:
        pass
    _NICK_AI_HISTORY = {k: v[-_NICK_AI_HISTORY_LIMIT:] for k, v in tmp.items()}


def load_historical_suspects(threshold: int) -> list:
    """Return list of (nick, avg_score, total_msgs, first_ts) for all nicks in the
    log whose average AI score is >= threshold, sorted by avg_score descending."""
    nick_data: dict = {}  # nick_lower → {"nick": str, "scores": [], "first_ts": float}

    try:
        with open(AI_LOG_PATH, "r", encoding="utf-8") as f:
            for raw in f:
                raw = raw.strip()
                if not raw or not raw.startswith("{"):
                    continue
                try:
                    entry = json.loads(raw)
                except (json.JSONDecodeError, ValueError):
                    continue
                if entry.get("type") == "session_start":
                    continue
                nick = entry.get("nick", "")
                if not nick:
                    continue
                key  = nick.lower()
                ts   = entry.get("ts", 0.0)
                a    = entry.get("a", 0)
                if key not in nick_data:
                    nick_data[key] = {"nick": nick, "scores": [], "first_ts": ts}
                nick_data[key]["scores"].append(a)
                if ts < nick_data[key]["first_ts"]:
                    nick_data[key]["first_ts"] = ts
    except FileNotFoundError:
        return []
    except Exception:
        return []

    results = []
    for data in nick_data.values():
        scores = data["scores"]
        avg = sum(scores) / len(scores) if scores else 0
        if avg >= threshold:
            results.append((data["nick"], int(avg), len(scores), data["first_ts"]))
    results.sort(key=lambda x: x[1], reverse=True)
    return results

# =========================
# AI Detector
# =========================
AI_AVAILABLE = False
if not _NO_AI:
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification, GPT2LMHeadModel, GPT2TokenizerFast
        import torch
        AI_AVAILABLE = True
    except Exception:
        AI_AVAILABLE = False

# PEFT (LoRA) optional — only needed for incremental fine-tuning (Area 7)
_PEFT_AVAILABLE = False
if not _NO_AI:
    try:
        import peft  # noqa: F401
        _PEFT_AVAILABLE = True
    except ImportError:
        _PEFT_AVAILABLE = False

IRC_CASUAL_WORDS = frozenset({
    "lol", "lmao", "lmfao", "rofl", "haha", "hehe", "xd", "xdd",
    "brb", "afk", "omg", "wtf", "gtg", "gg", "rip", "smh", "imo",
    "imho", "tbh", "ngl", "idk", "irl", "fyi", "ty", "thx", "np",
    "nvm", "btw", "iirc", "tfw", "mfw", "welp", "kek", "ez",
    "lmk", "imo", "ikr", "fr", "no cap", "w", "l", "based", "cope",
    "slay", "bro", "dude", "gonna", "wanna", "gotta",
})

# General LLM tell-phrases — applies across GPT-4, Claude, Gemini, Llama, etc.
AI_TELL_PHRASES = frozenset({
    # Hedging / meta-commentary
    "it's worth noting", "it is worth noting",
    "it's important to", "it is important to",
    "it should be noted", "it's crucial to",
    "as previously mentioned", "as noted above",
    "it's important to understand", "it's essential to understand",
    "keep in mind that", "bear in mind that",
    "it's worth mentioning", "worth pointing out",
    # Transitional connectors overused by LLMs
    "to elaborate", "to clarify", "in other words",
    "furthermore", "moreover", "additionally", "consequently",
    "that being said", "having said that", "with that said",
    "on the other hand", "in conclusion", "to that end",
    "at its core", "at the end of the day",
    # Summary / recap language
    "to summarize", "in summary", "to recap", "to put it simply",
    "in a nutshell", "in essence", "to boil it down",
    "overall,", "ultimately,", "in short,",
    # Sycophantic openers
    "certainly!", "absolutely!", "great question", "excellent question",
    "good question", "that's a great", "what a great",
    "of course!", "sure thing", "i'd be happy to", "i'd be glad to",
    "happy to help", "glad to help", "i'm happy to",
    # Closing / helper phrases
    "i hope this helps", "i hope that helps", "hope this helps",
    "feel free to", "please let me know", "let me know if",
    "don't hesitate to", "if you have any questions",
    "if you'd like more", "if you need further",
    # LLM identity tells
    "as an ai", "as an ai assistant", "as an ai language model",
    "as a language model", "i'm just an ai", "i am just an ai",
    "my training data", "my knowledge cutoff", "my training",
    "based on my training", "i don't have real-time",
    "i don't have access to real-time",
    # 2025/2026 stylistic tells
    "delve into", "tapestry", "nuanced perspective",
    "it's fascinating", "it's interesting to note",
    "navigating the", "landscape of", "realm of",
    "leverage", "synergize", "holistic approach",
    "robust solution", "empower", "cutting-edge",
    # Deliberative / thinking-aloud phrases (Claude 3/4, GPT-4o)
    "let me think through", "here's my thinking",
    "to put it another way", "to be more specific",
    "broadly speaking", "in practical terms",
    "at a high level", "drill down into",
    "the key takeaway", "the main takeaway",
    "worth unpacking", "let me unpack",
    "when it comes to", "in real-world terms",
    # 2026 additions — newer stylistic tics across all frontier models
    "i think it's worth", "one thing to consider",
    "it depends on", "the short answer is",
    "the long answer is", "to answer directly",
    "to give you a direct answer", "what i'd say is",
    "here's the thing:", "the thing is,",
})

# Phrases characteristic of Llama 2 / Llama 3 / Mistral / open-source LLMs
LLAMA_TELL_PHRASES = frozenset({
    # Typical Llama openers
    "sure, here", "sure! here", "sure, i can",
    "of course, here", "of course! i",
    "i'll do my best", "i'll try my best",
    "let me provide", "let me explain", "let me walk you through",
    "let me break this down", "let me break down",
    "let me help you", "let me help with",
    "here's a step-by-step", "here are some steps",
    "here's how you can", "here's how to",
    "here's an overview", "here's a breakdown",
    "here's what you", "here are a few", "here are some",
    # Llama meta-language
    "as requested", "as you asked", "as you mentioned",
    "based on your question", "based on what you've said",
    "to answer your question", "to address your question",
    "your question is", "you asked about",
    # Llama recommendation style
    "my recommendation would be", "my suggestion would be",
    "i would recommend", "i would suggest", "i suggest",
    "i recommend", "one approach would be", "one option is",
    # Llama closing phrases
    "i hope this answers", "i hope this clarifies",
    "i hope this helps you", "please feel free",
    "feel free to ask", "feel free to reach out",
    "let me know if you", "let me know if there",
    "to summarize my response", "in summary,",
    # Llama hedging / safety language
    "i need to point out", "i should point out",
    "i should mention", "i should note",
    "to be clear", "to be precise", "to be transparent",
    "i want to be clear", "i want to clarify",
    "it's important that i clarify", "i must clarify",
    # Llama 2 refusal / alignment patterns
    "i cannot assist with", "i'm not able to assist",
    "i'm unable to", "i'm afraid i can't",
    "that falls outside", "outside my capabilities",
    "i'm designed to", "my purpose is to",
    # Llama 3 / newer patterns
    "my understanding is", "based on my knowledge",
    "as of my last update", "as of my knowledge",
    "as of my training", "my response to this",
    # Additional open-source LLM openers (Qwen, Gemma, Mistral, Phi)
    "i can certainly help", "i can help you with",
    "let me outline", "here's a quick overview",
    "here's a quick summary", "to break it down",
    "step by step:", "step-by-step guide",
    "here's what i'd suggest", "happy to elaborate",
    "glad you asked", "great, let me",
    "to put it simply,", "simply put,",
    # Qwen3 / DeepSeek thinking-mode bleed-through (internal CoT leaking)
    "let me think step by step", "thinking step by step",
    "let me reason through", "let me work through",
    "so first, let me", "ok, so the question",
})

# Vocabulary LLMs reach for that humans rarely use in casual IRC chat
FORMAL_WORDS = frozenset({
    # Classic formal vocabulary
    "utilize", "leverage", "implement", "facilitate",
    "demonstrate", "enumerate", "articulate",
    "commence", "terminate", "endeavor",
    "subsequent", "pertaining", "aforementioned",
    "constitute", "comprises", "optimal",
    "paramount", "imperative", "holistic",
    "synergy", "paradigm", "streamline",
    # 2025 additions — words AI over-applies in casual settings
    "comprehensive", "multifaceted", "intricate",
    "pivotal", "fundamental", "substantial",
    "conceptual", "theoretical", "contextual",
    "methodology", "framework", "perspective",
    "implications", "considerations", "ramifications",
    "sophisticated", "nuanced", "intrinsically",
    "inherently", "essentially", "fundamentally",
    "predominantly", "predominantly", "encompass",
    "elucidate", "expound", "elaborate",
    "ascertain", "discern", "navigate",
    "augment", "mitigate", "alleviate",
})

# ── Multi-language AI detection patterns ──

# CJK (Chinese/Japanese/Korean) LLM tell-phrases and patterns
CJK_AI_TELL_PHRASES = frozenset({
    "值得注意的是", "需要注意的是", "总的来说", "总而言之",
    "首先", "其次", "最后", "综上所述", "简而言之",
    "换句话说", "也就是说", "从某种意义上说", "从某种程度上说",
    "需要指出的是", "应当注意的是", "不可否认",
    "在我看来", "我认为", "可以说",
    "事实上", "实际上", "客观地说",
    "这是一个很好的问题", "好问题", "很好的问题",
    "让我来解释", "让我详细说明", "我来帮你",
    "希望能帮到你", "希望对你有帮助", "希望这能帮助",
    "作为一个人工智能", "作为AI", "我的训练数据",
    "我的知识截止", "我无法实时",
})

# Japanese LLM patterns
JP_AI_TELL_PHRASES = frozenset({
    "重要なのは", "注意すべきは", "まとめると", "つまり",
    "言い換えると", "端的に言えば", "結論として",
    "まず", "次に", "最後に",
    "良い質問ですね", "素晴らしい質問", "ご質問ありがとうございます",
    "詳しく説明します", "説明させていただきます",
    "お役に立てば幸いです", "参考になれば",
    "AIとして", "私の知識",
})

# Korean LLM patterns
KR_AI_TELL_PHRASES = frozenset({
    "주목할 점은", "유의해야 할 점은", "요약하자면", "결론적으로",
    "다시 말해", "즉", "간단히 말해",
    "먼저", "다음으로", "마지막으로",
    "좋은 질문이네요", "훌륭한 질문입니다",
    "자세히 설명해 드리겠습니다", "도움이 되길 바랍니다",
    "AI로서", "제 지식은",
})

# European language LLM tell-phrases (French, German, Spanish, Portuguese, Italian)
EU_AI_TELL_PHRASES = frozenset({
    # French
    "il est important de noter", "il vaut la peine de", "en résumé",
    "en conclusion", "autrement dit", "en d'autres termes",
    "tout d'abord", "ensuite", "enfin",
    "excellente question", "bonne question",
    "permettez-moi d'expliquer", "laissez-moi expliquer",
    "j'espère que cela aide", "n'hésitez pas à",
    "en tant qu'ia", "en tant qu'intelligence artificielle",
    # German
    "es ist wichtig zu beachten", "es lohnt sich zu",
    "zusammenfassend", "kurz gesagt", "mit anderen Worten",
    "zunächst", "desweiteren", "schließlich",
    "gute frage", "ausgezeichnete frage",
    "lass mich erklären", "ich erkläre gerne",
    "ich hoffe das hilft", "zögern sie nicht",
    "als ki", "als künstliche intelligenz",
    # Spanish
    "es importante tener en cuenta", "vale la pena señalar",
    "en resumen", "en conclusión", "en otras palabras",
    "primero", "segundo", "por último",
    "excelente pregunta", "buena pregunta",
    "déjame explicarte", "permíteme explicar",
    "espero que esto ayude", "no dudes en",
    "como ia", "como inteligencia artificial",
    # Portuguese
    "é importante notar", "vale a pena notar",
    "em resumo", "em conclusão", "em outras palavras",
    "primeiro", "segundo", "por fim",
    "excelente pergunta", "boa pergunta",
    "deixe-me explicar", "espero que isso ajude",
    "como ia", "como inteligência artificial",
    # Italian
    "è importante notare", "vale la pena notare",
    "in sintesi", "in conclusione", "in altre parole",
    "innanzitutto", "in secondo luogo", "infine",
    "ottima domanda", "buona domanda",
    "lasciami spiegare", "spero che questo aiuti",
    "come ia", "come intelligenza artificiale",
})

# CJK formal vocabulary that AI over-uses in casual settings
CJK_FORMAL_WORDS = frozenset({
    "此外", "然而", "因此", "总之", "鉴于",
    "毋庸置疑", "至关重要", "不可或缺", "显著",
    "涉及", "阐述", "探讨", "分析", "论证",
    "综上所述", "换言之", "与此同时", "另一方面",
})

# European formal vocabulary
EU_FORMAL_WORDS = frozenset({
    "par conséquent", "néanmoins", "en outre", "cependant",
    "demnach", "darüber hinaus", "insbesondere", "beziehungsweise",
    "adicionalmente", "asimismo", "no obstante", "por consiguiente",
    "adicionalmente", "outrossim", "entretanto", "por conseguinte",
    "inoltre", "pertanto", "d'altra parte", "di conseguenza",
})

# Casual CJK words that humans use but AI rarely does in chat
CJK_CASUAL_WORDS = frozenset({
    "哈哈", "嘿嘿", "额", "嗯", "哦", "啊",
    "卧槽", "牛逼", "666", "草", "emmm", "hhh",
    "w", "kwsk", "草", "うp", "乙", "おつ",
    "ㅋㅋ", "ㅎㅎ", "ㄷㄷ", "헐", "대박", "징징",
})

# Detect CJK character ranges for language identification
_CJK_RANGE_RE = re.compile(r'[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]')
_CJK_CN_RE = re.compile(r'[\u4e00-\u9fff]')
_CJK_JP_RE = re.compile(r'[\u3040-\u309f\u30a0-\u30ff]')
_CJK_KR_RE = re.compile(r'[\uac00-\ud7af]')
_LATIN_ACCENT_RE = re.compile(r'[àáâãäåèéêëìíîïòóôõöùúûüýÿñçßðþæœ]')

def _detect_text_language(text: str) -> str:
    """Simple language detection: 'zh', 'ja', 'ko', 'eu', or 'en'."""
    if _CJK_CN_RE.search(text) and not _CJK_JP_RE.search(text):
        return "zh"
    if _CJK_JP_RE.search(text):
        return "ja"
    if _CJK_KR_RE.search(text):
        return "ko"
    if _LATIN_ACCENT_RE.search(text):
        return "eu"
    return "en"
_BOT_OPENER_RE = re.compile(
    r"^(?:Sure[!,]?|Absolutely[!,]?|Certainly[!,]?|Of course[!,]?|"
    r"Great[!,]?|Gladly[!,]?|Happy to help[!,]?|I'?d be happy|"
    r"I'?d be glad|Let me|Here'?s |Here are |To answer|"
    r"Of course[,!] I'?d|I can help|I'?ll help|"
    r"I can certainly|Allow me|Thanks for (?:asking|the question)|"
    r"Good (?:question|point)[!,.]?|That'?s (?:a )?(?:great|good|interesting)|"
    r"To (?:address|answer|respond to)|I'?ll (?:break|walk|explain|outline)|"
    r"Step(?:\s+\d+)?[:.]\s*\w)",
    re.IGNORECASE,
)

# Structural patterns Llama/open-source LLMs use that are unusual in IRC
# (numbered lists, bullet points, markdown headers, code fences)
_LLAMA_STRUCT_RE = re.compile(
    r"(?m)^(?:\s*\d+[.)]\s+\S|\s*[-*•]\s+\S|\s*#{1,3}\s+\S|```)",
)

# =========================
# Ollama local-model helper
# =========================
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


async def _llm_classify_ai(text: str, model_key: str) -> float:
    """Ask the active /model to classify *text* as AI- or human-written.

    Sends a tightly constrained prompt and expects a single-word reply of
    "AI" or "HUMAN".  Returns 0.0–1.0 (1.0 = AI-generated).  Returns 0.0
    on any network or parse error so it degrades gracefully.

    Skipped for messages shorter than 6 words — too little signal to be
    meaningful and would waste API / local-inference budget.
    """
    if len(text.split()) < 6:
        return 0.0

    prompt = (
        "You are an AI-text detector reviewing IRC chat messages.\n"
        "Classify the message below as written by a human or generated by AI.\n"
        "Consider: informal language, typos, slang, IRC conventions, naturalness.\n"
        "Reply with ONLY one word: AI or HUMAN.\n\n"
        f"Message: {text!r}\n\nClassification:"
    )

    try:
        if model_key.startswith("ollama:"):
            provider = "ollama"
            model_id = model_key[len("ollama:"):]
        else:
            spec = AI_MODELS.get(model_key)
            if not spec:
                return 0.0
            provider = spec["provider"]
            model_id = spec["id"]

        global _classify_ac, _classify_oc
        answer = ""
        if provider == "claude":
            if not ANTHROPIC_AVAILABLE or not ANTHROPIC_API_KEY:
                return 0.0
            if _classify_ac is None:
                _classify_ac = _anthropic_mod.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
            try:
                msg = await _classify_ac.messages.create(
                    model=model_id, max_tokens=10,
                    messages=[{"role": "user", "content": prompt}],
                )
            except Exception:
                _classify_ac = None
                raise
            answer = msg.content[0].text if msg.content else ""
        elif provider == "openai":
            if not OPENAI_AVAILABLE or not OPENAI_API_KEY:
                return 0.0
            if _classify_oc is None:
                _classify_oc = _openai_mod.AsyncOpenAI(api_key=OPENAI_API_KEY)
            try:
                resp = await _classify_oc.chat.completions.create(
                    model=model_id, max_tokens=10,
                    messages=[{"role": "user", "content": prompt}],
                )
            except Exception:
                _classify_oc = None
                raise
            answer = resp.choices[0].message.content if resp.choices else ""
        elif provider == "gemini":
            if not GEMINI_AVAILABLE or not GEMINI_API_KEY:
                return 0.0
            try:
                gclient = _gemini_mod.aio.Client(api_key=GEMINI_API_KEY)
                resp = await gclient.models.generate_content(
                    model=model_id,
                    contents=prompt,
                    config=_gemini_mod.types.GenerateContentConfig(max_output_tokens=10))
                answer = resp.text if resp.text else ""
            except Exception:
                return 0.0
        elif provider == "ollama":
            loop   = asyncio.get_running_loop()
            answer, _ = await loop.run_in_executor(
                _IO_EXECUTOR, _ollama_blocking_call, model_id, prompt, 10)
        elif provider == "llamacpp":
            loop   = asyncio.get_running_loop()
            answer, _ = await loop.run_in_executor(
                _IO_EXECUTOR, _llamacpp_blocking_call, model_id, prompt, 10)
        else:
            return 0.0

        upper = answer.strip().upper()
        if "HUMAN" in upper:
            return 0.0
        if "AI" in upper:
            return 1.0
        return 0.5   # ambiguous / unexpected reply

    except Exception:
        return 0.0


class EnsembleAIDetector:
    _CACHE_MAX = 512  # LRU-style prediction cache (bots repeat themselves)

    # Primary classifier: trained on ChatGPT/GPT-family output
    _CLS1_MODEL = "Hello-SimpleAI/chatgpt-detector-roberta"
    # Secondary classifier: broader OpenAI GPT-2-era detector; generalises to
    # fluent AI text regardless of model family (Llama, Mistral, etc.).
    # Loaded opportunistically — falls back gracefully if unavailable.
    _CLS2_MODEL = "openai-community/roberta-base-openai-detector"

    def __init__(self, disabled: bool = False):
        self.enabled = not disabled
        self.active_detect_model: str = "" if disabled else "qwen3"  # default: llama.cpp qwen3 for LLM detection
        self._gpt2_model = None   # GPT-2: Binoculars performer
        self._obs_model  = None   # distilgpt2 or configurable observer
        self._obs_modern = None   # modern observer (TinyLlama etc.), optional
        self._obs_modern_tok = None
        self._gpt2_tok   = None   # shared GPT-2 tokenizer
        self._cls_model  = None   # primary classifier (ChatGPT-focused RoBERTa)
        self._cls_tok    = None
        self._cls2_model = None   # secondary classifier (general LLM detector), optional
        self._cls2_tok   = None
        self._embed_model = None  # sentence embedding model (drift detection), optional
        self._embed_tok   = None
        self._device = "cpu"
        self._pred_cache: OrderedDict = OrderedDict()  # text → Dict[str,float], LRU
        # ── LoRA incremental fine-tuning (Area 7) ────────────────────────────
        self._lora_peft_config = None
        self._lora_model = None
        self._lora_loaded = False

        if disabled:
            return
        if not AI_AVAILABLE:
            raise SystemExit(
                "AI detector requires: pip install transformers torch\n"
                "Core models (gpt2, distilgpt2, RoBERTa) must load successfully."
            )
        self._load_models()

    def _load_models(self) -> None:
        self._device = "cuda" if torch.cuda.is_available() else "cpu"

        print("AI detector: loading gpt2 tokenizer...", end=" ", flush=True)
        self._gpt2_tok = GPT2TokenizerFast.from_pretrained("gpt2")
        print("OK")

        print("AI detector: loading gpt2 (Binoculars performer)...", end=" ", flush=True)
        self._gpt2_model = GPT2LMHeadModel.from_pretrained("gpt2").to(self._device)
        self._gpt2_model.eval()
        print("OK")

        # ── Binoculars observer model (configurable via IRC_OBSERVER_MODEL) ──────────
        _obs_id = OBSERVER_MODEL_ID
        if _obs_id == "distilgpt2":
            print("AI detector: loading distilgpt2 (Binoculars observer)...", end=" ", flush=True)
            try:
                self._obs_model = GPT2LMHeadModel.from_pretrained(_obs_id).to(self._device)
                self._obs_model.eval()
                print("OK")
            except Exception as _e:
                print(f"failed ({_e})")
        else:
            # Modern observer — not GPT-2 family, so it gets its own tokenizer
            print(f"AI detector: loading {_obs_id} (modern Binoculars observer)...", end=" ", flush=True)
            try:
                from transformers import AutoModelForCausalLM as _AutoCausal
                self._obs_modern_tok = AutoTokenizer.from_pretrained(_obs_id)
                if self._obs_modern_tok.pad_token is None:
                    self._obs_modern_tok.pad_token = self._obs_modern_tok.eos_token
                self._obs_modern = _AutoCausal.from_pretrained(
                    _obs_id, torch_dtype="auto", device_map="auto",
                ).to(self._device)
                self._obs_modern.eval()
                print("OK")
            except Exception as _e:
                self._obs_modern = None
                self._obs_modern_tok = None
                print(f"skipped ({_e})")
            # Load distilgpt2 as fallback for the classic Binoculars path
            print("AI detector: loading distilgpt2 (fallback observer)...", end=" ", flush=True)
            try:
                self._obs_model = GPT2LMHeadModel.from_pretrained("distilgpt2").to(self._device)
                self._obs_model.eval()
                print("OK")
            except Exception as _e:
                print(f"failed ({_e})")

        # ── Sentence embedding model for semantic-drift detection ───────────────────
        if EMBEDDING_MODEL:
            print(f"AI detector: loading embedding model ({EMBEDDING_MODEL})...", end=" ", flush=True)
            try:
                from sentence_transformers import SentenceTransformer
                self._embed_model = SentenceTransformer(EMBEDDING_MODEL, device=self._device)
                print("OK")
            except ImportError:
                print("skipped (sentence-transformers not installed)")
            except Exception as _e:
                print(f"skipped ({_e})")

        # ── Classifiers ─────────────────────────────────────────────────────────────
        _tf_logger = logging.getLogger("transformers")
        _prev_tf_level = _tf_logger.level
        _tf_logger.setLevel(logging.ERROR)

        try:
            print(f"AI detector: loading primary classifier ({self._CLS1_MODEL})...", end=" ", flush=True)
            try:
                self._cls_tok = AutoTokenizer.from_pretrained(self._CLS1_MODEL)
                self._cls_model = AutoModelForSequenceClassification.from_pretrained(
                    self._CLS1_MODEL,
                    ignore_mismatched_sizes=True,
                ).to(self._device)
                self._cls_model.eval()
                print("OK")
            except Exception as _e:
                self._cls_tok   = None
                self._cls_model = None
                print(f"skipped ({_e})")

            print(f"AI detector: loading secondary classifier ({self._CLS2_MODEL})...", end=" ", flush=True)
            try:
                self._cls2_tok = AutoTokenizer.from_pretrained(self._CLS2_MODEL)
                self._cls2_model = AutoModelForSequenceClassification.from_pretrained(
                    self._CLS2_MODEL,
                    ignore_mismatched_sizes=True,
                ).to(self._device)
                self._cls2_model.eval()
                print("OK")
            except Exception as _e:
                self._cls2_tok   = None
                self._cls2_model = None
                print(f"skipped ({_e})")
        finally:
            _tf_logger.setLevel(_prev_tf_level)

        obs_name = OBSERVER_MODEL_ID if self._obs_modern else "distilgpt2"
        loaded = [f"Binoculars(gpt2+{obs_name})", "Llama-heuristics"]
        if self._cls_model:
            loaded.append("RoBERTa(chatgpt)")
        if self._cls2_model:
            loaded.append("RoBERTa(general)")
        if self._embed_model:
            loaded.append(f"Embed({EMBEDDING_MODEL})")
        print(f"AI detector ENABLED: {' + '.join(loaded)}  (device={self._device})")

    # ---- static heuristics ----

    @staticmethod
    def entropy(text: str) -> float:
        if not text: return 0.0
        total = len(text)
        freq: dict = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        inv = 1.0 / total
        return -sum(n * inv * log2(n * inv) for n in freq.values())

    @staticmethod
    def repetition(text: str) -> float:
        if not text: return 0.0
        words = text.lower().split()
        if len(words) < 3: return 0.0
        return 1.0 - (len(set(words)) / len(words))

    @staticmethod
    def _burstiness(text: str) -> float:
        """Measure sentence-length variance (burstiness).

        Human writing exhibits high burstiness — alternating short and long
        sentences.  LLM output tends toward uniform sentence lengths.
        Returns 0..1, higher = more human-like burstiness.
        """
        if not text:
            return 0.0
        sentences = [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]
        if len(sentences) < 3:
            return 0.0  # not enough data
        lengths = [len(s.split()) for s in sentences]
        mean_len = sum(lengths) / len(lengths)
        if mean_len < 1:
            return 0.0
        variance = sum((l - mean_len) ** 2 for l in lengths) / len(lengths)
        cv = (variance ** 0.5) / mean_len  # coefficient of variation
        # Human text: CV typically 0.4–1.2; AI text: CV 0.1–0.4
        return max(0.0, min(1.0, (cv - 0.15) / 0.85))

    @staticmethod
    def _lexical_diversity(text: str) -> float:
        """Measure of Textual Lexical Diversity (MTLD-style approximation).

        Humans use a wider variety of unique words relative to total word count.
        LLMs tend to recycle common vocabulary more frequently.
        Returns 0..1, higher = more diverse (human-like).
        """
        if not text:
            return 0.0
        words = [w.lower().strip(".,!?;:\"'()[]") for w in text.split() if w.strip(".,!?;:\"'()[]")]
        if len(words) < 5:
            return 0.0
        # Type-token ratio over sliding windows (more robust than simple TTR)
        window_size = 10
        ttr_values = []
        for i in range(0, len(words) - window_size + 1, window_size // 2):
            window = words[i:i + window_size]
            if len(window) >= window_size:
                ttr_values.append(len(set(window)) / len(window))
        if not ttr_values:
            return 0.0
        avg_ttr = sum(ttr_values) / len(ttr_values)
        # Human IRC: ~0.7–0.95; AI: ~0.5–0.75
        return max(0.0, min(1.0, (avg_ttr - 0.45) / 0.55))

    @staticmethod
    def _punctuation_anomaly(text: str) -> float:
        """Detect unusual punctuation patterns common in AI output.

        LLMs overuse certain punctuation (em-dashes, semicolons, colons)
        and underuse others (ellipses, interrobangs, casual punctuation).
        Returns 0..1, higher = more anomalous (AI-like).
        """
        if not text or len(text) < 10:
            return 0.0
        score = 0.0
        words = text.split()
        n_words = len(words)

        # Em-dash density (LLMs love em-dashes for parentheticals)
        emdash_count = text.count('\u2014') + text.count(' -- ')
        if emdash_count > 0 and n_words > 10:
            ratio = emdash_count / (n_words / 20)  # expected ~1 per 20 words
            if ratio > 2.0:
                score += 0.15

        # Semicolon density (rare in casual IRC, common in AI prose)
        semicolon_count = text.count(';')
        if semicolon_count > 1 and n_words < 50:
            score += 0.10 * min(1.0, semicolon_count / 2)

        # Colon density (LLMs use colons to introduce lists/explanations)
        colon_count = text.count(':') - text.count('::')  # exclude IRC smileys
        if colon_count > 1 and n_words < 40:
            score += 0.10 * min(1.0, colon_count / 2)

        # Lack of casual punctuation (humans use ???, !!!, ?!, etc.)
        has_casual_punct = bool(re.search(r'[!?]{2,}|[\?!]{2,}|\.{4,}', text))
        if not has_casual_punct and n_words > 15:
            score += 0.08

        # Overly balanced parentheses (LLMs use them for asides)
        paren_pairs = min(text.count('('), text.count(')'))
        if paren_pairs > 2 and n_words < 60:
            score += 0.07 * min(1.0, paren_pairs / 3)

        return min(1.0, score)

    @staticmethod
    def _function_word_ratio(text: str) -> float:
        """Ratio of function words to content words.

        LLMs tend to have higher function-word density due to verbose
        connective tissue ("it is important to note that...", etc.).
        Returns 0..1, higher = more function-word heavy (AI-like).
        """
        if not text:
            return 0.0
        words = [w.lower().strip(".,!?;:\"'()[]") for w in text.split() if w.strip(".,!?;:\"'()[]")]
        if len(words) < 5:
            return 0.0

        _function_words = frozenset({
            "the", "a", "an", "of", "to", "in", "is", "that", "for", "it",
            "on", "and", "be", "or", "as", "at", "by", "with", "this", "are",
            "was", "were", "been", "has", "have", "had", "do", "does", "did",
            "will", "would", "can", "could", "may", "might", "shall", "should",
            "not", "no", "so", "if", "than", "then", "but", "because", "we",
            "they", "them", "their", "there", "here", "where", "when", "what",
            "which", "who", "whom", "whose", "about", "into", "through",
            "during", "before", "after", "above", "below", "between",
            "under", "again", "further", "once", "also", "just", "even",
            "still", "already", "always", "never", "often", "sometimes",
            "usually", "however", "therefore", "thus", "hence", "moreover",
            "furthermore", "additionally", "consequently", "nevertheless",
        })

        func_count = sum(1 for w in words if w in _function_words)
        ratio = func_count / len(words)
        # Human IRC: ~0.25–0.40; AI: ~0.40–0.55
        return max(0.0, min(1.0, (ratio - 0.30) / 0.25))

    @staticmethod
    def _sentence_openers_variety(text: str) -> float:
        """Measure variety of sentence/phrase openers.

        Humans vary how they start sentences; LLMs often repeat patterns
        ("The...", "It...", "This...", "Additionally,...").
        Returns 0..1, higher = more varied (human-like).
        """
        if not text:
            return 0.0
        # Split on sentence boundaries and line breaks
        segments = re.split(r'[.!?]+\s*|\n', text)
        segments = [s.strip() for s in segments if len(s.strip()) > 3]
        if len(segments) < 3:
            return 0.0

        # Extract first 2 words of each segment
        openers = []
        for seg in segments:
            words = seg.split()[:2]
            if words:
                openers.append(' '.join(w.lower() for w in words))

        if not openers:
            return 0.0
        unique_ratio = len(set(openers)) / len(openers)
        # Human: ~0.7–1.0; AI: ~0.3–0.7
        return max(0.0, min(1.0, (unique_ratio - 0.25) / 0.75))

    @staticmethod
    def formality_score(text: str) -> float:
        """0..1 — calibrated for 2025/2026 LLM output patterns in IRC chat."""
        if not text: return 0.0
        words = text.split()
        if not words: return 0.0
        text_lower = text.lower()
        _strip = ".,!?;:\"'()[]"
        words_lower_stripped = {w.lower().strip(_strip) for w in words}

        # Classic IRC vs formal signals
        casual_hit   = bool(words_lower_stripped & IRC_CASUAL_WORDS)
        ends_cleanly = text.rstrip().endswith((".", "!", "?", "..."))
        starts_cap   = text[0].isupper()
        no_charspam  = not any(len(set(w)) == 1 and len(w) > 2 for w in words)
        no_emoticon  = not any(e in text for e in (":)", ":(", ":D", "xD", "XD", "^_^", ">_<", "o/"))
        long_enough  = len(words) >= 6

        # LLM-specific tells (general across all model families)
        has_emdash     = "\u2014" in text or " -- " in text
        tell_phrase    = any(p in text_lower for p in AI_TELL_PHRASES)
        llama_phrase   = any(p in text_lower for p in LLAMA_TELL_PHRASES)
        formal_vocab   = bool(words_lower_stripped & FORMAL_WORDS)
        no_contraction = not any(c in text_lower for c in
                                 ("n't", "'re", "'ve", "'ll", "'m", "'d"))
        # Bot-opener at the very start of the message
        bot_opener = bool(_BOT_OPENER_RE.match(text))

        return min(1.0,
            0.08 * ends_cleanly
            + 0.04 * starts_cap
            + 0.06 * (not casual_hit)
            + 0.04 * no_charspam
            + 0.03 * no_emoticon
            + 0.05 * long_enough
            + 0.16 * tell_phrase       # strongest general signal
            + 0.14 * llama_phrase      # Llama/open-source LLM signal
            + 0.12 * has_emdash
            + 0.12 * formal_vocab
            + 0.10 * no_contraction
            + 0.14 * bot_opener        # unambiguous AI opener pattern
        )

    @staticmethod
    def llama_pattern_score(text: str) -> float:
        """0..1 — detects structural and phrasing patterns specific to Llama/
        open-source LLM outputs (Llama 2, Llama 3, Mistral, Vicuna, etc.).

        Focuses on signals that are low-FP in casual IRC:
        • Markdown structure (numbered lists, bullets, headers) in plain chat
        • Bot-opener words at the message start
        • Colon-terminated sentences introducing a list
        • Unusually long single messages (LLMs over-explain)
        • Multi-sentence uniform capitalisation (templated output)
        """
        if not text:
            return 0.0
        text_lower = text.lower()
        score = 0.0

        # Llama-specific tell phrases (subset different from general AI_TELL_PHRASES)
        if any(p in text_lower for p in LLAMA_TELL_PHRASES):
            score += 0.30

        # Markdown-style structural elements in what should be plain IRC chat
        struct_hits = len(_LLAMA_STRUCT_RE.findall(text))
        if struct_hits >= 3:
            score += 0.25
        elif struct_hits >= 1:
            score += 0.12

        # Bot-opener (unambiguous start patterns)
        if _BOT_OPENER_RE.match(text):
            score += 0.18

        # Colon at end of a sentence followed by newline or end-of-text (list intro)
        if re.search(r':\s*(?:\n|$)', text):
            score += 0.08

        # Very long single message: Llama over-explains simple questions
        word_count = len(text.split())
        if word_count >= 60:
            score += 0.15
        elif word_count >= 30:
            score += 0.07

        # All sentences start with a capital: templated / AI-generated prose
        sentences = [s.strip() for s in re.split(r'[.!?]', text) if len(s.strip()) > 4]
        if len(sentences) >= 3 and all(s[0].isupper() for s in sentences):
            score += 0.08

        # Repeated numbered / enumerated structure (common Llama answer format)
        if re.search(r'\b(?:first|second|third|finally|lastly)[,:]', text_lower):
            score += 0.08

        return min(1.0, score)

    @staticmethod
    def _multilang_formality_score(text: str) -> float:
        """0..1 — language-specific formality scoring for CJK and European text."""
        if not text:
            return 0.0
        lang = _detect_text_language(text)
        score = 0.0

        if lang == "zh":
            text_lower = text.lower()
            if any(p in text for p in CJK_AI_TELL_PHRASES):
                score += 0.30
            if any(p in text for p in CJK_FORMAL_WORDS):
                score += 0.15
            if not any(p in text for p in CJK_CASUAL_WORDS):
                score += 0.10
            if re.search(r'[。；：]', text) and not re.search(r'[！？]', text):
                score += 0.08
            if len(text) > 80:
                score += 0.10
            if re.search(r'[一二三四五六七八九十]、', text):
                score += 0.12
            if any(p in text for p in ("首先", "其次", "最后", "第一", "第二", "第三")):
                score += 0.10
            return min(1.0, score)

        elif lang == "ja":
            if any(p in text for p in JP_AI_TELL_PHRASES):
                score += 0.30
            if re.search(r'。$', text) and not re.search(r'[！？ww]', text):
                score += 0.10
            if re.search(r'[①②③④⑤]', text):
                score += 0.12
            if len(text) > 80:
                score += 0.08
            if not re.search(r'ww|ｗｗ|笑', text):
                score += 0.05
            return min(1.0, score)

        elif lang == "ko":
            if any(p in text for p in KR_AI_TELL_PHRASES):
                score += 0.30
            if not any(p in text for p in CJK_CASUAL_WORDS):
                score += 0.10
            if re.search(r'[.；:]', text) and not re.search(r'[ㅋㅎㅠㅜ]', text):
                score += 0.08
            if len(text) > 80:
                score += 0.08
            return min(1.0, score)

        elif lang == "eu":
            text_lower = text.lower()
            if any(p in text_lower for p in EU_AI_TELL_PHRASES):
                score += 0.30
            if any(p in text_lower for p in EU_FORMAL_WORDS):
                score += 0.15
            if any(p in text for p in ("—", "–")):
                score += 0.10
            words = text.split()
            if len(words) >= 6:
                score += 0.05
            return min(1.0, score)

        return 0.0

    def _heuristic_score(self, text: str) -> float:
        """Combined heuristic score incorporating general formality,
        Llama-specific patterns, burstiness, lexical diversity, and
        punctuation anomalies."""
        form  = self.formality_score(text)
        llama = self.llama_pattern_score(text)
        rep   = self.repetition(text)
        ent   = self.entropy(text)
        length = min(1.0, len(text) / 300.0)
        ent_penalty = max(0.0, (ent - 4.0) / 2.0)

        # New signals
        burst   = 1.0 - self._burstiness(text)          # low burstiness → AI-like
        lex_div = 1.0 - self._lexical_diversity(text)   # low diversity → AI-like
        punct   = self._punctuation_anomaly(text)       # high anomaly → AI-like
        func_w  = self._function_word_ratio(text)       # high ratio → AI-like
        opener  = 1.0 - self._sentence_openers_variety(text)  # low variety → AI-like
        ml_form = self._multilang_formality_score(text) # CJK/EU language-specific signals

        lang = _detect_text_language(text)
        is_cjk_eu = lang not in ("en",)
        en_weight = 0.0 if is_cjk_eu else 0.28
        ml_weight = 0.30 if is_cjk_eu else 0.05
        llama_w = 0.10 if is_cjk_eu else 0.25

        return max(0.0, min(1.0,
            en_weight * form
            + llama_w * llama
            + ml_weight * ml_form
            + 0.10 * rep
            + 0.05 * length
            - 0.10 * ent_penalty
            + 0.08 * burst
            + 0.08 * lex_div
            + 0.06 * punct
            + 0.06 * func_w
            + 0.04 * opener
        ))

    # ---- ML signals ----

    def _binoculars_score(self, text: str) -> float:
        """Binoculars (Hans et al., 2024): CE_observer / CE_performer.

        Low ratio → both models find the text fluent → likely AI-generated.
        When `self._obs_modern` is set, both the performer (gpt2) and the
        modern observer run on their own tokenizers independently and we take
        whichever yields a stronger signal.  Falls back to classic (gpt2,
        distilgpt2) if the modern model is unavailable.
        Returns 0..1, higher = more AI-like.
        """
        if self._gpt2_tok is None or self._gpt2_model is None:
            return 0.0
        if len(text.split()) < 5:
            return 0.0

        performer_ready = self._gpt2_model is not None
        classic_ready   = performer_ready and self._obs_model is not None
        modern_ready    = performer_ready and self._obs_modern is not None and self._obs_modern_tok is not None

        if not classic_ready and not modern_ready:
            return 0.0

        best_ratio = None

        # Classic path (gpt2 performer + distilgpt2 observer)
        if classic_ready:
            try:
                enc = self._gpt2_tok(text, return_tensors="pt", truncation=True, max_length=128)
                enc = {k: v.to(self._device) for k, v in enc.items()}
                if enc["input_ids"].shape[1] >= 3:
                    with torch.inference_mode():
                        ce_perf = self._gpt2_model(**enc, labels=enc["input_ids"]).loss.item()
                        ce_obs  = self._obs_model(**enc, labels=enc["input_ids"]).loss.item()
                    if ce_perf >= 1e-6:
                        best_ratio = ce_obs / ce_perf
            except Exception:
                pass

        # Modern path (gpt2 performer + modern observer on its own tokenizer).
        # A strong fluency disagreement between the two architectures is a
        # cheaper signal than perplexity itself.
        if modern_ready:
            try:
                enc_m = self._obs_modern_tok(
                    text, return_tensors="pt", truncation=True, max_length=128,
                    padding=True,
                )
                enc_m = {k: v.to(self._device) for k, v in enc_m.items()}
                if enc_m["input_ids"].shape[1] >= 3:
                    with torch.inference_mode():
                        ce_modern = self._obs_modern(**enc_m, labels=enc_m["input_ids"]).loss.item()
                    if ce_modern >= 1e-6:
                        # Re-run performer through the same encoding to compare
                        # on the modern model's tokenization.
                        enc_p = self._gpt2_tok(
                            text, return_tensors="pt", truncation=True, max_length=128)
                        enc_p = {k: v.to(self._device) for k, v in enc_p.items()}
                        with torch.inference_mode():
                            ce_perf2 = self._gpt2_model(**enc_p, labels=enc_p["input_ids"]).loss.item()
                        if ce_perf2 >= 1e-6:
                            r = ce_modern / ce_perf2
                            if best_ratio is None or r < best_ratio:
                                best_ratio = r
            except Exception:
                pass

        if best_ratio is None:
            return 0.0

        # Calibration is model-pair specific.  distilgpt2 threshold:
        #   human ~1.3–2.5,  AI ~0.7–1.2  →  score = (1.9 - r) / 1.3
        # A modern observer (e.g. TinyLlama) has lower perplexity overall,
        # so the ratio for AI text is typically *higher* (~1.0–1.6) because
        # both the performer and the modern model find it reasonably fluent.
        if self._obs_modern is not None and best_ratio is not None:
            return max(0.0, min(1.0, (2.2 - best_ratio) / 1.4))
        return max(0.0, min(1.0, (1.9 - best_ratio) / 1.3))

    def _classifier_score(self, text: str) -> float:
        """Average AI-probability across all loaded classifiers.

        Primary (cls1): Hello-SimpleAI/chatgpt-detector-roberta — strong on
          ChatGPT / GPT-4 / Claude family output.  If a LoRA adapter is loaded
          (Area 7), the LoRA-adapted cls1 is used instead.
        Secondary (cls2): openai-community/roberta-base-openai-detector — trained
          on GPT-2 outputs; generalises to Llama / Mistral / open-source LLMs
          because it captures broad fluency features rather than ChatGPT style.
        If cls2 failed to load only cls1 is used.
        """
        scores: List[float] = []
        if len(text.split()) < 5:
            return 0.0
        _cls_model = self._cls_model
        if getattr(self, "_lora_loaded", False) and self._lora_model is not None:
            _cls_model = self._lora_model
        if _cls_model is not None:
            try:
                enc = self._cls_tok(text, return_tensors="pt", truncation=True, max_length=128)
                enc = {k: v.to(self._device) for k, v in enc.items()}
                with torch.inference_mode():
                    logits = _cls_model(**enc).logits
                scores.append(torch.softmax(logits, dim=-1)[0][1].item())
            except Exception:
                pass
        if self._cls2_model is not None:
            try:
                enc2 = self._cls2_tok(text, return_tensors="pt", truncation=True, max_length=128)
                enc2 = {k: v.to(self._device) for k, v in enc2.items()}
                with torch.inference_mode():
                    logits2 = self._cls2_model(**enc2).logits
                # openai-community/roberta-base-openai-detector: LABEL_0=Real, LABEL_1=Fake
                scores.append(torch.softmax(logits2, dim=-1)[0][1].item())
            except Exception:
                pass
        return sum(scores) / len(scores) if scores else 0.0

    # ---- adversarial character-level detection ----

    @staticmethod
    def _char_ngram_entropy(text: str, n: int = 3) -> float:
        """Normalised entropy over character n-grams.  Low entropy suggests
        repetitive/patterned text; near-zero is suspicious for natural language
        but common in adversarial padding (e.g. "s p r e a d  o u t")."""
        if not text or len(text) < n:
            return 1.0
        ngrams: Counter = Counter()
        for i in range(len(text) - n + 1):
            ngrams[text[i:i + n]] += 1
        total = sum(ngrams.values())
        inv   = 1.0 / total
        ent   = -sum(c * inv * log2(c * inv) for c in ngrams.values())
        max_ent = log2(len(ngrams)) if ngrams else 1.0
        return ent / max_ent if max_ent > 0 else 0.0

    @staticmethod
    def _spacing_anomaly(text: str) -> float:
        """Score (0..1) for unusual spacing patterns common in adversarial
        evasion: multi-space gaps, letter-spacing (every-other char space),
        excessive whitespace."""
        if not text:
            return 0.0
        score = 0.0
        # Multi-space runs (>2 spaces)
        multi = re.findall(r'  +', text)
        if multi:
            score += min(0.4, 0.1 * len(multi))
        # Letter-spacing detection: "s p r e a d" pattern
        spaced = re.findall(r'\b(?:\w ){3,}\w\b', text)
        if spaced:
            score += min(0.5, 0.15 * len(spaced))
        # Whitespace ratio anomaly
        if len(text) > 10:
            ws_ratio = text.count(" ") / len(text)
            if ws_ratio > 0.5:
                score += min(0.3, (ws_ratio - 0.5) * 2.0)
        return min(1.0, score)

    @staticmethod
    def _adversarial_score(text: str) -> float:
        """Combined adversarial-evasion score (0..1).  Low char-ngram entropy
        combined with spacing anomalies is a strong indicator of adversarial
        padding designed to bypass classifiers."""
        if not text or len(text) < 8:
            return 0.0
        tri_ent = EnsembleAIDetector._char_ngram_entropy(text, n=3)
        quad_ent = EnsembleAIDetector._char_ngram_entropy(text, n=4)
        spacing = EnsembleAIDetector._spacing_anomaly(text)
        entropy_penalty = max(0.0, 0.5 - (tri_ent + quad_ent) * 0.5) * 0.6
        return min(1.0, entropy_penalty + 0.4 * spacing)

    # ---- embedding-based semantic drift ----

    def _embed_text(self, text: str):
        """Return a sentence embedding vector, or None on failure."""
        if self._embed_model is None:
            return None
        try:
            return self._embed_model.encode(text, convert_to_numpy=True)
        except Exception:
            return None

    @staticmethod
    def _cosine_sim(a, b) -> float:
        """Cosine similarity between two 1-D vectors."""
        import numpy as _np
        a_n = _np.linalg.norm(a)
        b_n = _np.linalg.norm(b)
        if a_n < 1e-8 or b_n < 1e-8:
            return 0.0
        return float(_np.dot(a, b) / (a_n * b_n))

    def _embedding_variance_score(self, text: str, recent_embeds: list) -> float:
        """Return 0..1 based on how much *text*'s embedding deviates from
        the user's recent embedding history.  Low variance (tight cluster)
        suggests machine-generated text.  Returns 0 if not enough data or
        embedding model unavailable."""
        if self._embed_model is None or not recent_embeds:
            return 0.0
        emb = self._embed_text(text)
        if emb is None:
            return 0.0
        sims = [self._cosine_sim(emb, e) for e in recent_embeds if e is not None]
        if len(sims) < 3:
            return 0.0
        avg_sim = sum(sims) / len(sims)
        # Humans typically have avg_sim ~0.6–0.8 (diverse topics);
        # bots cluster at ~0.85–1.0 (uniform style/topic).
        # Scale: 1.0 at avg_sim=1.0, 0.0 at avg_sim <= 0.60
        return max(0.0, min(1.0, (avg_sim - 0.60) / 0.40))

    # ---- main entry point ----

    def predict_detailed(self, text: str,
                         recent_embeds: Optional[list] = None) -> Dict[str, float]:
        """Return ensemble probability plus per-signal breakdown.

        Keys:
          prob  – final ensemble score (0–1)
          heu   – combined heuristic (formality + Llama patterns + repetition
                  + burstiness + lexical diversity + punctuation + function words)
          llama – raw Llama-specific pattern sub-score (0–1)
          bino  – Binoculars perplexity ratio score (0–1)
          cls   – average classifier score across all loaded models (0–1)
          adv   – adversarial-evasion score (char n-gram entropy + spacing) (0–1)
          embed – embedding-variance score (0–1); needs recent_embeds
          styl  – stylometric score (burstiness + lexical diversity + punctuation)
          wm    – watermark detection score (0–1)

        All values 0–1; higher = more likely AI-generated.
        Results are LRU-cached (up to _CACHE_MAX entries).
        """
        _zero: Dict[str, float] = {
            "prob": 0.0, "heu": 0.0, "llama": 0.0,
            "bino": 0.0, "cls": 0.0, "adv": 0.0, "embed": 0.0,
            "styl": 0.0, "watermark": 0.0}
        if not self.enabled:
            return _zero
        text = text.strip()
        if not text:
            return _zero

        cached = self._pred_cache.get(text)
        if cached is not None:
            try:
                self._pred_cache.move_to_end(text)
            except KeyError:
                pass  # evicted by a concurrent thread between get() and move_to_end()
            return cached  # type: ignore[return-value]

        # Reasoning-model CoT leakage: <think>...</think> tags from Qwen3 / DeepSeek-R1
        # bleeding into chat are unambiguous AI evidence — skip all other scoring.
        if re.search(r'</?think\b', text, re.IGNORECASE):
            _certain: Dict[str, float] = {
                "prob": 1.0, "heu": 1.0, "llama": 1.0,
                "bino": 1.0, "cls": 1.0, "adv": 1.0, "embed": 0.0,
                "styl": 1.0, "watermark": 1.0}
            if len(self._pred_cache) >= self._CACHE_MAX:
                self._pred_cache.popitem(last=False)
            self._pred_cache[text] = _certain
            return _certain

        llama = self.llama_pattern_score(text)
        heu   = self._heuristic_score(text)
        bino  = self._binoculars_score(text)
        cls   = self._classifier_score(text)
        adv   = self._adversarial_score(text)
        embed = self._embedding_variance_score(text, recent_embeds or [])
        wm    = self.watermark_score(text)

        # Stylometric composite: burstiness + lexical diversity + punctuation
        # These capture structural writing patterns independent of vocabulary
        burst   = 1.0 - self._burstiness(text)
        lex_div = 1.0 - self._lexical_diversity(text)
        punct   = self._punctuation_anomaly(text)
        func_w  = self._function_word_ratio(text)
        opener  = 1.0 - self._sentence_openers_variety(text)
        styl    = max(0.0, min(1.0,
            0.30 * burst
            + 0.25 * lex_div
            + 0.20 * punct
            + 0.15 * func_w
            + 0.10 * opener
        ))

        # Adaptive ensemble: ML models are unreliable on short IRC messages
        # (< 8 words) — weight heuristics much higher there.  For long text
        # (>= 30 words) Binoculars and the classifiers become more trustworthy.
        n_words = len(text.split())
        if n_words < 8:
            prob = max(0.0, min(1.0, 0.10 * bino + 0.10 * cls + 0.65 * heu + 0.15 * styl))
        elif n_words < 30:
            prob = max(0.0, min(1.0, 0.30 * bino + 0.30 * cls + 0.25 * heu + 0.15 * styl))
        else:
            prob = max(0.0, min(1.0, 0.32 * bino + 0.32 * cls + 0.20 * heu + 0.16 * styl))

        # High-confidence override: unambiguous Llama structural output in short
        # IRC messages should score high even when ML signals are uncertain.
        if llama >= 0.60 and prob < 0.55:
            prob = min(1.0, prob * 0.5 + llama * 0.5)

        # Stylometric override: strong structural anomalies push score up
        if styl >= 0.55 and prob < 0.50:
            prob = min(1.0, prob + 0.4 * styl * (1.0 - prob))

        # Adversarial-evasion override: strong spacing/entropy anomalies push
        # the score upward regardless of the main ensemble.
        if adv >= 0.40:
            prob = min(1.0, prob + 0.6 * adv * (1.0 - prob))

        # Embedding-variance boost: add up to +0.08 when the text is unusually
        # consistent with the user's own recent style.
        if embed > 0.0:
            prob = min(1.0, prob + 0.08 * embed)

        # Watermark-detection boost: add up to +0.12 when watermark patterns found
        if wm > 0.0:
            prob = min(1.0, prob + 0.12 * wm)

        result: Dict[str, float] = {
            "prob": prob, "heu": heu, "llama": llama, "bino": bino,
            "cls": cls, "adv": adv, "embed": embed, "styl": styl, "watermark": wm}

        if len(self._pred_cache) >= self._CACHE_MAX:
            self._pred_cache.popitem(last=False)   # O(1) FIFO eviction
        self._pred_cache[text] = result
        return result

    def predict_prob(self, text: str) -> float:
        """Convenience wrapper — returns only the ensemble probability (0–1)."""
        return self.predict_detailed(text)["prob"]

    # ---- watermark detection (Area 5) ----

    def watermark_score(self, text: str) -> float:
        """Detect common LLM watermark patterns.  Returns 0..1.

        Checks:
          • Duplicate-token watermark (repeated function words / high-frequency
            tokens at suspiciously regular intervals)
          • Green-red list bias (unusual token-frequency distribution)
          • Structural watermarks (uniform sentence length, low positional entropy)
        """
        if not text or len(text) < 10:
            return 0.0
        score = 0.0
        words = text.lower().split()
        n_words = len(words)
        if n_words < 5:
            return 0.0

        # ── Duplicate-token watermark ────────────────────────────────────────
        # Some watermarking schemes bias toward repeating high-frequency tokens.
        # Detect by counting function-word repeats at 3–7 token intervals.
        _func_words = frozenset({
            "the", "a", "an", "of", "to", "in", "is", "that", "for", "it",
            "on", "and", "be", "or", "as", "at", "by", "with", "this", "are",
            "was", "were", "been", "has", "have", "had", "do", "does", "did",
            "will", "would", "can", "could", "may", "might", "shall", "should",
            "not", "no", "so", "if", "than", "then", "but", "because", "we",
        })
        func_positions = [i for i, w in enumerate(words) if w in _func_words]
        if len(func_positions) >= 6:
            gaps = [func_positions[i+1] - func_positions[i]
                    for i in range(len(func_positions)-1)]
            if gaps:
                mean_gap = sum(gaps) / len(gaps)
                low_var = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
                cv = (low_var ** 0.5) / max(mean_gap, 1)
                # Suspiciously regular function-word spacing → watermark
                if cv < 0.30 and mean_gap <= 7:
                    score += 0.25

        # ── Green-red token bias ─────────────────────────────────────────────
        # Watermarked text tends to have an unusually uniform token-frequency
        # rank distribution (too many "medium-rare" tokens, too few rare ones).
        if n_words >= 10:
            wf: Counter = Counter()
            for w in words:
                wf[w] += 1
            freqs = sorted(wf.values(), reverse=True)
            if len(freqs) >= 5:
                top3 = sum(freqs[:3])
                rare = sum(freqs[3:])
                total_f = sum(freqs)
                top3_ratio = top3 / total_f if total_f else 0
                # Human text: top-3 words account for ~15–35% of tokens.
                # Watermarked: more uniform → top-3 ratio < 15% or > 45%.
                if top3_ratio < 0.15:
                    score += 0.15
                elif top3_ratio > 0.45:
                    score += 0.10

        # ── Sentence-length uniformity ───────────────────────────────────────
        # Watermarked prose often has very uniform sentence lengths.
        sentences = re.split(r'[.!?]+', text)
        sent_lens = [len(s.split()) for s in sentences if len(s.split()) >= 2]
        if len(sent_lens) >= 4:
            m_sl = sum(sent_lens) / len(sent_lens)
            v_sl = sum((sl - m_sl) ** 2 for sl in sent_lens) / len(sent_lens)
            cv_sl = (v_sl ** 0.5) / max(m_sl, 1)
            if cv_sl < 0.25:
                score += 0.20

        return min(1.0, score)

    # ---- LoRA incremental fine-tuning (Area 7) ----

    def _init_lora(self) -> bool:
        """Attempt to prepare a LoRA adapter on cls1.  Returns True if ready."""
        if self._cls_model is None:
            return False
        try:
            from peft import LoraConfig, get_peft_model, TaskType
            if getattr(self, "_lora_peft_config", None) is None:
                self._lora_peft_config = LoraConfig(
                    task_type=TaskType.SEQ_CLS,
                    r=8,
                    lora_alpha=16,
                    lora_dropout=0.05,
                    target_modules=["query", "value"],
                )
                self._lora_model = get_peft_model(self._cls_model, self._lora_peft_config)
                self._lora_model.to(self._device)
            return True
        except ImportError:
            return False

    def _train_lora_adapter(self, positive_texts: List[str], negative_texts: List[str],
                             output_path: str, epochs: int = 3) -> str:
        """Fine-tune the LoRA adapter on positive vs negative examples.

        Runs synchronously (call from a thread executor).  Returns the adapter
        path on success, or an error message on failure.
        """
        if not _PEFT_AVAILABLE or self._cls_tok is None:
            return "PEFT not available"
        if not self._init_lora():
            return "failed to init LoRA"
        # Limit PyTorch to 1 thread so BLAS doesn't starve the event loop
        _old_torch_threads = torch.get_num_threads()
        torch.set_num_threads(1)
        from torch.utils.data import DataLoader, TensorDataset
        texts = positive_texts + negative_texts
        labels = [1] * len(positive_texts) + [0] * len(negative_texts)
        if len(texts) < 4:
            return "need at least 4 examples (2 pos + 2 neg)"
        enc = self._cls_tok(texts, truncation=True, padding=True, max_length=128, return_tensors="pt")
        dataset = TensorDataset(enc["input_ids"], enc["attention_mask"], torch.tensor(labels))
        loader = DataLoader(dataset, batch_size=4, shuffle=True)
        opt = torch.optim.AdamW(self._lora_model.parameters(), lr=3e-5)
        self._lora_model.train()
        for epoch in range(epochs):
            for batch_ids, batch_mask, batch_labels in loader:
                batch_ids = batch_ids.to(self._device)
                batch_mask = batch_mask.to(self._device)
                batch_labels = batch_labels.to(self._device).float()
                out = self._lora_model(input_ids=batch_ids, attention_mask=batch_mask,
                                       labels=batch_labels.long())
                loss = out.loss
                opt.zero_grad()
                loss.backward()
                opt.step()
        self._lora_model.eval()
        try:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            self._lora_model.save_pretrained(output_path)
        except Exception as e:
            return f"save failed: {e}"
        finally:
            torch.set_num_threads(_old_torch_threads)
        self._lora_loaded = True
        return output_path

# =========================
# Sentiment Analysis
# =========================
_SENTIMENT_POSITIVE = frozenset({
    "happy", "glad", "great", "awesome", "amazing", "love", "like", "nice",
    "cool", "fun", "funny", "lol", "haha", "rofl", "lmao", "thanks", "thank",
    "appreciate", "helpful", "perfect", "excellent", "wonderful", "fantastic",
    "brilliant", "superb", "outstanding", "impressive", "beautiful", "good",
    "yes", "yeah", "yep", "sure", "ok", "okay", "agree", "correct", "right",
    "welcome", "congrats", "congratulations", "cheers", "gg", "wp", "well done",
    "excited", "thrilled", "delighted", "pleased", "satisfied", "joy", "joyful",
    "blessed", "grateful", "proud", "hope", "hopeful", "optimistic",
    "nice one", "good job", "well played", "noice", "based", "w", "fire",
    "goat", "legend", "king", "queen", "slay", "iconic", "vibes", "mood",
})
_SENTIMENT_NEGATIVE = frozenset({
    "hate", "angry", "mad", "annoyed", "frustrated", "terrible", "awful",
    "horrible", "bad", "worst", "stupid", "idiot", "dumb", "ugly", "fail",
    "failed", "broken", "sucks", "shit", "crap", "damn", "hell", "fucking",
    "no", "nope", "wrong", "disagree", "incorrect", "false", "lie", "lying",
    "scam", "fake", "trash", "garbage", "useless", "pointless", "waste",
    "disappointed", "disappointing", "sad", "unhappy", "miserable", "depressed",
    "frustrating", "annoying", "irritating", "boring", "tired", "exhausted",
    "confused", "lost", "helpless", "hopeless", "pessimistic", "angry",
    "toxic", "drama", "dramatic", "rude", "mean", "cruel", "harsh", "hostile",
    "l", "mid", "cringe", "ratio", "copium", "cope", "seethe", "mad", "salty",
    "triggered", "butthurt", "salty", "butthurt", "cry", "crying", "whine",
})
_SENTIMENT_INTENSIFIERS = frozenset({
    "very", "really", "super", "extremely", "absolutely", "totally", "completely",
    "utterly", "incredibly", "amazingly", "so", "such", "quite", "pretty",
    "highly", "deeply", "strongly", "seriously", "literally", "actually",
})
_SENTIMENT_NEGATORS = frozenset({
    "not", "no", "never", "neither", "nobody", "nothing", "nowhere",
    "don't", "doesn't", "didn't", "won't", "wouldn't", "can't", "cannot",
    "couldn't", "shouldn't", "isn't", "aren't", "wasn't", "weren't",
    "hardly", "barely", "scarcely", "without",
})

class SentimentAnalyzer:
    """Lightweight rule-based sentiment analysis for IRC messages.

    Returns a score in [-1.0, 1.0] where negative = hostile/negative,
    positive = friendly/positive, and 0 = neutral.
    """

    def analyze(self, text: str) -> Dict[str, float]:
        """Return sentiment breakdown for *text*.

        Keys:
          score   – overall sentiment [-1.0, 1.0]
          pos     – positive word count
          neg     – negative word count
          intensity – intensifier multiplier
          is_negated – whether negation was detected
        """
        words = [w.lower().strip(".,!?;:\"'()[]") for w in text.split()]
        if not words:
            return {"score": 0.0, "pos": 0, "neg": 0, "intensity": 1.0, "is_negated": False}

        pos_count = 0
        neg_count = 0
        intensity = 1.0
        negated = False

        for i, w in enumerate(words):
            if w in _SENTIMENT_INTENSIFIERS:
                intensity = min(2.0, intensity + 0.3)
            if w in _SENTIMENT_NEGATORS:
                negated = True
            if w in _SENTIMENT_POSITIVE:
                pos_count += 1
            if w in _SENTIMENT_NEGATIVE:
                neg_count += 1

        # Caps lock = emotional intensity
        if text.isupper() and len(text) > 3:
            intensity = min(2.0, intensity + 0.2)

        # Exclamation marks = intensity
        exclam = text.count("!")
        if exclam > 1:
            intensity = min(2.0, intensity + 0.1 * min(exclam, 5))

        # Question marks = uncertainty (slight negative bias)
        questions = text.count("?")
        if questions > 2:
            neg_count += 1

        raw_score = (pos_count - neg_count) * intensity
        max_possible = max(pos_count + neg_count, 1)
        score = max(-1.0, min(1.0, raw_score / max_possible))

        # Negation flips the polarity
        if negated:
            score = -score * 0.5

        return {
            "score": round(score, 3),
            "pos": pos_count,
            "neg": neg_count,
            "intensity": round(intensity, 2),
            "is_negated": negated,
        }

    def sentiment_label(self, score: float) -> str:
        if score >= 0.5:
            return "very positive"
        if score >= 0.2:
            return "positive"
        if score > -0.2:
            return "neutral"
        if score > -0.5:
            return "negative"
        return "very negative"


# =========================
# Behavioral Anomaly Detector
# =========================
class BehavioralAnomalyDetector:
    """Detects sudden changes in a user's behavioral patterns.

    Tracks:
      • Message length distribution
      • Sentiment distribution
      • Timing patterns (messages per minute)
      • Vocabulary richness
      • Punctuation usage

    Flags when a user's recent behavior deviates significantly from their
    historical baseline (z-score > 2.0).
    """

    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        self._user_profiles: Dict[str, Dict] = {}

    def _get_profile(self, nick: str) -> Dict:
        if nick not in self._user_profiles:
            self._user_profiles[nick] = {
                "msg_lengths": [],
                "sentiments": [],
                "gaps": [],
                "vocab_sizes": [],
                "punct_ratios": [],
                "last_ts": None,
                "anomaly_count": 0,
                "last_anomaly_ts": 0,
            }
        return self._user_profiles[nick]

    def update(self, nick: str, msg: str, sentiment_score: float) -> Dict[str, Any]:
        """Update user profile and return anomaly analysis.

        Returns dict with:
          anomaly_score – 0..1 (higher = more anomalous)
          changed_aspects – list of aspects that changed significantly
          explanation – human-readable summary
        """
        prof = self._get_profile(nick)
        now = time.time()

        # Compute current metrics
        msg_len = len(msg)
        words = msg.split()
        vocab_size = len(set(w.lower() for w in words))
        punct_count = sum(1 for c in msg if c in ".,!?;:\"'()[]-")
        punct_ratio = punct_count / max(len(msg), 1)

        # Timing gap
        gap = 0.0
        if prof["last_ts"] is not None:
            gap = now - prof["last_ts"]
        prof["last_ts"] = now

        # Update rolling windows
        prof["msg_lengths"].append(msg_len)
        prof["sentiments"].append(sentiment_score)
        prof["vocab_sizes"].append(vocab_size)
        prof["punct_ratios"].append(punct_ratio)
        if gap > 0:
            prof["gaps"].append(gap)

        # Trim to window size
        for key in ("msg_lengths", "sentiments", "vocab_sizes", "punct_ratios", "gaps"):
            if len(prof[key]) > self.window_size:
                prof[key] = prof[key][-self.window_size:]

        # Need at least 10 samples to detect anomalies
        if len(prof["msg_lengths"]) < 10:
            return {
                "anomaly_score": 0.0,
                "changed_aspects": [],
                "explanation": "Insufficient data for anomaly detection",
            }

        # Compute z-scores for each aspect
        anomalies = []
        _calc_z = lambda lst, val: self._z_score(lst, val)

        len_z = _calc_z(prof["msg_lengths"][:-1], msg_len)
        sent_z = _calc_z(prof["sentiments"][:-1], sentiment_score)
        vocab_z = _calc_z(prof["vocab_sizes"][:-1], vocab_size)
        punct_z = _calc_z(prof["punct_ratios"][:-1], punct_ratio)

        # Gap anomaly (sudden burst or long silence)
        gap_z = 0.0
        if len(prof["gaps"]) >= 5:
            gap_z = _calc_z(prof["gaps"][:-1], gap)

        # Threshold: z-score > 2.0 = significant deviation
        if abs(len_z) > 2.0:
            anomalies.append(f"message length {'dramatically longer' if len_z > 0 else 'much shorter'} than usual")
        if abs(sent_z) > 2.0:
            anomalies.append(f"sentiment {'unusually positive' if sent_z > 0 else 'much more negative'} than usual")
        if abs(vocab_z) > 2.0:
            anomalies.append(f"vocabulary {'much richer' if vocab_z > 0 else 'much simpler'} than usual")
        if abs(punct_z) > 2.0:
            anomalies.append(f"punctuation usage {'much higher' if punct_z > 0 else 'much lower'} than usual")
        if abs(gap_z) > 2.0:
            anomalies.append(f"timing {'sudden burst' if gap_z < 0 else 'long silence'} detected")

        # Composite anomaly score
        max_z = max(abs(len_z), abs(sent_z), abs(vocab_z), abs(punct_z), abs(gap_z))
        anomaly_score = min(1.0, max_z / 4.0)

        # Track anomaly frequency
        if anomaly_score > 0.5:
            prof["anomaly_count"] += 1
            prof["last_anomaly_ts"] = now

        explanation = ""
        if anomalies:
            explanation = f"{nick}: " + "; ".join(anomalies)

        return {
            "anomaly_score": round(anomaly_score, 3),
            "changed_aspects": anomalies,
            "explanation": explanation,
            "z_scores": {
                "length": round(len_z, 2),
                "sentiment": round(sent_z, 2),
                "vocabulary": round(vocab_z, 2),
                "punctuation": round(punct_z, 2),
                "timing": round(gap_z, 2),
            },
        }

    @staticmethod
    def _z_score(data: list, value: float) -> float:
        if len(data) < 2:
            return 0.0
        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        std = variance ** 0.5
        if std < 1e-6:
            return 0.0
        return (value - mean) / std


# =========================
# Topic Detector
# =========================
_TOPIC_KEYWORDS = {
    "programming": {"code", "bug", "debug", "function", "variable", "python", "javascript",
                    "typescript", "rust", "c++", "java", "api", "server", "database", "sql",
                    "git", "commit", "merge", "pull", "branch", "deploy", "docker", "kubernetes",
                    "linux", "windows", "macos", "compiler", "runtime", "library", "framework",
                    "react", "vue", "angular", "node", "npm", "pip", "cargo", "maven"},
    "gaming": {"game", "play", "player", "match", "win", "lose", "score", "level", "boss",
               "raid", "dungeon", "quest", "npc", "pvp", "pve", "mmorpg", "fps", "rpg",
               "steam", "epic", "xbox", "playstation", "nintendo", "switch", "pc", "console",
               "gg", "wp", "noob", "pro", "carry", "feed", "afk", "respawn", "loot", "drop"},
    "anime": {"anime", "manga", "otaku", "waifu", "husband", "senpai", "kawaii", "shonen",
              "shoujo", "seinen", "josei", "isekai", "mecha", "slice of life", "episode",
              "season", "arc", "filler", "canon", "studio", "gibli", "crunchyroll", "funimation",
              "naruto", "one piece", "attack on titan", "demon slayer", "jujutsu", "chainsaw"},
    "music": {"song", "album", "track", "band", "artist", "genre", "rock", "pop", "jazz",
              "classical", "hip hop", "rap", "metal", "electronic", "indie", "folk", "blues",
              "spotify", "apple music", "youtube music", "soundcloud", "bandcamp", "playlist",
              "listen", "hear", "lyrics", "vocals", "guitar", "piano", "drums", "bass"},
    "science": {"science", "physics", "chemistry", "biology", "math", "research", "experiment",
                "theory", "hypothesis", "data", "analysis", "study", "paper", "journal",
                "quantum", "relativity", "evolution", "genetics", "neuroscience", "astronomy",
                "planet", "star", "galaxy", "universe", "black hole", "dark matter"},
    "politics": {"politics", "government", "election", "vote", "president", "congress", "senate",
                 "democrat", "republican", "liberal", "conservative", "policy", "law", "bill",
                 "tax", "budget", "economy", "trade", "war", "peace", "diplomacy", "treaty"},
    "crypto": {"crypto", "bitcoin", "ethereum", "blockchain", "token", "nft", "defi", "wallet",
               "mining", "hash", "consensus", "proof of work", "proof of stake", "exchange",
               "bull", "bear", "hodl", "moon", "lambo", "whale", "diamond hands", "paper hands"},
    "health": {"health", "fitness", "exercise", "diet", "nutrition", "weight", "muscle", "cardio",
               "yoga", "meditation", "sleep", "stress", "anxiety", "depression", "doctor",
               "hospital", "medicine", "vitamin", "supplement", "workout", "gym", "run"},
    "food": {"food", "cook", "recipe", "restaurant", "meal", "breakfast", "lunch", "dinner",
             "snack", "dessert", "pizza", "sushi", "burger", "pasta", "salad", "soup",
             "vegan", "vegetarian", "keto", "paleo", "gluten free", "organic", "fresh"},
    "ai_ml": {"ai", "machine learning", "deep learning", "neural network", "model", "training",
              "inference", "dataset", "label", "feature", "accuracy", "precision", "recall",
              "transformer", "llm", "gpt", "claude", "gemini", "llama", "mistral", "qwen",
              "prompt", "token", "embedding", "vector", "attention", "fine-tune", "rlhf"},
}

class TopicDetector:
    """Detects topics in messages using keyword matching.

    Returns a list of (topic, confidence) pairs for each message.
    """

    def detect(self, text: str) -> List[Tuple[str, float]]:
        """Return list of (topic, confidence) for *text*.

        Confidence is 0..1 based on keyword density.
        """
        text_lower = text.lower()
        words = set(text_lower.split())
        results = []

        for topic, keywords in _TOPIC_KEYWORDS.items():
            hits = words & keywords
            if hits:
                confidence = min(1.0, len(hits) / max(len(keywords) * 0.1, 1))
                results.append((topic, round(confidence, 3)))

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:3]  # Return top 3 topics


# =========================
# Semantic Similarity Detector
# =========================
class SemanticSimilarityDetector:
    """Detects when users send semantically similar messages.

    Uses lightweight n-gram overlap and word set similarity to find
    potential copy-paste, bot coordination, or repeated spam.
    """

    def __init__(self, max_entries: int = 500):
        self.max_entries = max_entries
        self._message_history: deque = deque(maxlen=max_entries)

    def add_message(self, nick: str, text: str, channel: str) -> None:
        """Store a message for future similarity checks."""
        self._message_history.append({
            "nick": nick,
            "text": text.lower(),
            "words": set(text.lower().split()),
            "channel": channel,
            "ts": time.time(),
        })

    def find_similar(self, nick: str, text: str, threshold: float = 0.7) -> List[Dict]:
        """Find messages similar to *text* from other users.

        Returns list of matches with similarity scores.
        """
        text_lower = text.lower()
        words = set(text_lower.split())
        matches = []

        for entry in self._message_history:
            if entry["nick"] == nick:
                continue
            # Skip old messages (> 1 hour)
            if time.time() - entry["ts"] > 3600:
                continue

            # Jaccard similarity
            intersection = words & entry["words"]
            union = words | entry["words"]
            jaccard = len(intersection) / len(union) if union else 0

            # Exact substring match
            is_substring = (text_lower in entry["text"] or
                           entry["text"] in text_lower)

            score = max(jaccard, 0.9 if is_substring else 0)
            if score >= threshold:
                matches.append({
                    "nick": entry["nick"],
                    "text": entry["text"][:100],
                    "channel": entry["channel"],
                    "score": round(score, 3),
                    "type": "substring" if is_substring else "jaccard",
                })

        matches.sort(key=lambda x: x["score"], reverse=True)
        return matches[:5]


# =========================
# Conversation Thread Tracker
# =========================
class ThreadTracker:
    """Tracks conversation threads by detecting reply patterns.

    Uses:
      • IRCv3 +reply tags
      • Nick mentions at message start ("nick: ...")
      • Temporal proximity (messages within 30s of each other)
    """

    def __init__(self, max_threads: int = 100, max_thread_length: int = 50):
        self.max_threads = max_threads
        self.max_thread_length = max_thread_length
        self._threads: Dict[str, List[Dict]] = {}  # thread_id → messages
        self._active_threads: List[str] = []
        self._last_messages: Dict[str, Dict] = {}  # channel → last message

    def add_message(self, msgid: str, nick: str, target: str, text: str,
                    reply_to: str = "", ts: float = 0) -> Optional[str]:
        """Add a message and return thread_id if it belongs to a thread."""
        if not ts:
            ts = time.time()

        msg = {"msgid": msgid, "nick": nick, "text": text[:100], "ts": ts}

        # Explicit reply
        if reply_to:
            thread_id = self._find_thread_by_msgid(reply_to)
            if thread_id:
                self._threads[thread_id].append(msg)
                if len(self._threads[thread_id]) > self.max_thread_length:
                    self._threads[thread_id] = self._threads[thread_id][-self.max_thread_length:]
                return thread_id

        # Nick mention at start
        colon = text.find(":")
        comma = text.find(",")
        end = min(colon, comma) if colon >= 0 and comma >= 0 else max(colon, comma)
        if end > 0:
            mentioned = text[:end].strip().lower()
            thread_id = self._find_thread_by_nick(mentioned, target)
            if thread_id:
                self._threads[thread_id].append(msg)
                return thread_id

        # Temporal proximity (within 30s of last message in channel)
        last = self._last_messages.get(target)
        if last and ts - last["ts"] < 30:
            thread_id = last.get("thread_id")
            if thread_id and thread_id in self._threads:
                self._threads[thread_id].append(msg)
                msg["thread_id"] = thread_id
                self._last_messages[target] = msg
                return thread_id

        # Start new thread
        thread_id = f"thread_{msgid or hash(text)}"
        self._threads[thread_id] = [msg]
        msg["thread_id"] = thread_id
        self._last_messages[target] = msg
        self._active_threads.append(thread_id)

        # Trim old threads
        if len(self._active_threads) > self.max_threads:
            old = self._active_threads.pop(0)
            self._threads.pop(old, None)

        return thread_id

    def _find_thread_by_msgid(self, msgid: str) -> Optional[str]:
        for tid, msgs in self._threads.items():
            for m in msgs:
                if m.get("msgid") == msgid:
                    return tid
        return None

    def _find_thread_by_nick(self, nick: str, channel: str) -> Optional[str]:
        for tid, msgs in self._threads.items():
            if msgs and msgs[-1].get("nick", "").lower() == nick:
                return tid
        return None

    def get_thread(self, thread_id: str) -> Optional[List[Dict]]:
        return self._threads.get(thread_id)

    def get_active_threads(self, channel: str = "", limit: int = 10) -> List[Dict]:
        """Return summary of active threads."""
        results = []
        for tid in reversed(self._active_threads):
            msgs = self._threads.get(tid, [])
            if not msgs:
                continue
            participants = list(set(m["nick"] for m in msgs))
            results.append({
                "thread_id": tid,
                "participants": participants,
                "message_count": len(msgs),
                "started": msgs[0]["ts"],
                "last_msg": msgs[-1]["ts"],
                "topic": msgs[0]["text"][:80],
            })
            if len(results) >= limit:
                break
        return results


# =========================
# Cross-Channel Bot Detector
# =========================
class CrossChannelBotDetector:
    """Detects bots that operate across multiple channels.

    Correlates:
      • Identical messages sent to multiple channels
      • Similar timing patterns across channels
      • Shared vocabulary fingerprints
    """

    def __init__(self):
        self._nick_channels: Dict[str, set] = {}
        self._nick_messages: Dict[str, deque] = {}
        self._cross_channel_alerts: List[Dict] = []

    def record_message(self, nick: str, channel: str, text: str) -> Optional[Dict]:
        """Record a message and check for cross-channel coordination.

        Returns alert dict if suspicious activity detected.
        """
        self._nick_channels.setdefault(nick, set()).add(channel)
        if nick not in self._nick_messages:
            self._nick_messages[nick] = deque(maxlen=200)
        self._nick_messages[nick].append({
            "channel": channel,
            "text": text.lower(),
            "ts": time.time(),
        })

        # Check for identical messages in different channels
        channels = self._nick_channels[nick]
        if len(channels) < 2:
            return None

        msgs = self._nick_messages[nick]
        recent = [m for m in msgs if time.time() - m["ts"] < 300]  # 5 min window

        # Group by text
        text_channels: Dict[str, set] = {}
        for m in recent:
            text_channels.setdefault(m["text"], set()).add(m["channel"])

        for text, chs in text_channels.items():
            if len(chs) >= 2:
                alert = {
                    "nick": nick,
                    "type": "identical_cross_channel",
                    "channels": sorted(chs),
                    "message": text[:100],
                    "ts": time.time(),
                }
                self._cross_channel_alerts.append(alert)
                return alert

        return None

    def get_suspicious_nicks(self, min_channels: int = 3) -> List[Dict]:
        """Return nicks active in many channels with suspicious patterns."""
        results = []
        for nick, channels in self._nick_channels.items():
            if len(channels) >= min_channels:
                msgs = self._nick_messages.get(nick, [])
                results.append({
                    "nick": nick,
                    "channels": sorted(channels),
                    "message_count": len(msgs),
                    "alerts": sum(1 for a in self._cross_channel_alerts if a["nick"] == nick),
                })
        results.sort(key=lambda x: x["alerts"], reverse=True)
        return results


# =========================
# Productivity Features
# =========================

# ── Reminder System ─────────────────────────────────────────────────────────
_REMINDER_PATH = os.path.join(_SCRIPT_DIR, "reminders.json")

class ReminderManager:
    """Manages user reminders with persistent storage.

    Supports:
      • Time-based reminders: "in 30m", "at 14:30", "tomorrow at 9am"
      • Message-based reminders: "remind me to check #channel"
      • Channel-specific reminders
    """

    def __init__(self):
        self._reminders: List[Dict] = []
        self._load()

    def _load(self) -> None:
        try:
            with open(_REMINDER_PATH, "r", encoding="utf-8") as f:
                self._reminders = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            self._reminders = []

    def _save(self) -> None:
        try:
            with open(_REMINDER_PATH, "w", encoding="utf-8") as f:
                json.dump(self._reminders, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def parse_time(self, time_str: str) -> Optional[float]:
        """Parse time string and return absolute timestamp.

        Supports:
          • "in 30m", "in 2h", "in 1d"
          • "at 14:30", "at 3pm"
          • "tomorrow at 9am"
          • "next monday"
        """
        now = time.time()
        time_str = time_str.strip().lower()

        # "in X" format
        in_match = re.match(r'^in\s+(\d+)\s*(s|m|h|d|w)$', time_str)
        if in_match:
            val = int(in_match.group(1))
            unit = in_match.group(2)
            multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
            return now + val * multipliers[unit]

        # "at HH:MM" format
        at_match = re.match(r'^at\s+(\d{1,2}):(\d{2})$', time_str)
        if at_match:
            hour = int(at_match.group(1))
            minute = int(at_match.group(2))
            target = now
            # If time is in the past, schedule for tomorrow
            from datetime import datetime
            dt = datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0)
            if dt.timestamp() <= now:
                dt = dt.replace(day=dt.day + 1)
            return dt.timestamp()

        # "tomorrow at HH:MM" format
        tomorrow_match = re.match(r'^tomorrow\s+at\s+(\d{1,2}):(\d{2})$', time_str)
        if tomorrow_match:
            hour = int(tomorrow_match.group(1))
            minute = int(tomorrow_match.group(2))
            from datetime import datetime, timedelta
            dt = datetime.now().replace(hour=hour, minute=minute, second=0, microsecond=0) + timedelta(days=1)
            return dt.timestamp()

        # "at Xam/pm" format
        ampm_match = re.match(r'^at\s+(\d{1,2})(am|pm)$', time_str)
        if ampm_match:
            hour = int(ampm_match.group(1))
            ampm = ampm_match.group(2)
            if ampm == "pm" and hour != 12:
                hour += 12
            elif ampm == "am" and hour == 12:
                hour = 0
            from datetime import datetime
            dt = datetime.now().replace(hour=hour, minute=0, second=0, microsecond=0)
            if dt.timestamp() <= now:
                dt = dt.replace(day=dt.day + 1)
            return dt.timestamp()

        return None

    def add_reminder(self, nick: str, time_str: str, message: str, channel: str = "") -> Optional[Dict]:
        """Add a reminder. Returns reminder dict or None if time parsing fails."""
        ts = self.parse_time(time_str)
        if ts is None:
            return None

        reminder = {
            "id": f"rem_{int(time.time())}_{hash(nick + message) % 10000}",
            "nick": nick,
            "time": ts,
            "message": message,
            "channel": channel,
            "created": time.time(),
            "fired": False,
        }
        self._reminders.append(reminder)
        self._save()
        return reminder

    def get_pending(self, nick: str = "") -> List[Dict]:
        """Get pending reminders, optionally filtered by nick."""
        now = time.time()
        pending = [r for r in self._reminders if not r["fired"] and r["time"] > now]
        if nick:
            pending = [r for r in pending if r["nick"].lower() == nick.lower()]
        pending.sort(key=lambda r: r["time"])
        return pending

    def get_due(self) -> List[Dict]:
        """Get reminders that are due now."""
        now = time.time()
        due = [r for r in self._reminders if not r["fired"] and r["time"] <= now]
        return due

    def mark_fired(self, reminder_id: str) -> None:
        """Mark a reminder as fired."""
        for r in self._reminders:
            if r["id"] == reminder_id:
                r["fired"] = True
                break
        self._save()

    def cancel(self, reminder_id: str) -> bool:
        """Cancel a reminder. Returns True if found."""
        for r in self._reminders:
            if r["id"] == reminder_id:
                r["fired"] = True
                self._save()
                return True
        return False

    def clear_old(self, max_age_days: int = 7) -> int:
        """Remove fired reminders older than max_age_days. Returns count removed."""
        cutoff = time.time() - max_age_days * 86400
        before = len(self._reminders)
        self._reminders = [r for r in self._reminders if not r["fired"] or r["time"] > cutoff]
        removed = before - len(self._reminders)
        if removed > 0:
            self._save()
        return removed

    def list_all(self, nick: str = "") -> List[Dict]:
        """List all reminders for a nick, or all if nick is empty."""
        reminders = self._reminders
        if nick:
            reminders = [r for r in reminders if r["nick"].lower() == nick.lower()]
        reminders.sort(key=lambda r: r["time"])
        return reminders


# ── Nick Watch System ───────────────────────────────────────────────────────
_WATCH_PATH = os.path.join(_SCRIPT_DIR, "nick_watches.json")

class NickWatchManager:
    """Watches for specific nicks and alerts when they join/speak.

    Supports:
      • Watch for nick joins
      • Watch for nick speaks in specific channels
      • Watch for nick mentions
      • Custom alert messages
    """

    def __init__(self):
        self._watches: Dict[str, Dict] = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(_WATCH_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._watches = data
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            self._watches = {}

    def _save(self) -> None:
        try:
            with open(_WATCH_PATH, "w", encoding="utf-8") as f:
                json.dump(self._watches, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def add_watch(self, nick: str, watcher: str, events: List[str] = None,
                  channels: List[str] = None, message: str = "") -> Dict:
        """Add a watch for a nick.

        events: ["join", "speak", "mention"] (default: all)
        channels: list of channels to watch (default: all)
        message: custom alert message
        """
        key = f"{watcher.lower()}:{nick.lower()}"
        self._watches[key] = {
            "nick": nick,
            "watcher": watcher,
            "events": events or ["join", "speak", "mention"],
            "channels": channels or [],
            "message": message,
            "created": time.time(),
            "triggers": 0,
            "last_trigger": 0,
        }
        self._save()
        return self._watches[key]

    def remove_watch(self, watcher: str, nick: str) -> bool:
        """Remove a watch. Returns True if found."""
        key = f"{watcher.lower()}:{nick.lower()}"
        if key in self._watches:
            del self._watches[key]
            self._save()
            return True
        return False

    def get_watches(self, watcher: str) -> List[Dict]:
        """Get all watches for a user."""
        return [w for w in self._watches.values() if w["watcher"].lower() == watcher.lower()]

    def check_event(self, event_type: str, nick: str, channel: str = "") -> List[Dict]:
        """Check if an event triggers any watches. Returns list of triggered watches."""
        triggered = []
        for key, watch in self._watches.items():
            if watch["nick"].lower() != nick.lower():
                continue
            if event_type not in watch["events"]:
                continue
            if watch["channels"] and channel and channel not in watch["channels"]:
                continue
            # Rate limit: max 1 trigger per 5 minutes
            if time.time() - watch.get("last_trigger", 0) < 300:
                continue
            watch["triggers"] += 1
            watch["last_trigger"] = time.time()
            triggered.append(watch)
        if triggered:
            self._save()
        return triggered

    def list_all(self) -> List[Dict]:
        """List all active watches."""
        return list(self._watches.values())


# ── Snippet Manager ─────────────────────────────────────────────────────────
_SNIPPET_PATH = os.path.join(_SCRIPT_DIR, "snippets.json")

class SnippetManager:
    """Manages text snippets for quick insertion.

    Supports:
      • Named snippets: /snippet add greeting Hello, welcome to the channel!
      • Tagged snippets for organization
      • Quick insertion via /snippet use <name> or $name
      • Snippet history and usage tracking
    """

    def __init__(self):
        self._snippets: Dict[str, Dict] = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(_SNIPPET_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._snippets = data
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            self._snippets = {}

    def _save(self) -> None:
        try:
            with open(_SNIPPET_PATH, "w", encoding="utf-8") as f:
                json.dump(self._snippets, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def add(self, name: str, text: str, tags: List[str] = None, user: str = "") -> Dict:
        """Add a snippet."""
        name = name.lower()
        self._snippets[name] = {
            "name": name,
            "text": text,
            "tags": tags or [],
            "user": user,
            "created": time.time(),
            "use_count": 0,
            "last_used": 0,
        }
        self._save()
        return self._snippets[name]

    def get(self, name: str) -> Optional[Dict]:
        """Get a snippet by name."""
        return self._snippets.get(name.lower())

    def use(self, name: str) -> Optional[str]:
        """Use a snippet and return its text. Updates usage stats."""
        snippet = self.get(name)
        if snippet:
            snippet["use_count"] += 1
            snippet["last_used"] = time.time()
            self._save()
            return snippet["text"]
        return None

    def remove(self, name: str) -> bool:
        """Remove a snippet. Returns True if found."""
        name = name.lower()
        if name in self._snippets:
            del self._snippets[name]
            self._save()
            return True
        return False

    def search(self, query: str) -> List[Dict]:
        """Search snippets by name, text, or tags."""
        query = query.lower()
        results = []
        for name, snippet in self._snippets.items():
            if (query in name or
                query in snippet["text"].lower() or
                any(query in tag.lower() for tag in snippet["tags"])):
                results.append(snippet)
        results.sort(key=lambda s: s["use_count"], reverse=True)
        return results

    def list_all(self, tag: str = "") -> List[Dict]:
        """List all snippets, optionally filtered by tag."""
        snippets = list(self._snippets.values())
        if tag:
            snippets = [s for s in snippets if tag.lower() in [t.lower() for t in s["tags"]]]
        snippets.sort(key=lambda s: s["name"])
        return snippets

    def expand_snippets_in_text(self, text: str) -> str:
        """Expand $name patterns in text with snippet content."""
        def replace_match(m):
            name = m.group(1)
            snippet = self.get(name)
            return snippet["text"] if snippet else m.group(0)
        return re.sub(r'\$(\w+)', replace_match, text)


# ── Channel Statistics ──────────────────────────────────────────────────────
class ChannelStatsTracker:
    """Tracks per-channel activity statistics.

    Provides:
      • Message counts per user
      • Activity heatmap (hour of day)
      • Top talkers
      • Message length statistics
      • Active hours detection
    """

    def __init__(self, max_channels: int = 50):
        self.max_channels = max_channels
        self._channels: Dict[str, Dict] = {}

    def _get_channel(self, channel: str) -> Dict:
        if channel not in self._channels:
            self._channels[channel] = {
                "users": {},
                "hourly": [0] * 24,
                "total_msgs": 0,
                "first_msg": time.time(),
                "last_msg": 0,
                "msg_lengths": [],
            }
            # Trim oldest channels if over limit
            if len(self._channels) > self.max_channels:
                oldest = min(self._channels.items(), key=lambda x: x[1]["last_msg"])
                del self._channels[oldest[0]]
        return self._channels[channel]

    def record_message(self, channel: str, nick: str, msg: str) -> None:
        """Record a message for statistics."""
        ch = self._get_channel(channel)
        ch["total_msgs"] += 1
        ch["last_msg"] = time.time()

        # User stats
        if nick not in ch["users"]:
            ch["users"][nick] = {
                "msgs": 0,
                "total_chars": 0,
                "first_msg": time.time(),
                "last_msg": 0,
                "hours": [0] * 24,
            }
        user = ch["users"][nick]
        user["msgs"] += 1
        user["total_chars"] += len(msg)
        user["last_msg"] = time.time()

        # Hourly tracking
        hour = time.localtime().tm_hour
        ch["hourly"][hour] += 1
        user["hours"][hour] += 1

        # Message length tracking (keep last 1000)
        ch["msg_lengths"].append(len(msg))
        if len(ch["msg_lengths"]) > 1000:
            ch["msg_lengths"] = ch["msg_lengths"][-1000:]

    def get_top_talkers(self, channel: str, limit: int = 10) -> List[Dict]:
        """Get top talkers in a channel."""
        ch = self._channels.get(channel)
        if not ch:
            return []
        users = sorted(ch["users"].items(), key=lambda x: x[1]["msgs"], reverse=True)
        results = []
        for nick, stats in users[:limit]:
            avg_len = stats["total_chars"] / stats["msgs"] if stats["msgs"] else 0
            results.append({
                "nick": nick,
                "msgs": stats["msgs"],
                "avg_len": round(avg_len, 1),
                "first_msg": stats["first_msg"],
                "last_msg": stats["last_msg"],
            })
        return results

    def get_heatmap(self, channel: str) -> List[int]:
        """Get hourly activity heatmap for a channel."""
        ch = self._channels.get(channel)
        return ch["hourly"] if ch else [0] * 24

    def get_active_hours(self, channel: str, threshold: float = 0.5) -> List[int]:
        """Get hours with activity above threshold (relative to peak)."""
        hourly = self.get_heatmap(channel)
        if not hourly or max(hourly) == 0:
            return []
        peak = max(hourly)
        return [h for h, count in enumerate(hourly) if count >= peak * threshold]

    def get_stats(self, channel: str) -> Dict:
        """Get comprehensive stats for a channel."""
        ch = self._channels.get(channel)
        if not ch:
            return {}
        lengths = ch["msg_lengths"]
        return {
            "total_msgs": ch["total_msgs"],
            "unique_users": len(ch["users"]),
            "first_msg": ch["first_msg"],
            "last_msg": ch["last_msg"],
            "avg_msg_len": round(sum(lengths) / len(lengths), 1) if lengths else 0,
            "max_msg_len": max(lengths) if lengths else 0,
            "min_msg_len": min(lengths) if lengths else 0,
            "top_talkers": self.get_top_talkers(channel, 5),
            "active_hours": self.get_active_hours(channel),
        }


# ── RSS Feed Bridge ─────────────────────────────────────────────────────────
_RSS_PATH = os.path.join(_SCRIPT_DIR, "rss_feeds.json")
_RSS_CACHE: Dict[str, Dict] = {}  # url → {entries, last_fetch, etag}

class RSSFeedBridge:
    """Bridges RSS feeds to IRC channels.

    Supports:
      • Multiple feeds per channel
      • Configurable poll intervals
      • Entry filtering by keywords
      • Feed entry caching to avoid duplicates
    """

    def __init__(self):
        self._feeds: List[Dict] = []
        self._load()

    def _load(self) -> None:
        try:
            with open(_RSS_PATH, "r", encoding="utf-8") as f:
                self._feeds = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            self._feeds = []

    def _save(self) -> None:
        try:
            with open(_RSS_PATH, "w", encoding="utf-8") as f:
                json.dump(self._feeds, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def add_feed(self, url: str, channel: str, interval: int = 300,
                 keywords: List[str] = None, title: str = "") -> Dict:
        """Add an RSS feed.

        interval: seconds between polls (default: 300 = 5 min)
        keywords: only post entries containing these words (default: all)
        """
        feed = {
            "id": f"rss_{hash(url) % 100000}",
            "url": url,
            "channel": channel,
            "interval": interval,
            "keywords": keywords or [],
            "title": title or url,
            "enabled": True,
            "last_fetch": 0,
            "last_entry": "",
            "error_count": 0,
        }
        self._feeds.append(feed)
        self._save()
        return feed

    def remove_feed(self, feed_id: str) -> bool:
        """Remove a feed by ID."""
        before = len(self._feeds)
        self._feeds = [f for f in self._feeds if f["id"] != feed_id]
        if len(self._feeds) < before:
            self._save()
            return True
        return False

    def get_feeds(self, channel: str = "") -> List[Dict]:
        """Get feeds, optionally filtered by channel."""
        if channel:
            return [f for f in self._feeds if f["channel"] == channel]
        return self._feeds

    def toggle_feed(self, feed_id: str) -> bool:
        """Toggle a feed's enabled status."""
        for f in self._feeds:
            if f["id"] == feed_id:
                f["enabled"] = not f["enabled"]
                self._save()
                return f["enabled"]
        return False

    def get_due_feeds(self) -> List[Dict]:
        """Get feeds that are due for polling."""
        now = time.time()
        return [f for f in self._feeds if f["enabled"] and now - f["last_fetch"] >= f["interval"]]

    def mark_fetched(self, feed_id: str, last_entry: str = "") -> None:
        """Mark a feed as fetched."""
        for f in self._feeds:
            if f["id"] == feed_id:
                f["last_fetch"] = time.time()
                if last_entry:
                    f["last_entry"] = last_entry
                f["error_count"] = 0
                break
        self._save()

    def mark_error(self, feed_id: str) -> None:
        """Increment error count for a feed."""
        for f in self._feeds:
            if f["id"] == feed_id:
                f["error_count"] += 1
                break
        self._save()

    def _parse_feed_blocking(self, url: str) -> List[Dict]:
        """Fetch and parse an RSS/Atom feed. Returns list of entries."""
        try:
            import xml.etree.ElementTree as ET
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (compatible; eyearesee/1.0; RSS Bot)",
            })
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read(524288)  # 512 KB max
            text = raw.decode("utf-8", errors="replace")
            root = ET.fromstring(text)

            entries = []
            # RSS 2.0
            if root.tag == "rss":
                for item in root.findall(".//item"):
                    title = item.findtext("title", "")
                    link = item.findtext("link", "")
                    desc = item.findtext("description", "")
                    # Strip HTML tags from description
                    desc = re.sub(r'<[^>]+>', '', desc)[:200]
                    entries.append({
                        "title": title,
                        "link": link,
                        "description": desc,
                    })
            # Atom
            elif "feed" in root.tag:
                ns = {"atom": "http://www.w3.org/2005/Atom"}
                for entry in root.findall("atom:entry", ns):
                    title = entry.findtext("atom:title", "", ns)
                    link_el = entry.find("atom:link", ns)
                    link = link_el.get("href", "") if link_el is not None else ""
                    summary = entry.findtext("atom:summary", "", ns)
                    summary = re.sub(r'<[^>]+>', '', summary)[:200]
                    entries.append({
                        "title": title,
                        "link": link,
                        "description": summary,
                    })
            return entries
        except Exception:
            return []

    async def fetch_new_entries(self, feed: Dict) -> List[Dict]:
        """Fetch new entries from a feed. Returns list of new entries."""
        loop = asyncio.get_running_loop()
        entries = await loop.run_in_executor(
            None, self._parse_feed_blocking, feed["url"])

        if not entries:
            self.mark_error(feed["id"])
            return []

        self.mark_fetched(feed["id"], entries[0].get("link", ""))

        # Filter by keywords
        if feed["keywords"]:
            keywords = [k.lower() for k in feed["keywords"]]
            entries = [e for e in entries if any(
                k in e["title"].lower() or k in e["description"].lower()
                for k in keywords)]

        # Filter out already seen entries
        last_entry = feed.get("last_entry", "")
        if last_entry:
            seen = False
            new_entries = []
            for e in entries:
                if e.get("link") == last_entry:
                    seen = True
                    continue
                if not seen:
                    new_entries.append(e)
            entries = new_entries

        return entries[:5]  # Max 5 new entries per poll


# ── Todo List ────────────────────────────────────────────────────────────────
_TODO_PATH = os.path.join(_SCRIPT_DIR, "todos.json")

class TodoManager:
    """Persistent todo list with priority, due dates, and completion tracking.

    Supports:
      • Priority levels: low, medium, high, urgent
      • Optional due dates
      • Tags for categorisation
      • Completion tracking with timestamps
      • Multiple lists (per-channel or global)
    """

    def __init__(self):
        self._todos: List[Dict] = []
        self._load()

    def _load(self) -> None:
        try:
            with open(_TODO_PATH, "r", encoding="utf-8") as f:
                self._todos = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            self._todos = []

    def _save(self) -> None:
        try:
            with open(_TODO_PATH, "w", encoding="utf-8") as f:
                json.dump(self._todos, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def add(self, text: str, priority: str = "medium", due: str = "",
            tags: List[str] = None, channel: str = "") -> Dict:
        priority = priority.lower()
        if priority not in ("low", "medium", "high", "urgent"):
            priority = "medium"
        todo = {
            "id": f"t_{int(time.time())}_{random.randint(0,9999):04d}",
            "text": text,
            "priority": priority,
            "due": due,
            "tags": tags or [],
            "channel": channel,
            "created": time.time(),
            "completed": False,
            "completed_at": None,
        }
        self._todos.append(todo)
        self._save()
        return todo

    def complete(self, todo_id: str) -> Optional[Dict]:
        for t in self._todos:
            if t["id"] == todo_id and not t["completed"]:
                t["completed"] = True
                t["completed_at"] = time.time()
                self._save()
                return t
        return None

    def uncomplete(self, todo_id: str) -> Optional[Dict]:
        for t in self._todos:
            if t["id"] == todo_id and t["completed"]:
                t["completed"] = False
                t["completed_at"] = None
                self._save()
                return t
        return None

    def remove(self, todo_id: str) -> bool:
        before = len(self._todos)
        self._todos = [t for t in self._todos if t["id"] != todo_id]
        if len(self._todos) < before:
            self._save()
            return True
        return False

    def edit(self, todo_id: str, text: str = None, priority: str = None,
             due: str = None, tags: List[str] = None) -> Optional[Dict]:
        for t in self._todos:
            if t["id"] == todo_id:
                if text is not None:
                    t["text"] = text
                if priority is not None:
                    p = priority.lower()
                    if p in ("low", "medium", "high", "urgent"):
                        t["priority"] = p
                if due is not None:
                    t["due"] = due
                if tags is not None:
                    t["tags"] = tags
                self._save()
                return t
        return None

    def list_todos(self, channel: str = "", show_completed: bool = False,
                   priority: str = "", tag: str = "") -> List[Dict]:
        results = []
        for t in self._todos:
            if t["completed"] and not show_completed:
                continue
            if channel and t.get("channel", "") != channel:
                continue
            if priority and t.get("priority", "") != priority.lower():
                continue
            if tag and tag.lower() not in [tg.lower() for tg in t.get("tags", [])]:
                continue
            results.append(t)
        _prio_order = {"urgent": 0, "high": 1, "medium": 2, "low": 3}
        results.sort(key=lambda x: (x["completed"], _prio_order.get(x.get("priority", "medium"), 2)))
        return results

    def clear_completed(self) -> int:
        before = len(self._todos)
        self._todos = [t for t in self._todos if not t["completed"]]
        removed = before - len(self._todos)
        if removed:
            self._save()
        return removed


# ── Pomodoro Timer ───────────────────────────────────────────────────────────
_POMODORO_PATH = os.path.join(_SCRIPT_DIR, "pomodoro_state.json")

class PomodoroManager:
    """Pomodoro technique timer with work/break cycles and session tracking.

    Supports:
      • Configurable work/break durations
      • Long break every N sessions
      • Session statistics
      • Auto-notification via IRC
    """

    def __init__(self):
        self.work_duration: int = 25 * 60
        self.short_break: int = 5 * 60
        self.long_break: int = 15 * 60
        self.sessions_before_long: int = 4
        self._state: Dict = self._load()
        self._running: bool = False
        self._task: Optional[asyncio.Task] = None
        self._ui_queue: Optional[asyncio.Queue] = None
        self._nick: str = ""

    def _load(self) -> Dict:
        try:
            with open(_POMODORO_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {
                "completed_sessions": 0,
                "total_work_minutes": 0,
                "last_session": 0,
            }

    def _save(self) -> None:
        try:
            with open(_POMODORO_PATH, "w", encoding="utf-8") as f:
                json.dump(self._state, f, indent=2)
        except OSError:
            pass

    def configure(self, work: int = 25, short_break: int = 5,
                  long_break: int = 15, sessions: int = 4) -> None:
        self.work_duration = work * 60
        self.short_break = short_break * 60
        self.long_break = long_break * 60
        self.sessions_before_long = sessions

    def start(self, ui_queue: asyncio.Queue, nick: str) -> Optional[str]:
        if self._running:
            return None
        self._ui_queue = ui_queue
        self._nick = nick
        self._running = True
        self._task = asyncio.create_task(self._run_cycle())
        sessions = self._state.get("completed_sessions", 0)
        return f"Pomodoro started: {self.work_duration // 60}m work session"

    def stop(self) -> Optional[str]:
        if not self._running:
            return None
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
        self._task = None
        return "Pomodoro stopped"

    @property
    def is_running(self) -> bool:
        return self._running

    def status(self) -> Dict:
        return {
            "running": self._running,
            "completed_sessions": self._state.get("completed_sessions", 0),
            "total_work_minutes": self._state.get("total_work_minutes", 0),
            "config": {
                "work_min": self.work_duration // 60,
                "short_break_min": self.short_break // 60,
                "long_break_min": self.long_break // 60,
                "sessions_before_long": self.sessions_before_long,
            },
        }

    async def _run_cycle(self) -> None:
        try:
            while self._running:
                if self._ui_queue:
                    await self._ui_queue.put(("status",
                        f"[pomodoro] Work session started — {self.work_duration // 60} min"))
                await asyncio.sleep(self.work_duration)
                if not self._running:
                    break
                sessions = self._state.get("completed_sessions", 0) + 1
                self._state["completed_sessions"] = sessions
                self._state["total_work_minutes"] = self._state.get("total_work_minutes", 0) + self.work_duration // 60
                self._state["last_session"] = time.time()
                self._save()
                is_long = sessions % self.sessions_before_long == 0
                break_dur = self.long_break if is_long else self.short_break
                break_label = "long" if is_long else "short"
                if self._ui_queue:
                    await self._ui_queue.put(("status",
                        f"[pomodoro] Work done! {sessions} sessions completed. "
                        f"Take a {break_label} break ({break_dur // 60} min)"))
                await asyncio.sleep(break_dur)
                if not self._running:
                    break
                if self._ui_queue:
                    await self._ui_queue.put(("status",
                        f"[pomodoro] Break over — starting work session"))
        except asyncio.CancelledError:
            pass
        finally:
            self._running = False


# ── Scratchpad / Notes ───────────────────────────────────────────────────────
_NOTES_PATH = os.path.join(_SCRIPT_DIR, "notes.json")

class NoteManager:
    """Persistent scratchpad notes with categories and search.

    Supports:
      • Categorised notes
      • Full-text search
      • Pin important notes
      • Timestamps and editing
    """

    def __init__(self):
        self._notes: Dict[str, Dict] = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(_NOTES_PATH, "r", encoding="utf-8") as f:
                self._notes = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            self._notes = {}

    def _save(self) -> None:
        try:
            with open(_NOTES_PATH, "w", encoding="utf-8") as f:
                json.dump(self._notes, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def add(self, text: str, category: str = "general", pinned: bool = False) -> Dict:
        note_id = f"n_{int(time.time())}_{random.randint(0,9999):04d}"
        note = {
            "id": note_id,
            "text": text,
            "category": category.lower(),
            "pinned": pinned,
            "created": time.time(),
            "edited": None,
        }
        self._notes[note_id] = note
        self._save()
        return note

    def edit(self, note_id: str, text: str = None, category: str = None,
             pinned: Optional[bool] = None) -> Optional[Dict]:
        note = self._notes.get(note_id)
        if not note:
            return None
        if text is not None:
            note["text"] = text
        if category is not None:
            note["category"] = category.lower()
        if pinned is not None:
            note["pinned"] = pinned
        note["edited"] = time.time()
        self._save()
        return note

    def remove(self, note_id: str) -> bool:
        if note_id in self._notes:
            del self._notes[note_id]
            self._save()
            return True
        return False

    def get(self, note_id: str) -> Optional[Dict]:
        return self._notes.get(note_id)

    def search(self, query: str, category: str = "") -> List[Dict]:
        query = query.lower()
        results = []
        for note in self._notes.values():
            if category and note.get("category", "") != category.lower():
                continue
            if query in note["text"].lower() or query in note.get("category", "").lower():
                results.append(note)
        results.sort(key=lambda n: (not n.get("pinned", False), n.get("created", 0)), reverse=True)
        return results

    def list_notes(self, category: str = "", pinned_only: bool = False) -> List[Dict]:
        results = []
        for note in self._notes.values():
            if category and note.get("category", "") != category.lower():
                continue
            if pinned_only and not note.get("pinned", False):
                continue
            results.append(note)
        results.sort(key=lambda n: (not n.get("pinned", False), n.get("created", 0)), reverse=True)
        return results

    def list_categories(self) -> List[str]:
        cats: set = set()
        for note in self._notes.values():
            cats.add(note.get("category", "general"))
        return sorted(cats)


# ── Bookmarks ─────────────────────────────────────────────────────────────────
_BOOKMARK_PATH = os.path.join(_SCRIPT_DIR, "bookmarks.json")

class BookmarkManager:
    """Persistent bookmarks for channels, nicks, URLs, and conversations.

    Supports:
      • Bookmark channels, nicks, URLs, or arbitrary items
      • Tags and descriptions
      • Search and filtering
      • Quick navigation via /bookmark go
    """

    def __init__(self):
        self._bookmarks: Dict[str, Dict] = {}
        self._load()

    def _load(self) -> None:
        try:
            with open(_BOOKMARK_PATH, "r", encoding="utf-8") as f:
                self._bookmarks = json.load(f)
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            self._bookmarks = {}

    def _save(self) -> None:
        try:
            with open(_BOOKMARK_PATH, "w", encoding="utf-8") as f:
                json.dump(self._bookmarks, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def add(self, target: str, description: str = "", tags: List[str] = None,
            btype: str = "channel") -> Dict:
        btype = btype.lower()
        if btype not in ("channel", "nick", "url", "general"):
            btype = "general"
        bm_id = f"bm_{int(time.time())}_{random.randint(0,9999):04d}"
        bm = {
            "id": bm_id,
            "target": target,
            "description": description,
            "tags": tags or [],
            "type": btype,
            "created": time.time(),
        }
        self._bookmarks[bm_id] = bm
        self._save()
        return bm

    def remove(self, bm_id: str) -> bool:
        if bm_id in self._bookmarks:
            del self._bookmarks[bm_id]
            self._save()
            return True
        return False

    def search(self, query: str, btype: str = "", tag: str = "") -> List[Dict]:
        query = query.lower()
        results = []
        for bm in self._bookmarks.values():
            if btype and bm.get("type", "") != btype.lower():
                continue
            if tag and tag.lower() not in [t.lower() for t in bm.get("tags", [])]:
                continue
            if (query in bm["target"].lower() or
                query in bm.get("description", "").lower()):
                results.append(bm)
        results.sort(key=lambda b: b.get("created", 0), reverse=True)
        return results

    def list_bookmarks(self, btype: str = "", tag: str = "") -> List[Dict]:
        results = []
        for bm in self._bookmarks.values():
            if btype and bm.get("type", "") != btype.lower():
                continue
            if tag and tag.lower() not in [t.lower() for t in bm.get("tags", [])]:
                continue
            results.append(bm)
        results.sort(key=lambda b: b.get("created", 0), reverse=True)
        return results

    def get_by_target(self, target: str) -> List[Dict]:
        target_lower = target.lower()
        return [bm for bm in self._bookmarks.values()
                if bm["target"].lower() == target_lower]


# ── Countdown Timer ──────────────────────────────────────────────────────────
class TimerManager:
    """Lightweight countdown timers with auto-notification.

    Supports:
      • Multiple concurrent timers
      • Named timers
      • Auto-notification via IRC when timer expires
    """

    def __init__(self):
        self._timers: Dict[str, Dict] = {}
        self._seq: int = 0
        self._ui_queue: Optional[asyncio.Queue] = None

    def set_ui_queue(self, queue: asyncio.Queue) -> None:
        self._ui_queue = queue

    def start(self, name: str, seconds: int, ui_queue: asyncio.Queue = None) -> str:
        if ui_queue:
            self._ui_queue = ui_queue
        self._seq += 1
        tid = f"tmr_{self._seq}"
        self._timers[tid] = {
            "id": tid,
            "name": name,
            "duration": seconds,
            "started": time.time(),
            "expires": time.time() + seconds,
            "task": asyncio.create_task(self._countdown(tid, name, seconds)),
        }
        return tid

    def cancel(self, tid: str) -> bool:
        entry = self._timers.get(tid)
        if not entry:
            return False
        if entry.get("task") and not entry["task"].done():
            entry["task"].cancel()
        del self._timers[tid]
        return True

    def list_timers(self) -> List[Dict]:
        now = time.time()
        results = []
        for tid, entry in self._timers.items():
            remaining = max(0, entry["expires"] - now)
            mins, secs = divmod(int(remaining), 60)
            results.append({
                "id": tid,
                "name": entry["name"],
                "remaining": f"{mins}m {secs}s",
                "remaining_secs": remaining,
            })
        results.sort(key=lambda x: x["remaining_secs"])
        return results

    async def _countdown(self, tid: str, name: str, seconds: int) -> None:
        try:
            await asyncio.sleep(seconds)
            if self._ui_queue:
                mins, secs = divmod(seconds, 60)
                dur_str = f"{mins}m {secs}s" if mins else f"{secs}s"
                await self._ui_queue.put(("status",
                    f"[timer] '{name}' ({dur_str}) has finished!"))
            self._timers.pop(tid, None)
        except asyncio.CancelledError:
            pass


# =========================
# RelationshipGraph
# =========================

class RelationshipGraph:
    """Tracks interaction patterns between nicks in channels.

    Records:
      • Who mentions whom (directed edge with weight)
      • Who replies to whom (via +reply tags or nick prefix)
      • Shared channel overlap (undirected co-membership)

    Provides /graph <nick> to visualize a nick's social connections.
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "relationship_graph.json")

    def __init__(self):
        self._edges: Dict[str, Dict[str, int]] = {}
        self._co_channels: Dict[str, set] = {}
        self._last_save: float = 0.0

    def record_mention(self, from_nick: str, to_nick: str, channel: str = "") -> None:
        fn = from_nick.lower()
        tn = to_nick.lower()
        if fn == tn:
            return
        self._edges.setdefault(fn, {})
        self._edges[fn][tn] = self._edges[fn].get(tn, 0) + 1
        if channel:
            self._co_channels.setdefault(fn, set()).add(channel.lower())
            self._co_channels.setdefault(tn, set()).add(channel.lower())

    def record_reply(self, from_nick: str, to_nick: str) -> None:
        fn = from_nick.lower()
        tn = to_nick.lower()
        if fn == tn:
            return
        self._edges.setdefault(fn, {})
        self._edges[fn][tn] = self._edges[fn].get(tn, 0) + 2

    def record_co_channel(self, nick: str, channel: str) -> None:
        self._co_channels.setdefault(nick.lower(), set()).add(channel.lower())

    def get_connections(self, nick: str, depth: int = 1) -> Dict:
        """Return connections for a nick up to depth hops."""
        root = nick.lower()
        result: Dict[str, Dict] = {}
        visited: set = set()
        frontier = {root}
        for hop in range(depth + 1):
            next_frontier: set = set()
            for n in frontier:
                if n in visited:
                    continue
                visited.add(n)
                outgoing = self._edges.get(n, {})
                incoming = {src: w for src, targets in self._edges.items()
                            for tgt, w in targets.items() if tgt == n}
                merged: Dict[str, int] = {}
                for k, v in outgoing.items():
                    merged[k] = merged.get(k, 0) + v
                for k, v in incoming.items():
                    merged[k] = merged.get(k, 0) + v
                result[n] = {
                    "outgoing": dict(sorted(outgoing.items(), key=lambda x: -x[1])[:20]),
                    "incoming": dict(sorted(incoming.items(), key=lambda x: -x[1])[:20]),
                    "top": dict(sorted(merged.items(), key=lambda x: -x[1])[:20]),
                    "channels": sorted(self._co_channels.get(n, set())),
                }
                next_frontier |= set(merged.keys())
            frontier = next_frontier - visited
        return result

    def get_top_interactions(self, nick: str, limit: int = 15) -> list:
        conn = self.get_connections(nick, depth=0)
        if nick.lower() not in conn:
            return []
        top = conn[nick.lower()]["top"]
        return list(top.items())[:limit]

    def get_mutual(self, nick: str, limit: int = 10) -> list:
        root = nick.lower()
        outgoing = self._edges.get(root, {})
        mutual = []
        for target, weight in outgoing.items():
            reverse = self._edges.get(target, {}).get(root, 0)
            if reverse > 0:
                mutual.append((target, weight, reverse))
        mutual.sort(key=lambda x: -(x[1] + x[2]))
        return mutual[:limit]

    def save(self) -> None:
        now = time.time()
        if now - self._last_save < 30:
            return
        self._last_save = now
        data = {
            "edges": {k: v for k, v in self._edges.items() if v},
            "co_channels": {k: sorted(v) for k, v in self._co_channels.items() if v},
        }
        try:
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._edges = {k: v for k, v in data.get("edges", {}).items() if v}
            self._co_channels = {k: set(v) for k, v in data.get("co_channels", {}).items() if v}
        except Exception:
            pass


# =========================
# AICalibrationManager
# =========================

class AICalibrationManager:
    """Manages AI detection confidence calibration using feedback history.

    Tracks:
      • Per-nick feedback (ai/human labels with associated scores)
      • Per-signal accuracy (how often each heuristic signal correlates with feedback)
      • Adaptive thresholds (auto-tuned from feedback distribution)
      • Calibration curve data (binned accuracy vs. predicted score)

    Provides /aicalibrate to inspect and adjust calibration.
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "ai_calibration.json")

    def __init__(self):
        self._feedback: list = []
        self._signal_stats: Dict[str, Dict] = {}
        self._thresholds: Dict[str, float] = {
            "ai_confirm": 70.0,
            "human_confirm": 30.0,
            "review": 50.0,
        }
        self._score_bins: Dict[str, int] = {}
        self._last_save: float = 0.0
        self.load()

    def record_feedback(self, nick: str, label: str, ai_score: float,
                        signal_scores: Dict = None) -> None:
        entry = {
            "nick": nick,
            "label": label,
            "ai_score": ai_score,
            "signal_scores": signal_scores or {},
            "ts": time.time(),
        }
        self._feedback.append(entry)
        self._update_signal_stats(entry)
        self._update_score_bins(ai_score, label)
        self._auto_adjust_thresholds()
        self._maybe_save()

    def _update_signal_stats(self, entry: dict) -> None:
        label = entry["label"]
        signals = entry.get("signal_scores", {})
        for sig_name, sig_val in signals.items():
            stats = self._signal_stats.setdefault(sig_name, {
                "ai_total": 0.0, "ai_count": 0,
                "human_total": 0.0, "human_count": 0,
            })
            if label == "ai":
                stats["ai_total"] += sig_val
                stats["ai_count"] += 1
            else:
                stats["human_total"] += sig_val
                stats["human_count"] += 1

    def _update_score_bins(self, ai_score: float, label: str) -> None:
        bin_key = f"{int(ai_score / 10) * 10}-{int(ai_score / 10) * 10 + 9}"
        self._score_bins.setdefault(bin_key, 0)
        if label == "ai":
            self._score_bins[bin_key] = self._score_bins.get(bin_key, 0) + 1

    def _auto_adjust_thresholds(self) -> None:
        if len(self._feedback) < 5:
            return
        ai_scores = [e["ai_score"] for e in self._feedback if e["label"] == "ai"]
        human_scores = [e["ai_score"] for e in self._feedback if e["label"] == "human"]
        if not ai_scores or not human_scores:
            return
        ai_avg = sum(ai_scores) / len(ai_scores)
        human_avg = sum(human_scores) / len(human_scores)
        midpoint = (ai_avg + human_avg) / 2.0
        spread = abs(ai_avg - human_avg)
        if spread < 10:
            return
        self._thresholds["review"] = midpoint
        self._thresholds["ai_confirm"] = midpoint + spread * 0.25
        self._thresholds["human_confirm"] = midpoint - spread * 0.25

    def get_signal_reliability(self) -> Dict[str, Dict]:
        results: Dict[str, Dict] = {}
        for sig, stats in self._signal_stats.items():
            ai_avg = stats["ai_total"] / stats["ai_count"] if stats["ai_count"] else 0
            human_avg = stats["human_total"] / stats["human_count"] if stats["human_count"] else 0
            separation = abs(ai_avg - human_avg)
            results[sig] = {
                "ai_avg": round(ai_avg, 3),
                "human_avg": round(human_avg, 3),
                "separation": round(separation, 3),
                "ai_count": stats["ai_count"],
                "human_count": stats["human_count"],
                "reliable": separation > 0.1 and stats["ai_count"] >= 3 and stats["human_count"] >= 3,
            }
        return results

    def get_thresholds(self) -> Dict[str, float]:
        return dict(self._thresholds)

    def get_summary(self) -> Dict:
        ai_count = sum(1 for e in self._feedback if e["label"] == "ai")
        human_count = sum(1 for e in self._feedback if e["label"] == "human")
        return {
            "total_feedback": len(self._feedback),
            "ai_confirmations": ai_count,
            "human_corrections": human_count,
            "thresholds": self.get_thresholds(),
            "signals": len(self._signal_stats),
            "recent": self._feedback[-5:],
        }

    def get_weight_adjustments(self) -> Dict[str, float]:
        reliability = self.get_signal_reliability()
        adj: Dict[str, float] = {}
        for sig, info in reliability.items():
            if info["reliable"]:
                if info["ai_avg"] > info["human_avg"]:
                    adj[sig] = min(0.05, info["separation"] * 0.1)
                else:
                    adj[sig] = -min(0.05, info["separation"] * 0.1)
            else:
                adj[sig] = 0.0
        return adj

    def reset(self) -> None:
        self._feedback.clear()
        self._signal_stats.clear()
        self._score_bins.clear()
        self._thresholds = {
            "ai_confirm": 70.0,
            "human_confirm": 30.0,
            "review": 50.0,
        }
        self._save()

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 60:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump({
                    "feedback": self._feedback[-200:],
                    "signal_stats": self._signal_stats,
                    "thresholds": self._thresholds,
                    "score_bins": self._score_bins,
                }, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._feedback = data.get("feedback", [])
            self._signal_stats = data.get("signal_stats", {})
            self._thresholds = data.get("thresholds", self._thresholds)
            self._score_bins = data.get("score_bins", {})
        except Exception:
            pass


# =========================
# TLSConnectionFingerprinter
# =========================

class TLSConnectionFingerprinter:
    """Records TLS certificate fingerprints and alerts on changes.

    Tracks:
      • SHA-256 fingerprint of the server's TLS certificate chain
      • TLS version and cipher suite
      • Change history (cert rotation, MITM detection)

    Alerts when the cert fingerprint changes between connections.
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "tls_fingerprints.json")

    def __init__(self):
        self._known: Dict[str, Dict] = {}
        self._ui_queue: Optional[asyncio.Queue] = None
        self.load()

    def set_ui_queue(self, queue: asyncio.Queue) -> None:
        self._ui_queue = queue

    def record_cert(self, server: str, fingerprint: str,
                    tls_version: str = "", cipher: str = "",
                    issuer: str = "", subject: str = "",
                    not_before: str = "", not_after: str = "") -> bool:
        """Record a server cert. Returns True if cert is NEW or CHANGED."""
        key = server.lower()
        entry = {
            "fingerprint": fingerprint,
            "tls_version": tls_version,
            "cipher": cipher,
            "issuer": issuer,
            "subject": subject,
            "not_before": not_before,
            "not_after": not_after,
            "first_seen": time.time(),
            "last_seen": time.time(),
        }
        if key not in self._known:
            self._known[key] = entry
            self._save()
            return True
        existing = self._known[key]
        if existing["fingerprint"] != fingerprint:
            old_fp = existing["fingerprint"]
            history = existing.setdefault("history", [])
            history.append({
                "fingerprint": old_fp,
                "last_seen": existing["last_seen"],
            })
            existing.update(entry)
            existing["first_seen"] = self._known[key].get("first_seen", time.time())
            existing["history"] = history
            self._save()
            return True
        existing["last_seen"] = time.time()
        if tls_version:
            existing["tls_version"] = tls_version
        if cipher:
            existing["cipher"] = cipher
        return False

    def check_cert_change(self, server: str, fingerprint: str) -> Optional[Dict]:
        """Check if fingerprint differs from known. Returns old entry if changed, None if same/new."""
        key = server.lower()
        if key not in self._known:
            return None
        existing = self._known[key]
        if existing["fingerprint"] != fingerprint:
            return {"old": existing["fingerprint"], "new": fingerprint,
                    "old_cipher": existing.get("cipher", "?"),
                    "old_tls": existing.get("tls_version", "?")}
        return None

    def get_status(self, server: str = "") -> Dict:
        if server:
            return self._known.get(server.lower(), {})
        return dict(self._known)

    def get_history(self, server: str) -> list:
        key = server.lower()
        entry = self._known.get(key, {})
        return entry.get("history", [])

    def _save(self) -> None:
        try:
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(self._known, f, indent=2)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                self._known = json.load(f)
        except Exception:
            pass



_FINGERPRINT_PATH = os.path.join(_SCRIPT_DIR, "bot_fingerprints.json")
_STRIP_PUNCT = str.maketrans("", "", ".,!?;:\"'()[]")

class BotFingerprint:
    """Linguistic fingerprint built from a confirmed bot/AI user's messages.

    Extracts vocabulary, bigrams, and trigrams so that future messages from
    *other* users with similar word patterns receive a score boost — effectively
    learning style from confirmed positives.
    """

    def __init__(self, nick: str):
        self.nick       = nick
        self.word_vocab: set = set()   # all lowercase words seen
        self.bigrams:   set = set()    # consecutive word pairs
        self.trigrams:  set = set()    # consecutive word triples
        self.msg_count: int = 0
        self.first_seen: float = time.time()
        self.last_seen: float = time.time()
        self.channels: set = set()     # channels where this bot was seen
        self.sample_messages: List[str] = []  # up to 10 representative messages

    def _tokenize(self, text: str) -> List[str]:
        return [w.lower().translate(_STRIP_PUNCT) for w in text.split() if w.strip(_STRIP_PUNCT)]

    def ingest(self, text: str, channel: str = "") -> None:
        """Feed one message into this fingerprint."""
        words = self._tokenize(text)
        if not words:
            return
        self.word_vocab.update(words)
        for i in range(len(words) - 1):
            self.bigrams.add((words[i], words[i + 1]))
        for i in range(len(words) - 2):
            self.trigrams.add((words[i], words[i + 1], words[i + 2]))
        self.msg_count += 1
        self.last_seen = time.time()
        if channel:
            self.channels.add(channel)
        if len(self.sample_messages) < 10 and len(text) > 10:
            self.sample_messages.append(text[:200])

    def similarity(self, text: str) -> float:
        """Return 0..1 — how closely *text* matches this bot's writing patterns.

        Combines Jaccard vocabulary overlap with bigram/trigram hit rates.
        Trigrams are the strongest signal because accidental three-word collisions
        are rare in natural IRC conversation.
        """
        if not self.word_vocab:
            return 0.0
        words = self._tokenize(text)
        if not words:
            return 0.0

        text_set = set(words)
        vocab_j  = len(text_set & self.word_vocab) / len(text_set | self.word_vocab)

        bi_score = 0.0
        if len(words) >= 2 and self.bigrams:
            text_bi  = {(words[i], words[i + 1]) for i in range(len(words) - 1)}
            bi_score = len(text_bi & self.bigrams) / len(text_bi)

        tri_score = 0.0
        if len(words) >= 3 and self.trigrams:
            text_tri  = {(words[i], words[i + 1], words[i + 2]) for i in range(len(words) - 2)}
            tri_score = len(text_tri & self.trigrams) / len(text_tri)

        return min(1.0, 0.25 * vocab_j + 0.35 * bi_score + 0.40 * tri_score)

    def to_dict(self) -> Dict:
        """Serialize fingerprint to a dictionary."""
        return {
            "nick": self.nick,
            "word_vocab": sorted(self.word_vocab),
            "bigrams": [f"{a} {b}" for a, b in self.bigrams],
            "trigrams": [f"{a} {b} {c}" for a, b, c in self.trigrams],
            "msg_count": self.msg_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "channels": sorted(self.channels),
            "sample_messages": self.sample_messages,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> "BotFingerprint":
        """Deserialize fingerprint from a dictionary."""
        fp = cls(data["nick"])
        fp.word_vocab = set(data.get("word_vocab", []))
        fp.bigrams = set()
        for bg in data.get("bigrams", []):
            parts = bg.split(" ", 2)
            if len(parts) >= 2:
                fp.bigrams.add((parts[0], parts[1]))
        fp.trigrams = set()
        for tg in data.get("trigrams", []):
            parts = tg.split(" ", 3)
            if len(parts) >= 3:
                fp.trigrams.add((parts[0], parts[1], parts[2]))
        fp.msg_count = data.get("msg_count", 0)
        fp.first_seen = data.get("first_seen", time.time())
        fp.last_seen = data.get("last_seen", time.time())
        fp.channels = set(data.get("channels", []))
        fp.sample_messages = data.get("sample_messages", [])
        return fp


def save_fingerprints(fingerprints: Dict[str, BotFingerprint]) -> None:
    """Persist all bot fingerprints to disk."""
    try:
        data = {nick: fp.to_dict() for nick, fp in fingerprints.items()}
        with open(_FINGERPRINT_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def load_fingerprints() -> Dict[str, BotFingerprint]:
    """Load bot fingerprints from disk."""
    fingerprints = {}
    try:
        with open(_FINGERPRINT_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        for nick, fp_data in data.items():
            fingerprints[nick] = BotFingerprint.from_dict(fp_data)
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass
    return fingerprints


# =========================
# Bouncer Buffer (BNC)
# =========================
class BouncerBuffer:
    """Persistent message buffer for the built-in bouncer.

    When the TUI is detached, incoming IRC messages are serialised to a JSONL
    file.  On reattach they are replayed via the ui_queue in chronological
    order, then the buffer file is truncated to zero.
    """

    def __init__(self, path: str = BNC_BUFFER_PATH):
        self.path = path
        self._count: int = 0
        self._channel_counts: Dict[str, int] = {}
        self._highlight_count: int = 0

    def append(self, event_type: str, *args) -> None:
        """Write one buffered event as a JSON line."""
        try:
            entry = {"t": event_type, "a": args, "ts": time.time()}
            # Track per-channel message counts
            if event_type == "msg" and len(args) >= 2:
                channel = args[1]  # target/channel
                self._channel_counts[channel] = self._channel_counts.get(channel, 0) + 1
            # Track highlights (mentions)
            if event_type == "msg" and len(args) >= 7:
                mention = args[5] if len(args) > 5 else ""
                if mention:
                    self._highlight_count += 1
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
            self._count += 1
        except Exception:
            pass

    def replay(self, ui_queue: asyncio.Queue, limit: int = 0, since: float = 0, channels: Optional[set] = None) -> int:
        """Read all buffered lines, push them onto *ui_queue*, and clear the file.

        Args:
            limit: Max events to replay (0 = unlimited)
            since: Only replay events after this timestamp (0 = all)
            channels: Only replay events for these channels (None = all)

        Returns the number of events replayed."""
        entries: list = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for raw in f:
                    raw = raw.strip()
                    if raw:
                        try:
                            entries.append(json.loads(raw))
                        except (json.JSONDecodeError, ValueError):
                            pass
        except FileNotFoundError:
            pass
        except Exception:
            pass
        if not entries:
            return 0
        # Sort by timestamp so replay order matches original arrival
        entries.sort(key=lambda e: e.get("ts", 0))

        # Apply filters
        if since > 0:
            entries = [e for e in entries if e.get("ts", 0) >= since]
        if channels:
            filtered = []
            for e in entries:
                if e["t"] == "msg" and len(e["a"]) >= 2:
                    if e["a"][1] in channels:
                        filtered.append(e)
                elif e["t"] != "msg":
                    filtered.append(e)
            entries = filtered

        replayed = 0
        for entry in entries:
            if limit > 0 and replayed >= limit:
                break
            try:
                ui_queue.put_nowait(tuple([entry["t"]] + list(entry["a"])))
                replayed += 1
            except asyncio.QueueFull:
                break
        # Truncate the buffer file
        try:
            open(self.path, "w").close()
        except Exception:
            pass
        self._count = 0
        self._channel_counts.clear()
        self._highlight_count = 0
        return replayed

    @property
    def count(self) -> int:
        return self._count

    def get_channel_stats(self) -> Dict[str, int]:
        """Return per-channel message counts."""
        return dict(self._channel_counts)

    @property
    def highlight_count(self) -> int:
        return self._highlight_count

    def clear(self) -> None:
        try:
            open(self.path, "w").close()
        except Exception:
            pass
        self._count = 0
        self._channel_counts.clear()
        self._highlight_count = 0


# =========================
# GPG helpers
# =========================

def _gpg_available() -> bool:
    """Return True if the gpg binary is reachable."""
    try:
        subprocess.run([GPG_BINARY, "--version"], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def _gpg_encrypt(plaintext: str, recipient: str) -> Optional[str]:
    """Encrypt *plaintext* for *recipient* using gpg --encrypt.
    Returns base64-encoded ciphertext, or None on failure."""
    try:
        proc = subprocess.run(
            [GPG_BINARY, "--encrypt", "--armor", "--recipient", recipient,
             "--trust-model", "always"],
            input=plaintext.encode("utf-8"),
            capture_output=True, timeout=15,
        )
        if proc.returncode == 0:
            return base64.b64encode(proc.stdout).decode()
    except Exception:
        pass
    return None


def _gpg_decrypt(b64_ciphertext: str) -> Optional[str]:
    """Decrypt a base64-encoded GPG ciphertext.
    Returns the plaintext string, or None on failure."""
    try:
        raw = base64.b64decode(b64_ciphertext)
        proc = subprocess.run(
            [GPG_BINARY, "--decrypt"],
            input=raw, capture_output=True, timeout=15,
        )
        if proc.returncode == 0:
            return proc.stdout.decode("utf-8", errors="replace").strip()
    except Exception:
        pass
    return None


def _gpg_sign(plaintext: str, key_fingerprint: str = "") -> Optional[str]:
    """Sign *plaintext* with GPG. Returns base64-encoded detached signature."""
    try:
        args = [GPG_BINARY, "--detach-sign", "--armor"]
        if key_fingerprint:
            args += ["--default-key", key_fingerprint]
        proc = subprocess.run(
            args, input=plaintext.encode("utf-8"),
            capture_output=True, timeout=15,
        )
        if proc.returncode == 0:
            return base64.b64encode(proc.stdout).decode()
    except Exception:
        pass
    return None


def _gpg_verify(plaintext: str, b64_signature: str) -> Optional[str]:
    """Verify a base64-encoded GPG detached signature against *plaintext*.
    Returns the signing key fingerprint on success, or None on failure."""
    try:
        sig = base64.b64decode(b64_signature)
        proc = subprocess.run(
            [GPG_BINARY, "--verify"],
            input=sig + plaintext.encode("utf-8"),
            capture_output=True, timeout=15,
        )
        if proc.returncode == 0:
            # Extract fingerprint from stderr
            for line in proc.stderr.decode("utf-8", errors="replace").splitlines():
                if "fingerprint" in line.lower() or "key ID" in line.lower():
                    return line.strip()
            return "(verified, no fingerprint in stderr)"
    except Exception:
        pass
    return None


# ── SOCKS5 proxy (Tor) ────────────────────────────────────────────────────
async def _socks5_connect(host: str, port: int,
                          proxy_host: str = TOR_PROXY_HOST,
                          proxy_port: int = TOR_PROXY_PORT,
                          timeout: float = 30.0,
                          ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Connect to *host:port* via a SOCKS5 proxy at *proxy_host:proxy_port*.

    Returns (reader, writer) — the same shape as ``asyncio.open_connection``.
    Raises ``ConnectionError`` on failure (handshake refused, timeout, …).
    """
    loop = asyncio.get_running_loop()
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(timeout)
        raw_sock.setblocking(False)

        await asyncio.wait_for(
            loop.sock_connect(raw_sock, (proxy_host, proxy_port)),
            timeout=timeout,
        )

        # ── 1. SOCKS5 greet (no auth) ──────────────────────────────────────
        greet = bytes([0x05, 0x01, 0x00])
        await asyncio.wait_for(
            loop.sock_sendall(raw_sock, greet), timeout=timeout,
        )
        resp = await asyncio.wait_for(
            loop.sock_recv(raw_sock, 2), timeout=timeout,
        )
        if resp != bytes([0x05, 0x00]):
            raw_sock.close()
            raise ConnectionError(f"SOCKS5: proxy rejected no-auth (got {resp.hex()})")

        # ── 2. CONNECT request (domain name) ───────────────────────────────
        host_bytes = host.encode("idna")
        if len(host_bytes) > 255:
            raise ConnectionError("SOCKS5: hostname too long")
        req = bytes([0x05, 0x01, 0x00, 0x03, len(host_bytes)]) \
              + host_bytes \
              + struct.pack("!H", port)
        await asyncio.wait_for(
            loop.sock_sendall(raw_sock, req), timeout=timeout,
        )
        # Response: version(1) + status(1) + reserved(1) + atyp(1) + bind(4-16) + port(2)
        resp = await asyncio.wait_for(
            loop.sock_recv(raw_sock, 255), timeout=timeout,
        )
        if len(resp) < 2:
            raw_sock.close()
            raise ConnectionError("SOCKS5: truncated connect response")
        if resp[1] != 0x00:
            statuses = {
                0x01: "general failure", 0x02: "not allowed",
                0x03: "network unreachable", 0x04: "host unreachable",
                0x05: "connection refused", 0x06: "TTL expired",
                0x07: "command not supported", 0x08: "address type not supported",
            }
            raw_sock.close()
            raise ConnectionError(
                f"SOCKS5: connect failed — {statuses.get(resp[1], f'0x{resp[1]:02x}')}")

        raw_sock.setblocking(True)
        reader = asyncio.StreamReader(limit=2 ** 20)
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_accepted_socket(
            lambda: protocol, raw_sock,
        )
        writer = asyncio.StreamWriter(raw_sock, protocol, reader, loop)
        return reader, writer

    except asyncio.TimeoutError:
        raise ConnectionError(f"SOCKS5: connection to {proxy_host}:{proxy_port} timed out")


class ScoringEngine:
    def __init__(self, ai_detector: EnsembleAIDetector):
        self.ai_detector      = ai_detector
        self.confirmed_bot_nicks: set = set()
        self.bot_fingerprints: Dict[str, BotFingerprint] = {}
        self.blocklisted_ngrams: set = set()
        self._load_blocklist()
        # Load persisted fingerprints
        self._load_fingerprints()
        # New AI/ML components
        self.sentiment = SentimentAnalyzer()
        self.behavioral = BehavioralAnomalyDetector()
        self.topics = TopicDetector()
        self.semantic = SemanticSimilarityDetector()
        self.threads = ThreadTracker()
        self.cross_channel = CrossChannelBotDetector()
        # Sentiment history per nick for trend analysis
        self._sentiment_history: Dict[str, deque] = {}
        # Productivity components
        self.reminders = ReminderManager()
        self.watches = NickWatchManager()
        self.snippets = SnippetManager()
        self.channel_stats = ChannelStatsTracker()
        self.rss = RSSFeedBridge()
        self.todos = TodoManager()
        self.pomodoro = PomodoroManager()
        self.notes = NoteManager()
        self.bookmarks = BookmarkManager()
        self.timers = TimerManager()
        self.relationships = RelationshipGraph()
        self.calibration = AICalibrationManager()
        self.tls_fingerprinter = TLSConnectionFingerprinter()
        self.ai_vs_ai = AIVsAIDetector()
        self.sentiment_ai = SentimentAICorrelator()

    def _load_fingerprints(self) -> None:
        """Load persisted bot fingerprints from disk."""
        self.bot_fingerprints = load_fingerprints()
        # Re-add loaded fingerprints to confirmed_bot_nicks
        for nick in self.bot_fingerprints:
            self.confirmed_bot_nicks.add(nick.lower())

    def save_fingerprints(self) -> None:
        """Persist all bot fingerprints to disk."""
        save_fingerprints(self.bot_fingerprints)

    def analyze_sentiment(self, nick: str, text: str) -> Dict[str, Any]:
        """Analyze sentiment and track history for *nick*."""
        result = self.sentiment.analyze(text)
        if nick not in self._sentiment_history:
            self._sentiment_history[nick] = deque(maxlen=100)
        self._sentiment_history[nick].append({
            "score": result["score"],
            "ts": time.time(),
            "text": text[:100],
        })
        return result

    def get_sentiment_trend(self, nick: str, window: int = 20) -> Dict[str, Any]:
        """Return sentiment trend for *nick* over last *window* messages."""
        history = self._sentiment_history.get(nick, deque())
        if not history:
            return {"trend": "no data", "avg_score": 0.0, "volatility": 0.0}
        recent = list(history)[-window:]
        scores = [h["score"] for h in recent]
        avg = sum(scores) / len(scores) if scores else 0.0
        # Volatility = standard deviation
        if len(scores) >= 2:
            variance = sum((s - avg) ** 2 for s in scores) / len(scores)
            volatility = variance ** 0.5
        else:
            volatility = 0.0
        # Trend direction
        if len(scores) >= 5:
            first_half = sum(scores[:len(scores)//2]) / (len(scores)//2)
            second_half = sum(scores[len(scores)//2:]) / (len(scores) - len(scores)//2)
            delta = second_half - first_half
            if delta > 0.1:
                trend = "improving"
            elif delta < -0.1:
                trend = "declining"
            else:
                trend = "stable"
        else:
            trend = "insufficient data"
        return {
            "trend": trend,
            "avg_score": round(avg, 3),
            "volatility": round(volatility, 3),
            "sample_count": len(scores),
        }

    # ── Collaborative n-gram blocklist (Area 3) ───────────────────────────

    def _blocklist_path(self) -> str:
        return USER_TELL_PATH

    def _load_blocklist(self) -> None:
        path = self._blocklist_path()
        if os.path.exists(path):
            try:
                with open(path, encoding="utf-8") as f:
                    data = json.load(f)
                self.blocklisted_ngrams = set(data.get("ngrams", []))
            except Exception:
                self.blocklisted_ngrams = set()

    def _save_blocklist(self) -> None:
        path = self._blocklist_path()
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"ngrams": sorted(self.blocklisted_ngrams)}, f)
        except Exception:
            pass

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return [w.lower().translate(_STRIP_PUNCT) for w in text.split() if w.strip(_STRIP_PUNCT)]

    def _extract_tell_ngrams(self, text: str) -> set:
        words = self._tokenize(text)
        ngrams: set = set()
        for w in words:
            ngrams.add(w)
        for i in range(len(words) - 1):
            ngrams.add(f"{words[i]} {words[i+1]}")
        for i in range(len(words) - 2):
            ngrams.add(f"{words[i]} {words[i+1]} {words[i+2]}")
        return ngrams

    def add_tell(self, phrase: str) -> int:
        ngrams = self._extract_tell_ngrams(phrase)
        before = len(self.blocklisted_ngrams)
        self.blocklisted_ngrams |= ngrams
        self._save_blocklist()
        return len(self.blocklisted_ngrams) - before

    def remove_tell(self, phrase: str) -> int:
        ngrams = self._extract_tell_ngrams(phrase)
        before = len(self.blocklisted_ngrams)
        self.blocklisted_ngrams -= ngrams
        self._save_blocklist()
        return before - len(self.blocklisted_ngrams)

    def blocklist_overlap_score(self, text: str) -> float:
        """Return 0..1 — fraction of blocklisted n-grams present in *text*."""
        if not self.blocklisted_ngrams or not text:
            return 0.0
        words = self._tokenize(text)
        if not words:
            return 0.0
        hits = 0
        total = 0
        seen = set()
        # Unigrams
        for w in words:
            if w in self.blocklisted_ngrams and w not in seen:
                hits += 1
                seen.add(w)
            total += 1
        # Bigrams
        for i in range(len(words) - 1):
            bg = f"{words[i]} {words[i+1]}"
            if bg in self.blocklisted_ngrams and bg not in seen:
                hits += 1
                seen.add(bg)
            total += 1
        # Trigrams
        for i in range(len(words) - 2):
            tg = f"{words[i]} {words[i+1]} {words[i+2]}"
            if tg in self.blocklisted_ngrams and tg not in seen:
                hits += 1
                seen.add(tg)
            total += 1
        return min(1.0, hits / max(1, total))

    def confirm_bot(self, nick: str, messages: List[str], channel: str = "") -> BotFingerprint:
        """Mark *nick* as a confirmed bot and build their linguistic fingerprint."""
        self.confirmed_bot_nicks.add(nick.lower())
        fp = self.bot_fingerprints.get(nick.lower()) or BotFingerprint(nick)
        for msg in messages:
            fp.ingest(msg, channel)
        self.bot_fingerprints[nick.lower()] = fp
        self.save_fingerprints()
        return fp

    def unconfirm_bot(self, nick: str) -> None:
        self.confirmed_bot_nicks.discard(nick.lower())
        self.bot_fingerprints.pop(nick.lower(), None)
        self.save_fingerprints()

    def max_fingerprint_similarity(self, text: str, exclude_nick: str = "") -> float:
        """Return the highest similarity score of *text* against all bot fingerprints."""
        if not self.bot_fingerprints:
            return 0.0
        return max(
            fp.similarity(text)
            for n, fp in self.bot_fingerprints.items()
            if n != exclude_nick
        )

    def score_user(self, user_state) -> int:
        return int(user_state.rolling_ai_likelihood())

    def score_message(self, msg_state, user_state) -> int:
        return int(user_state.rolling_ai_likelihood())

# =========================
# UserState + ChatWindow
# =========================
class UserState:
    __slots__ = ("nick", "join_time", "last_msg_time", "msg_times", "msg_lengths",
                 "total_msgs", "ai_scores", "_rolling_sum", "_len_sum", "_time_sum",
                 "is_confirmed_bot", "_recent_embeds", "_log_gaps", "_recent_signals")
    def __init__(self, nick: str):
        self.nick = nick
        self.join_time = time.monotonic()
        self.last_msg_time: Optional[float] = None
        self.msg_times: deque = deque(maxlen=USER_HISTORY_WINDOW)
        self.msg_lengths: deque = deque(maxlen=USER_HISTORY_WINDOW)
        self.total_msgs = 0
        self.ai_scores: deque = deque(maxlen=USER_HISTORY_WINDOW)
        self._rolling_sum: float = 0.0
        self._len_sum:     int   = 0
        self._time_sum:    float = 0.0
        self.is_confirmed_bot: bool = False
        # Embedding history for semantic-drift detection (max 32 vectors)
        self._recent_embeds: deque = deque(maxlen=32)
        # Log-transformed inter-message gaps for timing-distribution model
        self._log_gaps: deque = deque(maxlen=USER_HISTORY_WINDOW)
        # Per-signal breakdown history for explainability (Area 6)
        self._recent_signals: deque = deque(maxlen=USER_HISTORY_WINDOW)

    def record_message(self, msg: str, ai_score: Optional[int] = None) -> None:
        now = time.monotonic()
        if self.last_msg_time is not None:
            gap = now - self.last_msg_time
            if len(self.msg_times) == USER_HISTORY_WINDOW:
                self._time_sum -= self.msg_times[0]
            self.msg_times.append(gap)
            self._time_sum += gap
            self._log_gaps.append(log(gap + 1e-9))
        self.last_msg_time = now
        msg_len = len(msg)
        if len(self.msg_lengths) == USER_HISTORY_WINDOW:
            self._len_sum -= self.msg_lengths[0]
        self.msg_lengths.append(msg_len)
        self._len_sum += msg_len
        self.total_msgs += 1
        if ai_score is not None:
            if len(self.ai_scores) == USER_HISTORY_WINDOW:
                self._rolling_sum -= self.ai_scores[0]
            self.ai_scores.append(ai_score)
            self._rolling_sum += ai_score

    def seed_ai_history(self, scores: List[int]) -> None:
        """Pre-seed ai_scores from historical log data without affecting message counts."""
        for score in scores:
            score = max(0, min(100, score))
            if len(self.ai_scores) == USER_HISTORY_WINDOW:
                self._rolling_sum -= self.ai_scores[0]
            self.ai_scores.append(score)
            self._rolling_sum += score

    def rolling_ai_likelihood(self) -> float:
        n = len(self.ai_scores)
        return self._rolling_sum / n if n else 0.0

    # Extra stats for dashboard — O(1) via incremental sums
    def avg_msg_length(self) -> float:
        n = len(self.msg_lengths)
        return self._len_sum / n if n else 0.0

    def messages_per_minute(self) -> float:
        n = len(self.msg_times)
        return (n / self._time_sum) * 60 if n and self._time_sum > 0 else 0.0

    def timing_anomaly_score(self) -> float:
        """0..1 — log-normal timing regularity model.

        Models log-transformed inter-message gaps as a normal distribution.
        Bots exhibit low log-variance and consistently small z-scores.
        Higher return value = more automated/bot-like timing pattern.
        """
        if len(self._log_gaps) < 5:
            return 0.0
        import statistics as _stats
        mean_log = _stats.mean(self._log_gaps)
        stdev_log = _stats.stdev(self._log_gaps) if len(self._log_gaps) >= 2 else 0.0
        if stdev_log < 0.01:
            return 0.9  # near-zero variance → almost certainly automated
        latest_log = self._log_gaps[-1]
        z = abs((latest_log - mean_log) / stdev_log)
        reg_score = max(0.0, 1.0 - z / 2.0)           # small z → too regular
        stdev_score = max(0.0, min(1.0, (0.8 - stdev_log) / 0.8))  # low std → consistent
        return max(0.0, min(1.0, 0.5 * reg_score + 0.5 * stdev_score))

class ChatWindow:
    def __init__(self, name: str, is_channel: bool = True, server_id: str = ""):
        self.name = name
        self.is_channel = is_channel
        self.server_id = server_id
        self.lines: deque = deque(maxlen=MAX_MESSAGES)
        self._line_msgids: deque = deque(maxlen=MAX_MESSAGES)  # parallel msgid per line
        self._msg_store: dict = {}   # {msgid: (nick, text_preview)} — for reply lookups
        self._last_msgid: str = ""   # msgid of most recent incoming message
        self._reactions: dict = {}   # {msgid: {emoji: [nick, ...]}}
        self._unread_from: int = -1  # index of first unread line (-1 = none)
        self.wrapped_cache: List[str] = []
        self.url_map: Dict[int, str] = {}  # wrapped line index -> full URL
        self._wrap_dirty = True
        self._last_wrap_width = 0
        self.scroll_offset: int = 0  # 0 = pinned to bottom
        self._persist = True         # write new lines to disk
        # Optional override for the on-disk log filename.  Defaults to
        # self.name; used to disambiguate multiple windows that share a name
        # across servers (e.g. each server's own *status* window).
        self._log_name: str = ""

    def add_line(self, text: str, timestamp: bool = True,
                 ts_str: Optional[str] = None, msgid: str = "") -> None:
        if timestamp:
            ts = ts_str if ts_str else time.strftime("[%H:%M]")
            text = f"{ts} {text}"
        self.lines.append(text)
        self._line_msgids.append(msgid)
        self._wrap_dirty = True
        if self._persist:
            append_chat_line(self._log_name or self.name, text)

# Reuse one SSL context across all connections (parsing the CA bundle is expensive).
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.minimum_version = ssl.TLSVersion.TLSv1_2
if SASL_MECHANISM == "EXTERNAL" and SASL_CERT and SASL_KEY:
    _SSL_CTX.load_cert_chain(SASL_CERT, SASL_KEY)

# =========================
# IRCClient - FULL + CTCP
# =========================
class IRCClient:
    def __init__(self, server: str, port: int, nick: str, ui_queue: asyncio.Queue,
                 scoring_engine: ScoringEngine, use_ssl: bool = True,
                 use_tor: bool = False):
        self.server = server
        self.port = port
        self.nick = nick
        self.use_ssl = use_ssl
        self.use_tor = use_tor
        self.tor_strict: bool = False
        self._own_umodes: set = set()      # user modes (+i, +o, +w, etc.)
        self._ircop_nicks: set = set()     # nicks known to be IRC operators
        self._ctcp_mode: str = "normal"    # normal, off, spoof
        self._resume_token: str = ""       # IRCv3 draft/resume token
        self._resume_ts: str = ""          # IRCv3 draft/resume timestamp
        self._resumed_session: bool = False  # True after successful RESUME
        self._last_ping_ts: float = 0.0      # timestamp of last PING sent (draft/ping)
        self._latency: float = 0.0           # latest round-trip latency in seconds
        self._sts_policies: dict = self._load_sts_policies()
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.ui_queue = ui_queue
        self.current_channel: Optional[str] = None
        self.scoring = scoring_engine
        self.users: Dict[str, UserState] = {}
        self.running = True
        self._identified = False
        self.joined_channels: set = {DEFAULT_CHANNEL} if DEFAULT_CHANNEL else set()
        self._ctcp_times: Dict[str, deque] = {}  # rate-limit CTCP replies
        self._cap_ls_caps: set = set()           # accumulated caps across multiline CAP LS
        self._cap_ls_values: dict = {}           # cap name → advertised value (e.g. sts=...)
        self._active_caps: set = set()           # currently ACKed/enabled caps
        self._batch_buffer: dict = {}            # batch ref → [(cmd,nick,params,prefix,tags)]
        self._batch_types: dict = {}             # batch ref → batch type string
        self._batch_params: dict = {}            # batch ref → original BATCH+ params (for multiline target)
        self._current_batch_is_replay: bool = False  # True while replaying chathistory batch
        self._monitor_nicks: set = set()         # nicks on MONITOR list
        self._chathistory_cap: str = ""          # "chathistory" or "draft/chathistory"
        self._replay_enabled: bool = False       # must be set True before /replay works
        self._soju_networks: dict = {}           # net_id → {name, host, port, nick, state, ...}
        self._soju_is_bouncer: bool = False      # True when soju.im/bouncer-networks ACKed
        self._label_seq: int = 0                 # monotonic label counter (labeled-response)
        self._pending_labels: set = set()        # labels sent on outgoing msgs, awaiting echo
        self._whox_seq: int = 1                  # rotating token for WHOX queries (1–999)
        self._whox_tokens: dict = {}             # token → requested-fields string
        self._cap_req_queue: list = []           # individual caps queued after a CAP NAK
        self._sasl_state: dict = {}              # per-mechanism state across AUTHENTICATE exchanges
        self._auth_buffer: str = ""              # accumulates chunked AUTHENTICATE data (>400 chars)
        self._network_announced: bool = False    # one-shot announce of NETWORK token
        # Send queue — all outbound data goes here; _run_writer flushes it with
        # flood-control rate limiting so the server never disconnects us for flooding.
        self._send_queue: asyncio.Queue = asyncio.Queue(maxsize=512)
        # Monotonic timestamp of the last PONG received from the server.
        # Updated by _irc_pong; checked by keepalive to detect dead connections.
        self._last_pong: float = 0.0
        # The nick the user actually wants.  When a 433 collision forces us to
        # use nick_ we remember the original and periodically try to reclaim it.
        self._desired_nick: str = nick
        # Background task that retries _desired_nick after a 433 collision.
        self._nick_reclaim_task: Optional[asyncio.Task] = None
        # IRCv3 message tags from the current line being dispatched.
        # Set in process_line before calling each handler; read by handlers
        # that need tag data (e.g. server-time).
        self._current_msg_tags: dict = {}
        # Tokens from ISUPPORT (005 numeric): e.g. NETWORK, PREFIX, CHANTYPES.
        self._isupport: dict = {}
        # Accumulates RPL_LIST (322) results between /list and RPL_LISTEND (323).
        self._list_results: list = []
        # Accumulates RPL_BANLIST (367) results between /ban -l and RPL_ENDOFBANLIST (368).
        self._banlist_results: list = []
        self._irc_handlers: dict = {}
        self._build_irc_handlers()
        # Strong references to fire-and-forget scoring tasks so they are not
        # garbage-collected before they finish (asyncio only holds weak refs).
        self._bg_tasks: set = set()
        # Behavioral biometrics tracker for user typing patterns
        self.biometrics: BehavioralBiometrics = BehavioralBiometrics()
        # IRCv3 draft/thread: track last thread parent per channel
        self._thread_parents: Dict[str, str] = {}
        # IRCv3 read-marker: last known read marker per channel
        self._read_markers: Dict[str, str] = {}

    @property
    def server_id(self) -> str:
        return f"{self.server}:{self.port}"

    def _load_sts_policies(self) -> dict:
        try:
            with open(STS_POLICY_PATH, encoding="utf-8") as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_sts_policies(self) -> None:
        try:
            with open(STS_POLICY_PATH, "w", encoding="utf-8") as f:
                json.dump(self._sts_policies, f, indent=2)
        except Exception:
            pass

    def _clear_expired_sts(self) -> None:
        now = time.time()
        expired = [
            srv for srv, pol in self._sts_policies.items()
            if pol["duration"] > 0 and now > pol["timestamp"] + pol["duration"]
        ]
        for srv in expired:
            del self._sts_policies[srv]
        if expired:
            self._save_sts_policies()

    async def connect(self) -> None:
        # STS policy check: if a pinned policy exists and is still valid,
        # force SSL and the pinned port.
        self._clear_expired_sts()
        policy = self._sts_policies.get(self.server)
        if policy and not self.use_ssl:
            self.use_ssl = True
            self.port = policy["port"]
            await self.ui_queue.put(("status",
                f"[STS] Enforcing pinned policy — upgraded to SSL port {self.port}"))
        if policy and self.port != policy["port"]:
            self.port = policy["port"]
            await self.ui_queue.put(("status",
                f"[STS] Enforcing pinned SSL port {self.port}"))

        # Onion-only mode: refuse clearnet hosts
        if self.tor_strict and not self.server.endswith(".onion"):
            raise ConnectionError(
                f"Tor strict mode: refusing clearnet host '{self.server}' "
                f"(only .onion addresses allowed)")

        via = " (via Tor)" if self.use_tor else ""
        proto = "SSL" if self.use_ssl else "plain"
        await self.ui_queue.put(("status", f"Connecting to {self.server}:{self.port} ({proto}{via})..."))
        try:
            # 30-second connect timeout prevents hangs on unreachable hosts.
            # limit=2^20 (1 MiB) sets the StreamReader internal buffer; the default
            # 64 KB can stall on fast servers that send large NAMES / MOTD bursts.
            if self.use_tor:
                self.reader, self.writer = await asyncio.wait_for(
                    _socks5_connect(self.server, self.port),
                    timeout=30.0,
                )
                if self.use_ssl:
                    loop = asyncio.get_running_loop()
                    raw_sock = self.writer.transport.get_extra_info("socket")
                    ssl_sock = await loop.run_in_executor(
                        None, lambda: _SSL_CTX.wrap_socket(
                            raw_sock, server_hostname=self.server,
                            do_handshake_on_connect=True))
                    ssl_sock.setblocking(False)
                    ssl_reader = asyncio.StreamReader(limit=2**20)
                    ssl_protocol = asyncio.StreamReaderProtocol(ssl_reader)
                    await loop.connect_accepted_socket(
                        lambda: ssl_protocol, ssl_sock)
                    self.writer = asyncio.StreamWriter(
                        ssl_sock, ssl_protocol, ssl_reader, loop)
                    self.reader = ssl_reader
            else:
                self.reader, self.writer = await asyncio.wait_for(
                    asyncio.open_connection(
                        self.server, self.port,
                        ssl=_SSL_CTX if self.use_ssl else None,
                        limit=2 ** 20),
                    timeout=30.0,
                )
        except asyncio.TimeoutError:
            raise ConnectionError(
                f"Connection to {self.server}:{self.port} timed out after 30 s")
        except Exception as e:
            await self.ui_queue.put(("status", f"Connection failed: {e}"))
            raise
        # TCP_NODELAY: disable Nagle's algorithm so IRC commands are sent immediately
        # rather than waiting to coalesce with future data (Nagle adds ~40-200 ms).
        # SO_KEEPALIVE + TCP_KEEPIDLE/INTVL/CNT: OS-level dead-connection detection
        # as a second line of defence behind our PING/PONG keepalive.
        raw_sock = self.writer.get_extra_info("socket")
        if raw_sock is not None:
            try:
                raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                raw_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                if hasattr(socket, "TCP_KEEPIDLE"):
                    raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                if hasattr(socket, "TCP_KEEPINTVL"):
                    raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                if hasattr(socket, "TCP_KEEPCNT"):
                    raw_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            except Exception:
                pass  # socket options are best-effort
        via = " via Tor" if self.use_tor else ""
        conn_label = "SSL connection" if self.use_ssl else "Connection"
        # TLS certificate fingerprinting (MITM / cert-change detection)
        if self.use_ssl and self.scoring.tls_fingerprinter:
            try:
                ssl_obj = self.writer.transport.get_extra_info("ssl_object")
                if ssl_obj:
                    der_cert = ssl_obj.getpeercert(binary_form=True)
                    cert_info = ssl_obj.getpeercert()
                    if der_cert:
                        fp = hashlib.sha256(der_cert).hexdigest()
                        issuer = ""
                        subject = ""
                        tls_ver = ssl_obj.version() or ""
                        cipher = ssl_obj.cipher()[0] if ssl_obj.cipher() else ""
                        if cert_info:
                            issuer = str(cert_info.get("issuer", ""))
                            subject = str(cert_info.get("subject", ""))
                        changed = self.scoring.tls_fingerprinter.check_cert_change(self.server, fp)
                        self.scoring.tls_fingerprinter.record_cert(
                            self.server, fp, tls_ver, cipher, issuer, subject)
                        if changed:
                            await self.ui_queue.put(("status",
                                f"[TLS] CERT CHANGE on {self.server}: "
                                f"old={changed['old'][:16]}… new={changed['new'][:16]}… "
                                f"→ possible MITM or cert rotation"))
                        self.scoring.tls_fingerprinter._save()
            except Exception:
                pass
        await self.ui_queue.put(("status", f"{conn_label}{via} established to {self.server}:{self.port}"))
        # Flush any stale messages queued from a previous (failed) connection
        # so they are not replayed on the new session.
        while not self._send_queue.empty():
            try:
                self._send_queue.get_nowait()
            except asyncio.QueueEmpty:
                break
        self._last_pong = time.monotonic()
        # CAP LS must come before NICK/USER so the server holds registration
        # open until we send CAP END (or complete SASL).
        self.send_raw("CAP LS 302")
        # NICK/USER are deferred — they are sent after CAP END
        # via _finish_registration() (which may send RESUME instead if
        # draft/resume token is available).
        await self.ui_queue.put(("status", "Sent CAP LS — awaiting registration"))

    def send_raw(self, line: str) -> None:
        """Enqueue a raw IRC line for delivery by the rate-limited writer task.

        Synchronous so it can be called from anywhere.  Drops lines when the queue
        is full (512 items = a multi-second burst) to avoid unbounded memory growth
        under pathological conditions.
        """
        # Strip CRLF and null bytes to prevent IRC command injection
        line = line.replace("\r", "").replace("\n", "").replace("\x00", "")
        if not line:
            return
        # IRC protocol maximum is 512 bytes including CRLF (RFC 1459 §2.3).
        # Encode first so multi-byte UTF-8 chars are truncated on a byte boundary.
        encoded = line.encode("utf-8", "replace")[:510]
        try:
            self._send_queue.put_nowait(encoded + b"\r\n")
        except asyncio.QueueFull:
            pass  # drop; flood-protection is better than memory exhaustion

    async def _run_writer(self) -> None:
        """Consume the send queue, forwarding data to the server with flood control.

        Token-bucket: steady rate of 4 lines/second, burst capacity of 10.
        IRC servers typically kick clients that exceed ~10 lines/second; this
        keeps us well under that limit even on /join floods or mass-kicks.

        Batching: after the first token is consumed we drain all immediately
        available messages (up to remaining token budget) and send them in a
        single writelines() + drain() call.  This reduces kernel round-trips
        dramatically during connect bursts (NAMES, MOTD, JOIN floods, etc.).

        The wait_for timeout is intentionally absent: the task is cancelled by
        run_connection's finally block, so CancelledError is the exit path.
        """
        RATE  = 4.0   # tokens replenished per second
        BURST = 10.0  # maximum token bucket size
        tokens = BURST
        last_refill = time.monotonic()

        while self.running:
            try:
                data = await self._send_queue.get()
            except asyncio.CancelledError:
                break

            # Refill the bucket for time elapsed since last send
            now = time.monotonic()
            tokens = min(BURST, tokens + (now - last_refill) * RATE)
            last_refill = now

            # If the bucket is empty, sleep until we have a token
            if tokens < 1.0:
                wait = (1.0 - tokens) / RATE
                try:
                    await asyncio.sleep(wait)
                except asyncio.CancelledError:
                    break
                now = time.monotonic()
                tokens = min(BURST, tokens + (now - last_refill) * RATE)
                last_refill = now

            tokens -= 1.0

            # Batch: absorb all messages that are already queued (up to token
            # budget) so they share a single drain() syscall.
            batch = [data]
            while tokens >= 1.0:
                try:
                    batch.append(self._send_queue.get_nowait())
                    tokens -= 1.0
                except asyncio.QueueEmpty:
                    break

            try:
                if self.writer and not self.writer.is_closing():
                    self.writer.writelines(batch)
                    await self.writer.drain()
            except asyncio.CancelledError:
                break
            except Exception as e:
                await self.ui_queue.put(("status", f"Write error: {e}"))
                try:
                    if self.writer:
                        self.writer.close()
                except Exception:
                    pass
                break

    def _ctcp_allowed(self, nick: str) -> bool:
        """Allow at most 3 CTCP replies per nick per 30 s."""
        now = time.monotonic()
        q = self._ctcp_times.get(nick)
        if q is not None:
            while q and now - q[0] > 30:
                q.popleft()
            if not q:
                # All timestamps expired — evict the entry so _ctcp_times doesn't
                # accumulate thousands of empty deques from high-nick-churn channels.
                del self._ctcp_times[nick]
                q = None
        if q is None:
            q = deque()
            self._ctcp_times[nick] = q
        if len(q) >= 3:
            return False
        q.append(now)
        return True

    async def keepalive(self) -> None:
        """Send PING every 45 s and disconnect if no PONG arrives within 120 s.

        Dead TCP connections (e.g. NAT timeout, Wi-Fi handoff) do not always
        produce a RST/FIN; without this check the client would sit silently
        disconnected until the 300 s readline timeout fires.
        """
        PING_INTERVAL = 45.0
        PONG_TIMEOUT  = 120.0
        while self.running and self.writer:
            try:
                ts = int(time.time())
                self._last_ping_ts = ts
                if "draft/ping" in self._active_caps:
                    self.send_raw(f"PING {ts}")
                else:
                    self.send_raw(f"PING :keepalive-{ts}")
                await asyncio.sleep(PING_INTERVAL)
                if time.monotonic() - self._last_pong > PONG_TIMEOUT:
                    await self.ui_queue.put(("status", "Ping timeout — reconnecting"))
                    try:
                        self.writer.close()
                    except Exception:
                        pass
                    break
            except asyncio.CancelledError:
                break
            except Exception:
                break

    async def _delayed_nickserv_identify(self) -> None:
        """Send NickServ IDENTIFY after a short delay without blocking the read loop."""
        await asyncio.sleep(1.5)
        if self.writer and not self.writer.is_closing():
            self.send_raw(f"PRIVMSG NickServ :IDENTIFY {NICKSERV_PASSWORD}")
            await self.ui_queue.put(("status", "Auto-identified to NickServ"))
            self._identified = True

    async def run_connection(self) -> None:
        """Connect + keepalive with exponential-backoff auto-reconnect."""
        DELAYS = [5, 15, 30, 60]
        attempt = 0
        while self.running:
            self._identified = False
            # Reset all per-connection state. Anything populated by
            # the previous session (caps, ISUPPORT, batches,
            # chathistory cap, ...) would otherwise leak into the
            # new connection and produce subtle bugs (stale
            # CASEMAPPING, dropped self-echoes from the old server,
            # network name never re-announced, ...).
            self._cap_ls_caps.clear()
            self._cap_ls_values.clear()
            self._active_caps.clear()
            self._isupport.clear()
            self._batch_buffer.clear()
            self._batch_types.clear()
            self._batch_params.clear()
            self._cap_req_queue.clear()
            self._sasl_state.clear()
            self._auth_buffer = ""
            self._network_announced = False
            self._current_msg_tags = {}
            self._chathistory_cap = ""
            self._current_batch_is_replay = False
            self._label_seq = 0
            self._pending_labels.clear()
            self._whox_seq = 1
            self._whox_tokens.clear()
            keepalive_task: Optional[asyncio.Task] = None
            writer_task:    Optional[asyncio.Task] = None
            try:
                await self.connect()
                attempt = 0
                keepalive_task = asyncio.create_task(self.keepalive())
                writer_task    = asyncio.create_task(self._run_writer())
                await self.handle_incoming()
            except asyncio.CancelledError:
                break
            except Exception as e:
                await self.ui_queue.put(("status", f"Connection error: {e}"))
            finally:
                # Cancel background tasks and drain any leftover sends
                for task in (keepalive_task, writer_task):
                    if task and not task.done():
                        task.cancel()
                        try:
                            await task
                        except asyncio.CancelledError:
                            pass
                while not self._send_queue.empty():
                    try:
                        self._send_queue.get_nowait()
                    except asyncio.QueueEmpty:
                        break
                # Ensure the writer is closed so the OS releases the socket fd
                if self.writer:
                    try:
                        if not self.writer.is_closing():
                            self.writer.close()
                        await asyncio.wait_for(self.writer.wait_closed(), timeout=2.0)
                    except Exception:
                        pass
                    self.writer = None
                    self.reader = None

            if not self.running:
                break

            delay = DELAYS[min(attempt, len(DELAYS) - 1)]
            attempt += 1
            await self.ui_queue.put(("status", f"Reconnecting in {delay}s... (attempt {attempt})"))
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                break

    async def handle_incoming(self) -> None:
        # No per-readline wait_for: keepalive() detects dead TCP connections within
        # PONG_TIMEOUT (120 s) and calls writer.close(), which feeds EOF to the reader
        # and unblocks readline().  Removing wait_for eliminates one Task allocation
        # per received line — measurable on busy channels with hundreds of messages/min.
        try:
            while self.running:
                line = await self.reader.readline()
                if not line:
                    await self.ui_queue.put(("status", "Server closed the connection"))
                    break
                text = line.decode("utf-8", "ignore").rstrip("\r\n")
                if text:
                    try:
                        await self.process_line(text)
                    except Exception as _line_exc:
                        await self.ui_queue.put(("status", f"[err] line handler: {_line_exc}"))
        except Exception as e:
            await self.ui_queue.put(("status", f"Read error: {e}"))
        finally:
            if self.writer:
                try:
                    self.writer.close()
                except Exception:
                    pass
            await self.ui_queue.put(("status", "Disconnected from IRC"))

    @staticmethod
    def _parse_irc_line(raw: str):
        """Parse a raw IRC line (including IRCv3 message-tag prefix).

        Returns (cmd, nick, params, prefix, tags) where:
          cmd    – upper-cased command string
          nick   – nick extracted from prefix (or server name if no '!')
          params – list of parameters; trailing (after ' :') is the last element
          prefix – raw prefix string (needed for NOTICE '!' check)
          tags   – dict of IRCv3 message tags (empty dict if none present)
        Returns None if the line cannot be parsed.

        IRCv3 tagged lines look like:
          @time=2024-01-01T12:00:00.000Z;msgid=abc :nick!u@h PRIVMSG #ch :text
        Without this handling, any server that sends server-time would have ALL
        its messages silently dropped since the '@' breaks the ':' prefix check.
        """
        if not raw:
            return None
        # --- IRCv3 message tags (RFC; section 3.3) ---
        tags: dict = {}
        if raw.startswith("@"):
            try:
                tag_str, raw = raw[1:].split(" ", 1)
            except ValueError:
                return None
            for t in tag_str.split(";"):
                if not t:
                    continue
                if "=" in t:
                    k, v = t.split("=", 1)
                    # Unescape IRCv3 tag escape sequences in a single
                    # left-to-right pass. A chain of .replace() calls
                    # is order-dependent and can re-decode the bytes
                    # produced by an earlier replacement (e.g. an input
                    # containing \\: would be mis-decoded).
                    # Per IRCv3:
                    #     \: → ;   \s → space   \\ → \
                    #     \r → CR  \n → LF
                    #     unknown \X → X (drop the backslash)
                    #     trailing lone \ → dropped
                    _out: list = []
                    _it = iter(v)
                    for _c in _it:
                        if _c == "\\":
                            _n = next(_it, "")
                            if   _n == ":":  _out.append(";")
                            elif _n == "s":  _out.append(" ")
                            elif _n == "\\": _out.append("\\")
                            elif _n == "r":  _out.append("\r")
                            elif _n == "n":  _out.append("\n")
                            elif _n == "":   pass  # trailing \ — drop
                            else:             _out.append(_n)
                        else:
                            _out.append(_c)
                    v = "".join(_out)
                    tags[k] = v
                else:
                    tags[t] = ""
        # --- standard prefix / command / params ---
        prefix = ""
        trailing = None
        if raw.startswith(":"):
            try:
                prefix, raw = raw[1:].split(" ", 1)
            except ValueError:
                return None
        if " :" in raw:
            args, trailing = raw.split(" :", 1)
            parts = args.split()
        else:
            parts = raw.split()
        if not parts:
            return None
        cmd = parts[0].upper()
        params: List[str] = parts[1:]
        if trailing is not None:
            params.append(trailing)
        nick = prefix.split("!")[0] if "!" in prefix else prefix
        return cmd, nick, params, prefix, tags

    async def process_line(self, line: str) -> None:
        parsed = self._parse_irc_line(line)
        if parsed is None:
            return
        cmd, nick, params, prefix, tags = parsed
        self._current_msg_tags = tags
        # If this line carries a batch tag (and we're tracking that batch),
        # buffer it for later bulk dispatch instead of dispatching immediately.
        # BATCH itself is never buffered — it controls the batch lifecycle.
        if cmd != "BATCH":
            batch_ref = tags.get("batch")
            if batch_ref and batch_ref in self._batch_buffer:
                self._batch_buffer[batch_ref].append((cmd, nick, params, prefix, tags))
                return
        handler = self._irc_handlers.get(cmd)
        if handler:
            await handler(nick, params, prefix)
        elif cmd not in _SILENT_NUMERICS:
            if cmd in _SERVER_INFO:
                await self.ui_queue.put(("status", f"{cmd} {' '.join(params)}"))

    # ── IRC command handlers ──────────────────────────────────────────────────

    async def _irc_ping(self, nick, params, prefix):
        self.send_raw(f"PONG :{params[0] if params else 'keepalive'}")

    async def _irc_pong(self, nick, params, prefix):
        self._last_pong = time.monotonic()
        if params:
            try:
                echoed_ts = int(params[0].lstrip(":keepalive-"))
                if echoed_ts > 0:
                    self._latency = time.time() - echoed_ts
            except (ValueError, IndexError):
                pass

    # Capabilities we request whenever the server offers them.
    _WANT_CAPS = (
        "cap-notify",
        "away-notify", "multi-prefix", "account-notify", "extended-join",
        "chghost", "server-time", "echo-message", "userhost-in-names",
        "message-tags", "batch", "labeled-response", "invite-notify",
        "account-tag", "standard-replies", "setname",
        "chathistory", "draft/chathistory",
        "draft/multiline", "draft/format", "draft/ping",
        "message-redaction", "read-marker", "message-intents",
        "draft/thread", "draft/account-registration",
        "draft/reply", "draft/react", "draft/typing",
        "draft/mention", "draft/event-playback",
        "draft/channel-rename", "draft/persistent-channel",
        "draft/resume",
        "soju.im/bouncer-networks", "soju.im/bouncer-networks-notify",
        "soju.im/search", "soju.im/read-away",
    )

    async def _irc_cap(self, nick, params, prefix):
        subcmd = params[1].upper() if len(params) > 1 else ""
        if subcmd == "LS":
            # CAP LS 302 sends caps across multiple lines; "*" means more coming.
            # Preserve cap values (e.g. sts=port=6697,duration=3600).
            more_coming = len(params) > 2 and params[2] == "*"
            for raw_cap in (params[-1] if params else "").split():
                if "=" in raw_cap:
                    cname, cval = raw_cap.split("=", 1)
                else:
                    cname, cval = raw_cap, ""
                cname = cname.lower()
                self._cap_ls_caps.add(cname)
                if cval:
                    self._cap_ls_values[cname] = cval
            if not more_coming:
                if "sts" in self._cap_ls_values and not self.use_ssl:
                    self._handle_sts(self._cap_ls_values["sts"])
                if "chathistory" in self._cap_ls_caps:
                    self._chathistory_cap = "chathistory"
                elif "draft/chathistory" in self._cap_ls_caps:
                    self._chathistory_cap = "draft/chathistory"
                want = [c for c in self._WANT_CAPS if c in self._cap_ls_caps]
                # If both std and draft chathistory are advertised, ask
                # for only the std one — some servers NAK requests that
                # name both variants.
                if "chathistory" in want and "draft/chathistory" in want:
                    want.remove("draft/chathistory")
                _sasl_creds_ok = (
                    SASL_MECHANISM == "EXTERNAL"
                        and bool(SASL_CERT and SASL_KEY)
                    or SASL_MECHANISM == "ECDSA-NIST256P-CHALLENGE"
                        and bool(SASL_KEY)
                    or bool(NICKSERV_PASSWORD)
                )
                if "sasl" in self._cap_ls_caps and _sasl_creds_ok:
                    want.append("sasl")
                self.send_raw(f"CAP REQ :{' '.join(want)}" if want else "CAP END")
                if not want:
                    self._finish_registration()
                self._cap_ls_caps.clear()
        elif subcmd == "ACK":
            acked = set((params[-1] if params else "").lower().split())
            self._active_caps |= acked
            if "soju.im/bouncer-networks" in acked:
                self._soju_is_bouncer = True
                self.send_raw("BOUNCER LISTNETWORKS")
            if "sasl" in acked:
                self.send_raw(f"AUTHENTICATE {SASL_MECHANISM}")
            else:
                self.send_raw("CAP END")
                self._finish_registration()
        elif subcmd == "NAK":
            # Server rejected a batched REQ. Retry each cap
            # individually so we still get whichever subset the
            # server actually supports. Only when the retry queue
            # drains do we fall through to CAP END (and only if
            # SASL is not still in flight — its numeric handlers
            # own CAP END themselves).
            nak_caps = (params[-1] if params else "").lower().split()
            if len(nak_caps) > 1:
                self._cap_req_queue.extend(nak_caps)
            self._flush_cap_req_queue()
        elif subcmd == "NEW":
            # Dynamic cap announcement — request any we want that we don't have yet.
            new_avail: dict = {}
            for raw_cap in (params[-1] if params else "").split():
                if "=" in raw_cap:
                    cname, cval = raw_cap.split("=", 1)
                else:
                    cname, cval = raw_cap, ""
                new_avail[cname.lower()] = cval
                if cval:
                    self._cap_ls_values[cname.lower()] = cval
            if "sts" in new_avail and not self.use_ssl:
                self._handle_sts(new_avail["sts"])
            want = [c for c in self._WANT_CAPS
                    if c in new_avail and c not in self._active_caps]
            if want:
                self.send_raw(f"CAP REQ :{' '.join(want)}")
        elif subcmd == "DEL":
            removed = {c.lower() for c in (params[-1] if params else "").split()}
            self._active_caps -= removed
            await self.ui_queue.put(("status", f"[cap] server withdrew: {' '.join(removed)}"))

    # ------------------------------------------------------------------
    # SASL helpers
    # ------------------------------------------------------------------

    def _send_authenticate(self, payload: str) -> None:
        """Send AUTHENTICATE with 400-char chunking per IRCv3 SASL spec."""
        if not payload:
            self.send_raw("AUTHENTICATE +")
            return
        for i in range(0, len(payload), 400):
            self.send_raw(f"AUTHENTICATE {payload[i:i+400]}")
        if len(payload) % 400 == 0:
            # Exact multiple — trailing empty chunk signals end of message.
            self.send_raw("AUTHENTICATE +")

    async def _sasl_plain(self, _challenge: str) -> None:
        payload = base64.b64encode(
            f"{self.nick}\0{self.nick}\0{NICKSERV_PASSWORD}".encode("utf-8")
        ).decode()
        self._send_authenticate(payload)

    async def _sasl_external(self, _challenge: str) -> None:
        # Empty authzid — server derives identity from TLS client-cert CN/SAN.
        self._send_authenticate("")

    async def _sasl_scram_sha256(self, server_data: str) -> None:
        """SCRAM-SHA-256 (RFC 5802) state machine."""
        step = self._sasl_state.get("step", 0)

        if step == 0 and not NICKSERV_PASSWORD:
            await self.ui_queue.put((
                "status",
                "[SASL] SCRAM-SHA-256 requires IRC_NICKSERV_PASSWORD — aborting"))
            self.send_raw("AUTHENTICATE *")
            self._sasl_state = {}
            return

        if step == 0:
            # Server sent "+" — begin exchange with client-first-message.
            cnonce = base64.b64encode(os.urandom(18)).decode()
            # Escape '=' → '=3D' and ',' → '=2C' in username per spec.
            safe_nick = self.nick.replace("=", "=3D").replace(",", "=2C")
            cfm_bare = f"n={safe_nick},r={cnonce}"
            cfm = f"n,,{cfm_bare}"
            self._sasl_state = {"step": 1, "cnonce": cnonce, "cfm_bare": cfm_bare}
            self._send_authenticate(base64.b64encode(cfm.encode("utf-8")).decode())

        elif step == 1:
            # Server sent server-first-message: r=…,s=…,i=…
            if not server_data:
                await self.ui_queue.put(("status", "[SASL] SCRAM: empty server-first — aborting"))
                self.send_raw("AUTHENTICATE *")
                self._sasl_state = {}
                return
            sfm = base64.b64decode(server_data).decode("utf-8")
            sfm_parts: dict = {}
            for part in sfm.split(","):
                if "=" in part:
                    k, v = part.split("=", 1)
                    sfm_parts[k] = v

            r = sfm_parts.get("r", "")
            s = sfm_parts.get("s", "")
            i_str = sfm_parts.get("i", "4096")
            cnonce = self._sasl_state["cnonce"]

            if not r.startswith(cnonce):
                await self.ui_queue.put(("status", "[SASL] SCRAM: server nonce mismatch — aborting"))
                self.send_raw("AUTHENTICATE *")
                self._sasl_state = {}
                return

            salt = base64.b64decode(s)
            iterations = int(i_str)
            pw = NICKSERV_PASSWORD.encode("utf-8")

            salted_pw   = hashlib.pbkdf2_hmac("sha256", pw, salt, iterations)
            client_key  = hmac.new(salted_pw, b"Client Key", hashlib.sha256).digest()
            stored_key  = hashlib.sha256(client_key).digest()
            server_key  = hmac.new(salted_pw, b"Server Key", hashlib.sha256).digest()

            # GS2 header for no channel binding: "n,," → base64 = "biws"
            cb = base64.b64encode(b"n,,").decode()
            cfw_noproof = f"c={cb},r={r}"
            auth_message = f"{self._sasl_state['cfm_bare']},{sfm},{cfw_noproof}"

            client_sig   = hmac.new(stored_key, auth_message.encode("utf-8"), hashlib.sha256).digest()
            client_proof = bytes(a ^ b for a, b in zip(client_key, client_sig))
            server_sig   = hmac.new(server_key, auth_message.encode("utf-8"), hashlib.sha256).digest()

            cfm_final = f"{cfw_noproof},p={base64.b64encode(client_proof).decode()}"
            self._sasl_state = {
                "step": 2,
                "expected_server_sig": base64.b64encode(server_sig).decode(),
            }
            self._send_authenticate(base64.b64encode(cfm_final.encode("utf-8")).decode())

        elif step == 2:
            # Server-final-message (optional — server may go straight to 903).
            if server_data:
                try:
                    sfinal = base64.b64decode(server_data).decode("utf-8")
                    for part in sfinal.split(","):
                        if part.startswith("v="):
                            expected = self._sasl_state.get("expected_server_sig", "")
                            if part[2:] != expected:
                                await self.ui_queue.put(
                                    ("status", "[SASL] SCRAM: server signature mismatch (MITM?)"))
                            break
                except Exception:
                    pass
            self._sasl_state = {}

    async def _sasl_ecdsa(self, server_data: str) -> None:
        """ECDSA-NIST256P-CHALLENGE state machine."""
        step = self._sasl_state.get("step", 0)

        if step == 0:
            # Server sent "+" — send account name (nick).
            self._sasl_state = {"step": 1}
            self._send_authenticate(base64.b64encode(self.nick.encode("utf-8")).decode())

        elif step == 1:
            # Server sent the challenge to sign.
            if not server_data:
                await self.ui_queue.put(("status", "[SASL] ECDSA: empty challenge — aborting"))
                self.send_raw("AUTHENTICATE *")
                self._sasl_state = {}
                return
            if not CRYPTOGRAPHY_AVAILABLE:
                await self.ui_queue.put((
                    "status",
                    "[SASL] ECDSA requires the 'cryptography' package — pip install cryptography",
                ))
                self.send_raw("AUTHENTICATE *")
                self._sasl_state = {}
                return
            if not SASL_KEY:
                await self.ui_queue.put(("status", "[SASL] ECDSA: IRC_SASL_KEY not set — aborting"))
                self.send_raw("AUTHENTICATE *")
                self._sasl_state = {}
                return
            try:
                challenge_bytes = base64.b64decode(server_data)
                with open(SASL_KEY, "rb") as _kf:
                    private_key = _load_pem_private_key(_kf.read(), password=None)
                # sign() hashes with SHA-256 internally before signing.
                sig = private_key.sign(challenge_bytes, _ecdsa_ec.ECDSA(_ecdsa_hashes.SHA256()))
                self._send_authenticate(base64.b64encode(sig).decode())
                self._sasl_state = {}
            except Exception as exc:
                await self.ui_queue.put(("status", f"[SASL] ECDSA signing failed: {exc}"))
                self.send_raw("AUTHENTICATE *")
                self._sasl_state = {}

    async def _irc_authenticate(self, nick, params, prefix):
        chunk = params[0] if params else "+"
        # IRCv3 SASL: each chunk is ≤ 400 chars of base64; accumulate until
        # we get a short chunk (or "+").  "+" alone means empty payload.
        if len(chunk) == 400:
            self._auth_buffer += chunk
            return
        server_data = self._auth_buffer + ("" if chunk == "+" else chunk)
        self._auth_buffer = ""

        mech = SASL_MECHANISM
        if mech == "PLAIN":
            await self._sasl_plain(server_data)
        elif mech == "EXTERNAL":
            await self._sasl_external(server_data)
        elif mech == "SCRAM-SHA-256":
            await self._sasl_scram_sha256(server_data)
        elif mech == "ECDSA-NIST256P-CHALLENGE":
            await self._sasl_ecdsa(server_data)
        else:
            await self.ui_queue.put(("status", f"[SASL] Unknown mechanism '{mech}' — aborting"))
            self.send_raw("AUTHENTICATE *")

    async def _irc_sasl_ok(self, nick, params, prefix):  # 903
        await self.ui_queue.put(("status", "SASL authentication successful — ident set"))
        self._identified = True
        self.send_raw("CAP END")
        self._finish_registration()

    async def _irc_sasl_fail(self, nick, params, prefix):  # 904
        await self.ui_queue.put(("status", "SASL authentication failed — falling back to NickServ"))
        # Abort the SASL session cleanly before ending CAP.
        self.send_raw("AUTHENTICATE *")
        self.send_raw("CAP END")
        self._finish_registration()

    async def _irc_resumed(self, nick, params, prefix):  # 740 RPL_RESUMED
        if len(params) >= 3:
            self._resume_token = params[1]
            self._resume_ts = params[2]
        self._resumed_session = True
        self._save_resume_config()
        await self.ui_queue.put(("status",
            f"[resume] Session resumed (token: {self._resume_token[:16]}...)"))
        await self.ui_queue.put(("resumed",))

    async def _irc_resumeack(self, nick, params, prefix):  # 741 RPL_RESUMEACK
        if len(params) >= 2:
            self._resume_token = params[1]
        self._resumed_session = True
        self._save_resume_config()
        await self.ui_queue.put(("status",
            f"[resume] Resumed on another server (token: {self._resume_token[:16]}...)"))
        await self.ui_queue.put(("resumed",))

    def _save_resume_config(self) -> None:
        """Persist resume token to irc_config.json."""
        try:
            cfg = load_irc_config()
            cfg["resume"] = {"token": self._resume_token, "ts": self._resume_ts}
            save_irc_config(cfg)
        except Exception:
            pass

    def _irc_lower(self, s: str) -> str:
        r"""Casefold *s* per the server's CASEMAPPING ISUPPORT token.

        The default is rfc1459, which folds {|}~ to []\^ in addition
        to ASCII case. This matters for nick/channel equality checks:
        plain str.lower() would treat 'Foo[' and 'foo{' as different.
        """
        mapping = self._isupport.get("CASEMAPPING", "rfc1459")
        s = s.lower()
        if mapping == "ascii":
            return s
        if mapping == "strict-rfc1459":
            return s.translate(str.maketrans(r"\[]", r"|{}"))
        # rfc1459 (default)
        return s.translate(str.maketrans("[\\]^", "{|}~"))

    def _flush_cap_req_queue(self) -> None:
        """Pop the next queued single-cap REQ, or send CAP END.

        Used after CAP NAK to retry caps one at a time. SASL is
        deliberately *not* flushed here: when SASL is in flight
        the SASL numeric handlers (903/904) own CAP END, and we
        must not race them.
        """
        if self._cap_req_queue:
            cap = self._cap_req_queue.pop(0)
            self.send_raw(f"CAP REQ :{cap}")
        elif "sasl" not in self._active_caps:
            self.send_raw("CAP END")
            self._finish_registration()

    def _handle_sts(self, sts_value: str) -> None:
        """Parse Strict Transport Security CAP value and warn if TLS upgrade needed.

        Per IRCv3 STS:
          • duration=0 → server is *revoking* its policy. No warning.
          • port must be a valid TCP port number; ignore garbage.
        """
        params: dict = {}
        for part in sts_value.split(","):
            if "=" in part:
                k, v = part.split("=", 1)
                params[k] = v
            else:
                params[part] = ""
        # Validate port — fall back to the IRC TLS default if missing/garbage.
        port_str = params.get("port", "6697")
        try:
            port_int = int(port_str)
            if not (1 <= port_int <= 65535):
                raise ValueError
            port = str(port_int)
        except (TypeError, ValueError):
            port = "6697"
        # Validate duration — treat malformed as 0 (revoke).
        try:
            duration_int = int(params.get("duration", "0") or "0")
        except (TypeError, ValueError):
            duration_int = 0
        if duration_int <= 0:
            self._sts_policies.pop(self.server, None)
            self._save_sts_policies()
            try:
                self.ui_queue.put_nowait(("status", f"[STS] Policy revoked for {self.server}"))
            except Exception:
                pass
            return
        preload = "preload" in params
        now = time.time()
        self._sts_policies[self.server] = {
            "port": port_int, "duration": duration_int, "timestamp": now,
        }
        self._save_sts_policies()
        _expires = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(now + duration_int))
        msg = (f"[STS] Pinned policy for {self.server}: SSL port {port}, "
               f"duration={duration_int}s (expires {_expires})")
        try:
            self.ui_queue.put_nowait(("status", msg))
        except Exception:
            pass

    def send_tagged(self, tags: dict, line: str) -> None:
        """Prepend IRCv3 message tags to *line* when message-tags cap is active."""
        if tags and "message-tags" in self._active_caps:
            def _esc(v: str) -> str:
                return (v.replace("\\", "\\\\").replace(";", "\\:")
                          .replace(" ", "\\s").replace("\r", "\\r")
                          .replace("\n", "\\n"))
            tag_str = ";".join(
                f"{k}={_esc(str(v))}" if v else k for k, v in tags.items()
            )
            self.send_raw(f"@{tag_str} {line}")
        else:
            self.send_raw(line)

    def _next_label(self) -> str:
        """Generate a unique label for labeled-response."""
        self._label_seq += 1
        return f"eyrc-{self._label_seq}"

    async def _irc_logged_in(self, nick, params, prefix):  # 900
        account = params[2] if len(params) > 2 else "?"
        await self.ui_queue.put(("status", f"Logged in as {account}"))

    async def _irc_welcome(self, nick, params, prefix):  # 001
        await self.ui_queue.put(("clear_users",))
        if self._resumed_session:
            await self.ui_queue.put(("status",
                "Session resumed — server will replay channel state"))
            self._resumed_session = False
        else:
            await self.ui_queue.put(("status", "Successfully logged in to IRC"))
            if not self._identified and NICKSERV_PASSWORD:
                asyncio.create_task(self._delayed_nickserv_identify())
            for ch in sorted(self.joined_channels):
                self.send_raw(f"JOIN {ch}")
                await self.ui_queue.put(("status", f"Joining {ch}..."))
            for ch in sorted(_AUTOJOIN_CHANNELS):
                if self._irc_lower(ch) not in (self._irc_lower(c) for c in self.joined_channels):
                    self.send_raw(f"JOIN {ch}")
                    await self.ui_queue.put(("status", f"Joining {ch}..."))
        if not self.current_channel and DEFAULT_CHANNEL:
            self.current_channel = DEFAULT_CHANNEL
        if self._soju_is_bouncer and self._chathistory_cap:
            asyncio.create_task(self._soju_auto_replay())
        # Query own user modes (triggers 221 RPL_UMODEIS)
        self.send_raw(f"MODE {self.nick}")

    async def _soju_auto_replay(self) -> None:
        """Request chathistory for all joined channels after soju connect."""
        await asyncio.sleep(2)
        all_ch = set(self.joined_channels) | set(_AUTOJOIN_CHANNELS)
        for ch in sorted(all_ch):
            self.cmd_chathistory(ch, count=50)
        if all_ch:
            await self.ui_queue.put(("status",
                f"[soju] auto-replay requested for {len(all_ch)} channel{'s' if len(all_ch) != 1 else ''}"))

    def _finish_registration(self) -> None:
        """Send NICK/USER or RESUME after CAP negotiation completes."""
        if self._resume_token and "draft/resume" in self._active_caps:
            self.send_raw(f"RESUME {self._resume_token}")
            try:
                self.ui_queue.put_nowait(("status", f"[resume] Attempting resume with token {self._resume_token[:16]}..."))
            except Exception:
                pass
        else:
            self.send_raw(f"NICK {self.nick}")
            self.send_raw(f"USER {self.nick} 0 * :{self.nick}")
            try:
                self.ui_queue.put_nowait(("status", "Sent NICK and USER commands"))
            except Exception:
                pass

    async def _irc_join(self, nick, params, prefix):
        if not params:
            return
        channel = params[0]
        await self.ui_queue.put(("join", nick, channel))
        if nick == self.nick:
            await self.ui_queue.put(("self_join", channel))
        triggered = self.scoring.watches.check_event("join", nick, channel)
        for tw in triggered:
            alert = tw.get("message") or f"{nick} joined {channel}"
            await self.ui_queue.put(("status", f"[watch] {alert}"))

    async def _irc_part(self, nick, params, prefix):
        if params:
            await self.ui_queue.put(("part", nick, params[0]))

    async def _irc_kick(self, nick, params, prefix):
        if params:
            reason = params[-1] if len(params) > 2 else ""
            await self.ui_queue.put(("kick", nick, params[0],
                                     params[1] if len(params) > 1 else "", reason))

    async def _irc_topic_cmd(self, nick, params, prefix):
        if params:
            await self.ui_queue.put(("topic", params[0], params[-1] if len(params) > 1 else ""))

    async def _irc_mode(self, nick, params, prefix):
        # User mode change for self — update own modes
        if params and self._irc_lower(params[0]) == self._irc_lower(self.nick):
            self._apply_umodes(params[1])
            await self.ui_queue.put(("own_umodes", self._own_umodes.copy()))
        await self.ui_queue.put(("mode", nick, params))

    def _apply_umodes(self, modestr: str) -> None:
        """Parse a user mode string like ``+io-x`` and update ``_own_umodes``."""
        adding = True
        for ch in modestr:
            if ch == "+":
                adding = True
            elif ch == "-":
                adding = False
            elif ch.isalpha():
                if adding:
                    self._own_umodes.add(ch)
                else:
                    self._own_umodes.discard(ch)

    async def _irc_umodeis(self, nick, params, prefix):  # 221 RPL_UMODEIS
        if len(params) >= 2:
            self._apply_umodes(params[1])
            await self.ui_queue.put(("own_umodes", self._own_umodes.copy()))

    async def _irc_youreoper(self, nick, params, prefix):  # 381 RPL_YOUREOPER
        self._own_umodes.add("o")
        await self.ui_queue.put(("own_umodes", self._own_umodes.copy()))
        await self.ui_queue.put(("status", "[oper] You are now an IRC operator (+o)"))

    async def _irc_whois_reply(self, cmd_key: str, nick, params, prefix):
        w = params[1] if len(params) > 1 else "?"
        if cmd_key == "311" and len(params) >= 5:
            user, host = params[2], params[3]
            real = params[5] if len(params) > 5 else ""
            text = f"[whois] {w}  ({user}@{host})  \"{real}\""
        elif cmd_key == "312" and len(params) >= 3:
            srv  = params[2]
            info = params[3] if len(params) > 3 else ""
            text = f"[whois] {w}  server: {srv}" + (f" — {info}" if info else "")
        elif cmd_key == "313":
            self._ircop_nicks.add(self._irc_lower(w))
            await self.ui_queue.put(("ircop_status", w, True))
            text = f"[whois] {w}  ◈ is an IRC operator"
        elif cmd_key == "317" and len(params) >= 3:
            try:
                secs = int(params[2])
                parts_idle = []
                if secs >= 3600:
                    parts_idle.append(f"{secs // 3600}h")
                parts_idle.append(f"{(secs % 3600) // 60}m {secs % 60}s")
                idle_str = " ".join(parts_idle)
            except ValueError:
                idle_str = params[2]
            sign_str = ""
            if len(params) > 3 and params[3].isdigit():
                sign_str = "  signed on: " + time.strftime(
                    "%Y-%m-%d %H:%M", time.localtime(int(params[3])))
            text = f"[whois] {w}  idle: {idle_str}{sign_str}"
        elif cmd_key == "318":
            text = f"[whois] ── end of whois for {w} ──"
        elif cmd_key == "319" and len(params) >= 3:
            text = f"[whois] {w}  channels: {params[2]}"
        elif cmd_key == "307":
            text = f"[whois] {w}  is a registered nick"
        elif cmd_key == "330" and len(params) >= 3:
            text = f"[whois] {w}  logged in as: {params[2]}"
        elif cmd_key == "671":
            text = f"[whois] {w}  is using a secure connection (SSL/TLS)"
        else:
            text = f"[whois] {' '.join(params[1:])}"
        await self.ui_queue.put(("whois", text))

    async def _irc_privmsg(self, nick, params, prefix):
        if len(params) < 2:
            return
        tags = self._current_msg_tags
        # labeled-response: if the echo carries a label we sent, discard it cleanly.
        label = tags.get("label", "")
        if label and label in self._pending_labels:
            self._pending_labels.discard(label)
            return
        # Fallback nick-based echo dedup (when labeled-response not negotiated).
        if (self._irc_lower(nick) == self._irc_lower(self.nick)
                and not self._current_batch_is_replay):
            return
        # Biometrics: record incoming message timestamp for response latency
        self.biometrics.record_incoming_message()
        target = params[0]
        msg    = params[1]
        # server-time: prefer server-provided timestamp over local clock
        ts_str = _parse_server_time(tags["time"]) if "time" in tags else None
        # account-tag: sender's services account (if server advertises it)
        account  = tags.get("account", "")
        msgid    = tags.get("msgid", "")
        reply_to = tags.get("+reply", "")
        thread_id = tags.get("draft/thread", "")
        is_replay = self._current_batch_is_replay
        # read-marker: track last seen read marker per channel
        read_marker = tags.get("read-marker", "")
        if read_marker and target.startswith("#"):
            self._read_markers[target.lower()] = read_marker
        if thread_id and target.startswith("#"):
            self._thread_parents[target.lower()] = thread_id

        # ACTION must be checked before the generic CTCP block — both use \x01
        # wrappers and falling into the CTCP branch silently drops /me lines.
        is_action = msg.startswith("\x01ACTION ") and msg.endswith("\x01")
        if is_action:
            msg = msg[len("\x01ACTION "):-1]
        elif msg.startswith("\x01") and msg.endswith("\x01"):
            # Generic CTCP request (handled above — this path is dead for CTCP)
            return
        # User scoring — compute initial scores from historical state
        u_state = self.users.get(nick)
        if u_state is None:
            u_state = UserState(nick)
            self.users[nick] = u_state
        u_score = self.scoring.score_user(u_state)
        m_score = 50
        # mention tag: server indicates this message mentions our nick
        mention = tags.get("mention", "")
        # message-intents: optional tag describing message purpose
        intent = tags.get("+intent", "")
        await self.ui_queue.put(("msg", nick, target, msg, u_score, m_score, 0, 0,
                                 is_action, ts_str, account, is_replay, msgid, reply_to,
                                 mention, intent))
        if is_replay:
            return  # don't score replayed history; it's already been seen
        # Relationship graph: record mentions and replies
        if target.startswith("#"):
            self.scoring.relationships.record_co_channel(nick, target)
            for word in msg.split():
                if word.startswith("@"):
                    mentioned = word.lstrip("@").strip(",:;.!?")
                    if mentioned:
                        self.scoring.relationships.record_mention(nick, mentioned, target)
            if reply_to:
                self.scoring.relationships.record_reply(nick, reply_to)
            self.scoring.relationships.record_co_channel(nick, target)
        _t = asyncio.create_task(self._score_msg_bg(nick, target, msg, u_state, u_score, m_score))
        self._bg_tasks.add(_t)
        _t.add_done_callback(self._bg_tasks.discard)

    async def _irc_nick_change(self, nick, params, prefix):
        new_nick = params[0] if params else ""
        old_lower = self._irc_lower(nick)
        new_lower = self._irc_lower(new_nick)
        if old_lower in self._ircop_nicks:
            self._ircop_nicks.discard(old_lower)
            self._ircop_nicks.add(new_lower)
            await self.ui_queue.put(("ircop_status", nick, False))
            await self.ui_queue.put(("ircop_status", new_nick, True))
        if nick == self.nick:
            self.nick = new_nick
            # If we reclaimed our desired nick, stop the recovery loop.
            if new_nick == self._desired_nick:
                if self._nick_reclaim_task and not self._nick_reclaim_task.done():
                    self._nick_reclaim_task.cancel()
                    await self.ui_queue.put(("status", f"Reclaimed nick {new_nick}"))
        await self.ui_queue.put(("nick_change", nick, new_nick))

    async def _irc_notice(self, nick, params, prefix):
        text = params[-1] if params else ""
        if "!" in prefix:  # user NOTICE (not server)
            target = params[0] if params else self.nick
            display_target = target if target.startswith("#") else "*status*"
            await self.ui_queue.put(("notice", nick, display_target, text))
        else:
            await self.ui_queue.put(("status", f"NOTICE {text}"))

    async def _irc_quit(self, nick, params, prefix):
        self.users.pop(nick, None)
        reason = params[-1] if params else ""
        await self.ui_queue.put(("quit", nick, reason))

    async def _irc_names(self, nick, params, prefix):  # 353 RPL_NAMREPLY
        if len(params) < 4:
            return
        channel = params[2]
        prefix_isup = self._isupport.get("PREFIX", "(qaohv)~&@%+")
        prefix_chars = prefix_isup.split(")", 1)[1] if ")" in prefix_isup else "@+%&~!"
        pairs = []
        for entry in params[3].split():
            bare = entry.lstrip(prefix_chars)
            if "!" in bare:
                bare = bare.split("!", 1)[0]
            if bare:
                mode_char = entry[0] if entry and entry[0] in prefix_chars else ""
                pairs.append(f"{mode_char}{bare}")
        await self.ui_queue.put(("names", channel, " ".join(pairs)))

    async def _irc_who_reply(self, nick, params, prefix):  # 352/314
        await self.ui_queue.put(("status", f"{params[0] if params else ''} {' '.join(params[1:])}"))

    async def _irc_away_reply(self, nick, params, prefix):  # 301
        await self.ui_queue.put(("status", f"Away: {' '.join(params[1:])}"))

    async def _irc_chanmode(self, nick, params, prefix):  # 324 RPL_CHANNELMODEIS
        if len(params) >= 3:
            channel = params[1]
            modestr = params[2]
            mode_args = params[3:]
            await self.ui_queue.put(("chanmode", channel, modestr, mode_args))

    async def _irc_topic_reply(self, nick, params, prefix):  # 332
        channel = params[1] if len(params) > 1 else ""
        topic   = params[-1] if len(params) > 2 else ""
        await self.ui_queue.put(("topic", channel, topic))

    async def _irc_no_topic(self, nick, params, prefix):  # 331
        channel = params[1] if len(params) > 1 else ""
        await self.ui_queue.put(("status", f"No topic set for {channel}"))

    async def _irc_nick_in_use(self, nick, params, prefix):  # 433
        # During registration: append underscore and retry.
        # After registration: server rejected a NICK change — just report it.
        if not self._identified:
            self.nick = (self.nick + "_")[:30]
            self.send_raw(f"NICK {self.nick}")
            await self.ui_queue.put(("status", f"Nickname in use — trying {self.nick}"))
            # Start a background loop that periodically tries to reclaim the
            # original nick.  Only start one; cancel any stale previous one.
            if self._nick_reclaim_task and not self._nick_reclaim_task.done():
                self._nick_reclaim_task.cancel()
            self._nick_reclaim_task = asyncio.create_task(self._nick_reclaim_loop())
        else:
            wanted = params[1] if len(params) > 1 else "?"
            await self.ui_queue.put(("status", f"Nickname {wanted} is already in use"))

    async def _irc_bad_nick(self, nick, params, prefix):  # 432
        bad = params[1] if len(params) > 1 else "?"
        await self.ui_queue.put(("status", f"Erroneous nickname rejected by server: {bad}"))

    async def _irc_join_error(self, nick, params, prefix):  # 471/473/474/475/477/489
        channel = params[1] if len(params) > 1 else ""
        text    = params[-1] if len(params) > 2 else ""
        await self.ui_queue.put(("join_error", channel, f"Cannot join {channel}: {text}"))

    async def _irc_away_notify(self, nick, params, prefix):  # AWAY cap
        reason = params[-1] if params else ""
        if reason:
            await self.ui_queue.put(("status", f"* {nick} is away: {reason}"))
        else:
            await self.ui_queue.put(("status", f"* {nick} is back"))

    async def _irc_chghost(self, nick, params, prefix):
        new_user = params[0] if params else ""
        new_host = params[1] if len(params) > 1 else ""
        await self.ui_queue.put(("status", f"* {nick} changed host to {new_user}@{new_host}"))

    async def _irc_account(self, nick, params, prefix):
        account = params[0] if params else "*"
        # Persist on the UserState (creating one if we haven't seen
        # this nick before) so account-tag consumers elsewhere see
        # a consistent value. setattr keeps us forward-compatible
        # even if UserState doesn't yet declare `account`.
        u = self.users.get(nick)
        if u is None:
            u = UserState(nick)
            self.users[nick] = u
        try:
            u.account = "" if account == "*" else account
        except Exception:
            pass  # __slots__ without `account` — ignore
        if account == "*":
            await self.ui_queue.put(("status", f"* {nick} logged out of services"))
        else:
            await self.ui_queue.put(("status", f"* {nick} is identified as {account}"))

    async def _irc_setname(self, nick, params, prefix):
        realname = params[0] if params else ""
        await self.ui_queue.put(("status", f"* {nick} changed real name to: {realname}"))

    async def _irc_batch(self, nick, params, prefix):
        if not params:
            return
        ref_dir = params[0]
        if ref_dir.startswith("+"):
            ref = ref_dir[1:]
            self._batch_buffer[ref] = []
            self._batch_types[ref] = params[1] if len(params) > 1 else ""
            self._batch_params[ref] = params  # save full params for multiline target
        elif ref_dir.startswith("-"):
            ref = ref_dir[1:]
            buffered   = self._batch_buffer.pop(ref, [])
            batch_type = self._batch_types.pop(ref, "")
            open_params = self._batch_params.pop(ref, [])
            # draft/multiline: combine lines into a single message
            if batch_type == "draft/multiline":
                await self._handle_multiline_batch(buffered, open_params)
                return
            is_replay = batch_type in ("chathistory", "draft/chathistory", "draft/event-playback")
            prev_replay = self._current_batch_is_replay
            self._current_batch_is_replay = is_replay
            try:
                for bcmd, bnick, bparams, bprefix, btags in buffered:
                    handler = self._irc_handlers.get(bcmd)
                    if handler:
                        self._current_msg_tags = btags
                        try:
                            await handler(bnick, bparams, bprefix)
                        except Exception as _batch_exc:
                            await self.ui_queue.put(
                                ("status", f"[err] batch {bcmd}: {_batch_exc}"))
            finally:
                self._current_batch_is_replay = prev_replay
                self._current_msg_tags = {}

    async def _handle_multiline_batch(self, buffered: list, open_params: list) -> None:
        """Combine draft/multiline batch lines into a single PRIVMSG dispatch."""
        target = open_params[2] if len(open_params) > 2 else ""
        if not target or not buffered:
            return
        combined: list = []
        first_tags: dict = {}
        first_nick: str = ""
        for bcmd, bnick, bparams, bprefix, btags in buffered:
            if bcmd != "PRIVMSG":
                continue
            if not first_nick:
                first_nick = bnick
                first_tags = btags
            line_text = bparams[1] if len(bparams) > 1 else ""
            concat = "draft/multiline-concat" in btags
            if combined and not concat:
                combined.append("\n")
            combined.append(line_text)
        if not combined or not first_nick:
            return
        combined_text = "".join(combined)
        prev_tags = self._current_msg_tags
        self._current_msg_tags = first_tags
        try:
            await self._irc_privmsg(first_nick, [target, combined_text], "")
        finally:
            self._current_msg_tags = prev_tags

    async def _irc_redact(self, nick, params, prefix):
        """Handle incoming REDACT command (message-redaction CAP)."""
        if len(params) < 2:
            return
        target = params[0]
        msgid  = params[1]
        reason = params[2] if len(params) > 2 else ""
        await self.ui_queue.put(("redact", nick, target, msgid, reason))

    async def _irc_markread(self, nick, params, prefix):
        """Handle incoming MARKREAD response (read-marker CAP)."""
        if len(params) < 2:
            return
        target = params[0]
        ts_arg = params[1]  # e.g. "timestamp=2024-01-15T14:30:00.000Z"
        await self.ui_queue.put(("markread", target, ts_arg))

    async def _irc_tagmsg(self, nick, params, prefix):
        tags = self._current_msg_tags
        target = params[0] if params else ""
        typing_state = tags.get("+typing", "")
        if typing_state in ("active", "paused", "done"):
            await self.ui_queue.put(("typing", nick, target, typing_state))
        react    = tags.get("+react", "")
        reply_to = tags.get("+reply", "")
        if react and reply_to:
            await self.ui_queue.put(("react", nick, target, reply_to, react))

    async def _irc_channelrename(self, nick, params, prefix):
        if len(params) >= 2:
            old_ch = params[0]
            new_ch = params[1]
            # Update joined_channels
            old_lower = self._irc_lower(old_ch)
            new_lower = self._irc_lower(new_ch)
            self.joined_channels.discard(old_ch)
            self.joined_channels.add(new_ch)
            await self.ui_queue.put(("status",
                f"*** Channel renamed: {old_ch} → {new_ch}"))
            await self.ui_queue.put(("channel_rename", old_ch, new_ch))

    async def _irc_invite(self, nick, params, prefix):
        if len(params) < 2:
            return
        invitee = params[0]
        channel = params[1]
        if self._irc_lower(invitee) == self._irc_lower(self.nick):
            await self.ui_queue.put(("status", f"*** {nick} invites you to join {channel}"))
        else:
            # invite-notify: someone else in the channel was invited
            await self.ui_queue.put(("status", f"*** {nick} invited {invitee} to {channel}"))

    async def _irc_fail(self, nick, params, prefix):
        text = " ".join(params)
        if "RESUME" in text.upper() and self._resume_token:
            await self.ui_queue.put(("status",
                "[resume] Resume failed — connecting fresh"))
            self._resume_token = ""
            self._resume_ts = ""
            self.send_raw(f"NICK {self.nick}")
            self.send_raw(f"USER {self.nick} 0 * :{self.nick}")
        else:
            await self.ui_queue.put(("status", f"[FAIL] {text}"))

    async def _irc_warn(self, nick, params, prefix):
        await self.ui_queue.put(("status", f"[WARN] {' '.join(params)}"))

    async def _irc_note(self, nick, params, prefix):
        await self.ui_queue.put(("status", f"[NOTE] {' '.join(params)}"))

    async def _irc_bouncer(self, nick, params, prefix):
        if not params:
            return
        sub = params[0].upper()
        if sub == "LISTNETWORKS":
            # BOUNCER LISTNETWORKS sends individual lines + end marker
            # Each data line: BOUNCER NETWORK <id> <k=v ...>
            pass
        elif sub == "NETWORK":
            net_id = params[1] if len(params) > 1 else ""
            attrs = {}
            for kv_str in params[2:]:
                if "=" in kv_str:
                    k, v = kv_str.split("=", 1)
                    attrs[k] = v
            self._soju_networks[net_id] = attrs
            name = attrs.get("name", net_id)
            host = attrs.get("host", "?")
            state = attrs.get("state", "?")
            await self.ui_queue.put(("status",
                f"[soju] network {name}: host={host} state={state}"))
        elif sub == "ENDNETWORKS":
            n = len(self._soju_networks)
            await self.ui_queue.put(("status",
                f"[soju] {n} network{'s' if n != 1 else ''} loaded"))
        elif sub == "ADDNETWORK":
            name = params[1] if len(params) > 1 else ""
            await self.ui_queue.put(("status", f"[soju] network '{name}' added"))
            self.send_raw("BOUNCER LISTNETWORKS")
        elif sub == "DELNETWORK":
            name = params[1] if len(params) > 1 else ""
            self._soju_networks.pop(name, None)
            await self.ui_queue.put(("status", f"[soju] network '{name}' removed"))
        elif sub == "CHANGENETWORK":
            name = params[1] if len(params) > 1 else ""
            attrs = {}
            for kv_str in params[2:]:
                if "=" in kv_str:
                    k, v = kv_str.split("=", 1)
                    attrs[k] = v
            if name in self._soju_networks:
                self._soju_networks[name].update(attrs)
            else:
                self._soju_networks[name] = attrs
            await self.ui_queue.put(("status",
                f"[soju] network '{name}' updated: {attrs}"))
        else:
            await self.ui_queue.put(("status",
                f"[soju] BOUNCER {sub} {' '.join(params[1:])}"))

    async def _irc_mononline(self, nick, params, prefix):   # 730 RPL_MONONLINE
        for entry in (params[-1] if params else "").split(","):
            if entry:
                bare = entry.split("!")[0] if "!" in entry else entry
                await self.ui_queue.put(("status", f"[monitor] {bare} is online"))

    async def _irc_monoffline(self, nick, params, prefix):  # 731 RPL_MONOFFLINE
        for n in (params[-1] if params else "").split(","):
            if n:
                await self.ui_queue.put(("status", f"[monitor] {n} is offline"))

    async def _irc_monlist(self, nick, params, prefix):     # 732 RPL_MONLIST
        nicks = [n for n in (params[-1] if params else "").split(",") if n]
        if nicks:
            await self.ui_queue.put(("status", f"[monitor] watching: {', '.join(nicks)}"))

    async def _irc_monlistfull(self, nick, params, prefix): # 734 ERR_MONLISTFULL
        await self.ui_queue.put(("status", f"[monitor] list full — {' '.join(params[1:])}"))

    async def _irc_reg_success(self, nick, params, prefix):  # 920 RPL_REG_SUCCESS
        acct = params[1] if len(params) > 1 else "?"
        await self.ui_queue.put(("status", f"[register] '{acct}' registered successfully"))

    async def _irc_reg_verification(self, nick, params, prefix):  # 921 RPL_REG_VERIFICATION_REQUIRED
        acct = params[1] if len(params) > 1 else "?"
        detail = params[-1] if len(params) > 2 else ""
        await self.ui_queue.put(("status",
            f"[register] '{acct}' needs email verification" + (f" — {detail}" if detail else "")))

    async def _irc_reg_error(self, nick, params, prefix):  # 922–924 ERR_REG_*
        msg = params[-1] if params else "unknown error"
        await self.ui_queue.put(("status", f"[register] error: {msg}"))

    async def _irc_whox_reply(self, nick, params, prefix):  # 354 RPL_WHOSPCRPL
        vals = params[1:]  # drop our nick (params[0])
        token = vals[0] if vals else ""
        fields = self._whox_tokens.get(token, "")
        if fields:
            # WHOX servers always return fields in this fixed order (§ WHOX spec),
            # skipping any that weren't requested. 't' is first and already consumed.
            FIELD_ORDER = "cuihsnfdlar"
            FIELD_LABELS = {
                'c': 'chan',  'u': 'user', 'i': 'ip',   'h': 'host',
                's': 'server','n': 'nick', 'f': 'flags', 'd': 'hop',
                'l': 'idle',  'a': 'acct', 'r': 'real',
            }
            ordered = [f for f in FIELD_ORDER if f in fields]
            data = vals[1:]  # values after token
            parts = [f"{FIELD_LABELS.get(f, f)}={data[i]}"
                     for i, f in enumerate(ordered) if i < len(data)]
            await self.ui_queue.put(("status", f"[who] {'  '.join(parts)}"))
        else:
            await self.ui_queue.put(("status", f"[who] {' '.join(vals)}"))

    async def _irc_list(self, nick, params, prefix):  # 322 RPL_LIST
        if len(params) >= 3:
            channel = params[1]
            num_users = params[2] if len(params) > 2 else "0"
            topic = params[-1] if len(params) > 3 else ""
            self._list_results.append((channel, num_users, topic))

    async def _irc_listend(self, nick, params, prefix):  # 323 RPL_LISTEND
        results = self._list_results
        self._list_results = []
        await self.ui_queue.put(("list_results", results))

    async def _irc_banlist(self, nick, params, prefix):  # 367 RPL_BANLIST
        if len(params) >= 3:
            channel = params[1]
            mask = params[2]
            setter = params[3] if len(params) > 3 else ""
            ts_raw = params[4] if len(params) > 4 else ""
            self._banlist_results.append((channel, mask, setter, ts_raw))

    async def _irc_banlist_end(self, nick, params, prefix):  # 368 RPL_ENDOFBANLIST
        results = self._banlist_results
        self._banlist_results = []
        await self.ui_queue.put(("banlist", results))

    async def _irc_isupport(self, nick, params, prefix):  # 005 RPL_ISUPPORT
        """Parse ISUPPORT tokens and extract useful server capabilities."""
        # params = [yournick, TOKEN, TOKEN=value, ..., "are supported by this server"]
        for token in params[1:-1]:
            if not token:
                continue
            if token.startswith("-"):
                self._isupport.pop(token[1:], None)
            elif "=" in token:
                k, v = token.split("=", 1)
                self._isupport[k] = v
            else:
                self._isupport[token] = True
        # Announce the network name the first time we see it.
        # The flag lives on the instance, not in _isupport, so it
        # doesn't shadow real ISUPPORT tokens.
        if "NETWORK" in self._isupport and not self._network_announced:
            self._network_announced = True
            await self.ui_queue.put(("status",
                f"Network: {self._isupport['NETWORK']}"))

    async def _irc_no_such_nick(self, nick, params, prefix):  # 401 ERR_NOSUCHNICK
        target = params[1] if len(params) > 1 else params[0] if params else "?"
        await self.ui_queue.put(("status", f"No such nick/channel: {target}"))

    async def _nick_reclaim_loop(self) -> None:
        """Periodically send NICK <desired> to reclaim the original nick.

        Runs after a 433 collision forces us onto nick_.  Tries every 30 s.
        Cancelled automatically by _irc_nick_change once we succeed.
        """
        try:
            await asyncio.sleep(30)
            while self.running and self.nick != self._desired_nick:
                self.send_raw(f"NICK {self._desired_nick}")
                await asyncio.sleep(30)
        except asyncio.CancelledError:
            pass

    def _build_irc_handlers(self) -> None:
        """Populate the IRC command dispatch table."""
        h = self._irc_handlers
        h["PING"]         = self._irc_ping
        h["PONG"]         = self._irc_pong
        h["CAP"]          = self._irc_cap
        h["AUTHENTICATE"] = self._irc_authenticate
        h["903"]          = self._irc_sasl_ok
        h["904"]          = self._irc_sasl_fail
        h["900"]          = self._irc_logged_in
        h["001"]          = self._irc_welcome
        h["221"]          = self._irc_umodeis
        h["381"]          = self._irc_youreoper
        h["740"]          = self._irc_resumed
        h["741"]          = self._irc_resumeack
        h["JOIN"]         = self._irc_join
        h["PART"]         = self._irc_part
        h["KICK"]         = self._irc_kick
        h["TOPIC"]        = self._irc_topic_cmd
        h["MODE"]         = self._irc_mode
        h["PRIVMSG"]      = self._irc_privmsg
        h["NICK"]         = self._irc_nick_change
        h["NOTICE"]       = self._irc_notice
        h["INVITE"]       = self._irc_invite
        h["CHANNELRENAME"] = self._irc_channelrename
        h["QUIT"]         = self._irc_quit
        h["353"]          = self._irc_names
        h["301"]          = self._irc_away_reply
        h["332"]          = self._irc_topic_reply
        h["331"]          = self._irc_no_topic
        h["433"]          = self._irc_nick_in_use
        h["432"]          = self._irc_bad_nick
        h["401"]          = self._irc_no_such_nick
        h["322"]          = self._irc_list
        h["323"]          = self._irc_listend
        h["367"]          = self._irc_banlist
        h["368"]          = self._irc_banlist_end
        h["324"]          = self._irc_chanmode
        h["005"]          = self._irc_isupport
        h["AWAY"]         = self._irc_away_notify
        h["CHGHOST"]      = self._irc_chghost
        h["ACCOUNT"]      = self._irc_account
        h["SETNAME"]      = self._irc_setname
        h["BATCH"]        = self._irc_batch
        h["TAGMSG"]       = self._irc_tagmsg
        h["REDACT"]       = self._irc_redact
        h["MARKREAD"]     = self._irc_markread
        h["FAIL"]         = self._irc_fail
        h["WARN"]         = self._irc_warn
        h["NOTE"]         = self._irc_note
        h["730"]          = self._irc_mononline
        h["731"]          = self._irc_monoffline
        h["732"]          = self._irc_monlist
        h["734"]          = self._irc_monlistfull
        h["354"]          = self._irc_whox_reply
        h["920"]          = self._irc_reg_success
        h["921"]          = self._irc_reg_verification
        h["922"] = h["923"] = h["924"] = self._irc_reg_error
        # WHOIS numerics — bind each with its code via a closure
        for _code in _WHOIS_REPLIES:
            _c = _code
            h[_c] = lambda nick, params, prefix, c=_c: self._irc_whois_reply(c, nick, params, prefix)
        # WHO replies
        for _code in _WHO_REPLIES:
            h[_code] = self._irc_who_reply
        # Channel join error numerics
        for _code in _ERROR_REPLIES:
            h[_code] = self._irc_join_error
        # soju bouncer commands
        h["BOUNCER"]      = self._irc_bouncer

    # ====================== Commands ======================
    def cmd_join(self, channel: str) -> None:
        self.send_raw(f"JOIN {channel}")
        self.current_channel = channel
        self.joined_channels.add(channel)

    def cmd_part(self, channel: str, msg: Optional[str] = None) -> None:
        self.joined_channels.discard(channel)
        if msg:
            self.send_raw(f"PART {channel} :{msg}")
        else:
            self.send_raw(f"PART {channel}")

    def cmd_nick(self, new_nick: str) -> None:
        self.send_raw(f"NICK {new_nick}")
        self.nick = new_nick
        self._desired_nick = new_nick  # user intentionally chose this nick

    def cmd_whois(self, target: str) -> None:
        self.send_raw(f"WHOIS {target}")

    def cmd_mode(self, target: str, modes: str = "") -> None:
        self.send_raw(f"MODE {target} {modes}" if modes else f"MODE {target}")

    def cmd_topic(self, channel: str, topic: Optional[str] = None) -> None:
        self.send_raw(f"TOPIC {channel} :{topic}" if topic else f"TOPIC {channel}")

    def cmd_kick(self, channel: str, user: str, reason: str = "") -> None:
        self.send_raw(f"KICK {channel} {user} :{reason}" if reason else f"KICK {channel} {user}")

    def cmd_msg(self, target: str, text: str, is_action: bool = False) -> Optional[tuple]:
        if "\n" in text and not is_action and "draft/multiline" in self._active_caps:
            return self._cmd_msg_multiline(target, text)
        body = f":\x01ACTION {text}\x01" if is_action else f":{text}"
        if "labeled-response" in self._active_caps:
            label = self._next_label()
            self._pending_labels.add(label)
            self.send_tagged({"label": label}, f"PRIVMSG {target} {body}")
        else:
            self.send_raw(f"PRIVMSG {target} {body}")

        if self.nick not in self.users:
            u = UserState(self.nick)
            if self.nick in _NICK_AI_HISTORY:
                u.seed_ai_history(_NICK_AI_HISTORY[self.nick])
            self.users[self.nick] = u
        u_state = self.users[self.nick]
        u_state.record_message(text)
        u_score = self.scoring.score_user(u_state)
        m_score = 50
        a_score = 0  # own messages are human
        rolling_ai = int(u_state.rolling_ai_likelihood())
        return ("msg", self.nick, target, text, u_score, m_score, a_score, rolling_ai, is_action)

    def _cmd_msg_multiline(self, target: str, text: str) -> Optional[tuple]:
        """Send text containing \\n as a draft/multiline BATCH."""
        ref = f"ml{self._next_label()}"
        self.send_raw(f"BATCH +{ref} draft/multiline {target}")
        for ln in text.split("\n"):
            self.send_tagged({"batch": ref}, f"PRIVMSG {target} :{ln}")
        self.send_raw(f"BATCH -{ref}")
        if self.nick not in self.users:
            u = UserState(self.nick)
            self.users[self.nick] = u
        u_state = self.users[self.nick]
        u_state.record_message(text)
        u_score = self.scoring.score_user(u_state)
        rolling_ai = int(u_state.rolling_ai_likelihood())
        return ("msg", self.nick, target, text, u_score, 50, 0, rolling_ai, False)

    def cmd_service(self, service: str, command: str) -> None:
        self.send_raw(f"PRIVMSG {service} :{command}")

    def cmd_ctcp(self, target: str, ctcp_cmd: str, args: str = "") -> None:
        payload = f"{ctcp_cmd} {args}".strip()
        self.send_raw(f"PRIVMSG {target} :\x01{payload}\x01")

    # ── DCC file transfers ──────────────────────────────────────────────────
    # Active outgoing transfers: id → {nick, filename, filepath, total, sent, task, server, writer}
    # Active incoming transfers: id → {nick, filename, filepath, total, sent, reader, writer}
    _dcc_out: dict = {}
    _dcc_in:  dict = {}
    _dcc_seq: int = 0
    _dcc_chats: Dict[str, dict] = {}  # tid → {nick, reader, writer, task}

    async def _dcc_send_file(self, tid: str, nick: str, filepath: str,
                              turbo: bool = False, resume_pos: int = 0) -> None:
        """Background task: listen, offer via CTCP, stream file, report progress.

        If *resume_pos* > 0 the file bytes before that offset are skipped
        (receiver already has them).  *turbo* skips the ACK wait after each block.
        """
        try:
            filesize = os.path.getsize(filepath)
            filename = os.path.basename(filepath)
        except OSError as e:
            await self.ui_queue.put(("dcc_progress", tid, nick, filepath, 0, 0, f"error: {e}"))
            return
        if resume_pos > 0:
            filename = os.path.basename(filepath)

        # Get our local IP from the IRC socket
        sock = self.writer.get_extra_info("sockname") if self.writer else None
        local_ip = sock[0] if sock else "0.0.0.0"
        try:
            ip_int = int.from_bytes(socket.inet_aton(local_ip), 'big')
        except OSError:
            ip_int = int.from_bytes(socket.inet_aton("0.0.0.0"), 'big')

        # Start TCP listener on a random port
        try:
            server = await asyncio.start_server(
                lambda r, w: self._dcc_handle_client(tid, r, w, filepath, filesize, turbo),
                host="0.0.0.0", port=0)
            port = server.sockets[0].getsockname()[1]
        except OSError as e:
            await self.ui_queue.put(("dcc_progress", tid, nick, filename, 0, filesize, f"error: {e}"))
            return

        self._dcc_out[tid].update({"server": server, "port": port, "turbo": turbo})
        await self.ui_queue.put(("dcc_progress", tid, nick, filename, 0, filesize, "listening"))

        # Send DCC SEND / TSEND offer, possibly with resume
        cmd = "TSEND" if turbo else "SEND"
        self.send_raw(
            f"PRIVMSG {nick} :\x01DCC {cmd} {filename} {ip_int} {port} {filesize}\x01")

        # Wait up to 120 s for the receiver to connect (or reconnect after resume)
        for _ in range(120):
            if self._dcc_out.get(tid, {}).get("done"):
                break
            await asyncio.sleep(1)
        server.close()
        await server.wait_closed()
        entry = self._dcc_out.get(tid)
        if entry and not entry.get("done") and entry.get("sent", 0) < entry.get("total", 0):
            await self.ui_queue.put(("dcc_progress", tid, nick, filename,
                                     entry["sent"], filesize, "timeout"))

    async def _dcc_handle_client(self, tid: str, reader: asyncio.StreamReader,
                                  writer: asyncio.StreamWriter,
                                  filepath: str, filesize: int,
                                  turbo: bool = False) -> None:
        """Handle an incoming DCC connection: send file in 1024-byte blocks."""
        entry = self._dcc_out.get(tid)
        if not entry:
            writer.close()
            return
        nick = entry["nick"]
        filename = os.path.basename(filepath)
        resume_at = entry.get("resume_at", 0)

        # Handle reconnection for resume — use the stored position
        start_pos = max(resume_at, entry.get("sent", 0))
        entry["resume_at"] = 0  # consumed
        entry["writer"] = writer

        try:
            with open(filepath, "rb") as f:
                if start_pos > 0:
                    f.seek(start_pos)
                    entry["sent"] = start_pos
                while entry["sent"] < filesize:
                    chunk = f.read(1024)
                    if not chunk:
                        break
                    writer.write(chunk)
                    await writer.drain()
                    entry["sent"] += len(chunk)
                    await self.ui_queue.put(
                        ("dcc_progress", tid, nick, filename, entry["sent"], filesize, "transferring"))
                    if not turbo:
                        # Standard DCC: wait for ACK (4 bytes, network-order unsigned long)
                        try:
                            await asyncio.wait_for(reader.readexactly(4), timeout=30)
                        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError):
                            break
            entry["done"] = True
            await self.ui_queue.put(
                ("dcc_progress", tid, nick, filename, entry["sent"], filesize, "done"))
        except Exception as e:
            await self.ui_queue.put(
                ("dcc_progress", tid, nick, filename, entry["sent"], filesize, f"error: {e}"))
        finally:
            try:
                writer.close()
            except Exception:
                pass

    async def _dcc_recv_file(self, tid: str, nick: str, filename: str,
                              ip_int: int, port: int, filesize: int,
                              turbo: bool = False,
                              resume_at: int = 0,
                              use_tor: bool = False) -> None:
        """Connect to the sender and download the file.

        *turbo* omits ACKs.  *resume_at* starts writing at that offset (partial
        file must exist).  *use_tor* routes the connection through SOCKS5.
        """
        ip = socket.inet_ntoa(int.to_bytes(ip_int, 4, 'big'))
        safe_name = "".join(c for c in filename if c.isalnum() or c in "._- ")
        filepath = os.path.join(DCC_DIR, safe_name) if safe_name else os.path.join(DCC_DIR, "dcc_file")
        os.makedirs(DCC_DIR, exist_ok=True)

        try:
            if use_tor:
                reader, writer = await asyncio.wait_for(
                    _socks5_connect(ip, port), timeout=30)
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=30)
            self._dcc_in[tid]["reader"] = reader
            self._dcc_in[tid]["writer"] = writer
        except (OSError, asyncio.TimeoutError, ConnectionError) as e:
            await self.ui_queue.put(("dcc_progress", tid, nick, filename, 0, filesize, f"error: {e}"))
            return

        await self.ui_queue.put(("dcc_progress", tid, nick, filename, 0, filesize, "connecting"))
        try:
            mode = "ab" if resume_at > 0 else "wb"
            with open(filepath, mode) as f:
                if resume_at > 0:
                    self._dcc_in[tid]["sent"] = resume_at
                while self._dcc_in.get(tid, {}).get("sent", 0) < filesize:
                    chunk = await asyncio.wait_for(reader.read(1024), timeout=60)
                    if not chunk:
                        break
                    f.write(chunk)
                    self._dcc_in[tid]["sent"] += len(chunk)
                    if not turbo:
                        ack = struct.pack("!I", self._dcc_in[tid]["sent"])
                        writer.write(ack)
                        await writer.drain()
                    await self.ui_queue.put(
                        ("dcc_progress", tid, nick, filename,
                         self._dcc_in[tid]["sent"], filesize, "transferring"))

            status = "done" if self._dcc_in.get(tid, {}).get("sent", 0) >= filesize else "partial"
            await self.ui_queue.put(
                ("dcc_progress", tid, nick, filename,
                 self._dcc_in[tid].get("sent", 0), filesize, status))
        except Exception as e:
            await self.ui_queue.put(
                ("dcc_progress", tid, nick, filename,
                 self._dcc_in[tid].get("sent", 0), filesize, f"error: {e}"))
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def cmd_dcc_send(self, nick: str, filepath: str, turbo: bool = False) -> str:
        """Initiate an outgoing DCC SEND. Returns a transfer id."""
        self._dcc_seq += 1
        tid = f"dcc{self._dcc_seq}"
        self._dcc_out[tid] = {"nick": nick, "filepath": filepath, "total": 0,
                              "sent": 0, "server": None, "writer": None,
                              "turbo": turbo, "resume_at": 0, "port": 0}
        asyncio.create_task(self._dcc_send_file(tid, nick, filepath, turbo=turbo))
        return tid

    def cmd_dcc_tsend(self, nick: str, filepath: str) -> str:
        """Initiate an outgoing DCC TSEND (turbo, no ACKs)."""
        return self.cmd_dcc_send(nick, filepath, turbo=True)

    def cmd_dcc_accept(self, tid: str, nick: str, filename: str,
                        ip_int: int, port: int, filesize: int,
                        turbo: bool = False) -> None:
        """Accept an incoming DCC SEND from a trusted user."""
        use_tor = getattr(self, "use_tor", False)
        self._dcc_in[tid] = {"nick": nick, "filename": filename, "total": filesize,
                             "sent": 0, "reader": None, "writer": None, "turbo": turbo}
        asyncio.create_task(self._dcc_recv_file(
            tid, nick, filename, ip_int, port, filesize,
            turbo=turbo, use_tor=use_tor))

    def cmd_dcc_resume(self, tid: str) -> None:
        """Resume a failed incoming DCC transfer."""
        entry = self._dcc_in.get(tid)
        if not entry:
            return
        ip_int = entry.get("ip_int", 0)
        port = entry.get("port", 0)
        filesize = entry.get("total", 0)
        sent = entry.get("sent", 0)
        if sent <= 0 or sent >= filesize:
            return
        nick = entry["nick"]
        filename = entry["filename"]
        # Ask sender to resume
        self.send_raw(
            f"PRIVMSG {nick} :\x01DCC RESUME {filename} {port} {sent}\x01")

    def _dcc_handle_resume_req(self, tid: str, port: int, position: int) -> None:
        """Handle incoming DCC RESUME request (receiver wants to resume)."""
        for _tid, entry in self._dcc_out.items():
            if entry.get("port") == port and position < entry.get("total", 0):
                entry["resume_at"] = position
                filename = os.path.basename(entry["filepath"])
                self.send_raw(
                    f"PRIVMSG {entry['nick']} :\x01DCC ACCEPT {filename} {port} {position}\x01")
                break

    def _dcc_handle_resume_ack(self, tid: str, filename: str, port: int, position: int) -> None:
        """Handle incoming DCC ACCEPT (sender approved resume)."""
        entry = self._dcc_in.get(tid)
        if not entry:
            return
        # Restart the download from the resume position
        asyncio.create_task(self._dcc_recv_file(
            tid, entry["nick"], filename,
            entry.get("ip_int", 0), port, entry.get("total", 0),
            turbo=entry.get("turbo", False),
            resume_at=position,
            use_tor=getattr(self, "use_tor", False)))

    # ── DCC CHAT ──────────────────────────────────────────────────────────────

    def cmd_dcc_chat(self, nick: str) -> Optional[str]:
        """Initiate a DCC CHAT with *nick*.

        Opens a TCP listener, sends the CTCP offer, and returns the transfer id
        (or None on failure).
        """
        self._dcc_seq += 1
        tid = f"dcc_chat{self._dcc_seq}"
        # Start listener – will be filled when connection arrives
        self._dcc_chats[tid] = {"nick": nick, "reader": None, "writer": None, "task": None}
        asyncio.create_task(self._dcc_chat_listen(tid, nick))
        return tid

    async def _dcc_chat_listen(self, tid: str, nick: str) -> None:
        """Background: create TCP listener, send CTCP offer, accept connection."""
        sock = self.writer.get_extra_info("sockname") if self.writer else None
        local_ip = sock[0] if sock else "0.0.0.0"
        try:
            ip_int = int.from_bytes(socket.inet_aton(local_ip), 'big')
        except OSError:
            ip_int = int.from_bytes(socket.inet_aton("0.0.0.0"), 'big')
        try:
            server = await asyncio.start_server(
                lambda r, w: self._dcc_chat_on_connect(tid, nick, r, w),
                host="0.0.0.0", port=0)
            port = server.sockets[0].getsockname()[1]
        except OSError as e:
            await self.ui_queue.put(("dcc_chat_offer", tid, nick, 0, 0, f"error: {e}"))
            return
        self._dcc_chats[tid]["server"] = server
        self.send_raw(
            f"PRIVMSG {nick} :\x01DCC CHAT chat {ip_int} {port}\x01")
        await self.ui_queue.put(("dcc_chat_offer", tid, nick, 0, 0, "listening"))
        # Wait up to 120 s for connection
        await asyncio.sleep(120)
        server.close()
        await server.wait_closed()
        if tid in self._dcc_chats and self._dcc_chats[tid].get("writer") is None:
            self._dcc_chats.pop(tid, None)
            await self.ui_queue.put(("dcc_chat_closed", tid, nick))

    def _dcc_chat_on_connect(self, tid: str, nick: str,
                              reader: asyncio.StreamReader,
                              writer: asyncio.StreamWriter) -> None:
        """Called when the remote side connects to our listener."""
        entry = self._dcc_chats.get(tid)
        if not entry:
            writer.close()
            return
        entry["reader"] = reader
        entry["writer"] = writer
        task = asyncio.create_task(self._dcc_chat_reader(tid, nick, reader))
        entry["task"] = task
        self.ui_queue.put_nowait(("dcc_chat_offer", tid, nick, 0, 0, "connected"))

    def _accept_dcc_chat(self, tid: str, nick: str, ip_int: int, port: int) -> None:
        """Connect to the remote side's DCC CHAT listener."""
        ip = socket.inet_ntoa(int.to_bytes(ip_int, 4, 'big'))
        asyncio.create_task(self._dcc_chat_connect_out(tid, nick, ip, port))

    async def _dcc_chat_connect_out(self, tid: str, nick: str, ip: str, port: int) -> None:
        """Connect out to accept an incoming DCC CHAT offer."""
        use_tor = getattr(self, "use_tor", False)
        try:
            if use_tor:
                reader, writer = await asyncio.wait_for(
                    _socks5_connect(ip, port), timeout=30)
            else:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=30)
        except (OSError, asyncio.TimeoutError, ConnectionError) as e:
            await self.ui_queue.put(("dcc_chat_closed", tid, nick))
            return
        entry = self._dcc_chats.get(tid)
        if not entry:
            writer.close()
            return
        entry["reader"] = reader
        entry["writer"] = writer
        task = asyncio.create_task(self._dcc_chat_reader(tid, nick, reader))
        entry["task"] = task
        await self.ui_queue.put(("dcc_chat_offer", tid, nick, 0, 0, "connected"))

    async def _dcc_chat_reader(self, tid: str, nick: str,
                                reader: asyncio.StreamReader) -> None:
        """Background: read lines from the DCC CHAT socket and forward to UI."""
        try:
            while True:
                line = await reader.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace").rstrip("\r\n")
                await self.ui_queue.put(("dcc_chat_msg", tid, nick, text))
        except Exception:
            pass
        finally:
            self._dcc_chats.pop(tid, None)
            await self.ui_queue.put(("dcc_chat_closed", tid, nick))

    def dcc_chat_send(self, tid: str, text: str) -> None:
        """Send *text* over the DCC CHAT connection identified by *tid*."""
        entry = self._dcc_chats.get(tid)
        if entry and entry.get("writer"):
            try:
                entry["writer"].write((text + "\n").encode("utf-8"))
            except Exception:
                pass

    def dcc_chat_close(self, tid: str) -> None:
        """Close a DCC CHAT connection."""
        entry = self._dcc_chats.pop(tid, None)
        if entry:
            if entry.get("task"):
                entry["task"].cancel()
            try:
                if entry.get("writer"):
                    entry["writer"].close()
            except Exception:
                pass

    def cmd_notice(self, target: str, text: str) -> None:
        self.send_raw(f"NOTICE {target} :{text}")

    def cmd_away(self, msg: str = "") -> None:
        self.send_raw(f"AWAY :{msg}" if msg else "AWAY")

    def cmd_invite(self, nick: str, channel: str) -> None:
        self.send_raw(f"INVITE {nick} {channel}")

    def cmd_who(self, target: str) -> None:
        self.send_raw(f"WHO {target}")

    def cmd_whox(self, target: str, fields: str = "tnhuafr") -> None:
        """Send WHOX query (extended WHO) when server advertises WHOX in ISUPPORT.

        't' is always injected so the 354 reply carries the token, letting
        _irc_whox_reply map positional fields back to human-readable labels.
        The token rotates 1–999 so concurrent queries don't collide.
        """
        if "WHOX" in self._isupport:
            f = fields.replace(" ", "")
            if "t" not in f:
                f = "t" + f
            token = str(self._whox_seq)
            self._whox_seq = self._whox_seq % 999 + 1
            self._whox_tokens[token] = f
            self.send_raw(f"WHO {target} %{f},{token}")
        else:
            self.send_raw(f"WHO {target}")

    def cmd_whowas(self, nick: str) -> None:
        self.send_raw(f"WHOWAS {nick}")

    def cmd_names(self, channel: str = "") -> None:
        self.send_raw(f"NAMES {channel}" if channel else "NAMES")

    def cmd_monitor_add(self, nicks: List[str]) -> None:
        self._monitor_nicks.update(n.lower() for n in nicks)
        self.send_raw(f"MONITOR + {','.join(nicks)}")

    def cmd_monitor_remove(self, nicks: List[str]) -> None:
        for n in nicks:
            self._monitor_nicks.discard(n.lower())
        self.send_raw(f"MONITOR - {','.join(nicks)}")

    def cmd_monitor_clear(self) -> None:
        self._monitor_nicks.clear()
        self.send_raw("MONITOR C")

    def cmd_monitor_list(self) -> None:
        self.send_raw("MONITOR L")

    def cmd_monitor_status(self) -> None:
        self.send_raw("MONITOR S")

    def cmd_chathistory(self, channel: str, count: int = 50,
                        subcmd: str = "LATEST", reference: str = "*",
                        timestamp: str = "") -> None:
        if not self._chathistory_cap:
            try:
                self.ui_queue.put_nowait(("status",
                    "Server does not support chat history (chathistory CAP missing)"))
            except Exception:
                pass
            return
        sub = subcmd.upper()
        if sub == "LATEST":
            self.send_raw(f"CHATHISTORY LATEST {channel} {reference} {count}")
        elif sub == "BEFORE":
            ref = timestamp or reference
            self.send_raw(f"CHATHISTORY BEFORE {channel} ref={ref} {count}")
        elif sub == "AFTER":
            ref = timestamp or reference
            self.send_raw(f"CHATHISTORY AFTER {channel} ref={ref} {count}")
        elif sub == "BETWEEN":
            if not timestamp:
                try:
                    self.ui_queue.put_nowait(("status",
                        "BETWEEN requires timestamp= start,end"))
                except Exception:
                    pass
                return
            self.send_raw(f"CHATHISTORY BETWEEN {channel} {timestamp} {count}")
        elif sub == "TARGETS":
            self.send_raw(f"CHATHISTORY TARGETS * {count}")
        else:
            self.send_raw(f"CHATHISTORY LATEST {channel} {reference} {count}")

    def cmd_tagmsg(self, target: str, tags: dict) -> None:
        """Send a TAGMSG (client-only tags, no visible body text)."""
        self.send_tagged(tags, f"TAGMSG {target}")

    async def _score_msg_bg(self, nick: str, target: str, msg: str,
                            u_state: "UserState", u_score: int, m_score: int) -> None:
        """Run AI inference off the read loop, then push an update event."""
        if not self.scoring.ai_detector.enabled:
            # AI detection off (--no-ai or /aitoggle), but we still want a
            # complete audit trail in ai_scores.log.  Skip record_message so
            # the rolling-average isn't polluted with synthetic zeros.
            log_ai_event(
                nick, target, msg, u_score, m_score, 0,
                int(u_state.rolling_ai_likelihood()),
            )
            return
        a_score = 0
        detail: Dict[str, float] = {"prob": 0.0, "heu": 0.0, "bino": 0.0, "cls": 0.0, "llama": 0.0, "styl": 0.0}
        try:
            # Confirmed bots: skip inference entirely — score is always 100.
            # Also ingest the message into their fingerprint to keep learning.
            if nick.lower() in self.scoring.confirmed_bot_nicks:
                fp = self.scoring.bot_fingerprints.get(nick.lower())
                if fp is not None:
                    fp.ingest(msg)
                a_score = 100
            else:
                global _ML_SEM
                if _ML_SEM is None:
                    _ML_SEM = asyncio.Semaphore(2)
                loop = asyncio.get_running_loop()
                _recent_embeds = list(u_state._recent_embeds)
                async with _ML_SEM:
                    detail = await asyncio.wait_for(
                        loop.run_in_executor(
                            _ML_EXECUTOR,
                            lambda: self.scoring.ai_detector.predict_detailed(
                                msg, recent_embeds=_recent_embeds)),
                        timeout=15.0)
                prob = detail["prob"]
                # Optional LLM-based classification: blended in when /model is set.
                # Weight: 60% local ensemble (fast, always-on) + 40% LLM signal.
                detect_model = self.scoring.ai_detector.active_detect_model
                if detect_model:
                    llm_prob = await _llm_classify_ai(msg, detect_model)
                    prob = 0.60 * prob + 0.40 * llm_prob
                # Fingerprint similarity boost: if this message strongly resembles
                # a confirmed bot's writing style, nudge the probability up.
                # Excluded nicks: this user's own fingerprint (if they were later
                # confirmed too) — only cross-nick learning applies here.
                fp_sim = self.scoring.max_fingerprint_similarity(msg, exclude_nick=nick)
                if fp_sim > 0.0:
                    # Max +35 percentage points at full similarity; tapers off smoothly.
                    prob = min(1.0, prob + 0.35 * fp_sim)

                # Behavioral: timing regularity via log-normal distribution model.
                # Human IRC typing has irregular gaps (high log-variance, sporadic
                # z-scores); bots produce near-constant intervals.
                _timing_score = u_state.timing_anomaly_score()
                if _timing_score > 0.0:
                    prob = min(1.0, prob + 0.20 * _timing_score)

                # Rolling momentum: if this user is already tracking as AI across
                # several past messages, give new messages a small confidence nudge
                # so the rolling average crosses the suspect threshold faster.
                _rolling_prior = u_state.rolling_ai_likelihood()
                if _rolling_prior >= 75.0 and len(u_state.ai_scores) >= 4:
                    prob = min(1.0, prob + 0.10)

                # Collaborative blocklist boost (Area 3): if this message contains
                # n-grams that have been /learn_tell'd, boost the score.
                _blocklist_score = self.scoring.blocklist_overlap_score(msg)
                if _blocklist_score > 0.0:
                    prob = min(1.0, prob + 0.30 * _blocklist_score)

                a_score = int(prob * 100)
        except asyncio.CancelledError:
            # Task cancelled (e.g. during shutdown) — log the partial result before
            # propagating so the message is never silently dropped from the audit log.
            u_state.record_message(msg, a_score)
            log_ai_event(
                nick, target, msg, u_score, m_score, a_score,
                int(u_state.rolling_ai_likelihood()),
                heu_score=detail.get("heu", 0), bino_score=detail.get("bino", 0),
                cls_score=detail.get("cls", 0), llama_score=detail.get("llama", 0),
                adv_score=detail.get("adv", 0), embed_score=detail.get("embed", 0),
                watermark_score_val=detail.get("watermark", 0),
                styl_score=detail.get("styl", 0),
            )
            raise
        except Exception:
            # Inference failed for some other reason (timeout, ML error, etc).
            # Don't record_message — that would skew the rolling AI average
            # toward 'human' and mislead the suspect heuristic — but still
            # write the message to ai_scores.log so the audit trail is
            # complete.  Whatever partial signals we managed to compute are
            # preserved in `detail`; un-set fields stay at 0.0.
            log_ai_event(
                nick, target, msg, u_score, m_score, a_score,
                int(u_state.rolling_ai_likelihood()),
                heu_score=detail.get("heu", 0), bino_score=detail.get("bino", 0),
                cls_score=detail.get("cls", 0), llama_score=detail.get("llama", 0),
                adv_score=detail.get("adv", 0), embed_score=detail.get("embed", 0),
                watermark_score_val=detail.get("watermark", 0),
                styl_score=detail.get("styl", 0),
            )
            return
        u_state.record_message(msg, a_score)
        # Store per-signal breakdown for explainability (Area 6)
        u_state._recent_signals.append({
            "prob": detail.get("prob", 0), "heu": detail.get("heu", 0),
            "bino": detail.get("bino", 0), "cls": detail.get("cls", 0),
            "llama": detail.get("llama", 0), "adv": detail.get("adv", 0),
            "embed": detail.get("embed", 0), "watermark": detail.get("watermark", 0),
            "styl": detail.get("styl", 0),
        })
        # Store sentence embedding for future semantic-drift detection
        if self.scoring.ai_detector._embed_model is not None and len(msg.split()) >= 3:
            try:
                emb = self.scoring.ai_detector._embed_text(msg)
                if emb is not None:
                    u_state._recent_embeds.append(emb)
            except Exception:
                pass
        rolling_ai = int(u_state.rolling_ai_likelihood())
        # AI-vs-AI detection: check reply/mention target's AI score
        if target.startswith("#") and rolling_ai >= 50:
            for word in msg.split():
                if word.startswith("@"):
                    mentioned = word.lstrip("@").strip(",:;.!?")
                    if mentioned:
                        t_state = self.users.get(mentioned)
                        if t_state:
                            t_ai = int(t_state.rolling_ai_likelihood())
                            if t_ai >= 50:
                                self.scoring.ai_vs_ai.record_exchange(
                                    nick, mentioned, target, float(rolling_ai), float(t_ai))
        # Sentiment-AI correlation
        if target.startswith("#"):
            try:
                sent_result = self.scoring.sentiment.analyze(msg)
                self.scoring.sentiment_ai.record(
                    nick, target, float(rolling_ai),
                    sent_result["score"], sent_result.get("intensity", 0.0))
            except Exception:
                pass
        log_ai_event(
            nick, target, msg, u_score, m_score, a_score, rolling_ai,
            heu_score=detail.get("heu", 0), bino_score=detail.get("bino", 0),
            cls_score=detail.get("cls", 0), llama_score=detail.get("llama", 0),
            adv_score=detail.get("adv", 0), embed_score=detail.get("embed", 0),
            watermark_score_val=detail.get("watermark", 0),
            styl_score=detail.get("styl", 0),
        )
        await self.ui_queue.put(("ai_score", nick, rolling_ai, detail.get("styl", 0.0)))

# =========================
# Per-server state container
# =========================
# =========================
# Plugin System
# =========================

class PluginAPI:
    """Public interface passed to plugin setup(api) functions.

    Plugin files should define a top-level setup(api) function.  Optionally
    they may also define teardown(api) which is called on /unloadplugin.

    Plugin metadata (optional):
        __plugin_name__    = "My Plugin"
        __plugin_version__ = "1.0.0"
        __plugin_author__  = "Your Name"
        __plugin_desc__    = "What this plugin does"

    Minimal plugin example
    ----------------------
    def setup(api):
        @api.command("hello")
        async def hello(api, args):
            await api.status(f"Hello, {args or 'world'}!")
    """

    def __init__(self, name: str, tui: "TUI") -> None:
        self.name = name
        self._tui = tui
        self._commands: Dict[str, Callable] = {}
        self._hooks: Dict[str, List[Callable]] = {}
        self._keybindings: Dict[str, Callable] = {}
        self._repeat_tasks: List[asyncio.Task] = []
        # Metadata from module-level attributes
        self.version: str = ""
        self.author: str = ""
        self.description: str = ""
        self._config: Dict[str, Any] = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load plugin-specific config from bouncer config section."""
        cfg = load_irc_config()
        self._config = cfg.get("plugins", {}).get(self.name, {})

    def _save_config(self) -> None:
        """Persist plugin config to disk."""
        cfg = load_irc_config()
        cfg.setdefault("plugins", {})[self.name] = self._config
        save_irc_config(cfg)

    # ── Config persistence ───────────────────────────────────────────────────

    def get_config(self, key: str, default: Any = None) -> Any:
        """Get a plugin config value."""
        return self._config.get(key, default)

    def set_config(self, key: str, value: Any) -> None:
        """Set and persist a plugin config value."""
        self._config[key] = value
        self._save_config()

    def delete_config(self, key: str) -> bool:
        """Delete a plugin config key. Returns True if key existed."""
        if key in self._config:
            del self._config[key]
            self._save_config()
            return True
        return False

    def get_all_config(self) -> Dict[str, Any]:
        """Get a copy of all plugin config."""
        return dict(self._config)

    # ── Metadata ─────────────────────────────────────────────────────────────

    def set_metadata(self, version: str = "", author: str = "", description: str = "") -> None:
        """Set plugin metadata (also auto-detected from module attributes)."""
        if version:
            self.version = version
        if author:
            self.author = author
        if description:
            self.description = description

    # ── Command registration ─────────────────────────────────────────────────

    def command(self, name: str) -> Callable:
        """Decorator: register a /name slash command.

        The decorated function receives (api, args) where args is the
        remainder of the input line after the command name.  Both sync and
        async functions are accepted.
        """
        def decorator(fn: Callable) -> Callable:
            self._commands[name.lower()] = fn
            return fn
        return decorator

    def register(self, name: str, handler: Callable) -> None:
        """Imperatively register a slash command handler."""
        self._commands[name.lower()] = handler

    # ── Event hook registration ──────────────────────────────────────────────

    def on(self, event: str) -> Callable:
        """Decorator: register an event hook.

        Supported events:
          on_message(api, nick, target, msg, is_action, is_replay)
          on_join(api, nick, channel)
          on_part(api, nick, channel, reason)
          on_quit(api, nick, reason)
          on_nick_change(api, old_nick, new_nick)
          on_topic(api, channel, topic, setter_nick)
          on_kick(api, channel, nick, kicker, reason)
          on_mode(api, target, modes, setter_nick)
          on_react(api, nick, target, msgid, emoji)
          on_ai_score(api, nick, rolling_ai, styl_score)
          on_notice(api, sender, target, text)
          on_typing(api, nick, target, state)
          on_connect(api)
          on_disconnect(api, reason)
          on_command(api, cmd_name, args)  -- intercepts slash commands

        Both sync and async callbacks are accepted.
        """
        def decorator(fn: Callable) -> Callable:
            self._hooks.setdefault(event, []).append(fn)
            return fn
        return decorator

    # ── Status / output helpers ──────────────────────────────────────────────

    async def status(self, text: str) -> None:
        """Post text to the *status* window."""
        await self._tui.ui_queue.put(("status", text))

    def add_to_window(self, window_name: str, text: str, timestamp: bool = True) -> None:
        """Append a line to *window_name* (creates the window if absent)."""
        win = self._tui.window_by_name.get(window_name)
        if win is None:
            win = self._tui.ensure_window(window_name, is_channel=window_name.startswith("#"))
        win.add_line(text, timestamp=timestamp)
        self._tui._chat_dirty = True
        self._tui.dirty = True

    def send_to_current_window(self, text: str, timestamp: bool = True) -> None:
        """Send a line to the currently active window."""
        win = self._tui.get_current_window()
        win.add_line(text, timestamp=timestamp)
        self._tui._chat_dirty = True
        self._tui.dirty = True

    # ── IRC helpers ──────────────────────────────────────────────────────────

    def send(self, target: str, text: str) -> None:
        """Send an IRC PRIVMSG to *target* (channel or nick)."""
        self._tui._active_client().cmd_msg(target, text)

    def send_action(self, target: str, text: str) -> None:
        """Send an IRC ACTION (/me) to *target*."""
        self._tui._active_client().cmd_msg(target, f"\x01ACTION {text}\x01")

    def send_notice(self, target: str, text: str) -> None:
        """Send an IRC NOTICE to *target*."""
        self._tui._active_client().cmd_notice(target, text)

    def send_raw(self, line: str) -> None:
        """Send a raw IRC line."""
        self._tui._active_client().send_raw(line)

    def set_topic(self, channel: str, topic: str) -> None:
        """Set channel topic."""
        self._tui._active_client().cmd_topic(channel, topic)

    def kick(self, channel: str, nick: str, reason: str = "") -> None:
        """Kick a user from a channel."""
        self._tui._active_client().cmd_kick(channel, nick, reason)

    def set_mode(self, target: str, modes: str) -> None:
        """Set modes on a channel or user."""
        self._tui._active_client().cmd_mode(target, modes)

    # ── State accessors ──────────────────────────────────────────────────────

    @property
    def current_channel(self) -> Optional[str]:
        return self._tui.current_channel

    @property
    def current_window(self) -> str:
        return self._tui.get_current_window().name

    @property
    def my_nick(self) -> str:
        return self._tui._active_client().nick

    @property
    def is_connected(self) -> bool:
        return self._tui._active_client().is_connected

    def get_window_lines(self, window_name: str, limit: int = 0) -> List[str]:
        """Get recent lines from a window. limit=0 returns all."""
        win = self._tui.window_by_name.get(window_name)
        if not win:
            return []
        lines = list(win.lines)
        return lines[-limit:] if limit > 0 else lines

    def get_channel_users(self, channel: str) -> set:
        """Get the set of users in a channel."""
        return self._tui.channel_users.get(channel, set())

    def get_user_modes(self, channel: str, nick: str) -> set:
        """Get mode flags for a user in a channel."""
        return self._tui.channel_user_modes.get(channel, {}).get(nick, set())

    def get_ai_score(self, nick: str) -> int:
        """Get the current rolling AI score for a nick."""
        return self._tui.user_ai_scores.get(nick, 0)

    def get_ai_styl_score(self, nick: str) -> float:
        """Get the latest stylometric score for a nick."""
        return self._tui._recent_styl_scores.get(nick, 0.0)

    def is_suspect(self, nick: str) -> bool:
        """Check if a nick is in the suspect list."""
        return nick in self._tui._suspect_nicks

    def get_user_state(self, nick: str) -> Optional[Any]:
        """Get the UserState for a nick (if seen this session)."""
        return self._tui._active_client().users.get(nick)

    def ensure_window(self, name: str, is_channel: bool = False) -> None:
        self._tui.ensure_window(name, is_channel=is_channel)

    def switch_window(self, name: str) -> None:
        """Switch the TUI focus to a window by name."""
        win = self._tui.window_by_name.get(name)
        if win and win in self._tui.windows:
            # Reset dashboard state when navigating away
            prev_win = self._tui.get_current_window()
            if prev_win.name == "*dashboard*":
                self._tui._dashboard_mode = "suspects"
                self._tui._dashboard_profile_locked = False
            self._tui.current_window_index = self._tui.windows.index(win)
            # Reset dashboard state when navigating TO it
            if win.name == "*dashboard*":
                self._tui._dashboard_mode = "suspects"
                self._tui._dashboard_profile_locked = False
                self._tui._dashboard_dirty = True
                self._tui._dashboard_last_update = 0.0
            self._tui.current_channel = name if name.startswith("#") else None
            self._tui._unread_windows.discard(name)
            self._tui._chat_dirty = self._tui._userlist_dirty = self._tui._input_dirty = True
            self._tui.dirty = True

    # ── Scheduling ───────────────────────────────────────────────────────────

    def schedule(self, delay: float, callback: Callable) -> None:
        """Schedule a callback to run after *delay* seconds.

        callback can be sync or async.  Returns nothing; errors are logged.
        """
        async def _wrapper():
            await asyncio.sleep(delay)
            try:
                result = callback()
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                await self.status(f"[{self.name}] scheduled callback error: {exc}")
        asyncio.create_task(_wrapper())

    def repeat(self, interval: float, callback: Callable) -> asyncio.Task:
        """Schedule a callback to run repeatedly at *interval* seconds.

        Returns the asyncio.Task so it can be cancelled later.
        Task is automatically tracked and cancelled on plugin unload.
        """
        async def _wrapper():
            while True:
                await asyncio.sleep(interval)
                try:
                    result = callback()
                    if asyncio.iscoroutine(result):
                        await result
                except asyncio.CancelledError:
                    break
                except Exception as exc:
                    await self.status(f"[{self.name}] repeat callback error: {exc}")
        task = asyncio.create_task(_wrapper())
        self._repeat_tasks.append(task)
        return task

    # ── Keybindings ──────────────────────────────────────────────────────────

    def add_keybinding(self, key: str, callback: Callable) -> None:
        """Register a keybinding. key is a curses key name like 'F5' or '^B'.

        Note: keybindings are processed by the TUI main loop and must be
        registered through the plugin manager to take effect.
        """
        self._keybindings[key.lower()] = callback

    def remove_keybinding(self, key: str) -> None:
        self._keybindings.pop(key.lower(), None)


class PluginManager:
    """Loads, tracks, and routes commands for all active plugins."""

    def __init__(self) -> None:
        self._plugins: Dict[str, Tuple[PluginAPI, Any]] = {}          # name → (api, module)
        self._commands: Dict[str, Tuple[PluginAPI, Callable]] = {}    # cmd  → (api, handler)
        self._hooks: Dict[str, List[Tuple[PluginAPI, Callable]]] = {} # event → [(api, handler)]
        self._load_times: Dict[str, float] = {}                       # name → load timestamp

    def load(self, path: str, tui: "TUI") -> Tuple[bool, str]:
        """Load a plugin from *path*.  Returns (success, message)."""
        name = os.path.splitext(os.path.basename(path))[0]
        if name in self._plugins:
            return False, f"Plugin '{name}' already loaded — use /reloadplugin {name} to reload"
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                return False, f"Cannot load '{path}': not a valid Python file"
            module = importlib.util.module_from_spec(spec)
            api = PluginAPI(name, tui)
            spec.loader.exec_module(module)  # type: ignore[union-attr]
            if not hasattr(module, "setup"):
                return False, f"'{path}' has no setup(api) function"
            module.setup(api)
            # Auto-detect metadata from module attributes
            api.version = getattr(module, "__plugin_version__", "")
            api.author = getattr(module, "__plugin_author__", "")
            api.description = getattr(module, "__plugin_desc__", "")
            self._plugins[name] = (api, module)
            self._load_times[name] = time.time()
            for cmd_name, handler in api._commands.items():
                self._commands[cmd_name] = (api, handler)
            for event, handlers in api._hooks.items():
                for h in handlers:
                    self._hooks.setdefault(event, []).append((api, h))
            cmds = " ".join(f"/{c}" for c in api._commands) if api._commands else "(no commands)"
            meta = []
            if api.version:
                meta.append(f"v{api.version}")
            if api.author:
                meta.append(f"by {api.author}")
            meta_str = f"  [{', '.join(meta)}]" if meta else ""
            return True, f"Loaded plugin '{name}'{meta_str}  {cmds}"
        except Exception as exc:
            return False, f"Failed to load '{path}': {exc}"

    def unload(self, name: str) -> Tuple[bool, str]:
        """Unload plugin *name*.  Returns (success, message)."""
        if name not in self._plugins:
            return False, f"No plugin named '{name}' is loaded"
        api, module = self._plugins.pop(name)
        self._load_times.pop(name, None)
        # Cancel any repeating tasks tracked by the plugin
        if hasattr(api, "_repeat_tasks"):
            for task in api._repeat_tasks:
                task.cancel()
        if hasattr(module, "teardown"):
            try:
                result = module.teardown(api)
                if asyncio.iscoroutine(result):
                    asyncio.create_task(result)
            except Exception:
                pass
        for cmd_name in list(api._commands):
            self._commands.pop(cmd_name, None)
        for event in list(self._hooks):
            self._hooks[event] = [(a, h) for a, h in self._hooks[event] if a is not api]
            if not self._hooks[event]:
                del self._hooks[event]
        return True, f"Unloaded plugin '{name}'"

    def reload(self, name: str, tui: "TUI") -> Tuple[bool, str]:
        """Unload then re-load plugin *name* from its original file."""
        if name not in self._plugins:
            return False, f"No plugin named '{name}' is loaded"
        _, module = self._plugins[name]
        path = getattr(module, "__file__", None)
        if not path:
            return False, f"Cannot determine source file for plugin '{name}'"
        ok, msg = self.unload(name)
        if not ok:
            return ok, msg
        return self.load(path, tui)

    def get_command(self, cmd: str) -> Optional[Tuple[PluginAPI, Callable]]:
        return self._commands.get(cmd)

    def list_plugins(self) -> List[Dict[str, Any]]:
        """Return detailed info for all loaded plugins."""
        result = []
        for name, (api, module) in self._plugins.items():
            info = {
                "name": name,
                "version": api.version,
                "author": api.author,
                "description": api.description,
                "commands": list(api._commands.keys()),
                "hooks": list(api._hooks.keys()),
                "path": getattr(module, "__file__", "unknown"),
                "loaded_at": self._load_times.get(name, 0),
            }
            result.append(info)
        return result

    def get_plugin_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get detailed info for a specific plugin."""
        if name not in self._plugins:
            return None
        api, module = self._plugins[name]
        return {
            "name": name,
            "version": api.version,
            "author": api.author,
            "description": api.description,
            "commands": list(api._commands.keys()),
            "hooks": list(api._hooks.keys()),
            "keybindings": list(api._keybindings.keys()),
            "path": getattr(module, "__file__", "unknown"),
            "loaded_at": self._load_times.get(name, 0),
            "config": api.get_all_config(),
        }

    async def dispatch(self, event: str, **kwargs) -> None:
        """Dispatch *event* to all registered plugin hooks."""
        handlers = self._hooks.get(event)
        if not handlers:
            return
        for api, handler in handlers:
            try:
                result = handler(api, **kwargs)
                if asyncio.iscoroutine(result):
                    await result
            except Exception as exc:
                try:
                    await api.status(f"[plugin:{api.name}] hook '{event}' error: {exc}")
                except Exception:
                    pass

    async def dispatch_with_result(self, event: str, **kwargs) -> Optional[Dict[str, Any]]:
        """Dispatch *event* and return the first non-None result from any handler.

        Used for hooks that can intercept/modify behavior (e.g. on_command).
        Handlers should return a dict with "handled": True to stop processing.
        """
        handlers = self._hooks.get(event)
        if not handlers:
            return None
        for api, handler in handlers:
            try:
                result = handler(api, **kwargs)
                if asyncio.iscoroutine(result):
                    result = await result
                if result is not None:
                    return result
            except Exception as exc:
                try:
                    await api.status(f"[plugin:{api.name}] hook '{event}' error: {exc}")
                except Exception:
                    pass
        return None

    def auto_load_plugins(self, tui: "TUI", directory: str = "") -> List[str]:
        """Auto-load all .py files from the plugins/ directory.

        Returns list of successfully loaded plugin names.
        """
        if not directory:
            directory = os.path.join(_SCRIPT_DIR, "plugins")
        if not os.path.isdir(directory):
            return []
        loaded = []
        for fname in sorted(os.listdir(directory)):
            if fname.endswith(".py") and not fname.startswith("_"):
                path = os.path.join(directory, fname)
                ok, msg = self.load(path, tui)
                if ok:
                    loaded.append(fname[:-3])
        return loaded


# =========================
# Script Engine (Python / Lua)
# =========================
SCRIPT_DIR_SCRIPTS = os.path.join(_SCRIPT_DIR, "scripts")

class ScriptAPI:
    """Minimal API passed to each loaded script."""

    def __init__(self, name: str, tui: "TUI") -> None:
        self.name = name
        self._tui = tui

    async def status(self, text: str) -> None:
        await self._tui.ui_queue.put(("status", f"[script:{self.name}] {text}"))

    def send(self, target: str, text: str) -> None:
        self._tui._active_client().cmd_msg(target, text)

    def send_raw(self, line: str) -> None:
        self._tui._active_client().send_raw(line)

    def add_to_window(self, name: str, text: str) -> None:
        win = self._tui.window_by_name.get(name)
        if win is None:
            win = self._tui.ensure_window(name, is_channel=name.startswith("#"))
        win.add_line(text, timestamp=True)
        self._tui._chat_dirty = True
        self._tui.dirty = True

    @property
    def current_nick(self) -> str:
        return self._tui._active_client().nick

    @property
    def current_channel(self) -> Optional[str]:
        return self._tui.current_channel


class ScriptEngine:
    """Lightweight scripting engine that loads .py and .lua files from scripts/.

    Python scripts define module-level hook functions:
        on_message(api, nick, target, msg, is_action, is_replay)
        on_join(api, nick, channel)
        on_part(api, nick, channel)
        on_quit(api, nick, reason)
        on_nick_change(api, old_nick, new_nick)
        on_command(api, cmd, args)  — for custom /commands

    Lua scripts (via lupa if installed) define the same hooks as global functions.
    """

    def __init__(self, tui: "TUI") -> None:
        self._tui = tui
        self._scripts: Dict[str, Tuple[ScriptAPI, Any, str]] = {}  # name → (api, module, lang)
        self._hooks: Dict[str, List[Tuple[ScriptAPI, Callable]]] = {}
        self._commands: Dict[str, Tuple[ScriptAPI, Callable]] = {}
        self._lua_available: bool = False
        try:
            import lupa  # type: ignore
            self._lua_available = True
            self._lua_runtime = lupa.LuaRuntime(unpack_returned_tuples=True)
        except ImportError:
            self._lua_runtime = None

    def _load_py(self, path: str) -> Tuple[bool, str]:
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            spec = importlib.util.spec_from_file_location(name, path)
            if spec is None or spec.loader is None:
                return False, f"Cannot load '{path}'"
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:
            return False, f"Python error: {exc}"
        api = ScriptAPI(name, self._tui)
        self._scripts[name] = (api, module, "py")
        self._register_hooks(name, module)
        return True, f"Loaded Python script '{name}'"

    def _load_lua(self, path: str) -> Tuple[bool, str]:
        if not self._lua_available:
            return False, "lupa not installed — install with: pip install lupa"
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            with open(path, encoding="utf-8") as f:
                source = f.read()
            lua_globals = self._lua_runtime.execute(source)
        except Exception as exc:
            return False, f"Lua error: {exc}"
        api = ScriptAPI(name, self._tui)
        self._scripts[name] = (api, lua_globals, "lua")
        self._register_lua_hooks(name, lua_globals, api)
        return True, f"Loaded Lua script '{name}'"

    def _register_hooks(self, name: str, module: Any) -> None:
        api = self._scripts[name][0]
        for hook_name in ("on_message", "on_join", "on_part", "on_quit",
                          "on_nick_change", "on_command"):
            fn = getattr(module, hook_name, None)
            if fn is not None:
                self._hooks.setdefault(hook_name, []).append((api, fn))
                # Register /command for on_command hooks
                if hook_name == "on_command":
                    cmd_name = getattr(fn, "_cmd_name", name.lower())
                    self._commands[cmd_name] = (api, fn)

    def _register_lua_hooks(self, name: str, lua_globals: Any, api: ScriptAPI) -> None:
        for hook_name in ("on_message", "on_join", "on_part", "on_quit",
                          "on_nick_change", "on_command"):
            fn = getattr(lua_globals, hook_name, None)
            if fn is not None:
                self._hooks.setdefault(hook_name, []).append((api, fn))
                if hook_name == "on_command":
                    self._commands[name.lower()] = (api, fn)

    def load(self, path: str) -> Tuple[bool, str]:
        name = os.path.splitext(os.path.basename(path))[0]
        if name in self._scripts:
            return False, f"Script '{name}' already loaded"
        if path.endswith(".py"):
            return self._load_py(path)
        elif path.endswith(".lua"):
            return self._load_lua(path)
        else:
            return False, f"Unsupported script type: {path}"

    def unload(self, name: str) -> Tuple[bool, str]:
        if name not in self._scripts:
            return False, f"No script named '{name}' loaded"
        del self._scripts[name]
        for hook_list in self._hooks.values():
            hook_list[:] = [(a, h) for a, h in hook_list if a.name != name]
        self._commands = {c: v for c, v in self._commands.items() if v[0].name != name}
        return True, f"Unloaded script '{name}'"

    def list_scripts(self) -> List[Tuple[str, str]]:
        return [(n, lang) for n, (_, _, lang) in self._scripts.items()]

    def get_command(self, cmd: str) -> Optional[Tuple[ScriptAPI, Callable]]:
        return self._commands.get(cmd)

    async def dispatch(self, event: str, **kwargs) -> None:
        handlers = self._hooks.get(event)
        if not handlers:
            return
        for api, handler in handlers:
            try:
                result = handler(api, **kwargs)
                if asyncio.iscoroutine(result):
                    await result
            except Exception:
                pass

    def load_all(self) -> List[str]:
        """Load all .py and .lua files from SCRIPT_DIR_SCRIPTS."""
        os.makedirs(SCRIPT_DIR_SCRIPTS, exist_ok=True)
        msgs = []
        for fn in sorted(os.listdir(SCRIPT_DIR_SCRIPTS)):
            if fn.endswith((".py", ".lua")):
                ok, msg = self.load(os.path.join(SCRIPT_DIR_SCRIPTS, fn))
                msgs.append(msg)
        return msgs


class ServerContext:
    """Holds all state that is scoped to a single IRC server connection."""
    __slots__ = ("server_id", "client", "channel_users", "user_scores",
                 "user_ai_scores", "_suspect_nicks", "_sorted_users",
                 "channel_user_modes")

    def __init__(self, server_id: str, client: "IRCClient") -> None:
        self.server_id       = server_id
        self.client          = client
        self.channel_users:  Dict[str, set]      = {}
        self.user_scores:    Dict[str, int]       = {}
        self.user_ai_scores: Dict[str, int]       = {}
        self._suspect_nicks: set                  = set()
        self._sorted_users:  Dict[str, List[str]] = {}
        self.channel_user_modes: Dict[str, Dict[str, str]] = {}

# =========================
# TUI - Enhanced Dashboard
# =========================
class TUI:
    def __init__(self, stdscr, ui_queue: asyncio.Queue, client: IRCClient):
        self.stdscr = stdscr
        self.ui_queue = ui_queue
        self.client = client
        self.height, self.width = stdscr.getmaxyx()
        self.chat_height = max(1, self.height - 4)  # 1 extra row for tab bar
        self._content_height = max(1, self.chat_height - 1)  # row 0 is always the title bar
        self.userlist_width = 30
        self._show_userlist = True

        try:
            self.chat_win  = curses.newwin(self.chat_height, max(1, self.width - self.userlist_width), 0, 0)
            self.user_win  = curses.newwin(self.chat_height, self.userlist_width, 0, max(0, self.width - self.userlist_width))
            self.input_win = curses.newwin(4, max(1, self.width), max(0, self.height - 4), 0)
        except curses.error as e:
            raise SystemExit(f"Terminal too small to initialise windows: {e}")

        # Multi-server state: primary server is client passed to __init__
        self._primary_server_id: str = client.server_id
        _primary_ctx = ServerContext(self._primary_server_id, client)
        self.servers: Dict[str, ServerContext] = {self._primary_server_id: _primary_ctx}
        # _active_server_id is set during event dispatch; points at the server
        # whose dicts (channel_users etc.) are currently aliased to self.*
        self._active_server_id: str = self._primary_server_id

        self.windows: List[ChatWindow] = []
        self.window_by_name: Dict[str, ChatWindow] = {}
        _psid = self._primary_server_id
        for name in ("*status*", "*dashboard*"):
            win = ChatWindow(name, is_channel=False, server_id=_psid)
            # *dashboard* is a synthetic view that's rebuilt by clearing
            # in-memory lines and re-adding everything; persisting it would
            # accumulate identical rebuild dumps in chat_logs/ for no value.
            if name == "*dashboard*":
                win._persist = False
            self.windows.append(win)
            self.window_by_name[name] = win

        # Pre-create the default channel window so its tab is always visible and
        # join errors / join success messages land there immediately.
        if DEFAULT_CHANNEL:
            _dcw = ChatWindow(DEFAULT_CHANNEL, is_channel=True, server_id=_psid)
            _primary_ctx.channel_users[DEFAULT_CHANNEL] = set()
            # Load persisted chat history before the new-session marker so
            # previous messages appear above it in chronological order.
            _hist = load_chat_history(DEFAULT_CHANNEL)
            for _hl in _hist:
                _dcw.lines.append(_hl)
                _dcw._line_msgids.append("")
            if _hist:
                _dcw._wrap_dirty = True
            _dcw.add_line(f"log channel {DEFAULT_CHANNEL} enabled", timestamp=True)
            self.windows.append(_dcw)
            self.window_by_name[DEFAULT_CHANNEL] = _dcw

        # Alias primary ctx dicts directly onto self so all existing code continues
        # to work without changes.  _sync_ctx() swaps these aliases when a
        # different server's event needs processing.
        self.channel_users  = _primary_ctx.channel_users
        self.user_scores    = _primary_ctx.user_scores
        self.user_ai_scores = _primary_ctx.user_ai_scores
        self._suspect_nicks     = _primary_ctx._suspect_nicks
        self._sorted_users      = _primary_ctx._sorted_users
        self.channel_user_modes = _primary_ctx.channel_user_modes

        self.current_window_index = 0
        self.current_channel: Optional[str] = DEFAULT_CHANNEL
        self.ai_suspect_threshold = AI_SUSPECT_THRESHOLD

        self.input_buffer = ""
        self.input_cursor  = 0
        self.input_history: deque = deque(load_input_history(), maxlen=500)
        self.history_index  = -1
        self._history_draft = ""
        self.completion_state = None
        self.dirty = True
        self.last_redraw = 0.0
        self._start_time = time.monotonic()
        self.ignored_nicks: set = set(load_irc_config().get("ignored_nicks", []))
        self.ignored_masks: list = load_irc_config().get("ignored_masks", [])  # list of glob patterns
        self._aliases: Dict[str, str] = dict(load_irc_config().get("aliases", {}))
        self.mention_beep_muted: bool = False
        self._msg_hours: Dict[str, List[int]] = {}
        self._last_speaker: Dict[str, str] = {}
        self._adjacency: Dict[str, Counter] = {}
        self._targets: Dict[str, Counter] = {}
        self._ch_activity: Dict[str, Counter] = {}
        self._recent_styl_scores: Dict[str, float] = {}
        self._ai_feedback_log: List[Dict[str, Any]] = []

        # /seen tracking: nick_lower → (unix_ts, message_preview, channel)
        self._seen_times: Dict[str, Tuple[float, str, str]] = {}
        # /tell queue: nick_lower → [(from_nick, msg, timestamp), ...]
        self._tell_queue: Dict[str, List[Tuple[str, str, float]]] = {}

        # Ban list viewer: cached from last /ban -l
        self._cached_banlist: list = []
        # Channel list cache for local filtering
        self._cached_list_results: list = []
        # DCC transfers
        self._dcc_trusted: set = set(load_irc_config().get("dcc_trusted", []))

        # Performance caches — maintained incrementally to avoid per-frame rebuilds
        # NOTE: _suspect_nicks and _sorted_users are now aliased from the active
        # ServerContext; see _sync_ctx().
        self._suspect_re: Optional[re.Pattern] = None   # compiled regex, rebuilt on change
        self._suspect_re_nicks: frozenset = frozenset() # snapshot used to build _suspect_re
        self._mention_re: Optional[re.Pattern] = None   # matches our nick in message body
        self._mention_re_nick: str = ""                  # nick the regex was compiled for
        self._dashboard_dirty = False             # needs rebuild?
        self._dashboard_last_update = 0.0         # last rebuild timestamp
        self._dashboard_ota_interval = 5.0        # auto-refresh interval while dashboard is visible
        # "suspects" = normal auto-refreshing suspects view
        # "profile"  = /ai output; suppresses auto-refresh until user navigates away and back
        self._dashboard_mode = "suspects"
        self._prev_on_dashboard = False           # edge-detect navigate-back-to-dashboard
        self._dashboard_profile_locked = False    # one-shot: skip reset on same-tick navigate

        # IRCv3 +typing client tag
        # Incoming: {target_lower: {nick_lower: [orig_nick, state, expiry_monotonic]}}
        #   state "active" expires in 6 s, "paused" in 30 s; "done" removes immediately
        self._typing_peers: dict = {}
        # Outgoing
        self._typing_out_target: str = ""   # target we are currently reporting typing for
        self._typing_out_last:   float = 0.0  # monotonic time of last +typing=active sent
        self._typing_out_state:  str = ""   # "active" | "paused" | ""
        self._typing_last_key:   float = 0.0  # monotonic time of last buffer-modifying key

        # Claude API state
        self.ai_chat_model: str = CLAUDE_DEFAULT_MODEL   # key into CLAUDE_MODELS
        self._askai_pending: bool = False                # prevent concurrent calls
        self._anthropic_client = None                    # reuse HTTP connection pool
        self._openai_client    = None
        self._deepseek_client  = None
        self._copilot_client   = None
        self._gemini_client    = None

        # Pre-compute curses attributes (avoids repeated function calls every frame)
        try:
            self._A_ITALIC = curses.A_ITALIC
        except AttributeError:
            self._A_ITALIC = curses.A_DIM
        self._attr_normal     = curses.A_NORMAL
        self._attr_bold       = curses.A_BOLD
        self._attr_action     = curses.color_pair(8) | self._A_ITALIC
        self._attr_title      = curses.A_REVERSE | curses.color_pair(1)
        self._attr_userheader = curses.A_REVERSE | curses.color_pair(2)
        self._attr_suspect    = curses.A_BOLD | curses.color_pair(3)
        self._attr_mention    = curses.A_BOLD | curses.A_REVERSE
        self._attr_url        = curses.A_BOLD | curses.A_UNDERLINE | curses.color_pair(6)

        # Theme — starts at 1 (Classic); apply_theme reinitialises color pairs
        self.current_theme: int = 1
        self.apply_theme(1, announce=False)

        # Mouse: capture clicks so left-click can open URL lines.
        # Shift+Click still reaches the terminal for text selection in most emulators.
        try:
            curses.mouseinterval(0)  # 0 → no click-interval; only PRESSED events fire
            _mouse_extra = getattr(curses, 'REPORT_MOUSE_POSITION', 0)
            curses.mousemask(curses.ALL_MOUSE_EVENTS | _mouse_extra)
        except curses.error:
            pass
        # Resolve scroll-wheel bit masks — values differ between ncurses and PDCurses.
        self._wheel_up   = getattr(curses, 'BUTTON4_PRESSED', 1 << 16)  # ncurses: 0x200000  PDCurses: 0x10000
        self._wheel_down = getattr(curses, 'BUTTON5_PRESSED', 1 << 21)  # ncurses: 0x400000  PDCurses: 0x200000

        # Per-pane dirty flags — skip drawing panes that haven't changed
        self._chat_dirty    = True
        self._userlist_dirty = True
        self._input_dirty   = True

        # Cached window dimensions (updated only on resize)
        # Compute _tw from the logical expected width, not getmaxyx(), so that a
        # silently-failed chat_win.resize() can't leave _tw at the old oversized
        # value and cause text/erase to bleed into the userlist area.
        self._tw     = max(1, max(1, self.width - self.userlist_width) - 1)
        self._uw     = max(1, self.userlist_width - 2)            # userlist interior cols
        self._input_w = max(1, self.input_win.getmaxyx()[1] - 4) # input text cols

        # Unread tracking: window names that have received messages while inactive
        self._unread_windows: set = set()

        self._event_handlers: dict = {}
        self._slash_handlers: dict = {}
        self._build_event_handlers()
        self._build_slash_handlers()

        self.plugin_manager = PluginManager()
        self.script_engine = ScriptEngine(self)
        self.script_engine.load_all()
        # Auto-load plugins from plugins/ directory
        auto_loaded = self.plugin_manager.auto_load_plugins(self)
        if auto_loaded:
            self.window_by_name["*status*"].add_line(
                f"[plugin] Auto-loaded {len(auto_loaded)} plugin(s): {', '.join(auto_loaded)}",
                timestamp=False)

        stdscr.nodelay(True)
        stdscr.keypad(True)

        # ── Auto-translate CJK (Chinese/Japanese/…) messages to English
        self.auto_translate: bool = True
        # Auto-fetch link metadata (title, image info, domain warnings)
        self.link_preview_enabled: bool = True
        # ── IRC operator / user mode tracking ──────────────────────────────────────
        self._own_umodes: set = set()
        self._ircop_nicks: set = set()
        self._PREFIX_BY_LETTER: set = set("ovhaq")
        self._MODE_ARGS_CHARS: set = set("ovhaqbeklI")

        # ── Built-in bouncer ──────────────────────────────────────────────────────
        self._bouncer_enabled: bool = True         # master toggle
        self._bouncer_detached: bool = False       # TUI hidden, IRC still connected
        self._bouncer_buffer  = BouncerBuffer()
        self._bouncer_replay_limit: int = 0        # 0 = unlimited
        self._bouncer_filter_mode: str = "all"     # "all", "highlights", "dms"
        self._bouncer_last_attach: float = 0.0     # timestamp of last attach
        # Load bouncer config (server-side playback settings)
        _bc = load_irc_config().get("bouncer", {})
        self._bouncer_enabled = _bc.get("enabled", True)
        self._bouncer_detached = _bc.get("detached", False)
        self._bouncer_replay_limit = _bc.get("replay_limit", 0)
        self._bouncer_filter_mode = _bc.get("filter_mode", "all")

        # ── GPG ───────────────────────────────────────────────────────────────────
        self._gpg_enabled: bool = _gpg_available()
        self._gpg_key_fp: str = ""   # default signing key fingerprint
        _gc = load_irc_config().get("gpg", {})
        self._gpg_key_fp = _gc.get("key_fingerprint", "")

        # ── Tor ───────────────────────────────────────────────────────────────────
        self._use_tor: bool = load_irc_config().get("tor", {}).get("enabled", False)
        self._tor_strict: bool = load_irc_config().get("tor", {}).get("strict", False)
        self.client.use_tor = self._use_tor
        self.client.tor_strict = self._tor_strict

    # ── Multi-server helpers ─────────────────────────────────────────────────

    def _wk(self, server_id: str, name: str) -> str:
        """Compute the window_by_name key for (server_id, window_name).

        Primary server windows keep their bare name so legacy code that
        hard-codes self.window_by_name["*status*"] still works.
        """
        return name if server_id == self._primary_server_id else f"{server_id}/{name}"

    def _sync_ctx(self, server_id: str) -> None:
        """Alias self.channel_users / user_scores / … to the given server's dicts.

        Must be called before every event-handler invocation so that existing
        handler code (which writes to self.channel_users etc.) mutates the
        correct per-server dict.
        """
        self._active_server_id = server_id
        ctx = self.servers.get(server_id)
        if ctx is None:
            return
        self.channel_users  = ctx.channel_users
        self.user_scores    = ctx.user_scores
        self.user_ai_scores = ctx.user_ai_scores
        self._suspect_nicks = ctx._suspect_nicks
        self._sorted_users      = ctx._sorted_users
        self.channel_user_modes = ctx.channel_user_modes

    def _sync_draw_ctx(self) -> None:
        """Sync self.* aliases to the server that owns the currently visible window.

        Called at the top of redraw() so drawing methods always read from the
        right server's data regardless of which server last dispatched an event.
        """
        win = self.get_current_window()
        sid = win.server_id or self._primary_server_id
        self._sync_ctx(sid)

    def _status_win(self) -> ChatWindow:
        """Return the status window for the currently active server."""
        wk = self._wk(self._active_server_id, "*status*")
        return self.window_by_name.get(wk) or self.window_by_name["*status*"]

    def _active_client(self) -> IRCClient:
        """Return the IRCClient for the currently active server."""
        ctx = self.servers.get(self._active_server_id)
        return ctx.client if ctx else self.client

    def ensure_window(self, name: str, is_channel: bool = True) -> ChatWindow:
        sid = self._active_server_id
        wk  = self._wk(sid, name)
        if wk not in self.window_by_name:
            win = ChatWindow(name, is_channel=is_channel, server_id=sid)
            # Restore persisted chat history before first use so the window
            # shows previous messages immediately on creation.
            hist = load_chat_history(name)
            for hl in hist:
                win.lines.append(hl)
                win._line_msgids.append("")
            if hist:
                win._wrap_dirty = True
            self.windows.append(win)
            self.window_by_name[wk] = win
            if is_channel and name not in self.channel_users:
                self.channel_users[name] = set()
        return self.window_by_name[wk]

    def _chat_text_width(self) -> int:
        """Usable text columns in the chat window (leaves 1-col right margin)."""
        return self._tw  # always consistent with the value used for rendering

    def _wrap_window(self, win: ChatWindow) -> None:
        max_width = self._chat_text_width()
        if not win._wrap_dirty and win._last_wrap_width == max_width:
            return
        wrapped: List[str] = []
        url_map: Dict[int, str] = {}

        def _wrap_raw(raw: str) -> None:
            """Wrap a single raw fragment (no \\n) into wrapped[], word-wrapping if wide."""
            if not raw:
                return
            s = irc_strip_formatting(raw)
            while _str_visual_width(s) > max_width:
                rm = _irc_visual_pos(raw, max_width)
                sp = raw.rfind(" ", 0, rm)
                if sp == -1:
                    sp = rm if rm > 0 else 1
                wrapped.append(raw[:sp])
                raw = raw[sp:].lstrip()
                s   = irc_strip_formatting(raw)
            wrapped.append(raw)

        def _wrap_one_line(raw_line: str) -> None:
            """Wrap one logical line (no embedded \\n): URL-split then word-wrap."""
            if not raw_line:
                wrapped.append("")
                return
            stripped = irc_strip_formatting(raw_line)
            url_matches = list(_URL_RE.finditer(stripped))
            if url_matches:
                # Extract each URL as its own display line so long URLs never split.
                # Use stripped text for URL position tracking (IRC codes in raw_line
                # would shift offsets); pre/post segments fed through _wrap_raw.
                remaining = stripped
                for um in url_matches:
                    url_str   = um.group(0)
                    url_clean = url_str.rstrip('.,;:!?)"\'>')
                    pos = remaining.find(url_str)
                    if pos < 0:
                        continue
                    _wrap_raw(remaining[:pos].rstrip())
                    display = (url_clean
                               if _str_visual_width(url_clean) <= max_width
                               else _truncate_to_width(url_clean, max_width - 1) + "…")
                    url_map[len(wrapped)] = url_clean
                    wrapped.append(display)
                    remaining = remaining[pos + len(url_str):].lstrip()
                _wrap_raw(remaining)
            else:
                r = raw_line
                s = stripped
                while _str_visual_width(s) > max_width:
                    rm = _irc_visual_pos(r, max_width)
                    sp = r.rfind(" ", 0, rm)
                    if sp == -1:
                        sp = rm if rm > 0 else 1
                    wrapped.append(r[:sp])
                    r = r[sp:].lstrip()
                    s = irc_strip_formatting(r)
                wrapped.append(r)

        _msgids      = win._line_msgids
        _unread_from = win._unread_from

        for _src_i, line in enumerate(win.lines):
            _src_msgid = _msgids[_src_i] if _src_i < len(_msgids) else ""

            # read-marker: inject separator before the first unread line
            if _unread_from >= 0 and _src_i == _unread_from:
                _sep_inner = "  unread  "
                _sep_dash  = "─" * max(0, (max_width - len(_sep_inner)) // 2)
                wrapped.append(_sep_dash + _sep_inner + _sep_dash)

            if not line:
                wrapped.append("")
                continue

            # draft/multiline: messages with embedded \n from a multiline batch
            if "\n" in line:
                parts = line.split("\n")
                _wrap_one_line(parts[0])
                for _sp in parts[1:]:
                    _wrap_one_line("    " + _sp if _sp else "")
            else:
                _wrap_one_line(line)

            # Inject a reactions summary line immediately after this message
            if _src_msgid and _src_msgid in win._reactions:
                _reacts = win._reactions[_src_msgid]
                _rparts = []
                for _emoji, _nicks in _reacts.items():
                    _cnt = len(_nicks)
                    _rparts.append(f"{_emoji}×{_cnt}" if _cnt > 1 else _emoji)
                if _rparts:
                    wrapped.append("  [" + "  ".join(_rparts) + "]")

        win.wrapped_cache    = wrapped
        win.url_map          = url_map
        win._wrap_dirty      = False
        win._last_wrap_width = max_width

    async def update_dashboard(self):
        dash = self.window_by_name["*dashboard*"]
        dash.lines.clear()
        dash._wrap_dirty = True
        A = lambda t: dash.add_line(t, timestamp=False)

        client = self._active_client()
        now = time.monotonic()

        # ── Header ──────────────────────────────────────────────────────────
        A(f"=== AI Suspects Dashboard ===  {client.nick}@{client.server}")
        A(f"  Threshold: {self.ai_suspect_threshold}%  |  Plugins: {len(self.plugin_manager._plugins)}  |  BNC: {'ON' if self._bouncer_enabled else 'OFF'}")
        A("")

        # ── Current session suspects ────────────────────────────────────────
        A("── Current Session Suspects ──")
        A("")

        suspects = []
        for nick, state in self.client.users.items():
            ai = int(state.rolling_ai_likelihood())
            if ai >= self.ai_suspect_threshold:
                suspects.append((nick, ai, state))

        if not suspects:
            A("  No high-AI users detected in this session.")
        else:
            for nick, ai_pct, state in sorted(suspects, key=lambda x: x[1], reverse=True):
                join_ago = int((now - state.join_time) // 60)
                last_ago = int((now - state.last_msg_time) // 60) if state.last_msg_time else 0
                avg_len  = state.avg_msg_length()
                mpm      = state.messages_per_minute()
                bars = "▁▂▃▄▅▆▇█"
                spark = "".join(bars[min(7, s * 8 // 101)]
                                for s in list(state.ai_scores)[-16:])
                is_bot = state.is_confirmed_bot or nick.lower() in (client.scoring.confirmed_bot_nicks if hasattr(client, 'scoring') else set())
                badge = " [BOT]" if is_bot else ""
                A(f"  {nick:<14} [{ai_pct:2d}%]{badge}  msgs:{state.total_msgs:3d}  "
                  f"avg:{avg_len:4.0f}  mpm:{mpm:4.1f}  "
                  f"join:{join_ago:2d}m  last:{last_ago:2d}m")
                if spark:
                    A(f"    {spark}")

        # ── Channel activity ────────────────────────────────────────────────
        A("")
        A("── Channel Activity ──")
        A("")
        channels_with_msgs = {}
        for nick, ch_counts in self._ch_activity.items():
            for ch, count in ch_counts.items():
                channels_with_msgs[ch] = channels_with_msgs.get(ch, 0) + count
        if not channels_with_msgs:
            A("  No channel activity yet.")
        else:
            for ch, count in sorted(channels_with_msgs.items(), key=lambda x: -x[1])[:10]:
                users = len(self.channel_users.get(ch, set()))
                A(f"  {ch:<20} {count:4d} msgs  {users:3d} users")

        # ── Network stats ───────────────────────────────────────────────────
        A("")
        A("── Network Stats ──")
        A("")
        total_users = sum(len(users) for users in self.channel_users.values())
        total_channels = len(self.channel_users)
        total_msgs = sum(state.total_msgs for state in self.client.users.values())
        uptime_mins = int((now - self._start_time) // 60) if hasattr(self, '_start_time') else 0
        A(f"  Channels     : {total_channels}")
        A(f"  Total users  : {total_users}")
        A(f"  Messages     : {total_msgs}")
        A(f"  Uptime       : {uptime_mins // 60}h {uptime_mins % 60}m")
        A(f"  Buffered     : {self._bouncer_buffer.count} msgs ({self._bouncer_buffer.highlight_count} highlights)")

        # ── Your Biometrics ─────────────────────────────────────────────────
        A("")
        A("── Your Biometrics ──")
        A("")
        bio = client.biometrics
        cadence = bio.get_typing_cadence_stats()
        comp = bio.get_composition_stats()
        resp = bio.get_response_latency_stats()
        A(f"  Typing cadence   : {cadence['mean']:.0f} ms (σ {cadence['std']:.0f} ms)")
        A(f"  Composition time : {comp['mean']:.1f} s (σ {comp['std']:.1f} s)")
        A(f"  Response latency : {resp['mean']:.1f} s (σ {resp['std']:.1f} s)")
        A(f"  Backspace ratio  : {bio.get_backspace_ratio():.1%}")
        A(f"  Human likelihood : {bio.get_human_likelihood():.0f}%")
        A(f"  Messages sent    : {bio._messages_sent}  |  Keystrokes: {bio._total_keystrokes}")

        # ── Historical suspects from log ─────────────────────────────────
        A("")
        A("── Historical suspects (all sessions, from log) ──")
        A("")
        current_nicks = {n.lower() for n in self.client.users}
        try:
            loop = asyncio.get_running_loop()
            past = await loop.run_in_executor(
                None, load_historical_suspects, self.ai_suspect_threshold)
        except Exception:
            past = []
        if not past:
            A("  No historical data yet.")
        else:
            shown = 0
            for nick, avg_score, total_msgs, first_ts in past[:20]:
                marker = " *" if nick.lower() in current_nicks else "  "
                first_str = time.strftime("%Y-%m-%d", time.localtime(first_ts)) if first_ts else "?"
                A(f"{marker}{nick:<14} avg {avg_score:2d}%  {total_msgs:4d} msgs  "
                  f"first:{first_str}")
                shown += 1
            if shown == 0:
                A("  No historical data yet.")
            A("")
            A("  (* = currently active in this session)")

    async def show_user_ai_profile(self, nick: str) -> None:
        dash = self.window_by_name["*dashboard*"]
        dash.lines.clear()
        dash._wrap_dirty = True
        L = lambda t: dash.add_line(t, timestamp=False)
        bars = "▁▂▃▄▅▆▇█"

        # Load log history concurrently with building in-memory stats
        loop = asyncio.get_running_loop()
        hist_task = loop.run_in_executor(None, load_nick_history, nick)

        state = self.client.users.get(nick)
        now   = time.monotonic()

        # ── In-memory (current session) ─────────────────────────────────────
        if state:
            scores   = list(state.ai_scores)
            rolling  = int(state.rolling_ai_likelihood())
            s_peak   = max(scores) if scores else 0
            s_low    = min(scores) if scores else 0
            join_ago = int((now - state.join_time) // 60)
            last_ago = int((now - state.last_msg_time) // 60) if state.last_msg_time else None
            avg_len  = state.avg_msg_length()
            mpm      = state.messages_per_minute()
            s_std    = 0.0
            if len(scores) >= 2:
                mean  = sum(scores) / len(scores)
                s_std = (sum((s - mean) ** 2 for s in scores) / len(scores)) ** 0.5
            trend_str = ""
            if len(scores) >= 20:
                delta = sum(scores[-10:]) / 10 - sum(scores[-20:-10]) / 10
                arrow = "▲" if delta > 2 else ("▼" if delta < -2 else "►")
                trend_str = f"{arrow} {abs(delta):.0f}% vs prior 10 msgs"
            spark = "".join(bars[min(7, s * 8 // 101)] for s in scores[-48:]) if scores else ""
        else:
            scores = []

        # ── Await historical data ────────────────────────────────────────────
        hist = await hist_task
        hs   = hist["all_scores"]
        hl   = hist["all_lengths"]
        all_ts    = hist["all_ts"]
        h_total   = hist["total_msgs"]
        h_first   = hist["first_ts"]
        h_last    = hist["last_ts"]
        h_avg     = int(sum(hs) / len(hs)) if hs else 0
        h_peak    = max(hs) if hs else 0
        h_low     = min(hs) if hs else 0
        h_avg_len = int(sum(hl) / len(hl)) if hl else 0
        h_std     = 0.0
        if len(hs) >= 2:
            hm    = sum(hs) / len(hs)
            h_std = (sum((s - hm) ** 2 for s in hs) / len(hs)) ** 0.5
        # All-time trend: compare most recent half to older half
        h_trend_str = ""
        if len(hs) >= 20:
            mid   = len(hs) // 2
            delta = sum(hs[mid:]) / (len(hs) - mid) - sum(hs[:mid]) / mid
            arrow = "▲" if delta > 2 else ("▼" if delta < -2 else "►")
            h_trend_str = f"{arrow} {abs(delta):.0f}% newer vs older half"
        active_sessions = [(sid, sd) for sid, sd in hist["sessions"].items() if sd["msgs"] > 0]

        # ── Verdict ──────────────────────────────────────────────────────────
        combined_avg  = h_avg if h_total > 0 else (int(sum(scores) / len(scores)) if scores else 0)
        n_sessions    = len(active_sessions)
        is_consistent = h_std < 10 if h_total > 0 else (s_std < 10 if scores else True)
        is_bot        = (state and state.is_confirmed_bot) or (
            nick.lower() in self._active_client().scoring.confirmed_bot_nicks)
        fp            = self._active_client().scoring.bot_fingerprints.get(nick.lower())
        if is_bot:
            verdict = "CONFIRMED BOT/AI — manually identified"
        elif combined_avg >= 80 and n_sessions >= 3 and is_consistent:
            verdict = "HIGH RISK — persistent, consistent AI pattern across multiple sessions"
        elif combined_avg >= 70:
            verdict = "SUSPECT — elevated AI score"
        elif combined_avg >= 50:
            verdict = "MODERATE — borderline, watch for pattern"
        else:
            verdict = "LOW — no strong AI signal"

        # ── Render ───────────────────────────────────────────────────────────
        bot_badge = "  *** CONFIRMED BOT/AI ***" if is_bot else ""
        L(f"=== AI Profile: {nick}{bot_badge} ===")
        if is_bot and fp:
            L(f"  Fingerprint: {fp.msg_count} msgs  {len(fp.bigrams)} bigrams  "
              f"{len(fp.trigrams)} trigrams  {len(fp.word_vocab)} unique words")
        L("")

        if state:
            L("  ── This session ──────────────────────────────")
            L(f"  Rolling AI likelihood  : {rolling}%")
            L(f"  Peak / Low             : {s_peak}% / {s_low}%")
            L(f"  Std deviation          : {s_std:.1f}%  ({'consistent' if s_std < 10 else 'variable'})")
            if trend_str:
                L(f"  Recent trend           : {trend_str}")
            L(f"  Messages this session  : {state.total_msgs}")
            L(f"  Avg message length     : {avg_len:.0f} chars")
            L(f"  Messages / minute      : {mpm:.2f}")
            # Burst analysis: suspiciously short inter-message gaps suggest automation
            if state.msg_times:
                _gaps = list(state.msg_times)
                _min_gap  = min(_gaps)
                _burst_n  = sum(1 for g in _gaps if g < 2.0)
                _burst_pct = 100 * _burst_n // len(_gaps)
                _gap_tag  = "suspicious" if _min_gap < 0.5 else ("fast" if _min_gap < 1.5 else "normal")
                L(f"  Min msg interval       : {_min_gap:.1f}s  ({_gap_tag})")
                L(f"  Burst rate (<2s gap)   : {_burst_pct}%  ({_burst_n}/{len(_gaps)} msgs)")
            # Message length uniformity: low CoV suggests templated / AI text
            if len(state.msg_lengths) >= 4:
                _lens  = list(state.msg_lengths)
                _m_len = sum(_lens) / len(_lens)
                _std_l = (sum((l - _m_len) ** 2 for l in _lens) / len(_lens)) ** 0.5
                _cov   = _std_l / _m_len if _m_len > 0 else 0
                _utag  = "very uniform" if _cov < 0.15 else ("uniform" if _cov < 0.30 else "variable")
                L(f"  Msg length uniformity  : CoV {_cov:.2f}  ({_utag})")
            L(f"  Joined                 : {join_ago}m ago")
            if last_ago is not None:
                L(f"  Last message           : {last_ago}m ago")
            # Current channel presence
            _in_chans = sorted(ch for ch, users in self.channel_users.items() if nick in users)
            if _in_chans:
                L(f"  Currently in           : {' '.join(_in_chans)}")
            if nick.lower() in self.ignored_nicks:
                L("  Status                 : IGNORED")
            if spark:
                L(f"  Score history          : {spark}")
            # Per-signal breakdown (Area 6) — averages over recent scored messages
            _signals = list(state._recent_signals)
            if len(_signals) >= 3:
                _avg = lambda k: sum(d.get(k, 0) for d in _signals) / len(_signals)
                L("  ── Signal breakdown ─────────────────────────")
                L(f"  Binoculars (bino)      : {_avg('bino'):.2f}")
                L(f"  Classifier  (cls)      : {_avg('cls'):.2f}")
                L(f"  Heuristics  (heu)      : {_avg('heu'):.2f}")
                L(f"  Llama-patt  (llama)    : {_avg('llama'):.2f}")
                L(f"  Adversarial (adv)      : {_avg('adv'):.2f}")
                L(f"  Embed-drift (embed)    : {_avg('embed'):.2f}")
                L(f"  Watermark   (wm)       : {_avg('watermark'):.2f}")
                L(f"  Stylometric (styl)     : {_avg('styl'):.2f}")
            L("")
        else:
            L("  (not seen in current session)")
            L("")

        L("  ── All sessions (from log) ───────────────────")
        if h_total == 0:
            L("  No log entries found for this nick.")
        else:
            first_str = time.strftime("%Y-%m-%d %H:%M", time.localtime(h_first)) if h_first else "?"
            last_str  = time.strftime("%Y-%m-%d %H:%M", time.localtime(h_last))  if h_last  else "?"
            sess_this = state.total_msgs if state else 0
            L(f"  All-time messages      : {h_total}  ({sess_this} this session)")
            L(f"  All-time avg AI        : {h_avg}%  (peak {h_peak}%  low {h_low}%)")
            L(f"  All-time std deviation : {h_std:.1f}%  ({'consistent' if h_std < 10 else 'variable'})")
            if h_trend_str:
                L(f"  All-time trend         : {h_trend_str}")
            L(f"  Avg message length     : {h_avg_len} chars")
            L(f"  Sessions               : {n_sessions}")
            L(f"  First ever seen        : {first_str}")
            L(f"  Last seen in log       : {last_str}")
            if hist["channels"]:
                L(f"  Channels               : {' '.join(hist['channels'][:6])}")
            # Hour-of-day activity distribution (local time)
            if len(all_ts) >= 5:
                _hbkt = [0] * 24
                for _t in all_ts:
                    _hbkt[time.localtime(_t).tm_hour] += 1
                _hpeak = max(_hbkt)
                _hbar  = "▁▂▃▄▅▆▇█"
                _hspark = "".join(_hbar[min(7, b * 8 // (_hpeak + 1))] for b in _hbkt)
                _peak_h = _hbkt.index(_hpeak)
                L(f"  Active hours (0–23h)   : {_hspark}  peak:{_peak_h:02d}h")
            # All-time burst rate from inter-message gaps in log
            if len(all_ts) >= 4:
                _sts = sorted(all_ts)
                _hgaps = [_sts[i+1] - _sts[i] for i in range(len(_sts)-1)
                          if _sts[i+1] - _sts[i] < 3600]
                if _hgaps:
                    _h_min_gap   = min(_hgaps)
                    _h_burst_n   = sum(1 for g in _hgaps if g < 2.0)
                    _h_burst_pct = 100 * _h_burst_n // len(_hgaps)
                    _h_gap_tag   = "suspicious" if _h_min_gap < 0.5 else ("fast" if _h_min_gap < 1.5 else "normal")
                    L(f"  All-time min gap       : {_h_min_gap:.1f}s  ({_h_gap_tag})")
                    L(f"  All-time burst rate    : {_h_burst_pct}%  ({_h_burst_n}/{len(_hgaps)} inter-msg gaps)")

            if active_sessions:
                L("")
                L(f"  ── Per-session breakdown ({n_sessions} sessions) ──")
                for sid, sd in active_sessions[-8:]:
                    s_avg  = int(sum(sd["scores"]) / len(sd["scores"])) if sd["scores"] else 0
                    s_abar = bars[min(7, s_avg * 8 // 101)]
                    s_alen = int(sum(sd["lengths"]) / len(sd["lengths"])) if sd.get("lengths") else 0
                    chs    = " ".join(sorted(sd.get("channels", set()))[:3])
                    L(f"    [{sid}] {sd['dt'][:16]}  {sd['msgs']:3d} msgs  "
                      f"avg {s_avg:2d}% {s_abar}  len {s_alen}  {chs}")

            if n_sessions >= 2:
                h_spark = "".join(
                    bars[min(7, int(sum(sd["scores"]) / len(sd["scores"])) * 8 // 101)]
                    for _, sd in active_sessions if sd["scores"]
                )
                L("")
                L(f"  Session trend          : {h_spark}")

            if hist["top_messages"]:
                L("")
                L("  ── Top scored messages ──────────────────────")
                for tm in hist["top_messages"]:
                    preview = tm["msg"][:60].replace("\n", " ")
                    if len(tm["msg"]) > 60:
                        preview += "…"
                    L(f"  [{tm['a']:2d}%] {tm['dt'][:16]}  \"{preview}\"")

            if hist["gaps"]:
                L("")
                L(f"  [!] {len(hist['gaps'])} sequence gap(s) — log may be incomplete")

        L("")
        L("  ── Verdict ──────────────────────────────────")
        L(f"  {verdict}")

        self._dashboard_mode           = "profile"
        self._dashboard_profile_locked = True
        self._dashboard_dirty          = False
        self._dashboard_last_update    = time.monotonic()
        self.current_window_index      = 1
        self._chat_dirty               = True
        self.dirty                     = True

    async def _call_ai(self, prompt: str, model_key: str,
                       max_tokens: int = 1024) -> Tuple[str, str]:
        """Send *prompt* to the AI provider for *model_key*.

        Returns (answer_text, tokens_str).  On any error the answer starts
        with "[error]" so the caller can display it as-is.

        model_key may be:
          • a key from AI_MODELS ("gemma", "sonnet", "gpt4o", …)
          • "ollama:<model-id>" for any Ollama model not pre-registered
        """
        if model_key.startswith("ollama:"):
            provider = "ollama"
            model_id = model_key[len("ollama:"):]
        else:
            spec = AI_MODELS.get(model_key)
            if not spec:
                return f"[error] unknown model key '{model_key}'", "?"
            provider = spec["provider"]
            model_id = spec["id"]

        if provider == "claude":
            if not ANTHROPIC_AVAILABLE:
                return ("[error] anthropic package not installed — "
                        "run: pip install anthropic"), "?"
            if not ANTHROPIC_API_KEY:
                return ("[error] ANTHROPIC_API_KEY not set — "
                        "set the environment variable and restart"), "?"
            try:
                if self._anthropic_client is None:
                    self._anthropic_client = _anthropic_mod.AsyncAnthropic(
                        api_key=ANTHROPIC_API_KEY)
                msg = await self._anthropic_client.messages.create(
                    model=model_id, max_tokens=max_tokens,
                    messages=[{"role": "user", "content": prompt}],
                )
                answer = msg.content[0].text if msg.content else "(empty response)"
                usage  = getattr(msg, "usage", None)
                tokens = str(usage.input_tokens + usage.output_tokens) if usage else "?"
                return answer, tokens
            except Exception as exc:
                self._anthropic_client = None   # discard on error; recreate next call
                return f"[error] {exc}", "?"

        if provider == "openai":
            if not OPENAI_AVAILABLE:
                return ("[error] openai package not installed — "
                        "run: pip install openai"), "?"
            if not OPENAI_API_KEY:
                return ("[error] OPENAI_API_KEY not set — "
                        "set the environment variable and restart"), "?"
            try:
                if self._openai_client is None:
                    self._openai_client = _openai_mod.AsyncOpenAI(
                        api_key=OPENAI_API_KEY)
                resp = await self._openai_client.chat.completions.create(
                    model=model_id, max_tokens=max_tokens,
                    messages=[{"role": "user", "content": prompt}],
                )
                answer = (resp.choices[0].message.content
                          if resp.choices else "(empty response)")
                usage  = getattr(resp, "usage", None)
                tokens = str(usage.total_tokens) if usage else "?"
                return answer, tokens
            except Exception as exc:
                self._openai_client = None      # discard on error; recreate next call
                return f"[error] {exc}", "?"

        if provider == "deepseek":
            if not OPENAI_AVAILABLE:
                return ("[error] openai package not installed — "
                        "run: pip install openai"), "?"
            if not DEEPSEEK_API_KEY:
                return ("[error] DEEPSEEK_API_KEY not set — "
                        "set the environment variable and restart"), "?"
            try:
                if self._deepseek_client is None:
                    self._deepseek_client = _openai_mod.AsyncOpenAI(
                        api_key=DEEPSEEK_API_KEY,
                        base_url="https://api.deepseek.com")
                resp = await self._deepseek_client.chat.completions.create(
                    model=model_id, max_tokens=max_tokens,
                    messages=[{"role": "user", "content": prompt}],
                )
                answer = (resp.choices[0].message.content
                          if resp.choices else "(empty response)")
                usage  = getattr(resp, "usage", None)
                tokens = str(usage.total_tokens) if usage else "?"
                return answer, tokens
            except Exception as exc:
                self._deepseek_client = None
                return f"[error] {exc}", "?"

        if provider == "copilot":
            if not OPENAI_AVAILABLE:
                return ("[error] openai package not installed — "
                        "run: pip install openai"), "?"
            if not GITHUB_TOKEN:
                return ("[error] GITHUB_TOKEN not set — "
                        "set the environment variable and restart"), "?"
            try:
                if self._copilot_client is None:
                    self._copilot_client = _openai_mod.AsyncOpenAI(
                        api_key=GITHUB_TOKEN,
                        base_url="https://api.githubcopilot.com",
                        default_headers={
                            "editor-version":        "eyearesee/1.0",
                            "editor-plugin-version": "eyearesee/1.0",
                            "copilot-integration-id": "eyearesee",
                        })
                resp = await self._copilot_client.chat.completions.create(
                    model=model_id, max_tokens=max_tokens,
                    messages=[{"role": "user", "content": prompt}],
                )
                answer = (resp.choices[0].message.content
                          if resp.choices else "(empty response)")
                usage  = getattr(resp, "usage", None)
                tokens = str(usage.total_tokens) if usage else "?"
                return answer, tokens
            except Exception as exc:
                self._copilot_client = None
                return f"[error] {exc}", "?"

        if provider == "gemini":
            if not GEMINI_AVAILABLE:
                return ("[error] google-genai package not installed — "
                        "run: pip install google-genai"), "?"
            if not GEMINI_API_KEY:
                return ("[error] GEMINI_API_KEY not set — "
                        "set the environment variable and restart"), "?"
            try:
                if self._gemini_client is None:
                    self._gemini_client = _gemini_mod.aio.Client(api_key=GEMINI_API_KEY)
                resp = await self._gemini_client.models.generate_content(
                    model=model_id,
                    contents=prompt,
                    config=_gemini_mod.types.GenerateContentConfig(
                        max_output_tokens=max_tokens))
                answer = resp.text if resp.text else "(empty response)"
                usage  = getattr(resp, "usage_metadata", None)
                if usage:
                    tokens = str(usage.prompt_token_count + usage.candidates_token_count)
                else:
                    tokens = "?"
                return answer, tokens
            except Exception as exc:
                self._gemini_client = None
                return f"[error] {exc}", "?"

        if provider == "ollama":
            loop = asyncio.get_running_loop()
            answer, tokens = await loop.run_in_executor(
                _IO_EXECUTOR, _ollama_blocking_call, model_id, prompt, max_tokens)
            return answer, tokens

        if provider == "llamacpp":
            loop = asyncio.get_running_loop()
            answer, tokens = await loop.run_in_executor(
                _IO_EXECUTOR, _llamacpp_blocking_call, model_id, prompt, max_tokens)
            return answer, tokens

        return f"[error] unknown provider '{provider}'", "?"

    async def _do_askai(self, question: str, model_key: str) -> None:
        """Call the configured AI and post the Q+A to the *dashboard* window."""
        if self._askai_pending:
            await self.ui_queue.put(("status", "/askai already in progress, please wait…"))
            return

        if model_key.startswith("ollama:"):
            model_id = model_key[len("ollama:"):]
            label    = f"Ollama/{model_id}"
        else:
            spec     = AI_MODELS.get(model_key) or AI_MODELS[CLAUDE_DEFAULT_MODEL]
            model_id = spec["id"]
            label    = spec["label"]
        self._askai_pending = True
        await self.ui_queue.put(("status",
            f"[askai] querying {model_key} ({model_id})…"))

        answer, tokens = "", "?"
        try:
            answer, tokens = await asyncio.wait_for(
                self._call_ai(question, model_key, max_tokens=1024), timeout=120.0)
        except asyncio.TimeoutError:
            answer, tokens = "[error] AI request timed out after 120 s", "?"
        except Exception as exc:
            answer, tokens = f"[error] {exc}", "?"
        finally:
            self._askai_pending = False

        dash = self.window_by_name["*dashboard*"]
        dash.lines.clear()
        dash._wrap_dirty = True
        L = lambda t: dash.add_line(t, timestamp=False)

        L(f"=== /askai [{model_key}  {label}] ===")
        L("")
        L(f"Q: {question}")
        L("")
        L("A:")
        for raw_line in answer.splitlines():
            L(f"  {raw_line}" if raw_line.strip() else "")
        L("")
        L(f"  model: {model_id}  tokens used: {tokens}")

        self.current_window_index      = 1   # switch to *dashboard*
        self._chat_dirty               = True
        self._dashboard_dirty          = False
        self._dashboard_last_update    = time.monotonic()
        self._dashboard_mode           = "profile"
        self._dashboard_profile_locked = True
        self.dirty                     = True

    async def _post_translation(self, win: ChatWindow, text: str) -> None:
        """Translate *text* and append the result as an indented line in *win*.

        Runs as a fire-and-forget asyncio task; any exception is caught here
        so it never propagates to the task's unhandled-exception handler."""
        try:
            translated = await _translate_to_english(text)
            if not translated:
                return
            win.add_line(f"  \u21b3 [EN] {translated}", timestamp=False)
            self._chat_dirty = True
            self.dirty = True
        except Exception:
            pass

    async def _post_link_info(self, win: ChatWindow, nick: str, msg: str, win_name: str) -> None:
        """Fetch metadata for URLs in *msg* and append results as indented lines."""
        try:
            cleaned = irc_strip_formatting(msg)
            urls = list(_URL_RE.finditer(cleaned))
            if not urls:
                return
            for um in urls:
                url = um.group(0).rstrip('.,;:!?)"\'>')
                if not url:
                    continue
                info = await _fetch_link_info(url)
                if info["domain_warn"]:
                    win.add_line(f"  \u26a0 {info['domain_warn']}", timestamp=False)
                if info["title"]:
                    win.add_line(f"  \u21b7 {info['title']}", timestamp=False)
                if info["image"]:
                    win.add_line(f"  {info['image']}", timestamp=False)
                _append_link_log(win_name, nick, url,
                                 info["title"] or "",
                                 urllib.parse.urlparse(url).netloc)
            if urls:
                self._chat_dirty = True
                self.dirty = True
        except Exception:
            pass

    async def _periodic_reminder_checker(self) -> None:
        """Periodically check for due reminders and notify the user."""
        while True:
            try:
                await asyncio.sleep(10)
                if not hasattr(self._active_client(), 'scoring'):
                    continue
                scoring = self._active_client().scoring
                due = scoring.reminders.check_due()
                if due:
                    status_win = self.window_by_name.get("*status*")
                    if status_win:
                        for reminder in due:
                            status_win.add_line(
                                f"-!- Reminder: {reminder['message']} (set {time.strftime('%H:%M', time.localtime(reminder['created_at']))})")
                        self._chat_dirty = True
                        self.dirty = True
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    async def _periodic_rss_poller(self) -> None:
        """Periodically poll RSS feeds and post new items to channels."""
        while True:
            try:
                await asyncio.sleep(300)  # 5 minutes
                if not hasattr(self._active_client(), 'scoring'):
                    continue
                scoring = self._active_client().scoring
                new_items = await scoring.rss.poll_all()
                if new_items:
                    status_win = self.window_by_name.get("*status*")
                    if status_win:
                        for item in new_items:
                            status_win.add_line(
                                f"-!- RSS [{item['feed']}]: {item['title']} - {item['link']}")
                        self._chat_dirty = True
                        self.dirty = True
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    def apply_theme(self, n: int, announce: bool = True) -> None:
        """Switch to theme n (1-based). Re-initialises the four key color pairs
        and forces a full redraw.  Color pair integers are live — no need to
        recompute _attr_* fields; the terminal picks up the new palette instantly."""
        idx = max(0, min(n - 1, len(THEMES) - 1))
        name, p1f, p1b, p2f, p2b, p3f, p3b, p8f, p8b = THEMES[idx]
        curses.init_pair(1, p1f, p1b)
        curses.init_pair(2, p2f, p2b)
        curses.init_pair(3, p3f, p3b)
        curses.init_pair(8, p8f, p8b)
        # Recompute attrs that bake in color_pair values so the change propagates
        self._attr_action     = curses.color_pair(8) | self._A_ITALIC
        self._attr_title      = curses.A_REVERSE | curses.color_pair(1)
        self._attr_userheader = curses.A_REVERSE | curses.color_pair(2)
        self._attr_suspect    = curses.A_BOLD    | curses.color_pair(3)
        self.current_theme = idx + 1
        self._chat_dirty = self._userlist_dirty = self._input_dirty = True
        self.dirty = True
        if announce:
            theme_list = "  ".join(
                f"[{i+1}] {t[0]}" for i, t in enumerate(THEMES))
            self.window_by_name["*status*"].add_line(
                f"Theme → {name} ({self.current_theme}/{len(THEMES)})  {theme_list}")

    def _resize_windows(self) -> None:
        """Resize/reposition subwindows and refresh cached dimensions."""
        if self._show_userlist:
            chat_w = max(1, self.width - self.userlist_width)
        else:
            chat_w = max(1, self.width)
        user_x = self.width - self.userlist_width
        try:
            self.chat_win.resize(self.chat_height, chat_w)
        except curses.error:
            pass
        try:
            self.user_win.resize(self.chat_height, self.userlist_width)
            self.user_win.mvwin(0, user_x)
        except curses.error:
            pass
        try:
            self.input_win.resize(4, self.width)
            self.input_win.mvwin(self.height - 4, 0)
        except curses.error:
            pass
        # Refresh cached dimension values and force full repaint.
        # Use the expected logical width (not getmaxyx) so a silently-failed
        # resize can't leave _tw pointing at the old oversized chat window.
        self._tw             = max(1, chat_w - 1)
        self._uw             = max(1, self.userlist_width - 2)
        self._input_w        = max(1, self.input_win.getmaxyx()[1] - 4)
        self._content_height = max(1, self.chat_height - 1)
        self._chat_dirty = self._userlist_dirty = self._input_dirty = True

    def _render_irc_line(self, row: int, line: str, base_attr: int, tw: int) -> None:
        """Write *line* to chat_win at *row*, applying IRC inline formatting.
        *col* tracks terminal columns, not character count, so wide (CJK) chars
        advance by 2 and are never truncated mid-character."""
        segments = irc_parse_formatting(line)
        col = 0
        for text, fmt_attr in segments:
            if col >= tw:
                break
            chunk = _truncate_to_width(text, tw - col)
            if not chunk:
                continue
            try:
                self.chat_win.addstr(row, col, chunk, base_attr | fmt_attr)
            except curses.error:
                pass
            col += _str_visual_width(chunk)

    def _draw_chat(self) -> None:
        tw = self._tw
        current_win = self.get_current_window()
        self.chat_win.erase()
        self._wrap_window(current_win)
        wrapped = current_win.wrapped_cache
        total = len(wrapped)

        # Row 0 is permanently the title bar; content occupies rows 1..chat_height-1.
        content_height = self._content_height

        # IRCv3 typing: expire stale entries then check if any peers are typing here.
        _now_m = time.monotonic()
        _tgt_key = current_win.name.lower()
        _peers = self._typing_peers.get(_tgt_key)
        if _peers:
            _stale = [_n for _n, _e in _peers.items() if _now_m > _e[2]]
            for _n in _stale:
                del _peers[_n]
        _typing_names = [_e[0] for _e in _peers.values()] if _peers else []
        if _typing_names:
            content_height = max(1, content_height - 1)  # reserve bottom row for indicator

        max_offset = max(0, total - content_height)
        current_win.scroll_offset = min(current_win.scroll_offset, max_offset)
        offset = current_win.scroll_offset

        end_idx   = total - offset
        start_idx = max(0, end_idx - content_height)
        visible   = wrapped[start_idx:end_idx]

        suspect_nicks = self._suspect_nicks
        attr_bold    = self._attr_bold
        attr_normal  = self._attr_normal
        attr_action  = self._attr_action
        attr_mention = self._attr_mention
        attr_url     = self._attr_url
        url_map      = current_win.url_map
        # Rebuild suspect regex only when the set has changed (not every frame)
        if suspect_nicks != self._suspect_re_nicks:
            self._suspect_re = (
                re.compile("|".join(re.escape(n) for n in suspect_nicks))
                if suspect_nicks else None
            )
            self._suspect_re_nicks = frozenset(suspect_nicks)
        _suspect_re = self._suspect_re
        # Rebuild mention regex only when our nick changes
        _our_nick = self._active_client().nick
        if _our_nick != self._mention_re_nick:
            self._mention_re = (
                re.compile(
                    r'\[\d{2}:\d{2}\] (?:<[^>]+>|\* \S+) .*\b'
                    + re.escape(_our_nick) + r'\b',
                    re.IGNORECASE,
                )
                if _our_nick else None
            )
            self._mention_re_nick = _our_nick

        # Bind hot callables to locals — avoids repeated global/attr lookups
        # inside the per-line render loop (called up to ~60 times per frame).
        _action_match    = _ACTION_LINE_RE.match
        _render          = self._render_irc_line
        _suspect_search  = _suspect_re.search if _suspect_re else None
        _mention_search  = self._mention_re.search if self._mention_re else None
        _content_height  = content_height

        for i, line in enumerate(visible):
            if i >= _content_height: break
            if (start_idx + i) in url_map:
                base = attr_url
            elif _action_match(line):
                base = attr_action
            elif _mention_search and _mention_search(line):
                base = attr_mention
            elif _suspect_search and _suspect_search(line):
                base = attr_bold
            else:
                base = attr_normal
            _render(i + 1, line, base, tw)  # +1: row 0 is reserved for the title bar

        # Typing indicator — drawn on the row just below the last message row.
        if _typing_names:
            if len(_typing_names) == 1:
                _typ_text = f" ✎ {_typing_names[0]} is typing…"
            elif len(_typing_names) == 2:
                _typ_text = f" ✎ {_typing_names[0]} and {_typing_names[1]} are typing…"
            else:
                _typ_text = f" ✎ {len(_typing_names)} people are typing…"
            try:
                self.chat_win.addstr(content_height + 1, 1,
                                     _typ_text[:tw], curses.A_DIM)
            except curses.error:
                pass

        title = (f" {current_win.name} [↑ {offset} line{'s' if offset != 1 else ''}] "
                 if offset > 0 else f" {current_win.name} ")
        try:
            self.chat_win.addstr(0, 0, title.center(tw)[:tw], self._attr_title)
        except curses.error:
            pass

    def _draw_userlist(self) -> None:
        uw = self._uw
        self.user_win.erase()
        self.user_win.border()

        # Prefer the current window's channel; fall back to current_channel for
        # non-channel windows (status/dashboard) so the userlist stays populated
        # while browsing those windows.  DM windows (no leading #) are excluded.
        cur_win = self.get_current_window()
        if cur_win.is_channel and cur_win.name in self.channel_users:
            display_ch = cur_win.name
        elif self.current_channel and self.current_channel in self.channel_users:
            display_ch = self.current_channel
        else:
            display_ch = None

        # Enhanced header with user count and suspect count
        if display_ch:
            ch_users = self.channel_users.get(display_ch, set())
            suspect_count = len(ch_users & self._suspect_nicks)
            header = f" Users ({display_ch}) "
            if suspect_count > 0:
                header += f"[{suspect_count}S]"
        else:
            header = f" Users (None) "
        try:
            self.user_win.addstr(0, 1, header[:uw], self._attr_userheader)
        except curses.error:
            pass

        if display_ch:
            ch = display_ch
            if ch not in self._sorted_users:
                self._sorted_users[ch] = self._sort_users_by_mode(ch)
            users = self._sorted_users[ch]
            modes = self.channel_user_modes.get(ch, {})
            thresh      = self.ai_suspect_threshold
            attr_sus    = self._attr_suspect
            attr_normal = self._attr_normal
            client = self._active_client()
            confirmed_bots = client.scoring.confirmed_bot_nicks if hasattr(client, 'scoring') else set()

            for i, nick in enumerate(users[:self.chat_height - 2]):
                ai_pct = self.user_ai_scores.get(nick, 0)
                mode_char = self._highest_prefix(modes.get(nick, set()))
                oper_mark = "◈" if nick.lower() in self._ircop_nicks else ""

                # Build status indicators
                status_marks = ""
                if nick.lower() in confirmed_bots:
                    status_marks += "B"
                elif ai_pct >= thresh:
                    status_marks += "S"
                elif ai_pct >= 50:
                    status_marks += "?"

                display_nick = (mode_char + oper_mark + nick) if (mode_char or oper_mark) else nick
                nick_vis = _str_visual_width(display_nick)

                # Compact format: show AI score as single digit bar for space efficiency
                # [0-9]: 0-9%, 10-19%, ..., 90-99%, 100%
                ai_bar = min(9, ai_pct // 10)
                ai_display = f"{ai_bar}"

                # Calculate available width for nick
                status_width = len(status_marks) + 1 if status_marks else 0
                ai_width = 2  # " N" format
                max_nick_width = uw - 4 - status_width - ai_width  # 4 for borders and spacing

                if nick_vis > max_nick_width:
                    display_nick = _truncate_to_width(display_nick, max_nick_width)
                    nick_vis = max_nick_width

                padded = display_nick + " " * max(0, max_nick_width - nick_vis)
                line = f"{padded}"
                if status_marks:
                    line += f" {status_marks}"
                line += f" {ai_display}"

                try:
                    if ai_pct >= thresh:
                        self.user_win.addstr(i + 1, 1, line[:uw], attr_sus)
                    else:
                        self.user_win.addstr(i + 1, 1, line[:uw], attr_normal)
                except curses.error:
                    break

    def _handle_tab_click(self, mx: int) -> None:
        """Switch to the window whose tab label was clicked."""
        _, w = self.input_win.getmaxyx()
        usable = w - 2

        multi_server = len(self.servers) > 1
        labels: List[str] = []
        for i, win in enumerate(self.windows):
            name = win.name
            if name == "*status*":
                short = "status"
            elif name == "*dashboard*":
                short = "dash"
            elif name.startswith("#"):
                short = name[:14]
            else:
                short = f">{name[:10]}"
            if multi_server and win.server_id and win.server_id != self._primary_server_id:
                host = win.server_id.split(":")[0]
                short = f"{host[:8]}:{short}"
            is_active = (i == self.current_window_index)
            has_unread = (name in self._unread_windows and not is_active)
            labels.append(f"[{'*' if has_unread else ''}{i + 1}:{short}]")

        widths = [len(l) + 1 for l in labels]
        active = self.current_window_index
        start = 0
        if sum(widths) > usable:
            for j in range(active + 1):
                if sum(widths[j:active + 1]) <= usable:
                    start = j
                    break

        col = 1
        for i in range(start, len(labels)):
            label = labels[i]
            lw = len(label)
            if col + lw + 1 > usable:
                break
            if col <= mx < col + lw:
                # Reset dashboard state when navigating away
                prev_win = self.get_current_window()
                if prev_win.name == "*dashboard*":
                    self._dashboard_mode = "suspects"
                    self._dashboard_profile_locked = False
                self.current_window_index = i
                win = self.windows[i]
                # Reset dashboard state when navigating TO it
                if win.name == "*dashboard*":
                    self._dashboard_mode = "suspects"
                    self._dashboard_profile_locked = False
                    self._dashboard_dirty = True
                    self._dashboard_last_update = 0.0
                self.current_channel = None
                self._chat_dirty = self._userlist_dirty = self._input_dirty = True
                self.dirty = True
                return
            col += lw + 1

    def _draw_tabs(self) -> None:
        """Draw the window tab strip on row 1 of input_win.

        Format: [1:status] [*2:##chat] [3:##anime]
        Active tab uses A_REVERSE|A_BOLD; windows with unread messages get A_BOLD
        and a '*' prefix; inactive read windows are dimmed.  The strip scrolls so
        the active tab is always visible.

        Enhanced: shows unread counts (>9 as +), suspect indicators (S), and
        highlights/mentions (H) for channels.
        """
        _, w = self.input_win.getmaxyx()
        usable = w - 2  # columns between left and right borders

        # Build label strings for every window
        multi_server = len(self.servers) > 1
        labels: List[str] = []
        indicators: List[str] = []
        for i, win in enumerate(self.windows):
            name = win.name
            if name == "*status*":
                short = "status"
            elif name == "*dashboard*":
                short = "dash"
            elif name.startswith("#"):
                short = name[:14]
            else:
                short = f">{name[:10]}"   # DM: ">nick"
            # Prepend a short server tag when multiple servers are connected
            if multi_server and win.server_id and win.server_id != self._primary_server_id:
                host = win.server_id.split(":")[0]
                short = f"{host[:8]}:{short}"
            is_active = (i == self.current_window_index)
            has_unread = (name in self._unread_windows and not is_active)

            # Build indicator string
            indicator = ""
            if has_unread:
                # Count unread lines
                unread_count = len(win.lines) - win._unread_from if win._unread_from >= 0 else len(win.lines)
                if unread_count > 99:
                    indicator = "+"
                elif unread_count > 1:
                    indicator = str(unread_count)
                else:
                    indicator = "*"

                # Check for suspects in this channel
                if name.startswith("#"):
                    ch_users = self.channel_users.get(name, set())
                    suspect_in_ch = bool(ch_users & self._suspect_nicks)
                    if suspect_in_ch:
                        indicator += "S"
            labels.append(f"[{indicator if indicator else ''}{i + 1}:{short}]")
            indicators.append(indicator)

        # Find the leftmost visible index so the active tab is always on screen
        widths = [len(l) + 1 for l in labels]   # +1 for the space separator
        active = self.current_window_index
        start = 0
        if sum(widths) > usable:
            # Walk forward until the slice [start..active] fits
            for j in range(active + 1):
                if sum(widths[j:active + 1]) <= usable:
                    start = j
                    break

        col = 1
        for i in range(start, len(labels)):
            label = labels[i]
            lw = len(label)
            if col + lw + 1 > usable:
                break
            is_active = (i == self.current_window_index)
            has_unread = (self.windows[i].name in self._unread_windows and not is_active)
            has_suspect = False
            if self.windows[i].name.startswith("#"):
                ch_users = self.channel_users.get(self.windows[i].name, set())
                has_suspect = bool(ch_users & self._suspect_nicks)

            if is_active:
                attr = curses.A_REVERSE | curses.A_BOLD
            elif has_suspect:
                attr = curses.A_BOLD | curses.color_pair(3)
            elif has_unread:
                attr = curses.A_BOLD
            else:
                attr = curses.A_DIM
            try:
                self.input_win.addstr(1, col, label, attr)
            except curses.error:
                pass
            col += lw + 1   # +1 space between tabs

    def _draw_input(self) -> None:
        self.input_win.erase()
        self.input_win.border()

        # BNC indicator in top-right corner of the border
        if self._bouncer_detached and self._bouncer_enabled:
            try:
                _, w = self.input_win.getmaxyx()
                buf_count = self._bouncer_buffer.count
                hl_count = self._bouncer_buffer.highlight_count
                indicator = f"[BNC:{buf_count}]"
                if hl_count > 0:
                    indicator = f"[BNC:{buf_count}*{hl_count}]"
                self.input_win.addstr(0, max(2, w - len(indicator) - 2), indicator, curses.A_BOLD | curses.color_pair(3))
            except curses.error:
                pass

        self._draw_tabs()

        # Show current send-target in the prompt so the user always knows where
        # text will go.  Status/dashboard windows have no chat target.
        cur_win = self.get_current_window()
        _cur_nick = self._active_client().nick
        oper_indicator = "◈" if "o" in self._own_umodes else ""
        if cur_win.name not in ("*status*", "*dashboard*"):
            prompt = f"[{cur_win.name}] {oper_indicator}{_cur_nick}> "
        else:
            prompt = f"{oper_indicator}{_cur_nick}> "
        iw     = self._input_w

        # All width calculations use visual column counts (not character counts)
        # so that IRC control codes (zero-width) and CJK/wide chars (2 columns)
        # both position the cursor and viewport correctly.
        vis_prompt = prompt                        # prompt is ASCII-only
        vis_buf    = irc_strip_formatting(self.input_buffer)
        vis_before = irc_strip_formatting(self.input_buffer[:self.input_cursor]) \
                     if self.input_cursor else ""
        cursor_abs  = _str_visual_width(vis_prompt) + _str_visual_width(vis_before)

        full_vis    = vis_prompt + vis_buf
        full_vis_w  = _str_visual_width(full_vis)
        view_start  = max(0, cursor_abs - iw + 1) if cursor_abs >= iw else 0
        if full_vis_w > iw:
            view_start = min(view_start, full_vis_w - iw)

        display    = _truncate_to_width(_skip_visual_cols(full_vis, view_start), iw)
        cursor_col = 1 + (cursor_abs - view_start)
        try:
            self.input_win.addstr(2, 1, display)
            self.input_win.move(2, max(1, min(cursor_col, iw)))
        except curses.error:
            pass

    def redraw(self) -> bool:
        if time.monotonic() - self.last_redraw < 0.033:
            return False
        self.last_redraw = time.monotonic()

        new_h, new_w = self.stdscr.getmaxyx()
        if new_h != self.height or new_w != self.width:
            self.height, self.width = new_h, new_w
            self.chat_height = max(1, self.height - 4)
            self._resize_windows()  # sets all three pane-dirty flags + updates _tw/_uw/_input_w

        # Sync aliases to the server that owns the currently visible window.
        self._sync_draw_ctx()

        refreshed = []
        _chat_refreshed = False
        if self._chat_dirty:
            self._draw_chat()
            self._chat_dirty = False
            refreshed.append(self.chat_win)
            _chat_refreshed = True
        if self._userlist_dirty:
            if self._show_userlist:
                self._draw_userlist()
                refreshed.append(self.user_win)
            self._userlist_dirty = False
        elif self._show_userlist and _chat_refreshed:
            # Re-assert the userlist after every chat refresh even when the
            # userlist itself hasn't changed.  chat_win.noutrefresh() writes the
            # full chat buffer (including the blank right-margin column) to the
            # virtual screen.  If the window was ever the wrong size (e.g. a
            # silently-failed resize) those writes can land on top of the |
            # border.  Calling user_win.noutrefresh() second means the userlist
            # always wins that region, keeping the border and nicks intact.
            refreshed.append(self.user_win)
        if self._input_dirty:
            self._draw_input()
            self._input_dirty = False
            refreshed.append(self.input_win)

        for w in refreshed:
            w.noutrefresh()
        if refreshed:
            curses.doupdate()
        return True

    def get_current_window(self) -> ChatWindow:
        return self.windows[self.current_window_index]

    def _mark_window_read(self, win: "ChatWindow") -> None:
        """Send MARKREAD for *win* and clear its unread marker."""
        if win.name in ("*status*", "*dashboard*") or not win.is_channel:
            return
        client = self._active_client()
        if "read-marker" not in client._active_caps:
            return
        from datetime import datetime, timezone
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")
        client.send_raw(f"MARKREAD {win.name} timestamp={ts}")
        win._unread_from = -1
        win._wrap_dirty = True

    def switch_to_next_window(self):
        prev_win = self.get_current_window()
        self._mark_window_read(prev_win)
        # Reset dashboard state when navigating away
        if prev_win.name == "*dashboard*":
            self._dashboard_mode = "suspects"
            self._dashboard_profile_locked = False
        self.current_window_index = (self.current_window_index + 1) % len(self.windows)
        win = self.get_current_window()
        # Reset dashboard state when navigating TO it
        if win.name == "*dashboard*":
            self._dashboard_mode = "suspects"
            self._dashboard_profile_locked = False
            self._dashboard_dirty = True
            self._dashboard_last_update = 0.0
        if win.name not in ("*status*", "*dashboard*"):
            self.current_channel = win.name
        if win.name in self._unread_windows:
            win.scroll_offset = 0  # jump to bottom so the new messages are visible
        self._unread_windows.discard(win.name)
        win._unread_from = -1
        self._chat_dirty = self._userlist_dirty = self._input_dirty = True
        self.dirty = True

    @staticmethod
    def _prefix_rank(mode_char: str) -> int:
        return {"~": 5, "&": 4, "@": 3, "%": 2, "+": 1}.get(mode_char, 0)

    @staticmethod
    def _highest_prefix(modes: set) -> str:
        mode_to_prefix = {"q": "~", "a": "&", "o": "@", "h": "%", "v": "+"}
        order = ["q", "a", "o", "h", "v"]
        for m in order:
            if m in modes:
                return mode_to_prefix[m]
        return ""

    def _sort_users_by_mode(self, ch: str) -> List[str]:
        modes = self.channel_user_modes.get(ch, {})
        users = self.channel_users.get(ch, set())
        return sorted(users, key=lambda n: (-self._prefix_rank(self._highest_prefix(modes.get(n, set()))), n.lower()))

    def do_nick_complete(self, reverse: bool = False) -> None:
        if not self.current_channel or self.current_channel not in self.channel_users:
            return
        ch = self.current_channel
        if ch not in self._sorted_users:
            self._sorted_users[ch] = self._sort_users_by_mode(ch)
        users = self._sorted_users[ch]
        if not users:
            return
        buf    = self.input_buffer
        cursor = min(self.input_cursor, len(buf))
        word_start = cursor
        while word_start > 0 and buf[word_start - 1] not in (" ", "\t"):
            word_start -= 1
        prefix = buf[word_start:cursor].lower()
        if not prefix:
            return
        matches = [u for u in users if u.lower().startswith(prefix)]
        if not matches:
            return
        if self.completion_state and self.completion_state[0] == prefix:
            if reverse:
                idx = (self.completion_state[2] - 1) % len(self.completion_state[1])
            else:
                idx = (self.completion_state[2] + 1) % len(self.completion_state[1])
            match = self.completion_state[1][idx]
        else:
            idx = len(matches) - 1 if reverse else 0
            match = matches[idx]
        self.completion_state = (prefix, matches, idx)
        suffix = ": " if word_start == 0 else " "
        replacement = match + suffix
        self.input_buffer = buf[:word_start] + replacement + buf[cursor:]
        self.input_cursor = word_start + len(replacement)
        self._input_dirty = True
        self.dirty = True

    def do_command_complete(self, reverse: bool = False) -> None:
        """Complete slash command names when input starts with '/'."""
        buf = self.input_buffer
        cursor = min(self.input_cursor, len(buf))
        if not buf.startswith("/"):
            return

        # Extract partial command (after /, up to cursor, no spaces)
        partial = buf[1:cursor].lower()
        if " " in partial:
            return  # Already typed a full command with args

        # Gather all available commands
        builtins = sorted(self._slash_handlers.keys())
        plugin_cmds = sorted(self.plugin_manager._commands.keys())
        script_cmds = sorted(self.script_engine._commands.keys())
        aliases = sorted(k for k in self._aliases.keys() if k not in self._slash_handlers)

        # Combine and deduplicate
        all_cmds = sorted(set(builtins + plugin_cmds + script_cmds + aliases))
        if not all_cmds:
            return

        matches = [c for c in all_cmds if c.startswith(partial)]
        if not matches:
            return

        # Completion state for cycling through matches
        state_prefix = "/" + partial
        if self.completion_state and self.completion_state[0] == state_prefix:
            if reverse:
                idx = (self.completion_state[2] - 1) % len(self.completion_state[1])
            else:
                idx = (self.completion_state[2] + 1) % len(self.completion_state[1])
            match = self.completion_state[1][idx]
        else:
            idx = len(matches) - 1 if reverse else 0
            match = matches[idx]

        self.completion_state = (state_prefix, matches, idx)
        replacement = "/" + match + " "
        self.input_buffer = replacement + buf[cursor:]
        self.input_cursor = len(replacement)
        self._input_dirty = True
        self.dirty = True

    def _build_event_handlers(self) -> None:
        h = self._event_handlers
        h["msg"]         = self._ev_msg
        h["ai_score"]    = self._ev_ai_score
        h["notice"]      = self._ev_notice
        h["nick_change"] = self._ev_nick_change
        h["names"]       = self._ev_names
        h["clear_users"] = self._ev_clear_users
        h["topic"]       = self._ev_topic
        h["join"]        = self._ev_join
        h["self_join"]   = self._ev_self_join
        h["join_error"]  = self._ev_join_error
        h["part"]        = self._ev_part
        h["quit"]        = self._ev_quit
        h["typing"]      = self._ev_typing
        h["react"]       = self._ev_react
        h["redact"]      = self._ev_redact
        h["markread"]    = self._ev_markread
        h["mode"]        = self._ev_mode
        h["kick"]        = self._ev_kick
        h["own_umodes"]  = self._ev_own_umodes
        h["ircop_status"] = self._ev_ircop_status
        h["list_results"]  = self._ev_list_results
        h["chanmode"]      = self._ev_chanmode
        h["resumed"]       = self._ev_resumed
        h["banlist"]       = self._ev_banlist
        h["dcc_progress"]  = self._ev_dcc_progress
        h["dcc_offer"]     = self._ev_dcc_offer
        h["dcc_resume_req"] = self._ev_dcc_resume_req
        h["dcc_resume_ack"] = self._ev_dcc_resume_ack
        h["dcc_chat_offer"]  = self._ev_dcc_chat_offer
        h["dcc_chat_msg"]    = self._ev_dcc_chat_msg
        h["dcc_chat_closed"] = self._ev_dcc_chat_closed
        h["channel_rename"]  = self._ev_channel_rename
        for k in ("whois", "status"):
            h[k] = self._ev_status_line

    async def handle_event(self, event: tuple) -> None:
        if not event:
            return
        # "_srv" events arrive from secondary servers via _mux_server_events.
        # Unwrap, sync aliases to that server's dicts, dispatch, then restore.
        if event[0] == "_srv":
            _, server_id, inner = event
            prev = self._active_server_id
            self._sync_ctx(server_id)
            try:
                await self.handle_event(inner)
            finally:
                self._sync_ctx(prev)
            return
        # Untagged events come from the primary server; ensure aliases are correct.
        self._sync_ctx(self._primary_server_id)
        handler = self._event_handlers.get(event[0])
        if handler:
            await handler(event)

    # ── TUI event handlers ────────────────────────────────────────────────────

    async def _ev_msg(self, event):
        # Unpack with defaults for the optional tail fields added for IRCv3
        (_, nick, target, msg, u_score, m_score, a_score, rolling_ai,
         is_action, *_extra) = event
        ts_str    = _extra[0] if len(_extra) > 0 else None
        account   = _extra[1] if len(_extra) > 1 else ""
        is_replay = _extra[2] if len(_extra) > 2 else False
        msgid     = _extra[3] if len(_extra) > 3 else ""
        reply_to  = _extra[4] if len(_extra) > 4 else ""
        mention   = _extra[5] if len(_extra) > 5 else ""
        intent    = _extra[6] if len(_extra) > 6 else ""
        if self._is_ignored(nick):
            return
        if target.startswith("#"):
            win_name = target
            is_chan   = True
        elif nick == self._active_client().nick:
            win_name = target
            is_chan   = False
        else:
            win_name = nick
            is_chan   = False
        win = self.ensure_window(win_name, is_channel=is_chan)
        # read-marker: mark the first unread line when this window is not active
        if not is_replay and win is not self.get_current_window() and win._unread_from < 0:
            win._unread_from = len(win.lines)  # points to the line about to be added
        # +reply: show a quoted preview of the referenced message
        if reply_to:
            ref = win._msg_store.get(reply_to)
            if ref:
                ref_nick, ref_prev = ref
                p = ref_prev[:50] + "…" if len(ref_prev) > 50 else ref_prev
                win.add_line(f"  ↩ {ref_nick}: {p}", timestamp=False)
        prefix_str = f"* {nick} " if is_action else f"<{nick}> "
        if nick.lower() in self._ircop_nicks:
            prefix_str = "◈" + prefix_str
        # Replay lines get a visual marker; account shown if account-tag active
        replay_mark = "[↑] " if is_replay else ""
        acc_mark    = f"[{account}]" if account else ""
        win.add_line(f"{replay_mark}{prefix_str}{acc_mark}{msg}", ts_str=ts_str, msgid=msgid)
        # Store msgid for reply/react lookups; prune if over limit
        if msgid:
            if len(win._msg_store) >= 500:
                del win._msg_store[next(iter(win._msg_store))]
            preview = f"* {nick} {msg}" if is_action else msg
            win._msg_store[msgid] = (nick, preview)
            win._last_msgid = msgid
        our_nick = self._active_client().nick
        is_mention = bool(mention) or (
            our_nick and nick.lower() != our_nick.lower()
            and re.search(r'\b' + re.escape(our_nick) + r'\b', msg, re.IGNORECASE))
        if is_mention and not self.mention_beep_muted:
            try:
                curses.beep()
            except Exception:
                pass
        if self.auto_translate and _has_cjk(irc_strip_formatting(msg)):
            asyncio.create_task(self._post_translation(win, msg))
        if self.link_preview_enabled and _URL_RE.search(irc_strip_formatting(msg)):
            asyncio.create_task(self._post_link_info(win, nick, msg, win_name))
        # Investigative tracking
        hour = time.localtime().tm_hour
        self._msg_hours.setdefault(nick, []).append(hour)
        if target.startswith("#"):
            prev = self._last_speaker.get(target)
            if prev and prev != nick:
                self._adjacency.setdefault(nick, Counter())[prev] += 1
                self._adjacency.setdefault(prev, Counter())[nick] += 1
            self._last_speaker[target] = nick
            self._ch_activity.setdefault(nick, Counter())[target] += 1
        # Targeting: detect "nick:" or "nick," at message start
        clean = msg.lstrip()
        if clean:
            comma = clean.find(",")
            colon = clean.find(":")
            end = min(comma, colon) if comma >= 0 and colon >= 0 else max(comma, colon)
            if end > 0:
                maybe = clean[:end].lower()
                if maybe and maybe != nick.lower():
                    self._targets.setdefault(nick, Counter())[maybe] += 1
        self.user_scores[nick] = u_score
        self.user_ai_scores[nick] = rolling_ai

        # ── New AI/ML pipeline ──────────────────────────────────────────────
        if not is_replay and hasattr(self._active_client(), 'scoring'):
            scoring = self._active_client().scoring
            # Sentiment analysis
            scoring.analyze_sentiment(nick, msg)
            # Topic detection
            scoring.topics.detect(msg)
            # Semantic similarity tracking
            scoring.semantic.add_message(nick, msg, target)
            # Thread tracking
            scoring.threads.add_message(msgid, nick, target, msg, reply_to=reply_to)
            # Cross-channel bot detection
            if target.startswith("#"):
                scoring.cross_channel.record_message(nick, target, msg)
            # Productivity: channel stats tracking
            if target.startswith("#"):
                scoring.channel_stats.record_message(nick, target, msg)
            # Productivity: nick watch checks
            triggered = scoring.watches.check_event("speak", nick, target)
            if mention:
                triggered += scoring.watches.check_event("mention", nick, target)
            for tw in triggered:
                alert = tw.get("message") or f"{nick} triggered a watch"
                await self.ui_queue.put(("status", f"[watch] {alert}"))

        # /seen tracking
        nick_lower = nick.lower()
        msg_preview = (msg[:80] + "\u2026") if len(msg) > 80 else msg
        self._seen_times[nick_lower] = (time.time(), msg_preview, target)

        # /tell delivery
        if nick_lower in self._tell_queue and self._tell_queue[nick_lower]:
            pending = self._tell_queue.pop(nick_lower)
            _tell_sw = self.window_by_name.get("*status*")
            if _tell_sw:
                for _from, _tell_msg, _ts in pending:
                    _tell_sw.add_line(
                        f"-!- Tell from {_from} ({time.strftime('%H:%M', time.localtime(_ts))}): "
                        f"{_tell_msg}")
                self._chat_dirty = True

        if win is not self.get_current_window():
            self._unread_windows.add(win_name)
            self._input_dirty = True
            if not target.startswith("#") and nick != self._active_client().nick:
                preview = (msg[:40] + "...") if len(msg) > 40 else msg
                self.get_current_window().add_line(
                    f"-!- PM from {nick}: {preview}  [/win {self.windows.index(win) + 1}]")
        if rolling_ai >= self.ai_suspect_threshold:
            self._suspect_nicks.add(nick)
            self._dashboard_dirty = True
        else:
            self._suspect_nicks.discard(nick)
        if win_name in self.channel_users and nick not in self.channel_users[win_name]:
            self.channel_users[win_name].add(nick)
            self._sorted_users.pop(win_name, None)
            self._userlist_dirty = True
        # A sent message implicitly clears any typing indicator for that nick.
        tgt_peers = self._typing_peers.get(win_name.lower(), {})
        if tgt_peers.pop(nick.lower(), None) is not None:
            pass  # _chat_dirty already set below
        self._chat_dirty = True
        self.dirty = True
        await self.plugin_manager.dispatch("on_message", nick=nick, target=target,
                                           msg=msg, is_action=is_action, is_replay=is_replay)
        await self.script_engine.dispatch("on_message", nick=nick, target=target,
                                          msg=msg, is_action=is_action, is_replay=is_replay)

    async def _ev_typing(self, event):
        _, nick, target, state = event
        tgt = target.lower()
        nick_l = nick.lower()
        peers = self._typing_peers.setdefault(tgt, {})
        if state == "done":
            peers.pop(nick_l, None)
        else:
            expiry = time.monotonic() + (6.0 if state == "active" else 30.0)
            peers[nick_l] = [nick, state, expiry]
        if tgt == self.get_current_window().name.lower():
            self._chat_dirty = True
            self.dirty = True
        await self.plugin_manager.dispatch("on_typing", nick=nick, target=target, state=state)
        if tgt == self.get_current_window().name.lower():
            self._chat_dirty = True
            self.dirty = True

    async def _ev_react(self, event):
        _, nick, target, msgid, emoji = event
        win_name = target if target.startswith("#") else nick
        wk = self._wk(self._active_server_id, win_name)
        win = self.window_by_name.get(wk)
        if win is None:
            return
        nicks = win._reactions.setdefault(msgid, {}).setdefault(emoji, [])
        if nick not in nicks:
            nicks.append(nick)
        win._wrap_dirty = True
        if win is self.get_current_window():
            self._chat_dirty = True
            self.dirty = True
        await self.plugin_manager.dispatch("on_react", nick=nick, target=target, msgid=msgid, emoji=emoji)

    async def _ev_redact(self, event):
        _, nick, target, msgid, reason = event
        win_name = target if target.startswith("#") else nick
        wk = self._wk(self._active_server_id, win_name)
        win = self.window_by_name.get(wk)
        if win is None:
            return
        for i, mid in enumerate(win._line_msgids):
            if mid == msgid:
                old_line = win.lines[i]
                ts_prefix = old_line[:8] if old_line.startswith("[") and len(old_line) >= 8 else ""
                reason_str = f": {reason}" if reason else ""
                win.lines[i] = f"{ts_prefix} [redacted by {nick}{reason_str}]"
                win._wrap_dirty = True
                break
        if win is self.get_current_window():
            self._chat_dirty = True
            self.dirty = True

    async def _ev_markread(self, event):
        _, target, ts_arg = event
        wk = self._wk(self._active_server_id, target)
        win = self.window_by_name.get(wk)
        if win is None:
            return
        if not ts_arg.startswith("timestamp="):
            return
        ts_iso = ts_arg[len("timestamp="):]
        marker_time = _parse_server_time(ts_iso)  # returns "[HH:MM]" or None
        if not marker_time:
            return
        # Find index of the first line whose timestamp is after the marker
        unread_from = -1
        for i, line in enumerate(win.lines):
            if line.startswith("[") and len(line) >= 7 and line[6] == "]":
                if line[:7] > marker_time:
                    unread_from = i
                    break
        win._unread_from = unread_from
        win._wrap_dirty = True
        if win is self.get_current_window():
            self._chat_dirty = True
            self.dirty = True

    async def _ev_ai_score(self, event):
        _, nick, rolling_ai, styl_score = event if len(event) > 3 else (event[0], event[1], event[2], 0.0)
        old_score = self.user_ai_scores.get(nick)
        self.user_ai_scores[nick] = rolling_ai
        self._recent_styl_scores[nick] = styl_score
        was_suspect = nick in self._suspect_nicks
        if rolling_ai >= self.ai_suspect_threshold:
            self._suspect_nicks.add(nick)
            self._dashboard_dirty = True
        else:
            self._suspect_nicks.discard(nick)
        is_suspect = nick in self._suspect_nicks
        if old_score != rolling_ai or was_suspect != is_suspect:
            self._userlist_dirty = True
            self.dirty = True
        if was_suspect != is_suspect:
            # Suspect set changed — chat must repaint to apply/remove bold highlighting
            self._chat_dirty = True
            self.dirty = True
        await self.plugin_manager.dispatch("on_ai_score", nick=nick, rolling_ai=rolling_ai, styl_score=styl_score)

    async def _ev_notice(self, event):
        _, sender, target, text = event
        if self._is_ignored(sender):
            return
        win = self.ensure_window(target, is_channel=target.startswith("#"))
        win.add_line(f"-{sender}- {text}")
        if win is not self.get_current_window():
            self._unread_windows.add(target)
            self._input_dirty = True
        self._chat_dirty = True
        self.dirty = True
        await self.plugin_manager.dispatch("on_notice", sender=sender, target=target, text=text)

    async def _ev_nick_change(self, event):
        _, old_nick, new_nick = event
        for ch, users in self.channel_users.items():
            if old_nick in users:
                users.discard(old_nick)
                users.add(new_nick)
                mode_set = self.channel_user_modes.get(ch, {}).pop(old_nick, None)
                if mode_set is not None:
                    self.channel_user_modes[ch][new_nick] = mode_set
        # Migrate investigative data
        for d in (self._msg_hours, self._adjacency, self._targets, self._ch_activity):
            if old_nick in d:
                d[new_nick] = d.pop(old_nick)
                self._sorted_users.pop(ch, None)
        if old_nick in self.user_scores:
            self.user_scores[new_nick] = self.user_scores.pop(old_nick)
        if old_nick in self.user_ai_scores:
            score = self.user_ai_scores.pop(old_nick)
            self.user_ai_scores[new_nick] = score
            self._suspect_nicks.discard(old_nick)
            if score >= self.ai_suspect_threshold:
                self._suspect_nicks.add(new_nick)
        if old_nick in self._recent_styl_scores:
            self._recent_styl_scores[new_nick] = self._recent_styl_scores.pop(old_nick)
        old_lower = old_nick.lower()
        new_lower = new_nick.lower()
        if old_lower in self._ircop_nicks:
            self._ircop_nicks.discard(old_lower)
            self._ircop_nicks.add(new_lower)
        self._status_win().add_line(f"* {old_nick} is now known as {new_nick}")
        self._chat_dirty = self._userlist_dirty = True
        self.dirty = True
        await self.plugin_manager.dispatch("on_nick_change", old_nick=old_nick, new_nick=new_nick)

    async def _ev_names(self, event):
        _, channel, names_raw = event
        if channel not in self.channel_users:
            self.channel_users[channel] = set()
            self.channel_user_modes[channel] = {}
        modes = self.channel_user_modes.setdefault(channel, {})
        _letter_by_prefix = {"~": "q", "&": "a", "@": "o", "%": "h", "+": "v"}
        for n in names_raw.split():
            mode_char = n[0] if n and n[0] in "~&@%+" else ""
            clean = n.lstrip("~&@%+")
            if clean:
                self.channel_users[channel].add(clean)
                modes[clean] = {_letter_by_prefix[mode_char]} if mode_char else set()
        self._sorted_users.pop(channel, None)
        self._userlist_dirty = True
        self.dirty = True

    async def _ev_clear_users(self, event):
        for users in self.channel_users.values():
            users.clear()
        for cm in self.channel_user_modes.values():
            cm.clear()
        self._sorted_users.clear()
        self._userlist_dirty = True
        self.dirty = True

    async def _ev_topic(self, event):
        _, channel, topic_text = event
        text = (f"* Topic for {channel}: {topic_text}"
                if topic_text else f"* No topic set for {channel}")
        win = self.ensure_window(channel)
        win.add_line(text)
        self._chat_dirty = True
        self.dirty = True
        await self.plugin_manager.dispatch("on_topic", channel=channel, topic=topic_text, setter_nick="")

    async def _ev_join(self, event):
        _, nick, channel = event
        win = self.ensure_window(channel)
        if nick == self._active_client().nick:
            self.channel_users[channel] = set()
            self.channel_user_modes[channel] = {}
            self._sorted_users.pop(channel, None)
        else:
            if channel in self.channel_users:
                self.channel_users[channel].add(nick)
                self.channel_user_modes.setdefault(channel, {})[nick] = set()
                self._sorted_users.pop(channel, None)
            mark = "◈" if nick.lower() in self._ircop_nicks else "*"
            win.add_line(f"{mark} {nick} has joined {channel}")
        self._chat_dirty = self._userlist_dirty = True
        self.dirty = True
        await self.plugin_manager.dispatch("on_join", nick=nick, channel=channel)
        await self.script_engine.dispatch("on_join", nick=nick, channel=channel)

    async def _ev_join_error(self, event):
        _, channel, msg = event
        win = self.ensure_window(channel)
        win.add_line(msg)
        self._chat_dirty = True
        self.dirty = True

    async def _ev_part(self, event):
        _, nick, channel = event
        reason = event[3] if len(event) > 3 else ""
        if channel in self.channel_users:
            self.channel_users[channel].discard(nick)
            self.channel_user_modes.get(channel, {}).pop(nick, None)
            self._sorted_users.pop(channel, None)
        win = self.ensure_window(channel)
        win.add_line(f"* {nick} has left {channel}" + (f" ({reason})" if reason else ""))
        if win is not self.get_current_window():
            self._unread_windows.add(channel)
            self._input_dirty = True
        self._chat_dirty = self._userlist_dirty = True
        self.dirty = True
        await self.plugin_manager.dispatch("on_part", nick=nick, channel=channel, reason=reason)

    async def _ev_quit(self, event):
        _, nick, reason = event
        mark = "◈" if nick.lower() in self._ircop_nicks else "*"
        quit_msg = f"{mark} {nick} has quit" + (f" ({reason})" if reason else "")
        for ch, users in self.channel_users.items():
            if nick in users:
                users.discard(nick)
                self.channel_user_modes.get(ch, {}).pop(nick, None)
                self._sorted_users.pop(ch, None)
                ch_win = self.window_by_name.get(self._wk(self._active_server_id, ch))
                if ch_win:
                    ch_win.add_line(quit_msg)
                    if ch_win is not self.get_current_window():
                        self._unread_windows.add(ch_win.name)
                        self._input_dirty = True
        self._suspect_nicks.discard(nick)
        self._ircop_nicks.discard(nick.lower())
        self.user_scores.pop(nick, None)
        self.user_ai_scores.pop(nick, None)
        self._chat_dirty = self._userlist_dirty = True
        self.dirty = True
        await self.plugin_manager.dispatch("on_quit", nick=nick, reason=reason)

    async def _ev_mode(self, event):
        _, nick, params = event
        if len(params) < 2:
            return
        target = params[0]
        if not target.startswith("#"):
            return
        modestr = params[1]
        mode_args = params[2:]
        modes = self.channel_user_modes.get(target)
        if modes is None:
            return
        adding = True
        arg_idx = 0
        for ch in modestr:
            if ch == "+":
                adding = True
            elif ch == "-":
                adding = False
            elif ch in self._PREFIX_BY_LETTER and arg_idx < len(mode_args):
                user = mode_args[arg_idx]
                uset = modes.setdefault(user, set())
                if adding:
                    uset.add(ch)
                else:
                    uset.discard(ch)
                arg_idx += 1
            elif ch in self._MODE_ARGS_CHARS:
                arg_idx += 1
        self._sorted_users.pop(target, None)
        self._userlist_dirty = True
        self.dirty = True
        await self.plugin_manager.dispatch("on_mode", target=target, modes=modestr, setter_nick=nick)

    async def _ev_channel_rename(self, event):
        _, old_ch, new_ch = event
        # Migrate channel state
        if old_ch in self.channel_users:
            self.channel_users[new_ch] = self.channel_users.pop(old_ch)
        if old_ch in self.channel_user_modes:
            self.channel_user_modes[new_ch] = self.channel_user_modes.pop(old_ch)
        if old_ch in self._sorted_users:
            self._sorted_users[new_ch] = self._sorted_users.pop(old_ch)
        # Rename window if it exists
        wk_old = self._wk(self._active_server_id, old_ch)
        win = self.window_by_name.get(wk_old)
        if win:
            win.name = new_ch
            self.window_by_name[self._wk(self._active_server_id, new_ch)] = win
            del self.window_by_name[wk_old]
        self._chat_dirty = self._userlist_dirty = True
        self.dirty = True

    async def _ev_kick(self, event):
        _, nick, channel, kicked, reason = event
        if channel in self.channel_users:
            self.channel_users[channel].discard(kicked)
            self.channel_user_modes.get(channel, {}).pop(kicked, None)
            self._sorted_users.pop(channel, None)
        self._suspect_nicks.discard(kicked)
        ch_win = self.window_by_name.get(self._wk(self._active_server_id, channel))
        if ch_win:
            msg = f"* {kicked} was kicked from {channel} by {nick}" + (f" ({reason})" if reason else "")
            ch_win.add_line(msg)
            if ch_win is not self.get_current_window():
                self._unread_windows.add(ch_win.name)
                self._input_dirty = True
        self._chat_dirty = self._userlist_dirty = True
        self.dirty = True
        await self.plugin_manager.dispatch("on_kick", channel=channel, nick=kicked, kicker=nick, reason=reason)

    async def _ev_own_umodes(self, event):
        self._own_umodes = event[1]
        self._userlist_dirty = True
        self.dirty = True

    async def _ev_ircop_status(self, event):
        _, nick, is_oper = event
        lower = nick.lower()
        if is_oper:
            self._ircop_nicks.add(lower)
        else:
            self._ircop_nicks.discard(lower)
        self._userlist_dirty = True
        self.dirty = True

    async def _ev_list_results(self, event):
        _, results = event
        self._cached_list_results = list(results)
        ch_count = len(results)
        sw = self._status_win()
        sw.add_line(f"── Channel list ({ch_count} channels) ──")
        limit = 500
        if ch_count <= limit:
            for ch, users, topic in results:
                short_topic = topic[:60] + "…" if len(topic) > 60 else topic
                sw.add_line(f"  {ch:<20} {users:>4}  {short_topic}")
        else:
            for ch, users, topic in results[:limit]:
                short_topic = topic[:60] + "…" if len(topic) > 60 else topic
                sw.add_line(f"  {ch:<20} {users:>4}  {short_topic}")
            sw.add_line(f"  ... ({ch_count - limit} more — use /lf <keyword> or /lf min=<n> to filter)")
        sw.add_line(f"── End of channel list ──")
        self._chat_dirty = True
        self.dirty = True

    async def _ev_self_join(self, event):
        _, channel = event
        if channel not in self.channel_users:
            self.channel_users[channel] = set()
            self.channel_user_modes[channel] = {}
        win = self.ensure_window(channel)
        win.add_line(f"* You have joined {channel}")
        self.current_channel = channel
        self.current_window_index = self.windows.index(win)
        self._unread_windows.discard(channel)
        # Fetch stored read marker from server if supported
        client = self._active_client()
        if "read-marker" in client._active_caps:
            client.send_raw(f"MARKREAD {channel} *")
        self._chat_dirty = self._userlist_dirty = self._input_dirty = True
        self.dirty = True

    async def _ev_resumed(self, event):
        self._status_win().add_line("Session resumed — not rejoining channels")
        self._chat_dirty = True
        self.dirty = True

    async def _ev_banlist(self, event):
        _, results = event
        self._cached_banlist = list(results)
        sw = self._status_win()
        if not results:
            sw.add_line("── Ban list: empty ──")
        else:
            sw.add_line(f"── Ban list ({len(results)} entries) ──")
            for ch, mask, setter, ts_raw in results:
                ts_str = time.strftime("%Y-%m-%d", time.localtime(float(ts_raw))) if ts_raw else ""
                by = f" by {setter}" if setter else ""
                sw.add_line(f"  {mask:<30} {by}{ts_str}")
            sw.add_line("── End of ban list ──")
        self._chat_dirty = True
        self.dirty = True

    async def _ev_dcc_progress(self, event):
        _, tid, nick, fname, sent, total, status = event
        sw = self._status_win()
        if status in ("done", "partial"):
            sw.add_line(f"DCC {tid}: {fname} to {nick} complete ({sent}/{total} bytes)")
        elif status == "timeout":
            sw.add_line(f"DCC {tid}: {fname} to {nick} timed out ({sent}/{total})")
        elif status.startswith("error"):
            sw.add_line(f"DCC {tid}: {fname} {status}")
        elif status == "transferring":
            pct = 100 * sent // total if total else 0
            sw.add_line(f"DCC {tid}: {fname} → {nick}  {pct}% ({sent}/{total})")
        elif status == "listening":
            sw.add_line(f"DCC {tid}: offering {fname} to {nick}...")
        elif status == "connecting":
            sw.add_line(f"DCC {tid}: receiving {fname} from {nick}...")
        self._chat_dirty = True
        self.dirty = True

    async def _ev_dcc_offer(self, event):
        # event: (_, nick, filename, ip_int, port, filesize, is_turbo)
        _, nick, filename, ip_int, port, filesize = event[:6]
        is_turbo = event[6] if len(event) > 6 else False
        fsize_str = f"{filesize // 1024} KB" if filesize > 1024 else f"{filesize} B"
        if nick.lower() in self._dcc_trusted:
            client = self._active_client()
            client._dcc_seq += 1
            tid = f"dcc{client._dcc_seq}"
            client._dcc_in[tid] = {"nick": nick, "filename": filename, "total": filesize,
                                   "sent": 0, "reader": None, "writer": None,
                                   "turbo": is_turbo, "ip_int": ip_int, "port": port}
            client.cmd_dcc_accept(tid, nick, filename, ip_int, port, filesize, turbo=is_turbo)
            await self.ui_queue.put(("status",
                f"DCC: {'turbo-' if is_turbo else ''}auto-accepting {filename} ({fsize_str}) from {nick}"))
        else:
            await self.ui_queue.put(("status",
                f"DCC: incoming {'turbo-' if is_turbo else ''}{filename} ({fsize_str}) from {nick} — "
                f"use /dcc trust {nick} to auto-accept"))

    async def _ev_dcc_resume_req(self, event):
        _, nick, filename, port, position = event
        client = self._active_client()
        client._dcc_handle_resume_req(None, port, position)
        await self.ui_queue.put(("status",
            f"DCC: resume request from {nick} for {filename} at byte {position}"))

    async def _ev_dcc_resume_ack(self, event):
        _, nick, filename, port, position = event
        client = self._active_client()
        # Find the matching incoming transfer
        for tid, entry in list(client._dcc_in.items()):
            if entry.get("nick") == nick and entry.get("filename") == filename:
                client._dcc_handle_resume_ack(tid, filename, port, position)
                await self.ui_queue.put(("status",
                    f"DCC: resuming {filename} from byte {position}"))
                break

    # ── DCC CHAT event handlers ─────────────────────────────────────────────
    def _dcc_chat_window_name(self, nick: str) -> str:
        return f"=DCC-chat-{nick}"

    def _dcc_chat_tid_for_window(self, win_name: str) -> Optional[str]:
        for tid, entry in self._active_client()._dcc_chats.items():
            if self._dcc_chat_window_name(entry["nick"]) == win_name:
                return tid
        return None

    async def _ev_dcc_chat_offer(self, event):
        if len(event) >= 6:
            _, tid, nick, ip_int, port, status = event
        else:
            _, nick, ip_int, port = event
            status = "offer"
            tid = None
        if status == "listening":
            await self.ui_queue.put(("status", f"DCC CHAT: offering chat to {nick}..."))
            return
        if status == "connected":
            win_name = self._dcc_chat_window_name(nick)
            win = self.window_by_name.get(win_name)
            if win:
                win.add_line("* DCC CHAT connected")
                self._chat_dirty = True
                self.dirty = True
            return
        if status == "error":
            await self.ui_queue.put(("status", f"DCC CHAT: error with {nick}"))
            return
        # Incoming offer — auto-accept from trusted or prompt
        fsize_str = ""
        if nick.lower() in self._dcc_trusted:
            client = self._active_client()
            client._dcc_seq += 1
            tid = f"dcc_chat{client._dcc_seq}"
            client._dcc_chats[tid] = {"nick": nick, "reader": None, "writer": None, "task": None}
            client._accept_dcc_chat(tid, nick, ip_int, port)
            win_name = self._dcc_chat_window_name(nick)
            self.ensure_window(win_name, is_channel=False)
            w = self.window_by_name[win_name]
            w.add_line("* DCC CHAT connecting...")
            await self.ui_queue.put(("status",
                f"DCC CHAT: auto-accepting from trusted user {nick}"))
        else:
            await self.ui_queue.put(("status",
                f"DCC CHAT: incoming from {nick} — use /dcc trust {nick} to auto-accept"))

    async def _ev_dcc_chat_msg(self, event):
        _, tid, nick, text = event
        win_name = self._dcc_chat_window_name(nick)
        win = self.window_by_name.get(win_name)
        if win is None:
            win = self.ensure_window(win_name, is_channel=False)
        win.add_line(f"<{nick}> {text}")
        self._chat_dirty = True
        self.dirty = True

    async def _ev_dcc_chat_closed(self, event):
        _, tid, nick = event
        win_name = self._dcc_chat_window_name(nick)
        win = self.window_by_name.get(win_name)
        if win:
            win.add_line("* DCC CHAT disconnected")
        self._chat_dirty = True
        self.dirty = True
        await self.ui_queue.put(("status", f"DCC CHAT with {nick} closed"))

    async def _ev_status_line(self, event):
        msg = str(event[1]) if len(event) > 1 else str(event)
        self._status_win().add_line(msg)
        self._chat_dirty = True
        self.dirty = True

    def _build_slash_handlers(self) -> None:
        h = self._slash_handlers
        h["me"] = h["action"] = self._slash_me
        h["ctcp"]       = self._slash_ctcp
        h["whois"]      = self._slash_whois
        h["mode"]       = self._slash_mode
        h["topic"]      = self._slash_topic
        h["kick"]       = self._slash_kick
        h["ns"] = h["nickserv"] = self._slash_ns
        h["cs"] = h["chanserv"] = self._slash_cs
        h["ai"]         = self._slash_ai
        h["bot"]        = self._slash_bot
        h["unbot"]      = self._slash_unbot
        h["learn_tell"] = h["ltell"] = self._slash_learn_tell
        h["forget_tell"] = h["ftell"] = self._slash_forget_tell
        h["scan_watermark"] = h["watermark"] = self._slash_scan_watermark
        h["topai"]      = self._slash_topai
        h["aitoggle"]   = self._slash_aitoggle
        h["logtoggle"]  = self._slash_logtoggle
        h["feedback"]   = self._slash_feedback
        h["sentiment"]  = self._slash_sentiment
        h["mood"]       = self._slash_sentiment
        h["anomaly"]    = self._slash_anomaly
        h["topics"]     = self._slash_topics
        h["topic"]      = self._slash_topics
        h["similar"]    = self._slash_similar
        h["threads"]    = self._slash_threads
        h["thread"]     = self._slash_threads
        h["crosschannel"] = self._slash_crosschannel
        h["xchan"]      = self._slash_crosschannel
        h["fingerprint"] = self._slash_fingerprint
        h["fp"]         = self._slash_fingerprint
        h["savefp"]     = self._slash_savefp
        h["behavior"]   = self._slash_behavior
        h["biometrics"] = self._slash_biometrics
        h["aistatus"]   = self._slash_aistatus
        h["aipipeline"] = self._slash_aistatus
        h["join"]       = self._slash_join
        h["part"]       = self._slash_part
        h["nick"]       = self._slash_nick
        h["msg"] = h["m"] = self._slash_msg
        h["query"]      = self._slash_query
        h["notice"]     = self._slash_notice
        h["away"]       = self._slash_away
        h["back"]       = self._slash_back
        h["invite"]     = self._slash_invite
        h["op"]         = self._slash_op
        h["deop"]       = self._slash_deop
        h["voice"]      = self._slash_voice
        h["devoice"]    = self._slash_devoice
        h["hop"]        = self._slash_hop
        h["dehop"]      = self._slash_dehop
        h["ban"]        = self._slash_ban
        h["unban"]      = self._slash_unban
        h["quietlist"]  = self._slash_quietlist
        h["chanmute"]   = self._slash_chanmute
        h["chanunmute"] = self._slash_chanunmute
        h["quiet"]      = self._slash_chanmute
        h["unquiet"]    = self._slash_chanunmute
        h["halfop"]     = self._slash_halfop
        h["dehalfop"]   = self._slash_dehalfop
        h["admin"]      = self._slash_admin
        h["deadmin"]    = self._slash_deadmin
        h["owner"]      = self._slash_owner
        h["deowner"]    = self._slash_deowner
        h["cap"]        = self._slash_cap
        h["sasl"]       = self._slash_sasl
        h["chghost"]    = self._slash_chghost
        h["setname"]    = self._slash_setname
        h["umode"]      = self._slash_umode
        h["oper"]       = self._slash_oper
        h["raw"]        = self._slash_raw
        h["stats"]      = self._slash_stats
        h["uptime"]     = self._slash_uptime
        h["ping"]       = self._slash_ping
        h["who"]        = self._slash_who
        h["whowas"]     = self._slash_whowas
        h["names"]      = self._slash_names
        h["ignore"]     = self._slash_ignore
        h["unignore"]   = self._slash_unignore
        h["clear"]      = self._slash_clear
        h["close"] = h["wc"] = self._slash_close
        h["win"] = h["window"] = self._slash_win
        h["quit"] = h["exit"] = self._slash_quit
        h["server"]     = self._slash_server
        h["reconnect"]  = self._slash_reconnect
        h["theme"]      = self._slash_theme
        h["askai"]      = self._slash_askai
        h["summarize"] = h["summarise"] = h["summerize"] = self._slash_summarize
        h["model"]      = self._slash_model
        h["api"]        = self._slash_api
        h["autotranslate"] = self._slash_autotranslate
        h["linkpreview"]  = self._slash_linkpreview
        h["autojoin"]     = self._slash_autojoin
        h["commands"]   = self._slash_commands
        h["help"]       = self._slash_help
        h["loadplugin"]   = self._slash_loadplugin
        h["unloadplugin"] = self._slash_unloadplugin
        h["reloadplugin"] = self._slash_reloadplugin
        h["plugins"]      = self._slash_plugins
        h["script"]       = self._slash_script
        h["remind"]       = self._slash_remind
        h["reminder"]     = self._slash_remind
        h["watch"]        = self._slash_watch
        h["unwatch"]      = self._slash_unwatch
        h["snippet"]      = self._slash_snippet
        h["snippets"]     = self._slash_snippet
        h["chstats"]      = self._slash_chstats
        h["rss"]          = self._slash_rss
        h["todo"]         = self._slash_todo
        h["todos"]        = self._slash_todo
        h["task"]         = self._slash_todo
        h["pomodoro"]     = self._slash_pomodoro
        h["pomo"]         = self._slash_pomodoro
        h["note"]         = self._slash_note
        h["notes"]        = self._slash_note
        h["memo"]         = self._slash_note
        h["bookmark"]     = self._slash_bookmark
        h["bm"]           = self._slash_bookmark
        h["bookmarks"]    = self._slash_bookmark
        h["timer"]        = self._slash_timer
        h["redraw"]       = self._slash_redraw
        h["links"]        = self._slash_links
        h["list"]         = self._slash_list
        h["lf"]           = self._slash_lf
        h["dcc"]          = self._slash_dcc
        h["dccchat"]      = self._slash_dccchat
        h["userlist"]     = self._slash_userlist
        h["znc"]          = self._slash_znc
        h["jitsi"]        = self._slash_jitsi
        h["chain"]        = self._slash_chain
        h["idle"]         = self._slash_idle
        h["together"]     = self._slash_together
        h["adjacent"]     = self._slash_adjacent
        h["targets"]      = self._slash_targets
        h["alias"]        = self._slash_alias
        h["mute"]         = self._slash_mute
        h["replay"]       = self._slash_replay
        h["soju"]         = self._slash_soju
        h["graph"]        = self._slash_graph
        h["aicalibrate"]  = self._slash_aicalibrate
        h["certfp"]       = self._slash_certfp
        h["tlsinfo"]      = self._slash_tlsinfo
        h["aivai"]        = self._slash_aivai
        h["saicorr"]      = self._slash_saicorr
        h["brief"]        = self._slash_brief
        h["monitor"]      = self._slash_monitor
        h["whox"]         = self._slash_whox
        h["tagmsg"]       = self._slash_tagmsg
        h["reply"]        = self._slash_reply
        h["react"]        = self._slash_react
        h["ml"] = h["multiline"] = self._slash_multiline
        h["redact"]       = self._slash_redact
        h["register"]     = self._slash_register
        h["pem"]          = self._slash_pem
        h["vibe"]         = self._slash_vibe
        h["explain"]      = self._slash_explain
        h["fingerprint"]  = self._slash_fingerprint
        h["cluster"]      = self._slash_cluster
        h["seen"]         = self._slash_seen
        h["tell"]         = self._slash_tell
        h["x0"]           = self._slash_x0
        h["bouncer"]      = self._slash_bouncer
        h["bnc"]          = self._slash_bouncer
        h["detach"]       = self._slash_detach
        h["attach"]       = self._slash_attach
        h["pgp"]          = self._slash_pgp
        h["tor"]          = self._slash_tor
        h["ctcpmode"]     = self._slash_ctcpmode

    async def handle_input_line(self, line: str) -> None:
        if not line.strip():
            return
        # Sync context to the server owning the current window so slash commands
        # and plain text go to the right server.
        self._sync_draw_ctx()
        if line.startswith("/"):
            parts = line[1:].split(maxsplit=2)
            cmd   = parts[0].lower()
            args  = parts[1] if len(parts) > 1 else ""
            extra = parts[2] if len(parts) > 2 else ""
            # Plugin on_command hook: allows intercepting/modifying commands
            cmd_result = await self.plugin_manager.dispatch_with_result(
                "on_command", cmd_name=cmd, args=args, extra=extra, line=line)
            if cmd_result is not None and cmd_result.get("handled"):
                return  # Plugin handled the command
            # User-defined alias expansion — only expand once (no recursion)
            if cmd in self._aliases and cmd not in self._slash_handlers:
                expanded = self._aliases[cmd]
                new_line = "/" + expanded + (" " + " ".join(filter(None, [args, extra]))).rstrip()
                await self.handle_input_line(new_line)
                return
            handler = self._slash_handlers.get(cmd)
            if handler:
                await handler(args, extra, line)
            else:
                plugin_entry = self.plugin_manager.get_command(cmd)
                if plugin_entry:
                    plug_api, plug_handler = plugin_entry
                    plug_args = line[1 + len(cmd):].lstrip()
                    try:
                        result = plug_handler(plug_api, plug_args)
                        if asyncio.iscoroutine(result):
                            await result
                    except Exception as plug_exc:
                        await self.ui_queue.put(
                            ("status", f"[plugin:{plug_api.name}] error: {plug_exc}"))
                else:
                    script_entry = self.script_engine.get_command(cmd)
                    if script_entry:
                        scr_api, scr_handler = script_entry
                        scr_args = line[1 + len(cmd):].lstrip()
                        try:
                            result = scr_handler(scr_api, scr_args)
                            if asyncio.iscoroutine(result):
                                await result
                        except Exception as scr_exc:
                            await self.ui_queue.put(
                                ("status", f"[script:{scr_api.name}] error: {scr_exc}"))
                    else:
                        self._active_client().send_raw(line[1:])
        else:
            stripped_line = line.strip()
            ext = os.path.splitext(stripped_line)[1].lower()
            if ext in _IMAGE_EXTENSIONS and os.path.isfile(stripped_line):
                await self.ui_queue.put(("status", f"Auto-uploading {stripped_line} to x0.at\u2026"))
                loop = asyncio.get_event_loop()
                url = await loop.run_in_executor(_IO_EXECUTOR, _upload_to_x0, stripped_line)
                if url:
                    line = url
                else:
                    await self.ui_queue.put(("status", "x0.at auto-upload failed, sending as text."))
            await self._send_plain_text(line)
        self._chat_dirty = True
        self._input_dirty = True
        self.dirty = True
        self.completion_state = None

    async def _send_plain_text(self, line: str) -> None:
        cur_win = self.get_current_window()
        client = self._active_client()
        client.biometrics.record_composition_complete()
        client.biometrics.record_response()
        # DCC CHAT: route text over the direct TCP connection
        if cur_win.name.startswith("=DCC-chat-"):
            nick = cur_win.name[len("=DCC-chat-"):]
            tid = self._dcc_chat_tid_for_window(cur_win.name)
            if tid:
                client.dcc_chat_send(tid, line)
                cur_win.add_line(f"<{client.nick}> {line}")
                self._chat_dirty = True
                self.dirty = True
            else:
                await self.ui_queue.put(("status", "DCC CHAT not connected"))
            return
        if cur_win.name not in ("*status*", "*dashboard*"):
            target = cur_win.name
        else:
            target = self.current_channel or DEFAULT_CHANNEL
            if target:
                dest = self.ensure_window(target, is_channel=target.startswith("#"))
                self.current_channel = target
                self.current_window_index = self.windows.index(dest)
                self._unread_windows.discard(target)
        result = client.cmd_msg(target, line)
        if result:
            await self.ui_queue.put(result)

    async def _slash_me(self, args, extra, line):
        slash_end = line.index(" ") + 1 if " " in line else len(line)
        action_text = line[slash_end:].strip()
        if not action_text:
            return
        cur_win = self.get_current_window()
        target = (cur_win.name if cur_win.name not in ("*status*", "*dashboard*")
                  else self.current_channel or DEFAULT_CHANNEL)
        result = self._active_client().cmd_msg(target, action_text, is_action=True)
        if result:
            await self.ui_queue.put(result)

    async def _slash_ctcp(self, args, extra, line):
        if args and extra:
            self._active_client().cmd_ctcp(args, extra.upper())
            await self.ui_queue.put(("status", f"CTCP {extra.upper()} sent to {args}"))
        else:
            await self.ui_queue.put(("status", "Usage: /ctcp <nick> <command> [args]"))

    async def _slash_whois(self, args, extra, line):
        if args:
            self._active_client().cmd_whois(args)

    async def _ev_chanmode(self, event):
        _, channel, modestr, mode_args = event
        wk = self._wk(self._active_server_id, channel)
        win = self.window_by_name.get(wk) or self._status_win()
        if mode_args:
            win.add_line(f"* Channel modes for {channel}: +{modestr} {' '.join(mode_args)}")
        else:
            win.add_line(f"* Channel modes for {channel}: +{modestr}" if modestr
                         else f"* No channel modes set for {channel}")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_mode(self, args, extra, line):
        # Reconstruct from the raw line to avoid maxsplit=2 truncation
        space = line.find(" ")
        if space == -1:
            ch = self.current_channel or self.get_current_window().name
            if ch and ch.startswith("#"):
                self._active_client().cmd_mode(ch)
            else:
                await self.ui_queue.put(("status", "Usage: /mode [<#channel>] [modes]"))
            return
        rest = line[space + 1:].strip()
        parts = rest.split(maxsplit=1)
        target = parts[0]
        modestr = parts[1] if len(parts) > 1 else ""
        if target.startswith("#") or target.startswith("&"):
            self._active_client().cmd_mode(target, modestr)
        else:
            await self.ui_queue.put(("status", "Usage: /mode <#channel> [modes]"))

    async def _slash_topic(self, args, extra, line):
        if not args and not extra:
            ch = self.current_channel or self.get_current_window().name
            if ch and ch.startswith("#"):
                self._active_client().cmd_topic(ch)
            else:
                await self.ui_queue.put(("status", "Usage: /topic [<#channel>] [<new topic>]"))
            return
        first = args.strip()
        rest = extra.strip()
        if first.startswith("#"):
            # /topic <#channel> [new topic]
            if rest:
                self._active_client().cmd_topic(first, rest)
            else:
                self._active_client().cmd_topic(first)
        else:
            # /topic <new topic>  (current channel)
            ch = self.current_channel or self.get_current_window().name
            if ch and ch.startswith("#"):
                text = first + (" " + rest if rest else "")
                self._active_client().cmd_topic(ch, text)
            else:
                await self.ui_queue.put(("status", "Usage: /topic [<#channel>] [<new topic>]"))

    async def _slash_kick(self, args, extra, line):
        if args:
            p = args.split(maxsplit=2)
            if len(p) >= 2:
                self._active_client().cmd_kick(p[0], p[1], p[2] if len(p) > 2 else "")

    async def _slash_ns(self, args, extra, line):
        if args:
            self._active_client().cmd_service("NickServ", args)

    async def _slash_cs(self, args, extra, line):
        if args:
            self._active_client().cmd_service("ChanServ", args)

    async def _slash_ai(self, args, extra, line):
        if _NO_AI:
            await self.ui_queue.put(("status", "[ai] disabled by --no-ai")); return
        if args:
            await self.show_user_ai_profile(args)
        else:
            await self.ui_queue.put(("status", "Usage: /ai <nick>"))

    # ── /bot and /unbot ──────────────────────────────────────────────────────

    _MSG_LINE_RE = re.compile(r'^\[\d{2}:\d{2}\] <(\S+?)> (.+)$')
    _ACT_LINE_RE = re.compile(r'^\[\d{2}:\d{2}\] \* (\S+) (.+)$')

    async def _slash_bot(self, args, extra, line):
        """Mark a nick as a confirmed bot/AI and build a fingerprint from history."""
        if _NO_AI:
            await self.ui_queue.put(("status", "[bot] disabled by --no-ai")); return
        nick = args.strip()
        if not nick:
            await self.ui_queue.put(("status", "Usage: /bot <nick>  —  mark as confirmed bot/AI"))
            return

        client  = self._active_client()
        scoring = client.scoring
        nick_lower = nick.lower()

        u_state = client.users.get(nick)
        if u_state:
            u_state.is_confirmed_bot = True

        raw_msgs: List[str] = []
        for win in self.windows:
            for ln in win.lines:
                m = self._MSG_LINE_RE.match(ln)
                if m and m.group(1).lower() == nick_lower:
                    raw_msgs.append(m.group(2))
                    continue
                a = self._ACT_LINE_RE.match(ln)
                if a and a.group(1).lower() == nick_lower:
                    raw_msgs.append(a.group(2))

        fp = scoring.confirm_bot(nick, raw_msgs)

        msg_count = u_state.total_msgs if u_state else 0
        await self.ui_queue.put(("status",
            f"[bot] {nick} marked as confirmed bot/AI — "
            f"fingerprint built from {fp.msg_count} msgs "
            f"({len(fp.bigrams)} bigrams, {len(fp.trigrams)} trigrams)  "
            f"session msgs: {msg_count}"))

        # ── Asynchronously train LoRA adapter on this bot's messages ────────
        if _PEFT_AVAILABLE and raw_msgs:
            _neg_msgs: List[str] = []
            for _win in self.windows:
                for _ln in list(_win.lines)[-100:]:
                    _m = self._MSG_LINE_RE.match(_ln)
                    if _m and _m.group(1).lower() != nick_lower and len(_m.group(2).split()) >= 3:
                        _neg_msgs.append(_m.group(2))
            if len(_neg_msgs) > len(raw_msgs) * 3:
                _neg_msgs = random.sample(_neg_msgs, min(len(raw_msgs) * 3, 60))
            _adapter_dir = os.path.join(_SCRIPT_DIR, f"lora_{nick}")
            _detector = scoring.ai_detector
            loop = asyncio.get_running_loop()
            try:
                _lora_result = await asyncio.wait_for(
                    loop.run_in_executor(
                        _ML_EXECUTOR, _detector._train_lora_adapter,
                        raw_msgs, _neg_msgs, _adapter_dir),
                    timeout=120.0)
            except asyncio.TimeoutError:
                _lora_result = "[timeout] LoRA training took too long (>120s) — skipped"
            except Exception as _lora_exc:
                _lora_result = f"[error] LoRA training failed: {_lora_exc}"
            if _lora_result and os.path.isdir(_lora_result):
                await self.ui_queue.put(("status",
                    f"[bot] LoRA adapter saved to {_lora_result}  "
                    f"(use /bot to confirm another user, or restart to reload)"))
            elif _lora_result:
                await self.ui_queue.put(("status",
                    f"[bot] LoRA: {_lora_result}"))

    async def _slash_unbot(self, args, extra, line):
        """Remove confirmed-bot status from a nick."""
        if _NO_AI:
            await self.ui_queue.put(("status", "[unbot] disabled by --no-ai")); return
        nick = args.strip()
        if not nick:
            await self.ui_queue.put(("status", "Usage: /unbot <nick>"))
            return

        client  = self._active_client()
        scoring = client.scoring
        nick_lower = nick.lower()

        was_confirmed = nick_lower in scoring.confirmed_bot_nicks
        u_state = client.users.get(nick)
        if u_state:
            u_state.is_confirmed_bot = False

        scoring.unconfirm_bot(nick)

        if was_confirmed:
            # Clean up LoRA adapter directory if it exists
            _adapter_dir = os.path.join(_SCRIPT_DIR, f"lora_{nick}")
            if os.path.isdir(_adapter_dir):
                try:
                    import shutil
                    shutil.rmtree(_adapter_dir, ignore_errors=True)
                    await self.ui_queue.put(("status",
                        f"[bot] {nick} removed from confirmed-bot list (LoRA adapter cleaned up)"))
                except Exception:
                    await self.ui_queue.put(("status",
                        f"[bot] {nick} removed from confirmed-bot list (LoRA cleanup failed)"))
            else:
                await self.ui_queue.put(("status",
                    f"[bot] {nick} removed from confirmed-bot list"))
        else:
            await self.ui_queue.put(("status",
                f"[bot] {nick} was not in the confirmed-bot list"))

    # ── /learn_tell  —  collaborative n-gram blocklist  (Area 3) ──────────

    async def _slash_learn_tell(self, args, extra, line):
        """Add n-grams from a phrase to the shared blocklist.

        Usage: /learn_tell <phrase>
          The phrase is tokenised into words, bigrams, and trigrams and added
          to the persistent blocklist.  Future messages containing these n-grams
          receive a score boost.
        """
        phrase = (args + " " + extra).strip()
        if not phrase:
            await self.ui_queue.put(("status", "Usage: /learn_tell <phrase>"))
            return
        scoring = self._active_client().scoring
        n_added = scoring.add_tell(phrase)
        await self.ui_queue.put(("status",
            f"[learn_tell] added {n_added} n-gram(s) from \"{phrase[:60]}\"  "
            f"(total: {len(scoring.blocklisted_ngrams)})"))

    async def _slash_forget_tell(self, args, extra, line):
        """Remove n-grams of a phrase from the shared blocklist.

        Usage: /forget_tell <phrase>
        """
        phrase = (args + " " + extra).strip()
        if not phrase:
            await self.ui_queue.put(("status", "Usage: /forget_tell <phrase>"))
            return
        scoring = self._active_client().scoring
        n_removed = scoring.remove_tell(phrase)
        await self.ui_queue.put(("status",
            f"[forget_tell] removed {n_removed} n-gram(s) for \"{phrase[:60]}\"  "
            f"(total: {len(scoring.blocklisted_ngrams)})"))

    # ── /scan_watermark  —  LLM watermark detection  (Area 5) ─────────────

    async def _slash_scan_watermark(self, args, extra, line):
        """Scan recent messages or provided text for LLM watermark patterns.

        Usage: /scan_watermark [text]
          If text is provided, analyse it directly.  Otherwise scan the last
          10 messages in the current window.
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[watermark] disabled by --no-ai")); return
        msg_text = (args + " " + extra).strip()
        detector = self._active_client().scoring.ai_detector
        if not detector.enabled:
            await self.ui_queue.put(("status", "[watermark] AI detector is disabled")); return

        results: List[Tuple[str, float]] = []
        if msg_text:
            wm = detector.watermark_score(msg_text)
            results.append((msg_text[:80], wm))
        else:
            cur_win = self.get_current_window()
            _TS_RE = re.compile(r'^\[\d{2}:\d{2}\]\s*')
            _SPEAKER_RE = re.compile(r'^<(\S+?)>\s*(.*)')
            count = 0
            for ln in reversed(list(cur_win.lines)):
                stripped = _TS_RE.sub("", ln)
                m = _SPEAKER_RE.match(stripped)
                if m:
                    wm = detector.watermark_score(m.group(2))
                    results.append((f"<{m.group(1)}> {m.group(2)[:60]}", wm))
                    count += 1
                    if count >= 10:
                        break

        if not results:
            await self.ui_queue.put(("status", "[watermark] no messages to scan"))
            return

        dash = self.window_by_name["*dashboard*"]
        dash.lines.clear()
        dash._wrap_dirty = True
        L = lambda t: dash.add_line(t, timestamp=False)
        L("=== Watermark Scan ===")
        L("")
        bars = "▁▂▃▄▅▆▇█"
        for preview, wm_score in results:
            bar = bars[min(7, int(wm_score * 8))]
            flag = "  *** WATERMARK ***" if wm_score >= 0.35 else ""
            L(f"  [{wm_score:.2f} {bar}] {preview}{flag}")
        L("")
        L("  ── Legend ──────────────────────────────────────")
        L("  Score ≥ 0.35  — likely watermarked (LLM-generated)")
        L("  Score 0.15–0.34 — weak watermark signal")
        L("  Score < 0.15  — natural/unwatermarked text")

        self._dashboard_mode = "profile"
        self._dashboard_profile_locked = True
        self._dashboard_dirty = False
        self._dashboard_last_update = time.monotonic()
        self.current_window_index = 1
        self._chat_dirty = True
        self.dirty = True

    async def _slash_topai(self, args, extra, line):
        if _NO_AI:
            await self.ui_queue.put(("status", "[topai] disabled by --no-ai")); return
        cur_win = self.get_current_window()
        channel = cur_win.name if cur_win.name.startswith("#") else self.current_channel or ""
        if not channel or channel not in self.channel_users:
            await self.ui_queue.put(("status", "/topai: switch to a channel window first"))
            return

        client    = self._active_client()
        chan_nicks = self.channel_users.get(channel, set())
        bars      = "▁▂▃▄▅▆▇█"
        now       = time.monotonic()

        confirmed = client.scoring.confirmed_bot_nicks if hasattr(client, 'scoring') else set()

        rows = []
        for nick in chan_nicks:
            state = client.users.get(nick)
            is_bot = nick.lower() in confirmed
            if state is None or state.total_msgs == 0:
                # Include confirmed bots even with 0 session messages
                if not is_bot:
                    continue
            ai_pct = int(state.rolling_ai_likelihood()) if state else 100
            if ai_pct == 0 and not is_bot:
                continue
            rows.append((nick, ai_pct, state, is_bot))
        # Confirmed bots always sort first, then by descending AI%
        rows.sort(key=lambda x: (not x[3], -x[1], x[0].lower()))

        dash = self.window_by_name["*dashboard*"]
        dash.lines.clear()
        dash._wrap_dirty = True
        L = lambda t: dash.add_line(t, timestamp=False)

        L(f"=== /topai — {channel}  ({len(rows)} scored users) ===")
        L("")

        if not rows:
            L("  No users with scored messages in this channel yet.")
        else:
            L(f"  {'Nick':<16} {'AI%':>4}  {'Msgs':>4}  {'AvgLen':>6}  {'mpm':>5}  {'Last':>5}  History")
            L("  " + "─" * 66)
            thresh = self.ai_suspect_threshold
            for nick, ai_pct, state, is_bot in rows:
                last_ago = (int((now - state.last_msg_time) // 60)
                            if state and state.last_msg_time else 0)
                spark    = ("".join(bars[min(7, s * 8 // 101)]
                                    for s in list(state.ai_scores)[-12:])
                            if state else "")
                msgs     = state.total_msgs if state else 0
                avg_len  = state.avg_msg_length() if state else 0.0
                mpm      = state.messages_per_minute() if state else 0.0
                styl     = self._recent_styl_scores.get(nick, 0.0)
                if is_bot:
                    flag = "B"
                elif ai_pct >= thresh:
                    flag = "*"
                else:
                    flag = " "
                L(f"  {flag}{nick:<15} {ai_pct:3d}%  {msgs:4d}  "
                  f"{avg_len:6.0f}  {mpm:5.1f}"
                  f"  {last_ago:3d}m  styl:{styl:.2f}  {spark}")

        L("")
        L(f"  B = confirmed bot/AI  * = at or above suspect threshold ({self.ai_suspect_threshold}%)")
        L(f"  styl = stylometric score (burstiness + lexical diversity + punctuation)")

        self._dashboard_mode           = "profile"
        self._dashboard_profile_locked = True
        self._dashboard_dirty          = False
        self._dashboard_last_update    = time.monotonic()
        self.current_window_index      = 1
        self._chat_dirty               = True
        self.dirty                     = True

    async def _slash_aitoggle(self, args, extra, line):
        if _NO_AI:
            await self.ui_queue.put(("status", "[aitoggle] disabled by --no-ai")); return
        detector = self._active_client().scoring.ai_detector
        detector.enabled = not detector.enabled
        det_state = "ENABLED" if detector.enabled else "DISABLED"
        log_state = "log:ON" if _ai_logging_enabled else "log:OFF"
        await self.ui_queue.put(("status", f"AI detection {det_state}  ({log_state})"))

    async def _slash_logtoggle(self, args, extra, line):
        if _NO_AI:
            await self.ui_queue.put(("status", "[logtoggle] disabled by --no-ai")); return
        global _ai_logging_enabled
        # Write a final "disabled" record before we stop writing, or a "enabled" record
        # immediately after we start — so the log gap is bounded and auditable.
        if _ai_logging_enabled:
            log_toggle_event(enabled=False, nick=self._active_client().nick)
        _ai_logging_enabled = not _ai_logging_enabled
        if _ai_logging_enabled:
            log_toggle_event(enabled=True, nick=self._active_client().nick)
        state = "ENABLED" if _ai_logging_enabled else "DISABLED"
        await self.ui_queue.put(("status", f"AI detection logging {state}  (file: {AI_LOG_PATH})"))

    async def _slash_feedback(self, args, extra, line):
        """Provide feedback on AI detection to tune weights dynamically.

        Usage:
          /feedback ai <nick>          – confirm this user IS AI/bot
          /feedback human <nick>       – confirm this user is HUMAN (false positive)
          /feedback status             – show feedback stats and current weight adjustments
          /feedback reset              – clear all feedback data and restore default weights
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[feedback] disabled by --no-ai")); return

        action = (args or "").strip().lower()
        nick = (extra or "").strip()

        if action == "ai" or action == "bot":
            if not nick:
                await self.ui_queue.put(("status", "Usage: /feedback ai <nick>  – confirm user is AI/bot"))
                return
            self._record_feedback(nick, "ai")
            await self.ui_queue.put(("status", f"[feedback] {nick} marked as AI — weights will adapt"))

        elif action == "human" or action == "notai":
            if not nick:
                await self.ui_queue.put(("status", "Usage: /feedback human <nick>  – confirm user is human"))
                return
            self._record_feedback(nick, "human")
            await self.ui_queue.put(("status", f"[feedback] {nick} marked as human — weights will adapt"))

        elif action == "status":
            self._show_feedback_status()

        elif action == "reset":
            self._reset_feedback()
            await self.ui_queue.put(("status", "[feedback] All feedback data cleared, weights restored to defaults"))

        else:
            await self.ui_queue.put(("status",
                "Usage: /feedback <ai|human> <nick> | status | reset\n"
                "  ai <nick>    – confirm user IS AI/bot\n"
                "  human <nick> – confirm user is HUMAN (false positive)\n"
                "  status       – show feedback stats\n"
                "  reset        – clear feedback and restore defaults"))

    def _record_feedback(self, nick: str, label: str) -> None:
        """Store feedback and adjust detector weights."""
        client = self._active_client()
        detector = client.scoring.ai_detector
        state = client.users.get(nick)

        feedback_entry = {
            "nick": nick,
            "label": label,
            "ts": time.time(),
            "rolling_ai": self.user_ai_scores.get(nick, 0),
            "styl": self._recent_styl_scores.get(nick, 0.0),
        }
        if state:
            scores = list(state.ai_scores)
            feedback_entry["recent_scores"] = scores[-10:] if scores else []
            feedback_entry["msg_count"] = state.total_msgs

        self._ai_feedback_log.append(feedback_entry)

        # Feed to calibration manager for threshold/signal analysis
        client.scoring.calibration.record_feedback(
            nick, label,
            ai_score=float(self.user_ai_scores.get(nick, 0)),
            signal_scores={
                "formality": feedback_entry.get("styl", 0),
                "rolling_ai": feedback_entry.get("rolling_ai", 0),
            })

        # Adaptive weight tuning based on feedback
        self._apply_feedback_weights(detector, label)

    def _apply_feedback_weights(self, detector, label: str) -> None:
        """Nudge ensemble weights based on user feedback."""
        if not hasattr(detector, '_feedback_adjustments'):
            detector._feedback_adjustments = {"ai": 0, "human": 0}

        adjustments = detector._feedback_adjustments
        if label == "ai":
            adjustments["ai"] += 1
        else:
            adjustments["human"] += 1

        total = adjustments["ai"] + adjustments["human"]
        if total < 3:
            return  # Need more feedback before adjusting

        ai_ratio = adjustments["ai"] / total

        # If we're getting many false positives (human feedback), reduce heuristic aggressiveness
        if ai_ratio < 0.3 and hasattr(detector, '_heu_weight'):
            detector._heu_weight = max(0.05, detector._heu_weight - 0.02)
        # If we're missing real bots (ai feedback), increase classifier weight
        elif ai_ratio > 0.7 and hasattr(detector, '_cls_weight'):
            detector._cls_weight = min(0.40, detector._cls_weight + 0.02)

    def _show_feedback_status(self) -> None:
        """Display feedback statistics to the user."""
        total = len(self._ai_feedback_log)
        ai_count = sum(1 for f in self._ai_feedback_log if f["label"] == "ai")
        human_count = total - ai_count

        lines = [
            f"=== AI Feedback Status ===",
            f"  Total feedback entries : {total}",
            f"  AI/bot confirmations   : {ai_count}",
            f"  Human (false positive) : {human_count}",
        ]

        client = self._active_client()
        detector = client.scoring.ai_detector
        if hasattr(detector, '_feedback_adjustments'):
            adj = detector._feedback_adjustments
            lines.append(f"  Feedback ratio (AI)    : {adj['ai']}/{adj['ai'] + adj['human']}")

        if hasattr(detector, '_heu_weight'):
            lines.append(f"  Current heu_weight     : {detector._heu_weight:.3f}")
        if hasattr(detector, '_cls_weight'):
            lines.append(f"  Current cls_weight     : {detector._cls_weight:.3f}")

        lines.append("")
        lines.append("  Recent feedback:")
        for entry in self._ai_feedback_log[-5:]:
            nick = entry["nick"]
            label = entry["label"]
            rolling = entry.get("rolling_ai", 0)
            lines.append(f"    {nick:15s} → {label.upper():5s}  (was {rolling}%)")

        sw = self.window_by_name.get("*status*")
        if sw:
            for line in lines:
                sw.add_line(line)
            self._chat_dirty = True
            self.dirty = True

    def _reset_feedback(self) -> None:
        """Clear all feedback data and restore default weights."""
        self._ai_feedback_log.clear()
        client = self._active_client()
        detector = client.scoring.ai_detector
        if hasattr(detector, '_feedback_adjustments'):
            detector._feedback_adjustments = {"ai": 0, "human": 0}
        # Restore default weights if they were modified
        if hasattr(detector, '_heu_weight'):
            detector._heu_weight = detector._default_heu_weight if hasattr(detector, '_default_heu_weight') else 0.25
        if hasattr(detector, '_cls_weight'):
            detector._cls_weight = detector._default_cls_weight if hasattr(detector, '_default_cls_weight') else 0.25

    async def _slash_sentiment(self, args, extra, line):
        """Analyze sentiment for a user or the current channel.

        Usage:
          /sentiment <nick>       — show sentiment analysis for a user
          /sentiment              — show sentiment for last 10 messages in current window
          /sentiment channel      — show channel-wide sentiment summary
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[sentiment] disabled by --no-ai")); return

        client = self._active_client()
        scoring = client.scoring
        target = (args or "").strip().lower()

        if target == "channel":
            # Channel-wide sentiment summary
            cur_win = self.get_current_window()
            chan = cur_win.name if cur_win.name.startswith("#") else self.current_channel
            if not chan:
                await self.ui_queue.put(("status", "No channel active"))
                return
            _TS_RE = re.compile(r'^\[\d{2}:\d{2}\]\s*')
            _SPEAKER_RE = re.compile(r'^<(\S+?)>')
            nick_scores: Dict[str, list] = {}
            for ln in list(cur_win.lines)[-200:]:
                stripped = _TS_RE.sub("", ln)
                m = _SPEAKER_RE.match(stripped)
                if m:
                    nick = m.group(1)
                    text = m.group(2) if m.group(2) else ""
                    result = scoring.sentiment.analyze(text)
                    nick_scores.setdefault(nick, []).append(result["score"])
            if not nick_scores:
                await self.ui_queue.put(("status", "No messages to analyze"))
                return
            sw = self._status_win()
            sw.add_line(f"=== Channel Sentiment: {chan} ===")
            for nick, scores in sorted(nick_scores.items(), key=lambda x: sum(x[1])/len(x[1]), reverse=True):
                avg = sum(scores) / len(scores)
                label = scoring.sentiment.sentiment_label(avg)
                sw.add_line(f"  {nick:<15} avg: {avg:+.2f}  ({label})  [{len(scores)} msgs]")
            self._chat_dirty = True
            self.dirty = True
            return

        if target:
            # User sentiment trend
            trend = scoring.get_sentiment_trend(target)
            sw = self._status_win()
            sw.add_line(f"=== Sentiment Analysis: {target} ===")
            sw.add_line(f"  Trend       : {trend['trend']}")
            sw.add_line(f"  Avg score   : {trend['avg_score']:+.3f}")
            sw.add_line(f"  Volatility  : {trend['volatility']:.3f}")
            sw.add_line(f"  Samples     : {trend['sample_count']}")
            # Show recent sentiment history
            history = scoring._sentiment_history.get(target, [])
            if history:
                sw.add_line("")
                sw.add_line("  Recent messages:")
                for h in list(history)[-5:]:
                    label = scoring.sentiment.sentiment_label(h["score"])
                    sw.add_line(f"    [{h['score']:+.2f}] {label}: {h['text'][:60]}")
            self._chat_dirty = True
            self.dirty = True
        else:
            # Analyze last 10 messages in current window
            cur_win = self.get_current_window()
            _TS_RE = re.compile(r'^\[\d{2}:\d{2}\]\s*')
            sw = self._status_win()
            sw.add_line(f"=== Message Sentiment: {cur_win.name} ===")
            count = 0
            for ln in reversed(list(cur_win.lines)):
                stripped = _TS_RE.sub("", ln)
                m = re.match(r'^<(\S+?)>\s*(.*)', stripped)
                if m:
                    nick = m.group(1)
                    text = m.group(2)
                    result = scoring.sentiment.analyze(text)
                    label = scoring.sentiment.sentiment_label(result["score"])
                    sw.add_line(f"  [{result['score']:+.2f}] {label}  <{nick}> {text[:60]}")
                    count += 1
                    if count >= 10:
                        break
            if count == 0:
                sw.add_line("  No messages to analyze")
            self._chat_dirty = True
            self.dirty = True

    async def _slash_anomaly(self, args, extra, line):
        """Show behavioral anomaly analysis for a user.

        Usage: /anomaly <nick>
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[anomaly] disabled by --no-ai")); return

        nick = (args or "").strip()
        if not nick:
            await self.ui_queue.put(("status", "Usage: /anomaly <nick>"))
            return

        client = self._active_client()
        scoring = client.scoring
        u_state = client.users.get(nick)
        if not u_state:
            await self.ui_queue.put(("status", f"No data for {nick} in this session"))
            return

        # Get latest sentiment score
        sent_history = scoring._sentiment_history.get(nick, deque())
        latest_sent = sent_history[-1]["score"] if sent_history else 0.0

        # Analyze behavioral anomalies
        anomaly = scoring.behavioral.update(nick, "dummy", latest_sent)

        sw = self._status_win()
        sw.add_line(f"=== Behavioral Anomaly: {nick} ===")
        sw.add_line(f"  Anomaly score : {anomaly['anomaly_score']:.3f}")
        if anomaly["changed_aspects"]:
            for aspect in anomaly["changed_aspects"]:
                sw.add_line(f"  ⚠ {aspect}")
        else:
            sw.add_line("  No significant anomalies detected")
        if anomaly.get("z_scores"):
            sw.add_line("")
            sw.add_line("  Z-scores (|z| > 2.0 = significant):")
            for aspect, z in anomaly["z_scores"].items():
                flag = " ⚠" if abs(z) > 2.0 else ""
                sw.add_line(f"    {aspect:<12} : {z:+.2f}{flag}")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_topics(self, args, extra, line):
        """Show topic analysis for the current channel or a user.

        Usage:
          /topics              — show topics in last 50 messages
          /topics <nick>       — show topics for a specific user
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[topics] disabled by --no-ai")); return

        client = self._active_client()
        scoring = client.scoring
        target = (args or "").strip().lower()

        cur_win = self.get_current_window()
        _TS_RE = re.compile(r'^\[\d{2}:\d{2}\]\s*')
        _SPEAKER_RE = re.compile(r'^<(\S+?)>')

        topic_counts: Dict[str, int] = {}
        count = 0
        for ln in list(cur_win.lines)[-200:]:
            stripped = _TS_RE.sub("", ln)
            m = _SPEAKER_RE.match(stripped)
            if m:
                nick = m.group(1)
                text = m.group(2) if m.group(2) else ""
                if target and nick.lower() != target:
                    continue
                topics = scoring.topics.detect(text)
                for topic, _ in topics:
                    topic_counts[topic] = topic_counts.get(topic, 0) + 1
                count += 1

        if not topic_counts:
            await self.ui_queue.put(("status", f"No topics detected in {count} messages"))
            return

        sw = self._status_win()
        title = f"=== Topics: {target} in {cur_win.name} ===" if target else f"=== Topics: {cur_win.name} ==="
        sw.add_line(title)
        for topic, cnt in sorted(topic_counts.items(), key=lambda x: x[1], reverse=True):
            bar = "█" * min(20, cnt)
            sw.add_line(f"  {topic:<15} {cnt:3d} {bar}")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_similar(self, args, extra, line):
        """Find semantically similar messages from other users.

        Usage: /similar <text>
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[similar] disabled by --no-ai")); return

        text = (args + " " + extra).strip()
        if not text:
            await self.ui_queue.put(("status", "Usage: /similar <text>"))
            return

        client = self._active_client()
        scoring = client.scoring
        matches = scoring.semantic.find_similar(client.nick, text)

        sw = self._status_win()
        sw.add_line(f"=== Semantic Similarity ===")
        sw.add_line(f"  Query: {text[:80]}")
        if matches:
            sw.add_line("")
            for m in matches:
                sw.add_line(f"  [{m['score']:.2f}] <{m['nick']}> in {m['channel']}: {m['text'][:60]}")
        else:
            sw.add_line("  No similar messages found")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_threads(self, args, extra, line):
        """Show active conversation threads.

        Usage:
          /threads              — show all active threads
          /threads <channel>    — show threads in a specific channel
        """
        client = self._active_client()
        scoring = client.scoring
        channel = (args or "").strip()

        threads = scoring.threads.get_active_threads(channel=channel, limit=15)
        sw = self._status_win()
        sw.add_line(f"=== Active Threads{' in ' + channel if channel else ''} ===")
        if threads:
            for t in threads:
                duration = int(time.time() - t["started"])
                mins = duration // 60
                secs = duration % 60
                sw.add_line(f"  [{t['message_count']} msgs] {', '.join(t['participants'][:4])}")
                sw.add_line(f"    Topic: {t['topic'][:70]}")
                sw.add_line(f"    Duration: {mins}m {secs}s")
        else:
            sw.add_line("  No active threads")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_crosschannel(self, args, extra, line):
        """Show cross-channel bot detection results.

        Usage:
          /crosschannel          — show suspicious nicks
          /crosschannel <nick>   — show activity for a specific nick
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[crosschannel] disabled by --no-ai")); return

        client = self._active_client()
        scoring = client.scoring
        target = (args or "").strip()

        sw = self._status_win()
        if target:
            # Show specific nick's cross-channel activity
            channels = scoring.cross_channel._nick_channels.get(target, set())
            msgs = list(scoring.cross_channel._nick_messages.get(target, []))
            alerts = [a for a in scoring.cross_channel._cross_channel_alerts if a["nick"] == target]
            sw.add_line(f"=== Cross-Channel Activity: {target} ===")
            sw.add_line(f"  Channels: {', '.join(sorted(channels))}")
            sw.add_line(f"  Messages: {len(msgs)}")
            sw.add_line(f"  Alerts  : {len(alerts)}")
            if alerts:
                sw.add_line("")
                for a in alerts[-5:]:
                    sw.add_line(f"  ⚠ {a['type']} in {', '.join(a['channels'])}")
        else:
            # Show all suspicious nicks
            suspicious = scoring.cross_channel.get_suspicious_nicks(min_channels=2)
            sw.add_line(f"=== Cross-Channel Bot Detection ===")
            if suspicious:
                for s in suspicious[:10]:
                    sw.add_line(f"  {s['nick']:<15} {len(s['channels'])} channels  "
                                f"{s['message_count']} msgs  {s['alerts']} alerts")
                    sw.add_line(f"    Channels: {', '.join(s['channels'][:5])}")
            else:
                sw.add_line("  No suspicious cross-channel activity detected")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_fingerprint(self, args, extra, line):
        """Show bot fingerprint details.

        Usage:
          /fingerprint <nick>   — show fingerprint for a bot
          /fingerprint list     — list all saved fingerprints
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[fingerprint] disabled by --no-ai")); return

        client = self._active_client()
        scoring = client.scoring
        target = (args or "").strip().lower()

        if target == "list":
            sw = self._status_win()
            sw.add_line("=== Saved Bot Fingerprints ===")
            if scoring.bot_fingerprints:
                for nick, fp in sorted(scoring.bot_fingerprints.items()):
                    channels = ", ".join(sorted(fp.channels)[:3])
                    sw.add_line(f"  {nick:<15} {fp.msg_count:>4} msgs  "
                                f"{len(fp.bigrams)} bi  {len(fp.trigrams)} tri  "
                                f"[{channels}]")
            else:
                sw.add_line("  No saved fingerprints")
            self._chat_dirty = True
            self.dirty = True
            return

        if target:
            fp = scoring.bot_fingerprints.get(target.lower())
            if not fp:
                await self.ui_queue.put(("status", f"No fingerprint for {target}"))
                return
            sw = self._status_win()
            sw.add_line(f"=== Bot Fingerprint: {fp.nick} ===")
            sw.add_line(f"  Messages     : {fp.msg_count}")
            sw.add_line(f"  Channels     : {', '.join(sorted(fp.channels))}")
            sw.add_line(f"  Vocabulary   : {len(fp.word_vocab)} unique words")
            sw.add_line(f"  Bigrams      : {len(fp.bigrams)}")
            sw.add_line(f"  Trigrams     : {len(fp.trigrams)}")
            sw.add_line(f"  First seen   : {time.strftime('%Y-%m-%d %H:%M', time.localtime(fp.first_seen))}")
            sw.add_line(f"  Last seen    : {time.strftime('%Y-%m-%d %H:%M', time.localtime(fp.last_seen))}")
            if fp.sample_messages:
                sw.add_line("")
                sw.add_line("  Sample messages:")
                for msg in fp.sample_messages[:5]:
                    sw.add_line(f"    {msg[:80]}")
            self._chat_dirty = True
            self.dirty = True
        else:
            await self.ui_queue.put(("status", "Usage: /fingerprint <nick> | list"))

    async def _slash_savefp(self, args, extra, line):
        """Manually save all bot fingerprints to disk."""
        if _NO_AI:
            await self.ui_queue.put(("status", "[savefp] disabled by --no-ai")); return

        client = self._active_client()
        client.scoring.save_fingerprints()
        count = len(client.scoring.bot_fingerprints)
        await self.ui_queue.put(("status", f"Saved {count} bot fingerprint(s) to disk"))

    async def _slash_behavior(self, args, extra, line):
        """Show behavioral analysis for a user.

        Usage: /behavior <nick>
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[behavior] disabled by --no-ai")); return

        nick = (args or "").strip()
        if not nick:
            await self.ui_queue.put(("status", "Usage: /behavior <nick>"))
            return

        client = self._active_client()
        scoring = client.scoring
        u_state = client.users.get(nick)
        if not u_state:
            await self.ui_queue.put(("status", f"No data for {nick} in this session"))
            return

        # Sentiment trend
        sent_trend = scoring.get_sentiment_trend(nick)
        # Behavioral anomaly
        sent_history = scoring._sentiment_history.get(nick, deque())
        latest_sent = sent_history[-1]["score"] if sent_history else 0.0
        anomaly = scoring.behavioral.update(nick, "dummy", latest_sent)

        sw = self._status_win()
        sw.add_line(f"=== Behavioral Analysis: {nick} ===")
        sw.add_line("")
        sw.add_line("  ── Sentiment ─────────────────────────────")
        sw.add_line(f"  Trend       : {sent_trend['trend']}")
        sw.add_line(f"  Avg score   : {sent_trend['avg_score']:+.3f}")
        sw.add_line(f"  Volatility  : {sent_trend['volatility']:.3f}")
        sw.add_line("")
        sw.add_line("  ── Behavioral Anomalies ──────────────────")
        sw.add_line(f"  Anomaly score : {anomaly['anomaly_score']:.3f}")
        if anomaly.get("changed_aspects"):
            for aspect in anomaly["changed_aspects"]:
                sw.add_line(f"  ⚠ {aspect}")
        else:
            sw.add_line("  No significant anomalies")
        sw.add_line("")
        sw.add_line("  ── Activity ──────────────────────────────")
        sw.add_line(f"  Messages      : {u_state.total_msgs}")
        sw.add_line(f"  Avg length    : {u_state.avg_msg_length():.0f} chars")
        sw.add_line(f"  Messages/min  : {u_state.messages_per_minute():.1f}")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_biometrics(self, args, extra, line):
        """Show your own behavioral biometrics profile.

        Usage: /biometrics
        """
        client = self._active_client()
        bio = client.biometrics
        sw = self._status_win()
        sw.add_line("=== Your Behavioral Biometrics Profile ===")
        sw.add_line("")
        cadence = bio.get_typing_cadence_stats()
        sw.add_line("  ── Typing Cadence (flight times) ────────")
        sw.add_line(f"  Mean     : {cadence['mean']:.1f} ms")
        sw.add_line(f"  Std dev  : {cadence['std']:.1f} ms")
        sw.add_line(f"  Median   : {cadence['median']:.1f} ms")
        sw.add_line(f"  P10/P90  : {cadence['p10']:.1f} / {cadence['p90']:.1f} ms")
        sw.add_line(f"  Samples  : {cadence['samples']}")
        sw.add_line("")
        comp = bio.get_composition_stats()
        sw.add_line("  ── Message Composition ──────────────────")
        sw.add_line(f"  Mean     : {comp['mean']:.2f} s")
        sw.add_line(f"  Std dev  : {comp['std']:.2f} s")
        sw.add_line(f"  Median   : {comp['median']:.2f} s")
        sw.add_line(f"  Min/Max  : {comp['min']:.2f} / {comp['max']:.2f} s")
        sw.add_line(f"  Samples  : {comp['samples']}")
        sw.add_line("")
        resp = bio.get_response_latency_stats()
        sw.add_line("  ── Response Latency ─────────────────────")
        sw.add_line(f"  Mean     : {resp['mean']:.2f} s")
        sw.add_line(f"  Std dev  : {resp['std']:.2f} s")
        sw.add_line(f"  Median   : {resp['median']:.2f} s")
        sw.add_line(f"  Min/Max  : {resp['min']:.2f} / {resp['max']:.2f} s")
        sw.add_line(f"  Samples  : {resp['samples']}")
        sw.add_line("")
        bursts = bio.get_burst_stats()
        sw.add_line("  ── Typing Bursts ────────────────────────")
        sw.add_line(f"  Count        : {bursts['count']}")
        sw.add_line(f"  Avg duration : {bursts['avg_duration']:.2f} s")
        sw.add_line(f"  Avg rate     : {bursts['avg_rate']:.1f} keys/s")
        sw.add_line(f"  Avg keys     : {bursts['avg_keys']:.1f}")
        sw.add_line("")
        sw.add_line("  ── Summary ──────────────────────────────")
        sw.add_line(f"  Backspace ratio  : {bio.get_backspace_ratio():.2%}")
        sw.add_line(f"  Messages sent    : {bio._messages_sent}")
        sw.add_line(f"  Total keystrokes : {bio._total_keystrokes}")
        sw.add_line(f"  Human likelihood : {bio.get_human_likelihood():.0f}%")
        sw.add_line("")
        if "message-tags" in client._active_caps:
            sw.add_line("  IRCv3 message-tags: active")
        if "draft/typing" in client._active_caps:
            sw.add_line("  IRCv3 draft/typing: active")
        if "draft/thread" in client._active_caps:
            sw.add_line("  IRCv3 draft/thread: active")
        if "read-marker" in client._active_caps:
            sw.add_line("  IRCv3 read-marker: active")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_aistatus(self, args, extra, line):
        """Show status of all AI/ML pipeline components.

        Usage: /aistatus
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[aistatus] disabled by --no-ai")); return

        client = self._active_client()
        scoring = client.scoring
        detector = scoring.ai_detector

        sw = self._status_win()
        sw.add_line("=== AI/ML Pipeline Status ===")
        sw.add_line("")
        sw.add_line("  ── Core Detector ─────────────────────────")
        sw.add_line(f"  Enabled       : {detector.enabled}")
        sw.add_line(f"  Active model  : {detector.active_detect_model}")
        sw.add_line(f"  Cache hits    : {len(detector._pred_cache)}")
        sw.add_line("")
        sw.add_line("  ── Bot Fingerprints ──────────────────────")
        sw.add_line(f"  Saved bots    : {len(scoring.bot_fingerprints)}")
        total_fp_msgs = sum(fp.msg_count for fp in scoring.bot_fingerprints.values())
        sw.add_line(f"  Total msgs    : {total_fp_msgs}")
        sw.add_line("")
        sw.add_line("  ── Sentiment Analysis ────────────────────")
        total_sent = sum(len(h) for h in scoring._sentiment_history.values())
        sw.add_line(f"  Users tracked : {len(scoring._sentiment_history)}")
        sw.add_line(f"  Messages      : {total_sent}")
        sw.add_line("")
        sw.add_line("  ── Behavioral Anomaly ────────────────────")
        sw.add_line(f"  Users tracked : {len(scoring.behavioral._user_profiles)}")
        sw.add_line("")
        sw.add_line("  ── Topic Detection ───────────────────────")
        sw.add_line(f"  Topic models  : {len(_TOPIC_KEYWORDS)}")
        sw.add_line("")
        sw.add_line("  ── Semantic Similarity ───────────────────")
        sw.add_line(f"  Messages      : {len(scoring.semantic._message_history)}")
        sw.add_line("")
        sw.add_line("  ── Thread Tracker ────────────────────────")
        sw.add_line(f"  Active threads: {len(scoring.threads._active_threads)}")
        sw.add_line("")
        sw.add_line("  ── Cross-Channel Detection ───────────────")
        sw.add_line(f"  Nicks tracked : {len(scoring.cross_channel._nick_channels)}")
        sw.add_line(f"  Alerts        : {len(scoring.cross_channel._cross_channel_alerts)}")
        sw.add_line("")
        sw.add_line("  ── Blocklist ─────────────────────────────")
        sw.add_line(f"  N-grams       : {len(scoring.blocklisted_ngrams)}")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_remind(self, args, extra, line):
        """Create, list, or delete reminders.

        Usage:
          /remind in 30m Buy groceries
          /remind at 14:30 Meeting with team
          /remind tomorrow Submit report
          /remind list
          /remind delete <id>
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[remind] disabled by --no-ai")); return

        client = self._active_client()
        if not hasattr(client, 'scoring'):
            await self.ui_queue.put(("status", "[remind] AI system not initialized"))
            return

        rm = client.scoring.reminders
        sw = self._status_win()

        if not args:
            await self.ui_queue.put(("status", "Usage: /remind <in Xm|at HH:MM|tomorrow|list|delete <id>> <message>"))
            return

        parts = args.split(maxsplit=1)
        subcmd = parts[0].lower()

        if subcmd == "list":
            reminders = rm.list_reminders()
            if not reminders:
                sw.add_line("-!- No active reminders")
            else:
                sw.add_line("-!- Active reminders:")
                for r in reminders:
                    due_str = time.strftime('%H:%M', time.localtime(r['due_at']))
                    sw.add_line(f"  [{r['id']}] {due_str} - {r['message']}")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "delete":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /remind delete <id>"))
                return
            try:
                rid = int(parts[1])
                if rm.delete_reminder(rid):
                    sw.add_line(f"-!- Reminder {rid} deleted")
                else:
                    sw.add_line(f"-!- Reminder {rid} not found")
            except ValueError:
                await self.ui_queue.put(("status", "Invalid reminder ID"))
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd in ("in", "at"):
            if len(parts) < 2:
                await self.ui_queue.put(("status", f"Usage: /remind {subcmd} <time> <message>"))
                return
            rest = parts[1].split(maxsplit=1)
            if len(rest) < 2:
                await self.ui_queue.put(("status", f"Usage: /remind {subcmd} <time> <message>"))
                return
            time_spec = rest[0]
            message = rest[1]
            if subcmd == "in":
                success = rm.add_reminder_in(time_spec, message)
            else:
                success = rm.add_reminder_at(time_spec, message)
            if success:
                sw.add_line(f"-!- Reminder set: {message}")
            else:
                await self.ui_queue.put(("status", f"Failed to parse time: {time_spec}"))
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "tomorrow":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /remind tomorrow <message>"))
                return
            message = parts[1]
            success = rm.add_reminder_tomorrow(message)
            if success:
                sw.add_line(f"-!- Reminder set for tomorrow: {message}")
            else:
                await self.ui_queue.put(("status", "Failed to set reminder for tomorrow"))
            self._chat_dirty = True
            self.dirty = True
            return

        await self.ui_queue.put(("status", "Usage: /remind <in Xm|at HH:MM|tomorrow|list|delete <id>> <message>"))

    async def _slash_watch(self, args, extra, line):
        """Add a nick to the watch list.

        Usage: /watch <nick> [channel]
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[watch] disabled by --no-ai")); return

        client = self._active_client()
        if not hasattr(client, 'scoring'):
            await self.ui_queue.put(("status", "[watch] AI system not initialized"))
            return

        if not args:
            await self.ui_queue.put(("status", "Usage: /watch <nick> [channel]"))
            return

        parts = args.split()
        nick = parts[0]
        channel = parts[1] if len(parts) > 1 else ""

        wm = client.scoring.watches
        sw = self._status_win()
        watcher = client.nick
        channels = [channel] if channel else []

        wm.add_watch(nick, watcher, channels=channels)
        sw.add_line(f"-!- Now watching {nick}" + (f" in {channel}" if channel else ""))
        self._chat_dirty = True
        self.dirty = True

    async def _slash_unwatch(self, args, extra, line):
        """Remove a nick from the watch list.

        Usage: /unwatch <nick> [channel]
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[unwatch] disabled by --no-ai")); return

        client = self._active_client()
        if not hasattr(client, 'scoring'):
            await self.ui_queue.put(("status", "[unwatch] AI system not initialized"))
            return

        if not args:
            await self.ui_queue.put(("status", "Usage: /unwatch <nick> [channel]"))
            return

        parts = args.split()
        nick = parts[0]
        channel = parts[1] if len(parts) > 1 else ""

        wm = client.scoring.watches
        sw = self._status_win()
        watcher = client.nick

        if wm.remove_watch(watcher, nick):
            sw.add_line(f"-!- No longer watching {nick}" + (f" in {channel}" if channel else ""))
        else:
            sw.add_line(f"-!- Not watching {nick}" + (f" in {channel}" if channel else ""))
        self._chat_dirty = True
        self.dirty = True

    async def _slash_snippet(self, args, extra, line):
        """Manage text snippets.

        Usage:
          /snippet add <name> <text>
          /snippet remove <name>
          /snippet list
          /snippet <name> (inserts snippet)
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[snippet] disabled by --no-ai")); return

        client = self._active_client()
        if not hasattr(client, 'scoring'):
            await self.ui_queue.put(("status", "[snippet] AI system not initialized"))
            return

        sm = client.scoring.snippets
        sw = self._status_win()

        if not args:
            await self.ui_queue.put(("status", "Usage: /snippet <add|remove|list|name> [text]"))
            return

        parts = args.split(maxsplit=1)
        subcmd = parts[0].lower()

        if subcmd == "add":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /snippet add <name> <text>"))
                return
            name_and_text = parts[1].split(maxsplit=1)
            if len(name_and_text) < 2:
                await self.ui_queue.put(("status", "Usage: /snippet add <name> <text>"))
                return
            name, text = name_and_text
            sm.add_snippet(name, text)
            sw.add_line(f"-!- Snippet '{name}' added")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "remove":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /snippet remove <name>"))
                return
            name = parts[1]
            if sm.remove_snippet(name):
                sw.add_line(f"-!- Snippet '{name}' removed")
            else:
                sw.add_line(f"-!- Snippet '{name}' not found")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "list":
            snippets = sm.list_snippets()
            if not snippets:
                sw.add_line("-!- No snippets saved")
            else:
                sw.add_line("-!- Saved snippets:")
                for name, text in snippets.items():
                    preview = text[:50] + ("..." if len(text) > 50 else "")
                    sw.add_line(f"  {name}: {preview}")
            self._chat_dirty = True
            self.dirty = True
            return

        # Insert snippet into input buffer
        text = sm.get_snippet(subcmd)
        if text:
            cur_win = self.get_current_window()
            target = (cur_win.name if cur_win.name not in ("*status*", "*dashboard*")
                      else self.current_channel or DEFAULT_CHANNEL)
            self._active_client().cmd_msg(target, text)
            sw.add_line(f"-!- Inserted snippet '{subcmd}'")
        else:
            await self.ui_queue.put(("status", f"Snippet '{subcmd}' not found"))
        self._chat_dirty = True
        self.dirty = True

    async def _slash_chstats(self, args, extra, line):
        """Show channel statistics.

        Usage: /chstats [channel]
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[chstats] disabled by --no-ai")); return

        client = self._active_client()
        if not hasattr(client, 'scoring'):
            await self.ui_queue.put(("status", "[chstats] AI system not initialized"))
            return

        channel = args or self.current_channel or ""
        if not channel or not channel.startswith("#"):
            await self.ui_queue.put(("status", "Usage: /chstats [#channel]"))
            return

        stats = client.scoring.channel_stats.get_channel_stats(channel)
        sw = self._status_win()

        if not stats:
            sw.add_line(f"-!- No statistics for {channel}")
            self._chat_dirty = True
            self.dirty = True
            return

        sw.add_line(f"=== Channel Stats: {channel} ===")
        sw.add_line(f"  Total messages : {stats['total_messages']}")
        sw.add_line(f"  Unique users   : {stats['unique_users']}")
        sw.add_line(f"  Avg msg length : {stats['avg_msg_length']:.1f}")

        if stats['top_talkers']:
            sw.add_line("  Top talkers:")
            for nick, count in stats['top_talkers'][:5]:
                sw.add_line(f"    {nick}: {count} messages")

        if stats['hourly_activity']:
            sw.add_line("  Hourly activity (top 5):")
            sorted_hours = sorted(stats['hourly_activity'].items(), key=lambda x: x[1], reverse=True)[:5]
            for hour, count in sorted_hours:
                sw.add_line(f"    {hour:02d}:00 - {count} messages")

        self._chat_dirty = True
        self.dirty = True

    async def _slash_rss(self, args, extra, line):
        """Manage RSS feed subscriptions.

        Usage:
          /rss add <url> [channel]
          /rss remove <url>
          /rss list
          /rss poll
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[rss] disabled by --no-ai")); return

        client = self._active_client()
        if not hasattr(client, 'scoring'):
            await self.ui_queue.put(("status", "[rss] AI system not initialized"))
            return

        rm = client.scoring.rss
        sw = self._status_win()

        if not args:
            await self.ui_queue.put(("status", "Usage: /rss <add|remove|list|poll> [url] [channel]"))
            return

        parts = args.split(maxsplit=2)
        subcmd = parts[0].lower()

        if subcmd == "add":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /rss add <url> [channel]"))
                return
            url_and_channel = parts[1].split()
            url = url_and_channel[0]
            channel = url_and_channel[1] if len(url_and_channel) > 1 else ""
            if rm.add_feed(url, channel):
                sw.add_line(f"-!- RSS feed added: {url}" + (f" -> {channel}" if channel else ""))
            else:
                sw.add_line(f"-!- Feed already exists: {url}")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "remove":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /rss remove <url>"))
                return
            url = parts[1]
            if rm.remove_feed(url):
                sw.add_line(f"-!- RSS feed removed: {url}")
            else:
                sw.add_line(f"-!- Feed not found: {url}")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "list":
            feeds = rm.list_feeds()
            if not feeds:
                sw.add_line("-!- No RSS feeds subscribed")
            else:
                sw.add_line("-!- RSS feeds:")
                for feed in feeds:
                    sw.add_line(f"  {feed['url']}" + (f" -> {feed['channel']}" if feed['channel'] else ""))
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "poll":
            new_items = await rm.poll_all()
            if new_items:
                sw.add_line(f"-!- Polled RSS feeds, {len(new_items)} new items:")
                for item in new_items[:10]:
                    sw.add_line(f"  [{item['feed']}] {item['title']}")
            else:
                sw.add_line("-!- No new items from RSS feeds")
            self._chat_dirty = True
            self.dirty = True
            return

        await self.ui_queue.put(("status", "Usage: /rss <add|remove|list|poll> [url] [channel]"))

    async def _slash_todo(self, args, extra, line):
        """Manage todo list.

        Usage:
          /todo add <text> [@priority] [#due] [+tag ...]
          /todo done <id>
          /todo undo <id>
          /todo remove <id>
          /todo edit <id> [text]
          /todo list [priority|tag|channel]
          /todo clear
        """
        client = self._active_client()
        if not hasattr(client, 'scoring'):
            await self.ui_queue.put(("status", "[todo] scoring engine not initialized"))
            return
        tm = client.scoring.todos
        sw = self._status_win()

        if not args:
            todos = tm.list_todos()
            if not todos:
                sw.add_line("-!- No active todos")
            else:
                sw.add_line("=== Todo List ===")
                _prio_sym = {"urgent": "!!", "high": "!", "medium": "-", "low": "~"}
                for t in todos:
                    sym = _prio_sym.get(t.get("priority", "medium"), "-")
                    mark = "\u2713" if t["completed"] else "\u25cb"
                    due = f" (due:{t['due']})" if t.get("due") else ""
                    tags = f" [{','.join(t['tags'])}]" if t.get("tags") else ""
                    sw.add_line(f"  {mark} [{t['id'][:12]}] {sym} {t['text'][:80]}{due}{tags}")
            self._chat_dirty = True
            self.dirty = True
            return

        parts = args.split(maxsplit=1)
        subcmd = parts[0].lower()

        if subcmd == "add":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /todo add <text> [@priority] [#due] [+tag]"))
                return
            rest = parts[1]
            priority = "medium"
            due = ""
            tags = []
            for m in re.finditer(r'@(\w+)', rest):
                val = m.group(1).lower()
                if val in ("low", "medium", "high", "urgent"):
                    priority = val
            for m in re.finditer(r'#(\S+)', rest):
                due = m.group(1)
            for m in re.finditer(r'\+(\w+)', rest):
                tags.append(m.group(1))
            text = re.sub(r'[@#+]\S+\s*', '', rest).strip()
            if not text:
                text = rest.strip()
            channel = self.current_channel or ""
            todo = tm.add(text, priority=priority, due=due, tags=tags, channel=channel)
            sw.add_line(f"-!- Todo added [{todo['id'][:12]}]: {text} @{priority}")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd in ("done", "complete"):
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /todo done <id>"))
                return
            result = tm.complete(parts[1].strip())
            if result:
                sw.add_line(f"-!- Completed: {result['text'][:60]}")
            else:
                sw.add_line(f"-!- Todo '{parts[1]}' not found or already done")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd in ("undo", "uncomplete"):
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /todo undo <id>"))
                return
            result = tm.uncomplete(parts[1].strip())
            if result:
                sw.add_line(f"-!- Reopened: {result['text'][:60]}")
            else:
                sw.add_line(f"-!- Todo '{parts[1]}' not found or not completed")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd in ("remove", "delete", "rm"):
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /todo remove <id>"))
                return
            if tm.remove(parts[1].strip()):
                sw.add_line(f"-!- Todo removed")
            else:
                sw.add_line(f"-!- Todo '{parts[1]}' not found")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "edit":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /todo edit <id> [text] [@priority] [#due]"))
                return
            edit_parts = parts[1].split(maxsplit=1)
            tid = edit_parts[0].strip()
            new_text = edit_parts[1] if len(edit_parts) > 1 else None
            new_prio = None
            new_due = None
            if new_text:
                for m in re.finditer(r'@(\w+)', new_text):
                    val = m.group(1).lower()
                    if val in ("low", "medium", "high", "urgent"):
                        new_prio = val
                for m in re.finditer(r'#(\S+)', new_text):
                    new_due = m.group(1)
                cleaned = re.sub(r'[@#+]\S+\s*', '', new_text).strip()
                if cleaned:
                    new_text = cleaned
            result = tm.edit(tid, text=new_text, priority=new_prio, due=new_due)
            if result:
                sw.add_line(f"-!- Todo updated: {result['text'][:60]}")
            else:
                sw.add_line(f"-!- Todo '{tid}' not found")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "clear":
            removed = tm.clear_completed()
            sw.add_line(f"-!- Cleared {removed} completed todo(s)")
            self._chat_dirty = True
            self.dirty = True
            return

        await self.ui_queue.put(("status", "Usage: /todo [add|done|undo|remove|edit|list|clear]"))

    async def _slash_pomodoro(self, args, extra, line):
        """Pomodoro timer for focused work sessions.

        Usage:
          /pomodoro start
          /pomodoro stop
          /pomodoro status
          /pomodoro config [work N] [break N] [long N] [sessions N]
        """
        client = self._active_client()
        if not hasattr(client, 'scoring'):
            await self.ui_queue.put(("status", "[pomodoro] scoring engine not initialized"))
            return
        pm = client.scoring.pomodoro
        sw = self._status_win()

        if not args:
            args = "status"

        parts = args.split()
        subcmd = parts[0].lower()

        if subcmd == "start":
            result = pm.start(self.ui_queue, client.nick)
            if result:
                sw.add_line(f"-!- {result}")
            else:
                sw.add_line("-!- Pomodoro already running")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "stop":
            result = pm.stop()
            if result:
                sw.add_line(f"-!- {result}")
            else:
                sw.add_line("-!- No pomodoro running")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "status":
            st = pm.status()
            sw.add_line("=== Pomodoro Status ===")
            sw.add_line(f"  Running: {'yes' if st['running'] else 'no'}")
            sw.add_line(f"  Sessions completed: {st['completed_sessions']}")
            sw.add_line(f"  Total work: {st['total_work_minutes']} min")
            cfg = st['config']
            sw.add_line(f"  Work: {cfg['work_min']}m  Break: {cfg['short_break_min']}m  "
                        f"Long: {cfg['long_break_min']}m  Long every: {cfg['sessions_before_long']}")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "config":
            work = short_break = long_break = sessions = None
            i = 1
            while i < len(parts):
                if parts[i] == "work" and i + 1 < len(parts):
                    try: work = int(parts[i + 1]); i += 2
                    except ValueError: i += 1
                elif parts[i] == "break" and i + 1 < len(parts):
                    try: short_break = int(parts[i + 1]); i += 2
                    except ValueError: i += 1
                elif parts[i] == "long" and i + 1 < len(parts):
                    try: long_break = int(parts[i + 1]); i += 2
                    except ValueError: i += 1
                elif parts[i] == "sessions" and i + 1 < len(parts):
                    try: sessions = int(parts[i + 1]); i += 2
                    except ValueError: i += 1
                else:
                    i += 1
            pm.configure(
                work=work or pm.work_duration // 60,
                short_break=short_break or pm.short_break // 60,
                long_break=long_break or pm.long_break // 60,
                sessions=sessions or pm.sessions_before_long,
            )
            sw.add_line(f"-!- Pomodoro configured: work={pm.work_duration // 60}m "
                        f"break={pm.short_break // 60}m long={pm.long_break // 60}m "
                        f"sessions={pm.sessions_before_long}")
            self._chat_dirty = True
            self.dirty = True
            return

        await self.ui_queue.put(("status", "Usage: /pomodoro [start|stop|status|config]"))

    async def _slash_note(self, args, extra, line):
        """Scratchpad notes manager.

        Usage:
          /note add <text> [category]
          /note edit <id> <text>
          /note remove <id>
          /note list [category]
          /note search <query>
          /note pin <id>
          /note unpin <id>
          /note categories
        """
        client = self._active_client()
        if not hasattr(client, 'scoring'):
            await self.ui_queue.put(("status", "[note] scoring engine not initialized"))
            return
        nm = client.scoring.notes
        sw = self._status_win()

        if not args:
            notes = nm.list_notes()
            if not notes:
                sw.add_line("-!- No notes saved")
            else:
                sw.add_line("=== Notes ===")
                for n in notes[:20]:
                    pin = "\u2605" if n.get("pinned") else " "
                    cat = n.get("category", "general")
                    sw.add_line(f"  {pin} [{n['id'][:12]}] [{cat}] {n['text'][:70]}")
            self._chat_dirty = True
            self.dirty = True
            return

        parts = args.split(maxsplit=1)
        subcmd = parts[0].lower()

        if subcmd == "add":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /note add <text> [category]"))
                return
            rest = parts[1]
            category = "general"
            add_parts = rest.rsplit(maxsplit=1)
            if len(add_parts) == 2 and not add_parts[1].startswith(" ") and len(add_parts[1]) < 20:
                category = add_parts[1].lower()
                text = add_parts[0]
            else:
                text = rest
            note = nm.add(text, category=category)
            sw.add_line(f"-!- Note added [{note['id'][:12]}]: {text[:60]}")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "edit":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /note edit <id> <text>"))
                return
            edit_parts = parts[1].split(maxsplit=1)
            if len(edit_parts) < 2:
                await self.ui_queue.put(("status", "Usage: /note edit <id> <text>"))
                return
            result = nm.edit(edit_parts[0].strip(), text=edit_parts[1])
            if result:
                sw.add_line(f"-!- Note updated: {result['text'][:60]}")
            else:
                sw.add_line(f"-!- Note '{edit_parts[0]}' not found")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd in ("remove", "delete", "rm"):
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /note remove <id>"))
                return
            if nm.remove(parts[1].strip()):
                sw.add_line("-!- Note removed")
            else:
                sw.add_line(f"-!- Note '{parts[1]}' not found")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "search":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /note search <query>"))
                return
            results = nm.search(parts[1])
            if not results:
                sw.add_line("-!- No matching notes")
            else:
                sw.add_line(f"=== Search: {parts[1]} ===")
                for n in results[:15]:
                    pin = "\u2605" if n.get("pinned") else " "
                    sw.add_line(f"  {pin} [{n['id'][:12]}] {n['text'][:70]}")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "pin":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /note pin <id>"))
                return
            result = nm.edit(parts[1].strip(), pinned=True)
            if result:
                sw.add_line(f"-!- Note pinned: {result['text'][:60]}")
            else:
                sw.add_line(f"-!- Note '{parts[1]}' not found")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "unpin":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /note unpin <id>"))
                return
            result = nm.edit(parts[1].strip(), pinned=False)
            if result:
                sw.add_line(f"-!- Note unpinned: {result['text'][:60]}")
            else:
                sw.add_line(f"-!- Note '{parts[1]}' not found")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd in ("categories", "cats"):
            cats = nm.list_categories()
            if not cats:
                sw.add_line("-!- No categories")
            else:
                sw.add_line(f"-!- Categories: {', '.join(cats)}")
            self._chat_dirty = True
            self.dirty = True
            return

        await self.ui_queue.put(("status", "Usage: /note [add|edit|remove|list|search|pin|unpin|categories]"))

    async def _slash_bookmark(self, args, extra, line):
        """Bookmark manager for channels, nicks, URLs, and items.

        Usage:
          /bookmark add <target> [description] [type:channel|nick|url|general] [+tag ...]
          /bookmark remove <id>
          /bookmark list [type]
          /bookmark search <query>
        """
        client = self._active_client()
        if not hasattr(client, 'scoring'):
            await self.ui_queue.put(("status", "[bookmark] scoring engine not initialized"))
            return
        bm = client.scoring.bookmarks
        sw = self._status_win()

        if not args:
            bookmarks = bm.list_bookmarks()
            if not bookmarks:
                sw.add_line("-!- No bookmarks saved")
            else:
                sw.add_line("=== Bookmarks ===")
                for b in bookmarks[:20]:
                    tags = f" [{','.join(b['tags'])}]" if b.get("tags") else ""
                    desc = f" - {b['description'][:40]}" if b.get("description") else ""
                    sw.add_line(f"  [{b['type']}] {b['target']}{desc}{tags}")
            self._chat_dirty = True
            self.dirty = True
            return

        parts = args.split(maxsplit=1)
        subcmd = parts[0].lower()

        if subcmd == "add":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /bookmark add <target> [desc] [type:X] [+tag]"))
                return
            rest = parts[1]
            btype = "channel"
            tags = []
            for m in re.finditer(r'type:(\w+)', rest):
                val = m.group(1).lower()
                if val in ("channel", "nick", "url", "general"):
                    btype = val
            for m in re.finditer(r'\+(\w+)', rest):
                tags.append(m.group(1))
            cleaned = re.sub(r'type:\w+\s*', '', rest)
            cleaned = re.sub(r'\+\w+\s*', '', cleaned)
            cleaned = cleaned.strip()
            add_parts = cleaned.split(maxsplit=1)
            target = add_parts[0]
            description = add_parts[1] if len(add_parts) > 1 else ""
            if target.startswith("#"):
                btype = "channel"
            result = bm.add(target, description=description, tags=tags, btype=btype)
            sw.add_line(f"-!- Bookmarked [{btype}]: {target}")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd in ("remove", "delete", "rm"):
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /bookmark remove <id>"))
                return
            if bm.remove(parts[1].strip()):
                sw.add_line("-!- Bookmark removed")
            else:
                sw.add_line(f"-!- Bookmark '{parts[1]}' not found")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd == "search":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /bookmark search <query>"))
                return
            results = bm.search(parts[1])
            if not results:
                sw.add_line("-!- No matching bookmarks")
            else:
                sw.add_line(f"=== Bookmark search: {parts[1]} ===")
                for b in results[:15]:
                    desc = f" - {b['description'][:40]}" if b.get("description") else ""
                    sw.add_line(f"  [{b['type']}] {b['target']}{desc}")
            self._chat_dirty = True
            self.dirty = True
            return

        await self.ui_queue.put(("status", "Usage: /bookmark [add|remove|list|search]"))

    async def _slash_timer(self, args, extra, line):
        """Countdown timer with notification.

        Usage:
          /timer <duration> [name]   (e.g. /timer 5m tea, /timer 30s)
          /timer list
          /timer cancel <id>
        """
        client = self._active_client()
        if not hasattr(client, 'scoring'):
            await self.ui_queue.put(("status", "[timer] scoring engine not initialized"))
            return
        tmr = client.scoring.timers
        tmr.set_ui_queue(self.ui_queue)
        sw = self._status_win()

        if not args:
            await self.ui_queue.put(("status", "Usage: /timer <duration> [name] | list | cancel <id>"))
            return

        parts = args.split(maxsplit=1)
        subcmd = parts[0].lower()

        if subcmd == "list":
            timers = tmr.list_timers()
            if not timers:
                sw.add_line("-!- No active timers")
            else:
                sw.add_line("=== Active Timers ===")
                for t in timers:
                    sw.add_line(f"  [{t['id']}] {t['name']} - {t['remaining']}")
            self._chat_dirty = True
            self.dirty = True
            return

        if subcmd in ("cancel", "stop"):
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /timer cancel <id>"))
                return
            if tmr.cancel(parts[1].strip()):
                sw.add_line("-!- Timer cancelled")
            else:
                sw.add_line(f"-!- Timer '{parts[1]}' not found")
            self._chat_dirty = True
            self.dirty = True
            return

        duration_str = parts[0]
        name = parts[1] if len(parts) > 1 else "timer"

        dur_match = re.match(r'^(\d+)([smh]?)$', duration_str.lower())
        if not dur_match:
            await self.ui_queue.put(("status", "Usage: /timer <number>[s|m|h] [name]"))
            return
        val = int(dur_match.group(1))
        unit = dur_match.group(2) or "m"
        multipliers = {"s": 1, "m": 60, "h": 3600}
        seconds = val * multipliers.get(unit, 60)

        tid = tmr.start(name, seconds)
        mins, secs = divmod(seconds, 60)
        dur_display = f"{mins}m {secs}s" if mins else f"{secs}s"
        sw.add_line(f"-!- Timer '{name}' started: {dur_display} [{tid}]")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_join(self, args, extra, line):
        if args:
            self._active_client().cmd_join(args)

    async def _slash_part(self, args, extra, line):
        ch = args or self.current_channel or ""
        if ch:
            self._active_client().cmd_part(ch, extra or None)

    async def _slash_nick(self, args, extra, line):
        if args:
            self._active_client().cmd_nick(args)

    async def _slash_msg(self, args, extra, line):
        if args and extra:
            self._active_client().cmd_msg(args, extra)
            win = self.ensure_window(args, is_channel=False)
            win.add_line(f"<{self._active_client().nick}> {extra}")
            self.current_window_index = self.windows.index(win)
            self.current_channel = args
            self._unread_windows.discard(args)
            self._chat_dirty = self._userlist_dirty = self._input_dirty = True
            self.dirty = True
        else:
            await self.ui_queue.put(("status", "Usage: /msg <nick> <text>"))

    async def _slash_query(self, args, extra, line):
        if args:
            wk = self._wk(self._active_server_id, args)
            is_new = wk not in self.window_by_name
            win = self.ensure_window(args, is_channel=False)
            self.current_window_index = self.windows.index(win)
            self.current_channel = args
            self._unread_windows.discard(args)
            self._chat_dirty = self._userlist_dirty = self._input_dirty = True
            if is_new:
                win.add_line(f"** Query with {args} opened **", timestamp=False)
            if extra:
                self._active_client().cmd_msg(args, extra)
                win.add_line(f"<{self._active_client().nick}> {extra}")
        else:
            await self.ui_queue.put(("status", "Usage: /query <nick> [message]"))

    async def _slash_notice(self, args, extra, line):
        if args and extra:
            self._active_client().cmd_notice(args, extra)
            await self.ui_queue.put(("status", f"-> NOTICE to {args}: {extra}"))
        else:
            await self.ui_queue.put(("status", "Usage: /notice <nick> <text>"))

    async def _slash_away(self, args, extra, line):
        self._active_client().cmd_away(args)
        await self.ui_queue.put(("status", f"You are now away: {args}" if args else "You are now away"))

    async def _slash_back(self, args, extra, line):
        self._active_client().cmd_away()
        await self.ui_queue.put(("status", "You are no longer away"))

    async def _slash_invite(self, args, extra, line):
        if args:
            channel = extra or self.current_channel or ""
            if channel:
                self._active_client().cmd_invite(args, channel)
                await self.ui_queue.put(("status", f"Inviting {args} to {channel}"))
            else:
                await self.ui_queue.put(("status", "Usage: /invite <nick> [channel]"))

    async def _slash_op(self, args, extra, line):
        if args and self.current_channel:
            self._active_client().cmd_mode(self.current_channel, f"+o {args}")

    async def _slash_deop(self, args, extra, line):
        if args and self.current_channel:
            self._active_client().cmd_mode(self.current_channel, f"-o {args}")

    async def _slash_voice(self, args, extra, line):
        if args and self.current_channel:
            self._active_client().cmd_mode(self.current_channel, f"+v {args}")

    async def _slash_devoice(self, args, extra, line):
        if args and self.current_channel:
            self._active_client().cmd_mode(self.current_channel, f"-v {args}")

    async def _slash_hop(self, args, extra, line):
        if args and self.current_channel:
            self._active_client().cmd_mode(self.current_channel, f"+h {args}")

    async def _slash_dehop(self, args, extra, line):
        if args and self.current_channel:
            self._active_client().cmd_mode(self.current_channel, f"-h {args}")

    async def _slash_ban(self, args, extra, line):
        if not self.current_channel:
            await self.ui_queue.put(("status", "No channel active"))
            return
        if args.strip() == "-l":
            self._active_client().send_raw(f"MODE {self.current_channel} +b")
            await self.ui_queue.put(("status", f"Fetching ban list for {self.current_channel}..."))
            return
        if args:
            mask = args if "!" in args or "@" in args else f"{args}!*@*"
            self._active_client().cmd_mode(self.current_channel, f"+b {mask}")

    async def _slash_quietlist(self, args, extra, line):
        """Fetch the quiet list (+q) for the current channel."""
        if not self.current_channel:
            await self.ui_queue.put(("status", "No channel active"))
            return
        self._active_client().send_raw(f"MODE {self.current_channel} +q")
        await self.ui_queue.put(("status", f"Fetching quiet list for {self.current_channel}..."))

    async def _slash_unban(self, args, extra, line):
        if args and self.current_channel:
            self._active_client().cmd_mode(self.current_channel, f"-b {args}")

    async def _slash_chanmute(self, args, extra, line):
        """Mute a user in the current channel (mode +q, requires IRCv3 or supported server)."""
        if not self.current_channel:
            await self.ui_queue.put(("status", "No channel active"))
            return
        if not args:
            await self.ui_queue.put(("status", "Usage: /chanmute <nick>"))
            return
        nick = args.strip()
        self._active_client().cmd_mode(self.current_channel, f"+q {nick}")
        await self.ui_queue.put(("status", f"Muted {nick} in {self.current_channel}"))

    async def _slash_chanunmute(self, args, extra, line):
        """Unmute a user in the current channel (mode -q)."""
        if not self.current_channel:
            await self.ui_queue.put(("status", "No channel active"))
            return
        if not args:
            await self.ui_queue.put(("status", "Usage: /chanunmute <nick>"))
            return
        nick = args.strip()
        self._active_client().cmd_mode(self.current_channel, f"-q {nick}")
        await self.ui_queue.put(("status", f"Unmuted {nick} in {self.current_channel}"))

    async def _slash_halfop(self, args, extra, line):
        """Give halfop (+h) to a user in the current channel."""
        if args and self.current_channel:
            self._active_client().cmd_mode(self.current_channel, f"+h {args}")

    async def _slash_dehalfop(self, args, extra, line):
        """Remove halfop (-h) from a user in the current channel."""
        if args and self.current_channel:
            self._active_client().cmd_mode(self.current_channel, f"-h {args}")

    async def _slash_admin(self, args, extra, line):
        """Give admin (+a) to a user in the current channel."""
        if args and self.current_channel:
            self._active_client().cmd_mode(self.current_channel, f"+a {args}")

    async def _slash_deadmin(self, args, extra, line):
        """Remove admin (-a) from a user in the current channel."""
        if args and self.current_channel:
            self._active_client().cmd_mode(self.current_channel, f"-a {args}")

    async def _slash_owner(self, args, extra, line):
        """Give owner (+q) to a user in the current channel."""
        if args and self.current_channel:
            self._active_client().cmd_mode(self.current_channel, f"+q {args}")

    async def _slash_deowner(self, args, extra, line):
        """Remove owner (-q) from a user in the current channel."""
        if args and self.current_channel:
            self._active_client().cmd_mode(self.current_channel, f"-q {args}")

    async def _slash_cap(self, args, extra, line):
        """View or request IRCv3 capabilities.

        Usage:
          /cap              — show currently active capabilities
          /cap ls           — show what the server offers
          /cap req <cap>    — request a capability
          /cap list         — list all active capabilities
        """
        client = self._active_client()
        sub = (args or "").strip().lower()
        if not sub or sub == "list":
            active = sorted(client._active_caps)
            if active:
                sw = self._status_win()
                sw.add_line(f"Active capabilities ({len(active)}):")
                for c in active:
                    val = client._cap_ls_values.get(c, "")
                    sw.add_line(f"  {c}" + (f" = {val}" if val else ""))
                self._chat_dirty = True
                self.dirty = True
            else:
                await self.ui_queue.put(("status", "No capabilities active"))
        elif sub == "ls":
            available = sorted(client._cap_ls_caps)
            if available:
                sw = self._status_win()
                sw.add_line(f"Server offers {len(available)} capabilities:")
                for c in available:
                    val = client._cap_ls_values.get(c, "")
                    owned = " [active]" if c in client._active_caps else ""
                    sw.add_line(f"  {c}" + (f" = {val}" if val else "") + owned)
                self._chat_dirty = True
                self.dirty = True
            else:
                await self.ui_queue.put(("status", "No capabilities advertised (try /cap ls after reconnect)"))
        elif sub == "req":
            cap_name = extra.strip()
            if cap_name:
                client.send_raw(f"CAP REQ :{cap_name}")
                await self.ui_queue.put(("status", f"Requesting capability: {cap_name}"))
            else:
                await self.ui_queue.put(("status", "Usage: /cap req <capability>"))
        else:
            await self.ui_queue.put(("status",
                "Usage: /cap [list|ls|req <cap>]"))

    async def _slash_sasl(self, args, extra, line):
        """View or configure SASL authentication.

        Usage:
          /cap sasl          — show current SASL configuration
          /cap sasl <mech>   — set SASL mechanism (PLAIN, EXTERNAL, SCRAM-SHA-256, ECDSA-NIST256P-CHALLENGE)
        """
        sub = (args or "").strip().upper()
        if not sub:
            sw = self._status_win()
            sw.add_line("SASL Configuration:")
            sw.add_line(f"  Mechanism : {SASL_MECHANISM}")
            sw.add_line(f"  Cert path : {SASL_CERT or '(not set)'}")
            sw.add_line(f"  Key path  : {SASL_KEY or '(not set)'}")
            has_pass = "set" if NICKSERV_PASSWORD else "not set"
            sw.add_line(f"  Password  : {has_pass}")
            client = self._active_client()
            sasl_active = "sasl" in client._active_caps
            sw.add_line(f"  Status    : {'active' if sasl_active else 'not negotiated'}")
            sw.add_line("")
            sw.add_line("Supported mechanisms:")
            sw.add_line("  PLAIN                    — password-based (default)")
            sw.add_line("  SCRAM-SHA-256            — RFC-5802 SCRAM (password)")
            sw.add_line("  EXTERNAL                 — TLS client certificate")
            sw.add_line("  ECDSA-NIST256P-CHALLENGE — EC key (requires 'cryptography' pkg)")
            sw.add_line("")
            sw.add_line("Usage: /sasl <MECHANISM>")
            self._chat_dirty = True
            self.dirty = True
        elif sub in ("PLAIN", "EXTERNAL", "SCRAM-SHA-256", "ECDSA-NIST256P-CHALLENGE"):
            os.environ["IRC_SASL_MECHANISM"] = sub
            await self.ui_queue.put(("status",
                f"SASL mechanism set to {sub} — reconnect to apply"))
        else:
            await self.ui_queue.put(("status",
                f"Unknown SASL mechanism '{sub}'. Supported: PLAIN, EXTERNAL, SCRAM-SHA-256, ECDSA-NIST256P-CHALLENGE"))

    async def _slash_chghost(self, args, extra, line):
        """Change a user's host (requires IRCop or appropriate permissions).

        Usage: /chghost <nick> <new_host>
        """
        parts = (args + " " + extra).strip().split(maxsplit=1)
        if len(parts) == 2:
            self._active_client().send_raw(f"CHGHOST {parts[0]} {parts[1]}")
            await self.ui_queue.put(("status", f"CHGHOST {parts[0]} {parts[1]}"))
        else:
            await self.ui_queue.put(("status", "Usage: /chghost <nick> <new_host>"))

    async def _slash_setname(self, args, extra, line):
        """Change your realname (requires setname CAP).

        Usage: /setname <new_realname>
        """
        new_name = (args + " " + extra).strip()
        if new_name:
            if "setname" in self._active_client()._active_caps:
                self._active_client().send_raw(f"SETNAME :{new_name}")
                await self.ui_queue.put(("status", f"SETNAME :{new_name}"))
            else:
                await self.ui_queue.put(("status", "Server does not support setname CAP"))
        else:
            await self.ui_queue.put(("status", "Usage: /setname <new_realname>"))

    async def _slash_umode(self, args, extra, line):
        """View or change your user modes.

        Usage:
          /umode          — show current user modes
          /umode +i       — set invisible mode
          /umode -w       — disable wallops
        """
        client = self._active_client()
        if not args:
            modes = sorted(client._own_umodes)
            mode_str = "+" + "".join(modes) if modes else "(none)"
            await self.ui_queue.put(("status", f"Your user modes: {mode_str}"))
            return
        target = client.nick
        modes = args.strip()
        client.cmd_mode(target, modes)

    async def _slash_oper(self, args, extra, line):
        """Attempt to authenticate as an IRC operator.

        Usage: /oper <username> <password>
        """
        parts = (args + " " + extra).strip().split(maxsplit=1)
        if len(parts) == 2:
            self._active_client().send_raw(f"OPER {parts[0]} {parts[1]}")
            await self.ui_queue.put(("status", f"OPER {parts[0]} ***"))
        else:
            await self.ui_queue.put(("status", "Usage: /oper <username> <password>"))

    async def _slash_raw(self, args, extra, line):
        """Send a raw IRC command to the server.

        Usage: /raw <command> [args]
        Example: /raw PRIVMSG #channel :Hello world
        """
        raw_cmd = (args + " " + extra).strip()
        if raw_cmd:
            self._active_client().send_raw(raw_cmd)
        else:
            await self.ui_queue.put(("status", "Usage: /raw <IRC command>"))

    async def _slash_stats(self, args, extra, line):
        """Show channel statistics.

        Usage: /stats [channel]
        """
        chan = (args or "").strip()
        if not chan:
            cur_win = self.get_current_window()
            chan = cur_win.name if cur_win.name.startswith("#") else self.current_channel
        if not chan or chan not in self.channel_users:
            await self.ui_queue.put(("status", "No channel active or channel not found"))
            return
        users = self.channel_users.get(chan, set())
        modes = self.channel_user_modes.get(chan, {})
        ops = sum(1 for u in users if "o" in modes.get(u, set()))
        voices = sum(1 for u in users if "v" in modes.get(u, set()))
        halfops = sum(1 for u in users if "h" in modes.get(u, set()))
        suspects = len(users & self._suspect_nicks)

        sw = self._status_win()
        sw.add_line(f"=== Channel Stats: {chan} ===")
        sw.add_line(f"  Total users : {len(users)}")
        sw.add_line(f"  Owners      : {sum(1 for u in users if 'q' in modes.get(u, set()))}")
        sw.add_line(f"  Admins      : {sum(1 for u in users if 'a' in modes.get(u, set()))}")
        sw.add_line(f"  Ops         : {ops}")
        sw.add_line(f"  Halfops     : {halfops}")
        sw.add_line(f"  Voices      : {voices}")
        sw.add_line(f"  Regular     : {len(users) - ops - halfops - voices}")
        sw.add_line(f"  AI suspects : {suspects}")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_uptime(self, args, extra, line):
        """Show connection uptime and latency."""
        client = self._active_client()
        now = time.monotonic()
        uptime_secs = now - self._start_time
        hours = int(uptime_secs // 3600)
        mins = int((uptime_secs % 3600) // 60)
        secs = int(uptime_secs % 60)
        latency_ms = int(client._latency * 1000) if client._latency > 0 else "?"
        await self.ui_queue.put(("status",
            f"Uptime: {hours}h {mins}m {secs}s  |  "
            f"Server: {client.server}:{client.port}  |  "
            f"Latency: {latency_ms}ms" if latency_ms != "?" else "Latency: unknown"))

    async def _slash_ping(self, args, extra, line):
        """Send a PING to the server and measure round-trip latency."""
        client = self._active_client()
        ts = int(time.time())
        client._last_ping_ts = ts
        client.send_raw(f"PING :latency-{ts}")
        await self.ui_queue.put(("status", f"PING sent — waiting for PONG..."))
        await asyncio.sleep(2)
        if client._last_ping_ts == ts:
            await self.ui_queue.put(("status", "PING timeout — no PONG received"))
        else:
            latency_ms = int(client._latency * 1000)
            await self.ui_queue.put(("status", f"PONG received — latency: {latency_ms}ms"))

    async def _slash_who(self, args, extra, line):
        if args:
            c = self._active_client()
            # Use WHOX when server supports it; falls back to plain WHO automatically
            c.cmd_whox(args)

    async def _slash_whowas(self, args, extra, line):
        if args:
            self._active_client().cmd_whowas(args)

    async def _slash_names(self, args, extra, line):
        self._active_client().cmd_names(args or self.current_channel or "")

    def _save_ignored(self) -> None:
        cfg = load_irc_config()
        cfg["ignored_nicks"] = sorted(self.ignored_nicks)
        cfg["ignored_masks"] = self.ignored_masks
        save_irc_config(cfg)

    def _is_ignored(self, nick: str, user: str = "", host: str = "") -> bool:
        """Check if *nick* (optionally with user@host) matches any ignore rule.

        Supports:
          • Exact nick matches (e.g. "badnick")
          • Wildcard masks (e.g. "*!*@*.spam.net", "bad*!*@*")
        """
        if nick.lower() in self.ignored_nicks:
            return True
        if not self.ignored_masks:
            return False
        ident = f"{nick}!{user}@{host}" if user or host else nick
        import fnmatch
        for mask in self.ignored_masks:
            if fnmatch.fnmatch(ident.lower(), mask.lower()):
                return True
            if fnmatch.fnmatch(nick.lower(), mask.lower()):
                return True
        return False

    def _save_aliases(self) -> None:
        cfg = load_irc_config()
        cfg["aliases"] = dict(self._aliases)
        save_irc_config(cfg)

    async def _slash_ignore(self, args, extra, line):
        if not args:
            if self.ignored_nicks or self.ignored_masks:
                entries = []
                for n in sorted(self.ignored_nicks):
                    entries.append(f"  nick: {n}")
                for m in self.ignored_masks:
                    entries.append(f"  mask: {m}")
                sw = self._status_win()
                sw.add_line("Current ignore list:")
                for e in entries:
                    sw.add_line(e)
                self._chat_dirty = True
                self.dirty = True
            else:
                await self.ui_queue.put(("status", "Ignore list is empty"))
            return
        target = args.strip()
        if "!" in target or "@" in target or "*" in target or "?" in target:
            mask = target.lower()
            if mask not in self.ignored_masks:
                self.ignored_masks.append(mask)
                self._save_ignored()
                await self.ui_queue.put(("status", f"Now ignoring mask: {mask}"))
            else:
                await self.ui_queue.put(("status", f"Mask already ignored: {mask}"))
        else:
            nick = target.lower()
            if nick not in self.ignored_nicks:
                self.ignored_nicks.add(nick)
                self._save_ignored()
                await self.ui_queue.put(("status", f"Now ignoring {target}"))
            else:
                await self.ui_queue.put(("status", f"Already ignoring {target}"))

    async def _slash_unignore(self, args, extra, line):
        if not args:
            await self.ui_queue.put(("status", "Usage: /unignore <nick|mask>"))
            return
        target = args.strip().lower()
        removed = False
        if target in self.ignored_nicks:
            self.ignored_nicks.discard(target)
            removed = True
        if target in self.ignored_masks:
            self.ignored_masks.remove(target)
            removed = True
        if removed:
            self._save_ignored()
            await self.ui_queue.put(("status", f"No longer ignoring {target}"))
        else:
            await self.ui_queue.put(("status", f"Not ignoring {target}"))

    async def _slash_clear(self, args, extra, line):
        win = self.get_current_window()
        win.lines.clear()
        win._line_msgids.clear()
        win._msg_store.clear()
        win._reactions.clear()
        win._last_msgid = ""
        win._unread_from = -1
        win._wrap_dirty = True

    async def _slash_close(self, args, extra, line):
        win = self.get_current_window()
        if win.name not in ("*status*", "*dashboard*"):
            self._unread_windows.discard(win.name)
            self.windows.remove(win)
            wk = self._wk(win.server_id or self._primary_server_id, win.name)
            self.window_by_name.pop(wk, None)
            self.current_window_index = max(0, self.current_window_index - 1)
            new_win = self.get_current_window()
            if new_win.name not in ("*status*", "*dashboard*"):
                self.current_channel = new_win.name
            # Reset dashboard state if we landed on it
            if new_win.name == "*dashboard*":
                self._dashboard_mode = "suspects"
                self._dashboard_profile_locked = False
            self._chat_dirty = self._userlist_dirty = self._input_dirty = True
            self.dirty = True

    async def _slash_win(self, args, extra, line):
        if args.isdigit():
            idx = int(args) - 1
            if 0 <= idx < len(self.windows):
                self._mark_window_read(self.get_current_window())
                # Reset dashboard state when navigating away
                prev_win = self.get_current_window()
                if prev_win.name == "*dashboard*":
                    self._dashboard_mode = "suspects"
                    self._dashboard_profile_locked = False
                self.current_window_index = idx
                win = self.windows[idx]
                # Reset dashboard state when navigating TO it
                if win.name == "*dashboard*":
                    self._dashboard_mode = "suspects"
                    self._dashboard_profile_locked = False
                    self._dashboard_dirty = True
                    self._dashboard_last_update = 0.0
                if win.name not in ("*status*", "*dashboard*"):
                    self.current_channel = win.name
                if win.name in self._unread_windows:
                    win.scroll_offset = 0
                self._unread_windows.discard(win.name)
                win._unread_from = -1
                self._chat_dirty = self._userlist_dirty = self._input_dirty = True
                self.dirty = True

    async def _slash_quit(self, args, extra, line):
        msg = (args + " " + extra).strip() if args else ""
        quit_line = (
            (f"QUIT :{msg}" if msg else "QUIT :Client exiting")
            .encode("utf-8", "replace")[:510] + b"\r\n"
        )
        for ctx in self.servers.values():
            c = ctx.client
            c.running = False          # prevent the reconnect loop from restarting
            if c.writer and not c.writer.is_closing():
                try:
                    # Write directly to the transport — bypasses _send_queue so the
                    # QUIT is guaranteed to go out before we tear down the event loop.
                    c.writer.write(quit_line)
                    await asyncio.wait_for(c.writer.drain(), timeout=1.0)
                    c.writer.close()   # sends TCP FIN → reader in run_connection gets
                                       # EOF and exits naturally, no cancel needed
                except Exception:
                    pass
        raise SystemExit

    async def _slash_server(self, args, extra, line):
        """Connect to an additional IRC server (runs in parallel with existing connections).

        Usage: /server [-ssl] <host> [port]
        """
        if not args:
            await self.ui_queue.put(("status",
                "Usage: /server [-ssl] <host> [port]  "
                "(omit -ssl for plain, default ports: 6697 SSL / 6667 plain)"))
            return
        parts   = args.split()
        use_ssl = False
        if parts and parts[0] == "-ssl":
            use_ssl = True
            parts   = parts[1:]
        if not parts:
            await self.ui_queue.put(("status", "Usage: /server [-ssl] <host> [port]"))
            return
        new_host = parts[0]
        default_port = 6697 if use_ssl else 6667
        new_port = default_port
        if len(parts) >= 2:
            if parts[1].isdigit():
                new_port = int(parts[1])
            else:
                await self.ui_queue.put(("status",
                    f"/server: invalid port '{parts[1]}', using {default_port}"))
        new_sid = f"{new_host}:{new_port}"

        if new_sid in self.servers:
            # Already connected — switch status window into view
            sw_wk = self._wk(new_sid, "*status*")
            sw    = self.window_by_name.get(sw_wk)
            if sw and sw in self.windows:
                self.current_window_index = self.windows.index(sw)
                self._sync_draw_ctx()
                self._chat_dirty = self._userlist_dirty = self._input_dirty = True
                self.dirty = True
            await self.ui_queue.put(("status",
                f"Already connected to {new_host}:{new_port} — switched to its window"))
            return

        nick = self._active_client().nick
        # Each extra server gets its own raw queue; a mux task wraps events
        # with the server_id and forwards them to the shared ui_queue.
        srv_raw_queue: asyncio.Queue = asyncio.Queue()
        new_scoring   = ScoringEngine(self.client.scoring.ai_detector)
        new_client    = IRCClient(new_host, new_port, nick, srv_raw_queue,
                                  new_scoring, use_ssl=use_ssl,
                                  use_tor=self._use_tor)
        new_client.tor_strict = self._tor_strict
        new_ctx = ServerContext(new_sid, new_client)
        self.servers[new_sid] = new_ctx

        # Create a dedicated status window for this server.
        sw_wk = self._wk(new_sid, "*status*")
        sw    = ChatWindow("*status*", is_channel=False, server_id=new_sid)
        # Persist to a per-server filename so secondary servers' status
        # streams aren't collapsed into the primary's _status_.log.
        sw._log_name = f"*status*-{new_sid}"
        self.windows.append(sw)
        self.window_by_name[sw_wk] = sw
        self.current_window_index = self.windows.index(sw)
        self._sync_draw_ctx()

        proto = "SSL" if use_ssl else "plain"
        sw.add_line(f"*** Connecting to {new_host}:{new_port} ({proto}) as {nick}", timestamp=False)

        asyncio.create_task(self._mux_server_events(srv_raw_queue, new_sid),
                            name=f"mux-{new_sid}")
        asyncio.create_task(new_client.run_connection(), name=f"irc-{new_sid}")

        self._chat_dirty = self._userlist_dirty = self._input_dirty = True
        self.dirty = True

    async def _mux_server_events(self, src: asyncio.Queue, server_id: str) -> None:
        """Forward events from a secondary server's queue to the TUI's ui_queue.

        Each event is wrapped as ("_srv", server_id, original_event) so that
        handle_event can route it to the right ServerContext.
        """
        while True:
            event = await src.get()
            await self.ui_queue.put(("_srv", server_id, event))

    async def _slash_reconnect(self, args, extra, line):
        cur = self._active_client()
        await self.ui_queue.put(("status", f"Forcing reconnect to {cur.server}:{cur.port}..."))
        if cur.writer:
            try:
                cur.writer.close()
            except Exception:
                pass

    async def _slash_theme(self, args, extra, line):
        if args.isdigit() and 1 <= int(args) <= len(THEMES):
            self.apply_theme(int(args))
        else:
            names = "  ".join(f"[{i+1}] {t[0]}" for i, t in enumerate(THEMES))
            await self.ui_queue.put(("status",
                f"Usage: /theme <1-{len(THEMES)}>  {names}  (current: {self.current_theme})"))

    async def _slash_askai(self, args, extra, line):
        if _NO_AI:
            await self.ui_queue.put(("status", "[askai] disabled by --no-ai")); return
        rest = line[len("/askai"):].strip()
        if not rest:
            keys = " | ".join(AI_MODELS)
            await self.ui_queue.put(("status",
                f"Usage: /askai [model] <question>   models: {keys}"))
            return
        first_word, *remainder = rest.split(maxsplit=1)
        fw = first_word.lower()
        if fw in AI_MODELS or fw.startswith("ollama:"):
            model_key = fw
            question  = remainder[0] if remainder else ""
        else:
            model_key = self.ai_chat_model
            question  = rest
        if question:
            t = asyncio.create_task(self._do_askai(question, model_key))
            t.add_done_callback(self._ai_task_done)
        else:
            keys = " | ".join(AI_MODELS)
            await self.ui_queue.put(("status",
                f"Usage: /askai [model] <question>   models: {keys}"
                f"   or ollama:<model-name> for any local Ollama model"))

    async def _slash_summarize(self, args, extra, line) -> None:
        """Summarize recent messages in the current window using any configured AI.

        Usage: /summarize [n] [model]
          n      – number of most-recent messages to include (default 50, max 200)
          model  – any key from /model  (e.g. sonnet, gpt4o, gemini)
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[summarize] disabled by --no-ai")); return
        if self._askai_pending:
            await self.ui_queue.put(("status", "/summarize already in progress, please wait…"))
            return

        # Parse positional args: integer → n, known model key or ollama:* → model
        n_msgs    = 50
        model_key = self.ai_chat_model
        for token in args.split():
            if token.isdigit():
                n_msgs = max(5, min(200, int(token)))
            elif token.lower() in AI_MODELS or token.lower().startswith("ollama:"):
                model_key = token.lower()

        win = self.get_current_window()
        if win.name in ("*status*", "*dashboard*"):
            await self.ui_queue.put(("status",
                "/summarize: switch to a channel or DM window first"))
            return

        raw_lines = list(win.lines)[-n_msgs:]
        if not raw_lines:
            await self.ui_queue.put(("status", "/summarize: no messages in this window"))
            return

        _TS_RE      = re.compile(r'^\[\d{2}:\d{2}\]\s*')
        _SPEAKER_RE = re.compile(r'^<(\S+?)>')
        cleaned     = [irc_strip_formatting(_TS_RE.sub("", ln)) for ln in raw_lines]
        transcript  = "\n".join(cleaned)

        speakers = sorted({m.group(1) for ln in cleaned for m in [_SPEAKER_RE.match(ln)] if m})
        speaker_hint = (f"Active speakers: {', '.join(speakers)}\n\n" if speakers else "")

        if model_key.startswith("ollama:"):
            model_id = model_key[len("ollama:"):]
            label    = f"Ollama/{model_id}"
        elif model_key.startswith("llamacpp:"):
            model_id = model_key[len("llamacpp:"):]
            label    = f"llama.cpp/{model_id}"
        else:
            spec     = AI_MODELS.get(model_key) or AI_MODELS[CLAUDE_DEFAULT_MODEL]
            model_id = spec["id"]
            label    = spec["label"]

        prompt = (
            f"The following is a transcript of an IRC chat in \"{win.name}\" "
            f"({len(raw_lines)} messages).\n"
            f"{speaker_hint}"
            f"Write a structured analysis covering:\n"
            f"1. Main topics — what the conversation was about (2-3 sentences).\n"
            f"2. Per-user contributions — for each active speaker, one or two sentences "
            f"on what they said or argued.\n"
            f"3. User interactions — who replied to whom, any debates, agreements, "
            f"disagreements, jokes, or notable exchanges between specific users.\n"
            f"4. Conclusions or open threads — any decisions reached or questions left unanswered.\n\n"
            f"Be specific: name the users involved in each point. "
            f"Keep the total under 400 words.\n\n"
            f"Transcript:\n{transcript}"
        )

        # Mark pending synchronously before creating the task so a second
        # /summarize issued in the same event-loop tick is rejected.
        self._askai_pending = True
        await self.ui_queue.put(("status",
            f"[summarize] {len(raw_lines)} msgs from {win.name} via "
            f"{model_key} ({label})…"))
        task = asyncio.create_task(
            self._do_summarize(prompt, model_key, model_id, label,
                               win.name, len(raw_lines), speakers))
        task.add_done_callback(self._ai_task_done)

    def _ai_task_done(self, task: asyncio.Task) -> None:
        """Done-callback for fire-and-forget AI tasks.  Logs unhandled exceptions
        to the status window instead of letting them vanish silently."""
        exc = task.exception() if not task.cancelled() else None
        if exc:
            try:
                self.window_by_name["*status*"].add_line(f"[ai error] {exc}")
                self._chat_dirty = self.dirty = True
            except Exception:
                pass

    async def _do_summarize(self, prompt: str, model_key: str, model_id: str,
                             label: str, win_name: str, n_msgs: int,
                             speakers: list) -> None:
        answer, tokens = "", "?"
        try:
            # 2000 output tokens fits the 4-section structured summary even on
            # busy channels (200 msgs, many speakers); 800 was getting truncated
            # mid-sentence and dropping the "Conclusions" section.  Timeout
            # bumped to 180s to give slower local models headroom for the
            # larger response.
            answer, tokens = await asyncio.wait_for(
                self._call_ai(prompt, model_key, max_tokens=2000), timeout=180.0)
        except asyncio.TimeoutError:
            answer, tokens = "[error] AI request timed out after 180 s", "?"
        except Exception as exc:
            answer, tokens = f"[error] {exc}", "?"
        finally:
            self._askai_pending = False

        dash = self.window_by_name["*dashboard*"]
        dash.lines.clear()
        dash._wrap_dirty = True
        L = lambda t: dash.add_line(t, timestamp=False)
        L(f"=== /summarize  [{win_name}]  last {n_msgs} msgs  [{model_key}  {label}] ===")
        if speakers:
            L(f"  Speakers: {', '.join(speakers)}")
        L("")
        for raw_line in answer.splitlines():
            L(f"  {raw_line}" if raw_line.strip() else "")
        L("")
        L(f"  model: {model_id}  tokens used: {tokens}")
        self.current_window_index      = 1
        self._chat_dirty               = True
        self._dashboard_dirty          = False
        self._dashboard_last_update    = time.monotonic()
        self._dashboard_mode           = "profile"
        self._dashboard_profile_locked = True
        self.dirty                     = True

    async def _slash_vibe(self, args, extra, line) -> None:
        """Analyze channel culture using AI.

        Usage: /vibe <channel> [n] [model]
          n      – number of most-recent messages to include (default 100, max 500)
          model  – any key from /model  (e.g. sonnet, gpt4o, gemini)
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[vibe] disabled by --no-ai")); return
        if self._askai_pending:
            await self.ui_queue.put(("status", "/vibe already in progress, please wait\u2026"))
            return

        tokens = args.split()
        if not tokens:
            await self.ui_queue.put(("status", "Usage: /vibe <channel> [n] [model]"))
            return

        chan_name = tokens[0]
        n_msgs    = 100
        model_key = self.ai_chat_model
        for token in tokens[1:]:
            if token.isdigit():
                n_msgs = max(10, min(500, int(token)))
            elif token.lower() in AI_MODELS or token.lower().startswith("ollama:"):
                model_key = token.lower()

        # Find window by name (case-insensitive)
        win = None
        for w in self.window_by_name.values():
            if w.name.lower() == chan_name.lower():
                win = w
                break
        if not win or win.name in ("*status*", "*dashboard*"):
            await self.ui_queue.put(("status", f"/vibe: channel '{chan_name}' not found"))
            return

        raw_lines = list(win.lines)[-n_msgs:]
        if not raw_lines:
            await self.ui_queue.put(("status", f"/vibe: no messages in {chan_name}"))
            return

        _TS_RE      = re.compile(r'^\[\d{2}:\d{2}\]\s*')
        _SPEAKER_RE = re.compile(r'^<(\S+?)>')
        cleaned     = [irc_strip_formatting(_TS_RE.sub("", ln)) for ln in raw_lines]
        transcript  = "\n".join(cleaned)

        speakers = sorted({m.group(1) for ln in cleaned for m in [_SPEAKER_RE.match(ln)] if m})
        speaker_hint = (f"Active speakers: {', '.join(speakers)}\n\n" if speakers else "")

        if model_key.startswith("ollama:"):
            model_id = model_key[len("ollama:"):]
            label    = f"Ollama/{model_id}"
        elif model_key.startswith("llamacpp:"):
            model_id = model_key[len("llamacpp:"):]
            label    = f"llama.cpp/{model_id}"
        else:
            spec     = AI_MODELS.get(model_key) or AI_MODELS[CLAUDE_DEFAULT_MODEL]
            model_id = spec["id"]
            label    = spec["label"]

        prompt = (
            f"The following is a transcript of an IRC channel \"{win.name}\" "
            f"({len(raw_lines)} messages).\n"
            f"{speaker_hint}"
            f"Analyze the channel's culture and vibe based on this transcript. Cover:\n"
            f"1. Overall atmosphere \u2014 is it friendly, technical, chaotic, quiet, etc.\n"
            f"2. Recurring topics and interests of the community.\n"
            f"3. Social dynamics \u2014 inside jokes, recurring bits, how people interact.\n"
            f"4. Individual personalities \u2014 for active speakers, describe their role/style.\n"
            f"5. Any notable norms, rituals, or unwritten rules.\n\n"
            f"Be specific, name users, and keep the total under 400 words.\n\n"
            f"Transcript:\n{transcript}"
        )

        self._askai_pending = True
        await self.ui_queue.put(("status",
            f"[vibe] {len(raw_lines)} msgs from {win.name} via "
            f"{model_key} ({label})\u2026"))
        task = asyncio.create_task(
            self._do_vibe(prompt, model_key, model_id, label,
                          win.name, len(raw_lines), speakers))
        task.add_done_callback(self._ai_task_done)

    async def _do_vibe(self, prompt: str, model_key: str, model_id: str,
                        label: str, win_name: str, n_msgs: int,
                        speakers: list) -> None:
        answer, tokens = "", "?"
        try:
            answer, tokens = await asyncio.wait_for(
                self._call_ai(prompt, model_key, max_tokens=2000), timeout=180.0)
        except asyncio.TimeoutError:
            answer, tokens = "[error] AI request timed out after 180 s", "?"
        except Exception as exc:
            answer, tokens = f"[error] {exc}", "?"
        finally:
            self._askai_pending = False

        dash = self.window_by_name["*dashboard*"]
        dash.lines.clear()
        dash._wrap_dirty = True
        L = lambda t: dash.add_line(t, timestamp=False)
        L(f"=== /vibe  [{win_name}]  last {n_msgs} msgs  [{model_key}  {label}] ===")
        if speakers:
            L(f"  Speakers: {', '.join(speakers)}")
        L("")
        for raw_line in answer.splitlines():
            L(f"  {raw_line}" if raw_line.strip() else "")
        L("")
        L(f"  model: {model_id}  tokens used: {tokens}")
        self.current_window_index      = 1
        self._chat_dirty               = True
        self._dashboard_dirty          = False
        self._dashboard_last_update    = time.monotonic()
        self._dashboard_mode           = "profile"
        self._dashboard_profile_locked = True
        self.dirty                     = True

    async def _slash_explain(self, args, extra, line) -> None:
        """Analyze a user's behavior using AI.

        Usage: /explain <nick> [model]
          model  – any key from /model  (e.g. sonnet, gpt4o, gemini)
        """
        if _NO_AI:
            await self.ui_queue.put(("status", "[explain] disabled by --no-ai")); return
        if self._askai_pending:
            await self.ui_queue.put(("status", "/explain already in progress, please wait\u2026"))
            return

        tokens = (args + " " + extra).strip().split()
        if not tokens:
            await self.ui_queue.put(("status", "Usage: /explain <nick> [model]"))
            return

        target    = tokens[0].lower()
        model_key = self.ai_chat_model
        for token in tokens[1:]:
            if token.lower() in AI_MODELS or token.lower().startswith("ollama:"):
                model_key = token.lower()

        # Collect all messages from this nick across all windows
        _TS_RE      = re.compile(r'^\[\d{2}:\d{2}\]\s*')
        _SPEAKER_RE = re.compile(r'^<(\S+?)>')
        found       = []  # (window_name, cleaned_line)
        for win in self.window_by_name.values():
            if win.name in ("*status*", "*dashboard*"):
                continue
            for ln in win.lines:
                stripped = _TS_RE.sub("", ln)
                m = _SPEAKER_RE.match(stripped)
                if m and m.group(1).lower() == target:
                    found.append((win.name, irc_strip_formatting(stripped)))

        if not found:
            await self.ui_queue.put(("status", f"/explain: no messages found for '{target}'"))
            return

        # Group by window, limit per-window to 100
        by_win = {}
        for wname, line_text in found:
            by_win.setdefault(wname, []).append(line_text)
        parts = []
        for wname, lines in by_win.items():
            if len(lines) > 100:
                lines = lines[-100:]
            parts.append(f"--- {wname} ({len(lines)} messages) ---")
            parts.extend(lines)
        transcript = "\n".join(parts)

        if model_key.startswith("ollama:"):
            model_id = model_key[len("ollama:"):]
            label    = f"Ollama/{model_id}"
        elif model_key.startswith("llamacpp:"):
            model_id = model_key[len("llamacpp:"):]
            label    = f"llama.cpp/{model_id}"
        else:
            spec     = AI_MODELS.get(model_key) or AI_MODELS[CLAUDE_DEFAULT_MODEL]
            model_id = spec["id"]
            label    = spec["label"]

        prompt = (
            f"The following are messages from a user '{target}' across IRC channels "
            f"({len(found)} total messages).\n\n"
            f"Analyze this user's behavior and personality based on their messages. Cover:\n"
            f"1. Communication style \u2014 tone, formality, verbosity.\n"
            f"2. Expertise and interests \u2014 what topics they engage with.\n"
            f"3. Social role \u2014 helpful, argumentative, humorous, lurker, etc.\n"
            f"4. Interaction patterns \u2014 who they talk to, how they respond.\n"
            f"5. Overall impression \u2014 what kind of community member they are.\n\n"
            f"Be specific, cite examples, and keep the total under 400 words.\n\n"
            f"Messages:\n{transcript}"
        )

        self._askai_pending = True
        await self.ui_queue.put(("status",
            f"[explain] {len(found)} msgs from {target} via "
            f"{model_key} ({label})\u2026"))
        task = asyncio.create_task(
            self._do_explain(prompt, model_key, model_id, label,
                            target, len(found)))
        task.add_done_callback(self._ai_task_done)

    async def _do_explain(self, prompt: str, model_key: str, model_id: str,
                           label: str, target: str, n_msgs: int) -> None:
        answer, tokens = "", "?"
        try:
            answer, tokens = await asyncio.wait_for(
                self._call_ai(prompt, model_key, max_tokens=2000), timeout=180.0)
        except asyncio.TimeoutError:
            answer, tokens = "[error] AI request timed out after 180 s", "?"
        except Exception as exc:
            answer, tokens = f"[error] {exc}", "?"
        finally:
            self._askai_pending = False

        dash = self.window_by_name["*dashboard*"]
        dash.lines.clear()
        dash._wrap_dirty = True
        L = lambda t: dash.add_line(t, timestamp=False)
        L(f"=== /explain  [{target}]  {n_msgs} msgs  [{model_key}  {label}] ===")
        L("")
        for raw_line in answer.splitlines():
            L(f"  {raw_line}" if raw_line.strip() else "")
        L("")
        L(f"  model: {model_id}  tokens used: {tokens}")
        self.current_window_index      = 1
        self._chat_dirty               = True
        self._dashboard_dirty          = False
        self._dashboard_last_update    = time.monotonic()
        self._dashboard_mode           = "profile"
        self._dashboard_profile_locked = True
        self.dirty                     = True

    async def _slash_model(self, args, extra, line):
        key = args.strip().lower()
        detector = self._active_client().scoring.ai_detector
        if not key:
            # List every available model with its provider
            sw = self._status_win()
            sw.add_line("Available AI models for /askai, /summarize, and AI detection:")
            for k, spec in AI_MODELS.items():
                chat_mark = ">" if k == self.ai_chat_model else " "
                det_mark  = "D" if k == detector.active_detect_model else " "
                avail  = ""
                if spec["provider"] == "claude" and not ANTHROPIC_API_KEY:
                    avail = "  (ANTHROPIC_API_KEY not set)"
                elif spec["provider"] == "openai" and not OPENAI_API_KEY:
                    avail = "  (OPENAI_API_KEY not set)"
                elif spec["provider"] == "deepseek" and not DEEPSEEK_API_KEY:
                    avail = "  (DEEPSEEK_API_KEY not set)"
                elif spec["provider"] == "copilot" and not GITHUB_TOKEN:
                    avail = "  (GITHUB_TOKEN not set)"
                elif spec["provider"] == "gemini" and not GEMINI_API_KEY:
                    avail = "  (GEMINI_API_KEY not set)"
                sw.add_line(f"  {chat_mark}{det_mark} {k:<8} {spec['label']:<22} [{spec['provider']}]{avail}")
            sw.add_line("  > = chat model   D = also used for AI detection")
            sw.add_line(f"  Usage: /model <key>   current: {self.ai_chat_model}")
            self._chat_dirty = True
            self.dirty = True
            return
        if key in AI_MODELS:
            self.ai_chat_model = key
            detector.active_detect_model = key
            spec = AI_MODELS[key]
            await self.ui_queue.put(("status",
                f"AI model set to {key}  ({spec['label']}  {spec['id']})  [{spec['provider']}]"
                f"  — also active for AI detection"))
        else:
            keys = "  ".join(AI_MODELS)
            await self.ui_queue.put(("status",
                f"Unknown model '{key}'. Available: {keys}  (current: {self.ai_chat_model})"))

    async def _slash_api(self, args, extra, line):
        global ANTHROPIC_API_KEY, OPENAI_API_KEY, DEEPSEEK_API_KEY, GITHUB_TOKEN, GEMINI_API_KEY, OLLAMA_URL, LLAMACPP_URL
        _KNOWN = {"ANTHROPIC_API_KEY", "OPENAI_API_KEY", "DEEPSEEK_API_KEY", "GITHUB_TOKEN", "GEMINI_API_KEY", "OLLAMA_URL", "LLAMACPP_URL"}

        if not args:
            sw = self._status_win()
            sw.add_line("")
            sw.add_line("  ── AI Provider Keys " + "─" * 44)

            def _mask(val: str) -> str:
                if not val:
                    return "NOT SET"
                if len(val) <= 8:
                    return val[:2] + "****"
                return val[:8] + "\u2026" + val[-4:]

            rows = [
                ("Claude",    "ANTHROPIC_API_KEY", ANTHROPIC_API_KEY, "console.anthropic.com"),
                ("OpenAI",    "OPENAI_API_KEY",    OPENAI_API_KEY,    "platform.openai.com"),
                ("DeepSeek",  "DEEPSEEK_API_KEY",  DEEPSEEK_API_KEY,  "platform.deepseek.com"),
                ("Copilot",   "GITHUB_TOKEN",       GITHUB_TOKEN,      "github.com/settings/tokens"),
                ("Gemini",    "GEMINI_API_KEY",     GEMINI_API_KEY,    "console.cloud.google.com"),
                ("Ollama",    "OLLAMA_URL",         OLLAMA_URL,        "local server — no key needed"),
                ("llama.cpp", "LLAMACPP_URL",       LLAMACPP_URL,      "local server — no key needed"),
            ]
            for provider, varname, val, note in rows:
                sw.add_line(f"  {provider:<10}  {varname:<22}  {_mask(val):<32}  ({note})")

            sw.add_line("")
            sw.add_line("  Set a key:  /api <VAR_NAME> <value>")
            sw.add_line("    /api ANTHROPIC_API_KEY  sk-ant-api03-...")
            sw.add_line("    /api OPENAI_API_KEY     sk-proj-...")
            sw.add_line("    /api OLLAMA_URL         http://192.168.1.10:11434")
            sw.add_line("    /api LLAMACPP_URL       http://192.168.1.10:8033")
            sw.add_line("")
            self._chat_dirty = True
            self.dirty = True
            return

        if args.upper() in _KNOWN:
            var_name = args.upper()
            value = extra.strip()
            if not value:
                await self.ui_queue.put(("status", f"Usage: /api {var_name} <value>"))
                return
            os.environ[var_name] = value
            if var_name == "ANTHROPIC_API_KEY":
                ANTHROPIC_API_KEY = value
            elif var_name == "OPENAI_API_KEY":
                OPENAI_API_KEY = value
                if _openai_mod is not None:
                    _openai_mod.api_key = value
            elif var_name == "DEEPSEEK_API_KEY":
                DEEPSEEK_API_KEY = value
                self._deepseek_client = None   # force reconnect with new key
            elif var_name == "GITHUB_TOKEN":
                GITHUB_TOKEN = value
                self._copilot_client = None    # force reconnect with new key
            elif var_name == "GEMINI_API_KEY":
                GEMINI_API_KEY = value
                self._gemini_client = None     # force reconnect with new key
            elif var_name == "OLLAMA_URL":
                OLLAMA_URL = value
            elif var_name == "LLAMACPP_URL":
                LLAMACPP_URL = value
            masked = (value[:8] + "\u2026" + value[-4:]) if len(value) > 12 else (value[:4] + "****")
            await self.ui_queue.put(("status",
                f"Set {var_name} = {masked}  (active immediately)"))
            return

        await self.ui_queue.put(("status",
            f"Unknown variable '{args}'.  Known: ANTHROPIC_API_KEY  OPENAI_API_KEY  DEEPSEEK_API_KEY  GITHUB_TOKEN  OLLAMA_URL  LLAMACPP_URL"))

    async def _slash_znc(self, args, extra, line):
        text = (args + " " + extra).strip()
        if not text:
            await self.ui_queue.put(("status", "Usage: /znc <command>  —  sends command to ZNC *status"))
            return
        client = self._active_client()
        client.send_raw(f"PRIVMSG *status :{text}")
        await self.ui_queue.put(("status", f">>> *status: {text}"))

    # ── BNC (built-in bouncer) ──────────────────────────────────────────────
    async def _slash_bouncer(self, args, extra, line):
        text = line[9:].strip().lower()  # strip "/bouncer "
        parts = text.split()
        sub = parts[0] if parts else ""
        if sub == "on":
            self._bouncer_enabled = True
            self._save_bouncer_config()
            await self.ui_queue.put(("status", "BNC enabled — messages will buffer when detached"))
        elif sub == "off":
            self._bouncer_enabled = False
            self._save_bouncer_config()
            await self.ui_queue.put(("status", "BNC disabled"))
        elif sub == "status":
            buf = self._bouncer_buffer
            stats = buf.get_channel_stats()
            lines = [
                f"BNC: {'ON' if self._bouncer_enabled else 'OFF'}  "
                f"Detached: {self._bouncer_detached}  "
                f"Buffered: {buf.count}",
                f"Highlights: {buf.highlight_count}  "
                f"Filter: {self._bouncer_filter_mode}  "
                f"Replay limit: {self._bouncer_replay_limit or 'unlimited'}",
            ]
            if stats:
                lines.append("Per-channel:")
                for ch, cnt in sorted(stats.items(), key=lambda x: -x[1]):
                    lines.append(f"  {ch}: {cnt} msgs")
            for line_text in lines:
                await self.ui_queue.put(("status", line_text))
        elif sub in ("detach", "hide"):
            self._bouncer_detached = True
            self._save_bouncer_config()
            await self.ui_queue.put(("status", "BNC: detached (IRC stays connected, messages buffer)"))
        elif sub in ("attach", "show"):
            await self._do_attach()
        elif sub == "replay":
            limit_str = parts[1] if len(parts) > 1 else ""
            limit = int(limit_str) if limit_str.isdigit() else self._bouncer_replay_limit
            n = self._bouncer_buffer.replay(self.ui_queue, limit=limit)
            await self.ui_queue.put(("status", f"BNC: replayed {n} buffered messages"))
        elif sub == "clear":
            self._bouncer_buffer.clear()
            await self.ui_queue.put(("status", "BNC: buffer cleared"))
        elif sub == "limit":
            limit_str = parts[1] if len(parts) > 1 else ""
            if not limit_str.isdigit():
                await self.ui_queue.put(("status", f"Current replay limit: {self._bouncer_replay_limit or 'unlimited'}"))
                return
            self._bouncer_replay_limit = int(limit_str)
            self._save_bouncer_config()
            await self.ui_queue.put(("status", f"BNC: replay limit set to {limit_str}"))
        elif sub == "filter":
            mode = parts[1] if len(parts) > 1 else ""
            if mode not in ("all", "highlights", "dms"):
                await self.ui_queue.put(("status", f"Current filter mode: {self._bouncer_filter_mode} (all|highlights|dms)"))
                return
            self._bouncer_filter_mode = mode
            self._save_bouncer_config()
            await self.ui_queue.put(("status", f"BNC: filter mode set to '{mode}'"))
        else:
            await self.ui_queue.put(("status",
                "Usage: /bouncer on|off|status|detach|attach|replay [N]|clear|limit [N]|filter [mode]"))

    async def _slash_detach(self, args, extra, line):
        """Convenience alias: /detach"""
        if self._bouncer_enabled:
            self._bouncer_detached = True
            self._save_bouncer_config()
            await self.ui_queue.put(("status", "BNC: detached"))
        else:
            await self.ui_queue.put(("status", "BNC is off — enable with /bouncer on"))

    async def _slash_attach(self, args, extra, line):
        """Convenience alias: /attach"""
        if self._bouncer_detached:
            await self._do_attach()
        else:
            await self.ui_queue.put(("status", "BNC: already attached"))

    async def _do_attach(self) -> None:
        self._bouncer_detached = False
        self._bouncer_last_attach = time.time()
        n = self._bouncer_buffer.replay(
            self.ui_queue,
            limit=self._bouncer_replay_limit,
            since=self._bouncer_last_attach if self._bouncer_last_attach > 0 else 0,
        )
        self._save_bouncer_config()
        await self.ui_queue.put(("status", f"BNC: attached — replayed {n} buffered messages"))

    def _should_buffer_event(self, event) -> bool:
        """Determine if an event should be buffered based on filter mode."""
        if self._bouncer_filter_mode == "all":
            return True

        event_type = event[0] if event else ""
        if event_type != "msg":
            # Always buffer non-message events (joins, parts, etc.)
            return True

        args = event[1] if len(event) > 1 else ()
        if self._bouncer_filter_mode == "highlights":
            # Only buffer messages with mentions
            mention = args[5] if len(args) > 5 else ""
            return bool(mention)

        elif self._bouncer_filter_mode == "dms":
            # Only buffer direct messages (target doesn't start with #)
            target = args[1] if len(args) > 1 else ""
            return not target.startswith("#")

        return True

    def _save_bouncer_config(self) -> None:
        cfg = load_irc_config()
        bnc = cfg.setdefault("bouncer", {})
        bnc["enabled"]      = self._bouncer_enabled
        bnc["detached"]     = self._bouncer_detached
        bnc["replay_limit"] = self._bouncer_replay_limit
        bnc["filter_mode"]  = self._bouncer_filter_mode
        cfg.setdefault("gpg", {})["key_fingerprint"] = self._gpg_key_fp
        save_irc_config(cfg)

    # ── PGP / GPG ───────────────────────────────────────────────────────────
    async def _slash_pgp(self, args, extra, line):
        text = line[5:].strip().lower()
        parts = text.split(maxsplit=2)
        sub = parts[0] if parts else ""
        if not self._gpg_enabled:
            await self.ui_queue.put(("status", "GPG binary not found — set IRC_GPG_BINARY"))
            return
        if sub == "key":
            fp = parts[1] if len(parts) > 1 else ""
            if not fp:
                await self.ui_queue.put(("status", f"Current key: {self._gpg_key_fp or '(none)'}"))
                return
            self._gpg_key_fp = fp
            self._save_bouncer_config()
            await self.ui_queue.put(("status", f"GPG default key set to {fp}"))
        elif sub == "encrypt":
            rest = (parts[1] if len(parts) > 1 else "") + (" " + parts[2] if len(parts) > 2 else "")
            if not rest or " " not in rest:
                await self.ui_queue.put(("status", "Usage: /pgp encrypt <recipient> <message>"))
                return
            recip, *msg_parts = rest.split(" ", 1)
            msg = msg_parts[0] if msg_parts else ""
            ct = _gpg_encrypt(msg, recip)
            if ct:
                win = self.get_current_window()
                win.add_line(f"[PGP] encrypted for {recip}: {ct[:120]}...")
                await self.ui_queue.put(("status", "Message encrypted (ciphertext shown in window)"))
            else:
                await self.ui_queue.put(("status", f"GPG encryption failed (key for {recip}?)"))
        elif sub == "decrypt":
            rest = (parts[1] if len(parts) > 1 else "") + (" " + parts[2] if len(parts) > 2 else "")
            pt = _gpg_decrypt(rest)
            if pt:
                win = self.get_current_window()
                win.add_line(f"[PGP] decrypted: {pt}")
                await self.ui_queue.put(("status", "Message decrypted"))
            else:
                await self.ui_queue.put(("status", "GPG decryption failed"))
        elif sub == "sign":
            rest = (parts[1] if len(parts) > 1 else "") + (" " + parts[2] if len(parts) > 2 else "")
            sig = _gpg_sign(rest, self._gpg_key_fp)
            if sig:
                win = self.get_current_window()
                win.add_line(f"[PGP] signature: {sig[:120]}...")
                await self.ui_queue.put(("status", "Message signed"))
            else:
                await self.ui_queue.put(("status", "GPG signing failed"))
        elif sub == "verify":
            # /pgp verify <message> <base64-signature>
            if len(parts) < 3:
                await self.ui_queue.put(("status", "Usage: /pgp verify <message> <signature>"))
                return
            key = _gpg_verify(parts[1], parts[2])
            if key:
                await self.ui_queue.put(("status", f"Verified — signed by {key}"))
            else:
                await self.ui_queue.put(("status", "GPG verification failed"))
        elif sub in ("list", "keys"):
            try:
                proc = subprocess.run(
                    [GPG_BINARY, "--list-keys", "--keyid-format", "long"],
                    capture_output=True, timeout=10,
                )
                out = proc.stdout.decode("utf-8", errors="replace")
                win = self.get_current_window()
                win.add_line("--- GPG public keys ---")
                for line_text in out.splitlines():
                    win.add_line(f"  {line_text}")
            except Exception as e:
                await self.ui_queue.put(("status", f"GPG keys failed: {e}"))
        else:
            await self.ui_queue.put(("status",
                "Usage: /pgp key [fp] | encrypt <nick> <msg> | decrypt <b64> | "
                "sign <msg> | verify <msg> <sig> | list"))

    # ── Tor ─────────────────────────────────────────────────────────────────
    async def _slash_tor(self, args, extra, line):
        text = (args + " " + extra).strip().lower()
        parts = text.split()
        sub = parts[0] if parts else ""
        if sub == "on":
            self._use_tor = True
            self.client.use_tor = True
            for ctx in self.servers.values():
                ctx.client.use_tor = True
            self._save_tor_config()
            await self.ui_queue.put(("status", "Tor enabled — new connections route through SOCKS5"))
        elif sub == "off":
            self._use_tor = False
            self.client.use_tor = False
            for ctx in self.servers.values():
                ctx.client.use_tor = False
            self._save_tor_config()
            await self.ui_queue.put(("status", "Tor disabled — new connections use direct TCP"))
        elif sub == "strict":
            self._tor_strict = True
            self.client.tor_strict = True
            for ctx in self.servers.values():
                ctx.client.tor_strict = True
            self._save_tor_config()
            await self.ui_queue.put(("status",
                "Tor strict mode ON — only .onion hosts allowed"))
        elif sub == "nostrict":
            self._tor_strict = False
            self.client.tor_strict = False
            for ctx in self.servers.values():
                ctx.client.tor_strict = False
            self._save_tor_config()
            await self.ui_queue.put(("status",
                "Tor strict mode OFF — clearnet hosts allowed"))
        elif sub in ("status", ""):
            await self.ui_queue.put(("status",
                f"Tor: {'ON' if self._use_tor else 'OFF'}  "
                f"Strict: {'ON' if self._tor_strict else 'OFF'}  "
                f"proxy: {TOR_PROXY_HOST}:{TOR_PROXY_PORT}"))
        else:
            await self.ui_queue.put(("status", "Usage: /tor on|off|strict|nostrict|status"))

    def _save_tor_config(self) -> None:
        cfg = load_irc_config()
        cfg.setdefault("tor", {})["enabled"] = self._use_tor
        cfg.setdefault("tor", {})["strict"] = self._tor_strict
        save_irc_config(cfg)

    async def _slash_ctcpmode(self, args, extra, line):
        mode = (args + " " + extra).strip().lower()
        if mode not in ("normal", "off", "spoof"):
            await self.ui_queue.put(("status", "Usage: /ctcpmode normal|off|spoof"))
            return
        self._active_client()._ctcp_mode = mode
        for ctx in self.servers.values():
            ctx.client._ctcp_mode = mode
        cfg = load_irc_config()
        cfg["ctcp_mode"] = mode
        save_irc_config(cfg)
        await self.ui_queue.put(("status", f"CTCP reply mode set to: {mode}"))

    async def _slash_jitsi(self, args, extra, line):
        win = self.get_current_window()
        if win.is_channel or win.name in ("*status*", "*dashboard*"):
            await self.ui_queue.put(("status", "/jitsi: switch to a PM window first"))
            return
        target = win.name
        room = uuid.uuid4().hex[:12]
        url = f"https://meet.jit.si/{room}"
        client = self._active_client()
        client.send_raw(f"PRIVMSG {target} :\x01ACTION suggests a Jitsi call: {url}\x01")
        win.add_line(f"* You suggest a Jitsi call: {url}")
        webbrowser.open(url)
        await self.ui_queue.put(("status", f"Jitsi link sent and opened in browser"))
        self._chat_dirty = True
        self.dirty = True

    async def _slash_chain(self, args, extra, line):
        win = self.get_current_window()
        if win.name in ("*status*", "*dashboard*"):
            await self.ui_queue.put(("status", "/chain: switch to a channel or PM window"))
            return
        nick_filter = (args + " " + extra).strip().lower() or None
        msgs = []
        for line_text in win.lines:
            parts = line_text.split(None, 2)
            if len(parts) >= 2:
                ts = parts[0]
                rest = parts[1] if len(parts) > 1 else ""
                sender = ""
                text = ""
                if rest.startswith("<") and ">" in rest:
                    sender = rest[1:].split(">", 1)[0].lower()
                    text = rest.split(">", 1)[1] if ">" in rest else ""
                elif rest.startswith("*"):
                    sender = rest[2:].split()[0].lower() if len(rest) > 2 else ""
                    text = rest
                if sender and (not nick_filter or sender == nick_filter):
                    msgs.append((ts, sender, text.strip()))
        if not msgs:
            await self.ui_queue.put(("status", "/chain: no messages found" + (f" from {nick_filter}" if nick_filter else "")))
            return
        sw = self._status_win()
        sw.add_line(f"── Message chain ({win.name})" + (f" — {nick_filter}" if nick_filter else "") + " ──")
        for ts, sender, text in msgs[-30:]:
            preview = text[:60] + "…" if len(text) > 60 else text
            sw.add_line(f"  {ts} <{sender}> {preview}")
        sw.add_line(f"── {len(msgs)} messages, showing last 30 ──")
        self._chat_dirty = True
        self.dirty = True

    def _make_sparkline(self, hours: List[int]) -> str:
        if not hours:
            return ""
        buckets = [0] * 24
        for h in hours:
            if 0 <= h <= 23:
                buckets[h] += 1
        mx = max(buckets)
        if mx == 0:
            return "·" * 24
        bars = ["▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"]
        return "".join(bars[min(7, int(b / mx * 7))] for b in buckets)

    async def _slash_idle(self, args, extra, line):
        nick = (args + " " + extra).strip()
        if not nick:
            await self.ui_queue.put(("status", "Usage: /idle <nick>"))
            return
        nl = nick.lower()
        hours = self._msg_hours.get(nl)
        if not hours:
            await self.ui_queue.put(("status", f"No message data for {nick}"))
            return
        total = len(hours)
        spark = self._make_sparkline(hours)
        sw = self._status_win()
        sw.add_line(f"── Activity pattern: {nick} ({total} messages) ──")
        sw.add_line(f"   0         6        12        18       24")
        sw.add_line(f"   {spark}")
        sw.add_line(f"   └{'─'*23}┘ hour (UTC)")
        chs = self._ch_activity.get(nl, {})
        if chs:
            top = sorted(chs.items(), key=lambda x: -x[1])[:5]
            sw.add_line(f"  Top channels: " + ", ".join(f"{ch}({n})" for ch, n in top))
        self._chat_dirty = True
        self.dirty = True

    async def _slash_together(self, args, extra, line):
        parts = (args + " " + extra).strip().split()
        if len(parts) < 2:
            await self.ui_queue.put(("status", "Usage: /together <nick1> <nick2>"))
            return
        n1, n2 = parts[0].lower(), parts[1].lower()
        ac1 = self._ch_activity.get(n1, {})
        ac2 = self._ch_activity.get(n2, {})
        common = {}
        for ch, c1 in ac1.items():
            c2 = ac2.get(ch)
            if c2:
                common[ch] = (c1, c2)
        sw = self._status_win()
        sw.add_line(f"── Together: {parts[0]} & {parts[1]} ──")
        if not common:
            # Fall back to checking current channel membership overlap
            cur = [ch for ch, us in self.channel_users.items()
                   if parts[0].lower() in {u.lower() for u in us}
                   and parts[1].lower() in {u.lower() for u in us}]
            if cur:
                sw.add_line(f"  Currently together in: {', '.join(cur)}")
            else:
                sw.add_line(f"  No common channels detected")
        else:
            sw.add_line(f"  {'Channel':<20} {parts[0]:<8} {parts[1]:<8}")
            total1 = total2 = 0
            for ch in sorted(common, key=lambda c: -common[c][0] - common[c][1]):
                c1, c2 = common[ch]
                sw.add_line(f"  {ch:<20} {c1:<8} {c2:<8}")
                total1 += c1; total2 += c2
            sw.add_line(f"  {'─'*20} {'─'*8} {'─'*8}")
            sw.add_line(f"  {'Total':<20} {total1:<8} {total2:<8}")
            # Also check current membership
            cur = [ch for ch, us in self.channel_users.items()
                   if parts[0].lower() in {u.lower() for u in us}
                   and parts[1].lower() in {u.lower() for u in us}
                   and ch not in common]
            if cur:
                sw.add_line(f"  Also currently in: {', '.join(cur)}")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_adjacent(self, args, extra, line):
        nick = (args + " " + extra).strip()
        if not nick:
            await self.ui_queue.put(("status", "Usage: /adjacent <nick>"))
            return
        nl = nick.lower()
        adj = self._adjacency.get(nl)
        if not adj:
            await self.ui_queue.put(("status", f"No adjacency data for {nick}"))
            return
        sw = self._status_win()
        total = sum(adj.values())
        sw.add_line(f"── Conversation adjacency: {nick} ({total} pairs) ──")
        for other, count in adj.most_common(20):
            pct = count / total * 100
            bar = "█" * int(pct / 5) + "▏" * (1 if pct % 5 >= 3 else 0)
            sw.add_line(f"  {other:<20} {count:>4} ({pct:4.0f}%) {bar}")
        sw.add_line("  (messages spoken immediately before or after)")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_targets(self, args, extra, line):
        nick = (args + " " + extra).strip()
        if not nick:
            await self.ui_queue.put(("status", "Usage: /targets <nick>"))
            return
        nl = nick.lower()
        tgt = self._targets.get(nl)
        if not tgt:
            await self.ui_queue.put(("status", f"No targeting data for {nick}"))
            return
        sw = self._status_win()
        total = sum(tgt.values())
        sw.add_line(f"── Targeting score: {nick} ({total} addresses) ──")
        for other, count in tgt.most_common(20):
            pct = count / total * 100
            bar = "█" * int(pct / 5)
            sw.add_line(f"  {other:<20} {count:>4} ({pct:4.0f}%) {bar}")
        sw.add_line("  (messages starting with '<nick>:' or '<nick>,' )")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_fingerprint(self, args, extra, line) -> None:
        """Cross-nick linguistic similarity check.

        Builds a BotFingerprint for <nick> from their message history and
        compares it against fingerprints built for every other user, ranking
        them by Jaccard vocabulary + n-gram overlap.

        Usage: /fingerprint <nick> [min_similarity]
          min_similarity  – 0.0–1.0 threshold to show (default 0.0)
        """
        tokens = (args + " " + extra).strip().split()
        if not tokens:
            await self.ui_queue.put(("status",
                "Usage: /fingerprint <nick> [min_similarity]"))
            return

        target    = tokens[0]
        min_sim   = 0.0
        if len(tokens) > 1:
            try:
                min_sim = max(0.0, min(1.0, float(tokens[1])))
            except ValueError:
                pass

        _MSG_RE = re.compile(r'^\[\d{2}:\d{2}\] <(\S+?)> (.+)$')
        _ACT_RE = re.compile(r'^\[\d{2}:\d{2}\] \* (\S+) (.+)$')

        # One pass through all windows — collect message texts per nick
        nicks_msgs: Dict[str, List[str]] = {}
        for win in self.window_by_name.values():
            if win.name in ("*status*", "*dashboard*"):
                continue
            for ln in win.lines:
                m = _MSG_RE.match(ln)
                if m:
                    nicks_msgs.setdefault(m.group(1).lower(), []).append(m.group(2))
                    continue
                a = _ACT_RE.match(ln)
                if a:
                    nicks_msgs.setdefault(a.group(1).lower(), []).append(a.group(2))

        target_l = target.lower()
        if target_l not in nicks_msgs:
            await self.ui_queue.put(("status",
                f"/fingerprint: no messages found for '{target}'"))
            return

        target_msgs = nicks_msgs.pop(target_l)

        # Build target fingerprint
        target_fp = BotFingerprint(target)
        for msg in target_msgs:
            target_fp.ingest(msg)

        if target_fp.msg_count < 3:
            await self.ui_queue.put(("status",
                f"/fingerprint: too few msgs ({target_fp.msg_count}) for '{target}' — need ≥3"))
            return

        def _fp_similarity(a: BotFingerprint, b: BotFingerprint) -> float:
            if not a.word_vocab or not b.word_vocab:
                return 0.0
            vocab_j  = len(a.word_vocab & b.word_vocab) / len(a.word_vocab | b.word_vocab)
            bi_score = 0.0
            if a.bigrams and b.bigrams:
                bi_score = len(a.bigrams & b.bigrams) / len(a.bigrams | b.bigrams)
            tri_score = 0.0
            if a.trigrams and b.trigrams:
                tri_score = len(a.trigrams & b.trigrams) / len(a.trigrams | b.trigrams)
            return min(1.0, 0.25 * vocab_j + 0.35 * bi_score + 0.40 * tri_score)

        results = []
        for nick_l, msgs in nicks_msgs.items():
            if len(msgs) < 3:
                continue
            fp = BotFingerprint(nick_l)
            for msg in msgs:
                fp.ingest(msg)
            sim = _fp_similarity(target_fp, fp)
            if sim >= min_sim:
                results.append((sim, nick_l, fp.msg_count))

        results.sort(key=lambda x: -x[0])

        sw = self._status_win()
        sw.add_line(
            f"\u2500\u2500 Linguistic fingerprint: {target} "
            f"({target_fp.msg_count} msgs, {len(target_fp.word_vocab)} words, "
            f"{len(target_fp.bigrams)} bigrams, {len(target_fp.trigrams)} trigrams) "
            f"\u2500\u2500")
        if not results:
            sw.add_line("  No similar users found" +
                        (f"  (min similarity: {min_sim:.2f})" if min_sim > 0 else ""))
        else:
            sw.add_line(f"  {'Nick':<20} {'Sim':>6}  {'Msgs':>5}")
            _h = "\u2500" * 20; _hs = "\u2500" * 6; _hs2 = "\u2500" * 5
            sw.add_line(f"  {_h} {_hs}  {_hs2}")
            for sim, nick_l, msg_count in results[:20]:
                sw.add_line(f"  {nick_l:<20} {sim*100:5.1f}%  {msg_count:>5}")
        sw.add_line(f"\u2500\u2500 {len(results)} matches, showing top 20 \u2500\u2500")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_cluster(self, args, extra, line) -> None:
        """Show a nick's social circle — who they talk to, who addresses them,
        and what channels they share.

        Combines adjacency, targeting, inverse-targeting, and channel activity
        into a ranked list of connections.

        Usage: /cluster <nick>
        """
        nick = (args + " " + extra).strip()
        if not nick:
            await self.ui_queue.put(("status", "Usage: /cluster <nick>"))
            return

        nl = nick.lower()

        adj = self._adjacency.get(nl, {})
        adj_total = sum(adj.values()) if adj else 0

        tgt = self._targets.get(nl, {})
        tgt_total = sum(tgt.values()) if tgt else 0

        ch_act = self._ch_activity.get(nl, {})

        # Inverse targets — who addresses this nick
        inverse_tgt: Counter = Counter()
        for other_nick, targets in self._targets.items():
            if other_nick == nl:
                continue
            if nl in targets:
                inverse_tgt[other_nick] = targets[nl]
        inv_total = sum(inverse_tgt.values()) if inverse_tgt else 0

        all_connections = set(adj) | set(tgt) | set(inverse_tgt)
        connections = []
        for other in all_connections:
            adj_score = adj.get(other, 0)
            tgt_score = tgt.get(other, 0)
            inv_score = inverse_tgt.get(other, 0)

            adj_pct = (adj_score / adj_total * 100) if adj_total > 0 else 0
            tgt_pct = (tgt_score / tgt_total * 100) if tgt_total > 0 else 0
            inv_pct = (inv_score / inv_total * 100) if inv_total > 0 else 0

            # Weighted strength: adjacency (40%), targeting (35%), being targeted (25%)
            combined = adj_pct * 0.40 + tgt_pct * 0.35 + inv_pct * 0.25
            connections.append((combined, other, adj_score, tgt_score, inv_score))

        connections.sort(key=lambda x: -x[0])

        sw = self._status_win()
        ch_list = ", ".join(
            sorted(ch_act, key=lambda c: -ch_act[c])[:8]) if ch_act else ""
        sw.add_line(f"\u2500\u2500 Social cluster: {nick} \u2500\u2500")
        if ch_list:
            sw.add_line(f"  Channels: {ch_list}")
        if not connections:
            sw.add_line("  No social connections found.")
        else:
            sw.add_line(f"  {'Nick':<20} {'Str':>5}  {'Adj':>4} {'Tgt':>4} {'Inv':>4}")
            _h = "\u2500" * 20; _hs = "\u2500" * 5; _hs2 = "\u2500" * 4
            sw.add_line(f"  {_h} {_hs}  {_hs2} {_hs2} {_hs2}")
            for combined, other, adj_score, tgt_score, inv_score in connections[:20]:
                sw.add_line(
                    f"  {other:<20} {combined:4.0f}%  "
                    f"{adj_score:>4} {tgt_score:>4} {inv_score:>4}")
        sw.add_line(f"\u2500\u2500 {len(connections)} connections, showing top 20 \u2500\u2500")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_alias(self, args, extra, line):
        parts = (args + " " + extra).strip().split(maxsplit=1)
        if not parts or not parts[0]:
            if not self._aliases:
                await self.ui_queue.put(("status", "No aliases defined. Usage: /alias <name> <expansion>"))
                return
            sw = self._status_win()
            sw.add_line("── Aliases ──")
            for name in sorted(self._aliases):
                sw.add_line(f"  {name:<20} → {self._aliases[name]}")
            sw.add_line(f"── {len(self._aliases)} aliases ──")
            self._chat_dirty = True
            self.dirty = True
            return
        name = parts[0].lower()
        if name.startswith("-"):
            name = name[1:]
            self._aliases.pop(name, None)
            self._save_aliases()
            await self.ui_queue.put(("status", f"Alias removed: {name}"))
            return
        if len(parts) < 2 or not parts[1]:
            expansion = self._aliases.get(name)
            if expansion:
                await self.ui_queue.put(("status", f"Alias: {name} → {expansion}"))
            else:
                await self.ui_queue.put(("status", f"No alias defined for '{name}'"))
            return
        expansion = parts[1].strip()
        self._aliases[name] = expansion
        self._save_aliases()
        await self.ui_queue.put(("status", f"Alias set: {name} → {expansion}"))

    async def _slash_seen(self, args, extra, line):
        nick = (args + " " + extra).strip()
        if not nick:
            await self.ui_queue.put(("status", "Usage: /seen <nick>"))
            return
        nl = nick.lower()
        info = self._seen_times.get(nl)
        if not info:
            await self.ui_queue.put(("status", f"[seen] No record of '{nick}' in this session"))
            return
        ts, preview, channel = info
        dt = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        await self.ui_queue.put(("status",
            f"[seen] {nick} was last seen in {channel} at {dt}: {preview}"))

    async def _slash_tell(self, args, extra, line):
        parts = (args + " " + extra).strip().split(maxsplit=1)
        if len(parts) < 2:
            await self.ui_queue.put(("status", "Usage: /tell <nick> <message>"))
            return
        target_nick, tell_msg = parts
        tl = target_nick.lower()
        if tl == self._active_client().nick.lower():
            await self.ui_queue.put(("status", "[tell] You can't tell yourself"))
            return
        now = time.time()
        self._tell_queue.setdefault(tl, []).append(
            (self._active_client().nick, tell_msg, now))
        await self.ui_queue.put(("status",
            f"[tell] Message for {target_nick} queued ({len(self._tell_queue[tl])} pending)"))

    async def _slash_mute(self, args, extra, line):
        self.mention_beep_muted = not self.mention_beep_muted
        state = "muted" if self.mention_beep_muted else "unmuted"
        await self.ui_queue.put(("status", f"Mention beep {state} (highlight still active)"))

    async def _slash_autotranslate(self, args, extra, line):
        self.auto_translate = not self.auto_translate
        state = "ON" if self.auto_translate else "OFF"
        await self.ui_queue.put(("status", f"Auto-translate CJK → English: {state}"))

    async def _slash_linkpreview(self, args, extra, line):
        self.link_preview_enabled = not self.link_preview_enabled
        state = "ON" if self.link_preview_enabled else "OFF"
        await self.ui_queue.put(("status", f"Link preview {state}"))

    async def _slash_autojoin(self, args, extra, line):
        global _AUTOJOIN_CHANNELS
        p = args.strip().split(None, 1)
        if not p or p[0] not in ("+", "-", "list", "clear"):
            await self.ui_queue.put(("status", "Usage: /autojoin +<#chan> | -<#chan> | list | clear"))
            return
        sub = p[0]
        if sub == "list":
            if _AUTOJOIN_CHANNELS:
                await self.ui_queue.put(("status", f"Auto-join channels: {' '.join(sorted(_AUTOJOIN_CHANNELS))}"))
            else:
                await self.ui_queue.put(("status", "No auto-join channels configured"))
            return
        if sub == "clear":
            _AUTOJOIN_CHANNELS.clear()
            _save_autojoin_config()
            await self.ui_queue.put(("status", "Auto-join channel list cleared"))
            return
        chan = (p[1] if len(p) > 1 else "").strip()
        if not chan:
            await self.ui_queue.put(("status", f"Usage: /autojoin {sub} <#channel>"))
            return
        if not chan.startswith("#"):
            chan = "#" + chan
        if sub == "+":
            _AUTOJOIN_CHANNELS.add(chan)
            _save_autojoin_config()
            await self.ui_queue.put(("status", f"Auto-join: added {chan}"))
        elif sub == "-":
            _AUTOJOIN_CHANNELS.discard(chan)
            _save_autojoin_config()
            await self.ui_queue.put(("status", f"Auto-join: removed {chan}"))

    async def _slash_commands(self, args, extra, line):
        sw = self.window_by_name["*status*"]
        _C = lambda t: sw.add_line(t)
        _H = lambda title: _C(f"  ── {title} " + "─" * max(0, 38 - len(title)))
        _E = lambda c, d: _C(f"  {c:<34} {d}")
        _C("")
        _C("  ╔" + "═" * 44 + "╗")
        _C("  ║          Available IRC Commands          ║")
        _C("  ╚" + "═" * 44 + "╝")
        _C("")
        _H("Messaging")
        _E("/msg <nick> <text>",            "Send a PM; opens and switches to the DM window")
        _E("/query <nick> [message]",       "Open a DM window with nick; optionally send a first message")
        _E("/jitsi",                        "Generate a Jitsi Meet link and send it in the current PM")
        _E("/chain [nick]",                 "Show recent message chain for current window in status")
        _E("/idle <nick>",                  "24h activity heatmap for a user")
        _E("/together <n1> <n2>",           "Compare two users' channel overlap")
        _E("/adjacent <nick>",              "Show who speaks before/after a user")
        _E("/targets <nick>",               "Show who a user addresses most")
        _E("/notice <nick> <text>",         "Send a notice (-nick- style, not shown in chat)")
        _E("/me <text>",                    "Send an action line  (* nick waves)")
        _E("/reply <text>",                 "Reply to last message with +reply tag (IRCv3 message-tags)")
        _E("/react <emoji>",                "React to last message with +react TAGMSG (IRCv3 message-tags)")
        _E("/ml <l1> | <l2> | ...",         "Send multiline message via draft/multiline batch")
        _E("/redact [reason]",              "Redact last message in this window (message-redaction)")
        _E("/tagmsg <target> key=val[;k=v]","Send a TAGMSG with client-only tags to a target")
        _E("/x0 <path>",                    "Upload an image file to x0.at and share the URL")
        _C("")
        _H("Channels")
        _E("/join <channel>",               "Join a channel (# is added automatically if omitted)")
        _E("/part [channel] [message]",     "Leave a channel with an optional part message")
        _E("/topic [channel] [text]",       "View or set the channel topic (uses current channel)")
        _E("/names [channel]",              "List users currently in the channel")
        _E("/kick <chan> <nick> [reason]",  "Kick a user from the channel")
        _E("/invite <nick> [channel]",      "Invite a user to a channel")
        _E("/mode [channel] [modes]",       "Get or set channel modes (no args = show current)")
        _E("/autojoin +<chan> | -<chan> | list | clear","Add/remove/list/clear auto-join channels")
        _C("")
        _H("Operator")
        _E("/op <nick>",    "Grant operator status  (+o)")
        _E("/deop <nick>",  "Remove operator status (-o)")
        _E("/voice <nick>", "Grant voice  (+v)")
        _E("/devoice <nick>","Remove voice (-v)")
        _E("/hop <nick>",   "Grant half-op  (+h)")
        _E("/dehop <nick>", "Remove half-op (-h)")
        _E("/ban <nick|mask>","Ban user; bare nick expands to nick!*@*")
        _E("/ban -l", "List bans in current channel")
        _E("/unban <mask>", "Remove a ban mask")
        _C("")
        _H("Users & Status")
        _E("/nick <newnick>",               "Change your nickname")
        _E("/whois <nick>",                 "Look up user info — shown formatted in *status*")
        _E("/whowas <nick>",                "Info on a recently disconnected user")
        _E("/who <target>",                 "List users matching a pattern")
        _E("/ignore <nick>",                "Suppress all messages from nick")
        _E("/unignore <nick>",              "Stop ignoring nick")
        _E("/away [message]",               "Set away status with optional message")
        _E("/back",                         "Remove away status")
        _E("/seen <nick>",                  "Show when a nick was last seen in this session")
        _E("/tell <nick> <text>",           "Queue a message for delivery when nick next speaks")
        _E("/monitor + nick[,…] | - | list | clear | status","Watch nicks for online/offline notifications")
        _E("/whox [target] [fields]",       "Send a WHOX query with extended fields")
        _E("/cluster <nick>",               "Show a nick's social circle (adjacency + targets)")
        _E("/graph <nick> [depth]",          "Relationship graph: who nick talks to, mutual connections")
        _C("")
        _H("Productivity")
        _E("/todo [add <text> @priority #due +tag]", "Todo list: add/done/undo/remove/edit/list/clear")
        _E("/todo done <id>",                       "Mark a todo as completed")
        _E("/todo list [completed]",                "List todos (optionally include completed)")
        _E("/pomodoro start|stop|status|config",    "Pomodoro timer: 25/5/15 min work/break cycles")
        _E("/pomo start|stop",                      "Alias for /pomodoro")
        _E("/note [add <text> [cat]]",              "Scratchpad: add/edit/remove/list/search/pin/unpin/categories")
        _E("/memo <text>",                          "Alias for /note add")
        _E("/bookmark [add <target> [desc] type:X +tag]","Bookmarks: add/remove/list/search (channel/nick/url)")
        _E("/bm <target>",                          "Alias for /bookmark")
        _E("/timer <duration> [name]",               "Countdown timer: 5m tea, 30s break, 1h meeting")
        _E("/timer list|cancel <id>",               "List or cancel active timers")
        _E("/remind in 30m <msg>",                   "Set a reminder (in Xm, at HH:MM, tomorrow)")
        _E("/watch <nick> [channel]",                "Alert when a nick joins/speaks/mentions")
        _E("/snippet add|remove|list|<name>",         "Text snippets for quick insertion")
        _E("/chstats [channel]",                     "Channel activity stats: top talkers, heatmap")
        _E("/rss add|remove|list|poll",              "RSS feed bridge to IRC channels")
        _C("")
        _H("Services & CTCP")
        _E("/ns <command>",                 "Send command to NickServ  (e.g. /ns identify pw)")
        _E("/cs <command>",                 "Send command to ChanServ")
        _E("/ctcp <nick> <cmd> [args]",     "Send a CTCP request  (PING VERSION TIME …)")
        _E("/ctcpmode normal|off|spoof",   "CTCP leak protection: off=silent, spoof=fake replies")
        _C("")
        _H("AI Detection")
        _E("/ai <nick>",                    "Full AI profile: score, idle, sparkline, verdict")
        _E("/topai",                        "All scored users in current channel, ranked by AI%")
        _E("/bot <nick>",                   "Mark nick as confirmed bot/AI; builds typing fingerprint")
        _E("/unbot <nick>",                 "Remove confirmed-bot status and fingerprint for nick")
        _E("/aitoggle",                     "Enable or disable AI scoring (detection)")
        _E("/logtoggle",                    "Enable or disable AI detection logging to disk (default: on)")
        _E("/learn_tell <phrase>",          "Add n-grams from a phrase to the AI blocklist")
        _E("/forget_tell <phrase>",         "Remove n-grams of a phrase from the AI blocklist")
        _E("/scan_watermark [text]",        "Scan recent msgs or text for LLM watermark patterns")
        _E("/fingerprint <nick> [min_sim]", "Compare a nick's linguistic fingerprint against all others")
        _E("/feedback <ai|human> <nick>",   "Confirm AI/bot or human to tune detection weights")
        _E("/aicalibrate [status|reset|threshold]", "Inspect/adjust AI detection calibration from feedback")
        _E("/aivai [pair <n1> <n2>]",          "Detect AI-vs-AI conversation pairs (mutual high scores)")
        _E("/saicorr <nick|channel|anomaly>",  "Sentiment-AI score correlation analysis")
        _C("")
        _H("AI Integration  (Claude + OpenAI + Gemini + Ollama + llama.cpp)")
        _E("/askai [model] <question>",   "Ask AI a question; answer shown in dashboard")
        _E("/summarize [n] [model]",      "Summarize last n msgs in current window (default 50)")
        _E("/brief [channel]",            "AI one-paragraph summary of unread messages in channel")
        _E("/model [key]",                "Set/list AI models: opus sonnet haiku gpt4o gpt4 gpt35 gemini gpro")
        _E("/vibe <channel> [n] [model]", "Analyze channel culture using AI")
        _E("/explain <nick> [model]",     "Analyze a user's behavior using AI")
        _E("/api",                        "Show AI provider key status (Claude/OpenAI/Gemini/Ollama)")
        _E("/api <VAR_NAME> <value>",     "Set an API key in environment: ANTHROPIC_API_KEY OPENAI_API_KEY GEMINI_API_KEY OLLAMA_URL")
        _spec = AI_MODELS.get(self.ai_chat_model, {})
        _C(f"  Current model: {self.ai_chat_model}  ({_spec.get('label','?')}  [{_spec.get('provider','?')}])")
        _C("")
        _H("Translation")
        _E("/autotranslate",               "Toggle auto CJK → English translation (on by default)")
        _C("")
        _H("Connection")
        _E("/server [-ssl] <host> [port]", "Add a parallel server connection (SSL with -ssl, else plain)")
        _E("/reconnect",                   "Drop and re-establish (uses draft/resume token if available)")
        _E("/tor on|off|strict|nostrict|status", "Route IRC through Tor; strict = .onion only")
        _E("/replay [on|off|n|before|after|between <ts>]", "Request chat history via CHATHISTORY (needs /replay on)")
        _E("/register <account|*> <email> <pw>","Register an account via draft/account-registration")
        _E("/pem [/path/to.pem]",          "Generate NIST P-256 key pair for SASL ECDSA auth")
        _E("/certfp status|generate|fingerprint", "Auto-generate CertFP for SASL EXTERNAL auth")
        _E("/tlsinfo [history]",             "Show TLS cert fingerprint for server; alert on cert changes")
        _C("")
        _H("Windows & Navigation")
        _C("  Tab bar: [1:status] [2:dash] [*3:##chat]  * = unread  N = count  S = suspect")
        _E("/win <n>",    "Switch to window n; clears its unread marker")
        _E("/close  (or /wc)", "Close current window; focus moves to previous")
        _E("/clear",     "Clear messages in the current window")
        _E("/alias [name] [expansion]", "List, set or remove command alias (/alias -<name> to remove)")
        _E("/links [n]", "Show last n links shared in this channel (default 20)")
        _E("/list [pattern]","Fetch and display the server's channel list")
        _E("/lf [keyword|min=<n>]","Locally filter cached /list results by keyword or min users")
        _E("/theme <1-12>","Switch colour theme: Classic Hacker Ocean Sunset Neon Nord Dracula Monokai Solarized Gruvbox Tokyo Catppuccin")
        _E("/userlist",   "Toggle the user list panel on/off")
        _E("/znc <cmd>",  "Send a command to ZNC's *status (e.g. /znc play *chan 60)")
        _C("  Ctrl+N  next window    Tab/Shift+Tab  nick or command completion")
        _C("  Ctrl+A/E  line start/end    Ctrl+K  kill to end    Ctrl+W  delete word")
        _C("  Ctrl+B/]/_ bold/italic/underline    Ctrl+O  reset formatting")
        _C("  Ctrl+L  clear window    Ctrl+R  toggle userlist    Ctrl+G  go to window #")
        _C("  Ctrl+T  toggle link preview    Ctrl+Z  clear input    Esc  clear/close/reset dashboard")
        _C("  Left-click nick → /query    Left-click header → switch channel    Wheel → scroll")
        _C("")
        _H("BNC & GPG & Tor")
        _E("/bouncer on|off|status|detach|attach|replay","Built-in bouncer: buffer msgs when detached, replay on attach")
        _E("/bouncer replay [N]",                 "Replay buffered msgs (optional limit N)")
        _E("/bouncer limit [N]",                  "Set max msgs to replay on attach (0 = unlimited)")
        _E("/bouncer filter [all|highlights|dms]","Filter mode: all msgs, only highlights, or only DMs")
        _E("/bouncer clear",                      "Clear the message buffer without replaying")
        _E("/detach",                         "Shortcut for /bouncer detach")
        _E("/attach",                         "Shortcut for /bouncer attach")
        _E("/pgp key [fp]",                   "Set signing key; with no arg, show current key")
        _E("/pgp encrypt <nick> <msg>",       "Encrypt a message for nick's GPG key")
        _E("/pgp decrypt <b64>",              "Decrypt a base64-encoded GPG message")
        _E("/pgp sign <msg>",                 "Sign a message with your GPG key")
        _E("/pgp verify <msg> <sig>",         "Verify a detached signature")
        _E("/pgp list",                       "List GPG public keys in your keyring")
        _E("/tor on|off|strict|nostrict|status", "Route IRC through Tor; strict = .onion only")
        _C("")
        _H("Soju Bouncer Integration")
        _E("/soju networks",                   "List soju bouncer networks")
        _E("/soju add <name> host=<h> [k=v]",  "Add a network to the soju bouncer")
        _E("/soju del <name>",                  "Remove a network from the soju bouncer")
        _E("/soju update <name> k=v …",         "Change network attributes (nick, host, port)")
        _E("/soju replay [N]",                  "Request CHATHISTORY replay for current channel")
        _E("/soju status",                      "Show soju connection state, caps, networks")
        _E("/replay before|after <ts> [N]",     "Fetch messages before/after a timestamp")
        _E("/replay between <ts> [N]",          "Fetch messages in a timestamp range")
        _C("")
        _E("/loadplugin <path>",   "Load a Python plugin file; its setup(api) is called")
        _E("/unloadplugin <name>", "Unload a plugin and remove its commands")
        _E("/reloadplugin <name>", "Reload a plugin from its original file (hot-swap)")
        _E("/plugins [name]",      "List loaded plugins; with name, show detailed info")
        _E("/script load|unload|reload|list", "Manage Python/Lua scripts in scripts/ dir")
        _C("  Plugins auto-load from plugins/ directory on startup")
        _C("  Plugin API: command(), on(event), send(), status(), schedule(), get_config()")
        _C("")
        _H("General")
        _E("/redraw [channel]",   "Force full screen repaint and reload userlist from server")
        _E("/quit [message]", "Send quit message and exit")
        _E("/help",           "Brief one-line command reference")
        _E("/commands",       "This full command list")
        _E("/mute",           "Toggle mention beep on/off (highlight stays active)")
        _E("/linkpreview",    "Toggle automatic URL link preview on/off")
        _E("/dcc <sub>",      "DCC: send|tsend|resume|chat|trust|untrust|trusted|status — file/chat transfers")
        _E("/dccchat close|list", "Manage DCC CHAT connections")
        _C("")
        self.current_window_index = 0
        self._chat_dirty = True
        self.dirty = True

    async def _slash_help(self, args, extra, line):
        for l in [
            "── Messaging ──────────────────────────────────────────────",
            "  /msg <nick> <text>       PM nick; opens & switches to DM window",
            "  /query <nick> [message]  Open a DM window (optional first message)",
            "  /jitsi                   Jitsi video call — sends link in current PM",
            "  /notice <nick> <text>    Send a notice   /me <text>  Action line",
            "── Channels ──────────────────────────────────────────────",
            "  /join <chan>  /part [chan] [msg]  /topic [chan] [text]",
            "  /kick <chan> <nick> [reason]  /invite <nick> [chan]",
            "  /names [chan]  /mode [chan] [modes]",
            "── Operator ──────────────────────────────────────────────",
            "  /op /deop /voice /devoice /hop /dehop  /ban [-l] /unban",
            "── Users ─────────────────────────────────────────────────",
            "  /nick <new>  /whois <nick>  /whowas <nick>  /who <pat>",
            "  /idle <nick>     24h activity heatmap",
            "  /adjacent <nick>  who speaks before/after",
            "  /targets <nick>   who they address most",
            "  /together <n1> <n2>  channel overlap",
            "  /cluster <nick>  social circle  /graph <nick> [depth]  relationship map",
            "  /ignore <nick>  /unignore <nick>  /away [msg]  /back",
            "── Services ──────────────────────────────────────────────",
            "  /ns <cmd>  /cs <cmd>  /ctcp <nick> <cmd> [args]",
            "  /ctcpmode normal|off|spoof       CTCP leak protection",
            "── AI Detection ──────────────────────────────────────────",
            "  /ai <nick>  full profile    /topai  channel ranking by AI%",
            "  /aitoggle  enable/disable scoring    /logtoggle  toggle log",
            "  /aicalibrate  inspect/adjust detection calibration from feedback",
            "  /aivai  detect AI-vs-AI pairs  /saicorr  sentiment-AI correlation",
            "── AI  (Claude / OpenAI) ─────────────────────────────────",
            "  /askai [model] <question>  (answer in dashboard)",
            "  /summarize [n] [model]  /brief [chan]  unread channel summary",
            "  /summarize [n] [model]  summarize last n msgs (default 50)",
            "  /model [key]  set/list model  (opus sonnet haiku gpt4o gpt4 gpt35 gemini gpro)",
            "── Translation ───────────────────────────────────────────",
            "  /autotranslate  toggle CJK → English (default: on)",
            "── Productivity ──────────────────────────────────────────",
            "  /todo add <text> @priority #due +tag  /todo done|undo|remove|list|clear",
            "  /pomodoro start|stop|status|config  /pomo  alias",
            "  /note add <text> [cat]  /note list|search|pin|unpin|edit|remove|categories",
            "  /bookmark add <target> [desc] type:X +tag  /bm  alias",
            "  /timer <5m|30s|1h> [name]  countdown with notification  /timer list|cancel",
            "  /remind in 30m <msg>  /watch <nick>  /snippet add|list|<name>  /chstats  /rss",
            "── Connection ─────────────────────────────────────────────",
            "  /server [-ssl] <host> [port]  (parallel; -ssl for TLS)  /reconnect",
            "  /certfp generate|fingerprint|status  CertFP for SASL EXTERNAL",
            "  /tlsinfo [history]  TLS cert pinning + MITM change alerts",
            "── BNC & GPG & Tor ─────────────────────────────────────────",
            "  /bouncer on|off|status|detach|attach|replay   built-in BNC",
            "  /pgp encrypt|decrypt|sign|verify|key|list     GPG crypto",
            "  /tor on|off|strict|nostrict|status            Tor SOCKS5; strict=onion only",
            "── Soju Bouncer ──────────────────────────────────────────",
            "  /soju networks|add|del|update|replay|status   manage soju networks",
            "  /replay before|after|between <ts> [N]         time-based chathistory",
            "── Interface ──────────────────────────────────────────────",
            "  /win <n>  /close (/wc)  /clear  /links  /list [pat]  /lf <kw|min=n>",
            "  /alias [name] [expansion]  list/set/remove command aliases",
            "  /chain [nick]  message tree for current window  /jitsi  video call",
            "  /theme <1-5>  /userlist  Ctrl+N next window  /dcc send|tsend|resume|trust|chat|status",
            "  Tab/Shift+Tab nick-complete  PgUp/Dn scroll",
            "  Left-click a highlighted URL line to open it in the browser",
            "  Left-click a nick in userlist or chat to open a DM /query",
            "  Left-click the userlist header to jump to that channel window",
            "  Tab bar: [1:status] [2:dash] [*3:##chat]  * = unread",
            "  /quit [msg]  /commands  (full list)  /help  (this)",
            "  /redraw [channel]  force repaint + reload userlist from server",
            "── Plugins ────────────────────────────────────────────────",
            "  /loadplugin <path>  load .py plugin    /plugins  list loaded",
            "  /unloadplugin <name>    /reloadplugin <name>  hot-swap",
            "── Scripts ──────────────────────────────────────────────────",
            "  /script load <path>  load .py/.lua    /script list  loaded",
            "  /script unload <name>    /script reload  all hot-reload",
        ]:
            self.window_by_name["*status*"].add_line(l)
        self.current_window_index = 0
        self._chat_dirty = self._userlist_dirty = self._input_dirty = True
        self.dirty = True

    async def _slash_userlist(self, args, extra, line):
        self._show_userlist = not self._show_userlist
        self._resize_windows()
        state = "shown" if self._show_userlist else "hidden"
        await self.ui_queue.put(("status", f"Userlist {state}"))

    async def _slash_lf(self, args, extra, line):
        """Locally filter the cached channel list by keyword or min users."""
        if not self._cached_list_results:
            await self.ui_queue.put(("status", "No cached list results. Run /list first."))
            return
        results = self._cached_list_results
        kw = (args + " " + extra).strip()
        if kw.startswith("min="):
            try:
                min_users = int(kw[4:])
            except ValueError:
                await self.ui_queue.put(("status", "Usage: /lf min=<number>"))
                return
            filtered = [r for r in results if r[1].isdigit() and int(r[1]) >= min_users]
            desc = f"with ≥{min_users} users"
        elif kw:
            kw_lower = kw.lower()
            filtered = [r for r in results if kw_lower in r[0].lower() or kw_lower in r[2].lower()]
            desc = f"matching '{kw}'"
        else:
            filtered = list(results)
            desc = "all"
        sw = self._status_win()
        sw.add_line(f"── Filtered list ({len(filtered)} channels {desc}) ──")
        for ch, users, topic in filtered:
            short_topic = topic[:60] + "…" if len(topic) > 60 else topic
            sw.add_line(f"  {ch:<20} {users:>4}  {short_topic}")
        sw.add_line("── End ──")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_dcc(self, args, extra, line):
        """Manage DCC file transfers."""
        parts = (args + " " + extra).strip().split()
        if not parts:
            await self.ui_queue.put(("status", "Usage: /dcc <send|tsend|resume|chat|trust|untrust|trusted|status> ..."))
            return
        sub = parts[0].lower()
        if sub in ("send", "tsend"):
            turbo = sub == "tsend"
            if len(parts) < 3:
                await self.ui_queue.put(("status", f"Usage: /dcc {sub} <nick> <filepath>"))
                return
            nick = parts[1]
            filepath = " ".join(parts[2:])
            if not os.path.isfile(filepath):
                await self.ui_queue.put(("status", f"File not found: {filepath}"))
                return
            client = self._active_client()
            if turbo:
                tid = client.cmd_dcc_tsend(nick, filepath)
            else:
                tid = client.cmd_dcc_send(nick, filepath)
            await self.ui_queue.put(("status", f"DCC {tid}: {'turbo-' if turbo else ''}sending {filepath} to {nick}"))
        elif sub == "resume":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /dcc resume <tid>"))
                return
            tid = parts[1]
            client = self._active_client()
            if tid not in client._dcc_in:
                await self.ui_queue.put(("status", f"No incoming DCC transfer '{tid}'"))
                return
            client.cmd_dcc_resume(tid)
            await self.ui_queue.put(("status", f"DCC: resume requested for {tid}"))
        elif sub == "chat":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /dcc chat <nick>"))
                return
            nick = parts[1]
            client = self._active_client()
            tid = client.cmd_dcc_chat(nick)
            if tid:
                win_name = self._dcc_chat_window_name(nick)
                self.ensure_window(win_name, is_channel=False)
                w = self.window_by_name[win_name]
                w.add_line(f"* DCC CHAT initiating with {nick}...")
                self.current_window_index = self.windows.index(w)
                self._sync_draw_ctx()
                await self.ui_queue.put(("status", f"DCC CHAT: offering chat to {nick}"))
        elif sub == "trust":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /dcc trust <nick>"))
                return
            nick = parts[1].lower()
            self._dcc_trusted.add(nick)
            cfg = load_irc_config()
            cfg["dcc_trusted"] = sorted(self._dcc_trusted)
            save_irc_config(cfg)
            await self.ui_queue.put(("status", f"DCC: {parts[1]} added to trusted list"))
        elif sub == "untrust":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /dcc untrust <nick>"))
                return
            nick = parts[1].lower()
            self._dcc_trusted.discard(nick)
            cfg = load_irc_config()
            cfg["dcc_trusted"] = sorted(self._dcc_trusted)
            save_irc_config(cfg)
            await self.ui_queue.put(("status", f"DCC: {parts[1]} removed from trusted list"))
        elif sub == "trusted":
            if self._dcc_trusted:
                await self.ui_queue.put(("status", f"DCC trusted: {', '.join(sorted(self._dcc_trusted))}"))
            else:
                await self.ui_queue.put(("status", "DCC trusted list is empty"))
        elif sub == "status":
            active = []
            for client in [c.client for c in self.servers.values()]:
                for tid, entry in getattr(client, "_dcc_out", {}).items():
                    active.append(f"{tid}: {entry['nick']} {entry['sent']}/{entry['total']}")
                for tid, entry in getattr(client, "_dcc_in", {}).items():
                    active.append(f"{tid}: {entry['nick']} {entry.get('sent',0)}/{entry['total']}")
                for tid, entry in getattr(client, "_dcc_chats", {}).items():
                    s = "connected" if entry.get("writer") else "waiting"
                    active.append(f"{tid}: CHAT {entry['nick']} ({s})")
            if active:
                for s in active:
                    await self.ui_queue.put(("status", f"  {s}"))
            else:
                await self.ui_queue.put(("status", "No active DCC transfers"))
        else:
            await self.ui_queue.put(("status", "Subcommands: send, tsend, resume, chat, trust, untrust, trusted, status"))

    async def _slash_dccchat(self, args, extra, line):
        """Manage DCC CHAT connections."""
        parts = (args + " " + extra).strip().split()
        if not parts:
            await self.ui_queue.put(("status", "Usage: /dccchat close <nick>"))
            return
        sub = parts[0].lower()
        if sub == "close":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /dccchat close <nick>"))
                return
            nick = parts[1]
            client = self._active_client()
            for tid, entry in list(client._dcc_chats.items()):
                if entry["nick"] == nick:
                    client.dcc_chat_close(tid)
                    await self.ui_queue.put(("status", f"DCC CHAT with {nick} closed"))
                    break
            else:
                await self.ui_queue.put(("status", f"No active DCC CHAT with {nick}"))
        elif sub == "list":
            client = self._active_client()
            if not client._dcc_chats:
                await self.ui_queue.put(("status", "No active DCC CHAT connections"))
            else:
                for tid, entry in client._dcc_chats.items():
                    status = "connected" if entry.get("writer") else "waiting"
                    await self.ui_queue.put(("status", f"DCC CHAT {tid}: {entry['nick']} ({status})"))
        else:
            await self.ui_queue.put(("status", "Usage: /dccchat close <nick> | list"))

    async def _slash_list(self, args, extra, line):
        """Fetch and display the server's channel list (RPL_LIST 322/323)."""
        pattern = (args + " " + extra).strip()
        client = self._active_client()
        client._list_results = []
        if pattern:
            client.send_raw(f"LIST {pattern}")
            await self.ui_queue.put(("status", f"Fetching channel list matching '{pattern}'…"))
        else:
            client.send_raw("LIST")
            await self.ui_queue.put(("status", "Fetching channel list…"))

    async def _slash_links(self, args, extra, line):
        """Show recent links for the current channel window."""
        parts = args.strip().split()
        n = 20
        filter_nick = ""
        for p in parts:
            if p.isdigit():
                n = max(5, min(200, int(p)))
            else:
                filter_nick = p.lower()
        win = self.get_current_window()
        if win.name in ("*status*", "*dashboard*"):
            await self.ui_queue.put(("status", "/links: switch to a channel or DM window first"))
            return
        entries = _load_link_history(win.name, limit=n)
        if not entries:
            await self.ui_queue.put(("status", f"No link history for {win.name}"))
            return
        if filter_nick:
            entries = [e for e in entries if e.get("nick", "").lower() == filter_nick]
        if not entries:
            await self.ui_queue.put(("status", f"No matching links for {filter_nick} in {win.name}"))
            return
        sw = self._status_win()
        sw.add_line(f"── Recent links in {win.name} ({len(entries)}) ──")
        for e in reversed(entries):
            nick = e.get("nick", "?")
            url  = e.get("url", "")
            dt   = e.get("dt", "")[5:16] if e.get("dt") else ""
            title = e.get("title", "") or ""
            preview = (title[:60] + "…") if len(title) > 60 else title
            line = f"  [{dt}] <{nick}> {url[:80]}"
            if preview:
                line += f"  {preview}"
            sw.add_line(line)
        sw.add_line(f"── End of link history ──")
        self.current_window_index = 0
        self._chat_dirty = True
        self.dirty = True

    async def _slash_replay(self, args, extra, line):
        """Request chat history for the current channel via CHATHISTORY."""
        a = args.strip().lower()
        c = self._active_client()
        if a in ("on", "enable"):
            c._replay_enabled = True
            await self.ui_queue.put(("status", "[replay] chat history replay enabled"))
            return
        if a in ("off", "disable"):
            c._replay_enabled = False
            await self.ui_queue.put(("status", "[replay] chat history replay disabled"))
            return
        if not c._replay_enabled:
            await self.ui_queue.put(("status",
                "[replay] disabled — use /replay on to enable, then /replay [n] to fetch"))
            return
        chan = self.current_channel or ""
        if not chan.startswith("#"):
            await self.ui_queue.put(("status", "[replay] must be in a channel"))
            return
        parts = a.split()
        subcmd = "LATEST"
        count = 50
        timestamp = ""
        if parts and parts[0] in ("before", "after", "between", "latest", "targets"):
            subcmd = parts[0].upper()
            if subcmd == "BETWEEN" and len(parts) >= 2:
                timestamp = parts[1]
                count = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 50
            elif subcmd in ("BEFORE", "AFTER") and len(parts) >= 2:
                timestamp = parts[1]
                count = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 50
            elif len(parts) > 1 and parts[1].isdigit():
                count = int(parts[1])
        elif a.isdigit():
            count = int(a)
        count = max(1, min(count, 500))
        c.cmd_chathistory(chan, count, subcmd=subcmd, timestamp=timestamp)
        label = subcmd.lower()
        if timestamp:
            await self.ui_queue.put(("status",
                f"[replay] requesting {label} from {timestamp} for {chan}…"))
        else:
            await self.ui_queue.put(("status",
                f"[replay] requesting last {count} messages for {chan}…"))

    async def _slash_soju(self, args, extra, line):
        """Manage soju bouncer networks and settings."""
        c = self._active_client()
        parts = args.strip().split()
        sub = parts[0].lower() if parts else ""
        if sub in ("networks", "list", "ls"):
            if not c._soju_networks:
                await self.ui_queue.put(("status", "[soju] no networks loaded (not connected to soju?)"))
                return
            for nid, attrs in sorted(c._soju_networks.items(),
                                     key=lambda x: x[1].get("name", x[0])):
                name = attrs.get("name", nid)
                host = attrs.get("host", "?")
                state = attrs.get("state", "?")
                nick = attrs.get("nick", "")
                extra_info = f" nick={nick}" if nick else ""
                await self.ui_queue.put(("status",
                    f"  {name}: host={host} state={state}{extra_info}"))
        elif sub == "add":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "[soju] usage: /soju add <name> host=<h> [nick=<n>] [port=<p>]"))
                return
            name = parts[1]
            kv_parts = [f"host={name}"]  # fallback
            for p in parts[2:]:
                if "=" in p:
                    kv_parts.append(p)
                else:
                    kv_parts.append(f"host={p}")
            c.send_raw(f"BOUNCER ADDNETWORK {name} {' '.join(kv_parts)}")
            await self.ui_queue.put(("status", f"[soju] adding network '{name}'…"))
        elif sub in ("del", "remove", "rm"):
            if len(parts) < 2:
                await self.ui_queue.put(("status", "[soju] usage: /soju del <name>"))
                return
            name = parts[1]
            c.send_raw(f"BOUNCER DELNETWORK {name}")
            await self.ui_queue.put(("status", f"[soju] removing network '{name}'…"))
        elif sub in ("update", "change", "set"):
            if len(parts) < 2:
                await self.ui_queue.put(("status", "[soju] usage: /soju update <name> key=value …"))
                return
            name = parts[1]
            kv_parts = [p for p in parts[2:] if "=" in p]
            if not kv_parts:
                await self.ui_queue.put(("status", "[soju] need key=value pairs"))
                return
            c.send_raw(f"BOUNCER CHANGENETWORK {name} {' '.join(kv_parts)}")
            await self.ui_queue.put(("status", f"[soju] updating network '{name}'…"))
        elif sub == "replay":
            if not c._soju_is_bouncer:
                await self.ui_queue.put(("status", "[soju] not connected to a soju bouncer"))
                return
            chan = self.current_channel or ""
            if not chan.startswith("#"):
                await self.ui_queue.put(("status", "[soju] must be in a channel to replay"))
                return
            count_str = parts[1] if len(parts) > 1 else "50"
            count = int(count_str) if count_str.isdigit() else 50
            c.cmd_chathistory(chan, count)
            await self.ui_queue.put(("status", f"[soju] replaying last {count} for {chan}…"))
        elif sub == "status":
            bnc = "YES" if c._soju_is_bouncer else "NO"
            ch = c._chathistory_cap or "none"
            nets = len(c._soju_networks)
            caps = sorted(k for k in c._active_caps if "soju" in k or "bouncer" in k)
            await self.ui_queue.put(("status",
                f"[soju] bouncer={bnc} chathistory={ch} networks={nets} caps={','.join(caps) or 'none'}"))
        else:
            await self.ui_queue.put(("status",
                "Usage: /soju networks|add <n> [k=v]|del <n>|update <n> k=v|replay [N]|status"))

    async def _slash_graph(self, args, extra, line):
        """Visualize interaction patterns for a nick."""
        c = self._active_client()
        target = args.strip().lower()
        if not target:
            await self.ui_queue.put(("status",
                "Usage: /graph <nick> [depth]  — show who nick talks to"))
            return
        parts = target.split()
        nick = parts[0]
        depth = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
        depth = min(depth, 3)
        rel = c.scoring.relationships
        conn = rel.get_connections(nick, depth=depth)
        if nick not in conn:
            await self.ui_queue.put(("status",
                f"[graph] no interaction data for '{nick}'"))
            return
        root_data = conn[nick]
        lines = [f"=== Relationship graph for {nick} ==="]
        top = root_data.get("top", {})
        if top:
            lines.append("  Top interactions:")
            for other, weight in sorted(top.items(), key=lambda x: -x[1])[:15]:
                bar = "█" * min(20, max(1, weight))
                lines.append(f"    {other:15s} {bar} ({weight})")
        mutual = rel.get_mutual(nick, limit=10)
        if mutual:
            lines.append("  Mutual (bidirectional):")
            for other, out_w, in_w in mutual:
                lines.append(f"    {other:15s} →{out_w} ←{in_w}")
        channels = root_data.get("channels", [])
        if channels:
            lines.append(f"  Shared channels: {', '.join(channels)}")
        if depth > 1:
            lines.append(f"  Extended (depth={depth}): {len(conn) - 1} secondary connections")
            for secondary, sdata in sorted(conn.items()):
                if secondary == nick:
                    continue
                s_top = list(sdata.get("top", {}).keys())[:5]
                if s_top:
                    lines.append(f"    {secondary}: → {', '.join(s_top)}")
        rel.save()
        sw = self.window_by_name.get("*status*")
        if sw:
            for ln in lines:
                sw.add_line(ln)
            self._chat_dirty = True
            self.dirty = True

    async def _slash_aicalibrate(self, args, extra, line):
        """Inspect and adjust AI detection calibration."""
        if _NO_AI:
            await self.ui_queue.put(("status", "[aicalibrate] disabled by --no-ai")); return
        c = self._active_client()
        cal = c.scoring.calibration
        sub = (args or "").strip().lower()
        if sub in ("status", ""):
            summary = cal.get_summary()
            lines = [
                "=== AI Calibration Status ===",
                f"  Total feedback    : {summary['total_feedback']}",
                f"  AI confirmations  : {summary['ai_confirmations']}",
                f"  Human corrections : {summary['human_corrections']}",
                f"  Signals tracked   : {summary['signals']}",
                "  Thresholds:",
            ]
            for name, val in summary["thresholds"].items():
                lines.append(f"    {name:20s}: {val:.1f}")
            reliability = cal.get_signal_reliability()
            if reliability:
                lines.append("  Signal reliability:")
                for sig, info in sorted(reliability.items(), key=lambda x: -x[1]["separation"]):
                    mark = "✓" if info["reliable"] else "?"
                    lines.append(
                        f"    {mark} {sig:20s}: ai={info['ai_avg']:.3f} "
                        f"human={info['human_avg']:.3f} sep={info['separation']:.3f}")
            weight_adj = cal.get_weight_adjustments()
            if weight_adj:
                lines.append("  Recommended weight adjustments:")
                for sig, adj in sorted(weight_adj.items(), key=lambda x: -abs(x[1])):
                    if adj != 0:
                        direction = "↑" if adj > 0 else "↓"
                        lines.append(f"    {sig:20s}: {direction} {abs(adj):.3f}")
            recent = summary.get("recent", [])
            if recent:
                lines.append("  Recent feedback:")
                for entry in recent[-5:]:
                    lines.append(
                        f"    {entry['nick']:15s} → {entry['label'].upper():5s} "
                        f"(score: {entry.get('ai_score', 0):.0f})")
            sw = self.window_by_name.get("*status*")
            if sw:
                for ln in lines:
                    sw.add_line(ln)
                self._chat_dirty = True
                self.dirty = True
        elif sub == "reset":
            cal.reset()
            await self.ui_queue.put(("status",
                "[aicalibrate] calibration data reset to defaults"))
        elif sub.startswith("threshold"):
            parts = sub.split()
            if len(parts) >= 4:
                name = parts[1]
                try:
                    value = float(parts[2])
                    if name in ("ai_confirm", "human_confirm", "review"):
                        cal._thresholds[name] = value
                        cal._save()
                        await self.ui_queue.put(("status",
                            f"[aicalibrate] threshold '{name}' set to {value:.1f}"))
                    else:
                        await self.ui_queue.put(("status",
                            f"[aicalibrate] unknown threshold: {name}"))
                except ValueError:
                    await self.ui_queue.put(("status",
                        "[aicalibrate] invalid threshold value"))
            else:
                await self.ui_queue.put(("status",
                    "Usage: /aicalibrate threshold <name> <value>"))
        else:
            await self.ui_queue.put(("status",
                "Usage: /aicalibrate status|reset|threshold <name> <value>"))

    async def _slash_certfp(self, args, extra, line):
        """Auto-generate CertFP for SASL EXTERNAL authentication."""
        sub = (args or "").strip().lower()
        cert_dir = _SCRIPT_DIR
        cert_path = os.path.join(cert_dir, "client.pem")
        key_path = os.path.join(cert_dir, "client.key")

        if sub in ("status", ""):
            lines = ["=== CertFP Status ==="]
            if os.path.exists(cert_path) and os.path.exists(key_path):
                try:
                    from cryptography import x509
                    from cryptography.hazmat.primitives import serialization
                    with open(cert_path, "rb") as f:
                        cert = x509.load_pem_x509_certificate(f.read())
                    with open(key_path, "rb") as f:
                        key = serialization.load_pem_private_key(f.read(), password=None)
                    der = cert.public_bytes(serialization.Encoding.DER)
                    fp = hashlib.sha256(der).hexdigest()
                    subject = cert.subject.rfc4514_string()
                    not_after = cert.not_valid_after_utc.isoformat()
                    lines.append(f"  Cert: {cert_path}")
                    lines.append(f"  Key:  {key_path}")
                    lines.append(f"  Subject: {subject}")
                    lines.append(f"  Expires: {not_after}")
                    lines.append(f"  SHA-256: {fp}")
                    lines.append(f"  SASL EXTERNAL: ready — set SASL_MECHANISM=EXTERNAL")
                except ImportError:
                    lines.append(f"  Cert: {cert_path}")
                    lines.append(f"  Key:  {key_path}")
                    lines.append("  (install 'cryptography' for cert details)")
            else:
                lines.append("  No CertFP found. Use /certfp generate to create one.")
            if SASL_MECHANISM == "EXTERNAL":
                lines.append(f"  SASL EXTERNAL: enabled (mechanism={SASL_MECHANISM})")
            else:
                lines.append(f"  SASL EXTERNAL: not active (mechanism={SASL_MECHANISM})")
            sw = self.window_by_name.get("*status*")
            if sw:
                for ln in lines:
                    sw.add_line(ln)
                self._chat_dirty = True
                self.dirty = True
            return

        if sub == "generate":
            try:
                from cryptography import x509
                from cryptography.hazmat.primitives import hashes, serialization
                from cryptography.hazmat.primitives.asymmetric import ec
                from cryptography.x509.oid import NameOID
                import datetime
                key = ec.generate_private_key(ec.SECP256R1())
                subject = issuer = x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, self._active_client().nick or "ircclient"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "eyearesee CertFP"),
                ])
                cert = (
                    x509.CertificateBuilder()
                    .subject_name(subject)
                    .issuer_name(issuer)
                    .public_key(key.public_key())
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(datetime.datetime.utcnow())
                    .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
                    .sign(key, hashes.SHA256())
                )
                with open(cert_path, "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
                with open(key_path, "wb") as f:
                    f.write(key.private_bytes(
                        serialization.Encoding.PEM,
                        serialization.PrivateFormat.TraditionalOpenSSL,
                        serialization.NoEncryption()))
                der = cert.public_bytes(serialization.Encoding.DER)
                fp = hashlib.sha256(der).hexdigest()
                await self.ui_queue.put(("status",
                    f"[certfp] generated NIST P-256 cert+key pair"))
                await self.ui_queue.put(("status",
                    f"[certfp] SHA-256 fingerprint: {fp}"))
                await self.ui_queue.put(("status",
                    f"[certfp] cert={cert_path}  key={key_path}"))
                await self.ui_queue.put(("status",
                    "[certfp] To use SASL EXTERNAL, restart with: "
                    "SASL_MECHANISM=EXTERNAL SASL_CERT=client.pem SASL_KEY=client.key"))
            except ImportError:
                await self.ui_queue.put(("status",
                    "[certfp] 'cryptography' package required: pip install cryptography"))
            except Exception as e:
                await self.ui_queue.put(("status",
                    f"[certfp] generation failed: {e}"))

        elif sub == "fingerprint":
            if not os.path.exists(cert_path):
                await self.ui_queue.put(("status",
                    "[certfp] no cert found — use /certfp generate first"))
                return
            try:
                with open(cert_path, "rb") as f:
                    cert_data = f.read()
                from cryptography.hazmat.primitives import serialization
                from cryptography import x509
                cert = x509.load_pem_x509_certificate(cert_data)
                der = cert.public_bytes(serialization.Encoding.DER)
                fp_sha256 = hashlib.sha256(der).hexdigest()
                fp_sha1 = hashlib.sha1(der).hexdigest()
                await self.ui_queue.put(("status",
                    f"[certfp] SHA-256: {fp_sha256}"))
                await self.ui_queue.put(("status",
                    f"[certfp] SHA-1:   {fp_sha1}"))
                await self.ui_queue.put(("status",
                    "[certfp] Register with NickServ: /msg NickServ CERT ADD {fp_sha256}"))
            except ImportError:
                with open(cert_path, "rb") as f:
                    pem_data = f.read()
                import subprocess
                try:
                    result = subprocess.run(
                        ["openssl", "x509", "-noout", "-fingerprint", "-sha256", "-in", cert_path],
                        capture_output=True, text=True, timeout=10)
                    if result.returncode == 0:
                        await self.ui_queue.put(("status",
                            f"[certfp] {result.stdout.strip()}"))
                    else:
                        await self.ui_queue.put(("status",
                            "[certfp] install 'cryptography' or 'openssl' to get fingerprint"))
                except Exception:
                    await self.ui_queue.put(("status",
                        "[certfp] install 'cryptography' or 'openssl' to get fingerprint"))
            except Exception as e:
                await self.ui_queue.put(("status",
                    f"[certfp] fingerprint failed: {e}"))

        else:
            await self.ui_queue.put(("status",
                "Usage: /certfp status|generate|fingerprint"))

    async def _slash_tlsinfo(self, args, extra, line):
        """Show TLS certificate fingerprint and history for current server."""
        c = self._active_client()
        sub = (args or "").strip().lower()
        fp = c.scoring.tls_fingerprinter
        if sub == "history":
            history = fp.get_history(c.server)
            if not history:
                await self.ui_queue.put(("status",
                    f"[tls] no cert change history for {c.server}"))
                return
            lines = [f"=== TLS cert history for {c.server} ==="]
            for entry in history:
                ts = time.strftime("%Y-%m-%d %H:%M",
                    time.localtime(entry.get("last_seen", 0)))
                lines.append(f"  {ts}  {entry.get('fingerprint', '?')[:32]}…")
            sw = self.window_by_name.get("*status*")
            if sw:
                for ln in lines:
                    sw.add_line(ln)
                self._chat_dirty = True
                self.dirty = True
        else:
            status = fp.get_status(c.server)
            if not status:
                await self.ui_queue.put(("status",
                    f"[tls] no TLS fingerprint data for {c.server}"))
                return
            lines = [f"=== TLS info for {c.server} ==="]
            if "fingerprint" in status:
                lines.append(f"  SHA-256: {status['fingerprint']}")
            if "tls_version" in status:
                lines.append(f"  TLS version: {status['tls_version']}")
            if "cipher" in status:
                lines.append(f"  Cipher: {status['cipher']}")
            if "issuer" in status:
                lines.append(f"  Issuer: {status['issuer']}")
            if "subject" in status:
                lines.append(f"  Subject: {status['subject']}")
            if "last_seen" in status:
                ts = time.strftime("%Y-%m-%d %H:%M", time.localtime(status["last_seen"]))
                lines.append(f"  Last seen: {ts}")
            history = status.get("history", [])
            if history:
                lines.append(f"  Cert changes: {len(history)}")
            sw = self.window_by_name.get("*status*")
            if sw:
                for ln in lines:
                    sw.add_line(ln)
                self._chat_dirty = True
                self.dirty = True

    async def _slash_aivai(self, args, extra, line):
        """Detect and list AI-vs-AI conversation pairs."""
        c = self._active_client()
        sub = (args or "").strip().lower()
        if sub in ("nick", "pair"):
            nick_a = (extra or "").strip().split()[0] if extra.strip() else ""
            nick_b = (extra or "").strip().split()[1] if len(extra.strip().split()) > 1 else ""
            if not nick_a or not nick_b:
                await self.ui_queue.put(("status",
                    "Usage: /aivai pair <nick1> <nick2>"))
                return
            pair = c.scoring.ai_vs_ai.get_pair(nick_a, nick_b)
            if not pair:
                await self.ui_queue.put(("status",
                    f"[aivai] no data for {nick_a} ↔ {nick_b}"))
                return
            lines = [
                f"=== AI-vs-AI: {pair['nick_a']} ↔ {pair['nick_b']} ===",
                f"  Channel: {pair['channel']}",
                f"  Exchanges: {pair['exchanges']}",
                f"  Both-high exchanges: {pair['both_high']}",
                f"  Average AI score: {pair['avg_ai']}%",
                f"  Gap uniformity: {pair['gap_uniformity']:.3f}",
                f"  Confidence: {pair['confidence']:.0%}",
            ]
            sw = self.window_by_name.get("*status*")
            if sw:
                for ln in lines:
                    sw.add_line(ln)
                self._chat_dirty = True
                self.dirty = True
        else:
            pairs = c.scoring.ai_vs_ai.get_active_pairs(min_confidence=0.2)
            if not pairs:
                await self.ui_queue.put(("status",
                    "[aivai] no AI-vs-AI conversation pairs detected"))
                return
            lines = ["=== Active AI-vs-AI Pairs ==="]
            for p in pairs[:15]:
                bar = "█" * int(p["confidence"] * 20)
                lines.append(
                    f"  {p['nick_a']:12s} ↔ {p['nick_b']:12s}  "
                    f"conf={p['confidence']:.0%} {bar}  "
                    f"avg_ai={p['avg_ai']}%  "
                    f"exchanges={p['exchanges']}")
            sw = self.window_by_name.get("*status*")
            if sw:
                for ln in lines:
                    sw.add_line(ln)
                self._chat_dirty = True
                self.dirty = True

    async def _slash_saicorr(self, args, extra, line):
        """Inspect sentiment-AI score correlation per nick or channel."""
        if _NO_AI:
            await self.ui_queue.put(("status", "[saicorr] disabled by --no-ai")); return
        c = self._active_client()
        sub = (args or "").strip().lower()
        if sub in ("anomaly", "anomalies"):
            anomalies = c.scoring.sentiment_ai.get_top_anomalies(limit=15)
            if not anomalies:
                await self.ui_queue.put(("status",
                    "[saicorr] no sentiment anomalies detected"))
                return
            lines = ["=== Sentiment Anomalies (uniform sentiment + high AI) ==="]
            for a in anomalies:
                lines.append(
                    f"  {a['nick']:15s}  samples={a['samples']}  "
                    f"high_ai={a['high_ai_count']}  "
                    f"variance={a['sentiment_variance']:.4f}  "
                    f"corr={a['correlation']}")
            sw = self.window_by_name.get("*status*")
            if sw:
                for ln in lines:
                    sw.add_line(ln)
                self._chat_dirty = True
                self.dirty = True
        elif sub == "channel":
            chan = (extra or "").strip() or self.current_channel or ""
            if not chan.startswith("#"):
                await self.ui_queue.put(("status",
                    "[saicorr] specify a channel"))
                return
            corr = c.scoring.sentiment_ai.get_channel_correlation(chan)
            lines = [
                f"=== Sentiment-AI Correlation: {chan} ===",
                f"  Samples: {corr['samples']}",
                f"  Correlation (r): {corr['correlation'] or 'insufficient data'}",
                f"  AI msg sentiment avg: {corr.get('ai_sentiment_avg', 'N/A')}",
                f"  Human msg sentiment avg: {corr.get('human_sentiment_avg', 'N/A')}",
                f"  AI msg intensity avg: {corr.get('ai_intensity_avg', 'N/A')}",
                f"  Human msg intensity avg: {corr.get('human_intensity_avg', 'N/A')}",
                f"  High-AI %: {corr.get('high_ai_pct', 'N/A')}%",
            ]
            sw = self.window_by_name.get("*status*")
            if sw:
                for ln in lines:
                    sw.add_line(ln)
                self._chat_dirty = True
                self.dirty = True
        else:
            nick = (args or "").strip().lower()
            if nick:
                corr = c.scoring.sentiment_ai.get_nick_correlation(nick)
                lines = [
                    f"=== Sentiment-AI Correlation: {nick} ===",
                    f"  Samples: {corr['samples']}",
                    f"  Correlation (r): {corr['correlation'] or 'insufficient data'}",
                    f"  AI msg sentiment avg: {corr.get('ai_sentiment_avg', 'N/A')}",
                    f"  Human msg sentiment avg: {corr.get('human_sentiment_avg', 'N/A')}",
                    f"  Sentiment variance: {corr['sentiment_variance']:.4f}",
                    f"  High-AI messages: {corr['high_ai_count']}",
                    f"  Anomaly: {'YES — ' + corr['anomaly_reason'] if corr['anomaly'] else 'no'}",
                ]
                sw = self.window_by_name.get("*status*")
                if sw:
                    for ln in lines:
                        sw.add_line(ln)
                    self._chat_dirty = True
                    self.dirty = True
            else:
                await self.ui_queue.put(("status",
                    "Usage: /saicorr <nick> | channel [chan] | anomaly"))

    async def _slash_brief(self, args, extra, line):
        """AI-generated summary of what happened since you last read the channel."""
        if _NO_AI:
            await self.ui_queue.put(("status", "[brief] disabled by --no-ai")); return
        c = self._active_client()
        chan = (args or "").strip()
        if not chan:
            chan = self.current_channel or ""
        if not chan.startswith("#"):
            await self.ui_queue.put(("status",
                "[brief] must specify a channel or be in one"))
            return
        win = self.window_by_name.get(self._wk(self._active_server_id(), chan))
        if not win:
            await self.ui_queue.put(("status", f"[brief] no window for {chan}"))
            return
        # Determine unread start index
        unread_from = win._unread_from
        if unread_from < 0:
            raw_lines = list(win.lines)[-50:]
            label = "last 50 messages"
        else:
            raw_lines = list(win.lines)[unread_from:]
            label = f"{len(raw_lines)} unread messages"
        if not raw_lines:
            await self.ui_queue.put(("status", f"[brief] no messages in {chan}"))
            return
        if len(raw_lines) > 200:
            raw_lines = raw_lines[-200:]
            label = f"last 200 of {len(list(win.lines)[unread_from:])} messages"
        _TS_RE = re.compile(r'^\[\d{2}:\d{2}\]\s*')
        _SPEAKER_RE = re.compile(r'^<(\S+?)>')
        cleaned = [irc_strip_formatting(_TS_RE.sub("", ln)) for ln in raw_lines]
        transcript = "\n".join(cleaned)
        speakers = set()
        for ln in raw_lines:
            m = _SPEAKER_RE.match(irc_strip_formatting(_TS_RE.sub("", ln)))
            if m:
                speakers.add(m.group(1))
        speaker_hint = (f"Active speakers: {', '.join(sorted(speakers))}.\n"
                        if speakers else "")
        prompt = (
            f"The following is an IRC chat log from \"{chan}\" ({label}).\n"
            f"{speaker_hint}"
            f"Write a ONE-PARAGRAPH summary (under 150 words) of what happened.\n"
            f"Focus on: key topics discussed, decisions made, questions asked, "
            f"and any notable interactions between users.\n"
            f"Name the users involved. Be specific but concise.\n\n"
            f"Chat log:\n{transcript}"
        )
        model_key, model_id, label_m = self._resolve_ai_model(None)
        await self.ui_queue.put(("status",
            f"[brief] summarizing {chan} ({label}) via {label_m}…"))
        task = asyncio.create_task(
            self._do_brief(prompt, model_key, model_id, chan, len(raw_lines)))
        self._bg_tasks.add(task)
        task.add_done_callback(self._bg_tasks.discard)

    async def _do_brief(self, prompt: str, model_key: str, model_id: str,
                         chan: str, n_msgs: int) -> None:
        try:
            answer, tokens = await asyncio.wait_for(
                self._call_ai(prompt, model_key, max_tokens=400), timeout=120.0)
            if answer:
                answer = answer.strip()
                sw = self.window_by_name.get("*status*")
                if sw:
                    sw.add_line(f"=== Brief: {chan} ({n_msgs} msgs) ===")
                    for paragraph in answer.split("\n\n"):
                        if paragraph.strip():
                            sw.add_line(f"  {paragraph.strip()}")
                    sw.add_line("")
                    self._chat_dirty = True
                    self.dirty = True
        except asyncio.TimeoutError:
            await self.ui_queue.put(("status", "[brief] AI request timed out"))
        except Exception as e:
            await self.ui_queue.put(("status", f"[brief] AI error: {e}"))

    async def _slash_monitor(self, args, extra, line):
        """MONITOR a nick for online/offline notifications."""
        c = self._active_client()
        parts = args.strip().split(None, 1)
        subcmd = parts[0].lower() if parts else ""
        nicks_raw = parts[1] if len(parts) > 1 else ""
        nicks = [n.strip() for n in nicks_raw.split(",") if n.strip()]
        if subcmd in ("+", "add", "watch") and nicks:
            c.cmd_monitor_add(nicks)
            await self.ui_queue.put(("status", f"[monitor] watching: {', '.join(nicks)}"))
        elif subcmd in ("-", "del", "remove") and nicks:
            c.cmd_monitor_remove(nicks)
            await self.ui_queue.put(("status", f"[monitor] stopped watching: {', '.join(nicks)}"))
        elif subcmd in ("c", "clear"):
            c.cmd_monitor_clear()
            await self.ui_queue.put(("status", "[monitor] cleared all"))
        elif subcmd in ("l", "list"):
            c.cmd_monitor_list()
        elif subcmd in ("s", "status"):
            c.cmd_monitor_status()
        else:
            await self.ui_queue.put(("status",
                "Usage: /monitor + nick[,…] | - nick[,…] | list | clear | status"))

    async def _slash_whox(self, args, extra, line):
        """Send a WHOX query for the current channel or given target."""
        c = self._active_client()
        parts = args.strip().split(None, 1)
        target = parts[0] if parts else (self.current_channel or "")
        fields = parts[1].replace(" ", "") if len(parts) > 1 else "hnuraf"
        if not target:
            await self.ui_queue.put(("status", "Usage: /whox [target] [fields]"))
            return
        c.cmd_whox(target, fields)

    async def _slash_tagmsg(self, args, extra, line):
        """Send a TAGMSG with client-only tags to target."""
        c = self._active_client()
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            await self.ui_queue.put(("status",
                "Usage: /tagmsg <target> key=value[;key2=value2]"))
            return
        target, tag_str = parts
        tags: dict = {}
        for part in tag_str.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                tags[k.strip()] = v.strip()
            elif part.strip():
                tags[part.strip()] = ""
        c.cmd_tagmsg(target, tags)
        await self.ui_queue.put(("status", f"[tagmsg] sent to {target}: {tag_str}"))

    async def _slash_reply(self, args, extra, line):
        """Send a PRIVMSG with +reply tag referencing the last message in this window."""
        slash_end = line.index(" ") + 1 if " " in line else len(line)
        text = line[slash_end:].strip()
        if not text:
            await self.ui_queue.put(("status", "Usage: /reply <text>"))
            return
        win = self.get_current_window()
        if win.name in ("*status*", "*dashboard*"):
            await self.ui_queue.put(("status", "/reply: not in a chat window"))
            return
        if not win._last_msgid:
            await self.ui_queue.put(("status",
                "/reply: no msgid — server may not support message-tags"))
            return
        client = self._active_client()
        client.send_tagged({"+reply": win._last_msgid}, f"PRIVMSG {win.name} :{text}")
        ref = win._msg_store.get(win._last_msgid)
        if ref:
            ref_nick, ref_prev = ref
            p = ref_prev[:50] + "…" if len(ref_prev) > 50 else ref_prev
            win.add_line(f"  ↩ {ref_nick}: {p}", timestamp=False)
        win.add_line(f"<{client.nick}> {text}")
        self._chat_dirty = True
        self.dirty = True

    async def _slash_react(self, args, extra, line):
        """Send a +react TAGMSG to the last message in this window."""
        emoji = args.strip()
        if not emoji:
            await self.ui_queue.put(("status", "Usage: /react <emoji>"))
            return
        win = self.get_current_window()
        if win.name in ("*status*", "*dashboard*"):
            await self.ui_queue.put(("status", "/react: not in a chat window"))
            return
        if not win._last_msgid:
            await self.ui_queue.put(("status",
                "/react: no msgid — server may not support message-tags"))
            return
        client = self._active_client()
        client.cmd_tagmsg(win.name, {"+react": emoji, "+reply": win._last_msgid})
        nicks = win._reactions.setdefault(win._last_msgid, {}).setdefault(emoji, [])
        if client.nick not in nicks:
            nicks.append(client.nick)
        win._wrap_dirty = True
        self._chat_dirty = True
        self.dirty = True

    async def _slash_multiline(self, args, extra, line):
        """Send a multiline message using draft/multiline batch (| = line break)."""
        slash_end = line.index(" ") + 1 if " " in line else len(line)
        text_raw = line[slash_end:].strip()
        if not text_raw:
            await self.ui_queue.put(("status", "Usage: /ml <line1> | <line2> | ..."))
            return
        win = self.get_current_window()
        if win.name in ("*status*", "*dashboard*"):
            await self.ui_queue.put(("status", "/ml: not in a chat window"))
            return
        # Replace | separators with actual newlines
        text = "\n".join(part.strip() for part in text_raw.split("|"))
        client = self._active_client()
        result = client.cmd_msg(win.name, text)
        if result:
            await self.ui_queue.put(result)

    async def _slash_redact(self, args, extra, line):
        """Redact the last message in this window (message-redaction CAP)."""
        win = self.get_current_window()
        if win.name in ("*status*", "*dashboard*"):
            await self.ui_queue.put(("status", "/redact: not in a chat window"))
            return
        if not win._last_msgid:
            await self.ui_queue.put(("status",
                "/redact: no msgid — server may not support message-tags"))
            return
        reason = (args + (" " + extra if extra else "")).strip()
        client = self._active_client()
        if reason:
            client.send_raw(f"REDACT {win.name} {win._last_msgid} :{reason}")
        else:
            client.send_raw(f"REDACT {win.name} {win._last_msgid}")

    async def _slash_register(self, args, extra, line):
        """Register a new account via draft/account-registration.

        Usage: /register <account|*> <email> <password>
        Use * as account to register the current nick as the account name.
        """
        c = self._active_client()
        if "draft/account-registration" not in c._active_caps:
            await self.ui_queue.put(("status",
                "[register] server does not support draft/account-registration"))
            return
        parts = args.strip().split(None, 2)
        if len(parts) < 3:
            await self.ui_queue.put(("status",
                "Usage: /register <account|*> <email> <password>"))
            return
        account, email, password = parts
        c.send_raw(f"REGISTER {account} {email} :{password}")

    async def _slash_pem(self, args, extra, line):
        """Generate a NIST P-256 key pair for SASL ECDSA-NIST256P-CHALLENGE.

        Saves the private key to a PEM file, sends the public key to NickServ
        with SET PUBKEY, and updates irc_config.json to use the new key.

        Usage: /pem [/path/to/output.pem]
        Default path: <script_dir>/<nick>_sasl.pem
        """
        if not CRYPTOGRAPHY_AVAILABLE:
            await self.ui_queue.put(("status",
                "[pem] requires the 'cryptography' package — pip install cryptography"))
            return

        c = self._active_client()
        key_path = args.strip() if args.strip() else \
            os.path.join(os.getcwd(), f"{c.nick}_sasl.pem")

        # Generate ECDSA P-256 key pair.
        try:
            private_key = _ecdsa_ec.generate_private_key(_ecdsa_ec.SECP256R1())
        except Exception as exc:
            await self.ui_queue.put(("status", f"[pem] key generation failed: {exc}"))
            return

        # Persist private key as unencrypted PKCS8 PEM.
        try:
            from cryptography.hazmat.primitives.serialization import (
                Encoding, PrivateFormat, PublicFormat, NoEncryption,
            )
            pem_bytes = private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.PKCS8,
                encryption_algorithm=NoEncryption(),
            )
            with open(key_path, "wb") as _kf:
                _kf.write(pem_bytes)
        except Exception as exc:
            await self.ui_queue.put(("status", f"[pem] failed to save private key: {exc}"))
            return

        # Encode public key as base64 of the uncompressed EC point (0x04 || X || Y).
        # This is the format Atheme NickServ expects for SET PUBKEY.
        try:
            pub_bytes = private_key.public_key().public_bytes(
                encoding=Encoding.X962,
                format=PublicFormat.UncompressedPoint,
            )
            pub_b64 = base64.b64encode(pub_bytes).decode()
        except Exception as exc:
            await self.ui_queue.put(("status", f"[pem] failed to encode public key: {exc}"))
            return

        # Send public key to NickServ.
        c.cmd_service("NickServ", f"SET PUBKEY {pub_b64}")

        # Persist key path and mechanism to irc_config.json so the next launch
        # automatically uses ECDSA without manual env-var setup.
        try:
            _cfg = load_irc_config()
            _cfg["sasl_key"]       = key_path
            _cfg["sasl_mechanism"] = "ECDSA-NIST256P-CHALLENGE"
            save_irc_config(_cfg)
        except Exception:
            pass

        await self.ui_queue.put(("status", f"[pem] private key saved → {key_path}"))
        await self.ui_queue.put(("status", f"[pem] public key sent to NickServ (SET PUBKEY)"))
        await self.ui_queue.put(("status",
            "[pem] irc_config.json updated: sasl_mechanism=ECDSA-NIST256P-CHALLENGE"))

    async def _slash_redraw(self, args, extra, line):
        channel = args.strip() or self.current_channel or ""
        # Clear all subwindows so the next noutrefresh repaints from scratch.
        # This fixes display corruption without restarting curses.
        for w in (self.chat_win, self.user_win, self.input_win):
            try:
                w.clearok(True)
            except curses.error:
                pass
        self._chat_dirty = self._userlist_dirty = self._input_dirty = True
        self.dirty = True
        if channel and channel.startswith("#"):
            # Flush the stale userlist so the NAMES reply replaces it entirely
            # rather than merging on top of potentially outdated entries.
            self.channel_users.setdefault(channel, set()).clear()
            self._sorted_users.pop(channel, None)
            self._active_client().cmd_names(channel)
            await self.ui_queue.put(("status",
                f"Redrawing and refreshing userlist for {channel}…"))
        else:
            await self.ui_queue.put(("status", "Redrawing screen…"))

    # ── Plugin management commands ───────────────────────────────────────────

    async def _slash_loadplugin(self, args, extra, line):
        path = args.strip()
        if not path:
            await self.ui_queue.put(("status",
                "Usage: /loadplugin <path/to/plugin.py>"))
            return
        ok, msg = self.plugin_manager.load(path, self)
        prefix = "[plugin] " if ok else "[plugin:error] "
        await self.ui_queue.put(("status", prefix + msg))

    async def _slash_unloadplugin(self, args, extra, line):
        name = args.strip()
        if not name:
            await self.ui_queue.put(("status", "Usage: /unloadplugin <name>"))
            return
        ok, msg = self.plugin_manager.unload(name)
        prefix = "[plugin] " if ok else "[plugin:error] "
        await self.ui_queue.put(("status", prefix + msg))

    async def _slash_reloadplugin(self, args, extra, line):
        name = args.strip()
        if not name:
            await self.ui_queue.put(("status", "Usage: /reloadplugin <name>"))
            return
        ok, msg = self.plugin_manager.reload(name, self)
        prefix = "[plugin] " if ok else "[plugin:error] "
        await self.ui_queue.put(("status", prefix + msg))

    async def _slash_plugins(self, args, extra, line):
        plugins = self.plugin_manager.list_plugins()
        if not plugins:
            await self.ui_queue.put(("status",
                "[plugin] No plugins loaded — use /loadplugin <path>"))
            return
        query = (args + " " + extra).strip()
        if query:
            info = self.plugin_manager.get_plugin_info(query)
            if not info:
                await self.ui_queue.put(("status", f"[plugin] No plugin named '{query}'"))
                return
            await self.ui_queue.put(("status", f"=== Plugin: {info['name']} ==="))
            if info["version"]:
                await self.ui_queue.put(("status", f"  Version   : {info['version']}"))
            if info["author"]:
                await self.ui_queue.put(("status", f"  Author    : {info['author']}"))
            if info["description"]:
                await self.ui_queue.put(("status", f"  Desc      : {info['description']}"))
            await self.ui_queue.put(("status", f"  Path      : {info['path']}"))
            cmds_str = "  ".join(f"/{c}" for c in info["commands"]) if info["commands"] else "(none)"
            await self.ui_queue.put(("status", f"  Commands  : {cmds_str}"))
            hooks_str = ", ".join(info["hooks"]) if info["hooks"] else "(none)"
            await self.ui_queue.put(("status", f"  Hooks     : {hooks_str}"))
            if info["keybindings"]:
                kb_str = ", ".join(info["keybindings"])
                await self.ui_queue.put(("status", f"  Keys      : {kb_str}"))
            if info["config"]:
                await self.ui_queue.put(("status", f"  Config    : {info['config']}"))
            return
        for info in plugins:
            meta = []
            if info["version"]:
                meta.append(f"v{info['version']}")
            if info["author"]:
                meta.append(f"by {info['author']}")
            meta_str = f"  [{', '.join(meta)}]" if meta else ""
            cmds_str = "  ".join(f"/{c}" for c in info["commands"]) if info["commands"] else "(no commands)"
            await self.ui_queue.put(("status", f"[plugin] {info['name']}{meta_str}  {cmds_str}"))

    async def _slash_script(self, args, extra, line):
        parts = (args + " " + extra).strip().split()
        if not parts:
            await self.ui_queue.put(("status", "Usage: /script load|unload|reload|list"))
            return
        sub = parts[0].lower()
        if sub == "load":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /script load <path>"))
                return
            ok, msg = self.script_engine.load(parts[1])
            await self.ui_queue.put(("status", f"[script] {msg}"))
        elif sub == "unload":
            if len(parts) < 2:
                await self.ui_queue.put(("status", "Usage: /script unload <name>"))
                return
            ok, msg = self.script_engine.unload(parts[1])
            await self.ui_queue.put(("status", f"[script] {msg}"))
        elif sub == "reload":
            self.script_engine = ScriptEngine(self)
            msgs = self.script_engine.load_all()
            for m in msgs:
                await self.ui_queue.put(("status", f"[script] {m}"))
        elif sub == "list":
            scripts = self.script_engine.list_scripts()
            if not scripts:
                await self.ui_queue.put(("status", "[script] No scripts loaded"))
            else:
                for name, lang in scripts:
                    await self.ui_queue.put(("status", f"[script] {name} ({lang})"))
        elif sub == "dir":
            await self.ui_queue.put(("status", f"[script] Scripts directory: {SCRIPT_DIR_SCRIPTS}"))
        else:
            await self.ui_queue.put(("status", "Usage: /script load|unload|reload|list|dir"))

    async def _slash_x0(self, args, extra, line):
        path = args.strip()
        if not path:
            await self.ui_queue.put(("status", "Usage: /x0 <path/to/image>"))
            return
        if not os.path.isfile(path):
            await self.ui_queue.put(("status", f"File not found: {path}"))
            return
        ext = os.path.splitext(path)[1].lower()
        if ext not in _IMAGE_EXTENSIONS:
            await self.ui_queue.put(("status",
                f"Unsupported file type '{ext}'. Supported: {', '.join(sorted(_IMAGE_EXTENSIONS))}"))
            return
        await self.ui_queue.put(("status", f"Uploading {path} to x0.at\u2026"))
        loop = asyncio.get_event_loop()
        url = await loop.run_in_executor(_IO_EXECUTOR, _upload_to_x0, path)
        if url:
            await self.ui_queue.put(("status", f"Uploaded: {url}"))
        else:
            await self.ui_queue.put(("status", "x0.at upload failed."))

    def _handle_key(self, ch: int) -> bool:
        """Process a single keycode synchronously.  Returns True if the key was
        Enter (so the caller can await handle_input_line and break the drain loop),
        False for all other keys."""
        if ch in (curses.KEY_ENTER, 10, 13):
            return True   # caller handles asynchronously

        elif ch in (curses.KEY_BACKSPACE, 127, 8):
            self._active_client().biometrics.record_keypress(is_backspace=True)
            if self.input_cursor > 0:
                self.input_buffer = (self.input_buffer[:self.input_cursor - 1]
                                     + self.input_buffer[self.input_cursor:])
                self.input_cursor -= 1
            self.completion_state = None
            self._input_dirty = True
            self.dirty = True

        elif ch == curses.KEY_DC:
            if self.input_cursor < len(self.input_buffer):
                self.input_buffer = (self.input_buffer[:self.input_cursor]
                                     + self.input_buffer[self.input_cursor + 1:])
            self._input_dirty = True
            self.dirty = True

        elif ch == curses.KEY_LEFT:
            if self.input_cursor > 0:
                self.input_cursor -= 1
            self._input_dirty = True
            self.dirty = True

        elif ch == curses.KEY_RIGHT:
            if self.input_cursor < len(self.input_buffer):
                self.input_cursor += 1
            self._input_dirty = True
            self.dirty = True

        elif ch == curses.KEY_HOME:
            if self.input_buffer:
                if self.input_cursor > 0:
                    self.input_cursor = 0
                    self._input_dirty = True
                    self.dirty = True
                else:
                    win = self.get_current_window()
                    self._wrap_window(win)
                    win.scroll_offset = max(0, len(win.wrapped_cache) - self._content_height)
                    self._chat_dirty = True
                    self.dirty = True
            else:
                win = self.get_current_window()
                self._wrap_window(win)
                win.scroll_offset = max(0, len(win.wrapped_cache) - self._content_height)
                self._chat_dirty = True
                self.dirty = True

        elif ch == curses.KEY_END:
            if self.input_cursor < len(self.input_buffer):
                self.input_cursor = len(self.input_buffer)
                self._input_dirty = True
                self.dirty = True
            else:
                self.get_current_window().scroll_offset = 0
                self._chat_dirty = True
                self.dirty = True

        elif ch == 1:    # Ctrl+A
            self.input_cursor = 0
            self._input_dirty = True
            self.dirty = True

        elif ch == 5:    # Ctrl+E
            self.input_cursor = len(self.input_buffer)
            self._input_dirty = True
            self.dirty = True

        elif ch == 11:   # Ctrl+K
            self.input_buffer = self.input_buffer[:self.input_cursor]
            self._input_dirty = True
            self.dirty = True

        elif ch == 21:   # Ctrl+U
            self.input_buffer = ""
            self.input_cursor = 0
            self.history_index  = -1
            self._history_draft = ""
            self.completion_state = None
            self._input_dirty = True
            self.dirty = True

        elif ch == 23:   # Ctrl+W
            buf = self.input_buffer
            pos = self.input_cursor
            while pos > 0 and buf[pos - 1] == " ": pos -= 1
            while pos > 0 and buf[pos - 1] != " ": pos -= 1
            self.input_buffer = buf[:pos] + buf[self.input_cursor:]
            self.input_cursor = pos
            self.completion_state = None
            self._input_dirty = True
            self.dirty = True

        elif ch == 2:    # Ctrl+B — bold
            self.input_buffer = (self.input_buffer[:self.input_cursor]
                                 + "\x02" + self.input_buffer[self.input_cursor:])
            self.input_cursor += 1
            self._input_dirty = True
            self.dirty = True

        elif ch == 29:   # Ctrl+] — italic
            self.input_buffer = (self.input_buffer[:self.input_cursor]
                                 + "\x1D" + self.input_buffer[self.input_cursor:])
            self.input_cursor += 1
            self._input_dirty = True
            self.dirty = True

        elif ch == 31:   # Ctrl+_ — underline
            self.input_buffer = (self.input_buffer[:self.input_cursor]
                                 + "\x1F" + self.input_buffer[self.input_cursor:])
            self.input_cursor += 1
            self._input_dirty = True
            self.dirty = True

        elif ch == 15:   # Ctrl+O — reset formatting
            self.input_buffer = (self.input_buffer[:self.input_cursor]
                                 + "\x0F" + self.input_buffer[self.input_cursor:])
            self.input_cursor += 1
            self._input_dirty = True
            self.dirty = True

        elif ch == 6:    # Ctrl+F — word right
            pos = self.input_cursor
            buf = self.input_buffer
            while pos < len(buf) and buf[pos] == " ": pos += 1
            while pos < len(buf) and buf[pos] != " ": pos += 1
            self.input_cursor = pos
            self._input_dirty = True
            self.dirty = True

        elif ch == 16:   # Ctrl+P — previous history
            _hlen = len(self.input_history)
            if _hlen:
                if self.history_index == -1:
                    self._history_draft = self.input_buffer
                self.history_index = min(self.history_index + 1, _hlen - 1)
                self.input_buffer = self.input_history[self.history_index]
                self.input_cursor = len(self.input_buffer)
                self._input_dirty = True
                self.dirty = True

        elif ch == curses.KEY_UP:
            if self.input_buffer or self.history_index >= 0:
                _hlen = len(self.input_history)
                if _hlen:
                    if self.history_index == -1:
                        self._history_draft = self.input_buffer
                    self.history_index = min(self.history_index + 1, _hlen - 1)
                    self.input_buffer = self.input_history[self.history_index]
                    self.input_cursor = len(self.input_buffer)
                    self._input_dirty = True
                    self.dirty = True
            else:
                win = self.get_current_window()
                self._wrap_window(win)
                max_off = max(0, len(win.wrapped_cache) - self._content_height)
                win.scroll_offset = min(win.scroll_offset + 1, max_off)
                self._chat_dirty = True
                self.dirty = True

        elif ch == curses.KEY_DOWN:
            if self.history_index >= 0:
                self.history_index -= 1
                self.input_buffer = (self._history_draft if self.history_index < 0
                                     else self.input_history[self.history_index])
                self.input_cursor = len(self.input_buffer)
                self._input_dirty = True
                self.dirty = True
            else:
                win = self.get_current_window()
                win.scroll_offset = max(0, win.scroll_offset - 1)
                self._chat_dirty = True
                self.dirty = True

        elif ch == 9:    # Tab — nick completion or command completion
            buf = self.input_buffer[:self.input_cursor]
            if buf.startswith("/"):
                # Command completion: /partial_command
                self.do_command_complete()
            else:
                self.do_nick_complete()

        elif ch == curses.KEY_BTAB:  # Shift+Tab — reverse nick completion
            buf = self.input_buffer[:self.input_cursor]
            if buf.startswith("/"):
                self.do_command_complete(reverse=True)
            else:
                self.do_nick_complete(reverse=True)

        elif ch == 3:    # Ctrl+C
            raise SystemExit

        elif ch == 14:   # Ctrl+N — next window
            self.switch_to_next_window()
            self._chat_dirty = self._userlist_dirty = True

        elif ch == curses.KEY_PPAGE:
            win = self.get_current_window()
            self._wrap_window(win)
            max_off = max(0, len(win.wrapped_cache) - self._content_height)
            win.scroll_offset = min(win.scroll_offset + self._content_height // 2, max_off)
            self._chat_dirty = True
            self.dirty = True

        elif ch == curses.KEY_NPAGE:
            win = self.get_current_window()
            win.scroll_offset = max(0, win.scroll_offset - self._content_height // 2)
            self._chat_dirty = True
            self.dirty = True

        elif ch == curses.KEY_MOUSE:
            try:
                _, mx, my, _, bstate = curses.getmouse()
            except curses.error:
                return False
            # Scroll wheel: BUTTON4_PRESSED = up, BUTTON5_PRESSED = down.
            # Bit values differ between ncurses and PDCurses — resolved at init.
            if bstate & (self._wheel_up | self._wheel_down):
                win = self.get_current_window()
                if bstate & self._wheel_up:
                    self._wrap_window(win)
                    max_off = max(0, len(win.wrapped_cache) - self._content_height)
                    win.scroll_offset = min(win.scroll_offset + 3, max_off)
                elif bstate & self._wheel_down:
                    win.scroll_offset = max(0, win.scroll_offset - 3)
                self._chat_dirty = True
                self.dirty = True
                return True
            # Fire on any button-1 event (press or click) regardless of platform
            # constant differences between ncurses and pdcurses/windows-curses.
            # Values 1-16 cover: released, pressed, clicked, double, triple.
            if not (bstate & 0x001F):
                return False
            chat_w = self.chat_win.getmaxyx()[1]
            if my >= self.chat_height:
                # Tab bar is on input_win row 1 (absolute row = chat_height + 1)
                if my == self.chat_height + 1:
                    self._handle_tab_click(mx)
                return False

            # Userlist column: click on nick → /query, click on header → switch window
            if mx >= chat_w and mx < self.width:
                # Determine which channel the userlist is showing
                cur_win = self.get_current_window()
                if cur_win.is_channel and cur_win.name in self.channel_users:
                    disp_ch = cur_win.name
                elif self.current_channel and self.current_channel in self.channel_users:
                    disp_ch = self.current_channel
                else:
                    disp_ch = None

                if my == 0 and disp_ch:
                    # Click on header → switch to that channel window
                    # Reset dashboard state when navigating away
                    prev_win = self.get_current_window()
                    if prev_win.name == "*dashboard*":
                        self._dashboard_mode = "suspects"
                        self._dashboard_profile_locked = False
                    for i, w in enumerate(self.windows):
                        if w.name == disp_ch:
                            self.current_window_index = i
                            self.current_channel = disp_ch
                            self._chat_dirty = self._userlist_dirty = self._input_dirty = True
                            self.dirty = True
                            return True
                elif my >= 1 and disp_ch:
                    # Click on a nick → open /query
                    # Reset dashboard state when navigating away
                    prev_win = self.get_current_window()
                    if prev_win.name == "*dashboard*":
                        self._dashboard_mode = "suspects"
                        self._dashboard_profile_locked = False
                    if disp_ch not in self._sorted_users:
                        self._sorted_users[disp_ch] = self._sort_users_by_mode(disp_ch)
                    users = self._sorted_users[disp_ch]
                    nick_idx = my - 1
                    if nick_idx < len(users):
                        target_nick = users[nick_idx]
                        # Open /query via ensure_window + switch
                        win = self.ensure_window(target_nick, is_channel=False)
                        for i, w in enumerate(self.windows):
                            if w is win:
                                self.current_window_index = i
                                self.current_channel = None
                                self._chat_dirty = self._userlist_dirty = self._input_dirty = True
                                self.dirty = True
                                return True
                return False

            if my < 1:
                return False
            # Left-click in chat area: open URL if the clicked line is a URL line
            win = self.get_current_window()
            self._wrap_window(win)
            total     = len(win.wrapped_cache)
            offset    = win.scroll_offset
            end_idx   = total - offset
            start_idx = max(0, end_idx - self._content_height)
            line_idx  = start_idx + (my - 1)  # row 0 is the title bar
            if line_idx >= total:
                return False
            url = win.url_map.get(line_idx)
            if url:
                try:
                    webbrowser.open(url)
                except Exception:
                    pass
                self.window_by_name["*status*"].add_line(f"Opening: {url}")
                self._chat_dirty = True
                self.dirty = True
            else:
                # No URL — check if click is on a nick in the line → open /query
                line_text = win.wrapped_cache[line_idx]
                nick_match = re.match(
                    r'^(?:\[?\d{2}:\d{2}\]?\s*)?(?:\[↑\]\s*)?<(\S+)>', line_text)
                if not nick_match:
                    nick_match = re.match(
                        r'^(?:\[?\d{2}:\d{2}\]?\s*)?(?:\[↑\]\s*)?\*\s*(\S+)', line_text)
                if nick_match:
                    target = nick_match.group(1)
                    our_nick = self._active_client().nick
                    if target.lower() != our_nick.lower():
                        # Reset dashboard state when navigating away
                        prev_win = self.get_current_window()
                        if prev_win.name == "*dashboard*":
                            self._dashboard_mode = "suspects"
                            self._dashboard_profile_locked = False
                        qwin = self.ensure_window(target, is_channel=False)
                        for i, w in enumerate(self.windows):
                            if w is qwin:
                                self.current_window_index = i
                                self.current_channel = None
                                self._chat_dirty = self._userlist_dirty = self._input_dirty = True
                                self.dirty = True
                                return True

        elif 32 <= ch <= 1114111:
            self._active_client().biometrics.record_keypress(is_backspace=False)
            try:
                ch_str = chr(ch)
            except (ValueError, OverflowError):
                ch_str = ""
            if ch_str:
                self.input_buffer = (self.input_buffer[:self.input_cursor]
                                     + ch_str + self.input_buffer[self.input_cursor:])
                self.input_cursor += 1
                self.history_index  = -1
                self.completion_state = None
                self._input_dirty = True
                self.dirty = True

        elif ch == curses.KEY_RESIZE:
            self.dirty = True

        elif ch == 12:   # Ctrl+L — clear current window
            win = self.get_current_window()
            if win.name not in ("*status*", "*dashboard*"):
                win.lines.clear()
                win.wrapped_cache.clear()
                win.url_map.clear()
                win._line_msgids.clear()
                win._unread_from = -1
                win._wrap_dirty = True
                self._chat_dirty = True
                self.dirty = True

        elif ch == 18:   # Ctrl+R — toggle userlist
            self._show_userlist = not self._show_userlist
            self._resize_windows()
            self._chat_dirty = self._userlist_dirty = self._input_dirty = True
            self.dirty = True

        elif ch == 7:    # Ctrl+G — go to window by number
            if self.input_buffer:
                try:
                    win_num = int(self.input_buffer) - 1
                    if 0 <= win_num < len(self.windows):
                        # Reset dashboard state when navigating away
                        prev_win = self.get_current_window()
                        if prev_win.name == "*dashboard*":
                            self._dashboard_mode = "suspects"
                            self._dashboard_profile_locked = False
                        self.current_window_index = win_num
                        win = self.windows[win_num]
                        # Reset dashboard state when navigating TO it
                        if win.name == "*dashboard*":
                            self._dashboard_mode = "suspects"
                            self._dashboard_profile_locked = False
                            self._dashboard_dirty = True
                            self._dashboard_last_update = 0.0
                        self.current_channel = win.name if win.name.startswith("#") else None
                        self._unread_windows.discard(win.name)
                        self._chat_dirty = self._userlist_dirty = self._input_dirty = True
                        self.dirty = True
                except ValueError:
                    pass
            self.input_buffer = ""
            self.input_cursor = 0
            self._input_dirty = True

        elif ch == 20:   # Ctrl+T — toggle link preview
            self.link_preview_enabled = not self.link_preview_enabled
            state = "ON" if self.link_preview_enabled else "OFF"
            self.window_by_name["*status*"].add_line(f"Link preview: {state}", timestamp=False)
            self._chat_dirty = True
            self.dirty = True

        elif ch == 26:   # Ctrl+Z — undo (clear input buffer)
            if self.input_buffer:
                self.input_buffer = ""
                self.input_cursor = 0
                self._input_dirty = True
                self.dirty = True

        elif ch == 27:   # Escape — clear input, reset dashboard, or close window
            if self.input_buffer:
                self.input_buffer = ""
                self.input_cursor = 0
                self._input_dirty = True
                self.dirty = True
            else:
                win = self.get_current_window()
                if win.name == "*dashboard*":
                    # Reset dashboard to suspects mode
                    self._dashboard_mode = "suspects"
                    self._dashboard_profile_locked = False
                    self._dashboard_dirty = True
                    self._dashboard_last_update = 0.0
                    self._chat_dirty = True
                    self.dirty = True
                elif win.name not in ("*status*", "*dashboard*"):
                    self._slash_close("", "", "")

        return False

    # ── IRCv3 outgoing +typing helpers ───────────────────────────────────────

    def _typing_chat_target(self) -> str:
        """Return the current chat target, or '' for non-chat windows."""
        cur = self.get_current_window()
        return "" if cur.name in ("*status*", "*dashboard*") else cur.name

    def _send_typing(self, state: str) -> None:
        """Send a +typing TAGMSG; update outgoing state bookkeeping."""
        if state == "done":
            target = self._typing_out_target
        else:
            target = self._typing_chat_target()
        if not target:
            return
        c = self._active_client()
        if "message-tags" not in c._active_caps:
            return
        c.cmd_tagmsg(target, {"+typing": state})
        if state == "done":
            self._typing_out_target = ""
            self._typing_out_last   = 0.0
            self._typing_out_state  = ""
        elif state == "active":
            self._typing_out_target = target
            self._typing_out_last   = time.monotonic()
            self._typing_out_state  = "active"
        else:  # paused
            self._typing_out_target = target
            self._typing_out_state  = "paused"

    async def run(self) -> None:
        # Start periodic background tasks for productivity features
        asyncio.create_task(self._periodic_reminder_checker())
        asyncio.create_task(self._periodic_rss_poller())
        try:
            await self._run_loop()
        except (SystemExit, asyncio.CancelledError, KeyboardInterrupt):
            pass

    async def _run_loop(self) -> None:
        while True:
            # ── 1. Keyboard — checked first so local input beats network traffic ──
            # Drain all pending keys in one pass.  Enter is async so we break after
            # it and let the redraw fire before consuming the next key.
            had_key = False
            while True:
                ch = self.stdscr.getch()
                if ch == -1:
                    break
                had_key = True
                try:
                    is_enter = self._handle_key(ch)
                except Exception:
                    is_enter = False
                if is_enter:
                    # Send +typing=done *before* clearing the buffer.
                    if self._typing_out_state in ("active", "paused"):
                        self._send_typing("done")
                    line = self.input_buffer
                    if line.strip():
                        self.input_history.appendleft(line)
                        save_input_history_line(line)
                    self.history_index  = -1
                    self._history_draft = ""
                    await self.handle_input_line(line)
                    self.input_buffer  = ""
                    self.input_cursor  = 0
                    self.completion_state = None
                    self._input_dirty  = True
                    break  # redraw before consuming the next key

            # ── 1b. Outgoing +typing notifications ────────────────────────────────
            if had_key:
                _new_tgt = self._typing_chat_target()
                if _new_tgt != self._typing_out_target and self._typing_out_state in ("active", "paused"):
                    self._send_typing("done")   # switched windows while typing
                if self.input_buffer.strip() and _new_tgt:
                    self._typing_last_key = time.monotonic()
                    if time.monotonic() - self._typing_out_last >= 3.0:
                        self._send_typing("active")
                elif not self.input_buffer.strip() and self._typing_out_state in ("active", "paused"):
                    self._send_typing("done")   # buffer cleared (Ctrl-U / backspace to empty)

            # ── 2. Immediate input refresh — bypasses the 30fps chat throttle ────
            # Typing, cursor movement and backspace feel instantaneous because the
            # input pane is repainted right here, not in the next throttled frame.
            if had_key and self._input_dirty:
                self._draw_input()
                self._input_dirty = False
                self.input_win.noutrefresh()
                curses.doupdate()

            # ── 3. Network events (capped to prevent flood from starving keyboard) ─
            n = 0
            try:
                while n < 64:
                    event = self.ui_queue.get_nowait()
                    # Buffer to disk when detached (bouncer mode)
                    if self._bouncer_detached and self._bouncer_enabled:
                        if self._should_buffer_event(event):
                            self._bouncer_buffer.append(*event)
                    try:
                        await self.handle_event(event)
                    except Exception as _ev_exc:
                        self.window_by_name["*status*"].add_line(
                            f"[err] event handler crashed: {_ev_exc}")
                        self._chat_dirty = True
                        self.dirty = True
                    n += 1
            except asyncio.QueueEmpty:
                pass

            # ── 3b. When detached, buffer incoming events to disk ────────────────
            if self._bouncer_detached and self._bouncer_enabled and n > 0:
                pass  # events were already consumed by handle_event above

            # ── 3c. Outgoing +typing=paused after 5 s of inactivity ──────────────
            if (self._typing_out_state == "active"
                    and self._typing_out_target
                    and self.input_buffer.strip()
                    and time.monotonic() - self._typing_last_key >= 5.0):
                self._send_typing("paused")

            # ── 3d. When detached, skip rendering entirely ───────────────────────
            if self._bouncer_detached and self._bouncer_enabled:
                await asyncio.sleep(0.016)
                continue

            # ── 4. Dashboard auto-refresh ─────────────────────────────────────────
            now = time.monotonic()
            on_dashboard = (self.get_current_window().name == "*dashboard*")
            # When the user navigates back to the dashboard from another window,
            # drop the profile view so the suspects list auto-refreshes normally.
            # _dashboard_profile_locked is set by commands that switch to profile in
            # the same tick — skip the reset once so the 30-second hold can start.
            if on_dashboard and not self._prev_on_dashboard and self._dashboard_mode == "profile":
                if self._dashboard_profile_locked:
                    self._dashboard_profile_locked = False  # consume lock; hold the profile
                else:
                    self._dashboard_mode = "suspects"       # genuine navigate-back — reset
                    self._dashboard_dirty = True
            # Profile views (/summarize, /ai, /topai) hold for 30 s then expire.
            if self._dashboard_mode == "profile" and now - self._dashboard_last_update >= 30.0:
                self._dashboard_mode = "suspects"
                self._dashboard_dirty = True
            self._prev_on_dashboard = on_dashboard
            # Auto-refresh is suppressed while showing a profile (/ai output) so
            # the suspects rebuild doesn't overwrite it mid-read.
            if self._dashboard_mode == "suspects":
                if self._dashboard_dirty:
                    # Always refresh immediately when dirty
                    await self.update_dashboard()
                    self._dashboard_dirty = False
                    self._dashboard_last_update = now
                    if on_dashboard:
                        self._chat_dirty = True
                        self.dirty = True
                elif on_dashboard and now - self._dashboard_last_update >= self._dashboard_ota_interval:
                    # Periodic auto-refresh while viewing dashboard
                    await self.update_dashboard()
                    self._dashboard_dirty = False
                    self._dashboard_last_update = now
                    self._chat_dirty = True
                    self.dirty = True

            # ── 5. Full redraw (chat + userlist; throttled to ~30fps) ─────────────
            if self.dirty and self.redraw():
                self.dirty = False

            # ── 6. Adaptive sleep: yield once when busy, wait 16ms when idle ──────
            # asyncio.sleep(0) hands control back to the event loop for one cycle
            # (lets IRC reads and translation tasks progress) then returns
            # immediately — keeping the loop hot during active typing or floods.
            await asyncio.sleep(0.001 if (had_key or n > 0) else 0.016)

# =========================
# Main
# =========================
async def main_curses(stdscr, ai_detector: EnsembleAIDetector):
    curses.start_color()
    curses.use_default_colors()
    try:
        curses.curs_set(1)  # visible cursor for input editing
    except curses.error:
        pass

    for i, color in enumerate([curses.COLOR_CYAN, curses.COLOR_MAGENTA, curses.COLOR_YELLOW,
                               curses.COLOR_GREEN, curses.COLOR_WHITE, curses.COLOR_BLUE, curses.COLOR_RED], 1):
        curses.init_pair(i, color, -1)
    # pair 8: ACTION lines — green + italic where supported
    curses.init_pair(8, curses.COLOR_GREEN, -1)

    ui_queue: asyncio.Queue = asyncio.Queue()
    scoring_engine = ScoringEngine(ai_detector)
    _tor_cfg = load_irc_config().get("tor", {})
    _use_tor = _tor_cfg.get("enabled", False)
    _tor_strict = _tor_cfg.get("strict", False)
    _ctcp_mode = load_irc_config().get("ctcp_mode", "normal")
    _resume_cfg = load_irc_config().get("resume", {})
    client = IRCClient(DEFAULT_SERVER, DEFAULT_PORT, DEFAULT_NICK, ui_queue, scoring_engine,
                       use_tor=_use_tor)
    client.tor_strict = _tor_strict
    client._ctcp_mode = _ctcp_mode
    client._resume_token = _resume_cfg.get("token", "")
    client._resume_ts = _resume_cfg.get("ts", "")
    tui = TUI(stdscr, ui_queue, client)

    # Initial dashboard
    await tui.update_dashboard()

    tasks = [
        asyncio.create_task(client.run_connection()),
        asyncio.create_task(tui.run()),
    ]

    try:
        await asyncio.gather(*tasks, return_exceptions=True)
    except (SystemExit, asyncio.CancelledError, KeyboardInterrupt):
        pass
    finally:
        # Cancel any tasks still running (e.g. if we exit via SystemExit or
        # the gather is cancelled by asyncio.run on SIGINT).
        for task in tasks:
            if not task.done():
                task.cancel()
        # Drain cancellations — ignore whatever they return.
        await asyncio.gather(*tasks, return_exceptions=True)

        # Cleanly QUIT all connected servers (primary + any added via /server).
        for ctx in tui.servers.values():
            c = ctx.client
            c.running = False
            if c.writer:
                try:
                    c.send_raw("QUIT :Client exiting")
                    try:
                        await asyncio.wait_for(
                            asyncio.shield(c.writer.drain()), timeout=0.4)
                    except Exception:
                        pass
                    c.writer.close()
                    try:
                        await asyncio.wait_for(c.writer.wait_closed(), timeout=0.4)
                    except Exception:
                        pass
                except Exception:
                    pass

def _in_virtualenv() -> bool:
    """Return True if the interpreter is running inside a virtual environment."""
    return hasattr(sys, "real_prefix") or (
        hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
    )


def _ensure_deps() -> bool:
    """Check for every required and optional package.
    Any that are absent are installed via pip automatically.
    Returns True if at least one package was installed (the process must
    restart so that the freshly installed modules can be imported).
    Skipped entirely when --no-install is set."""

    if _NO_INSTALL:
        return False

    # (import_name, pip_package_name, description_for_display)
    wanted: List[Tuple[str, str, str]] = [
        ("anthropic",           "anthropic",              "Claude API client  (/askai, /summarize)"),
        ("openai",              "openai",                 "OpenAI API client  (/askai, /summarize with GPT models)"),
        ("google.genai", "google-genai",    "Google AI SDK  (/askai, /summarize with Gemini)"),
    ]
    if not _NO_AI:
        wanted += [
            ("transformers", "transformers",   "AI text detection  (HuggingFace)"),
            ("torch",        "torch",          "AI text detection  (PyTorch)"),
        ]
    def _spec_missing(imp: str) -> bool:
        try:
            return importlib.util.find_spec(imp) is None
        except ModuleNotFoundError:
            return True
    missing = [
        (imp, pkg, desc) for imp, pkg, desc in wanted
        if _spec_missing(imp)
    ]
    if not missing:
        return False

    # ── Detect available package installer ──────────────────────────────────
    def _check_installer() -> Optional[List[str]]:
        """Return the install command prefix, or None if none found."""
        # pip via python -m pip
        try:
            r = subprocess.run([sys.executable, "-m", "pip", "--version"],
                               capture_output=True, timeout=5)
            if r.returncode == 0:
                return [sys.executable, "-m", "pip", "install"]
        except Exception:
            pass
        # uv pip install
        for _uv in ("uv", "uv.exe"):
            try:
                r = subprocess.run([_uv, "--version"], capture_output=True, timeout=5)
                if r.returncode == 0:
                    return [_uv, "pip", "install"]
            except Exception:
                pass
        return None

    installer = _check_installer()
    w = 44
    print("─" * w)
    if installer:
        print(f"  Missing packages — installing via {' '.join(installer[:3])}:")
    else:
        print("  Missing packages — no installer found (pip/uv):")
    for _, pkg, desc in missing:
        print(f"    • {pkg:<20}  {desc}")
    print("─" * w)
    print()

    if installer is None:
        print("  No pip or uv available. Install packages manually:")
        for _, pkg, desc in missing:
            print(f"    pip install {pkg}")
        print("  Then restart the script.")
        return False

    installed_any = False
    for imp, pkg, desc in missing:
        print(f"  ▸ {' '.join(installer)} {pkg}")
        try:
            subprocess.check_call(installer + [pkg])
            print(f"  ✓  {pkg} installed\n")
            installed_any = True
        except subprocess.CalledProcessError:
            print(f"  ✗  {pkg} failed — some features may be unavailable\n")

    return installed_any


def main():
    if _REQUIRE_VENV and not _in_virtualenv():
        sys.exit(
            "error: --require-virtualenv is set but no virtual environment is active.\n"
            "  Create and activate one:\n"
            "    python -m venv venv\n"
            "    .\\venv\\Scripts\\activate   (Windows)\n"
            "    source venv/bin/activate    (Linux/macOS)"
        )

    global DEFAULT_SERVER, DEFAULT_PORT, DEFAULT_NICK, DEFAULT_CHANNEL
    global NICKSERV_PASSWORD, SASL_MECHANISM, SASL_CERT, SASL_KEY
    global ANTHROPIC_API_KEY, OPENAI_API_KEY, DEEPSEEK_API_KEY, GITHUB_TOKEN, GEMINI_API_KEY
    global OLLAMA_URL, LLAMACPP_URL

    # Ensure the pre-curses terminal output can render Unicode box-drawing
    # characters and symbols on Windows (default console codec is cp1252).
    for _stream in (sys.stdout, sys.stderr):
        if hasattr(_stream, "reconfigure"):
            try:
                _stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass

    # Install any missing packages before doing anything else.
    # If something was installed the process restarts so all module-level
    # imports pick up the newly available packages.
    if _ensure_deps():
        print("  All packages ready — restarting...\n")
        sys.exit(subprocess.call([sys.executable] + sys.argv))

    # ── Startup prompts (plain terminal, before curses takes over) ──────────────

    # ANSI helpers — gracefully degrade on terminals without colour support
    _TTY = sys.stdin.isatty()
    if sys.platform == "win32":
        try:
            import ctypes as _ctypes
            _k32 = _ctypes.windll.kernel32
            _k32.SetConsoleMode(_k32.GetStdHandle(-11), 7)
        except Exception:
            pass
    _HAS_COLOR = _TTY and hasattr(sys.stdout, "isatty") and sys.stdout.isatty()

    def _c(code: str, text: str = "") -> str:
        if not _HAS_COLOR:
            return text
        return f"\033[{code}m{text}"

    _RST   = _c("0")
    _B     = _c("1")
    _DIM   = _c("2")
    _UL    = _c("4")
    _BLK   = _c("30")
    _RD    = _c("31")
    _GN    = _c("32")
    _YL    = _c("33")
    _BL    = _c("34")
    _MG    = _c("35")
    _CY    = _c("36")
    _GR    = _c("37")
    _B_GN  = _c("1;32")
    _B_CY  = _c("1;36")
    _B_MG  = _c("1;35")
    _B_YL  = _c("1;33")
    _B_GR  = _c("1;37")
    _B_BL  = _c("1;34")
    _BG_BL = _c("44")
    _BG_MG = _c("45")
    _BG_CN = _c("46;30")

    def _status(on: bool) -> str:
        return f"{_B_GN}\u2713{_RST}" if on else f"{_DIM}\u2022{_RST}"

    def _mask(val: str, visible: int = 4) -> str:
        if not val:
            return ""
        if len(val) <= visible:
            return "*" * len(val)
        return val[:visible] + "\u2022" * min(len(val) - visible, 12)

    _W = 54
    _VL = "\u2502"
    _HL = "\u2500"
    _TL = "\u250c"
    _TR = "\u2510"
    _BL = "\u2514"
    _BR = "\u2518"
    _DASH = "\u2500"

    def _section(title: str) -> None:
        if not _TTY:
            print(f"\n  {title}")
            return
        print()
        half = (_W - len(title) - 4) // 2
        line = _HL * half
        print(f"  {_DIM}{line}{_RST} {_B_YL}{title}{_RST} {_DIM}{line}{_RST}")

    # Load all settings from irc_config.json; env vars are the fallback already
    # applied at module level.  Config file takes precedence over env vars.
    _saved = load_irc_config()

    if _saved.get("server"):        DEFAULT_SERVER     = _saved["server"]
    if _saved.get("port"):          DEFAULT_PORT       = int(_saved["port"])
    if _saved.get("nick"):          DEFAULT_NICK       = _saved["nick"]
    if _saved.get("channel"):       DEFAULT_CHANNEL    = _saved["channel"]
    if _saved.get("sasl_mechanism"):SASL_MECHANISM     = _saved["sasl_mechanism"].upper()
    if _saved.get("sasl_cert"):     SASL_CERT          = _saved["sasl_cert"]
    if _saved.get("sasl_key"):      SASL_KEY           = _saved["sasl_key"]
    if _saved.get("nickserv_password"): NICKSERV_PASSWORD = _saved["nickserv_password"]
    if _saved.get("anthropic_api_key"): ANTHROPIC_API_KEY = _saved["anthropic_api_key"]
    if _saved.get("openai_api_key"):    OPENAI_API_KEY    = _saved["openai_api_key"]
    if _saved.get("deepseek_api_key"):  DEEPSEEK_API_KEY  = _saved["deepseek_api_key"]
    if _saved.get("github_token"):      GITHUB_TOKEN      = _saved["github_token"]
    if _saved.get("gemini_api_key"):    GEMINI_API_KEY    = _saved["gemini_api_key"]
    if _saved.get("ollama_url"):        OLLAMA_URL        = _saved["ollama_url"]
    if _saved.get("llamacpp_url"):      LLAMACPP_URL      = _saved["llamacpp_url"]
    if _saved.get("autojoin"):
        _AUTOJOIN_CHANNELS.update(_saved["autojoin"])

    # ── Safe input helper (returns "" on EOF / non-TTY so defaults are used) ──
    if not _TTY:
        _input = lambda _: ""
    else:
        def _input(prompt: str) -> str:
            try:
                return input(prompt)
            except EOFError:
                return ""

    # ── Draw the startup interface ──────────────────────────────────────────────

    if _TTY:
        _logo = [
            f"{_B_CY}  ___  ___  ___  ___  {_RST}",
            f"{_B_CY} / _ \\/ __|/ _ \\/ __| {_RST}",
            f"{_B_CY}| (_) \\__ \\ (_) \\__ \\ {_RST}",
            f"{_B_CY} \\___/|___/\\___/|___/ {_RST}",
        ]
        print()
        for _ln in _logo:
            print(f"  {_ln}")
        print()
        for _ln in [
            f"  {_B_MG}eyearesee{_RST}{_DIM} \u2014 IRC client with AI detection{_RST}",
            f"  {_DIM}Press Enter to accept defaults  \u2502  Ctrl-C to cancel{_RST}",
        ]:
            print(_ln)
        print()
    else:
        print(f"  eyearesee \u2014 IRC client\n")

    # ── IRC Connection ─────────────────────────────────────────────────────────

    _section("CONNECTION")

    # Server
    _srv_hint = f"{_DIM}{DEFAULT_SERVER}:{DEFAULT_PORT}{_RST}" if _TTY else f"{DEFAULT_SERVER}:{DEFAULT_PORT}"
    raw = _input(f"  {_B_GR}Server{_RST}  {_srv_hint} : ").strip()
    if raw:
        if ":" in raw:
            host, _, port_str = raw.rpartition(":")
            if port_str.isdigit():
                DEFAULT_SERVER, DEFAULT_PORT = host, int(port_str)
            else:
                DEFAULT_SERVER = raw
        else:
            DEFAULT_SERVER = raw

    # Nick
    _nk_hint = f"{_DIM}{DEFAULT_NICK}{_RST}" if _TTY else DEFAULT_NICK
    raw = _input(f"  {_B_GR}Nick{_RST}    {_nk_hint} : ").strip()
    if raw:
        raw = re.sub(r'[^a-zA-Z0-9\[\]\\`_\-^{|}]', '', raw)[:30]
        if raw:
            DEFAULT_NICK = raw

    # Channel
    _ch_hint = f"{_DIM}{DEFAULT_CHANNEL}{_RST}" if _TTY else DEFAULT_CHANNEL
    raw = _input(f"  {_B_GR}Channel{_RST} {_ch_hint} : ").strip()
    if raw:
        DEFAULT_CHANNEL = raw if raw.startswith("#") else "#" + raw
        DEFAULT_CHANNEL = re.sub(r'[\x00-\x07\x09-\x1f\x7f ,]', '', DEFAULT_CHANNEL)[:50] \
                          or DEFAULT_CHANNEL

    # ── Auto-join channels ──────────────────────────────────────────────────────

    _section("AUTO-JOIN CHANNELS")

    if _TTY:
        _aj_list = sorted(_AUTOJOIN_CHANNELS)
        _aj_toggled = True
        while _aj_toggled:
            _aj_list = sorted(_AUTOJOIN_CHANNELS)
            if _aj_list:
                for _i, _ch in enumerate(_aj_list, 1):
                    _mark = _B_GN + "\u2713" + _RST
                    print("  " + _mark + " " + _DIM + str(_i).rjust(2) + _RST + " " + _ch)
            else:
                print("  " + _DIM + "  No channels configured" + _RST)
            print("  " + _DIM + "Toggle: number  \u2022  Add: #channel  \u2022  Remove: -#  \u2022  Done: Enter" + _RST)
            raw = _input("  " + _B_GR + "Auto-join" + _RST + " : ").strip()
            if not raw:
                _aj_toggled = False
            elif raw.isdigit():
                _idx = int(raw) - 1
                if 0 <= _idx < len(_aj_list):
                    _removed = _aj_list[_idx]
                    _AUTOJOIN_CHANNELS.discard(_removed)
                    print("  " + _RD + "\u2717 Removed " + _removed + _RST)
                    _save_autojoin_config()
            elif raw.startswith("-") and len(raw) > 1:
                _rm_ch = raw[1:]
                if not _rm_ch.startswith("#"):
                    _rm_ch = "#" + _rm_ch
                _AUTOJOIN_CHANNELS.discard(_rm_ch)
                print("  " + _RD + "\u2717 Removed " + _rm_ch + _RST)
                _save_autojoin_config()
            else:
                _add_ch = raw if raw.startswith("#") else "#" + raw
                _add_ch = re.sub(r'[\x00-\x07\x09-\x1f\x7f ,]', '', _add_ch)[:50]
                if _add_ch and len(_add_ch) > 1:
                    _AUTOJOIN_CHANNELS.add(_add_ch)
                    print("  " + _B_GN + "\u2713 Added " + _add_ch + _RST)
                    _save_autojoin_config()
    else:
        if _AUTOJOIN_CHANNELS:
            raw = _input("  Auto-join channels (space-separated, Enter to keep) : ").strip()
            if raw:
                _AUTOJOIN_CHANNELS.clear()
                for _ch in raw.split():
                    _ch = _ch if _ch.startswith("#") else "#" + _ch
                    _ch = re.sub(r'[\x00-\x07\x09-\x1f\x7f ,]', '', _ch)[:50]
                    if _ch and len(_ch) > 1:
                        _AUTOJOIN_CHANNELS.add(_ch)
                _save_autojoin_config()
        else:
            raw = _input("  Auto-join channels (space-separated, Enter to skip) : ").strip()
            if raw:
                for _ch in raw.split():
                    _ch = _ch if _ch.startswith("#") else "#" + _ch
                    _ch = re.sub(r'[\x00-\x07\x09-\x1f\x7f ,]', '', _ch)[:50]
                    if _ch and len(_ch) > 1:
                        _AUTOJOIN_CHANNELS.add(_ch)
                _save_autojoin_config()

    # ── SASL ────────────────────────────────────────────────────────────────────

    _section("AUTHENTICATION")

    _mech_hint = f"{_DIM}PLAIN | SCRAM-SHA-256 | EXTERNAL | ECDSA-NIST256P-CHALLENGE{_RST}" if _TTY else "PLAIN/SCRAM-SHA-256/EXTERNAL/ECDSA-NIST256P-CHALLENGE"
    _mech_disp = f"{_B_CY}{SASL_MECHANISM}{_RST}" if _TTY else SASL_MECHANISM
    raw = _input(f"  {_B_GR}SASL{_RST}     {_mech_disp} {_mech_hint} : ").strip().upper()
    if raw:
        SASL_MECHANISM = raw

    _pw_hint = f"{_B_GN}[configured]{_RST}" if NICKSERV_PASSWORD else f"{_DIM}blank to skip{_RST}"
    try:
        raw = getpass.getpass(f"  {_B_GR}Password{_RST} {_pw_hint} : ")
        if raw:
            NICKSERV_PASSWORD = raw
    except EOFError:
        pass

    if SASL_MECHANISM in ("EXTERNAL", "ECDSA-NIST256P-CHALLENGE"):
        if SASL_MECHANISM == "EXTERNAL":
            _cert_hint = f"{_DIM}{SASL_CERT or 'path to PEM cert'}{_RST}" if _TTY else (SASL_CERT or "path to PEM cert")
            raw = _input(f"  {_B_GR}Cert{_RST}    {_cert_hint} : ").strip()
            if raw:
                SASL_CERT = raw
        _key_hint = f"{_DIM}{SASL_KEY or 'path to PEM key'}{_RST}" if _TTY else (SASL_KEY or "path to PEM key")
        raw = _input(f"  {_B_GR}Key{_RST}     {_key_hint} : ").strip()
        if raw:
            SASL_KEY = raw

    # ── AI API keys ──────────────────────────────────────────────────────────────

    _section("AI PROVIDERS")
    if _TTY:
        print(f"  {_DIM}Enter to keep  \u2022  '-' to clear  \u2022  values masked on summary{_RST}")

    def _prompt_key(label: str, current: str) -> str:
        _icon = _status(bool(current)) if _TTY else ""
        hint = f"{_B_GN}[configured]{_RST}" if current else f"{_DIM}blank to skip{_RST}"
        val = _input(f"  {_icon} {_B_GR}{label:<18}{_RST} {hint} : ").strip()
        if val == "-":
            return ""
        return val if val else current

    ANTHROPIC_API_KEY = _prompt_key("Anthropic API key", ANTHROPIC_API_KEY)
    OPENAI_API_KEY    = _prompt_key("OpenAI API key",    OPENAI_API_KEY)
    DEEPSEEK_API_KEY  = _prompt_key("DeepSeek API key",  DEEPSEEK_API_KEY)
    GITHUB_TOKEN      = _prompt_key("GitHub token",      GITHUB_TOKEN)
    GEMINI_API_KEY    = _prompt_key("Gemini API key",    GEMINI_API_KEY)

    # ── Local inference ─────────────────────────────────────────────────────────

    _section("LOCAL INFERENCE")
    if _TTY:
        print(f"  {_DIM}Press Enter to keep current URLs{_RST}")

    raw = _input(f"  {_B_GR}Ollama{_RST}     {_DIM}{OLLAMA_URL}{_RST} : ").strip()
    if raw:
        OLLAMA_URL = raw
    raw = _input(f"  {_B_GR}llama.cpp{_RST}  {_DIM}{LLAMACPP_URL}{_RST} : ").strip()
    if raw:
        LLAMACPP_URL = raw

    # ── Persist everything to irc_config.json ───────────────────────────────────
    _cfg: dict = {
        "server":            DEFAULT_SERVER,
        "port":              DEFAULT_PORT,
        "nick":              DEFAULT_NICK,
        "channel":           DEFAULT_CHANNEL,
        "sasl_mechanism":    SASL_MECHANISM,
        "nickserv_password": NICKSERV_PASSWORD,
        "ollama_url":        OLLAMA_URL,
        "llamacpp_url":      LLAMACPP_URL,
        "autojoin":          sorted(_AUTOJOIN_CHANNELS),
    }
    if SASL_CERT:     _cfg["sasl_cert"]          = SASL_CERT
    if SASL_KEY:      _cfg["sasl_key"]            = SASL_KEY
    if ANTHROPIC_API_KEY: _cfg["anthropic_api_key"] = ANTHROPIC_API_KEY
    if OPENAI_API_KEY:    _cfg["openai_api_key"]    = OPENAI_API_KEY
    if DEEPSEEK_API_KEY:  _cfg["deepseek_api_key"]  = DEEPSEEK_API_KEY
    if GITHUB_TOKEN:      _cfg["github_token"]       = GITHUB_TOKEN
    if GEMINI_API_KEY:    _cfg["gemini_api_key"]     = GEMINI_API_KEY
    save_irc_config(_cfg)

    # ── Connection summary ──────────────────────────────────────────────────────

    if _TTY:
        print()
        _sw = _W
        _summary_top = _TL + _HL * _sw + _TR
        _summary_bot = _BL + _HL * _sw + _BR

        def _sec(t):
            _inner = " " + t
            return _VL + _B_CY + _inner.ljust(_sw - 1) + _RST + _VL

        def _row(k, v):
            return _VL + " " + _B_GR + k.ljust(16) + _RST + " " + v + _RST

        def _pw_row(k, v):
            if v:
                return _VL + " " + _B_GR + k.ljust(16) + _RST + " " + _DIM + v + _RST
            return _VL + " " + _B_GR + k.ljust(16) + _RST + " " + _DIM + "\u2014" + _RST

        _pw_show = _mask(NICKSERV_PASSWORD) if NICKSERV_PASSWORD else "\u2014"

        _rows = [
            _summary_top,
            _sec("CONNECTION"),
            _row("Server",  DEFAULT_SERVER + ":" + str(DEFAULT_PORT) + " (TLS)"),
            _row("Nick",    DEFAULT_NICK),
            _row("Channel", DEFAULT_CHANNEL or "\u2014"),
        ]
        if _AUTOJOIN_CHANNELS:
            _aj_sorted = sorted(_AUTOJOIN_CHANNELS)
            _rows.append(_row("Auto-join", ", ".join(_aj_sorted[:5]) + ("..." if len(_aj_sorted) > 5 else "")))
        _rows += [
            _sec("AUTH"),
            _row("SASL",    SASL_MECHANISM),
            _pw_row("Password", _pw_show),
        ]
        if SASL_MECHANISM in ("EXTERNAL", "ECDSA-NIST256P-CHALLENGE"):
            if SASL_CERT:
                _rows.append(_pw_row("Cert", _mask(SASL_CERT, 8)))
            if SASL_KEY:
                _rows.append(_pw_row("Key", _mask(SASL_KEY, 8)))
        _rows.append(_sec("AI PROVIDERS"))

        _ai_providers = []
        if ANTHROPIC_API_KEY: _ai_providers.append("Anthropic " + _status(True))
        if OPENAI_API_KEY:    _ai_providers.append("OpenAI " + _status(True))
        if DEEPSEEK_API_KEY:  _ai_providers.append("DeepSeek " + _status(True))
        if GITHUB_TOKEN:      _ai_providers.append("GitHub " + _status(True))
        if GEMINI_API_KEY:    _ai_providers.append("Gemini " + _status(True))
        if not _ai_providers:
            _ai_providers.append(_DIM + "none configured" + _RST)
        _provs = "  ".join(_ai_providers)
        _rows.append(_VL + " " + _provs)
        _rows.append(_sec("LOCAL INFERENCE"))
        _rows.append(_row("Ollama",    OLLAMA_URL))
        _rows.append(_row("llama.cpp", LLAMACPP_URL))
        _rows.append(_summary_bot)
        for _ln in _rows:
            print("  " + _ln)
        print()
    else:
        print("\n  -> " + str(DEFAULT_SERVER) + ":" + str(DEFAULT_PORT) + " (TLS)  nick=" + DEFAULT_NICK
              + (("  channel=" + DEFAULT_CHANNEL) if DEFAULT_CHANNEL else ""))
        print()

    # Load AI models before curses starts so progress prints go to the normal
    # terminal and don't corrupt the TUI display.
    if _NO_AI:
        print("  AI detection: DISABLED (--no-ai)")
    ai_detector = EnsembleAIDetector(disabled=_NO_AI)
    if not _NO_AI:
        _load_all_nick_ai_history()

    # Start logging immediately — before curses initialises — so the session
    # record is written even if the TUI fails to start (bad terminal size, etc.).
    log_session_start(DEFAULT_SERVER, DEFAULT_NICK)
    log_state = f"ON  → {AI_LOG_PATH}" if _ai_logging_enabled else "OFF (set IRC_AI_LOG=1 to enable)"
    print(f"  AI logging : {log_state}")
    print()

    try:
        curses.wrapper(lambda stdscr: asyncio.run(main_curses(stdscr, ai_detector)))
    except (KeyboardInterrupt, SystemExit):
        pass

    if not sys.stdin.isatty():
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()
