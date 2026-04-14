#!/usr/bin/env python3
import asyncio
import atexit
import base64
import getpass
import importlib.util
import socket
import subprocess
import sys
import unicodedata
import urllib.parse
import urllib.request
import heapq
import io
import json
import re
import ssl
import time
import platform
import os
import uuid
import warnings
from collections import deque, OrderedDict
from math import log2
from typing import Optional, Dict, List, Tuple

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
# Curses (Windows-aware)
# =========================
try:
    import curses
except ModuleNotFoundError:
    # _curses is missing — typical on Windows builds that ship without it.
    # windows_curses may be installed in a site-packages directory not yet on
    # sys.path (user-site, a parallel Python install, etc.).  Widen the search
    # before giving up.
    import pathlib, site as _site
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
        print("windows-curses not found — installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "windows-curses"])
        import windows_curses  # type: ignore
    import curses

# =========================
# Config
# =========================
DEFAULT_SERVER = "irc.libera.chat"
DEFAULT_PORT = 6697
DEFAULT_NICK = "cfuser"
DEFAULT_CHANNEL = "##anime"
NICKSERV_PASSWORD = os.environ.get("IRC_NICKSERV_PASSWORD", "")

MAX_MESSAGES = 100
USER_HISTORY_WINDOW = 200
AI_LOG_PATH = "ai_scores.log"
AI_SUSPECT_THRESHOLD = 70

INPUT_HISTORY_PATH = "irc_input_history.txt"
INPUT_HISTORY_MAX  = 500
CHAT_LOG_DIR       = "chat_logs"
CHAT_LOG_LOAD      = 100

# Claude API
ANTHROPIC_API_KEY  = os.environ.get("ANTHROPIC_API_KEY", "")
CLAUDE_MODELS: Dict[str, str] = {
    "opus":    "claude-opus-4-6",
    "sonnet":  "claude-sonnet-4-6",
    "haiku":   "claude-haiku-4-5-20251001",
}
CLAUDE_DEFAULT_MODEL = "sonnet"   # key into CLAUDE_MODELS

# 5 built-in UI colour themes
# Each row: (name, pair1_fg, pair1_bg, pair2_fg, pair2_bg, pair3_fg, pair3_bg, pair8_fg, pair8_bg)
#   pair1 = chat title bar    pair2 = userlist header
#   pair3 = suspect nick      pair8 = /me action line
# Colours: 0=black 1=red 2=green 3=yellow 4=blue 5=magenta 6=cyan 7=white  -1=terminal default
THEMES: List[Tuple] = [
    ("Classic",  6, -1,  5, -1,  3, -1,  2, -1),  # cyan title / magenta users / yellow suspect / green action
    ("Hacker",   2,  0,  2,  0,  2, -1,  2, -1),  # matrix-green on black
    ("Ocean",    7,  4,  6,  4,  6, -1,  6, -1),  # white+cyan headers on blue
    ("Sunset",   0,  3,  1, -1,  1, -1,  3, -1),  # black-on-yellow title / red suspects / yellow action
    ("Neon",     0,  5,  5, -1,  5, -1,  6, -1),  # black-on-magenta title / magenta suspects / cyan action
]

warnings.filterwarnings("ignore", category=UserWarning, module="transformers")

# =========================
# Chat & Input Persistence
# =========================
_UNSAFE_FILENAME_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_ACTION_LINE_RE     = re.compile(r'^\[\d{2}:\d{2}\] \* \S')  # "[HH:MM] * nick …"

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
# IRC Formatting
# =========================
# Control codes used by IRC for inline text formatting.
_IRC_FMT_RE = re.compile(
    r'\x03(?:\d{1,2}(?:,\d{1,2})?)?'   # \x03[fg][,bg]  colour
    r'|[\x02\x0F\x16\x1D\x1F]'          # bold / reset / reverse / italic / underline
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

def _char_width(ch: str) -> int:
    """Terminal display width of a single character: 2 for wide/fullwidth, 1 otherwise."""
    eaw = unicodedata.east_asian_width(ch)
    return 2 if eaw in ("W", "F") else 1

def _str_visual_width(s: str) -> int:
    """Total terminal column width of *s*, counting CJK/wide chars as 2 columns."""
    return sum(_char_width(c) for c in s)

def _truncate_to_width(s: str, max_cols: int) -> str:
    """Return the longest prefix of *s* that fits within *max_cols* terminal columns."""
    cols = 0
    for i, ch in enumerate(s):
        cw = _char_width(ch)
        if cols + cw > max_cols:
            return s[:i]
        cols += cw
    return s

def _skip_visual_cols(s: str, skip: int) -> str:
    """Return the substring of *s* that starts at visual column *skip*."""
    if skip <= 0:
        return s
    col = 0
    for i, ch in enumerate(s):
        if col >= skip:
            return s[i:]
        col += _char_width(ch)
    return ""

def _irc_visual_pos(line: str, max_visual: int) -> int:
    """Return the raw-string index at which the visual column count reaches *max_visual*.
    IRC control codes are zero-width; CJK/fullwidth chars count as 2 columns."""
    vis = 0
    i = 0
    n = len(line)
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
            cw = _char_width(ch)
            if vis + cw > max_visual:
                break       # this char would overflow — stop before it
            vis += cw
            i += 1
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


# ── Translation cache + concurrency control ───────────────────────────────────
# Cache: plain_text → Optional[str].  A cached None means "already English" or
# "previously failed" — we don't retry until the process restarts.
_TRANSLATION_CACHE: OrderedDict = OrderedDict()
_TRANSLATION_CACHE_MAX = 256
_CACHE_MISS = object()                        # sentinel: key absent from cache
_TRANSLATION_SEM: Optional[asyncio.Semaphore] = None   # created lazily in async context


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
                None, lambda: urllib.request.urlopen(url, timeout=6).read()
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

def irc_parse_formatting(text: str) -> List[Tuple[str, int]]:
    """Split *text* into (segment, curses_attr) pairs honouring IRC codes.

    Supports: \\x02 bold, \\x1D italic, \\x1F underline, \\x0F reset,
    \\x16 reverse, \\x03 colour (colour is stripped; only bold/italic/underline
    are mapped to curses attributes).

    Results are cached (up to 512 entries) since the same wrapped line is
    rendered on every frame until the window is scrolled or text changes.
    """
    cached = _FMT_PARSE_CACHE.get(text)
    if cached is not None:
        return cached

    segments: List[Tuple[str, int]] = []
    bold = italic = underline = reverse = False
    buf: List[str] = []
    i = 0

    def _flush():
        if buf:
            segments.append(("".join(buf), _irc_attr(bold, italic, underline, reverse)))
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
        elif ch == "\x0F":        # reset all
            _flush(); bold = italic = underline = reverse = False; i += 1
        elif ch == "\x03":        # colour code — advance past digits, map nothing
            _flush()
            i += 1
            for _ in range(2):    # up to 2 fg digits
                if i < len(text) and text[i].isdigit(): i += 1
                else: break
            if i < len(text) and text[i] == ",":
                i += 1
                for _ in range(2):  # up to 2 bg digits
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


def _irc_attr(bold: bool, italic: bool, underline: bool, reverse: bool) -> int:
    attr = curses.A_NORMAL
    if bold:      attr |= curses.A_BOLD
    if underline: attr |= curses.A_UNDERLINE
    if reverse:   attr |= curses.A_REVERSE
    if italic:
        try:    attr |= curses.A_ITALIC
        except AttributeError: attr |= curses.A_DIM   # fallback on older curses
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
    global _ai_log_handle
    try:
        if _ai_log_handle is None or _ai_log_handle.closed:
            _ai_log_handle = _open_append(AI_LOG_PATH)
        _ai_log_handle.write(payload)
    except Exception:
        pass


def log_session_start(server: str, nick: str) -> None:
    entry = {
        "type": "session_start",
        "ts": time.time(),
        "dt": time.strftime("%Y-%m-%d %H:%M:%S"),
        "sess": _LOG_SESSION_ID,
        "server": server,
        "nick": nick,
    }
    _ai_log_write(json.dumps(entry, ensure_ascii=False) + "\n")


def log_ai_event(nick: str, target: str, msg: str,
                 u_score: int, m_score: int, a_score: int, rolling_ai: int) -> None:
    global _log_seq
    _log_seq += 1
    entry = {
        "ts":   time.time(),
        "dt":   time.strftime("%Y-%m-%d %H:%M:%S"),
        "sess": _LOG_SESSION_ID,
        "seq":  _log_seq,
        "nick": nick,
        "target": target,
        "u":    u_score,
        "m":    m_score,
        "a":    a_score,
        "roll": rolling_ai,
        "msg":  msg,
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
        "sessions":     sessions,
        "channels":     sorted(channels),
        "top_messages": top_messages,
        "gaps":         gaps,
    }


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
try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification, GPT2LMHeadModel, GPT2TokenizerFast
    import torch
    AI_AVAILABLE = True
except Exception:
    AI_AVAILABLE = False

IRC_CASUAL_WORDS = frozenset({
    "lol", "lmao", "lmfao", "rofl", "haha", "hehe", "xd", "xdd",
    "brb", "afk", "omg", "wtf", "gtg", "gg", "rip", "smh", "imo",
    "imho", "tbh", "ngl", "idk", "irl", "fyi", "ty", "thx", "np",
    "nvm", "btw", "iirc", "tfw", "mfw", "welp", "kek", "ez",
})

# Phrases LLMs disproportionately use in chat contexts (2025/2026)
AI_TELL_PHRASES = frozenset({
    "it's worth noting", "it is worth noting",
    "it's important to", "it is important to",
    "it should be noted", "it's crucial to",
    "as previously mentioned", "as noted above",
    "to elaborate", "to clarify", "in other words",
    "furthermore", "moreover", "additionally", "consequently",
    "that being said", "having said that",
    "on the other hand", "in conclusion",
    "to summarize", "in summary", "to recap",
    "certainly!", "absolutely!", "great question", "excellent question",
    "i hope this helps", "feel free to", "let me know if",
    "happy to help", "glad to help", "please let me know",
    "it's fascinating", "it's interesting to note",
    "delve into", "tapestry", "nuanced perspective",
})

# Vocabulary LLMs reach for that humans rarely use in casual IRC chat
FORMAL_WORDS = frozenset({
    "utilize", "leverage", "implement", "facilitate",
    "demonstrate", "enumerate", "articulate",
    "commence", "terminate", "endeavor",
    "subsequent", "pertaining", "aforementioned",
    "constitute", "comprises", "optimal",
    "paramount", "imperative", "holistic",
    "synergy", "paradigm", "streamline",
})

class EnsembleAIDetector:
    _CACHE_MAX = 512  # LRU-style prediction cache (bots repeat themselves)

    def __init__(self):
        self.enabled = True
        self._gpt2_model = None   # GPT-2: Binoculars performer
        self._obs_model  = None   # distilgpt2: Binoculars observer
        self._gpt2_tok   = None   # shared tokenizer (same BPE vocab)
        self._cls_model  = None
        self._cls_tok    = None
        self._device = "cpu"
        self._pred_cache: OrderedDict = OrderedDict()  # text → float, FIFO eviction

        if not AI_AVAILABLE:
            raise SystemExit(
                "AI detector requires: pip install transformers torch\n"
                "All three models (gpt2, distilgpt2, RoBERTa) must load successfully."
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

        print("AI detector: loading distilgpt2 (Binoculars observer)...", end=" ", flush=True)
        self._obs_model = GPT2LMHeadModel.from_pretrained("distilgpt2").to(self._device)
        self._obs_model.eval()
        print("OK")

        print("AI detector: loading RoBERTa classifier...", end=" ", flush=True)
        _m = "Hello-SimpleAI/chatgpt-detector-roberta"
        self._cls_tok = AutoTokenizer.from_pretrained(_m)
        self._cls_model = AutoModelForSequenceClassification.from_pretrained(_m).to(self._device)
        self._cls_model.eval()
        print("OK")

        print(f"AI detector ENABLED: Binoculars + RoBERTa + heuristics (device={self._device})")

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

        # 2025/2026 LLM-specific tells
        has_emdash     = "\u2014" in text or " -- " in text   # LLMs reach for em-dashes
        tell_phrase    = any(p in text_lower for p in AI_TELL_PHRASES)
        formal_vocab   = bool(words_lower_stripped & FORMAL_WORDS)
        no_contraction = not any(c in text_lower for c in
                                 ("n't", "'re", "'ve", "'ll", "'m", "'d"))

        return min(1.0,
            0.10 * ends_cleanly
            + 0.05 * starts_cap
            + 0.08 * (not casual_hit)
            + 0.05 * no_charspam
            + 0.04 * no_emoticon
            + 0.06 * long_enough
            + 0.18 * tell_phrase       # strongest single heuristic
            + 0.16 * has_emdash
            + 0.14 * formal_vocab
            + 0.14 * no_contraction
        )

    def _heuristic_score(self, text: str) -> float:
        form   = self.formality_score(text)
        rep    = self.repetition(text)
        ent    = self.entropy(text)
        length = min(1.0, len(text) / 300.0)
        ent_penalty = max(0.0, (ent - 4.0) / 2.0)
        return max(0.0, min(1.0, 0.50 * form + 0.20 * rep + 0.12 * length - 0.18 * ent_penalty))

    # ---- ML signals ----

    def _binoculars_score(self, text: str) -> float:
        """Binoculars (Hans et al., 2024): CE_observer / CE_performer.
        Low ratio → both models find text fluent → AI-generated.
        Returns 0..1, higher = more AI-like."""
        try:
            enc = self._gpt2_tok(text, return_tensors="pt", truncation=True, max_length=128)
            enc = {k: v.to(self._device) for k, v in enc.items()}
            if enc["input_ids"].shape[1] < 3:
                return 0.0
            with torch.inference_mode():
                ce_obs  = self._obs_model( **enc, labels=enc["input_ids"]).loss.item()
                ce_perf = self._gpt2_model(**enc, labels=enc["input_ids"]).loss.item()
            if ce_perf < 1e-6:
                return 0.0
            ratio = ce_obs / ce_perf
            # Human IRC: ratio ~1.3-2.5  (smaller observer struggles more)
            # AI text:   ratio ~0.7-1.2  (both models agree it's fluent)
            return max(0.0, min(1.0, (1.8 - ratio) / 1.2))
        except Exception:
            return 0.0

    def _classifier_score(self, text: str) -> float:
        """0..1 probability that text is AI-generated."""
        try:
            enc = self._cls_tok(text, return_tensors="pt", truncation=True, max_length=128)
            enc = {k: v.to(self._device) for k, v in enc.items()}
            with torch.inference_mode():
                logits = self._cls_model(**enc).logits
            return torch.softmax(logits, dim=-1)[0][1].item()
        except Exception:
            return 0.0

    # ---- main entry point ----

    def predict_prob(self, text: str) -> float:
        if not self.enabled: return 0.0
        text = text.strip()
        if not text: return 0.0

        cached = self._pred_cache.get(text)
        if cached is not None:
            return cached

        heu  = self._heuristic_score(text)
        bino = self._binoculars_score(text)
        cls  = self._classifier_score(text)
        result = max(0.0, min(1.0, 0.40 * bino + 0.40 * cls + 0.20 * heu))

        if len(self._pred_cache) >= self._CACHE_MAX:
            self._pred_cache.popitem(last=False)   # O(1) FIFO eviction
        self._pred_cache[text] = result
        return result

class ScoringEngine:
    def __init__(self, ai_detector: EnsembleAIDetector):
        self.ai_detector = ai_detector

    def score_user(self, user_state) -> int:
        return min(99, user_state.total_msgs // 2)

    def score_message(self, msg_state, user_state) -> int:
        return 50

# =========================
# UserState + ChatWindow
# =========================
class UserState:
    __slots__ = ("nick", "join_time", "last_msg_time", "msg_times", "msg_lengths",
                 "total_msgs", "ai_scores", "_rolling_sum", "_len_sum", "_time_sum")
    def __init__(self, nick: str):
        self.nick = nick
        self.join_time = time.time()
        self.last_msg_time: Optional[float] = None
        self.msg_times: deque = deque(maxlen=USER_HISTORY_WINDOW)
        self.msg_lengths: deque = deque(maxlen=USER_HISTORY_WINDOW)
        self.total_msgs = 0
        self.ai_scores: deque = deque(maxlen=USER_HISTORY_WINDOW)
        self._rolling_sum: float = 0.0
        self._len_sum:     int   = 0
        self._time_sum:    float = 0.0

    def record_message(self, msg: str, ai_score: Optional[int] = None) -> None:
        now = time.time()
        if self.last_msg_time is not None:
            gap = now - self.last_msg_time
            if len(self.msg_times) == USER_HISTORY_WINDOW:
                self._time_sum -= self.msg_times[0]
            self.msg_times.append(gap)
            self._time_sum += gap
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

class ChatWindow:
    def __init__(self, name: str, is_channel: bool = True):
        self.name = name
        self.is_channel = is_channel
        self.lines: deque = deque(maxlen=MAX_MESSAGES)
        self.wrapped_cache: List[str] = []
        self._wrap_dirty = True
        self._last_wrap_width = 0
        self.scroll_offset: int = 0  # 0 = pinned to bottom
        self._persist = True         # write new lines to disk

    def add_line(self, text: str, timestamp: bool = True) -> None:
        if timestamp:
            text = f"{time.strftime('[%H:%M]')} {text}"
        self.lines.append(text)
        self._wrap_dirty = True
        if self._persist:
            append_chat_line(self.name, text)

# Reuse one SSL context across all connections (parsing the CA bundle is expensive).
_SSL_CTX = ssl.create_default_context()
_SSL_CTX.minimum_version = ssl.TLSVersion.TLSv1_2

# =========================
# IRCClient - FULL + CTCP
# =========================
class IRCClient:
    def __init__(self, server: str, port: int, nick: str, ui_queue: asyncio.Queue, scoring_engine: ScoringEngine):
        self.server = server
        self.port = port
        self.nick = nick
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
        self._irc_handlers: dict = {}
        self._build_irc_handlers()

    async def connect(self) -> None:
        await self.ui_queue.put(("status", f"Connecting to {self.server}:{self.port}..."))
        try:
            # 30-second connect timeout prevents hangs on unreachable hosts.
            # limit=2^20 (1 MiB) sets the StreamReader internal buffer; the default
            # 64 KB can stall on fast servers that send large NAMES / MOTD bursts.
            self.reader, self.writer = await asyncio.wait_for(
                asyncio.open_connection(
                    self.server, self.port, ssl=_SSL_CTX, limit=2 ** 20),
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
        await self.ui_queue.put(("status", "SSL connection established"))
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
        self.send_raw(f"NICK {self.nick}")
        self.send_raw(f"USER {self.nick} 0 * :{self.nick}")
        await self.ui_queue.put(("status", "Sent NICK and USER commands"))

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
        now = time.time()
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
                self.send_raw(f"PING :keepalive-{int(time.time())}")
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
            self._cap_ls_caps.clear()
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
                    await self.process_line(text)
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
                    # Unescape IRCv3 tag escape sequences
                    v = (v.replace("\\:", ";").replace("\\s", " ")
                          .replace("\\\\", "\\").replace("\\r", "\r")
                          .replace("\\n", "\n"))
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

    async def _irc_cap(self, nick, params, prefix):
        subcmd = params[1].upper() if len(params) > 1 else ""
        if subcmd == "LS":
            # CAP LS 302 sends caps across multiple lines; "*" in params[2] means more coming.
            # Cap names may carry values ("sasl=PLAIN,EXTERNAL") — strip after "=".
            more_coming = len(params) > 2 and params[2] == "*"
            for raw_cap in (params[-1] if params else "").lower().split():
                self._cap_ls_caps.add(raw_cap.split("=")[0])
            if not more_coming:
                _OPTIONAL_CAPS = (
                    "away-notify", "multi-prefix", "account-notify",
                    "extended-join", "chghost", "server-time",
                    "echo-message", "userhost-in-names",
                )
                want = [c for c in _OPTIONAL_CAPS if c in self._cap_ls_caps]
                if "sasl" in self._cap_ls_caps and NICKSERV_PASSWORD:
                    want.append("sasl")
                self.send_raw(f"CAP REQ :{' '.join(want)}" if want else "CAP END")
                self._cap_ls_caps.clear()
        elif subcmd == "ACK":
            acked = set((params[-1] if params else "").lower().split())
            if "sasl" in acked:
                self.send_raw("AUTHENTICATE PLAIN")
            else:
                self.send_raw("CAP END")
        elif subcmd == "NAK":
            self.send_raw("CAP END")

    async def _irc_authenticate(self, nick, params, prefix):
        if params and params[0] == "+":
            payload = base64.b64encode(
                f"{self.nick}\0{self.nick}\0{NICKSERV_PASSWORD}".encode()
            ).decode()
            self.send_raw(f"AUTHENTICATE {payload}")

    async def _irc_sasl_ok(self, nick, params, prefix):  # 903
        await self.ui_queue.put(("status", "SASL authentication successful — ident set"))
        self._identified = True
        self.send_raw("CAP END")

    async def _irc_sasl_fail(self, nick, params, prefix):  # 904
        await self.ui_queue.put(("status", "SASL authentication failed — falling back to NickServ"))
        self.send_raw("CAP END")

    async def _irc_logged_in(self, nick, params, prefix):  # 900
        account = params[2] if len(params) > 2 else "?"
        await self.ui_queue.put(("status", f"Logged in as {account}"))

    async def _irc_welcome(self, nick, params, prefix):  # 001
        await self.ui_queue.put(("clear_users",))
        await self.ui_queue.put(("status", "Successfully logged in to IRC"))
        if not self._identified and NICKSERV_PASSWORD:
            asyncio.create_task(self._delayed_nickserv_identify())
        for ch in sorted(self.joined_channels):
            self.send_raw(f"JOIN {ch}")
            await self.ui_queue.put(("status", f"Joining {ch}..."))
        if not self.current_channel and DEFAULT_CHANNEL:
            self.current_channel = DEFAULT_CHANNEL

    async def _irc_join(self, nick, params, prefix):
        if not params:
            return
        channel = params[0]
        await self.ui_queue.put(("join", nick, channel))
        if nick == self.nick:
            await self.ui_queue.put(("self_join", channel))

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
        await self.ui_queue.put(("mode", nick, params))

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
            text = f"[whois] {w}  is an IRC operator"
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
        # echo-message CAP causes the server to reflect our own sends back to us.
        # We already display messages locally when sent, so skip the server echo.
        if nick == self.nick:
            return
        target = params[0]
        msg    = params[1]

        # ACTION must be checked before the generic CTCP block — both use \x01
        # wrappers and falling into the CTCP branch silently drops /me lines.
        is_action = msg.startswith("\x01ACTION ") and msg.endswith("\x01")
        if is_action:
            msg = msg[len("\x01ACTION "):-1]
        elif msg.startswith("\x01") and msg.endswith("\x01"):
            # Generic CTCP request
            ctcp = msg[1:-1].split(" ", 1)
            ctcp_cmd  = ctcp[0].upper()
            ctcp_args = ctcp[1] if len(ctcp) > 1 else ""
            if not self._ctcp_allowed(nick):
                return
            if ctcp_cmd == "PING":
                safe_args = ctcp_args.replace("\x01", "")[:100]
                self.send_raw(f"NOTICE {nick} :\x01PING {safe_args}\x01")
            elif ctcp_cmd == "VERSION":
                self.send_raw(f"NOTICE {nick} :\x01VERSION eyearesee IRC client v2.0\x01")
                await self.ui_queue.put(("status", f"-!- CTCP VERSION from {nick}"))
            elif ctcp_cmd == "TIME":
                self.send_raw(
                    f"NOTICE {nick} :\x01TIME "
                    f"{time.strftime('%a, %d %b %Y %H:%M:%S %Z', time.localtime())}\x01")
                await self.ui_queue.put(("status", f"-!- CTCP TIME from {nick}"))
            elif ctcp_cmd == "CLIENTINFO":
                self.send_raw(
                    f"NOTICE {nick} :\x01CLIENTINFO "
                    f"PING VERSION TIME CLIENTINFO USERINFO SOURCE FINGER\x01")
            elif ctcp_cmd == "USERINFO":
                self.send_raw(f"NOTICE {nick} :\x01USERINFO {self.nick} is using eyearesee\x01")
            elif ctcp_cmd == "SOURCE":
                self.send_raw(f"NOTICE {nick} :\x01SOURCE https://github.com (custom eyearesee)\x01")
            elif ctcp_cmd == "FINGER":
                self.send_raw(f"NOTICE {nick} :\x01FINGER No finger info\x01")
            return  # CTCP — never treat as normal message

        if nick not in self.users:
            self.users[nick] = UserState(nick)
        u_state = self.users[nick]
        u_score = self.scoring.score_user(u_state)
        m_score = self.scoring.score_message(None, u_state)
        # Display immediately with a placeholder AI score (0); a background task
        # scores the message and sends an "ai_score" update once ML inference finishes.
        await self.ui_queue.put(("msg", nick, target, msg, u_score, m_score, 0, 0, is_action))
        asyncio.create_task(self._score_msg_bg(nick, target, msg, u_state, u_score, m_score))

    async def _irc_nick_change(self, nick, params, prefix):
        new_nick = params[0] if params else ""
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

    async def _irc_invite(self, nick, params, prefix):
        channel = params[1] if len(params) > 1 else (params[0] if params else "")
        await self.ui_queue.put(("status", f"*** {nick} invites you to join {channel}"))

    async def _irc_quit(self, nick, params, prefix):
        self.users.pop(nick, None)
        reason = params[-1] if params else ""
        await self.ui_queue.put(("quit", nick, reason))

    async def _irc_names(self, nick, params, prefix):  # 353 RPL_NAMREPLY
        if len(params) < 4:
            return
        channel = params[2]
        # When userhost-in-names CAP is active entries look like "@nick!user@host";
        # strip mode-prefix chars and drop the !user@host suffix so the user list
        # only contains bare nicks (matching how JOIN/PART/QUIT events work).
        cleaned = []
        for entry in params[3].split():
            entry = entry.lstrip("@+%&~!")   # strip mode prefix
            if "!" in entry:                  # userhost-in-names
                entry = entry.split("!", 1)[0]
            if entry:
                cleaned.append(entry)
        await self.ui_queue.put(("names", channel, " ".join(cleaned)))

    async def _irc_who_reply(self, nick, params, prefix):  # 352/314
        await self.ui_queue.put(("status", f"{params[0] if params else ''} {' '.join(params[1:])}"))

    async def _irc_away_reply(self, nick, params, prefix):  # 301
        await self.ui_queue.put(("status", f"Away: {' '.join(params[1:])}"))

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
        if account == "*":
            await self.ui_queue.put(("status", f"* {nick} logged out of services"))
        else:
            await self.ui_queue.put(("status", f"* {nick} is identified as {account}"))

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
        # Announce the network name the first time we see it
        if "NETWORK" in self._isupport and "_network_announced" not in self._isupport:
            self._isupport["_network_announced"] = True
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
        h["JOIN"]         = self._irc_join
        h["PART"]         = self._irc_part
        h["KICK"]         = self._irc_kick
        h["TOPIC"]        = self._irc_topic_cmd
        h["MODE"]         = self._irc_mode
        h["PRIVMSG"]      = self._irc_privmsg
        h["NICK"]         = self._irc_nick_change
        h["NOTICE"]       = self._irc_notice
        h["INVITE"]       = self._irc_invite
        h["QUIT"]         = self._irc_quit
        h["353"]          = self._irc_names
        h["301"]          = self._irc_away_reply
        h["332"]          = self._irc_topic_reply
        h["331"]          = self._irc_no_topic
        h["433"]          = self._irc_nick_in_use
        h["432"]          = self._irc_bad_nick
        h["401"]          = self._irc_no_such_nick
        h["005"]          = self._irc_isupport
        h["AWAY"]         = self._irc_away_notify
        h["CHGHOST"]      = self._irc_chghost
        h["ACCOUNT"]      = self._irc_account
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
        if is_action:
            self.send_raw(f"PRIVMSG {target} :\x01ACTION {text}\x01")
        else:
            self.send_raw(f"PRIVMSG {target} :{text}")

        if self.nick not in self.users:
            self.users[self.nick] = UserState(self.nick)
        u_state = self.users[self.nick]
        u_state.record_message(text)
        u_score = self.scoring.score_user(u_state)
        m_score = 50
        a_score = 0  # own messages are human
        rolling_ai = int(u_state.rolling_ai_likelihood())
        return ("msg", self.nick, target, text, u_score, m_score, a_score, rolling_ai, is_action)

    def cmd_service(self, service: str, command: str) -> None:
        self.send_raw(f"PRIVMSG {service} :{command}")

    def cmd_ctcp(self, target: str, ctcp_cmd: str, args: str = "") -> None:
        payload = f"{ctcp_cmd} {args}".strip()
        self.send_raw(f"PRIVMSG {target} :\x01{payload}\x01")

    def cmd_notice(self, target: str, text: str) -> None:
        self.send_raw(f"NOTICE {target} :{text}")

    def cmd_away(self, msg: str = "") -> None:
        self.send_raw(f"AWAY :{msg}" if msg else "AWAY")

    def cmd_invite(self, nick: str, channel: str) -> None:
        self.send_raw(f"INVITE {nick} {channel}")

    def cmd_who(self, target: str) -> None:
        self.send_raw(f"WHO {target}")

    def cmd_whowas(self, nick: str) -> None:
        self.send_raw(f"WHOWAS {nick}")

    def cmd_names(self, channel: str = "") -> None:
        self.send_raw(f"NAMES {channel}" if channel else "NAMES")

    async def _score_msg_bg(self, nick: str, target: str, msg: str,
                            u_state: "UserState", u_score: int, m_score: int) -> None:
        """Run AI inference off the read loop, then push an update event."""
        try:
            loop = asyncio.get_running_loop()
            a_prob = await loop.run_in_executor(
                None, self.scoring.ai_detector.predict_prob, msg)
            a_score = int(a_prob * 100)
            u_state.record_message(msg, a_score)
            rolling_ai = int(u_state.rolling_ai_likelihood())
            log_ai_event(nick, target, msg, u_score, m_score, a_score, rolling_ai)
            await self.ui_queue.put(("ai_score", nick, rolling_ai))
        except Exception:
            u_state.record_message(msg, 0)

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

        try:
            self.chat_win  = curses.newwin(self.chat_height, max(1, self.width - self.userlist_width), 0, 0)
            self.user_win  = curses.newwin(self.chat_height, self.userlist_width, 0, max(0, self.width - self.userlist_width))
            self.input_win = curses.newwin(4, max(1, self.width), max(0, self.height - 4), 0)
        except curses.error as e:
            raise SystemExit(f"Terminal too small to initialise windows: {e}")

        self.windows: List[ChatWindow] = []
        self.window_by_name: Dict[str, ChatWindow] = {}
        for name in ("*status*", "*dashboard*"):
            win = ChatWindow(name, is_channel=False)
            self.windows.append(win)
            self.window_by_name[name] = win

        # Pre-create the default channel window so its tab is always visible and
        # join errors / join success messages land there immediately.
        self.channel_users: Dict[str, set] = {}
        if DEFAULT_CHANNEL:
            _dcw = ChatWindow(DEFAULT_CHANNEL, is_channel=True)
            self.windows.append(_dcw)
            self.window_by_name[DEFAULT_CHANNEL] = _dcw
            self.channel_users[DEFAULT_CHANNEL] = set()

        self.current_window_index = 0
        self.current_channel: Optional[str] = DEFAULT_CHANNEL
        self.user_scores: Dict[str, int] = {}
        self.user_ai_scores: Dict[str, int] = {}
        self.ai_suspect_threshold = AI_SUSPECT_THRESHOLD

        self.input_buffer = ""
        self.input_cursor  = 0
        self.input_history: deque = deque(load_input_history(), maxlen=500)
        self.history_index  = -1
        self._history_draft = ""
        self.completion_state = None
        self.dirty = True
        self.last_redraw = 0.0
        self.ignored_nicks: set = set()

        # Performance caches — maintained incrementally to avoid per-frame rebuilds
        self._suspect_nicks: set = set()          # nicks at/above ai_suspect_threshold
        self._suspect_re: Optional[re.Pattern] = None   # compiled regex, rebuilt on change
        self._suspect_re_nicks: frozenset = frozenset() # snapshot used to build _suspect_re
        self._sorted_users: Dict[str, List[str]] = {}  # channel → sorted nick list
        self._dashboard_dirty = False             # needs rebuild?
        self._dashboard_last_update = 0.0         # last rebuild timestamp
        self._dashboard_ota_interval = 5.0        # auto-refresh interval while dashboard is visible

        # Claude API state
        self.ai_chat_model: str = CLAUDE_DEFAULT_MODEL   # key into CLAUDE_MODELS
        self._askai_pending: bool = False                # prevent concurrent calls

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

        # Theme — starts at 1 (Classic); apply_theme reinitialises color pairs
        self.current_theme: int = 1
        self.apply_theme(1, announce=False)

        # Per-pane dirty flags — skip drawing panes that haven't changed
        self._chat_dirty    = True
        self._userlist_dirty = True
        self._input_dirty   = True

        # Cached window dimensions (updated only on resize)
        self._tw     = max(1, self.chat_win.getmaxyx()[1] - 1)   # chat text cols
        self._uw     = max(1, self.userlist_width - 2)            # userlist interior cols
        self._input_w = max(1, self.input_win.getmaxyx()[1] - 4) # input text cols

        # Unread tracking: window names that have received messages while inactive
        self._unread_windows: set = set()

        self._event_handlers: dict = {}
        self._slash_handlers: dict = {}
        self._build_event_handlers()
        self._build_slash_handlers()

        stdscr.nodelay(True)
        stdscr.keypad(True)

        # Auto-translate CJK (Chinese/Japanese/…) messages to English
        self.auto_translate: bool = True

    def ensure_window(self, name: str, is_channel: bool = True) -> ChatWindow:
        if name not in self.window_by_name:
            win = ChatWindow(name, is_channel=is_channel)
            self.windows.append(win)
            self.window_by_name[name] = win
            if is_channel and name not in self.channel_users:
                self.channel_users[name] = set()
        return self.window_by_name[name]

    def _chat_text_width(self) -> int:
        """Usable text columns in the chat window (leaves 1-col right margin)."""
        return max(1, self.chat_win.getmaxyx()[1] - 1)

    def _wrap_window(self, win: ChatWindow) -> None:
        max_width = self._chat_text_width()
        if not win._wrap_dirty and win._last_wrap_width == max_width:
            return
        wrapped = []
        for line in win.lines:
            if not line:
                wrapped.append("")
                continue
            # Strip IRC formatting codes once per line, not on every loop
            # iteration, to avoid O(n²) cost for long lines without spaces.
            stripped = irc_strip_formatting(line)
            while _str_visual_width(stripped) > max_width:
                raw_max   = _irc_visual_pos(line, max_width)
                split_pos = line.rfind(" ", 0, raw_max)
                if split_pos == -1:
                    # No space found; force at least 1 raw character consumed so
                    # the loop always terminates (edge case: max_width=1 + wide char).
                    split_pos = raw_max if raw_max > 0 else 1
                wrapped.append(line[:split_pos])
                line = line[split_pos:].lstrip()
                stripped = irc_strip_formatting(line)
            wrapped.append(line)
        win.wrapped_cache = wrapped
        win._wrap_dirty = False
        win._last_wrap_width = max_width

    async def update_dashboard(self):
        dash = self.window_by_name["*dashboard*"]
        dash.lines.clear()
        dash._wrap_dirty = True
        A = lambda t: dash.add_line(t, timestamp=False)

        A("=== AI Suspects — current session (≥ {}%) ===".format(self.ai_suspect_threshold))
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
                now = time.time()
                join_ago = int((now - state.join_time) // 60)
                last_ago = int((now - state.last_msg_time) // 60) if state.last_msg_time else 0
                avg_len  = state.avg_msg_length()
                mpm      = state.messages_per_minute()
                bars = "▁▂▃▄▅▆▇█"
                spark = "".join(bars[min(7, s * 8 // 101)]
                                for s in list(state.ai_scores)[-16:])
                A(f"  {nick:<14} [{ai_pct:2d}%]  msgs:{state.total_msgs:3d}  "
                  f"avg:{avg_len:4.0f}  mpm:{mpm:4.1f}  "
                  f"join:{join_ago:2d}m  last:{last_ago:2d}m")
                if spark:
                    A(f"    {spark}")

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
        now   = time.time()

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
        if combined_avg >= 80 and n_sessions >= 3 and is_consistent:
            verdict = "HIGH RISK — persistent, consistent AI pattern across multiple sessions"
        elif combined_avg >= 70:
            verdict = "SUSPECT — elevated AI score"
        elif combined_avg >= 50:
            verdict = "MODERATE — borderline, watch for pattern"
        else:
            verdict = "LOW — no strong AI signal"

        # ── Render ───────────────────────────────────────────────────────────
        L(f"=== AI Profile: {nick} ===")
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
            L(f"  Joined                 : {join_ago}m ago")
            if last_ago is not None:
                L(f"  Last message           : {last_ago}m ago")
            if spark:
                L(f"  Score history          : {spark}")
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

        self.current_window_index = 1
        self._chat_dirty = True
        self.dirty = True

    async def _do_askai(self, question: str, model_key: str) -> None:
        """Call the Claude API and post the Q+A to the *dashboard* window."""
        if not ANTHROPIC_AVAILABLE:
            await self.ui_queue.put(("status",
                "anthropic package not installed — run: pip install anthropic"))
            return
        if not ANTHROPIC_API_KEY:
            await self.ui_queue.put(("status",
                "ANTHROPIC_API_KEY not set — set the environment variable and restart"))
            return
        if self._askai_pending:
            await self.ui_queue.put(("status", "/askai already in progress, please wait…"))
            return

        model_id = CLAUDE_MODELS.get(model_key, CLAUDE_MODELS[CLAUDE_DEFAULT_MODEL])
        self._askai_pending = True
        await self.ui_queue.put(("status",
            f"[askai] querying {model_key} ({model_id})…"))

        msg    = None   # must be initialised before the try so the finally block
        answer = ""     # and the render block below can always reference both
        try:
            client = _anthropic_mod.AsyncAnthropic(api_key=ANTHROPIC_API_KEY)
            msg = await client.messages.create(
                model=model_id,
                max_tokens=1024,
                messages=[{"role": "user", "content": question}],
            )
            answer = msg.content[0].text if msg.content else "(empty response)"
        except Exception as exc:
            answer = f"[error] {exc}"
        finally:
            self._askai_pending = False

        dash = self.window_by_name["*dashboard*"]
        dash.lines.clear()
        dash._wrap_dirty = True
        L = lambda t: dash.add_line(t, timestamp=False)

        L(f"=== /askai [{model_key}] ===")
        L("")
        L(f"Q: {question}")
        L("")
        L("A:")
        for raw_line in answer.splitlines():
            L(f"  {raw_line}" if raw_line.strip() else "")
        L("")
        _usage  = getattr(msg, "usage", None)
        _tokens = (_usage.input_tokens + _usage.output_tokens) if _usage else "?"
        L(f"  model: {model_id}  tokens used: {_tokens}")

        self.current_window_index = 1   # switch to *dashboard*
        self._chat_dirty = True
        self._dashboard_dirty = False
        self._dashboard_last_update = time.time()
        self.dirty = True

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
        chat_w = max(1, self.width - self.userlist_width)
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
        # Refresh cached dimension values and force full repaint
        self._tw             = max(1, self.chat_win.getmaxyx()[1] - 1)
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
        max_offset = max(0, total - content_height)
        current_win.scroll_offset = min(current_win.scroll_offset, max_offset)
        offset = current_win.scroll_offset

        end_idx   = total - offset
        start_idx = max(0, end_idx - content_height)
        visible   = wrapped[start_idx:end_idx]

        suspect_nicks = self._suspect_nicks
        attr_bold   = self._attr_bold
        attr_normal = self._attr_normal
        attr_action = self._attr_action
        # Rebuild suspect regex only when the set has changed (not every frame)
        if suspect_nicks != self._suspect_re_nicks:
            self._suspect_re = (
                re.compile("|".join(re.escape(n) for n in suspect_nicks))
                if suspect_nicks else None
            )
            self._suspect_re_nicks = frozenset(suspect_nicks)
        _suspect_re = self._suspect_re

        # Bind hot callables to locals — avoids repeated global/attr lookups
        # inside the per-line render loop (called up to ~60 times per frame).
        _action_match   = _ACTION_LINE_RE.match
        _render         = self._render_irc_line
        _suspect_search = _suspect_re.search if _suspect_re else None
        _content_height = content_height

        for i, line in enumerate(visible):
            if i >= _content_height: break
            if _action_match(line):
                base = attr_action
            elif _suspect_search and _suspect_search(line):
                base = attr_bold
            else:
                base = attr_normal
            _render(i + 1, line, base, tw)  # +1: row 0 is reserved for the title bar

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
        header = f" Users ({self.current_channel or 'None'}) "
        try:
            self.user_win.addstr(0, 1, header[:uw], self._attr_userheader)
        except curses.error:
            pass

        if self.current_channel and self.current_channel in self.channel_users:
            ch = self.current_channel
            if ch not in self._sorted_users:
                self._sorted_users[ch] = sorted(self.channel_users[ch])
            users = self._sorted_users[ch]
            thresh      = self.ai_suspect_threshold
            attr_sus    = self._attr_suspect
            attr_normal = self._attr_normal
            for i, nick in enumerate(users[:self.chat_height - 2]):
                ai_pct = self.user_ai_scores.get(nick, 0)
                # Pad nick to exactly 18 *visual columns* so the score badge
                # aligns correctly even when the nick contains wide (CJK) chars.
                nick_vis = _str_visual_width(nick)
                padded   = nick + " " * max(0, 18 - nick_vis)
                line     = _truncate_to_width(f"{padded} [{ai_pct:2d}%]", uw)
                try:
                    self.user_win.addstr(i + 1, 1, line,
                        attr_sus if ai_pct >= thresh else attr_normal)
                except curses.error:
                    break

    def _draw_tabs(self) -> None:
        """Draw the window tab strip on row 1 of input_win.

        Format: [1:status] [*2:##chat] [3:##anime]
        Active tab uses A_REVERSE|A_BOLD; windows with unread messages get A_BOLD
        and a '*' prefix; inactive read windows are dimmed.  The strip scrolls so
        the active tab is always visible.
        """
        _, w = self.input_win.getmaxyx()
        usable = w - 2  # columns between left and right borders

        # Build label strings for every window
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
                short = f">{name[:10]}"   # DM: ">nick"
            is_active = (i == self.current_window_index)
            has_unread = (name in self._unread_windows and not is_active)
            labels.append(f"[{'*' if has_unread else ''}{i + 1}:{short}]")

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
            if is_active:
                attr = curses.A_REVERSE | curses.A_BOLD
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

        self._draw_tabs()

        # Show current send-target in the prompt so the user always knows where
        # text will go.  Status/dashboard windows have no chat target.
        cur_win = self.get_current_window()
        if cur_win.name not in ("*status*", "*dashboard*"):
            prompt = f"[{cur_win.name}] {self.client.nick}> "
        else:
            prompt = f"{self.client.nick}> "
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
        if time.time() - self.last_redraw < 0.033:
            return False
        self.last_redraw = time.time()

        new_h, new_w = self.stdscr.getmaxyx()
        if new_h != self.height or new_w != self.width:
            self.height, self.width = new_h, new_w
            self.chat_height = max(1, self.height - 4)
            self._resize_windows()  # sets all three pane-dirty flags + updates _tw/_uw/_input_w

        refreshed = []
        if self._chat_dirty:
            self._draw_chat()
            self._chat_dirty = False
            refreshed.append(self.chat_win)
        if self._userlist_dirty:
            self._draw_userlist()
            self._userlist_dirty = False
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

    def switch_to_next_window(self):
        self.current_window_index = (self.current_window_index + 1) % len(self.windows)
        win = self.get_current_window()
        if win.name not in ("*status*", "*dashboard*"):
            self.current_channel = win.name
        if win.name in self._unread_windows:
            win.scroll_offset = 0  # jump to bottom so the new messages are visible
        self._unread_windows.discard(win.name)
        self._chat_dirty = self._userlist_dirty = self._input_dirty = True
        self.dirty = True

    def do_nick_complete(self) -> None:
        if not self.current_channel or self.current_channel not in self.channel_users:
            return
        ch = self.current_channel
        if ch not in self._sorted_users:
            self._sorted_users[ch] = sorted(self.channel_users[ch])
        users = self._sorted_users[ch]
        if not users:
            return
        # Complete the word ending at the cursor
        buf    = self.input_buffer
        cursor = self.input_cursor
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
            idx   = (self.completion_state[2] + 1) % len(self.completion_state[1])
            match = self.completion_state[1][idx]
        else:
            idx   = 0
            match = matches[0]
        self.completion_state = (prefix, matches, idx)
        # First word → append colon+space; subsequent words → just a space
        suffix = ": " if word_start == 0 else " "
        replacement = match + suffix
        self.input_buffer = buf[:word_start] + replacement + buf[cursor:]
        self.input_cursor = word_start + len(replacement)
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
        for k in ("whois", "kick", "mode", "status"):
            h[k] = self._ev_status_line

    async def handle_event(self, event: tuple) -> None:
        if not event:
            return
        handler = self._event_handlers.get(event[0])
        if handler:
            await handler(event)

    # ── TUI event handlers ────────────────────────────────────────────────────

    async def _ev_msg(self, event):
        _, nick, target, msg, u_score, m_score, a_score, rolling_ai, is_action = event
        if nick.lower() in self.ignored_nicks:
            return
        if target.startswith("#"):
            win_name = target
            is_chan   = True
        elif nick == self.client.nick:
            win_name = target
            is_chan   = False
        else:
            win_name = nick
            is_chan   = False
        win = self.ensure_window(win_name, is_channel=is_chan)
        prefix_str = f"* {nick} " if is_action else f"<{nick}> "
        win.add_line(f"{prefix_str}{msg}")
        if self.auto_translate and _has_cjk(irc_strip_formatting(msg)):
            asyncio.create_task(self._post_translation(win, msg))
        self.user_scores[nick] = u_score
        self.user_ai_scores[nick] = rolling_ai
        if win is not self.get_current_window():
            self._unread_windows.add(win_name)
            self._input_dirty = True
            if not target.startswith("#") and nick != self.client.nick:
                preview = (msg[:40] + "...") if len(msg) > 40 else msg
                self.get_current_window().add_line(
                    f"-!- PM from {nick}: {preview}  [/win {self.windows.index(win) + 1}]")
        if rolling_ai >= self.ai_suspect_threshold:
            self._suspect_nicks.add(nick)
            self._dashboard_dirty = True
        else:
            self._suspect_nicks.discard(nick)
        if win_name in self.channel_users:
            self.channel_users[win_name].add(nick)
            self._sorted_users.pop(win_name, None)
            self._userlist_dirty = True
        self._chat_dirty = True
        self.dirty = True

    async def _ev_ai_score(self, event):
        _, nick, rolling_ai = event
        self.user_ai_scores[nick] = rolling_ai
        if rolling_ai >= self.ai_suspect_threshold:
            self._suspect_nicks.add(nick)
            self._dashboard_dirty = True
        else:
            self._suspect_nicks.discard(nick)
        self._userlist_dirty = True
        self.dirty = True

    async def _ev_notice(self, event):
        _, sender, target, text = event
        if sender.lower() in self.ignored_nicks:
            return
        win = self.ensure_window(target, is_channel=target.startswith("#"))
        win.add_line(f"-{sender}- {text}")
        if win is not self.get_current_window():
            self._unread_windows.add(target)
            self._input_dirty = True
        self._chat_dirty = True
        self.dirty = True

    async def _ev_nick_change(self, event):
        _, old_nick, new_nick = event
        for ch, users in self.channel_users.items():
            if old_nick in users:
                users.discard(old_nick)
                users.add(new_nick)
                self._sorted_users.pop(ch, None)
        if old_nick in self.user_scores:
            self.user_scores[new_nick] = self.user_scores.pop(old_nick)
        if old_nick in self.user_ai_scores:
            score = self.user_ai_scores.pop(old_nick)
            self.user_ai_scores[new_nick] = score
            self._suspect_nicks.discard(old_nick)
            if score >= self.ai_suspect_threshold:
                self._suspect_nicks.add(new_nick)
        self.window_by_name["*status*"].add_line(f"* {old_nick} is now known as {new_nick}")
        self._chat_dirty = self._userlist_dirty = True
        self.dirty = True

    async def _ev_names(self, event):
        _, channel, names_raw = event
        if channel not in self.channel_users:
            self.channel_users[channel] = set()
        for n in names_raw.split():
            clean = n.lstrip("@+%&~!")
            if clean:
                self.channel_users[channel].add(clean)
        self._sorted_users.pop(channel, None)
        self._userlist_dirty = True
        self.dirty = True

    async def _ev_clear_users(self, event):
        for users in self.channel_users.values():
            users.clear()
        self._sorted_users.clear()
        self._userlist_dirty = True
        self.dirty = True

    async def _ev_topic(self, event):
        _, channel, topic_text = event
        text = (f"* Topic for {channel}: {topic_text}"
                if topic_text else f"* No topic set for {channel}")
        target_win = self.window_by_name.get(channel, self.window_by_name["*status*"])
        target_win.add_line(text)
        self._chat_dirty = True
        self.dirty = True

    async def _ev_join(self, event):
        _, nick, channel = event
        win = self.ensure_window(channel)
        if nick == self.client.nick:
            self.channel_users[channel] = set()
            self._sorted_users.pop(channel, None)
        else:
            if channel in self.channel_users:
                self.channel_users[channel].add(nick)
                self._sorted_users.pop(channel, None)
            win.add_line(f"* {nick} has joined {channel}")
        self._chat_dirty = self._userlist_dirty = True
        self.dirty = True

    async def _ev_self_join(self, event):
        _, channel = event
        win = self.ensure_window(channel)
        win.add_line(f"* You have joined {channel}")
        self.current_channel = channel
        self.current_window_index = self.windows.index(win)
        self._unread_windows.discard(channel)
        self._chat_dirty = self._userlist_dirty = self._input_dirty = True
        self.dirty = True

    async def _ev_join_error(self, event):
        _, channel, msg = event
        if channel:
            win = self.ensure_window(channel)
            win.add_line(msg)
            self.current_channel = channel
            self.current_window_index = self.windows.index(win)
            self._unread_windows.discard(channel)
        else:
            self.window_by_name["*status*"].add_line(msg)
        self._chat_dirty = self._userlist_dirty = self._input_dirty = True
        self.dirty = True

    async def _ev_part(self, event):
        _, nick, channel = event
        if channel in self.channel_users:
            self.channel_users[channel].discard(nick)
            self._sorted_users.pop(channel, None)
        self._suspect_nicks.discard(nick)
        ch_win = self.window_by_name.get(channel)
        if ch_win:
            ch_win.add_line(f"* {nick} has left {channel}")
            if ch_win is not self.get_current_window():
                self._unread_windows.add(channel)
                self._input_dirty = True
        self._chat_dirty = self._userlist_dirty = True
        self.dirty = True

    async def _ev_quit(self, event):
        _, nick, reason = event
        quit_msg = f"* {nick} has quit" + (f" ({reason})" if reason else "")
        for ch, users in self.channel_users.items():
            if nick in users:
                users.discard(nick)
                self._sorted_users.pop(ch, None)
                ch_win = self.window_by_name.get(ch)
                if ch_win:
                    ch_win.add_line(quit_msg)
                    if ch_win is not self.get_current_window():
                        self._unread_windows.add(ch)
                        self._input_dirty = True
        self._suspect_nicks.discard(nick)
        self.user_scores.pop(nick, None)
        self.user_ai_scores.pop(nick, None)
        self._chat_dirty = self._userlist_dirty = True
        self.dirty = True

    async def _ev_status_line(self, event):
        msg = str(event[1]) if len(event) > 1 else str(event)
        self.window_by_name["*status*"].add_line(msg)
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
        h["aitoggle"]   = self._slash_aitoggle
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
        h["model"]      = self._slash_model
        h["autotranslate"] = self._slash_autotranslate
        h["commands"]   = self._slash_commands
        h["help"]       = self._slash_help

    async def handle_input_line(self, line: str) -> None:
        if not line.strip():
            return
        if line.startswith("/"):
            parts = line[1:].split(maxsplit=2)
            cmd   = parts[0].lower()
            args  = parts[1] if len(parts) > 1 else ""
            extra = parts[2] if len(parts) > 2 else ""
            handler = self._slash_handlers.get(cmd)
            if handler:
                await handler(args, extra, line)
            else:
                self.client.send_raw(line[1:])
        else:
            await self._send_plain_text(line)
        self._chat_dirty = True
        self._input_dirty = True
        self.dirty = True
        self.completion_state = None

    async def _send_plain_text(self, line: str) -> None:
        cur_win = self.get_current_window()
        if cur_win.name not in ("*status*", "*dashboard*"):
            target = cur_win.name
        else:
            target = self.current_channel or DEFAULT_CHANNEL
            if target:
                dest = self.ensure_window(target, is_channel=target.startswith("#"))
                self.current_channel = target
                self.current_window_index = self.windows.index(dest)
                self._unread_windows.discard(target)
        result = self.client.cmd_msg(target, line)
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
        result = self.client.cmd_msg(target, action_text, is_action=True)
        if result:
            await self.ui_queue.put(result)

    async def _slash_ctcp(self, args, extra, line):
        if args and extra:
            self.client.cmd_ctcp(args, extra.upper())
            await self.ui_queue.put(("status", f"CTCP {extra.upper()} sent to {args}"))
        else:
            await self.ui_queue.put(("status", "Usage: /ctcp <nick> <command> [args]"))

    async def _slash_whois(self, args, extra, line):
        if args:
            self.client.cmd_whois(args)

    async def _slash_mode(self, args, extra, line):
        if args:
            target, *modes = args.split(maxsplit=1)
            self.client.cmd_mode(target, modes[0] if modes else "")

    async def _slash_topic(self, args, extra, line):
        if args:
            if " " in args:
                channel, topic = args.split(maxsplit=1)
                self.client.cmd_topic(channel, topic)
            else:
                self.client.cmd_topic(args)

    async def _slash_kick(self, args, extra, line):
        if args:
            p = args.split(maxsplit=2)
            if len(p) >= 2:
                self.client.cmd_kick(p[0], p[1], p[2] if len(p) > 2 else "")

    async def _slash_ns(self, args, extra, line):
        if args:
            self.client.cmd_service("NickServ", args)

    async def _slash_cs(self, args, extra, line):
        if args:
            self.client.cmd_service("ChanServ", args)

    async def _slash_ai(self, args, extra, line):
        if args:
            await self.show_user_ai_profile(args)
        else:
            await self.ui_queue.put(("status", "Usage: /ai <nick>"))

    async def _slash_aitoggle(self, args, extra, line):
        self.client.scoring.ai_detector.enabled = not self.client.scoring.ai_detector.enabled
        state = "ENABLED" if self.client.scoring.ai_detector.enabled else "DISABLED"
        await self.ui_queue.put(("status", f"AI detection {state}"))

    async def _slash_join(self, args, extra, line):
        if args:
            self.client.cmd_join(args)

    async def _slash_part(self, args, extra, line):
        ch = args or self.current_channel or ""
        if ch:
            self.client.cmd_part(ch, extra or None)

    async def _slash_nick(self, args, extra, line):
        if args:
            self.client.cmd_nick(args)

    async def _slash_msg(self, args, extra, line):
        if args and extra:
            self.client.cmd_msg(args, extra)
            win = self.ensure_window(args, is_channel=False)
            win.add_line(f"<{self.client.nick}> {extra}")
            self.current_window_index = self.windows.index(win)
            self.current_channel = args
            self._unread_windows.discard(args)
            self._chat_dirty = self._userlist_dirty = self._input_dirty = True
            self.dirty = True
        else:
            await self.ui_queue.put(("status", "Usage: /msg <nick> <text>"))

    async def _slash_query(self, args, extra, line):
        if args:
            is_new = args not in self.window_by_name
            win = self.ensure_window(args, is_channel=False)
            self.current_window_index = self.windows.index(win)
            self.current_channel = args
            self._unread_windows.discard(args)
            self._chat_dirty = self._userlist_dirty = self._input_dirty = True
            if is_new:
                win.add_line(f"** Query with {args} opened **", timestamp=False)
            if extra:
                self.client.cmd_msg(args, extra)
                win.add_line(f"<{self.client.nick}> {extra}")
        else:
            await self.ui_queue.put(("status", "Usage: /query <nick> [message]"))

    async def _slash_notice(self, args, extra, line):
        if args and extra:
            self.client.cmd_notice(args, extra)
            await self.ui_queue.put(("status", f"-> NOTICE to {args}: {extra}"))
        else:
            await self.ui_queue.put(("status", "Usage: /notice <nick> <text>"))

    async def _slash_away(self, args, extra, line):
        self.client.cmd_away(args)
        await self.ui_queue.put(("status", f"You are now away: {args}" if args else "You are now away"))

    async def _slash_back(self, args, extra, line):
        self.client.cmd_away()
        await self.ui_queue.put(("status", "You are no longer away"))

    async def _slash_invite(self, args, extra, line):
        if args:
            channel = extra or self.current_channel or ""
            if channel:
                self.client.cmd_invite(args, channel)
                await self.ui_queue.put(("status", f"Inviting {args} to {channel}"))
            else:
                await self.ui_queue.put(("status", "Usage: /invite <nick> [channel]"))

    async def _slash_op(self, args, extra, line):
        if args and self.current_channel:
            self.client.cmd_mode(self.current_channel, f"+o {args}")

    async def _slash_deop(self, args, extra, line):
        if args and self.current_channel:
            self.client.cmd_mode(self.current_channel, f"-o {args}")

    async def _slash_voice(self, args, extra, line):
        if args and self.current_channel:
            self.client.cmd_mode(self.current_channel, f"+v {args}")

    async def _slash_devoice(self, args, extra, line):
        if args and self.current_channel:
            self.client.cmd_mode(self.current_channel, f"-v {args}")

    async def _slash_hop(self, args, extra, line):
        if args and self.current_channel:
            self.client.cmd_mode(self.current_channel, f"+h {args}")

    async def _slash_dehop(self, args, extra, line):
        if args and self.current_channel:
            self.client.cmd_mode(self.current_channel, f"-h {args}")

    async def _slash_ban(self, args, extra, line):
        if args and self.current_channel:
            mask = args if "!" in args or "@" in args else f"{args}!*@*"
            self.client.cmd_mode(self.current_channel, f"+b {mask}")

    async def _slash_unban(self, args, extra, line):
        if args and self.current_channel:
            self.client.cmd_mode(self.current_channel, f"-b {args}")

    async def _slash_who(self, args, extra, line):
        if args:
            self.client.cmd_who(args)

    async def _slash_whowas(self, args, extra, line):
        if args:
            self.client.cmd_whowas(args)

    async def _slash_names(self, args, extra, line):
        self.client.cmd_names(args or self.current_channel or "")

    async def _slash_ignore(self, args, extra, line):
        if args:
            self.ignored_nicks.add(args.lower())
            await self.ui_queue.put(("status", f"Now ignoring {args}"))

    async def _slash_unignore(self, args, extra, line):
        if args:
            self.ignored_nicks.discard(args.lower())
            await self.ui_queue.put(("status", f"No longer ignoring {args}"))

    async def _slash_clear(self, args, extra, line):
        win = self.get_current_window()
        win.lines.clear()
        win._wrap_dirty = True

    async def _slash_close(self, args, extra, line):
        win = self.get_current_window()
        if win.name not in ("*status*", "*dashboard*"):
            self._unread_windows.discard(win.name)
            self.windows.remove(win)
            del self.window_by_name[win.name]
            self.current_window_index = max(0, self.current_window_index - 1)
            new_win = self.get_current_window()
            if new_win.name not in ("*status*", "*dashboard*"):
                self.current_channel = new_win.name
            self._chat_dirty = self._userlist_dirty = self._input_dirty = True
            self.dirty = True

    async def _slash_win(self, args, extra, line):
        if args.isdigit():
            idx = int(args) - 1
            if 0 <= idx < len(self.windows):
                self.current_window_index = idx
                win = self.windows[idx]
                if win.name not in ("*status*", "*dashboard*"):
                    self.current_channel = win.name
                if win.name in self._unread_windows:
                    win.scroll_offset = 0
                self._unread_windows.discard(win.name)
                self._chat_dirty = self._userlist_dirty = self._input_dirty = True
                self.dirty = True

    async def _slash_quit(self, args, extra, line):
        self.client.send_raw(f"QUIT :{args}" if args else "QUIT :Client exiting")
        raise SystemExit

    async def _slash_server(self, args, extra, line):
        if not args:
            await self.ui_queue.put(("status",
                "Usage: /server <host> [port] [nick]  (port defaults to 6697 SSL)"))
            return
        srv_parts = args.split()
        new_server = srv_parts[0]
        new_port   = 6697
        new_nick   = self.client.nick
        if len(srv_parts) >= 2:
            if srv_parts[1].isdigit():
                new_port = int(srv_parts[1])
            else:
                await self.ui_queue.put(("status",
                    f"/server: invalid port '{srv_parts[1]}', defaulting to 6697"))
        if len(srv_parts) >= 3:
            new_nick = srv_parts[2]
        self.client.server          = new_server
        self.client.port            = new_port
        self.client.nick            = new_nick
        self.client.joined_channels = set()
        self.client.users.clear()
        self.client._identified     = False
        self.client._ctcp_times.clear()
        for users in self.channel_users.values():
            users.clear()
        self._sorted_users.clear()
        self.user_scores.clear()
        self.user_ai_scores.clear()
        self._suspect_nicks.clear()
        self._suspect_re        = None
        self._suspect_re_nicks  = frozenset()
        self.current_channel    = None
        self._dashboard_dirty   = True
        self.window_by_name["*status*"].add_line(
            f"*** Connecting to {new_server}:{new_port} (SSL) as {new_nick}")
        self.current_window_index = 0
        if self.client.writer and not self.client.writer.is_closing():
            try:
                self.client.send_raw(f"QUIT :Switching to {new_server}")
                await asyncio.sleep(0.3)
                self.client.writer.close()
            except Exception:
                pass
        elif self.client.writer:
            try:
                self.client.writer.close()
            except Exception:
                pass

    async def _slash_reconnect(self, args, extra, line):
        await self.ui_queue.put(("status", "Forcing reconnect..."))
        if self.client.writer:
            try:
                self.client.writer.close()
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
        rest = line[len("/askai"):].strip()
        if not rest:
            await self.ui_queue.put(("status", "Usage: /askai [opus|sonnet|haiku] <question>"))
            return
        first_word, *remainder = rest.split(maxsplit=1)
        if first_word.lower() in CLAUDE_MODELS:
            model_key = first_word.lower()
            question  = remainder[0] if remainder else ""
        else:
            model_key = self.ai_chat_model
            question  = rest
        if question:
            asyncio.create_task(self._do_askai(question, model_key))
        else:
            await self.ui_queue.put(("status", "Usage: /askai [opus|sonnet|haiku] <question>"))

    async def _slash_model(self, args, extra, line):
        if args.lower() in CLAUDE_MODELS:
            self.ai_chat_model = args.lower()
            await self.ui_queue.put(("status",
                f"Claude model set to {self.ai_chat_model} ({CLAUDE_MODELS[self.ai_chat_model]})"))
        else:
            keys = "/".join(CLAUDE_MODELS)
            await self.ui_queue.put(("status",
                f"Unknown model '{args}'. Choose: {keys}  (current: {self.ai_chat_model})"))

    async def _slash_autotranslate(self, args, extra, line):
        self.auto_translate = not self.auto_translate
        state = "ON" if self.auto_translate else "OFF"
        await self.ui_queue.put(("status", f"Auto-translate CJK → English: {state}"))

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
        _E("/notice <nick> <text>",         "Send a notice (-nick- style, not shown in chat)")
        _E("/me <text>",                    "Send an action line  (* nick waves)")
        _C("")
        _H("Channels")
        _E("/join <channel>",               "Join a channel (# is added automatically if omitted)")
        _E("/part [channel] [message]",     "Leave a channel with an optional part message")
        _E("/topic <channel> [text]",       "View or set the channel topic")
        _E("/names [channel]",              "List users currently in the channel")
        _E("/kick <chan> <nick> [reason]",  "Kick a user from the channel")
        _E("/invite <nick> [channel]",      "Invite a user to a channel")
        _E("/mode <target> [modes]",        "Get or set channel / user modes")
        _C("")
        _H("Operator")
        _E("/op <nick>",    "Grant operator status  (+o)")
        _E("/deop <nick>",  "Remove operator status (-o)")
        _E("/voice <nick>", "Grant voice  (+v)")
        _E("/devoice <nick>","Remove voice (-v)")
        _E("/hop <nick>",   "Grant half-op  (+h)")
        _E("/dehop <nick>", "Remove half-op (-h)")
        _E("/ban <nick|mask>","Ban user; bare nick expands to nick!*@*")
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
        _C("")
        _H("Services & CTCP")
        _E("/ns <command>",                 "Send command to NickServ  (e.g. /ns identify pw)")
        _E("/cs <command>",                 "Send command to ChanServ")
        _E("/ctcp <nick> <cmd> [args]",     "Send a CTCP request  (PING VERSION TIME …)")
        _C("")
        _H("AI Detection")
        _E("/ai <nick>",                    "Full AI profile: score, idle, sparkline, verdict")
        _E("/aitoggle",                     "Enable or disable AI scoring entirely")
        _C("")
        _H("Claude Integration")
        _E("/askai [opus|sonnet|haiku] <q>","Ask Claude a question; answer shown in dashboard")
        _E("/model <opus|sonnet|haiku>",    "Set the default Claude model for /askai")
        _C(f"  Current model: {self.ai_chat_model}  ({CLAUDE_MODELS.get(self.ai_chat_model, '?')})")
        _C("")
        _H("Translation")
        _E("/autotranslate",               "Toggle auto CJK → English translation (on by default)")
        _C("")
        _H("Connection")
        _E("/server <host> [port] [nick]", "Connect to a new IRC server over SSL (default 6697)")
        _E("/reconnect",                   "Drop and re-establish the current connection")
        _C("")
        _H("Windows & Navigation")
        _C("  Tab bar (above input): [1:status] [2:dash] [*3:##chat]  * = unread")
        _E("/win <n>",    "Switch to window n; clears its unread marker")
        _E("/close  (or /wc)", "Close current window; focus moves to previous")
        _E("/clear",     "Clear messages in the current window")
        _E("/theme <1-5>","Switch colour theme: Classic Hacker Ocean Sunset Neon")
        _C("  Ctrl+N  next window    Tab  nick completion    PgUp/PgDn  scroll")
        _C("  Ctrl+A/E  line start/end    Ctrl+K  kill to end    Ctrl+W  delete word")
        _C("  Ctrl+B/]/_ bold/italic/underline    Ctrl+O  reset formatting")
        _C("")
        _H("General")
        _E("/quit [message]", "Send quit message and exit")
        _E("/help",           "Brief one-line command reference")
        _E("/commands",       "This full command list")
        _C("")
        self.current_window_index = 0
        self._chat_dirty = True
        self.dirty = True

    async def _slash_help(self, args, extra, line):
        for l in [
            "── Messaging ──────────────────────────────────────────────",
            "  /msg <nick> <text>       PM nick; opens & switches to DM window",
            "  /query <nick> [message]  Open a DM window (optional first message)",
            "  /notice <nick> <text>    Send a notice   /me <text>  Action line",
            "── Channels ──────────────────────────────────────────────",
            "  /join <chan>  /part [chan] [msg]  /topic <chan> [text]",
            "  /kick <chan> <nick> [reason]  /invite <nick> [chan]",
            "  /names [chan]  /mode <target> [modes]",
            "── Operator ──────────────────────────────────────────────",
            "  /op /deop /voice /devoice /hop /dehop  /ban /unban",
            "── Users ─────────────────────────────────────────────────",
            "  /nick <new>  /whois <nick>  /whowas <nick>  /who <pat>",
            "  /ignore <nick>  /unignore <nick>  /away [msg]  /back",
            "── Services ──────────────────────────────────────────────",
            "  /ns <cmd>  /cs <cmd>  /ctcp <nick> <cmd> [args]",
            "── AI Detection ──────────────────────────────────────────",
            "  /ai <nick>  full profile    /aitoggle  enable/disable scoring",
            "── Claude ────────────────────────────────────────────────",
            "  /askai [opus|sonnet|haiku] <question>  (answer in dashboard)",
            "  /model <opus|sonnet|haiku>  set default model",
            "── Translation ───────────────────────────────────────────",
            "  /autotranslate  toggle CJK → English (default: on)",
            "── Connection ─────────────────────────────────────────────",
            "  /server <host> [port] [nick]  /reconnect",
            "── Interface ──────────────────────────────────────────────",
            "  /win <n>  /close (/wc)  /clear  /theme <1-5>",
            "  Ctrl+N next window  Tab nick-complete  PgUp/Dn scroll",
            "  Tab bar: [1:status] [2:dash] [*3:##chat]  * = unread",
            "  /quit [msg]  /commands  (full list)  /help  (this)",
        ]:
            self.window_by_name["*status*"].add_line(l)
        self.current_window_index = 0
        self._chat_dirty = self._userlist_dirty = self._input_dirty = True
        self.dirty = True

    def _handle_key(self, ch: int) -> bool:
        """Process a single keycode synchronously.  Returns True if the key was
        Enter (so the caller can await handle_input_line and break the drain loop),
        False for all other keys."""
        if ch in (curses.KEY_ENTER, 10, 13):
            return True   # caller handles asynchronously

        elif ch in (curses.KEY_BACKSPACE, 127, 8):
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

        elif ch == 9:    # Tab — nick completion
            prev_len = len(self.input_buffer)
            self.do_nick_complete()
            self.input_cursor += len(self.input_buffer) - prev_len

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

        elif 32 <= ch <= 1114111:
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

        return False

    async def run(self) -> None:
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
                is_enter = self._handle_key(ch)
                if is_enter:
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

            # ── 4. Dashboard auto-refresh ─────────────────────────────────────────
            now = time.time()
            on_dashboard = (self.get_current_window().name == "*dashboard*")
            if on_dashboard and now - self._dashboard_last_update >= self._dashboard_ota_interval:
                await self.update_dashboard()
                self._dashboard_dirty = False
                self._dashboard_last_update = now
                self._chat_dirty = True
                self.dirty = True
            elif self._dashboard_dirty and now - self._dashboard_last_update >= 1.0:
                await self.update_dashboard()
                self._dashboard_dirty = False
                self._dashboard_last_update = now
                if on_dashboard:
                    self._chat_dirty = True

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
    client = IRCClient(DEFAULT_SERVER, DEFAULT_PORT, DEFAULT_NICK, ui_queue, scoring_engine)

    log_session_start(DEFAULT_SERVER, DEFAULT_NICK)

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

        client.running = False
        if client.writer:
            try:
                client.send_raw("QUIT :Client exiting")
                # Use a short wait that itself can't raise CancelledError
                # (the event loop may already be winding down here).
                try:
                    await asyncio.wait_for(
                        asyncio.shield(client.writer.drain()), timeout=0.4)
                except Exception:
                    pass
                client.writer.close()
                try:
                    await asyncio.wait_for(client.writer.wait_closed(), timeout=0.4)
                except Exception:
                    pass
            except Exception:
                pass

def _ensure_deps() -> bool:
    """Check for every required and optional package.
    Any that are absent are installed via pip automatically.
    Returns True if at least one package was installed (the process must
    restart so that the freshly installed modules can be imported)."""

    # (import_name, pip_package_name, description_for_display)
    wanted: List[Tuple[str, str, str]] = [
        ("anthropic",    "anthropic",      "Claude API client  (/askai)"),
        ("transformers", "transformers",   "AI text detection  (HuggingFace)"),
        ("torch",        "torch",          "AI text detection  (PyTorch)"),
    ]
    missing = [
        (imp, pkg, desc) for imp, pkg, desc in wanted
        if importlib.util.find_spec(imp) is None
    ]
    if not missing:
        return False

    w = 44
    print("─" * w)
    print("  Missing packages — installing via pip:")
    for _, pkg, desc in missing:
        print(f"    • {pkg:<20}  {desc}")
    print("─" * w)
    print()

    installed_any = False
    for imp, pkg, desc in missing:
        print(f"  ▸ pip install {pkg}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
            print(f"  ✓  {pkg} installed\n")
            installed_any = True
        except subprocess.CalledProcessError:
            print(f"  ✗  {pkg} failed — some features may be unavailable\n")

    return installed_any


def main():
    global DEFAULT_SERVER, DEFAULT_PORT, DEFAULT_NICK, DEFAULT_CHANNEL, NICKSERV_PASSWORD

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
    print("╔══════════════════════════════════════╗")
    print("║       eyearesee  —  IRC client       ║")
    print("╚══════════════════════════════════════╝")
    print("  Press Enter to accept the [default].\n")

    # Server — accepts host  or  host:port
    raw = input(f"  Server   [{DEFAULT_SERVER}] : ").strip()
    if raw:
        if ":" in raw:
            host, _, port_str = raw.rpartition(":")
            if port_str.isdigit():
                DEFAULT_SERVER, DEFAULT_PORT = host, int(port_str)
            else:
                DEFAULT_SERVER = raw          # treat whole thing as hostname
        else:
            DEFAULT_SERVER = raw

    # Nick
    raw = input(f"  Nick     [{DEFAULT_NICK}] : ").strip()
    if raw:
        # IRC nicks: letters/digits/[-\[\]\\`_^{|}], max 30 chars (RFC 1459 §2.3.1)
        raw = re.sub(r'[^a-zA-Z0-9\[\]\\`_\-^{|}]', '', raw)[:30]
        if raw:
            DEFAULT_NICK = raw

    # Channel — prepend # if omitted
    raw = input(f"  Channel  [{DEFAULT_CHANNEL}] : ").strip()
    if raw:
        DEFAULT_CHANNEL = raw if raw.startswith("#") else "#" + raw
        # Strip characters illegal in channel names: NUL, BEL, space, comma, CR/LF
        DEFAULT_CHANNEL = re.sub(r'[\x00-\x07\x09-\x1f\x7f ,]', '', DEFAULT_CHANNEL)[:50] \
                          or DEFAULT_CHANNEL

    # NickServ password — hidden input, blank = skip
    raw = getpass.getpass("  NickServ password (blank to skip) : ")
    if raw:
        NICKSERV_PASSWORD = raw

    print(f"\n  → {DEFAULT_SERVER}:{DEFAULT_PORT} (SSL)  nick={DEFAULT_NICK}"
          + (f"  channel={DEFAULT_CHANNEL}" if DEFAULT_CHANNEL else ""))
    print()

    # Load AI models before curses starts so progress prints go to the normal
    # terminal and don't corrupt the TUI display.
    ai_detector = EnsembleAIDetector()
    try:
        curses.wrapper(lambda stdscr: asyncio.run(main_curses(stdscr, ai_detector)))
    except (KeyboardInterrupt, SystemExit):
        pass

if __name__ == "__main__":
    main()
