#!/usr/bin/env python3
"""Log analyzer for ai_scores.log (overridable via --log).

Defaults to ai_scores.log (JSONL with fields: ts, dt, sess, nick, target,
msg, flag, scores: heu/bino/cls/llama). Also handles other common shapes:
  - IRC chat:   [HH:MM(:SS)] <nick> message    or    [HH:MM] * nick action
  - JSON Lines: {"timestamp": "...", ...}      (e.g. detections.log)
  - Syslog-ish: YYYY-MM-DD HH:MM:SS[,ms] [LEVEL] component: message

Usage:
  python analyzelog.py                                # ai_scores.log full report
  python analyzelog.py --log other.log
  python analyzelog.py --top 20
  python analyzelog.py --user cfuser                  # filter + LLM behavior analysis
  python analyzelog.py --user cfuser --no-llm

  # New batch modes:
  python analyzelog.py --batch --since 2024-01-01 --until 2024-02-01
  python analyzelog.py --batch --flagged "llama>0.8 heu>0.5"
  python analyzelog.py --batch --similar
  python analyzelog.py --batch --bursts cfuser
  python analyzelog.py --batch --diff other.log
  python analyzelog.py --batch --export-edges edges.csv
  python analyzelog.py --watch                        # live tail
"""

from __future__ import annotations

import argparse
import atexit
import cmd
import contextlib
import csv
import hashlib
import io
import itertools
import json
import math
import os
import pydoc
import re
import shlex
import shutil
import statistics
import sys
import threading
import time
import urllib.request
import urllib.error
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, Iterator, Sequence

try:
    import readline  # type: ignore[import-not-found]
except ImportError:
    readline = None  # type: ignore[assignment]

import sqlite3
import html as html_mod
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from queue import Queue
from collections import deque
import enum

try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    MATPLOTLIB_OK = True
except ImportError:
    MATPLOTLIB_OK = False

try:
    import pandas as pd
    PANDAS_OK = True
except ImportError:
    PANDAS_OK = False

try:
    from statsmodels.tsa.holtwinters import SimpleExpSmoothing
    STATSMODELS_OK = True
except ImportError:
    STATSMODELS_OK = False

try:
    import curses
    CURSES_OK = True
except ImportError:
    CURSES_OK = False

try:
    import pyperclip as _pyperclip
    PYPERCLIP_OK = True
except ImportError:
    PYPERCLIP_OK = False


# ---------- parsing ----------------------------------------------------------

IRC_MSG_RE = re.compile(r"^\[?(?P<ts>(?:\d{4}-\d{2}-\d{2} )?\d{1,2}:\d{2}(?::\d{2})?)\]?\s+<(?P<nick>[^>]+)>\s+(?P<msg>.*)$")
IRC_ACT_RE = re.compile(r"^\[?(?P<ts>(?:\d{4}-\d{2}-\d{2} )?\d{1,2}:\d{2}(?::\d{2})?)\]?\s+\*\s+(?P<rest>.*)$")
SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)"
    r"\s+\[?(?P<level>[A-Z]{3,8})\]?\s+(?P<comp>[\w.\-/:]+):\s*(?P<msg>.*)$"
)
SYSLOG_BSD_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[\w.\-]+)\s+(?P<comp>[\w.\-/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<msg>.*)$"
)
GENERIC_TIME_RE = re.compile(
    r"^\[?(?P<ts>\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)\]?\s*(?P<msg>.*)$"
)
ERROR_TOKENS = re.compile(r"\b(error|exception|failed|failure|critical|fatal|traceback|denied)\b", re.I)


@dataclass
class Entry:
    raw: str
    ts: datetime | None
    user: str | None
    level: str | None
    event: str | None
    target: str | None
    text: str
    fmt: str


def _parse_iso(ts: str) -> datetime | None:
    ts = ts.replace(",", ".")
    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(ts)
    except ValueError:
        return None


def _parse_timestamp(ts: str) -> datetime | None:
    if not ts: return None
    # 1. Try ISO
    d = _parse_iso(ts)
    if d: return d
    
    # 2. Try varied formats
    # Note: %b %d %H:%M:%S is for BSD syslog
    for fmt in ("%Y-%m-%d %H:%M:%S", "%H:%M:%S", "%H:%M", "%b %d %H:%M:%S", "%Y/%m/%d %H:%M:%S"):
        try:
            dt = datetime.strptime(ts, fmt)
            now = datetime.now()
            if "%H:%M" in fmt and "%Y" not in fmt:
                dt = dt.replace(year=now.year, month=now.month, day=now.day)
            elif "%b" in fmt and "%Y" not in fmt:
                dt = dt.replace(year=now.year)
            return dt
        except ValueError:
            continue
    return None


def _compact_json_text(obj: dict) -> str:
    dt = obj.get("dt") or obj.get("timestamp") or obj.get("ts")
    nick = obj.get("nick") or obj.get("user") or obj.get("source") or ""
    target = obj.get("target") or obj.get("channel") or ""
    msg = obj.get("msg") or obj.get("message") or ""
    flag = obj.get("flag") or obj.get("severity") or ""
    typ = obj.get("type") or obj.get("event_type") or ""
    scores = []
    for k in ("heu", "bino", "cls", "llama"):
        if k in obj:
            scores.append(f"{k}={obj[k]}")
    score_str = " ".join(scores)

    parts = []
    if dt:
        parts.append(str(dt))
    if typ:
        parts.append(f"[{typ}]")
    if nick:
        parts.append(str(nick))
    if target:
        parts.append(f"→{target}")
    if flag:
        parts.append(f"({flag})")
    if score_str:
        parts.append(score_str)
    if msg:
        parts.append(f": {msg}")
    if not parts:
        return json.dumps({k: v for k, v in obj.items() if k != "hmac"}, default=str)
    return " ".join(parts)


def _flatten_json_user(obj) -> str | None:
    if not isinstance(obj, dict):
        return None
    for key in ("user", "username", "nick", "source", "host", "process", "name"):
        v = obj.get(key)
        if isinstance(v, str) and v:
            return v
    details = obj.get("details") or obj.get("payload")
    if isinstance(details, dict):
        return _flatten_json_user(details)
    return None


def _try_json(line: str) -> dict | None:
    if "{" not in line: return None
    start = line.find("{")
    end = line.rfind("}")
    if end > start:
        try:
            return json.loads(line[start:end+1])
        except (json.JSONDecodeError, ValueError):
            return None
    return None


def parse_line(line: str) -> Entry | None:
    line = line.rstrip("\r\n")
    if not line.strip():
        return None

    # 1. Try JSON (Strict then Fuzzy)
    obj = None
    if line.lstrip().startswith("{"):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            pass
    
    if obj is None:
        obj = _try_json(line)
        
    if isinstance(obj, dict):
        ts_str = obj.get("timestamp") or obj.get("dt") or obj.get("ts") or obj.get("time")
        ts = None
        if isinstance(ts_str, str):
            ts = _parse_timestamp(ts_str)
        elif isinstance(obj.get("ts"), (int, float)):
            try:
                ts = datetime.fromtimestamp(float(obj["ts"]))
            except (OSError, OverflowError, ValueError):
                ts = None
        user = _flatten_json_user(obj)
        level = obj.get("severity") or obj.get("level") or obj.get("flag")
        event = obj.get("event_type") or obj.get("event") or obj.get("type")
        payload = obj.get("payload")
        if event is None and isinstance(payload, dict):
            event = payload.get("type") or payload.get("action")
        target = obj.get("target") or obj.get("channel")
        text = _compact_json_text(obj)
        return Entry(line, ts, user, str(level) if level else None,
                     str(event) if event else None,
                     str(target) if target else None, text, "json")

    # 2. Try Standard Syslog
    m = SYSLOG_RE.match(line)
    if m:
        ts = _parse_timestamp(m["ts"])
        return Entry(line, ts, m["comp"], m["level"], None, None, m["msg"], "syslog")

    # 3. Try BSD Syslog
    m = SYSLOG_BSD_RE.match(line)
    if m:
        ts = _parse_timestamp(m["ts"])
        return Entry(line, ts, f"{m['host']}/{m['comp']}", None, None, None, m["msg"], "syslog_bsd")

    # 4. Try IRC Msg
    m = IRC_MSG_RE.match(line)
    if m:
        ts = _parse_timestamp(m["ts"])
        return Entry(line, ts, m["nick"], None, "msg", None, m["msg"], "irc")

    # 5. Try IRC Action
    m = IRC_ACT_RE.match(line)
    if m:
        ts = _parse_timestamp(m["ts"])
        rest = m["rest"]
        user = rest.split()[0] if rest.split() else "???"
        event = "action"
        for kw in ("joined", "left", "quit", "is now known", "kicked", "set mode", "Topic"):
            if kw in rest:
                event = kw.split()[0].lower()
                break
        return Entry(line, ts, user, None, event, None, rest, "irc")

    # 6. Try Generic Fallback
    m = GENERIC_TIME_RE.match(line)
    if m:
        ts = _parse_timestamp(m["ts"])
        return Entry(line, ts, None, None, None, None, m["msg"], "generic")

    return Entry(line, None, None, None, None, None, line, "raw")


def iter_entries(path: str) -> Iterator[Entry]:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            e = parse_line(line)
            if e is not None:
                yield e


# ---------- analysis ---------------------------------------------------------

SCORE_KEYS = ("heu", "bino", "cls", "llama")


def line_matches_user(entry: Entry, user: str) -> bool:
    u = user.lower()
    return bool(entry.user and entry.user.lower() == u)


_NICK_BOUNDARY = re.compile(r"[A-Za-z0-9_\-\[\]\\^{}|`]")


def _mentions(text: str, nick: str) -> bool:
    if not text or not nick:
        return False
    nl = nick.lower()
    tl = text.lower()
    start = 0
    while True:
        i = tl.find(nl, start)
        if i < 0:
            return False
        before = tl[i - 1] if i > 0 else ""
        after = tl[i + len(nl)] if i + len(nl) < len(tl) else ""
        if not _NICK_BOUNDARY.match(before) and not _NICK_BOUNDARY.match(after):
            return True
        start = i + 1


def _scores_from_raw(raw: str) -> dict:
    if not raw.lstrip().startswith("{"):
        return {}
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    keys = ("heu", "bino", "cls", "llama", "msg_len", "msg", "flag", "target")
    return {k: obj.get(k) for k in keys if k in obj}


def build_profile(entries: list[Entry], user: str) -> dict:
    u = user.lower()
    authored = [e for e in entries if e.user and e.user.lower() == u]
    mentions = [e for e in entries if e.user and e.user.lower() != u
                and _mentions(e.text or e.raw, user)]

    channels: Counter = Counter()
    flags: Counter = Counter()
    score_sums = {k: 0.0 for k in SCORE_KEYS}
    score_counts = {k: 0 for k in SCORE_KEYS}
    msg_lens: list[int] = []
    by_hour: Counter = Counter()
    by_day: Counter = Counter()
    samples: list[str] = []
    first_ts: datetime | None = None
    last_ts: datetime | None = None

    for e in authored:
        if e.target:
            channels[e.target] += 1
        if e.level:
            flags[e.level] += 1
        if e.ts:
            by_hour[e.ts.hour] += 1
            by_day[e.ts.date().isoformat()] += 1
            if first_ts is None or e.ts < first_ts:
                first_ts = e.ts
            if last_ts is None or e.ts > last_ts:
                last_ts = e.ts

        scores = _scores_from_raw(e.raw)
        for k in SCORE_KEYS:
            v = scores.get(k)
            if isinstance(v, (int, float)):
                score_sums[k] += float(v)
                score_counts[k] += 1
        if isinstance(scores.get("msg_len"), int):
            msg_lens.append(scores["msg_len"])
        elif scores.get("msg"):
            msg_lens.append(len(str(scores["msg"])))

        samples.append(e.text)

    score_means = {k: (score_sums[k] / score_counts[k]) if score_counts[k] else None
                   for k in SCORE_KEYS}
    msg_len_mean = (sum(msg_lens) / len(msg_lens)) if msg_lens else None

    return {
        "user": user,
        "authored": len(authored),
        "mentioned_by_others": len(mentions),
        "channels": channels,
        "flags": flags,
        "score_means": score_means,
        "msg_len_mean": msg_len_mean,
        "by_hour": dict(sorted(by_hour.items())),
        "by_day": dict(sorted(by_day.items())),
        "first_ts": first_ts,
        "last_ts": last_ts,
        "samples": samples,
    }


def _fmt_score(x):
    return f"{x:.3f}" if isinstance(x, float) else "—"


def _fmt_dt(d):
    return d.strftime("%Y-%m-%d %H:%M") if d else "—"


def _peak_hours(by_hour: dict) -> str:
    if not by_hour:
        return "—"
    top = sorted(by_hour.items(), key=lambda kv: -kv[1])[:3]
    return ", ".join(f"{h:02d}h({n})" for h, n in top)


def _top_str(counter: Counter, n: int) -> str:
    if not counter:
        return ""
    return ", ".join(f"{k}({v})" for k, v in counter.most_common(n))


def _fmt_num(x):
    if x is None:
        return "—"
    return f"{x:.1f}"


def print_compare_table(pa: dict, pb: dict) -> None:
    print_compare_table_n([pa, pb])


def print_compare_table_n(profiles: list[dict]) -> None:
    rows = [
        ("Authored lines", lambda p: str(p["authored"])),
        ("Mentioned by others", lambda p: str(p["mentioned_by_others"])),
        ("First seen", lambda p: _fmt_dt(p["first_ts"])),
        ("Last seen", lambda p: _fmt_dt(p["last_ts"])),
        ("Active days", lambda p: str(len(p["by_day"]))),
        ("Peak hours", lambda p: _peak_hours(p["by_hour"])),
        ("Top channels", lambda p: _top_str(p["channels"], 3) or "—"),
        ("Flags", lambda p: _top_str(p["flags"], 4) or "—"),
        ("Mean msg_len", lambda p: _fmt_num(p["msg_len_mean"])),
        ("heu mean", lambda p: _fmt_score(p["score_means"]["heu"])),
        ("bino mean", lambda p: _fmt_score(p["score_means"]["bino"])),
        ("cls mean", lambda p: _fmt_score(p["score_means"]["cls"])),
        ("llama mean", lambda p: _fmt_score(p["score_means"]["llama"])),
    ]
    label_w = max(len(r[0]) for r in rows)
    cells = [[fn(p) for p in profiles] for _, fn in rows]
    headers = [p["user"] for p in profiles]
    col_w = max(20, max(len(h) for h in headers),
                max((len(c) for row in cells for c in row), default=0))
    print("  " + "METRIC".ljust(label_w) + "   " + "   ".join(h.ljust(col_w) for h in headers))
    print("  " + "-" * label_w + "   " + "   ".join("-" * col_w for _ in headers))
    for (label, _), row in zip(rows, cells):
        print("  " + label.ljust(label_w) + "   " + "   ".join(c.ljust(col_w) for c in row))


def line_is_interaction(entry: Entry, a: str, b: str) -> bool:
    if not entry.user:
        return False
    nick = entry.user.lower()
    a_l, b_l = a.lower(), b.lower()
    if nick == a_l:
        other = b
    elif nick == b_l:
        other = a
    else:
        return False
    if entry.target and entry.target.lower() == other.lower():
        return True
    return _mentions(entry.text or entry.raw, other)


def summarize(entries: Iterable[Entry], top_n: int) -> dict:
    total = 0
    formats: Counter = Counter()
    users: Counter = Counter()
    events: Counter = Counter()
    levels: Counter = Counter()
    targets: Counter = Counter()
    by_hour: Counter = Counter()
    by_day: Counter = Counter()
    errors: list[str] = []
    first_ts: datetime | None = None
    last_ts: datetime | None = None

    for e in entries:
        total += 1
        formats[e.fmt] += 1
        if e.user:
            users[e.user] += 1
        if e.event:
            events[e.event] += 1
        if e.level:
            levels[e.level.upper()] += 1
        if e.target:
            targets[e.target] += 1
        if e.ts:
            by_hour[e.ts.hour] += 1
            by_day[e.ts.date().isoformat()] += 1
            if first_ts is None or e.ts < first_ts:
                first_ts = e.ts
            if last_ts is None or e.ts > last_ts:
                last_ts = e.ts
        if (e.level and e.level.upper() in {"ERROR", "CRITICAL", "FATAL", "HIGH", "SUS", "SUSPICIOUS"}) \
                or ERROR_TOKENS.search(e.text or ""):
            if len(errors) < 25:
                errors.append(e.raw)

    return {
        "total": total,
        "formats": formats,
        "top_users": users.most_common(top_n),
        "top_events": events.most_common(top_n),
        "top_targets": targets.most_common(top_n),
        "levels": dict(levels),
        "by_hour": dict(sorted(by_hour.items())),
        "by_day": dict(sorted(by_day.items())),
        "first_ts": first_ts,
        "last_ts": last_ts,
        "errors": errors,
    }


def print_report(s: dict) -> None:
    print(f"Total entries: {s['total']}")
    print(f"Formats: {dict(s['formats'])}")
    if s["first_ts"] or s["last_ts"]:
        print(f"Time range: {s['first_ts']}  →  {s['last_ts']}")
    if s["levels"]:
        print(f"Levels/severities: {s['levels']}")

    if s["top_users"]:
        print("\nTop users / sources:")
        for name, n in s["top_users"]:
            print(f"  {n:>7}  {name}")

    if s["top_events"]:
        print("\nTop events:")
        for name, n in s["top_events"]:
            print(f"  {n:>7}  {name}")

    if s.get("top_targets"):
        print("\nTop targets / channels:")
        for name, n in s["top_targets"]:
            print(f"  {n:>7}  {name}")

    if s["by_hour"]:
        print("\nActivity by hour:")
        peak = max(s["by_hour"].values()) or 1
        for h, n in s["by_hour"].items():
            bar = "█" * int(40 * n / peak)
            print(f"  {h:02d}  {n:>7}  {bar}")

    if s["by_day"] and len(s["by_day"]) > 1:
        print("\nActivity by day:")
        peak = max(s["by_day"].values()) or 1
        for d, n in s["by_day"].items():
            bar = "█" * int(40 * n / peak)
            print(f"  {d}  {n:>7}  {bar}")

    if s["errors"]:
        print(f"\nError-like entries (showing {len(s['errors'])}):")
        for line in s["errors"]:
            print(f"  {line[:200]}")


# ---------- time / score / fingerprint helpers ------------------------------

def parse_iso_arg(s: str) -> datetime | None:
    """User-supplied datetime: ISO, '5h ago', 'now'."""
    if not s:
        return None
    s = s.strip().replace(",", ".")
    if s.lower() == "now":
        return datetime.now()
    m = re.match(r"^(\d+)\s*([smhd])\s*(?:ago)?$", s, re.I)
    if m:
        amt = int(m.group(1))
        unit = m.group(2).lower()
        units = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}
        return datetime.now() - timedelta(**{units[unit]: amt})
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    for attempt in (s, s.replace(" ", "T")):
        try:
            return datetime.fromisoformat(attempt)
        except ValueError:
            pass
    try:
        return datetime.strptime(s, "%Y-%m-%d")
    except ValueError:
        return None


def in_time_range(ts: datetime | None, since: datetime | None,
                  until: datetime | None) -> bool:
    if since is None and until is None:
        return True
    if ts is None:
        return False
    if since and ts < since:
        return False
    if until and ts > until:
        return False
    return True


def apply_time_filter(entries: Iterable[Entry], since: datetime | None,
                      until: datetime | None) -> list[Entry]:
    if since is None and until is None:
        return list(entries) if not isinstance(entries, list) else entries
    return [e for e in entries if in_time_range(e.ts, since, until)]


_SCORE_OP_RE = re.compile(
    r"^(?P<key>[A-Za-z_]+)\s*(?P<op>>=|<=|==|=|!=|>|<)\s*(?P<val>-?\d+(?:\.\d+)?)$"
)


def parse_score_filter(expr: str) -> list[tuple[str, str, float]]:
    """Parse 'llama>0.8 heu<0.3' into list of (key, op, value)."""
    out: list[tuple[str, str, float]] = []
    for tok in expr.split():
        m = _SCORE_OP_RE.match(tok)
        if not m:
            raise ValueError(f"bad score expression: {tok!r}")
        op = m["op"]
        if op == "=":
            op = "=="
        out.append((m["key"], op, float(m["val"])))
    return out


def _cmp(op: str, a: float, b: float) -> bool:
    return {
        "==": a == b, "!=": a != b,
        ">": a > b, "<": a < b,
        ">=": a >= b, "<=": a <= b,
    }[op]


def matches_score_filter(entry: Entry,
                         filters: Sequence[tuple[str, str, float]]) -> bool:
    if not filters:
        return True
    scores = _scores_from_raw(entry.raw)
    for key, op, val in filters:
        v = scores.get(key)
        if not isinstance(v, (int, float)):
            return False
        if not _cmp(op, float(v), val):
            return False
    return True


def collect_scores(entries: Iterable[Entry], user: str | None = None
                   ) -> dict[str, list[float]]:
    out: dict[str, list[float]] = {k: [] for k in SCORE_KEYS}
    u = user.lower() if user else None
    for e in entries:
        if u and not (e.user and e.user.lower() == u):
            continue
        scores = _scores_from_raw(e.raw)
        for k in SCORE_KEYS:
            v = scores.get(k)
            if isinstance(v, (int, float)):
                out[k].append(float(v))
    return out


def population_score_stats(entries: Iterable[Entry]
                           ) -> dict[str, tuple[float, float, int]]:
    pool = collect_scores(entries)
    res: dict[str, tuple[float, float, int]] = {}
    for k, vals in pool.items():
        if len(vals) >= 2:
            res[k] = (statistics.mean(vals), statistics.pstdev(vals), len(vals))
        elif len(vals) == 1:
            res[k] = (vals[0], 0.0, 1)
        else:
            res[k] = (0.0, 0.0, 0)
    return res


def histogram(values: list[float], bins: int = 10,
              lo: float | None = None, hi: float | None = None
              ) -> tuple[list[int], list[tuple[float, float]]]:
    if not values:
        return [], []
    if lo is None:
        lo = min(values)
    if hi is None:
        hi = max(values)
    if hi <= lo:
        hi = lo + 1.0
    edges = [lo + (hi - lo) * i / bins for i in range(bins + 1)]
    counts = [0] * bins
    for v in values:
        idx = int((v - lo) / (hi - lo) * bins)
        if idx == bins:
            idx = bins - 1
        if 0 <= idx < bins:
            counts[idx] += 1
    intervals = [(edges[i], edges[i + 1]) for i in range(bins)]
    return counts, intervals


def percentiles(values: list[float], ps: Sequence[int] = (10, 25, 50, 75, 90)
                ) -> dict[int, float]:
    if not values:
        return {}
    s = sorted(values)
    out: dict[int, float] = {}
    for p in ps:
        if len(s) == 1:
            out[p] = s[0]
            continue
        rank = (p / 100) * (len(s) - 1)
        lo = int(rank)
        hi = min(lo + 1, len(s) - 1)
        frac = rank - lo
        out[p] = s[lo] * (1 - frac) + s[hi] * frac
    return out


def print_score_dist(label: str, scores_by_key: dict[str, list[float]],
                     bins: int = 10) -> None:
    print(f"\nScore distributions for {label}:")
    for key in SCORE_KEYS:
        vals = scores_by_key.get(key) or []
        if not vals:
            print(f"  {key:6s}  (no data)")
            continue
        pcs = percentiles(vals)
        m = statistics.mean(vals)
        sd = statistics.pstdev(vals) if len(vals) > 1 else 0.0
        print(f"  {key:6s}  n={len(vals):<5d}  mean={m:.3f}  stdev={sd:.3f}"
              f"  p10={pcs[10]:.2f}  p50={pcs[50]:.2f}  p90={pcs[90]:.2f}")
        counts, intervals = histogram(vals, bins, 0.0, 1.0)
        peak = max(counts) or 1
        for c, (a, b) in zip(counts, intervals):
            bar = "█" * int(20 * c / peak)
            print(f"          [{a:.2f},{b:.2f})  {c:>5d}  {bar}")


def zscores_for_user(profile: dict,
                     pop: dict[str, tuple[float, float, int]]
                     ) -> dict[str, float | None]:
    out: dict[str, float | None] = {}
    means = profile.get("score_means", {})
    for k in SCORE_KEYS:
        um = means.get(k)
        pm, ps, n = pop.get(k, (0.0, 0.0, 0))
        if um is None or ps == 0 or n == 0:
            out[k] = None
        else:
            out[k] = (um - pm) / ps
    return out


def print_zscores(profile: dict, pop: dict[str, tuple[float, float, int]]) -> None:
    z = zscores_for_user(profile, pop)
    print(f"\nZ-scores for {profile['user']} vs population:")
    for k in SCORE_KEYS:
        pm, ps, n = pop.get(k, (0.0, 0.0, 0))
        um = profile["score_means"].get(k)
        zk = z[k]
        u_str = f"{um:.3f}" if isinstance(um, float) else "—"
        z_str = f"{zk:+.2f}σ" if isinstance(zk, float) else "—"
        print(f"  {k:6s}  user={u_str}  pop_mean={pm:.3f}  pop_sd={ps:.3f}"
              f"  n={n}   z={z_str}")


def user_fingerprint(profile: dict) -> list[float]:
    vec: list[float] = []
    sm = profile.get("score_means", {})
    for k in SCORE_KEYS:
        v = sm.get(k)
        vec.append(float(v) if isinstance(v, float) else 0.0)
    by_hour = profile.get("by_hour") or {}
    total = sum(by_hour.values()) or 1
    for h in range(24):
        vec.append(by_hour.get(h, 0) / total)
    msg_len = profile.get("msg_len_mean")
    vec.append((float(msg_len) / 200.0) if msg_len else 0.0)
    return vec


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def find_similar_users(entries: list[Entry], min_lines: int = 5,
                       threshold: float = 0.95, top: int = 20
                       ) -> list[tuple[str, str, float, int, int]]:
    counts: Counter = Counter(e.user for e in entries if e.user)
    candidates = sorted(u for u, n in counts.items() if n >= min_lines)
    profiles = {u: build_profile(entries, u) for u in candidates}
    fps = {u: user_fingerprint(p) for u, p in profiles.items()}
    pairs: list[tuple[str, str, float, int, int]] = []
    for i, a in enumerate(candidates):
        for b in candidates[i + 1:]:
            sim = cosine(fps[a], fps[b])
            if sim >= threshold:
                pairs.append((a, b, sim, profiles[a]["authored"],
                              profiles[b]["authored"]))
    pairs.sort(key=lambda p: -p[2])
    return pairs[:top]


def print_similar_users(pairs: list[tuple[str, str, float, int, int]]) -> None:
    if not pairs:
        print("\nNo user pairs above similarity threshold.")
        return
    print("\nMost-similar user pairs (cosine over score+hour fingerprint):")
    print(f"  {'sim':>8}   {'user A':<20} {'(lines)':>9}    {'user B':<20} {'(lines)':>9}")
    for a, b, sim, na, nb in pairs:
        print(f"  {sim:>8.4f}   {a:<20} ({na:>7})    {b:<20} ({nb:>7})")


def detect_bursts(entries: list[Entry], user: str, window_seconds: int = 60,
                  z_threshold: float = 3.0
                  ) -> list[tuple[datetime, int, float]]:
    u = user.lower()
    timestamps = [e.ts for e in entries
                  if e.ts and e.user and e.user.lower() == u]
    if len(timestamps) < 5:
        return []
    timestamps.sort()
    bins: Counter = Counter()
    start_epoch = int(timestamps[0].timestamp())
    for t in timestamps:
        bucket = int(t.timestamp() - start_epoch) // window_seconds
        bins[bucket] += 1
    counts = list(bins.values())
    mean = statistics.mean(counts)
    sd = statistics.pstdev(counts) if len(counts) > 1 else 0.0
    if sd == 0:
        return []
    bursts: list[tuple[datetime, int, float]] = []
    for b, c in sorted(bins.items()):
        z = (c - mean) / sd
        if z >= z_threshold:
            ts = datetime.fromtimestamp(start_epoch + b * window_seconds)
            bursts.append((ts, c, z))
    return bursts


def print_bursts(user: str, bursts: list[tuple[datetime, int, float]],
                 window_seconds: int) -> None:
    if not bursts:
        print(f"\nNo bursts detected for {user} (window={window_seconds}s).")
        return
    print(f"\nBursts for {user} (window={window_seconds}s):")
    for ts, c, z in bursts:
        print(f"  {ts}  count={c:<5d}  z={z:.2f}σ")


REPLY_PREFIX_RE = re.compile(r"^\s*([A-Za-z0-9_\-\[\]\\^{}|`]+)\s*[:,]\s+")
MENTION_RE = re.compile(r"@([A-Za-z0-9_\-\[\]\\^{}|`]+)")


def detect_reply_target(entry: Entry, known_nicks_lower: set[str]) -> str | None:
    text = entry.text or entry.raw or ""
    own = entry.user.lower() if entry.user else None
    m = REPLY_PREFIX_RE.match(text)
    if m:
        cand = m.group(1)
        if cand.lower() in known_nicks_lower and cand.lower() != own:
            return cand
    m = MENTION_RE.search(text)
    if m:
        cand = m.group(1)
        if cand.lower() in known_nicks_lower and cand.lower() != own:
            return cand
    return None


def build_edge_graph(entries: list[Entry]) -> Counter:
    nicks_lower = {e.user.lower() for e in entries if e.user}
    edges: Counter = Counter()
    for e in entries:
        if not e.user:
            continue
        tgt = detect_reply_target(e, nicks_lower)
        if tgt:
            edges[(e.user, tgt)] += 1
    return edges


def build_thread_for_user(entries: list[Entry], user: str
                          ) -> list[tuple[Entry, str | None]]:
    nicks_lower = {e.user.lower() for e in entries if e.user}
    out: list[tuple[Entry, str | None]] = []
    u = user.lower()
    for e in entries:
        if not e.user:
            continue
        author = e.user.lower()
        text = e.text or e.raw or ""
        if author == u:
            tgt = detect_reply_target(e, nicks_lower)
            out.append((e, tgt))
        elif _mentions(text, user):
            out.append((e, user))
    return out


# ---------- NEW: Session detection (#5) --------------------------------------

@dataclass
class Session:
    user: str
    start: datetime
    end: datetime
    line_count: int
    targets: list[str] = field(default_factory=list)

def detect_sessions(entries: list[Entry], user: str, gap_minutes: int = 30) -> list[Session]:
    u = user.lower()
    user_entries = sorted(
        [e for e in entries if e.ts and e.user and e.user.lower() == u],
        key=lambda e: e.ts
    )
    if not user_entries:
        return []
    sessions: list[Session] = []
    cur_start = user_entries[0].ts
    cur_end = user_entries[0].ts
    cur_count = 1
    cur_targets: list[str] = []
    if user_entries[0].target:
        cur_targets.append(user_entries[0].target)
    for e in user_entries[1:]:
        gap = (e.ts - cur_end).total_seconds() / 60
        if gap > gap_minutes:
            sessions.append(Session(user, cur_start, cur_end, cur_count, cur_targets))
            cur_start = e.ts
            cur_count = 0
            cur_targets = []
        cur_end = e.ts
        cur_count += 1
        if e.target:
            cur_targets.append(e.target)
    sessions.append(Session(user, cur_start, cur_end, cur_count, cur_targets))
    return sessions

# ---------- NEW: Response time analysis (#6) ---------------------------------

@dataclass
class ResponseTime:
    responder: str
    responded_to: str
    delay_seconds: float
    ts: datetime

def compute_response_times(entries: list[Entry], window_seconds: int = 300) -> list[ResponseTime]:
    nicks = {e.user for e in entries if e.user}
    nicks_lower = {e.user.lower() for e in entries if e.user}
    sorted_entries = sorted([e for e in entries if e.ts], key=lambda e: e.ts)
    result: list[ResponseTime] = []
    for i, e in enumerate(sorted_entries):
        if not e.user:
            continue
        tgt = detect_reply_target(e, nicks_lower)
        if tgt:
            # look back for the most recent message from tgt
            for j in range(i - 1, -1, -1):
                prev = sorted_entries[j]
                if prev.user and prev.user.lower() == tgt.lower() and prev.ts:
                    delay = (e.ts - prev.ts).total_seconds()
                    if delay <= window_seconds:
                        result.append(ResponseTime(e.user, tgt, delay, e.ts))
                    break
    return result

# ---------- NEW: Sentiment analysis (#4) -------------------------------------

SENTIMENT_POS = {
    "good", "great", "awesome", "thanks", "nice", "love", "perfect", "helpful",
    "excellent", "amazing", "beautiful", "wonderful", "fantastic", "brilliant",
    "outstanding", "superb", "glad", "happy", "correct", "agree", "works",
    "fixed", "solved", "appreciate", "thank", "please", "yes", "ok", "okay",
    "impressive", "cool", "wow", "delightful", "best", "legendary", "sweet",
    "neat", "fabulous", "bravo", "cheers", "recommend", "satisfied"
}

SENTIMENT_NEG = {
    "bad", "terrible", "awful", "hate", "ugly", "horrible", "wrong", "broken",
    "fails", "failed", "error", "crash", "stupid", "annoying", "useless",
    "worst", "sucks", "crap", "damn", "bug", "issue", "problem", "disaster",
    "fault", "never", "refuse", "reject", "no", "not", "can't", "cannot",
    "won't", "poor", "difficult", "hard", "slow", "expensive", "boring",
    "weird", "strange", "confusing", "frustrating", "waste", "garbage",
    "trash", "nonsense", "ridiculous", "shame", "unfortunate", "sad", "angry"
}

SENTIMENT_AGREE = {"agree", "yes", "correct", "right", "indeed", "exactly", "true", "same", "yep", "affirmative"}
SENTIMENT_DISAGREE = {"disagree", "no", "wrong", "incorrect", "false", "nonsense", "dispute", "reject", "nope", "negative"}

SENTIMENT_NEGATORS = {"not", "never", "no", "neither", "nor", "none", "cannot", "can't", "don't", "doesn't", "won't", "wasn't", "shouldn't", "couldn't", "hardly", "scarcely", "barely"}
SENTIMENT_INTENSIFIERS = {"very", "extremely", "really", "so", "too", "quite", "super", "highly", "absolutely", "totally", "utterly"}

@dataclass
class SentimentScore:
    positive: float
    negative: float
    agreement: float
    disagreement: float
    compound: float

def score_sentiment(text: str) -> SentimentScore:
    tokens = re.findall(r"\b\w+\b", text.lower())
    pos_score = 0.0
    neg_score = 0.0
    agr_score = 0.0
    dagr_score = 0.0
    
    negated = False
    negation_window = 0
    
    for i, tok in enumerate(tokens):
        # Intensity multiplier
        multiplier = 1.0
        if i > 0 and tokens[i-1] in SENTIMENT_INTENSIFIERS:
            multiplier = 2.0
            
        # Check for negation
        if tok in SENTIMENT_NEGATORS:
            negated = True
            negation_window = 3
            continue
            
        is_pos = tok in SENTIMENT_POS
        is_neg = tok in SENTIMENT_NEG
        is_agr = tok in SENTIMENT_AGREE
        is_dagr = tok in SENTIMENT_DISAGREE
        
        val = 1.0 * multiplier
        
        if negated and negation_window > 0:
            # Flip sentiment
            if is_pos:
                neg_score += val
            elif is_neg:
                pos_score += val
            # For agreement, we usually don't flip as easily in simple logic, but let's be consistent
            if is_agr:
                dagr_score += val
            elif is_dagr:
                agr_score += val
            negation_window -= 1
            if negation_window == 0:
                negated = False
        else:
            if is_pos:
                pos_score += val
            if is_neg:
                neg_score += val
            if is_agr:
                agr_score += val
            if is_dagr:
                dagr_score += val
                
    total = pos_score + neg_score + 1.0
    total_agr = agr_score + dagr_score + 1.0
    
    return SentimentScore(
        positive=pos_score / total,
        negative=neg_score / total,
        agreement=agr_score / total_agr,
        disagreement=dagr_score / total_agr,
        compound=(pos_score - neg_score) / total,
    )

def user_sentiment(entries: list[Entry], user: str) -> dict:
    u = user.lower()
    texts = [e.text or e.raw for e in entries if e.user and e.user.lower() == u and (e.text or e.raw)]
    if not texts:
        return {}
    scores = [score_sentiment(t) for t in texts]
    return {
        "user": user,
        "n": len(scores),
        "mean_positive": statistics.mean(s.positive for s in scores),
        "mean_negative": statistics.mean(s.negative for s in scores),
        "mean_compound": statistics.mean(s.compound for s in scores),
        "pos_rate": sum(1 for s in scores if s.compound > 0) / len(scores),
        "neg_rate": sum(1 for s in scores if s.compound < 0) / len(scores),
        "agree_rate": statistics.mean(s.agreement for s in scores),
    }

# ---------- NEW: Topic/keyword extraction (#3) --------------------------------

STOPWORDS = {
    "the", "a", "an", "is", "in", "to", "of", "and", "it", "you", "that", "on", "for", "with", "as", "at", "by", "this", "are", "be", "has", "have", "had", "not", "was", "were", "will", "can", "its", "or", "do", "if", "from", "they", "what", "which", "who", "all", "about", "but", "just", "like", "so", "up", "no", "out", "one", "also", "get", "would", "could", "there", "their", "more", "some", "my", "your", "we", "he", "she", "it's", "they're", "can't", "don't", "we're", "you're", "about", "did", "does", "been", "being", "should", "would", "could", "than", "then", "them", "these", "those", "when", "where", "how", "why"
}

def extract_keywords(texts: list[str], top_n: int = 20) -> list[tuple[str, int]]:
    counter: Counter = Counter()
    # Handle contractions better by including apostrophes
    token_re = re.compile(r"[A-Za-z][A-Za-z0-9_\-']{2,}")
    for t in texts:
        for tok in token_re.findall(t.lower()):
            if tok not in STOPWORDS and len(tok) > 2:
                # Remove trailing apostrophes or common short forms
                tok = tok.strip("'")
                if tok not in STOPWORDS and len(tok) > 2:
                    counter[tok] += 1
    return counter.most_common(top_n)

def extract_ngrams(texts: list[str], n: int = 2, top_n: int = 20) -> list[tuple[str, int]]:
    counter: Counter = Counter()
    token_re = re.compile(r"[A-Za-z][A-Za-z0-9_\-']{2,}")
    for t in texts:
        tokens = [tok for tok in token_re.findall(t.lower()) if tok not in STOPWORDS and len(tok) > 2]
        for i in range(len(tokens) - n + 1):
            gram = " ".join(tokens[i:i + n])
            counter[gram] += 1
    return counter.most_common(top_n)

def user_topics(entries: list[Entry], user: str, top_n: int = 15) -> dict:
    u = user.lower()
    texts = [e.text or e.raw for e in entries if e.user and e.user.lower() == u and (e.text or e.raw)]
    
    # Dynamically expand stopwords for this user to filter out common metadata
    local_stopwords = set(STOPWORDS)
    local_stopwords.add(u)
    # Filter out common channel names if they appear in text
    for e in entries:
        if e.target:
            local_stopwords.add(e.target.lower().lstrip("#"))
            local_stopwords.add(e.target.lower())
    # Filter out common scoring terms seen in _compact_json_text
    local_stopwords.update({"heu", "bino", "cls", "llama", "normal", "suspect", "msg", "message", "timestamp", "dt"})

    def extract_keywords_local(txts: list[str], n: int) -> list[tuple[str, int]]:
        counter: Counter = Counter()
        token_re = re.compile(r"[A-Za-z][A-Za-z0-9_\-']{2,}")
        for t in txts:
            for tok in token_re.findall(t.lower()):
                if tok not in local_stopwords and len(tok) > 2:
                    tok = tok.strip("'")
                    if tok not in local_stopwords and len(tok) > 2:
                        counter[tok] += 1
        return counter.most_common(n)

    def extract_ngrams_local(txts: list[str], n: int, top_n_local: int) -> list[tuple[str, int]]:
        counter: Counter = Counter()
        token_re = re.compile(r"[A-Za-z][A-Za-z0-9_\-']{2,}")
        for t in txts:
            tokens = [tok for tok in token_re.findall(t.lower()) if tok not in local_stopwords and len(tok) > 2]
            for i in range(len(tokens) - n + 1):
                gram = " ".join(tokens[i:i + n])
                counter[gram] += 1
        return counter.most_common(top_n_local)

    return {
        "user": user,
        "keywords": extract_keywords_local(texts, top_n),
        "bigrams": extract_ngrams_local(texts, 2, top_n),
        "trigrams": extract_ngrams_local(texts, 3, top_n),
    }

# ---------- NEW: Forensic analysis (#28) ---------------------------------------

IPV4_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
URL_RE = re.compile(r'https?://[^\s<>"\'{}|\\^`\[\]]+')
EMAIL_RE = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b')
FILEPATH_RE = re.compile(r'(?:[A-Za-z]:\\|/)?(?:[\w.\-]+[/\\])+[\w.\-]+')
MD5_RE = re.compile(r'\b[a-fA-F0-9]{32}\b')
SHA1_RE = re.compile(r'\b[a-fA-F0-9]{40}\b')
SHA256_RE = re.compile(r'\b[a-fA-F0-9]{64}\b')


@dataclass
class ExtractedEntity:
    type: str
    value: str
    count: int
    first_seen: datetime | None
    last_seen: datetime | None
    contexts: list[str] = field(default_factory=list)


def extract_entities(text: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    ips = IPV4_RE.findall(text)
    if ips:
        out["ip"] = [ip for ip in ips if sum(int(o) for o in ip.split(".")) > 0 and not ip.startswith("0.")]
    urls = URL_RE.findall(text)
    if urls:
        out["url"] = urls
    emails = EMAIL_RE.findall(text)
    if emails:
        out["email"] = emails
    paths = FILEPATH_RE.findall(text)
    if paths:
        out["filepath"] = paths
    md5s = MD5_RE.findall(text)
    if md5s:
        out["md5"] = md5s
    sha1s = SHA1_RE.findall(text)
    if sha1s:
        out["sha1"] = sha1s
    sha256s = SHA256_RE.findall(text)
    if sha256s:
        out["sha256"] = sha256s
    return out


def build_entity_catalog(entries: list[Entry]) -> dict[str, list[ExtractedEntity]]:
    catalog: dict[str, list[ExtractedEntity]] = {}
    seen: dict[str, set[str]] = {}
    for e in entries:
        entities = extract_entities(e.raw)
        for etype, values in entities.items():
            catalog.setdefault(etype, [])
            seen.setdefault(etype, set())
            for val in values:
                if val not in seen[etype]:
                    seen[etype].add(val)
                    catalog[etype].append(ExtractedEntity(
                        type=etype, value=val, count=1,
                        first_seen=e.ts, last_seen=e.ts,
                        contexts=[(e.text or e.raw)[:200]],
                    ))
                else:
                    for entry in catalog[etype]:
                        if entry.value == val:
                            entry.count += 1
                            if e.ts and (entry.last_seen is None or e.ts > entry.last_seen):
                                entry.last_seen = e.ts
                            if e.ts and (entry.first_seen is None or e.ts < entry.first_seen):
                                entry.first_seen = e.ts
                            if len(entry.contexts) < 5:
                                entry.contexts.append((e.text or e.raw)[:200])
                            break
    return catalog


def print_entity_report(catalog: dict[str, list[ExtractedEntity]]) -> None:
    if not catalog:
        print("(no entities found)")
        return
    total = sum(len(v) for v in catalog.values())
    print(f"\nEntity extraction report ({total} total entities):")
    for etype in sorted(catalog.keys()):
        entries = sorted(catalog[etype], key=lambda x: -x.count)
        print(f"\n  [{etype.upper()}] ({len(entries)} unique)")
        for ent in entries[:20]:
            first = _fmt_dt(ent.first_seen)
            last = _fmt_dt(ent.last_seen)
            ctx = ent.contexts[0][:120] if ent.contexts else ""
            print(f"    {ent.count:>4d}x  {ent.value:<50s}  {first}  {last}")
            if ctx:
                print(f"          e.g. \"{ctx}\"")
        if len(entries) > 20:
            print(f"    ...({len(entries) - 20} more)")


@dataclass
class TimelineGap:
    start: datetime
    end: datetime
    duration_minutes: float


def detect_timeline_gaps(entries: list[Entry], user: str | None = None,
                         threshold_minutes: int = 60) -> list[TimelineGap]:
    if user:
        u = user.lower()
        filtered = sorted(
            [e for e in entries if e.ts and e.user and e.user.lower() == u],
            key=lambda e: e.ts
        )
    else:
        filtered = sorted([e for e in entries if e.ts], key=lambda e: e.ts)
    if len(filtered) < 2:
        return []
    gaps: list[TimelineGap] = []
    for i in range(1, len(filtered)):
        gap_min = (filtered[i].ts - filtered[i - 1].ts).total_seconds() / 60
        if gap_min >= threshold_minutes:
            gaps.append(TimelineGap(filtered[i - 1].ts, filtered[i].ts, gap_min))
    return gaps


def print_timeline_gaps(gaps: list[TimelineGap], user: str | None) -> None:
    if not gaps:
        print(f"\nNo significant gaps detected{' for ' + user if user else ''}.")
        return
    label = f" for '{user}'" if user else ""
    print(f"\nTimeline gaps{label} ({len(gaps)} gaps):")
    for i, g in enumerate(gaps, 1):
        dur_h = g.duration_minutes / 60
        dur_str = f"{dur_h:.1f}h" if dur_h >= 1 else f"{g.duration_minutes:.0f}min"
        print(f"  #{i:<3d}  {g.start}  \u2192  {g.end}  ({dur_str})")


@dataclass
class TimelineEvent:
    ts: datetime | None
    user: str | None
    event_type: str
    summary: str
    raw: str
    entities: dict[str, list[str]] = field(default_factory=dict)


def reconstruct_timeline(entries: list[Entry], user: str | None = None,
                         max_events: int = 200) -> list[TimelineEvent]:
    if user:
        u = user.lower()
        filtered = sorted(
            [e for e in entries if e.ts and e.user and e.user.lower() == u],
            key=lambda e: e.ts
        )
    else:
        filtered = sorted([e for e in entries if e.ts], key=lambda e: e.ts)
    timeline: list[TimelineEvent] = []
    for e in filtered[:max_events]:
        entities = extract_entities(e.raw)
        event_type = e.event or e.level or "entry"
        summary = (e.text or e.raw)[:160]
        timeline.append(TimelineEvent(e.ts, e.user, event_type, summary, e.raw, entities))
    return timeline


def print_timeline_reconstruction(timeline: list[TimelineEvent],
                                  show_entities: bool = False) -> None:
    if not timeline:
        print("(no timeline data)")
        return
    print(f"\nTimeline reconstruction ({len(timeline)} events):")
    for i, ev in enumerate(timeline, 1):
        ts = ev.ts.strftime("%Y-%m-%d %H:%M:%S") if ev.ts else "\u2014"
        user = (ev.user or "?").ljust(15)
        print(f"  #{i:<4d}  {ts}  {user} [{ev.event_type}]  {ev.summary}")
        if show_entities and ev.entities:
            for etype, vals in ev.entities.items():
                if vals:
                    print(f"          {etype}: {', '.join(vals[:3])}")

# ---------- Log tamper detection (#28) ----------------------------------------

@dataclass
class TamperIndicator:
    severity: str  # "critical", "high", "medium", "low", "info"
    category: str  # "timestamp", "sequence", "content", "format", "statistical"
    description: str
    details: str
    line_numbers: list[int] = field(default_factory=list)
    affected_entries: list[Entry] = field(default_factory=list)

@dataclass
class TamperReport:
    total_entries: int
    analyzed_entries: int
    indicators: list[TamperIndicator]
    integrity_score: float  # 0.0 (heavily tampered) to 1.0 (clean)
    summary: str

def detect_tampering(entries: list[Entry], user: str | None = None,
                     strict_mode: bool = False) -> TamperReport:
    """Detect signs of log manipulation: out-of-order timestamps, duplicate entries,
    impossible gaps, format inconsistencies, content anomalies, and statistical irregularities."""
    filtered = [e for e in entries if line_matches_user(e, user)] if user else entries
    indicators: list[TamperIndicator] = []
    analyzed = 0

    # 1. Timestamp order analysis
    ts_entries = [(i, e) for i, e in enumerate(filtered) if e.ts]
    if len(ts_entries) >= 2:
        analyzed += len(ts_entries)
        out_of_order: list[tuple[int, Entry, Entry]] = []
        for i in range(1, len(ts_entries)):
            prev_idx, prev_e = ts_entries[i - 1]
            curr_idx, curr_e = ts_entries[i]
            if curr_e.ts < prev_e.ts:
                out_of_order.append((curr_idx, prev_e, curr_e))

        if out_of_order:
            severity = "critical" if len(out_of_order) > 5 else "high" if len(out_of_order) > 1 else "medium"
            indicators.append(TamperIndicator(
                severity=severity,
                category="timestamp",
                description=f"Out-of-order timestamps detected ({len(out_of_order)} occurrences)",
                details=f"Entries found with timestamps earlier than preceding entries. "
                        f"First occurrence: line {out_of_order[0][0]+1} "
                        f"({out_of_order[0][2].ts} < {out_of_order[0][1].ts})",
                line_numbers=[idx + 1 for idx, _, _ in out_of_order[:20]],
            ))

        # 2. Duplicate timestamp detection
        ts_counts: Counter = Counter()
        ts_first_seen: dict[datetime, int] = {}
        for idx, e in ts_entries:
            ts_counts[e.ts] += 1
            if e.ts not in ts_first_seen:
                ts_first_seen[e.ts] = idx
        dup_ts = [(ts, cnt) for ts, cnt in ts_counts.items() if cnt > 1]
        if dup_ts:
            max_dup = max(cnt for _, cnt in dup_ts)
            severity = "high" if max_dup > 10 else "medium" if max_dup > 3 else "low"
            indicators.append(TamperIndicator(
                severity=severity,
                category="timestamp",
                description=f"Duplicate timestamps ({len(dup_ts)} unique timestamps repeated)",
                details=f"Max duplicates for single timestamp: {max_dup}. "
                        f"Example: {dup_ts[0][0]} appears {dup_ts[0][1]} times",
            ))

        # 3. Impossible time gaps (negative or zero gaps in sorted order)
        sorted_ts = sorted(ts_entries, key=lambda x: x[1].ts)
        zero_gaps = []
        for i in range(1, len(sorted_ts)):
            prev_ts = sorted_ts[i - 1][1].ts
            curr_ts = sorted_ts[i][1].ts
            if prev_ts == curr_ts:
                zero_gaps.append(sorted_ts[i][0])
        if zero_gaps and strict_mode:
            indicators.append(TamperIndicator(
                severity="medium",
                category="timestamp",
                description=f"Zero-duration gaps ({len(zero_gaps)} entries with identical timestamps)",
                details=f"Multiple entries share exact timestamps, which may indicate batch insertion or copy-paste",
                line_numbers=[idx + 1 for idx in zero_gaps[:10]],
            ))

    # 4. Format consistency analysis
    format_sequence = [e.fmt for e in filtered]
    format_changes = []
    for i in range(1, len(format_sequence)):
        if format_sequence[i] != format_sequence[i - 1]:
            format_changes.append((i, format_sequence[i - 1], format_sequence[i]))
    if format_changes:
        # Check if format changes are clustered (suspicious) vs gradual (normal)
        change_positions = [fc[0] for fc in format_changes]
        if len(change_positions) >= 2:
            gaps_between_changes = [change_positions[i+1] - change_positions[i]
                                    for i in range(len(change_positions)-1)]
            avg_gap = statistics.mean(gaps_between_changes) if gaps_between_changes else 0
            if avg_gap < 5 and len(format_changes) > 3:
                indicators.append(TamperIndicator(
                    severity="high",
                    category="format",
                    description=f"Rapid format changes ({len(format_changes)} changes in close proximity)",
                    details=f"Average distance between format changes: {avg_gap:.1f} entries. "
                            f"Sudden format shifts may indicate log splicing or injection",
                    line_numbers=[pos + 1 for pos in change_positions[:10]],
                ))
            else:
                indicators.append(TamperIndicator(
                    severity="info",
                    category="format",
                    description=f"Format transitions detected ({len(format_changes)} changes)",
                    details=f"Formats: {dict(Counter(format_sequence))}. "
                            f"Changes appear gradual, likely normal log source variation",
                ))

    # 5. Content duplication analysis (copy-paste detection)
    raw_lines = [e.raw for e in filtered]
    line_counts = Counter(raw_lines)
    exact_dups = [(line, cnt) for line, cnt in line_counts.items() if cnt > 1]
    if exact_dups:
        max_dup_line = max(cnt for _, cnt in exact_dups)
        if max_dup_line > 5 or (strict_mode and max_dup_line > 2):
            severity = "high" if max_dup_line > 20 else "medium"
            indicators.append(TamperIndicator(
                severity=severity,
                category="content",
                description=f"Exact duplicate lines ({len(exact_dups)} unique lines repeated)",
                details=f"Most repeated line appears {max_dup_line} times. "
                        f"Sample: '{exact_dups[0][0][:100]}...'",
            ))

    # 6. Shannon entropy analysis on message content
    if filtered:
        texts = [e.text or e.raw for e in filtered if e.text or e.raw]
        if len(texts) >= 10:
            entropies = []
            for text in texts:
                if len(text) > 0:
                    freq = Counter(text)
                    length = len(text)
                    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
                    entropies.append(entropy)
            if entropies:
                mean_entropy = statistics.mean(entropies)
                stdev_entropy = statistics.pstdev(entropies) if len(entropies) > 1 else 0
                # Flag entries with unusually low or high entropy
                low_entropy_entries = []
                high_entropy_entries = []
                for i, (e, ent) in enumerate(zip(filtered, entropies)):
                    if stdev_entropy > 0:
                        z = (ent - mean_entropy) / stdev_entropy
                        if z < -2.5:
                            low_entropy_entries.append((i, e, ent))
                        elif z > 2.5:
                            high_entropy_entries.append((i, e, ent))
                if low_entropy_entries:
                    indicators.append(TamperIndicator(
                        severity="medium",
                        category="content",
                        description=f"Low-entropy entries detected ({len(low_entropy_entries)} entries)",
                        details=f"Unusually repetitive/predictable content (z < -2.5σ). "
                                f"May indicate automated generation or padding. "
                                f"Mean entropy: {mean_entropy:.2f}, threshold: {mean_entropy - 2.5*stdev_entropy:.2f}",
                        line_numbers=[idx + 1 for idx, _, _ in low_entropy_entries[:10]],
                    ))
                if high_entropy_entries and strict_mode:
                    indicators.append(TamperIndicator(
                        severity="low",
                        category="content",
                        description=f"High-entropy entries ({len(high_entropy_entries)} entries)",
                        details=f"Unusually random-looking content (z > 2.5σ). "
                                f"May indicate encrypted data, hashes, or noise injection",
                        line_numbers=[idx + 1 for idx, _, _ in high_entropy_entries[:10]],
                    ))

    # 7. Statistical density analysis (sudden spikes/drops in entry rate)
    if ts_entries and len(ts_entries) >= 10:
        sorted_by_time = sorted(ts_entries, key=lambda x: x[1].ts)
        # Divide into buckets and check for anomalous density changes
        total_span = (sorted_by_time[-1][1].ts - sorted_by_time[0][1].ts).total_seconds()
        if total_span > 0:
            num_buckets = min(len(sorted_by_time) // 5, 50)
            bucket_size = total_span / num_buckets
            buckets: list[int] = [0] * num_buckets
            for idx, e in sorted_by_time:
                bucket_idx = int((e.ts - sorted_by_time[0][1].ts).total_seconds() / bucket_size)
                bucket_idx = min(bucket_idx, num_buckets - 1)
                buckets[bucket_idx] += 1
            if len(buckets) >= 3:
                mean_bucket = statistics.mean(buckets)
                stdev_bucket = statistics.pstdev(buckets) if len(buckets) > 1 else 0
                if stdev_bucket > 0:
                    anomalous_buckets = []
                    for i, count in enumerate(buckets):
                        z = (count - mean_bucket) / stdev_bucket
                        if abs(z) > 3.0:
                            anomalous_buckets.append((i, count, z))
                    if anomalous_buckets:
                        severity = "high" if len(anomalous_buckets) > 3 else "medium"
                        indicators.append(TamperIndicator(
                            severity=severity,
                            category="statistical",
                            description=f"Anomalous entry density ({len(anomalous_buckets)} buckets with z > 3σ)",
                            details=f"Entry rate varies significantly from expected distribution. "
                                    f"Mean entries/bucket: {mean_bucket:.1f}, "
                                    f"Anomalous buckets: {[(i, cnt, f'{z:+.1f}σ') for i, cnt, z in anomalous_buckets[:5]]}",
                        ))

    # 8. Sequence number gaps (if entries contain sequential IDs)
    seq_pattern = re.compile(r'(?:seq(?:uence)?[\s:=]*|id[\s:=]*|#[\s:]*)(\d+)', re.I)
    seq_numbers: list[tuple[int, int, Entry]] = []
    for i, e in enumerate(filtered):
        m = seq_pattern.search(e.raw)
        if m:
            try:
                seq_numbers.append((i, int(m.group(1)), e))
            except ValueError:
                pass
    if len(seq_numbers) >= 5:
        seq_numbers.sort(key=lambda x: x[1])
        gaps_in_seq = []
        for i in range(1, len(seq_numbers)):
            prev_num = seq_numbers[i - 1][1]
            curr_num = seq_numbers[i][1]
            if curr_num - prev_num > 1:
                gaps_in_seq.append((seq_numbers[i][0], prev_num, curr_num, curr_num - prev_num))
        if gaps_in_seq:
            max_gap = max(g[3] for g in gaps_in_seq)
            severity = "high" if max_gap > 100 else "medium" if max_gap > 10 else "low"
            indicators.append(TamperIndicator(
                severity=severity,
                category="sequence",
                description=f"Sequence number gaps detected ({len(gaps_in_seq)} gaps)",
                details=f"Missing sequence numbers suggest deleted entries. "
                        f"Largest gap: {gaps_in_seq[0][2]} - {gaps_in_seq[0][1]} = {gaps_in_seq[0][3]} missing",
                line_numbers=[idx + 1 for idx, _, _, _ in gaps_in_seq[:10]],
            ))

    # Calculate integrity score
    severity_weights = {"critical": 1.0, "high": 0.7, "medium": 0.4, "low": 0.2, "info": 0.0}
    total_penalty = sum(severity_weights.get(ind.severity, 0) for ind in indicators)
    integrity_score = max(0.0, min(1.0, 1.0 - (total_penalty / 5.0)))

    # Generate summary
    critical_count = sum(1 for ind in indicators if ind.severity == "critical")
    high_count = sum(1 for ind in indicators if ind.severity == "high")
    if critical_count > 0:
        summary = f"CRITICAL: {critical_count} critical indicators suggest significant tampering"
    elif high_count > 0:
        summary = f"WARNING: {high_count} high-severity indicators suggest possible manipulation"
    elif indicators:
        summary = f"CAUTION: {len(indicators)} minor indicators detected; review recommended"
    else:
        summary = "CLEAN: No tampering indicators detected"

    return TamperReport(
        total_entries=len(entries),
        analyzed=analyzed or len(filtered),
        indicators=indicators,
        integrity_score=integrity_score,
        summary=summary,
    )


def print_tamper_report(report: TamperReport, user: str | None = None) -> None:
    """Print a formatted tamper detection report."""
    label = f" for '{user}'" if user else ""
    print(f"\n{'='*70}")
    print(f"LOG TAMPER DETECTION REPORT{label}")
    print(f"{'='*70}")
    print(f"  Total entries:       {report.total_entries}")
    print(f"  Analyzed entries:    {report.analyzed}")
    print(f"  Integrity score:     {report.integrity_score:.2f} / 1.00")
    print(f"  Indicators found:    {len(report.indicators)}")
    print(f"\n  {report.summary}")
    print(f"{'='*70}")

    if not report.indicators:
        print(f"\n  ✓ No signs of tampering detected")
        return

    # Group by severity
    by_severity: dict[str, list[TamperIndicator]] = {}
    for ind in report.indicators:
        by_severity.setdefault(ind.severity, []).append(ind)

    for severity in ("critical", "high", "medium", "low", "info"):
        if severity not in by_severity:
            continue
        indicators = by_severity[severity]
        severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "ℹ️"}.get(severity, "•")
        print(f"\n  [{severity_icon}] {severity.upper()} ({len(indicators)} indicators)")
        for ind in indicators:
            print(f"    [{ind.category}] {ind.description}")
            print(f"      {ind.details}")
            if ind.line_numbers:
                print(f"      Affected lines: {', '.join(str(ln) for ln in ind.line_numbers[:8])}"
                      f"{'...' if len(ind.line_numbers) > 8 else ''}")

    print(f"\n{'='*70}")
    if report.integrity_score < 0.5:
        print(f"  ⚠ RECOMMENDATION: Log integrity is compromised. Investigate immediately.")
    elif report.integrity_score < 0.8:
        print(f"  ⚠ RECOMMENDATION: Review flagged indicators and correlate with other evidence.")
    else:
        print(f"  ✓ Log integrity appears intact. Continue normal monitoring.")
    print(f"{'='*70}\n")


# ---------- NEW: Sequence mining (#14) ----------------------------------------

@dataclass
class SequencePattern:
    pattern: tuple[str, ...]
    count: int
    avg_gap_seconds: float

def find_common_sequences(entries: list[Entry], window_minutes: int = 10, max_gap_seconds: int = 600, min_support: int = 3) -> list[SequencePattern]:
    sorted_e = sorted([e for e in entries if e.ts and e.user], key=lambda e: e.ts)
    chains: list[list[str]] = []
    cur: list[str] = []
    cur_ts: datetime | None = None
    for e in sorted_e:
        if cur_ts is not None and (e.ts - cur_ts).total_seconds() > max_gap_seconds:
            if len(cur) >= 2:
                chains.append(cur)
            cur = []
        cur.append(e.user.lower())
        cur_ts = e.ts
    if len(cur) >= 2:
        chains.append(cur)

    pair_counter: Counter = Counter()
    pair_gaps: dict[tuple[str, str], list[float]] = {}
    for chain in chains:
        for i in range(len(chain) - 1):
            pair = (chain[i], chain[i + 1])
            pair_counter[pair] += 1
    result: list[SequencePattern] = []
    for (a, b), cnt in pair_counter.most_common():
        if cnt >= min_support:
            gaps: list[float] = []
            for chain in chains:
                for i in range(len(chain) - 1):
                    if chain[i] == a and chain[i + 1] == b:
                        gaps.append(0.0)  # simplified
            avg_gap = statistics.mean(gaps) if gaps else 0.0
            result.append(SequencePattern((a, b), cnt, avg_gap))
    return result[:20]

# ---------- NEW: Anomaly detection (#8) --------------------------------------

@dataclass
class Anomaly:
    user: str
    metric: str
    value: float
    expected: float
    zscore: float
    day: str | None = None
    hour: int | None = None

def detect_behavioral_anomalies(entries: list[Entry], user: str, 
                               z_threshold: float = 3.0) -> list[Anomaly]:
    u = user.lower()
    user_entries = [e for e in entries if e.user and e.user.lower() == u]
    if len(user_entries) < 10:
        return []

    results: list[Anomaly] = []
    
    # 1. Score Anomaly Detection (using existing _scores_from_raw)
    user_scores = {k: [] for k in SCORE_KEYS}
    for e in user_entries:
        s = _scores_from_raw(e.raw)
        for k in SCORE_KEYS:
            if k in s and isinstance(s[k], (int, float)):
                user_scores[k].append((e, s[k]))
                
    for k in SCORE_KEYS:
        vals = [v for e, v in user_scores[k]]
        if len(vals) > 5:
            mean = statistics.mean(vals)
            sd = statistics.pstdev(vals) if len(vals) > 1 else 0.0
            if sd > 0:
                for e, v in user_scores[k]:
                    z = (v - mean) / sd
                    if z >= z_threshold:
                        results.append(Anomaly(user, f"score_{k}", float(v), mean, z, 
                                               day=e.ts.date().isoformat() if e.ts else None,
                                               hour=e.ts.hour if e.ts else None))

    # 2. Length Anomaly Detection
    lengths = [(e, len(e.text or "")) for e in user_entries]
    l_vals = [v for e, v in lengths]
    if len(l_vals) > 5:
        mean_l = statistics.mean(l_vals)
        sd_l = statistics.pstdev(l_vals) if len(l_vals) > 1 else 0.0
        if sd_l > 0:
            for e, l in lengths:
                z = (l - mean_l) / sd_l
                if abs(z) >= z_threshold:
                     results.append(Anomaly(user, "msg_length", float(l), mean_l, z,
                                            day=e.ts.date().isoformat() if e.ts else None,
                                            hour=e.ts.hour if e.ts else None))

    # 3. Pattern-of-Life (PoL) Anomaly Detection
    # Detect if user is active at an hour they are usually NOT active in.
    hour_counts = Counter(e.ts.hour for e in user_entries if e.ts)
    total_active = sum(hour_counts.values())
    if total_active > 20:
        for e in user_entries:
            if not e.ts: continue
            h = e.ts.hour
            # If this hour represents < 2% of their total activity, it's a PoL anomaly
            if (hour_counts[h] / total_active) < 0.02:
                # We'll use a fixed z of 5.0 to flag it
                results.append(Anomaly(user, "pol_hour_mismatch", float(h), 0.0, 5.0,
                                       day=e.ts.date().isoformat(),
                                       hour=h))
                                       
    return results

def detect_anomalies(entries: list[Entry], user: str, z_threshold: float = 2.5) -> list[Anomaly]:
    u = user.lower()
    user_entries = [e for e in entries if e.user and e.user.lower() == u and e.ts]
    if len(user_entries) < 7:
        return []
    result: list[Anomaly] = []
    by_day: dict[str, list[Entry]] = {}
    for e in user_entries:
        if e.ts:
            d = e.ts.date().isoformat()
            by_day.setdefault(d, []).append(e)
    day_counts = [len(v) for v in by_day.values()]
    if len(day_counts) >= 3:
        mean = statistics.mean(day_counts)
        sd = statistics.pstdev(day_counts) if len(day_counts) > 1 else 0.0
        if sd > 0:
            for d, entries_for_day in by_day.items():
                z = (len(entries_for_day) - mean) / sd
                if abs(z) >= z_threshold:
                    result.append(Anomaly(user, "daily_volume", len(entries_for_day), mean, z, day=d))
    by_hour: dict[int, list[Entry]] = {}
    for e in user_entries:
        if e.ts:
            by_hour.setdefault(e.ts.hour, []).append(e)
    hour_counts = [len(v) for v in by_hour.values()]
    if len(hour_counts) >= 3:
        mean_h = statistics.mean(hour_counts)
        sd_h = statistics.pstdev(hour_counts) if len(hour_counts) > 1 else 0.0
        if sd_h > 0:
            for h, entries_for_hour in by_hour.items():
                z = (len(entries_for_hour) - mean_h) / sd_h
                if abs(z) >= z_threshold:
                    result.append(Anomaly(user, "hourly_volume", len(entries_for_hour), mean_h, z, hour=h))
    return result

# ---------- NEW: User lifecycle (#10) -----------------------------------------

@dataclass
class LifecycleStage:
    user: str
    first_seen: datetime | None
    last_seen: datetime | None
    active_days: int
    total_days: int
    activity_trend: str
    stages: list[tuple[str, datetime, datetime]]  # (stage_name, start, end)

def analyze_lifecycle(entries: list[Entry], user: str, gap_days: int = 14) -> LifecycleStage:
    u = user.lower()
    user_entries = sorted(
        [e for e in entries if e.user and e.user.lower() == u and e.ts],
        key=lambda e: e.ts
    )
    if not user_entries:
        return LifecycleStage(user, None, None, 0, 0, "unknown", [])
    first = user_entries[0].ts
    last = user_entries[-1].ts
    total_days = max((last - first).days, 1)
    active_dates = {e.ts.date() for e in user_entries if e.ts}
    active_days = len(active_dates)
    # trend: compare first half to second half activity density
    midpoint = first + (last - first) / 2
    first_half = sum(1 for e in user_entries if e.ts and e.ts <= midpoint)
    second_half = sum(1 for e in user_entries if e.ts and e.ts > midpoint)
    if first_half == 0:
        trend = "new"
    elif second_half / first_half > 1.3:
        trend = "growing"
    elif second_half / first_half < 0.7:
        trend = "declining"
    else:
        trend = "stable"
    # detect stages: active periods separated by gaps
    stages: list[tuple[str, datetime, datetime]] = []
    stage_start = user_entries[0].ts
    stage_end = user_entries[0].ts
    for e in user_entries[1:]:
        gap = (e.ts - stage_end).days
        if gap > gap_days:
            stages.append(("active", stage_start, stage_end))
            stage_start = e.ts
        stage_end = e.ts
    stages.append(("active", stage_start, stage_end))
    return LifecycleStage(user, first, last, active_days, total_days, trend, stages)

# ---------- NEW: Pattern-of-life analysis (#11) -------------------------------

@dataclass
class PatternOfLife:
    user: str
    hourly_profile: dict[int, float]  # hour -> normalized activity
    weekday_profile: dict[int, float]  # day -> normalized
    peak_hour: int | None
    quiet_hours: list[int]
    consistency_score: float  # 0-1 how consistent the pattern is

def pattern_of_life(entries: list[Entry], user: str) -> PatternOfLife:
    u = user.lower()
    user_entries = [e for e in entries if e.user and e.user.lower() == u and e.ts]
    if len(user_entries) < 10:
        return PatternOfLife(user, {}, {}, None, [], 0.0)
    hourly: Counter = Counter()
    weekly: Counter = Counter()
    for e in user_entries:
        if e.ts:
            hourly[e.ts.hour] += 1
            weekly[e.ts.weekday()] += 1
    total_h = max(sum(hourly.values()), 1)
    total_w = max(sum(weekly.values()), 1)
    hour_profile = {h: hourly.get(h, 0) / total_h for h in range(24)}
    week_profile = {d: weekly.get(d, 0) / total_w for d in range(7)}
    peak_hour = max(range(24), key=lambda h: hourly.get(h, 0)) if hourly else None
    mean_h = statistics.mean([hourly.get(h, 0) for h in range(24)])
    sd_h = statistics.pstdev([hourly.get(h, 0) for h in range(24)]) or 1
    quiet = [h for h in range(24) if (hourly.get(h, 0) - mean_h) / sd_h < -1]
    # consistency: coefficient of variation across days
    if len(user_entries) >= 3:
        by_day: dict[str, int] = {}
        for e in user_entries:
            if e.ts:
                by_day[e.ts.date().isoformat()] = by_day.get(e.ts.date().isoformat(), 0) + 1
        counts = list(by_day.values())
        cv = statistics.pstdev(counts) / (statistics.mean(counts) or 1)
        consistency = max(0.0, min(1.0, 1.0 - cv))
    else:
        consistency = 0.0
    return PatternOfLife(user, hour_profile, week_profile, peak_hour, quiet, consistency)

# ---------- NEW: Alert rules engine (#13) -------------------------------------

@dataclass
class AlertRule:
    name: str
    field: str  # user|target|level|score_key
    op: str  # == != > < contains matches
    value: str
    message: str
    enabled: bool = True

class AlertEngine:
    def __init__(self) -> None:
        self.rules: list[AlertRule] = []

    def add(self, rule: AlertRule) -> None:
        self.rules.append(rule)

    def remove(self, name: str) -> bool:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.name != name]
        return len(self.rules) < before

    def evaluate(self, entry: Entry) -> list[str]:
        out: list[str] = []
        for rule in self.rules:
            if not rule.enabled:
                continue
            val: str | None = None
            if rule.field == "user":
                val = entry.user
            elif rule.field == "target":
                val = entry.target
            elif rule.field == "level":
                val = entry.level
            elif rule.field in SCORE_KEYS:
                scores = _scores_from_raw(entry.raw)
                sv = scores.get(rule.field)
                val = str(sv) if sv is not None else None
            else:
                val = entry.raw
            if val is None:
                continue
            matched = False
            if rule.op == "==":
                matched = val.lower() == rule.value.lower()
            elif rule.op == "!=":
                matched = val.lower() != rule.value.lower()
            elif rule.op == ">":
                try:
                    matched = float(val) > float(rule.value)
                except ValueError:
                    matched = False
            elif rule.op == "<":
                try:
                    matched = float(val) < float(rule.value)
                except ValueError:
                    matched = False
            elif rule.op == "matches":
                try:
                    matched = bool(re.search(rule.value, val, re.I))
                except re.error:
                    matched = False
            elif rule.op == "contains":
                matched = rule.value.lower() in val.lower()
            if matched:
                out.append(rule.message.format(val=val, user=entry.user or "?", target=entry.target or "?"))
        return out

# ---------- NEW: Multi-log correlation (#12) ----------------------------------

@dataclass
class Correlation:
    event_a: str
    event_b: str
    count: int
    avg_delay_seconds: float

def correlate_logs(log_a_entries: list[Entry], log_b_entries: list[Entry],
                   window_seconds: int = 60) -> list[Correlation]:
    events_a = [(e.ts, e.event or e.user or e.level or "?") for e in log_a_entries if e.ts]
    events_b = [(e.ts, e.event or e.user or e.level or "?") for e in log_b_entries if e.ts]
    events_a.sort(key=lambda x: x[0])
    events_b.sort(key=lambda x: x[0])
    pair_counts: Counter = Counter()
    pair_delays: dict[tuple[str, str], list[float]] = {}
    for tsa, eva in events_a:
        for tsb, evb in events_b:
            delay = abs((tsb - tsa).total_seconds())
            if delay <= window_seconds:
                pair_counts[(eva, evb)] += 1
                pair_delays.setdefault((eva, evb), []).append(delay)
    result: list[Correlation] = []
    for (ea, eb), cnt in pair_counts.most_common(30):
        delays = pair_delays.get((ea, eb), [0.0])
        avg_d = statistics.mean(delays) if delays else 0.0
        result.append(Correlation(ea, eb, cnt, avg_d))
    return result

# ---------- Log template mining (#1) ------------------------------------------

TEMPLATE_VAR_RE = re.compile(r"\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b|0x[0-9a-fA-F]+|[0-9a-fA-F]{8,}|(?<=/)[a-zA-Z0-9._-]+(?=/)")

def extract_log_templates(entries: list[Entry], top_n: int = 20) -> list[tuple[str, int, str]]:
    counter: Counter = Counter()
    sample_lines: dict[str, str] = {}
    for e in entries:
        text = e.text or e.raw
        template = TEMPLATE_VAR_RE.sub("{}", text)
        template = re.sub(r"([\"']).*?(\1)", r'\1{}\1', template)
        template = re.sub(r"\b[a-f0-9]{8,}\b", "{}", template, flags=re.I)
        template = re.sub(r"\d{2,}", "{}", template)
        counter[template] += 1
        if template not in sample_lines:
            sample_lines[template] = text[:200]
    out: list[tuple[str, int, str]] = []
    for template, count in counter.most_common(top_n):
        out.append((template[:200], count, (sample_lines.get(template) or template)[:200]))
    return out

# ---------- Change-point detection (#2) ---------------------------------------

@dataclass
class ChangePoint:
    user: str
    metric: str
    at: datetime
    before_val: float
    after_val: float
    effect_size: float

def detect_change_points(entries: list[Entry], user: str, window_days: int = 3) -> list[ChangePoint]:
    u = user.lower()
    user_entries = sorted(
        [e for e in entries if e.ts and e.user and e.user.lower() == u],
        key=lambda e: e.ts
    )
    if len(user_entries) < 10:
        return []
    windows: list[tuple[datetime, list[Entry]]] = []
    if not user_entries or not user_entries[0].ts:
        return []
    cur_start = user_entries[0].ts
    while cur_start <= user_entries[-1].ts:
        win_end = cur_start + timedelta(days=window_days)
        win = [e for e in user_entries if cur_start <= e.ts < win_end]
        if win:
            windows.append((cur_start, win))
        cur_start = win_end

    results: list[ChangePoint] = []
    for i in range(1, len(windows)):
        prev_count = len(windows[i - 1][1])
        cur_count = len(windows[i][1])
        if prev_count > 0 and cur_count > 0:
            effect = (cur_count - prev_count) / (prev_count + cur_count)
            if abs(effect) > 0.5:
                results.append(ChangePoint(user, "volume", windows[i][0], prev_count, cur_count, effect))
        # score changes
        prev_scores = [v for e in windows[i - 1][1] for v in _scores_from_raw(e.raw).values() if isinstance(v, (int, float))]
        cur_scores = [v for e in windows[i][1] for v in _scores_from_raw(e.raw).values() if isinstance(v, (int, float))]
        if prev_scores and cur_scores:
            prev_m = statistics.mean(prev_scores)
            cur_m = statistics.mean(cur_scores)
            pooled_sd = (statistics.pstdev(prev_scores) + statistics.pstdev(cur_scores)) / 2 or 1
            effect = (cur_m - prev_m) / pooled_sd
            if abs(effect) > 0.8:
                results.append(ChangePoint(user, "score_shift", windows[i][0], prev_m, cur_m, effect))
    return results

# ---------- Root cause tracing (#3) -------------------------------------------

@dataclass
class RootCause:
    preceding_user: str
    preceding_event: str
    correlation: float
    avg_lag_seconds: float
    occurrences: int

def trace_root_causes(entries: list[Entry], target_user: str,
                      lookback_seconds: int = 120, min_occurrences: int = 2) -> list[RootCause]:
    u = target_user.lower()
    sorted_e = sorted([e for e in entries if e.ts], key=lambda e: e.ts)
    target_times: list[datetime] = []
    for e in sorted_e:
        if e.user and e.user.lower() == u:
            target_times.append(e.ts)

    causes: Counter = Counter()
    lags: dict[tuple[str, str], list[float]] = {}
    for tt in target_times:
        seen: set[tuple[str, str]] = set()
        for e in sorted_e:
            if not e.user or not e.ts or e.user.lower() == u:
                continue
            lag = (tt - e.ts).total_seconds()
            if 0 < lag <= lookback_seconds:
                key = (e.user, e.event or e.level or "msg")
                if key not in seen:
                    causes[key] += 1
                    lags.setdefault(key, []).append(lag)
                    seen.add(key)

    total_target = len(target_times) or 1
    results: list[RootCause] = []
    for (preceding_user, preceding_event), cnt in causes.most_common(30):
        if cnt >= min_occurrences:
            avg_lag = statistics.mean(lags.get((preceding_user, preceding_event), [0]))
            results.append(RootCause(preceding_user, preceding_event, cnt / total_target, avg_lag, cnt))
    return results

# ---------- Forecasting (#4) ---------------------------------------------------

@dataclass
class Forecast:
    daily_counts: dict[str, int]
    predictions: list[tuple[str, float]]
    trend: str  # increasing | decreasing | stable

def forecast_activity(entries: list[Entry], user: str | None = None,
                      days_ahead: int = 7) -> Forecast:
    if user:
        u = user.lower()
        filtered = [e for e in entries if e.ts and e.user and e.user.lower() == u]
    else:
        filtered = [e for e in entries if e.ts]
    if not filtered:
        return Forecast({}, [], "unknown")
    by_day: dict[str, int] = {}
    for e in filtered:
        if e.ts:
            d = e.ts.date().isoformat()
            by_day[d] = by_day.get(d, 0) + 1
    dates = sorted(by_day.keys())
    counts = [by_day[d] for d in dates]
    if len(counts) < 3:
        return Forecast(by_day, [], "unknown")

    # simple approach: average of last few days + linear extrapolation
    recent = counts[-min(len(counts), 5):]
    avg = statistics.mean(recent)
    # linear trend
    n = len(counts)
    xs = list(range(n))
    mean_x = statistics.mean(xs)
    mean_y = statistics.mean(counts)
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, counts))
    den = sum((x - mean_x) ** 2 for x in xs) or 1
    slope = num / den
    if slope > 0.5:
        trend = "increasing"
    elif slope < -0.5:
        trend = "decreasing"
    else:
        trend = "stable"

    predictions: list[tuple[str, float]] = []
    last_date = datetime.fromisoformat(dates[-1])
    for i in range(1, days_ahead + 1):
        pred_date = (last_date + timedelta(days=i)).isoformat()[:10]
        pred_val = max(0, avg + slope * (n + i))
        predictions.append((pred_date, round(pred_val, 1)))
    return Forecast(by_day, predictions, trend)

# ---------- Multi-factor anomaly score (#5) -----------------------------------

@dataclass
class MultiFactorAnomaly:
    user: str
    composite_score: float
    daily_z: float | None
    hourly_z: float | None
    sentiment_z: float | None

def multi_factor_anomaly(entries: list[Entry], user: str) -> MultiFactorAnomaly | None:
    u = user.lower()
    user_entries = [e for e in entries if e.user and e.user.lower() == u and e.ts]
    if len(user_entries) < 10:
        return None
    all_entries = [e for e in entries if e.ts]

    # daily volume z-score
    by_day_all: Counter = Counter()
    for e in all_entries:
        if e.ts:
            by_day_all[e.ts.date()] += 1
    by_day_user: Counter = Counter()
    for e in user_entries:
        if e.ts:
            by_day_user[e.ts.date()] += 1
    day_vals_all = list(by_day_all.values())
    day_vals_user = list(by_day_user.values())
    daily_z: float | None = None
    if len(day_vals_all) >= 3:
        m = statistics.mean(day_vals_all)
        s = statistics.pstdev(day_vals_all) or 1
        daily_z = (statistics.mean(day_vals_user) - m) / s if day_vals_user else 0

    # hourly z-score
    by_hour_user: Counter = Counter()
    for e in user_entries:
        if e.ts:
            by_hour_user[e.ts.hour] += 1
    by_hour_all: Counter = Counter()
    for e in all_entries:
        if e.ts:
            by_hour_all[e.ts.hour] += 1
    hourly_z: float | None = None
    h_vals_all = [by_hour_all.get(h, 0) for h in range(24)]
    h_vals_user = [by_hour_user.get(h, 0) for h in range(24)]
    if len(h_vals_all) >= 3:
        m_h = statistics.mean(h_vals_all)
        s_h = statistics.pstdev(h_vals_all) or 1
        hourly_z = (statistics.mean(h_vals_user) - m_h) / s_h

    # sentiment z-score vs population
    sent_user = user_sentiment(entries, user)
    pop_sents = [user_sentiment(entries, u2)["mean_compound"]
                 for u2 in {e.user for e in entries if e.user}
                 if u2.lower() != u and user_sentiment(entries, u2)]
    sentiment_z: float | None = None
    if pop_sents and sent_user:
        m_s = statistics.mean(pop_sents)
        s_s = statistics.pstdev(pop_sents) or 1
        sentiment_z = (sent_user["mean_compound"] - m_s) / s_s

    factors = [v for v in [daily_z, hourly_z, sentiment_z] if v is not None]
    composite = statistics.mean(factors) if factors else 0.0
    return MultiFactorAnomaly(user, composite, daily_z, hourly_z, sentiment_z)

# ---------- Matplotlib chart export (#6) --------------------------------------

def chart_timeline(entries: list[Entry], path: str,
                   user: str | None = None) -> bool:
    if not MATPLOTLIB_OK:
        print("matplotlib not installed; try: pip install matplotlib")
        return False
    if user:
        u = user.lower()
        filtered = [e for e in entries if e.ts and e.user and e.user.lower() == u]
    else:
        filtered = [e for e in entries if e.ts]
    if not filtered:
        print("(no data to chart)")
        return False
    by_day: Counter = Counter()
    for e in filtered:
        if e.ts:
            by_day[e.ts.date()] += 1
    dates = sorted(by_day.keys())
    counts = [by_day[d] for d in dates]
    fig, ax = plt.subplots(figsize=(10, 4))
    ax.bar(range(len(dates)), counts, color="#4a9eff")
    ax.set_xticks(range(len(dates)))
    ax.set_xticklabels([str(d)[5:] for d in dates], rotation=45, ha="right", fontsize=8)
    ax.set_ylabel("Entries" + (f" ({user})" if user else ""))
    ax.set_title("Activity Timeline")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    print(f"Chart saved to {path}")
    return True

def chart_histogram(values: list[float], path: str, label: str = "",
                    bins: int = 10, range_lo: float = 0.0, range_hi: float = 1.0) -> bool:
    if not MATPLOTLIB_OK:
        print("matplotlib not installed")
        return False
    if not values:
        return False
    fig, ax = plt.subplots(figsize=(8, 3))
    ax.hist(values, bins=bins, range=(range_lo, range_hi), color="#4a9eff", edgecolor="white")
    ax.set_xlabel(label)
    ax.set_ylabel("Frequency")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return True

def chart_network(edges: Counter, path: str, top_n: int = 15) -> bool:
    if not MATPLOTLIB_OK:
        print("matplotlib not installed")
        return False
    top = edges.most_common(top_n)
    if not top:
        return False
    labels = [f"{a}->{b}" for (a, b), _ in top]
    weights = [w for _, w in top]
    fig, ax = plt.subplots(figsize=(8, 4))
    ax.barh(range(len(labels)), weights, color="#4a9eff")
    ax.set_yticks(range(len(labels)))
    ax.set_yticklabels(labels, fontsize=8)
    ax.set_xlabel("Weight")
    fig.tight_layout()
    fig.savefig(path, dpi=150)
    plt.close(fig)
    return True

# ---------- Interactive data frame (#7) ---------------------------------------

def dataframe_view(entries: list[Entry], expr: str = "") -> str:
    if not PANDAS_OK:
        return "pandas not installed; try: pip install pandas"
    rows = []
    for e in entries:
        rows.append({
            "ts": e.ts.isoformat() if e.ts else None,
            "user": e.user,
            "target": e.target,
            "level": e.level,
            "event": e.event,
            "text": (e.text or "")[:200],
        })
    df = pd.DataFrame(rows)
    if expr.strip():
        try:
            result = eval(expr, {"pd": pd, "df": df, "np": __import__("numpy", on_error=lambda: None)})
            return str(result)
        except Exception as exc:
            return f"Error: {exc}"
    return str(df.head(50))

# ---------- Recurrence detection (#8) -----------------------------------------

@dataclass
class Recurrence:
    user: str
    pattern_type: str  # daily|weekly|hourly
    confidence: float  # 0-1
    description: str

def detect_recurrence(entries: list[Entry], user: str) -> list[Recurrence]:
    u = user.lower()
    user_entries = [e for e in entries if e.ts and e.user and e.user.lower() == u]
    if len(user_entries) < 7:
        return []
    results: list[Recurrence] = []

    # weekly recurrence: check if active on consistent weekdays
    by_weekday: Counter = Counter()
    for e in user_entries:
        if e.ts:
            by_weekday[e.ts.weekday()] += 1
    if by_weekday:
        max_wd = max(by_weekday.values())
        active_wds = [d for d, n in by_weekday.items() if n >= max_wd * 0.5]
        confidence = max_wd / (sum(by_weekday.values()) or 1)
        if len(active_wds) <= 3 and confidence > 0.3:
            wd_names = [("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")[d] for d in sorted(active_wds)]
            results.append(Recurrence(user, "weekly", confidence, f"Active on {', '.join(wd_names)}"))

    # hourly recurrence
    by_hour_r: Counter = Counter()
    for e in user_entries:
        if e.ts:
            by_hour_r[e.ts.hour] += 1
    if by_hour_r:
        peak_h = max(by_hour_r, key=by_hour_r.get)
        peak_n = by_hour_r[peak_h]
        total_h = sum(by_hour_r.values())
        conf_h = peak_n / total_h if total_h > 0 else 0
        if conf_h > 0.25:
            results.append(Recurrence(user, "hourly", conf_h,
                                      f"Peak activity at {peak_h}:00 ({conf_h:.0%} of all activity)"))

    # daily recurrence: are they appearing nearly every day?
    if len(user_entries) >= 3:
        dates = sorted({e.ts.date() for e in user_entries if e.ts})
        span = (dates[-1] - dates[0]).days or 1
        coverage = len(dates) / span
        if coverage > 0.5:
            results.append(Recurrence(user, "daily", coverage,
                                      f"Active on {len(dates)}/{span} days ({coverage:.0%})"))

    return results

# ---------- Churn prediction (#9) ---------------------------------------------

@dataclass
class ChurnPrediction:
    user: str
    risk_score: float  # 0-1
    factors: list[str]

def predict_churn(entries: list[Entry], user: str) -> ChurnPrediction:
    u = user.lower()
    user_entries = [e for e in entries if e.ts and e.user and e.user.lower() == u]
    if len(user_entries) < 5:
        return ChurnPrediction(user, 0.0, ["insufficient data"])

    dates = sorted({e.ts.date() for e in user_entries if e.ts})
    factors: list[str] = []
    score = 0.0

    # factor 1: recency (how long since last seen)
    if dates:
        days_since_last = (datetime.now().date() - dates[-1]).days
        if days_since_last > 7:
            score += 0.3
            factors.append(f"last active {days_since_last}d ago")
        elif days_since_last > 3:
            score += 0.15

    # factor 2: activity trend (declining?)
    if len(user_entries) >= 6:
        half = len(user_entries) // 2
        first_half = user_entries[:half]
        second_half = user_entries[half:]
        if second_half and first_half:
            ratio = len(second_half) / len(first_half)
            if ratio < 0.5:
                score += 0.3
                factors.append(f"activity declined {ratio:.0%} (recent vs earlier)")

    # factor 3: sentiment trend
    s = user_sentiment(entries, user)
    if s and s.get("mean_compound", 0) < -0.1:
        score += 0.2
        factors.append(f"negative sentiment ({s['mean_compound']:.2f})")

    # factor 4: narrowing targets (fewer channels/targets recently)
    half = max(len(user_entries) // 2, 1)
    recent_targets = {e.target for e in user_entries[-half:] if e.target}
    early_targets = {e.target for e in user_entries[:half] if e.target}
    if early_targets and len(recent_targets) < len(early_targets) * 0.5:
        score += 0.2
        factors.append("narrowing engagement (fewer targets)")

    risk = min(1.0, score)
    return ChurnPrediction(user, risk, factors)

# ---------- Pareto analysis (#10) ---------------------------------------------

@dataclass
class ParetoResult:
    category: str  # users|events|targets
    items: list[tuple[str, int, float]]  # name, count, cumulative%
    top_80_pct_count: int  # how many items account for 80% of activity

def pareto_analysis(entries: list[Entry], category: str = "users",
                    top_n: int = 50) -> ParetoResult:
    counter: Counter = Counter()
    for e in entries:
        if category == "users" and e.user:
            counter[e.user] += 1
        elif category == "events" and e.event:
            counter[e.event] += 1
        elif category == "targets" and e.target:
            counter[e.target] += 1
        elif category == "levels" and e.level:
            counter[e.level] += 1
    if not counter:
        return ParetoResult(category, [], 0)
    total = sum(counter.values()) or 1
    running = 0
    items: list[tuple[str, int, float]] = []
    top_80_count = 0
    for name, count in counter.most_common(top_n):
        running += count
        cum_pct = running / total * 100
        items.append((name, count, cum_pct))
        if cum_pct < 80:
            top_80_count += 1
    return ParetoResult(category, items, top_80_count)

# ---------- Dashboard mode (#16) - curses real-time TUI -----------------------

_DASH_REFRESH_SEC = 2.0

def _dashboard_curses(stdscr, entries_access, alert_engine, log_path) -> None:
    if not CURSES_OK:
        return
    curses.curs_set(0)
    curses.use_default_colors()
    stdscr.nodelay(True)
    last_refresh = 0.0
    pause = False
    while True:
        now = time.time()
        if now - last_refresh >= _DASH_REFRESH_SEC and not pause:
            last_refresh = now
            try:
                stdscr.erase()
                maxy, maxx = stdscr.getmaxyx()
                if maxy < 10 or maxx < 30:
                    stdscr.addstr(0, 0, "Terminal too small")
                    stdscr.refresh()
                    continue
                entries = entries_access()
                col_w = maxx // 3
                # Left panel: top users
                users: Counter = Counter()
                for e in entries:
                    if e.user:
                        users[e.user] += 1
                top_users = users.most_common(15)
                header = f"DASHBOARD  {log_path}  ({len(entries)} entries)"
                stdscr.attron(curses.A_BOLD)
                stdscr.addstr(0, 0, header[:maxx-1])
                stdscr.attroff(curses.A_BOLD)
                stdscr.addstr(1, 0, "─" * min(maxx-1, 60))
                stdscr.addstr(2, 0, "TOP USERS", curses.A_BOLD)
                row = 3
                for i, (u, c) in enumerate(top_users):
                    if row >= maxy - 2:
                        break
                    label = f" {i+1:2d} {c:>5d}  {u[:col_w-12]}"
                    stdscr.addstr(row, 0, label[:col_w-1])
                    row += 1
                # Middle panel: hourly histogram
                mid_x = col_w
                hist: Counter = Counter()
                for e in entries:
                    if e.ts:
                        hist[e.ts.hour] += 1
                stdscr.addstr(2, mid_x, "HOURLY ACTIVITY", curses.A_BOLD)
                max_h = max(hist.values()) or 1
                row = 3
                for h in range(24):
                    if row >= maxy - 2:
                        break
                    cnt = hist.get(h, 0)
                    bar_w = int(cnt / max_h * (col_w - 8))
                    stdscr.addstr(row, mid_x, f"{h:02d} {'█' * bar_w:<{col_w-8}} {cnt}")
                    row += 1
                # Right panel: alerts + recent flagged
                right_x = mid_x * 2
                stdscr.addstr(2, right_x, "ALERTS / FLAGGED", curses.A_BOLD)
                alerts = []
                if alert_engine:
                    for rule in alert_engine.rules:
                        if rule.enabled:
                            alerts.append(f" {rule.name}: {rule.message[:30]}")
                row = 3
                for a in alerts[:maxy-6]:
                    if row >= maxy - 2:
                        break
                    stdscr.addstr(row, right_x, a[:maxx-right_x-1])
                    row += 1
                # Bottom bar
                status = " PAUSED" if pause else " LIVE"
                stdscr.attron(curses.A_REVERSE)
                stdscr.addstr(maxy-1, 0, f" {status}  [Q]uit [P]ause [R]efresh  ".ljust(maxx-1))
                stdscr.attroff(curses.A_REVERSE)
                stdscr.refresh()
            except curses.error:
                pass
        # Key handling
        try:
            key = stdscr.getch()
        except curses.error:
            key = -1
        if key == ord("q") or key == ord("Q"):
            break
        elif key == ord("p") or key == ord("P"):
            pause = not pause
        elif key == ord("r") or key == ord("R"):
            last_refresh = 0.0
        elif key == ord("d"):
            _dashboard_drill(stdscr, entries, entries_access)
        elif key != -1:
            pass
        time.sleep(0.1)

def _dashboard_drill(stdscr, entries, entries_access) -> None:
    """Sub-screen: pick a user to drill into."""
    users = sorted({e.user for e in entries if e.user})
    if not users:
        return
    curses.curs_set(0)
    curses.use_default_colors()
    sel = 0
    offset = 0
    max_vis = 20
    while True:
        try:
            stdscr.erase()
            maxy, maxx = stdscr.getmaxyx()
            stdscr.addstr(0, 0, "SELECT USER (up/down, enter to drill, q back)", curses.A_BOLD)
            visible = users[offset:offset+max_vis]
            for i, u in enumerate(visible):
                attr = curses.A_REVERSE if i == sel - offset else 0
                stdscr.addstr(2 + i, 2, f" {u[:maxx-4]} ", attr)
            stdscr.refresh()
            key = stdscr.getch()
            if key == ord("q"):
                break
            elif key == curses.KEY_UP and sel > 0:
                sel -= 1
                if sel < offset:
                    offset = max(0, offset - 1)
            elif key == curses.KEY_DOWN and sel < len(users) - 1:
                sel += 1
                if sel - offset >= max_vis:
                    offset = min(len(users) - max_vis, offset + 1)
            elif key == ord("\n") or key == ord("\r"):
                _dashboard_user_detail(stdscr, users[sel], entries_access)
                curses.curs_set(0)
        except curses.error:
            break

def _dashboard_user_detail(stdscr, user, entries_access) -> None:
    user_entries = [e for e in entries_access() if e.user and e.user.lower() == user.lower()]
    if not user_entries:
        return
    curses.curs_set(0)
    curses.use_default_colors()
    offset = 0
    rows = 15
    while True:
        try:
            stdscr.erase()
            maxy, maxx = stdscr.getmaxyx()
            stdscr.addstr(0, 0, f"USER: {user}  ({len(user_entries)} lines) [q] back", curses.A_BOLD)
            visible = user_entries[offset:offset+rows]
            for i, e in enumerate(visible):
                ts = e.dt or e.ts
                text = e.text or e.raw[:80]
                line = f" {ts:%H:%M} {text[:maxx-14]}"
                stdscr.addstr(2 + i, 0, line[:maxx-1])
            stdscr.addstr(maxy-1, 0, " ↑↓ scroll  q back", curses.A_REVERSE)
            stdscr.refresh()
            key = stdscr.getch()
            if key == ord("q"):
                break
            elif key == curses.KEY_UP and offset > 0:
                offset -= 1
            elif key == curses.KEY_DOWN and offset < len(user_entries) - rows:
                offset += 1
        except curses.error:
            break

def run_dashboard(entries, alert_engine, log_path="ai_scores.log") -> None:
    if not CURSES_OK:
        print("curses not available; install via 'pip install windows-curses' on Windows")
        return
    entries_shared = entries
    def _access():
        return entries_shared
    try:
        curses.wrapper(lambda stdscr: _dashboard_curses(stdscr, _access, alert_engine, log_path))
    except KeyboardInterrupt:
        pass

# ---------- Watch-mode alerting (feature a) -----------------------------------

# Global holder for shell state access from callbacks
_current_shell: dict[str, Any] = {}
def _set_current_shell(shell) -> None:
    _current_shell["shell"] = shell

def watch_with_alerts(log_path: str, engine: AlertEngine, webhook_url: str = "", webhook_type: str = "slack",
                      poll: float = 2.0) -> None:
    def cb(new_entries: list[Entry]) -> None:
        for entry in new_entries:
            alerts = engine.evaluate(entry)
            if alerts:
                for msg in alerts:
                    print(f"\r ALERT: {msg}")
                if webhook_url:
                    send_webhook(webhook_url, "\n".join(alerts), webhook_type)
    watch_loop(log_path, cb, poll=poll)

# ---------- Forecast-aware anomaly (feature b) --------------------------------

def forecast_aware_anomaly(entries: list[Entry], user: str, z: float = 2.5,
                           forecast_days: int = 7) -> dict:
    """Detect anomalies using forecasted baseline instead of simple mean."""
    base = forecast_activity(entries, user, forecast_days)
    user_entries = [e for e in entries if line_matches_user(e, user)]
    daily: Counter = Counter()
    for e in user_entries:
        if e.ts:
            daily[e.ts.date()] += 1
    if not daily:
        return {"user": user, "anomalies": [], "note": "insufficient data"}
    if not base.predictions:
        anomalies = detect_anomalies(entries, user, z)
        return {"user": user, "anomalies": [{"date": str(a.ts), "score": a.z_score} for a in anomalies], "forecast_based": False}
    forecast_map = {str(p[0]): p[1] for p in base.predictions}
    anomalies = []
    for date_key, actual in sorted(daily.items()):
        expected = forecast_map.get(str(date_key))
        if expected is not None:
            dev = abs(actual - expected)
            if dev > z * (statistics.mean([abs(a - v) for v in forecast_map.values() if v > 0]) or 1):
                anomalies.append({"date": str(date_key), "actual": actual, "expected": expected})
    return {"user": user, "anomalies": anomalies, "forecast_based": True}

# ---------- Alert fatigue scoring (feature c) ---------------------------------

@dataclass
class AlertFatigueScore:
    rule_name: str
    fires_total: int
    fires_last_hour: int
    signal_rate: float  # 0-1, lower = more fatigued
    suggestion: str

def alert_fatigue_scores(engine: AlertEngine, recent_entries: list[Entry],
                         window_hours: int = 1) -> list[AlertFatigueScore]:
    now = datetime.now()
    window_ago = now - timedelta(hours=window_hours)
    recent_set = [e for e in recent_entries if e.ts and e.ts >= window_ago]
    scores: list[AlertFatigueScore] = []
    for rule in engine.rules:
        if not rule.enabled:
            continue
        total = 0
        last_hour = 0
        for e in recent_set:
            vals = []
            if rule.field == "user":
                vals = [e.user]
            elif rule.field in SCORE_KEYS:
                sv = _scores_from_raw(e.raw).get(rule.field)
                if sv is not None:
                    vals = [str(sv)]
            else:
                vals = [e.raw]
            for v in vals:
                if v is None:
                    continue
                try:
                    if rule.op == "==" and v.lower() == rule.value.lower():
                        total += 1
                        if e.ts and e.ts >= window_ago:
                            last_hour += 1
                    elif rule.op == ">" and float(v) > float(rule.value):
                        total += 1
                        if e.ts and e.ts >= window_ago:
                            last_hour += 1
                except (ValueError, TypeError):
                    pass
        total_fires = total
        hourly_rate = last_hour / max(1, window_hours)
        signal_rate = max(0.0, 1.0 - min(1.0, hourly_rate / 10.0))
        if signal_rate < 0.3:
            suggestion = "Consider raising threshold or disabling"
        elif signal_rate < 0.7:
            suggestion = "Monitor; may need tuning"
        else:
            suggestion = "Healthy signal rate"
        scores.append(AlertFatigueScore(rule.name, total_fires, last_hour, signal_rate, suggestion))
    return scores

# ---------- Drill-down HTML report (feature d) --------------------------------

def write_html_report_drilldown(path: str, summary: dict, profiles: list[dict] | None = None) -> None:
    """Enhanced HTML report with collapsible user sections."""
    html_parts = ['<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">',
                  '<title>Log Analysis Report</title>',
                  '<style>body{font-family:sans-serif;margin:20px}',
                  '.section{cursor:pointer;background:#f0f0f0;padding:8px;margin:4px 0;border-radius:4px}',
                  '.section:hover{background:#e0e0e0}',
                  '.content{display:none;padding:8px;border-left:3px solid #ccc;margin:0 0 8px 8px}',
                  '.active .content{display:block}',
                  'table{border-collapse:collapse;width:100%}',
                  'td,th{border:1px solid #ddd;padding:6px;text-align:left}',
                  '</style>',
                  '<script>function toggle(e){e.classList.toggle("active")}</script>',
                  '</head><body>']
    html_parts.append(f"<h1>Log Analysis Report</h1>")
    html_parts.append(f"<p>Total entries: {summary.get('total', 0):,}</p>")
    # Collapsible sections
    for title, data_key in [("Users", "users"), ("Targets/Channels", "targets"),
                             ("Events", "events"), ("Levels", "levels")]:
        items = summary.get(data_key, {})
        if items:
            html_parts.append(f'<div class="section" onclick="toggle(this)">▸ <b>{title}</b> ({len(items)})</div>')
            html_parts.append(f'<div class="content">')
            html_parts.append("<table><tr><th>Name</th><th>Count</th></tr>")
            for name, count in sorted(items.items(), key=lambda x: -x[1])[:30]:
                html_parts.append(f"<tr><td>{html_mod.escape(name)}</td><td>{count}</td></tr>")
            html_parts.append("</table></div>")
    # Profiles
    if profiles:
        for prof in profiles:
            user = prof.get("user", "?")
            html_parts.append(f'<div class="section" onclick="toggle(this)">▸ <b>Profile: {html_mod.escape(user)}</b></div>')
            html_parts.append(f'<div class="content"><pre>{html_mod.escape(json.dumps(prof, indent=2, default=str))}</pre></div>')
    html_parts.append("</body></html>")
    try:
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(html_parts))
    except OSError as exc:
        print(f"Error writing HTML: {exc}", file=sys.stderr)

# ---------- Session-aware metrics (feature e) ---------------------------------

def session_response_times(entries: list[Entry], user_a: str, user_b: str,
                           gap_minutes: int = 30) -> list[dict]:
    """Compute response times grouped by session."""
    sessions = detect_sessions(entries, user_a, gap_minutes)
    results = []
    for sess in sessions:
        a_entries = [e for e in entries if e.ts and sess.start <= e.ts <= sess.end
                     and line_matches_user(e, user_a)]
        b_entries = [e for e in entries if e.ts and sess.start <= e.ts <= sess.end
                     and line_matches_user(e, user_b)]
        if not a_entries or not b_entries:
            continue
        a_times = sorted([e.ts for e in a_entries if e.ts])
        b_times = sorted([e.ts for e in b_entries if e.ts])
        if not a_times or not b_times:
            continue
        for at in a_times:
            future = [bt for bt in b_times if bt > at]
            if future:
                delay = (future[0] - at).total_seconds()
                results.append({"session_start": str(sess.start), "responder": user_b,
                                "delay_seconds": delay, "type": "a_to_b"})
        for bt in b_times:
            future = [at for at in a_times if at > bt]
            if future:
                delay = (future[0] - bt).total_seconds()
                results.append({"session_start": str(sess.start), "responder": user_a,
                                "delay_seconds": delay, "type": "b_to_a"})
    return results

# ---------- Influence chain tracking (feature f) ------------------------------

def influence_chains(entries: list[Entry], seed_user: str, max_hops: int = 3,
                     window_seconds: int = 300) -> list[list[dict]]:
    """Trace multi-hop reply chains: A→B→C within a time window per hop."""
    hop_map: dict[str, list[Entry]] = {}
    for e in entries:
        if e.target:
            hop_map.setdefault(e.target.lower(), []).append(e)
    chains: list[list[dict]] = []
    def _walk(current_user: str, depth: int, chain: list, visited: set) -> None:
        if depth >= max_hops:
            return
        replied = hop_map.get(current_user.lower(), [])
        for re in replied:
            if re.user and re.user.lower() not in visited and re.ts:
                next_user = re.user
                chain.append({"user": next_user, "ts": str(re.ts), "text": (re.text or re.raw)[:100]})
                visited.add(next_user.lower())
                _walk(next_user, depth + 1, chain, visited)
                if len(chain) >= 2:
                    chains.append(list(chain))
                chain.pop()
                visited.discard(next_user.lower())
    _walk(seed_user, 0, [], {seed_user.lower()})
    # Filter by window
    filtered = []
    for chain in chains:
        ok = True
        for i in range(1, len(chain)):
            t0 = _safe_parse_ts(chain[i-1]["ts"])
            t1 = _safe_parse_ts(chain[i]["ts"])
            if t0 and t1 and abs((t1 - t0).total_seconds()) > window_seconds:
                ok = False
                break
        if ok:
            filtered.append(chain)
    return filtered

def _safe_parse_ts(ts_str: str) -> datetime | None:
    try:
        return datetime.fromisoformat(ts_str)
    except (ValueError, TypeError):
        return None

# ---------- Template-based filtering (feature g) ------------------------------

def filter_by_template(entries: list[Entry], template_id: str) -> list[Entry]:
    """Filter entries matching a specific template ID."""
    tmpls = extract_log_templates(entries, top_n=200)
    try:
        idx = int(template_id)
        if idx < 1 or idx > len(tmpls):
            return []
        pattern, _, sample = tmpls[idx - 1]
    except (ValueError, IndexError):
        return []
    # Match by splitting template on placeholders and checking each literal segment
    parts = pattern.split("{}")
    # Remove empty leading/trailing parts
    parts = [p for p in parts if p.strip()]
    if not parts:
        return [e for e in entries if e.raw]
    results = []
    for e in entries:
        text = e.text or e.raw or ""
        if all(p in text for p in parts):
            results.append(e)
    return results

# ---------- Drift monitoring (feature h) --------------------------------------

def drift_detection(entries: list[Entry], user: str,
                    window_a_days: int = 7, window_b_days: int = 7,
                    gap_days: int = 0) -> dict:
    """Compare pattern-of-life profiles across two time windows to detect drift."""
    now = datetime.now()
    # Window B = most recent
    wb_end = now
    wb_start = now - timedelta(days=window_b_days)
    # Window A = before the gap
    wa_end = wb_start - timedelta(days=gap_days)
    wa_start = wa_end - timedelta(days=window_a_days)
    entries_a = apply_time_filter(entries, wa_start, wa_end)
    entries_b = apply_time_filter(entries, wb_start, wb_end)
    a_user = [e for e in entries_a if line_matches_user(e, user)]
    b_user = [e for e in entries_b if line_matches_user(e, user)]
    if not a_user or not b_user:
        return {"user": user, "drift_detected": False, "note": "insufficient data in both windows"}
    pol_a = pattern_of_life(a_user, user) if a_user else None
    pol_b = pattern_of_life(b_user, user) if b_user else None
    if not pol_a or not pol_b:
        return {"user": user, "drift_detected": False, "note": "could not compute profile"}
    # Compare hourly profiles
    drift_score = 0.0
    max_val = 0.0
    for h in range(24):
        va = pol_a.hourly_profile.get(h, 0)
        vb = pol_b.hourly_profile.get(h, 0)
        drift_score += abs(va - vb)
        max_val = max(max_val, abs(va - vb))
    avg = drift_score / 24
    return {"user": user, "drift_score": round(drift_score, 3),
            "avg_hourly_delta": round(avg, 3),
            "max_hourly_delta": round(max_val, 3),
            "drift_detected": drift_score > 0.5 or max_val > 0.2}

# ---------- Behavioral profile persistence (feature i) ------------------------

def save_profile(user: str, entries: list[Entry], path: str) -> str:
    """Compute and save a user profile to JSON."""
    prof = build_profile(entries, user)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(prof, f, indent=2, default=str)
        return f"Profile for {user} saved to {path}"
    except OSError as exc:
        return f"Error saving profile: {exc}"

def load_profile(path: str) -> dict | None:
    """Load a saved profile from JSON."""
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error loading profile: {exc}", file=sys.stderr)
        return None

def compare_saved_profiles(paths: list[str]) -> list[dict]:
    """Compare multiple saved profiles."""
    profiles = []
    for p in paths:
        prof = load_profile(p)
        if prof:
            profiles.append(prof)
    return profiles

# ---------- Auto-tagging (feature j) -----------------------------------------

def auto_tag_user(entries: list[Entry], user: str, llm_url: str, llm_model: str,
                  max_chunk_chars: int = 12000, cache: LLMCache | None = None) -> str:
    """Use LLM to auto-tag a user based on their log lines."""
    user_entries = [e for e in entries if line_matches_user(e, user)]
    if not user_entries:
        return f"(no data for {user})"
    text = "\n".join(e.text or e.raw for e in user_entries[:50])
    if len(text) > max_chunk_chars:
        text = text[:max_chunk_chars]
    prompt = (
        f"Analyze the following log lines from user '{user}' and assign 3-5 short tags "
        f"(e.g. 'high-volume', 'error-prone', 'night-owl', 'support-focused', 'bot-like').\n"
        f"Return only comma-separated tags, no explanation.\n\n{text}"
    )
    try:
        result = call_llm_cached(llm_url, llm_model, "", prompt, cache=cache)
        return result.strip() if result else "(no response)"
    except Exception as exc:
        return f"(error: {exc})"

def auto_tag_bulk(entries: list[Entry], llm_url: str, llm_model: str,
                  max_chunk_chars: int = 12000, cache: LLMCache | None = None,
                  top_n: int = 10) -> dict[str, str]:
    """Auto-tag top N users by activity."""
    users: Counter = Counter()
    for e in entries:
        if e.user:
            users[e.user] += 1
    top = [u for u, _ in users.most_common(top_n)]
    result: dict[str, str] = {}
    for u in top:
        result[u] = auto_tag_user(entries, u, llm_url, llm_model, max_chunk_chars, cache)
    return result

# ---------- Recurrence breach alert (feature k) -------------------------------

def check_recurrence_breach(entries: list[Entry], user: str,
                            recent_days: int = 3) -> dict:
    """Check if a user breaks their established recurrence pattern."""
    patterns = detect_recurrence(entries, user)
    if not patterns:
        return {"user": user, "breach": False, "note": "no pattern established"}
    now = datetime.now()
    window_start = now - timedelta(days=recent_days)
    recent = [e for e in entries if e.ts and e.ts >= window_start and line_matches_user(e, user)]
    breaches = []
    for pat in patterns:
        period = pat.pattern_type
        if period == "daily":
            counts: Counter = Counter()
            for e in recent:
                if e.ts:
                    counts[e.ts.date()] += 1
            expected = sum(counts.values()) / max(1, len(counts))
            for d, c in sorted(counts.items()):
                if expected > 0 and c < expected * 0.3:
                    breaches.append({"date": str(d), "count": c, "expected": round(expected, 1), "period": "daily"})
        elif period == "weekly":
            wd_counts: Counter = Counter()
            for e in recent:
                if e.ts:
                    wd_counts[e.ts.weekday()] += 1
            expected_wd = sum(wd_counts.values()) / max(1, len(wd_counts))
            for wd, c in sorted(wd_counts.items()):
                if expected_wd > 0 and c < expected_wd * 0.3:
                    breaches.append({"weekday": wd, "count": c, "expected": round(expected_wd, 1), "period": "weekly"})
        elif period == "hourly" and pat.description:
            h_counts: Counter = Counter()
            for e in recent:
                if e.ts:
                    h_counts[e.ts.hour] += 1
            import re as _re_h2
            m = _re_h2.search(r"(\d+):00", pat.description)
            if m:
                peak_h = int(m.group(1))
                if h_counts.get(peak_h, 0) < max(1, sum(h_counts.values()) // max(1, len(h_counts))):
                    breaches.append({"hour": peak_h, "expected_peak": peak_h, "period": "hourly", "note": "reduced peak activity"})
    if breaches:
        return {"user": user, "breach": True, "breaches": breaches[:10], "patterns": [p.pattern_type for p in patterns]}
    return {"user": user, "breach": False, "patterns": [p.pattern_type for p in patterns]}

# ---------- Config persistence (feature l) ------------------------------------

_SHELL_CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".analyzelog_config.json")

def save_shell_config(state: "ShellState") -> None:
    data: dict[str, Any] = {
        "webhook_url": state.webhook_url,
        "webhook_type": state.webhook_type,
        "plugin_dir": state.plugin_dir,
        "top_n": state.top_n,
        "llm_url": state.llm_url,
        "llm_model": state.llm_model,
        "max_chunk_chars": state.max_chunk_chars,
        "rules": [],
        "ignore_set": sorted(state.ignore_set),
        "aliases": state.aliases,
        "notes": state.notes,
        "presets": state.presets,
        "advanced": {
            "default_z_threshold": state.default_z_threshold,
            "default_anomaly_window": state.default_anomaly_window,
            "default_forecast_days": state.default_forecast_days,
            "default_burst_window": state.default_burst_window,
            "default_burst_z": state.default_burst_z,
            "default_session_gap": state.default_session_gap,
            "default_response_window": state.default_response_window,
            "output_format": state.output_format,
            "command_timing": state.command_timing,
            "debug_mode": state.debug_mode,
            "quiet_mode": state.quiet_mode,
            "default_export_dir": state.default_export_dir,
            "score_flag_threshold": state.score_flag_threshold,
            "max_output_lines": state.max_output_lines,
        },
    }
    for rule in state.alert_engine.rules:
        data["rules"].append({
            "name": rule.name, "field": rule.field, "op": rule.op,
            "value": rule.value, "message": rule.message, "enabled": rule.enabled,
        })
    if state.case_store:
        data["cases"] = {"_counter": state.case_store._counter, "cases": {}}
        for cid, c in state.case_store.cases.items():
            data["cases"]["cases"][cid] = {
                "name": c.name, "description": c.description, "status": c.status,
                "priority": c.priority, "created": c.created, "updated": c.updated,
                "tags": c.tags, "assigned_to": c.assigned_to,
                "findings": [
                    {"id": f.id, "entry_id": f.entry_id, "user": f.user,
                     "evidence_text": f.evidence_text, "category": f.category,
                     "severity": f.severity, "note": f.note, "ts_added": f.ts_added}
                    for f in c.findings
                ],
            }
    try:
        with open(_SHELL_CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
    except OSError:
        pass

def load_shell_config(state: "ShellState") -> None:
    try:
        with open(_SHELL_CONFIG_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return
    state.webhook_url = data.get("webhook_url", state.webhook_url)
    state.webhook_type = data.get("webhook_type", state.webhook_type)
    state.plugin_dir = data.get("plugin_dir", state.plugin_dir)
    state.top_n = data.get("top_n", state.top_n)
    state.llm_url = data.get("llm_url", state.llm_url)
    state.llm_model = data.get("llm_model", state.llm_model)
    state.max_chunk_chars = data.get("max_chunk_chars", state.max_chunk_chars)
    for r in data.get("rules", []):
        state.alert_engine.add(AlertRule(
            name=r.get("name", "?"), field=r.get("field", "user"),
            op=r.get("op", "=="), value=r.get("value", ""),
            message=r.get("message", ""), enabled=r.get("enabled", True),
        ))
    state.ignore_set.update(data.get("ignore_set", []))
    state.aliases.update(data.get("aliases", {}))
    state.notes.update(data.get("notes", {}))
    if "presets" in data:
        state.presets.update(data["presets"])
    if "advanced" in data:
        adv = data["advanced"]
        for key in ("default_z_threshold", "default_anomaly_window", "default_forecast_days",
                    "default_burst_window", "default_burst_z", "default_session_gap",
                    "default_response_window", "output_format", "command_timing",
                    "debug_mode", "quiet_mode", "default_export_dir", "score_flag_threshold",
                    "max_output_lines"):
            if key in adv:
                setattr(state, key, adv[key])
    if state.case_store and "cases" in data:
        cdata = data["cases"]
        state.case_store._counter = cdata.get("_counter", 0)
        for cid, cd in cdata.get("cases", {}).items():
            findings = [CaseFinding(**fd) for fd in cd.get("findings", [])]
            state.case_store.cases[cid] = Case(
                id=cid, name=cd["name"], description=cd.get("description", ""),
                status=cd.get("status", "open"), priority=cd.get("priority", "medium"),
                created=cd.get("created", ""), updated=cd.get("updated", ""),
                tags=cd.get("tags", []), findings=findings,
                assigned_to=cd.get("assigned_to", ""),
            )


# ---------- views (named filter sets) ---------------------------------------

@dataclass
class View:
    name: str
    user: str | None = None
    target: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    regex: str | None = None
    score_filter: list[tuple[str, str, float]] = field(default_factory=list)


def apply_view(entries: Iterable[Entry], view: View) -> list[Entry]:
    rx = re.compile(view.regex, re.I) if view.regex else None
    u = view.user.lower() if view.user else None
    t = view.target.lower() if view.target else None
    out: list[Entry] = []
    for e in entries:
        if not in_time_range(e.ts, view.since, view.until):
            continue
        if u:
            ok = (e.user and e.user.lower() == u) or _mentions(e.raw or "", view.user)
            if not ok:
                continue
        if t and not (e.target and e.target.lower() == t):
            continue
        if rx and not rx.search(e.raw):
            continue
        if view.score_filter and not matches_score_filter(e, view.score_filter):
            continue
        out.append(e)
    return out


def view_describe(v: View) -> str:
    parts = []
    if v.user:
        parts.append(f"user={v.user}")
    if v.target:
        parts.append(f"target={v.target}")
    if v.since:
        parts.append(f"since={v.since.isoformat()}")
    if v.until:
        parts.append(f"until={v.until.isoformat()}")
    if v.regex:
        parts.append(f"regex={v.regex!r}")
    if v.score_filter:
        parts.append("scores=[" + " ".join(f"{k}{op}{val}" for k, op, val in v.score_filter) + "]")
    return ", ".join(parts) or "(empty)"


# ---------- color / spinner / sparkline / config helpers -------------------

class _Color:
    enabled: bool = True
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    @classmethod
    def wrap(cls, s: str, c: str) -> str:
        return f"{c}{s}{cls.RESET}" if cls.enabled else s

    @classmethod
    def auto_disable(cls) -> None:
        if not sys.stdout.isatty():
            cls.enabled = False
        if os.environ.get("NO_COLOR"):
            cls.enabled = False


def _color_score(x) -> str:
    """Color a score float by threshold (red ≥ 0.8, yellow ≥ 0.5, green else)."""
    if not isinstance(x, float):
        return _fmt_score(x)
    s = f"{x:.3f}"
    if x >= 0.8:
        return _Color.wrap(s, _Color.RED)
    if x >= 0.5:
        return _Color.wrap(s, _Color.YELLOW)
    return _Color.wrap(s, _Color.GREEN)


SPARK_GLYPHS = "▁▂▃▄▅▆▇█"


def sparkline(values: list[int]) -> str:
    if not values:
        return ""
    peak = max(values) or 1
    out = []
    for v in values:
        idx = int((v / peak) * (len(SPARK_GLYPHS) - 1))
        out.append(SPARK_GLYPHS[idx])
    return "".join(out)

# ---------- ASCII timeline (#1) -----------------------------------------------

def ascii_timeline(entries: list[Entry], user: str | None = None,
                   width: int = 60, height: int = 12) -> str:
    if user:
        u = user.lower()
        filtered = [e for e in entries if e.ts and e.user and e.user.lower() == u]
    else:
        filtered = [e for e in entries if e.ts]
    if not filtered:
        return "(no timestamped entries)"
    ts_min = min(e.ts for e in filtered)
    ts_max = max(e.ts for e in filtered)
    span = (ts_max - ts_min).total_seconds() or 1
    buckets: list[list[str]] = [[] for _ in range(width)]
    for e in filtered:
        frac = (e.ts - ts_min).total_seconds() / span
        col = min(int(frac * width), width - 1)
        label = (e.user or "?")[:6]
        buckets[col].append(label)
    max_per_col = max((len(b) for b in buckets), default=1)
    lines: list[str] = []
    for row in range(height - 1, -1, -1):
        threshold = int(max_per_col * row / height) if height > 0 else 0
        line_chars: list[str] = []
        for col in range(width):
            if len(buckets[col]) >= threshold:
                line_chars.append("█")
            elif len(buckets[col]) >= threshold - 1 and row > 0:
                line_chars.append("▄")
            else:
                line_chars.append("·")
        lines.append("".join(line_chars))
    lines.append("─" * width)
    label_lines = [f"  start: {ts_min}", f"  end:   {ts_max}", f"  span:  {ts_max - ts_min}"]
    if user:
        label_lines.insert(0, f"  user:  {user}")
    return "\n".join(lines + label_lines)

# ---------- Calendar heatmap (#2) ---------------------------------------------

CALENDAR_COLORS = [" ", "░", "▒", "▓", "█"]

def calendar_heatmap(entries: list[Entry], user: str | None = None,
                     months: int = 3) -> str:
    now = datetime.now()
    start = now - timedelta(days=months * 31)
    if user:
        u = user.lower()
        filtered = [e for e in entries if e.ts and e.user and e.user.lower() == u]
    else:
        filtered = [e for e in entries if e.ts]
    by_date: Counter = Counter()
    for e in filtered:
        by_date[e.ts.date()] += 1
    all_counts = list(by_date.values())
    if not all_counts:
        return "(no data)"
    max_count = max(all_counts) or 1
    lines: list[str] = []
    lines.append(f"  Calendar heatmap for {'user ' + user if user else 'all users'} ({len(by_date)} active days)")
    lines.append(f"  {CALENDAR_COLORS[0]}=0  {CALENDAR_COLORS[1]}=low  {CALENDAR_COLORS[2]}=med  {CALENDAR_COLORS[3]}=high  {CALENDAR_COLORS[4]}=peak")
    cur = start
    week: list[str] = []
    header = True
    while cur <= now:
        if cur.weekday() == 0 and week:
            lines.append("".join(week))
            week = []
        if header:
            lines.append("  " + " ".join("Mon Tue Wed Thu Fri Sat Sun".split()))
            header = False
        count = by_date.get(cur.date(), 0)
        idx = min(int(count / max_count * 4), 4) if max_count > 0 else 0
        week.append(CALENDAR_COLORS[idx] + CALENDAR_COLORS[idx])
        cur += timedelta(days=1)
    if week:
        lines.append("".join(week))
    return "\n".join(lines)

# ---------- ASCII network graph (#7) ------------------------------------------

def ascii_network_graph(edges: Counter, top_n: int = 15, width: int = 50) -> str:
    top_edges = edges.most_common(top_n)
    if not top_edges:
        return "(no edges)"
    # collect nodes
    nodes: set[str] = set()
    for (a, b), _ in top_edges:
        nodes.add(a)
        nodes.add(b)
    max_weight = max(w for _, w in top_edges) or 1
    lines: list[str] = [f"  Network graph ({len(nodes)} nodes, {len(top_edges)} edges shown)"]
    # print adjacency list
    for (a, b), w in top_edges:
        bar_len = int(w / max_weight * 20)
        bar = "━" * bar_len + "➤" if bar_len > 0 else "➤"
        lines.append(f"  {a:<15} {bar:<22} {b:<15}  (w={w})")
    return "\n".join(lines)


class Spinner:
    """Thread-driven spinner on stderr; no-op when stderr is not a TTY."""
    GLYPHS = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

    def __init__(self, msg: str = "working", enabled: bool | None = None) -> None:
        self.msg = msg
        if enabled is None:
            enabled = bool(getattr(sys.stderr, "isatty", lambda: False)())
        self.enabled = enabled
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "Spinner":
        if self.enabled:
            self._thread = threading.Thread(target=self._spin, daemon=True)
            self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._thread:
            self._stop.set()
            self._thread.join(timeout=1.0)
            try:
                sys.stderr.write("\r" + " " * (len(self.msg) + 4) + "\r")
                sys.stderr.flush()
            except Exception:  # noqa: BLE001
                pass

    def _spin(self) -> None:
        for ch in itertools.cycle(self.GLYPHS):
            if self._stop.is_set():
                break
            try:
                sys.stderr.write(f"\r{ch} {self.msg} ")
                sys.stderr.flush()
            except Exception:  # noqa: BLE001
                return
            if self._stop.wait(0.1):
                return


def _config_dir() -> str:
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    p = os.path.join(base, "analyzelog")
    try:
        os.makedirs(p, exist_ok=True)
    except OSError:
        pass
    return p


def _aliases_path() -> str:
    return os.path.join(_config_dir(), "aliases.json")


def _ignore_path() -> str:
    return os.path.join(_config_dir(), "ignore.json")


def _notes_path() -> str:
    return os.path.join(_config_dir(), "notes.json")


def _history_path() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    try:
        os.makedirs(base, exist_ok=True)
    except OSError:
        pass
    return os.path.join(base, "analyzelog_history")


def _load_json(path: str, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return default


def _save_json(path: str, data) -> None:
    try:
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)
    except OSError as exc:
        print(f"Failed to write {path}: {exc}", file=sys.stderr)


# ---------- LLM --------------------------------------------------------------

def _llm_endpoint(base: str) -> str:
    base = base.rstrip("/")
    if base.endswith("/v1/chat/completions") or base.endswith("/chat/completions"):
        return base
    return base + "/v1/chat/completions"


def call_llm(base_url: str, model: str, system: str, user_msg: str,
             timeout: int = 180) -> str:
    body = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user_msg},
        ],
        "temperature": 0.3,
        "stream": False,
    }).encode("utf-8")
    req = urllib.request.Request(
        _llm_endpoint(base_url),
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = json.loads(resp.read().decode("utf-8", errors="replace"))
    try:
        return data["choices"][0]["message"]["content"]
    except (KeyError, IndexError, TypeError):
        return json.dumps(data)[:2000]


class LLMCache:
    """JSON-on-disk cache of LLM responses keyed by (model, system, user_msg)."""

    def __init__(self, path: str | None) -> None:
        self.path = path
        self.data: dict[str, str] = {}
        self.dirty = False
        if path and os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    obj = json.load(f)
                if isinstance(obj, dict):
                    self.data = {k: v for k, v in obj.items() if isinstance(v, str)}
            except (OSError, json.JSONDecodeError):
                self.data = {}

    @staticmethod
    def make_key(model: str, system: str, user_msg: str) -> str:
        h = hashlib.sha256()
        h.update(model.encode())
        h.update(b"\0")
        h.update(system.encode())
        h.update(b"\0")
        h.update(user_msg.encode())
        return h.hexdigest()

    def get(self, model: str, system: str, user_msg: str) -> str | None:
        return self.data.get(self.make_key(model, system, user_msg))

    def put(self, model: str, system: str, user_msg: str, response: str) -> None:
        self.data[self.make_key(model, system, user_msg)] = response
        self.dirty = True
        self.save()

    def save(self) -> None:
        if not self.path or not self.dirty:
            return
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self.data, f)
            os.replace(tmp, self.path)
            self.dirty = False
        except OSError as exc:
            print(f"LLM cache save failed: {exc}", file=sys.stderr)

    def __len__(self) -> int:
        return len(self.data)


def call_llm_cached(base_url: str, model: str, system: str, user_msg: str,
                    timeout: int = 180, cache: LLMCache | None = None,
                    spinner_msg: str = "LLM thinking") -> str:
    if cache is not None:
        hit = cache.get(model, system, user_msg)
        if hit is not None:
            return hit
    with Spinner(spinner_msg):
        out = call_llm(base_url, model, system, user_msg, timeout)
    if cache is not None:
        cache.put(model, system, user_msg, out)
    return out


def chunk_lines(lines: list[str], max_chars: int) -> list[str]:
    chunks: list[str] = []
    buf: list[str] = []
    size = 0
    for ln in lines:
        ln_len = len(ln) + 1
        if size + ln_len > max_chars and buf:
            chunks.append("\n".join(buf))
            buf, size = [], 0
        buf.append(ln)
        size += ln_len
    if buf:
        chunks.append("\n".join(buf))
    return chunks


def analyze_user_with_llm(user: str, lines: list[str], llm_url: str,
                          model: str, max_chars: int,
                          cache: LLMCache | None = None) -> None:
    if not lines:
        print(f"\nNo lines matched user '{user}'. Nothing to send to the LLM.")
        return

    print(f"\nFiltered to {len(lines)} lines for user '{user}'.")
    chunks = chunk_lines(lines, max_chars)
    print(f"Sending {len(chunks)} chunk(s) to LLM at {llm_url} (model={model}).")

    system = (
        "You are a log-analysis assistant. Given log lines authored by a "
        "single user/identifier, summarize that user's behavior: what they do, "
        "when they are active, who/what they interact with, anomalies, and any "
        "signs of trouble. Be concrete, cite line patterns, and keep it tight."
    )

    partials: list[str] = []
    for i, chunk in enumerate(chunks, 1):
        prompt = (
            f"User of interest: {user}\n"
            f"Chunk {i}/{len(chunks)} of log lines authored by this user:\n\n"
            f"{chunk}\n\n"
            f"Summarize this chunk's evidence about {user}'s behavior."
        )
        try:
            out = call_llm_cached(llm_url, model, system, prompt, cache=cache)
        except urllib.error.URLError as exc:
            print(f"  [chunk {i}] LLM request failed: {exc}", file=sys.stderr)
            return
        except Exception as exc:  # noqa: BLE001
            print(f"  [chunk {i}] LLM error: {exc}", file=sys.stderr)
            return
        partials.append(out)
        print(f"\n--- Chunk {i}/{len(chunks)} summary ---\n{out}")

    if len(partials) > 1:
        merge_prompt = (
            f"Combine these per-chunk summaries about user '{user}' into one "
            f"cohesive behavior profile. Deduplicate, resolve contradictions, "
            f"and call out the strongest signals.\n\n"
            + "\n\n---\n\n".join(f"Chunk {i+1}:\n{p}" for i, p in enumerate(partials))
        )
        try:
            final = call_llm_cached(llm_url, model, system, merge_prompt, cache=cache)
            print(f"\n=== Final behavior profile for {user} ===\n{final}")
        except Exception as exc:  # noqa: BLE001
            print(f"Final merge failed: {exc}", file=sys.stderr)


def analyze_interaction_with_llm(a: str, b: str, lines: list[str], llm_url: str,
                                 model: str, max_chars: int,
                                 cache: LLMCache | None = None) -> None:
    if not lines:
        print(f"\nNo direct interactions found between '{a}' and '{b}'. Nothing to send to the LLM.")
        return

    print(f"\nFound {len(lines)} direct-interaction lines between '{a}' and '{b}'.")
    chunks = chunk_lines(lines, max_chars)
    print(f"Sending {len(chunks)} chunk(s) to LLM at {llm_url} (model={model}).")

    system = (
        "You are a log-analysis assistant. You will receive log lines that "
        "represent direct exchanges between exactly two users. Characterize "
        "their relationship: frequency and rhythm of contact, tone, who "
        "initiates, recurring topics, agreement vs. conflict, role asymmetry "
        "(e.g. helper/asker, friends, antagonists, bot/operator), and any "
        "anomalies. Cite concrete evidence and keep it tight."
    )

    partials: list[str] = []
    for i, chunk in enumerate(chunks, 1):
        prompt = (
            f"User A: {a}\nUser B: {b}\n"
            f"Chunk {i}/{len(chunks)} of log lines representing direct exchanges "
            f"between them:\n\n{chunk}\n\n"
            f"Summarize this chunk's evidence about how {a} and {b} interact."
        )
        try:
            out = call_llm_cached(llm_url, model, system, prompt, cache=cache)
        except urllib.error.URLError as exc:
            print(f"  [chunk {i}] LLM request failed: {exc}", file=sys.stderr)
            return
        except Exception as exc:  # noqa: BLE001
            print(f"  [chunk {i}] LLM error: {exc}", file=sys.stderr)
            return
        partials.append(out)
        print(f"\n--- Chunk {i}/{len(chunks)} summary ---\n{out}")

    if len(partials) > 1:
        merge_prompt = (
            f"Combine these per-chunk summaries about the interaction between "
            f"'{a}' and '{b}' into one cohesive relationship profile. "
            f"Deduplicate, resolve contradictions, and call out the strongest "
            f"signals.\n\n"
            + "\n\n---\n\n".join(f"Chunk {i+1}:\n{p}" for i, p in enumerate(partials))
        )
        try:
            final = call_llm_cached(llm_url, model, system, merge_prompt, cache=cache)
            print(f"\n=== Final interaction profile: {a} ↔ {b} ===\n{final}")
        except Exception as exc:  # noqa: BLE001
            print(f"Final merge failed: {exc}", file=sys.stderr)


def _profile_summary_for_llm(p: dict) -> str:
    sm = p["score_means"]
    return (
        f"User: {p['user']}\n"
        f"  authored_lines: {p['authored']}\n"
        f"  mentioned_by_others: {p['mentioned_by_others']}\n"
        f"  first_seen: {_fmt_dt(p['first_ts'])}   last_seen: {_fmt_dt(p['last_ts'])}\n"
        f"  active_days: {len(p['by_day'])}   peak_hours: {_peak_hours(p['by_hour'])}\n"
        f"  top_channels: {_top_str(p['channels'], 5) or '—'}\n"
        f"  flags: {_top_str(p['flags'], 5) or '—'}\n"
        f"  mean_msg_len: {_fmt_num(p['msg_len_mean'])}\n"
        f"  score_means: heu={_fmt_score(sm['heu'])} bino={_fmt_score(sm['bino'])} "
        f"cls={_fmt_score(sm['cls'])} llama={_fmt_score(sm['llama'])}"
    )


def _trim_samples(samples: list[str], max_chars: int) -> list[str]:
    if not samples:
        return []
    if len(samples) <= 60:
        chosen = samples
    else:
        step = len(samples) / 60
        chosen = [samples[int(i * step)] for i in range(60)]
    out: list[str] = []
    used = 0
    for s in chosen:
        if used + len(s) + 1 > max_chars:
            break
        out.append(s)
        used += len(s) + 1
    return out


def compare_users_with_llm(pa: dict, pb: dict, llm_url: str, model: str,
                           max_chunk_chars: int,
                           cache: LLMCache | None = None) -> None:
    compare_n_users_with_llm([pa, pb], llm_url, model, max_chunk_chars, cache)


def compare_n_users_with_llm(profiles: list[dict], llm_url: str, model: str,
                             max_chunk_chars: int,
                             cache: LLMCache | None = None) -> None:
    names = ", ".join(p["user"] for p in profiles)
    if not any(p["authored"] for p in profiles):
        print(f"\nNone of the requested users ({names}) authored lines in this log.")
        return

    sample_budget = max(1500, max_chunk_chars // (len(profiles) + 1))
    parts: list[str] = []
    counts: list[int] = []
    for p in profiles:
        samples = _trim_samples(p["samples"], sample_budget)
        counts.append(len(samples))
        parts.append(
            f"=== Profile: {p['user']} ===\n{_profile_summary_for_llm(p)}\n\n"
            f"Sample lines authored by {p['user']} ({len(samples)}):\n"
            + "\n".join(samples)
        )
    user_msg = "\n\n".join(parts) + f"\n\nCompare these users: {names}."

    if len(profiles) == 2:
        system = (
            "You are a log-analysis assistant. You will receive two users' "
            "behavior profiles (aggregate metrics) plus sample messages each "
            "user authored. Compare them: tone and style, topics they engage "
            "with, where and when they're active, score-profile differences, "
            "role (helper/asker/lurker/bot/troll), similarities, and any "
            "anomalies that distinguish them. Cite metrics and quote short "
            "snippets when useful. Keep it tight and structured."
        )
    else:
        system = (
            "You are a log-analysis assistant. You will receive several users' "
            "behavior profiles and sample messages. Compare them across tone, "
            "topics, activity windows, score-profile differences, and roles. "
            "Group users that look alike (possible sock-puppets) and call out "
            "ones that stand apart. Cite metrics, quote short snippets, and "
            "structure clearly."
        )

    print(f"\nSending {len(profiles)}-way behavior comparison to LLM at {llm_url} (model={model}).")
    print("  " + "  |  ".join(f"{p['user']}: {n} samples" for p, n in zip(profiles, counts)))

    try:
        out = call_llm_cached(llm_url, model, system, user_msg, cache=cache)
    except urllib.error.URLError as exc:
        print(f"LLM request failed: {exc}", file=sys.stderr)
        return
    except Exception as exc:  # noqa: BLE001
        print(f"LLM error: {exc}", file=sys.stderr)
        return
    print(f"\n=== Behavior comparison: {names} ===\n{out}")


def ask_about_user_with_llm(user: str, question: str, lines: list[str],
                            llm_url: str, model: str, max_chars: int,
                            cache: LLMCache | None = None) -> None:
    if not lines:
        print(f"\nNo lines for '{user}'. Nothing to ask.")
        return
    chunks = chunk_lines(lines, max_chars)
    print(f"\nAsking LLM about {user} ({len(chunks)} chunk(s)) at {llm_url} (model={model}).")
    system = (
        "You are a log-analysis assistant. Given log lines that all relate to "
        "a single user, answer the operator's question concretely, citing "
        "evidence from the lines. If the lines do not contain enough "
        "information to answer, say so."
    )
    partials: list[str] = []
    for i, chunk in enumerate(chunks, 1):
        prompt = (
            f"User of interest: {user}\n"
            f"Operator question: {question}\n\n"
            f"Chunk {i}/{len(chunks)} of log lines for this user:\n\n{chunk}\n\n"
            f"Answer the question for this chunk. Cite lines when useful."
        )
        try:
            out = call_llm_cached(llm_url, model, system, prompt, cache=cache)
        except urllib.error.URLError as exc:
            print(f"  [chunk {i}] LLM request failed: {exc}", file=sys.stderr)
            return
        except Exception as exc:  # noqa: BLE001
            print(f"  [chunk {i}] LLM error: {exc}", file=sys.stderr)
            return
        partials.append(out)
        print(f"\n--- Chunk {i}/{len(chunks)} answer ---\n{out}")
    if len(partials) > 1:
        merge = (
            f"Operator question: {question}\n\n"
            f"Combine the per-chunk answers below into one coherent response. "
            f"Resolve contradictions, deduplicate, and cite the strongest evidence.\n\n"
            + "\n\n---\n\n".join(f"Chunk {i+1}:\n{p}" for i, p in enumerate(partials))
        )
        try:
            final = call_llm_cached(llm_url, model, system, merge, cache=cache)
            print(f"\n=== Final answer about {user}: {question} ===\n{final}")
        except Exception as exc:  # noqa: BLE001
            print(f"Final merge failed: {exc}", file=sys.stderr)


# ---------- NEW: LLM anomaly explanation (#19) --------------------------------

def llm_explain_anomalies(anomalies: list[Anomaly], context_lines: list[str],
                          llm_url: str, model: str, max_chars: int = 8000,
                          cache: LLMCache | None = None) -> None:
    if not anomalies:
        print("(no anomalies to explain)")
        return
    anomaly_text = "\n".join(
        f"  {a.metric}: value={a.value:.2f}, expected={a.expected:.2f}, z={a.zscore:.2f}, "
        f"day={a.day or '?'}, hour={a.hour or '?'}"
        for a in anomalies[:10]
    )
    context = "\n".join(context_lines[:50])
    system = "You are a log-anomaly analyst. Explain what might be happening given the detected anomalies and context."
    prompt = (
        f"Detected anomalies:\n{anomaly_text}\n\n"
        f"Recent context lines:\n{context}\n\n"
        f"Explain these anomalies: what do they suggest and should we be concerned?"
    )
    try:
        out = call_llm_cached(llm_url, model, system, prompt, cache=cache, spinner_msg="LLM explaining anomalies")
        print(f"\n=== LLM anomaly explanation ===\n{out}")
    except Exception as exc:
        print(f"LLM anomaly explanation failed: {exc}")

# ---------- NEW: Conversation summarization (#20) -----------------------------

def llm_summarize_conversation(a: str, b: str, lines: list[str],
                               llm_url: str, model: str, max_chars: int = 8000,
                               cache: LLMCache | None = None) -> None:
    if not lines:
        print(f"(no conversation to summarize)")
        return
    chunks = chunk_lines(lines, max_chars)
    system = "You summarize chat conversations into bullet points covering topics, tone, and key exchanges."
    partials: list[str] = []
    for i, chunk in enumerate(chunks, 1):
        prompt = (
            f"Conversation between {a} and {b}, chunk {i}/{len(chunks)}:\n\n"
            f"{chunk}\n\n"
            f"Summarize this chunk's conversation as bullet points."
        )
        try:
            out = call_llm_cached(llm_url, model, system, prompt, cache=cache, spinner_msg="LLM summarizing")
        except Exception as exc:
            print(f"LLM error: {exc}")
            return
        partials.append(out)
        print(f"\n--- Chunk {i} summary ---\n{out}")
    if len(partials) > 1:
        merge_prompt = (
            f"Combine these per-chunk summaries of a conversation between {a} and {b}:\n\n"
            + "\n\n".join(f"Chunk {i+1}: {p}" for i, p in enumerate(partials))
        )
        try:
            final = call_llm_cached(llm_url, model, system, merge_prompt, cache=cache)
            print(f"\n=== Full conversation summary: {a} ↔ {b} ===\n{final}")
        except Exception as exc:
            print(f"Merge failed: {exc}")

# ---------- NEW: LLM clustering (#21) -----------------------------------------

def llm_cluster_users(profiles: list[dict], llm_url: str, model: str,
                      max_chars: int = 12000, cache: LLMCache | None = None) -> None:
    if len(profiles) < 3:
        print("Need at least 3 users for clustering.")
        return
    sample_budget = max(2000, max_chars // (len(profiles) + 1))
    parts: list[str] = []
    for p in profiles[:15]:
        samples = _trim_samples(p.get("samples", []), sample_budget)
        parts.append(
            f"User: {p['user']} (lines={p.get('authored', 0)})\n"
            f"Score means: {p.get('score_means', {})}\n"
            f"Peak hours: {_peak_hours(p.get('by_hour', {}))}\n"
            f"Sample lines:\n" + "\n".join(samples[:10])
        )
    system = (
        "You are a behavioral clustering analyst. Group these users by similar behavior patterns "
        "(tone, activity, topics, roles). For each group, describe the common traits. "
        "Flag any users that are anomalous outliers."
    )
    prompt = f"Cluster these {len(profiles)} users into behavioral groups:\n\n" + "\n---\n".join(parts)
    try:
        out = call_llm_cached(llm_url, model, system, prompt, cache=cache, spinner_msg="LLM clustering")
        print(f"\n=== LLM user clustering ===\n{out}")
    except Exception as exc:
        print(f"LLM clustering failed: {exc}")

# ---------- NEW: Automated LLM report (#22) -----------------------------------

def llm_auto_report(summary: dict, top_profiles: list[dict], llm_url: str, model: str,
                    max_chars: int = 12000, cache: LLMCache | None = None) -> None:
    system = "You are a log analysis reporter. Generate a concise narrative report of the key findings."
    summary_part = (
        f"Total entries: {summary.get('total', 0)}\n"
        f"Time range: {summary.get('first_ts')} to {summary.get('last_ts')}\n"
        f"Top users: {summary.get('top_users', [])[:10]}\n"
        f"Top events: {summary.get('top_events', [])[:10]}\n"
    )
    profile_parts: list[str] = []
    for p in top_profiles[:5]:
        profile_parts.append(
            f"{p['user']}: lines={p.get('authored', 0)}, "
            f"scores={p.get('score_means', {})}"
        )
    prompt = (
        f"Log summary:\n{summary_part}\n\n"
        f"Top user profiles:\n" + "\n".join(profile_parts) + "\n\n"
        f"Generate a 1-2 paragraph narrative report of the key findings, trends, and anomalies."
    )
    try:
        out = call_llm_cached(llm_url, model, system, prompt, cache=cache, spinner_msg="LLM generating report")
        print(f"\n=== Automated log report ===\n{out}")
    except Exception as exc:
        print(f"Auto report failed: {exc}")

# ---------- NEW: LLM forensic features (#29) -----------------------------------

def llm_forensic_report(entries: list[Entry], user: str, llm_url: str, model: str,
                        max_chars: int = 15000, cache: LLMCache | None = None) -> None:
    user_entries = [e for e in entries if line_matches_user(e, user)]
    if not user_entries:
        print(f"(no data for {user})")
        return

    entity_catalog = build_entity_catalog(user_entries)
    timeline = reconstruct_timeline(user_entries, user, max_events=100)
    gaps = detect_timeline_gaps(user_entries, user, 30)
    profile = build_profile(user_entries, user)
    sentiment = user_sentiment(user_entries, user)
    anomalies = detect_behavioral_anomalies(entries, user)

    evidence_sections: list[str] = [
        f"FORENSIC REPORT FOR USER: {user}",
        "",
        "=== PROFILE ===",
        f"Total authored lines: {profile['authored']}",
        f"First seen: {_fmt_dt(profile['first_ts'])}",
        f"Last seen: {_fmt_dt(profile['last_ts'])}",
        f"Active days: {len(profile['by_day'])}",
        f"Peak hours: {_peak_hours(profile['by_hour'])}",
        f"Top channels: {_top_str(profile['channels'], 5) or '(none)'}",
        f"Mean scores: {json.dumps(profile['score_means'])}",
        "",
        "=== SENTIMENT ===",
    ]
    comp = sentiment.get("mean_compound")
    if comp is not None:
        evidence_sections.append(f"Mean compound: {comp:.3f} (Rate: {sentiment.get('pos_rate',0):.1%} pos, {sentiment.get('neg_rate',0):.1%} neg)")
        evidence_sections.append(f"Agreement Rate: {sentiment.get('agree_rate',0):.1%}")

    if anomalies:
        evidence_sections.append("\n=== BEHAVIORAL ANOMALIES ===")
        for a in sorted(anomalies, key=lambda x: abs(x.zscore), reverse=True)[:15]:
            evidence_sections.append(f"  {a.metric}: z={a.zscore:+.2f} val={a.value:.1f} exp={a.expected:.1f} ({a.day} h{a.hour})")

    if entity_catalog:
        evidence_sections.append("\n=== ENTITY EXTRACTION ===")
        for etype, entities in entity_catalog.items():
            if entities:
                top = sorted(entities, key=lambda x: -x.count)[:8]
                vals = ", ".join(f"{e.value}({e.count}x)" for e in top)
                evidence_sections.append(f"  {etype}: {vals}")

    evidence_sections.append("\n=== TIMELINE GAPS ===")
    if gaps:
        for g in gaps[:10]:
            evidence_sections.append(f"  {g.start} -> {g.end} ({g.duration_minutes:.0f}min)")

    evidence_sections.append("\n=== RECENT CHAT LOGS (tail) ===")
    for e in user_entries[-50:]:
        evidence_sections.append(f"  [{e.ts}] {e.user}: {(e.text or e.raw)[:200]}")

    evidence_text = "\n".join(evidence_sections)
    if len(evidence_text) > max_chars:
        # Keep stats and tail
        evidence_text = evidence_text[:max_chars//3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2*max_chars//3):]

    system = (
        "You are an expert forensic log analyst and behavioral profiler. "
        "Your goal is to analyze the provided evidence and build a comprehensive "
        "forensic profile of the user. Focus on identifying intent, operational security (OPSEC) "
        "patterns, potential automation/botting, and behavioral shifts. "
        "Use a professional, investigative tone."
    )
    prompt = (
        f"DATASET FOR ANALYSIS:\n{evidence_text}\n\n"
        "Please provide a structured report with the following sections:\n"
        "1. EXECUTIVE SUMMARY: High-level overview of activity and suspicious indicators.\n"
        "2. BEHAVIORAL PROFILE: Analysis of communication style, sentiment, and 'Pattern of Life'.\n"
        "3. ANOMALY ANALYSIS: Deep dive into detected anomalies (Z-scores, time shifts, score spikes).\n"
        "4. ENTITY & NETWORK ANALYSIS: Interpretation of mentioned IPs, URLs, and associates.\n"
        "5. RISK ASSESSMENT: Categorize risk level (Low/Medium/High/Critical) with justification.\n"
        "6. RECOMMENDATIONS: Suggested follow-up actions for investigators."
    )
    try:
        out = call_llm_cached(llm_url, model, system, prompt, cache=cache, spinner_msg=f"Generating forensic report for {user}")
        print(f"\n{'='*80}\nFORENSIC ANALYSIS: {user}\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Forensic report generation failed: {exc}")
        print(f"\n{'='*60}\nFORENSIC REPORT: {user}\n{'='*60}\n{out}")
    except Exception as exc:
        print(f"Forensic report failed: {exc}")


def llm_timeline_narrative(entries: list[Entry], user: str, llm_url: str, model: str,
                           max_chars: int = 12000, cache: LLMCache | None = None) -> None:
    timeline = reconstruct_timeline(entries, user, max_events=80)
    if not timeline:
        print(f"(no timeline data for {user})")
        return

    chunks: list[str] = []
    for i in range(0, len(timeline), 20):
        chunk_events = timeline[i:i + 20]
        chunk_lines = [f"[{e.ts}] {e.user}: [{e.event_type}] {e.summary}" for e in chunk_events]
        chunks.append("\n".join(chunk_lines))

    system = (
        "You are a timeline analyst. Given a chronological sequence of events for a user, "
        "write a concise narrative describing what happened, in what order, and what patterns "
        "emerge. Highlight unusual activity, key transitions, and behavioral patterns. "
        "Be specific and reference timestamps."
    )

    partials: list[str] = []
    for i, chunk in enumerate(chunks, 1):
        prompt = (
            f"User: {user}\n"
            f"Chunk {i}/{len(chunks)} of timeline events:\n\n{chunk}\n\n"
            f"Describe the activity in this period as a narrative."
        )
        try:
            out = call_llm_cached(llm_url, model, system, prompt, cache=cache,
                                  spinner_msg=f"LLM narrating timeline chunk {i}/{len(chunks)}")
            partials.append(out)
            print(f"\n--- Timeline chunk {i}/{len(chunks)} ---\n{out}")
        except Exception as exc:
            print(f"Timeline narrative chunk {i} failed: {exc}")
            return

    if len(partials) > 1:
        merge_prompt = (
            f"Combine these per-chunk timeline narratives for user '{user}' into one "
            f"coherent chronological story. Deduplicate and highlight the most significant events.\n\n"
            + "\n\n".join(f"Chunk {i+1}:\n{p}" for i, p in enumerate(partials))
        )
        try:
            final = call_llm_cached(llm_url, model, system, merge_prompt, cache=cache,
                                    spinner_msg="LLM merging timeline narrative")
            print(f"\n=== Timeline narrative: {user} ===\n{final}")
        except Exception as exc:
            print(f"Merge failed: {exc}")


def llm_evidence_extraction(entries: list[Entry], user: str, llm_url: str, model: str,
                            max_chars: int = 12000, cache: LLMCache | None = None) -> None:
    user_entries = [e for e in entries if line_matches_user(e, user)]
    if not user_entries:
        print(f"(no data for {user})")
        return

    entity_catalog = build_entity_catalog(user_entries)
    evidence_lines: list[str] = [
        f"EVIDENCE EXTRACTION FOR: {user}",
        f"Total log lines: {len(user_entries)}",
        "",
    ]
    if entity_catalog:
        for etype, entities in entity_catalog.items():
            if entities:
                evidence_lines.append(f"  {etype.upper()}:")
                for ent in entities[:10]:
                    first = _fmt_dt(ent.first_seen) or "?"
                    last = _fmt_dt(ent.last_seen) or "?"
                    evidence_lines.append(f"    {ent.value} (seen {ent.count}x, {first} to {last})")
                    if ent.contexts:
                        evidence_lines.append(f"      e.g. \"{ent.contexts[0][:120]}\"")

    evidence_lines.append(f"\nLast 20 raw lines:")
    for e in user_entries[-20:]:
        evidence_lines.append(f"  [{e.ts}] {e.raw[:200]}")

    evidence_text = "\n".join(evidence_lines)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[-max_chars:]

    system = (
        "You are an evidence extraction specialist. From the provided log data, extract and "
        "list all forensic artifacts: IP addresses, URLs, file paths, email addresses, hash values, "
        "usernames, and any indicators of compromise. For each artifact, note how many times it appears "
        "and the context. Structure your output as a categorized evidence inventory."
    )
    prompt = f"Extract all forensic evidence from this user's log data:\n\n{evidence_text}"

    try:
        out = call_llm_cached(llm_url, model, system, prompt, cache=cache,
                              spinner_msg="LLM extracting evidence")
        print(f"\n{'='*60}\nEVIDENCE EXTRACTION: {user}\n{'='*60}\n{out}")
    except Exception as exc:
        print(f"Evidence extraction failed: {exc}")


# ---------- NEW LLM commands -------------------------------------------------

def llm_search(entries: list[Entry], query: str, llm_url: str, model: str,
               max_chars: int = 12000, cache: LLMCache | None = None,
               top_k: int = 20) -> None:
    """Natural language semantic search: LLM finds relevant log lines."""
    if not entries:
        print("(no entries to search)")
        return
    lines = [e.raw for e in entries if e.raw]
    chunks = chunk_lines(lines, max_chars)
    system = (
        "You are a log search engine. Given a user's natural language query and a batch of log lines, "
        "return ONLY the line numbers (1-indexed) that are relevant to the query, one per line. "
        "Do NOT explain. Format: just numbers, e.g.:\n3\n7\n12\n"
        "If no lines are relevant, return: NONE"
    )
    all_hits: set[int] = set()
    offset = 0
    for i, chunk in enumerate(chunks, 1):
        prompt = f"Query: {query}\n\nLog lines (numbered):\n"
        for j, ln in enumerate(chunk.split("\n"), 1):
            prompt += f"{offset + j}: {ln}\n"
        try:
            out = call_llm_cached(llm_url, model, system, prompt, cache=cache,
                                  spinner_msg=f"LLM searching chunk {i}/{len(chunks)}")
            for line in out.strip().split("\n"):
                line = line.strip()
                if line.isdigit():
                    all_hits.add(int(line))
        except Exception as exc:
            print(f"  [chunk {i}] error: {exc}", file=sys.stderr)
        offset += len(chunk.split("\n"))
    if not all_hits:
        print(f"\nNo results for: {query}")
        return
    all_hits = sorted(h for h in all_hits if 1 <= h <= len(entries))[:top_k]
    print(f"\nSearch: \"{query}\" ({len(all_hits)} results, top {top_k}):")
    for idx in all_hits:
        e = entries[idx - 1]
        ts = _fmt_dt(e.ts)
        user = e.user or "?"
        print(f"  [{idx:>5d}] {ts}  {user:>15s}  {e.raw[:250]}")


def llm_threat_assessment(entries: list[Entry], user: str, llm_url: str, model: str,
                          max_chars: int = 15000, cache: LLMCache | None = None) -> None:
    """LLM threat assessment: evaluates risk level of a user."""
    user_entries = [e for e in entries if line_matches_user(e, user)]
    if len(user_entries) < 5:
        print(f"(insufficient data for '{user}', need >=5 lines)")
        return
    profile = build_profile(user_entries, user)
    sentiment = user_sentiment(user_entries, user)
    anomalies = detect_behavioral_anomalies(entries, user)
    entity_catalog = build_entity_catalog(user_entries)
    edges = build_edge_graph(user_entries)

    evidence: list[str] = [
        f"THREAT ASSESSMENT REQUEST: {user}",
        f"Lines authored: {profile['authored']}",
        f"First/Last seen: {_fmt_dt(profile['first_ts'])} / {_fmt_dt(profile['last_ts'])}",
        f"Active days: {len(profile['by_day'])}",
        f"Peak hours: {_peak_hours(profile['by_hour'])}",
        f"Score means: {json.dumps(profile['score_means'], default=str)}",
    ]
    if sentiment:
        evidence.append(f"Sentiment: compound={sentiment['mean_compound']:.3f}, pos_rate={sentiment['pos_rate']:.1%}, neg_rate={sentiment['neg_rate']:.1%}")
    if anomalies:
        evidence.append(f"Anomalies detected: {len(anomalies)}")
        for a in sorted(anomalies, key=lambda x: abs(x.zscore), reverse=True)[:10]:
            evidence.append(f"  {a.metric}: z={a.zscore:+.2f} val={a.value:.1f}")
    if entity_catalog:
        for etype, ents in entity_catalog.items():
            if ents:
                vals = ", ".join(e.value for e in sorted(ents, key=lambda x: -x.count)[:5])
                evidence.append(f"  Entities ({etype}): {vals}")
    if edges:
        top_edges = edges.most_common(10)
        evidence.append(f"  Top interaction edges: {', '.join(f'{a}->{b}({w})' for (a,b),w in top_edges)}")
    evidence.append("\nRecent lines:")
    for e in user_entries[-40:]:
        evidence.append(f"  [{_fmt_dt(e.ts)}] {e.raw[:200]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are a threat intelligence analyst. Given behavioral evidence about a user, "
        "produce a structured threat assessment with:\n"
        "1. THREAT LEVEL: Low / Medium / High / Critical (with confidence %)\n"
        "2. INDICATORS: List specific behavioral signals that support the assessment\n"
        "3. TTPs: Tactics, techniques, and procedures observed\n"
        "4. RISK FACTORS: What makes this user potentially dangerous\n"
        "5. MITIGATING FACTORS: What reduces concern\n"
        "6. RECOMMENDATIONS: Specific actions to take\n"
        "Be evidence-based, cite concrete data points, and avoid speculation without basis."
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg=f"LLM threat assessment for {user}")
        print(f"\n{'='*80}\nTHREAT ASSESSMENT: {user}\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Threat assessment failed: {exc}")


def llm_bot_detection(entries: list[Entry], user: str, llm_url: str, model: str,
                      max_chars: int = 12000, cache: LLMCache | None = None) -> None:
    """LLM-based bot/automation detection for a user."""
    user_entries = [e for e in entries if line_matches_user(e, user)]
    if len(user_entries) < 10:
        print(f"(insufficient data for '{user}', need >=10 lines)")
        return
    profile = build_profile(user_entries, user)
    pol = pattern_of_life(user_entries, user)

    evidence: list[str] = [
        f"BOT DETECTION ANALYSIS: {user}",
        f"Total messages: {profile['authored']}",
        f"Active days: {len(profile['by_day'])}",
        f"Peak hours: {_peak_hours(profile['by_hour'])}",
        f"Consistency score: {pol.consistency_score:.2f}",
    ]
    hourly = [pol.hourly_profile.get(h, 0) for h in range(24)]
    evidence.append(f"Hourly distribution: {json.dumps({str(h): round(v, 3) for h, v in pol.hourly_profile.items()})}")
    evidence.append(f"\nMessage timing analysis:")
    if user_entries and all(e.ts for e in user_entries):
        sorted_e = sorted(user_entries, key=lambda e: e.ts)
        gaps = [(sorted_e[i+1].ts - sorted_e[i].ts).total_seconds() for i in range(len(sorted_e)-1)]
        if gaps:
            evidence.append(f"  Mean gap: {statistics.mean(gaps):.1f}s")
            evidence.append(f"  Median gap: {statistics.median(gaps):.1f}s")
            evidence.append(f"  Stdev gap: {statistics.pstdev(gaps):.1f}s")
            cv = statistics.pstdev(gaps) / (statistics.mean(gaps) or 1)
            evidence.append(f"  Coefficient of variation: {cv:.3f} (low CV = more regular = more bot-like)")
    evidence.append(f"\nScore profile: {json.dumps(profile['score_means'], default=str)}")
    evidence.append(f"\nSample messages (last 50):")
    for e in user_entries[-50:]:
        evidence.append(f"  [{_fmt_dt(e.ts)}] {e.raw[:200]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[-max_chars:]

    system = (
        "You are a bot detection specialist. Analyze the provided evidence and determine "
        "whether this user is likely a human, a bot, or a hybrid (human using automation tools).\n"
        "Consider: timing regularity, message content patterns, score profiles, activity hours, "
        "linguistic style, and response patterns.\n\n"
        "Output format:\n"
        "1. VERDICT: Human / Likely Human / Ambiguous / Likely Bot / Bot (with confidence %)\n"
        "2. BOT INDICATORS: Evidence suggesting automation\n"
        "3. HUMAN INDICATORS: Evidence suggesting human behavior\n"
        "4. AUTOMATION TYPE: If bot-like, what kind? (script, AI, macro, etc.)\n"
        "5. SOPHISTICATION: How well is the bot disguised?\n"
        "6. KEY EVIDENCE: Quote the most telling messages or patterns"
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg=f"LLM bot detection for {user}")
        print(f"\n{'='*80}\nBOT DETECTION: {user}\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Bot detection failed: {exc}")


def llm_deep_profile(entries: list[Entry], user: str, llm_url: str, model: str,
                     max_chars: int = 15000, cache: LLMCache | None = None) -> None:
    """Comprehensive psychological/behavioral profile beyond basic analysis."""
    user_entries = [e for e in entries if line_matches_user(e, user)]
    if len(user_entries) < 10:
        print(f"(insufficient data for '{user}', need >=10 lines)")
        return
    profile = build_profile(user_entries, user)
    sentiment = user_sentiment(user_entries, user)
    topics = user_topics(user_entries, user)
    pol = pattern_of_life(user_entries, user)
    recurrences = detect_recurrence(user_entries, user)
    churn = predict_churn(user_entries, user)
    threads = build_thread_for_user(user_entries, user)

    evidence: list[str] = [
        f"DEEP BEHAVIORAL PROFILE: {user}",
        "",
        "=== ACTIVITY METRICS ===",
        f"Authored: {profile['authored']}, Mentioned: {profile['mentioned_by_others']}",
        f"Active days: {len(profile['by_day'])}, Peak: {_peak_hours(profile['by_hour'])}",
        f"Score means: {json.dumps(profile['score_means'], default=str)}",
        f"Mean msg length: {_fmt_num(profile['msg_len_mean'])}",
        "",
        "=== SENTIMENT ===",
    ]
    if sentiment:
        evidence.append(f"Compound: {sentiment['mean_compound']:.3f}, Pos: {sentiment['pos_rate']:.1%}, Neg: {sentiment['neg_rate']:.1%}")
        evidence.append(f"Agreement rate: {sentiment['agree_rate']:.1%}")
    evidence.append("")
    evidence.append("=== TOPICS ===")
    if topics.get("keywords"):
        evidence.append(f"Keywords: {', '.join(kw for kw, _ in topics['keywords'][:10])}")
    if topics.get("bigrams"):
        evidence.append(f"Bigrams: {', '.join(bg for bg, _ in topics['bigrams'][:5])}")
    evidence.append("")
    evidence.append("=== PATTERN OF LIFE ===")
    evidence.append(f"Consistency: {pol.consistency_score:.2f}, Peak hour: {pol.peak_hour}")
    evidence.append(f"Quiet hours: {pol.quiet_hours}")
    evidence.append("")
    evidence.append("=== RECURRENCE ===")
    for r in recurrences:
        evidence.append(f"  [{r.pattern_type}] confidence={r.confidence:.0%}: {r.description}")
    evidence.append("")
    evidence.append("=== CHURN RISK ===")
    evidence.append(f"Risk: {churn.risk_score:.2f}, Factors: {', '.join(churn.factors)}")
    evidence.append("")
    evidence.append("=== SOCIAL GRAPH ===")
    reply_targets = Counter()
    for _, tgt in threads:
        if tgt:
            reply_targets[tgt] += 1
    if reply_targets:
        for tgt, cnt in reply_targets.most_common(10):
            evidence.append(f"  Replies to {tgt}: {cnt}")
    evidence.append("")
    evidence.append("=== SAMPLE MESSAGES ===")
    for e in user_entries[-60:]:
        evidence.append(f"  [{_fmt_dt(e.ts)}] {e.raw[:200]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are an expert behavioral psychologist and data analyst. Create a comprehensive "
        "psychological profile based on the provided log evidence. Structure your analysis:\n\n"
        "1. PERSONALITY TRAITS: Big Five indicators (Openness, Conscientiousness, Extraversion, "
        "   Agreeableness, Neuroticism) with evidence\n"
        "2. COMMUNICATION STYLE: Direct/indirect, formal/casual, verbose/concise, emotional/rational\n"
        "3. SOCIAL ROLE: Leader, follower, mediator, instigator, lurker, expert, novice\n"
        "4. MOTIVATION DRIVERS: What seems to drive their participation?\n"
        "5. COGNITIVE PATTERNS: Problem-solving style, learning patterns, expertise areas\n"
        "6. EMOTIONAL REGULATION: How they handle stress, conflict, praise, criticism\n"
        "7. RELATIONSHIP DYNAMICS: How they interact with different people\n"
        "8. BEHAVIORAL SHIFTS: Any notable changes over time\n"
        "9. UNIQUE IDENTIFIERS: Distinctive patterns that would help identify this person\n"
        "10. PREDICTIONS: Likely future behavior based on current trajectory\n\n"
        "Be specific, cite evidence, and avoid overconfident claims."
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg=f"LLM deep profiling {user}")
        print(f"\n{'='*80}\nDEEP BEHAVIORAL PROFILE: {user}\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Deep profiling failed: {exc}")


def llm_insider_threat(entries: list[Entry], user: str, llm_url: str, model: str,
                       max_chars: int = 15000, cache: LLMCache | None = None) -> None:
    """Insider threat analysis: data exfiltration, policy violations, privilege abuse."""
    user_entries = [e for e in entries if line_matches_user(e, user)]
    if len(user_entries) < 5:
        print(f"(insufficient data for '{user}')")
        return
    entity_catalog = build_entity_catalog(user_entries)
    profile = build_profile(user_entries, user)
    sentiment = user_sentiment(user_entries, user)
    anomalies = detect_anomalies(entries, user)

    evidence: list[str] = [
        f"INSIDER THREAT ANALYSIS: {user}",
        f"Authored lines: {profile['authored']}",
        f"Time range: {_fmt_dt(profile['first_ts'])} to {_fmt_dt(profile['last_ts'])}",
        f"Score means: {json.dumps(profile['score_means'], default=str)}",
    ]
    if sentiment:
        evidence.append(f"Sentiment: compound={sentiment['mean_compound']:.3f}")
    if anomalies:
        evidence.append(f"Anomalies: {len(anomalies)}")
        for a in sorted(anomalies, key=lambda x: abs(x.zscore), reverse=True)[:8]:
            evidence.append(f"  {a.metric}: z={a.zscore:+.2f}")
    if entity_catalog:
        evidence.append("\nExtracted entities:")
        for etype, ents in entity_catalog.items():
            if ents:
                for ent in sorted(ents, key=lambda x: -x.count)[:8]:
                    evidence.append(f"  {etype}: {ent.value} ({ent.count}x)")
                    if ent.contexts:
                        evidence.append(f"    e.g. {ent.contexts[0][:150]}")
    evidence.append("\nAll log lines:")
    for e in user_entries[-80:]:
        evidence.append(f"  [{_fmt_dt(e.ts)}] {e.raw[:250]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are an insider threat analyst. Analyze the provided log data for signs of "
        "malicious insider activity. Look for:\n"
        "- Data exfiltration indicators (unusual file access, large transfers, external sharing)\n"
        "- Privilege abuse (accessing resources outside normal scope)\n"
        "- Policy violations (bypassing controls, unauthorized tools)\n"
        "- Disgruntled employee signals (negative sentiment, threats, job search activity)\n"
        "- Unusual timing (access at odd hours, after termination notice)\n"
        "- Reconnaissance behavior (probing, enumeration, testing boundaries)\n\n"
        "Output:\n"
        "1. RISK LEVEL: None / Low / Medium / High / Critical\n"
        "2. INDICATORS FOUND: Specific evidence for each category\n"
        "3. ENTITIES OF CONCERN: IPs, URLs, files, emails that are suspicious\n"
        "4. TIMELINE OF CONCERN: When did suspicious activity occur?\n"
        "5. FALSE POSITIVE CHECK: What benign explanations exist?\n"
        "6. RECOMMENDED ACTIONS: Immediate and long-term responses"
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg=f"LLM insider threat analysis for {user}")
        print(f"\n{'='*80}\nINSIDER THREAT ANALYSIS: {user}\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Insider threat analysis failed: {exc}")


def llm_social_dynamics(entries: list[Entry], llm_url: str, model: str,
                        max_chars: int = 15000, cache: LLMCache | None = None,
                        top_users: int = 15) -> None:
    """LLM analysis of social dynamics, influence patterns, and group structures."""
    active = [e for e in entries if e.user]
    if len(active) < 20:
        print("(insufficient data, need >=20 entries)")
        return
    user_counts = Counter(e.user for e in active)
    candidates = [u for u, _ in user_counts.most_common(top_users)]
    edges = build_edge_graph(active)
    profiles = {u: build_profile(active, u) for u in candidates}

    evidence: list[str] = [
        f"SOCIAL DYNAMICS ANALYSIS ({len(candidates)} users, {len(edges)} edges)",
        "",
        "=== USER ACTIVITY ===",
    ]
    for u in candidates:
        p = profiles[u]
        evidence.append(f"  {u}: lines={p['authored']}, days={len(p['by_day'])}, "
                        f"peak={_peak_hours(p['by_hour'])}, "
                        f"scores={json.dumps(p['score_means'], default=str)}")
    evidence.append("")
    evidence.append("=== INTERACTION EDGES (top 30) ===")
    for (a, b), w in edges.most_common(30):
        evidence.append(f"  {a} -> {b}: {w}")
    evidence.append("")
    evidence.append("=== SAMPLE CONVERSATIONS ===")
    sample_entries = sorted(active, key=lambda e: e.ts)[-200:]
    for e in sample_entries:
        evidence.append(f"  [{_fmt_dt(e.ts)}] {e.user}: {(e.text or e.raw)[:200]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are a social network analyst. Analyze the group dynamics in this log data:\n\n"
        "1. POWER STRUCTURE: Who are the leaders, influencers, and peripheral members?\n"
        "2. COMMUNITY CLUSTERS: Are there subgroups? Who bridges them?\n"
        "3. INFORMATION FLOW: How does information spread? Who are the hubs?\n"
        "4. SOCIAL ROLES: Identify helpers, askers, trolls, experts, lurkers, mediators\n"
        "5. CONFLICT PATTERNS: Any interpersonal tensions or disagreements?\n"
        "6. COHESION: How tight-knit is the group? Any isolated members?\n"
        "7. INFLUENCE CHAINS: Who influences whom? Trace key influence paths\n"
        "8. HEALTH ASSESSMENT: Overall group health and sustainability\n\n"
        "Cite specific interaction patterns and metrics as evidence."
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg="LLM analyzing social dynamics")
        print(f"\n{'='*80}\nSOCIAL DYNAMICS ANALYSIS\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Social dynamics analysis failed: {exc}")


def llm_incident_timeline(entries: list[Entry], llm_url: str, model: str,
                           max_chars: int = 15000, cache: LLMCache | None = None,
                           query: str = "") -> None:
    """LLM incident timeline reconstruction: finds and narrates a security incident."""
    active = sorted([e for e in entries if e.ts], key=lambda e: e.ts)
    if not active:
        print("(no timestamped entries)")
        return
    evidence: list[str] = [
        f"INCIDENT TIMELINE RECONSTRUCTION",
        f"Time range: {active[0].ts} to {active[-1].ts}",
        f"Total entries: {len(active)}",
    ]
    if query:
        evidence.append(f"Focus query: {query}")
    evidence.append("")
    evidence.append("=== ERROR/ALERT ENTRIES ===")
    error_entries = [e for e in active if e.level and e.level.upper() in {"ERROR", "CRITICAL", "FATAL", "HIGH", "SUS", "SUSPICIOUS", "WARN", "WARNING"}
                     or ERROR_TOKENS.search(e.text or "")]
    for e in error_entries[:50]:
        evidence.append(f"  [{e.ts}] [{e.level or '?'}] {e.user or '?'}: {(e.text or e.raw)[:250]}")
    if not error_entries:
        evidence.append("  (none found)")
    evidence.append("")
    evidence.append("=== FULL CHRONOLOGICAL LOG (last 300 entries) ===")
    for e in active[-300:]:
        evidence.append(f"  [{e.ts}] [{e.level or '-'}] {e.user or '?'}: {(e.text or e.raw)[:200]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are an incident response analyst. Reconstruct the incident timeline from the "
        "provided log data. Produce:\n\n"
        "1. INCIDENT SUMMARY: What happened in 2-3 sentences\n"
        "2. TIMELINE: Chronological narrative with timestamps, key events, and phases\n"
        "   (Initial Access → Execution → Persistence → Lateral Movement → Impact)\n"
        "3. KEY ACTORS: Users/systems involved and their roles\n"
        "4. INDICATORS OF COMPROMISE: IPs, hashes, URLs, file paths\n"
        "5. IMPACT ASSESSMENT: What was affected?\n"
        "6. ROOT CAUSE: What enabled this incident?\n"
        "7. RECOMMENDATIONS: Containment, eradication, recovery steps\n\n"
        "If no incident is evident, state that clearly and describe what the logs do show."
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg="LLM reconstructing incident timeline")
        print(f"\n{'='*80}\nINCIDENT TIMELINE RECONSTRUCTION\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Incident timeline failed: {exc}")


def llm_topic_map(entries: list[Entry], llm_url: str, model: str,
                  max_chars: int = 12000, cache: LLMCache | None = None,
                  top_users: int = 10) -> None:
    """LLM topic map: shows what users discuss and how topics connect."""
    active = [e for e in entries if e.user]
    if len(active) < 20:
        print("(insufficient data)")
        return
    user_counts = Counter(e.user for e in active)
    candidates = [u for u, _ in user_counts.most_common(top_users)]

    evidence: list[str] = [f"TOPIC MAP ANALYSIS ({len(candidates)} users)"]
    for u in candidates:
        user_lines = [e.text or e.raw for e in active if e.user == u and (e.text or e.raw)]
        topics = user_topics([e for e in active if e.user == u], u)
        evidence.append(f"\n=== {u} ({len(user_lines)} messages) ===")
        if topics.get("keywords"):
            evidence.append(f"Keywords: {', '.join(f'{kw}({n})' for kw, n in topics['keywords'][:8])}")
        if topics.get("bigrams"):
            evidence.append(f"Bigrams: {', '.join(f'{bg}({n})' for bg, n in topics['bigrams'][:5])}")
        evidence.append("Sample messages:")
        for ln in user_lines[:15]:
            evidence.append(f"  {ln[:200]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are a topic modeling expert. Analyze the discussion topics across these users:\n\n"
        "1. TOPIC CLUSTERS: Identify 5-10 main discussion topics\n"
        "2. USER-TOPIC MATRIX: Which users engage with which topics?\n"
        "3. TOPIC EXPERTS: Who is the go-to person for each topic?\n"
        "4. CROSS-TOPIC BRIDGES: Users who connect different topic areas\n"
        "5. TOPIC EVOLUTION: How topics change over time (if timestamps available)\n"
        "6. GAPS: Important topics that are under-discussed\n"
        "7. TOPIC GRAPH: Draw a text-based graph showing topic connections\n\n"
        "Use the format: TopicA <--UserX--> TopicB to show bridges."
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg="LLM building topic map")
        print(f"\n{'='*80}\nTOPIC MAP ANALYSIS\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Topic map analysis failed: {exc}")


def llm_compare_sessions(entries: list[Entry], user: str, llm_url: str, model: str,
                         max_chars: int = 12000, cache: LLMCache | None = None,
                         gap_minutes: int = 60) -> None:
    """Compare a user's behavior across different sessions/time periods."""
    sessions = detect_sessions(entries, user, gap_minutes)
    if len(sessions) < 2:
        print(f"(need >=2 sessions for '{user}', found {len(sessions)})")
        return
    evidence: list[str] = [f"SESSION COMPARISON: {user} ({len(sessions)} sessions)"]
    for i, sess in enumerate(sessions[:10], 1):
        dur = (sess.end - sess.start).total_seconds()
        sess_entries = [e for e in entries if e.user and e.user.lower() == user.lower()
                        and e.ts and sess.start <= e.ts <= sess.end]
        sentiment = user_sentiment(sess_entries, user) if sess_entries else {}
        evidence.append(f"\n=== Session {i}: {sess.start} - {sess.end} ({dur/60:.0f}min, {sess.line_count} lines) ===")
        if sentiment:
            evidence.append(f"  Sentiment: compound={sentiment.get('mean_compound', 0):.3f}")
        evidence.append("  Messages:")
        for e in sess_entries[:20]:
            evidence.append(f"    [{_fmt_dt(e.ts)}] {e.raw[:200]}")
    if len(sessions) > 10:
        evidence.append(f"\n...({len(sessions) - 10} more sessions)")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are a behavioral analyst comparing multiple sessions of the same user. Analyze:\n\n"
        "1. SESSION PATTERNS: How does behavior differ across sessions?\n"
        "2. MOOD SHIFTS: Changes in sentiment, tone, or engagement level\n"
        "3. TOPIC SHIFTS: Different subjects discussed in different sessions\n"
        "4. ACTIVITY RHYTHM: Session duration, intensity, and timing patterns\n"
        "5. PROGRESSION: Is there a learning curve or degradation over sessions?\n"
        "6. ANOMALOUS SESSIONS: Any session that stands out as unusual?\n"
        "7. PREDICTION: What would the next session likely look like?"
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg=f"LLM comparing sessions for {user}")
        print(f"\n{'='*80}\nSESSION COMPARISON: {user}\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Session comparison failed: {exc}")


def llm_baseline(entries: list[Entry], user: str, llm_url: str, model: str,
                 max_chars: int = 12000, cache: LLMCache | None = None) -> None:
    """Establish behavioral baseline and flag deviations."""
    user_entries = [e for e in entries if line_matches_user(e, user)]
    if len(user_entries) < 20:
        print(f"(insufficient data for '{user}', need >=20 lines)")
        return
    profile = build_profile(user_entries, user)
    pol = pattern_of_life(user_entries, user)
    sentiment = user_sentiment(user_entries, user)
    recurrences = detect_recurrence(user_entries, user)
    scores = collect_scores(user_entries, user)

    evidence: list[str] = [
        f"BEHAVIORAL BASELINE: {user}",
        f"Total observations: {len(user_entries)}",
        f"Active days: {len(profile['by_day'])}",
        f"Time span: {_fmt_dt(profile['first_ts'])} to {_fmt_dt(profile['last_ts'])}",
        "",
        "=== BASELINE METRICS ===",
        f"Hourly profile: {json.dumps({str(h): round(v, 3) for h, v in pol.hourly_profile.items()})}",
        f"Weekday profile: {json.dumps({str(d): round(v, 3) for d, v in pol.weekday_profile.items()})}",
        f"Peak hour: {pol.peak_hour}, Quiet hours: {pol.quiet_hours}",
        f"Consistency: {pol.consistency_score:.2f}",
    ]
    if sentiment:
        evidence.append(f"Sentiment baseline: compound={sentiment['mean_compound']:.3f}, pos_rate={sentiment['pos_rate']:.1%}")
    for k in SCORE_KEYS:
        vals = scores.get(k, [])
        if vals:
            evidence.append(f"Score {k}: mean={statistics.mean(vals):.3f}, stdev={statistics.pstdev(vals):.3f}, n={len(vals)}")
    for r in recurrences:
        evidence.append(f"Recurrence: [{r.pattern_type}] confidence={r.confidence:.0%}: {r.description}")
    evidence.append("")
    evidence.append("=== ALL MESSAGES (for deviation detection) ===")
    for e in user_entries[-100:]:
        evidence.append(f"  [{_fmt_dt(e.ts)}] {e.raw[:200]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are a behavioral baseline analyst. From the provided data:\n\n"
        "1. ESTABLISH BASELINE: Define 'normal' behavior for this user across:\n"
        "   - Activity timing (hours, days, session length)\n"
        "   - Communication style (tone, length, vocabulary)\n"
        "   - Score patterns (typical ranges)\n"
        "   - Social patterns (who they interact with, how often)\n"
        "2. DEVIATION THRESHOLDS: What would constitute a meaningful deviation?\n"
        "3. CURRENT DEVIATIONS: Are any messages outside the baseline?\n"
        "4. TREND ANALYSIS: Is the baseline itself shifting over time?\n"
        "5. ALERT RULES: Suggest 3-5 specific rules to monitor for anomalies\n\n"
        "Be precise with numbers and ranges."
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg=f"LLM establishing baseline for {user}")
        print(f"\n{'='*80}\nBEHAVIORAL BASELINE: {user}\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Baseline analysis failed: {exc}")


def llm_summary(entries: list[Entry], llm_url: str, model: str,
                max_chars: int = 15000, cache: LLMCache | None = None) -> None:
    """LLM summary of the entire log — key events, trends, anomalies."""
    active = [e for e in entries if e.user]
    if not active:
        print("(no entries)")
        return
    s = summarize(entries, 20)
    evidence: list[str] = [
        f"FULL LOG SUMMARY ({len(entries)} entries, {len({e.user for e in entries if e.user})} users)",
        f"Time range: {_fmt_dt(s['first_ts'])} to {_fmt_dt(s['last_ts'])}",
        f"Formats: {dict(s['formats'])}",
        f"Levels: {s['levels']}",
        "",
        "=== TOP USERS ===",
    ]
    for u, n in s["top_users"][:15]:
        evidence.append(f"  {u}: {n} messages")
    evidence.append("")
    evidence.append("=== TOP EVENTS ===")
    for ev, n in s["top_events"][:10]:
        evidence.append(f"  {ev}: {n}")
    if s.get("top_targets"):
        evidence.append("")
        evidence.append("=== TOP TARGETS ===")
        for t, n in s["top_targets"][:10]:
            evidence.append(f"  {t}: {n}")
    evidence.append("")
    evidence.append("=== HOURLY ACTIVITY ===")
    for h, n in s["by_hour"].items():
        evidence.append(f"  {h:02d}: {n}")
    if s["errors"]:
        evidence.append("")
        evidence.append("=== ERRORS ===")
        for err in s["errors"][:15]:
            evidence.append(f"  {err[:200]}")
    evidence.append("")
    evidence.append("=== RECENT MESSAGES ===")
    for e in sorted(active, key=lambda x: x.ts or datetime.min)[-80:]:
        evidence.append(f"  [{_fmt_dt(e.ts)}] {e.user}: {(e.text or e.raw)[:200]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are a senior log analyst. Provide a comprehensive executive summary of this log:\n\n"
        "1. OVERVIEW: What is this log? What system/community does it represent?\n"
        "2. KEY EVENTS: The 5-10 most significant events or patterns\n"
        "3. USER LANDSCAPE: Who are the main actors and their roles?\n"
        "4. TRENDS: Activity patterns, growth, decline, shifts\n"
        "5. ANOMALIES: Anything unusual or noteworthy\n"
        "6. ERRORS/ISSUES: Recurring problems or critical failures\n"
        "7. HEALTH ASSESSMENT: Overall system/community health\n"
        "8. RECOMMENDATIONS: Top 3 actions to take"
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg="LLM summarizing entire log")
        print(f"\n{'='*80}\nFULL LOG SUMMARY\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Log summary failed: {exc}")


def llm_replay(entries: list[Entry], user: str, llm_url: str, model: str,
               max_chars: int = 12000, cache: LLMCache | None = None) -> None:
    """LLM narrates a user's activity as a chronological story."""
    user_entries = sorted([e for e in entries if line_matches_user(e, user) and e.ts], key=lambda e: e.ts)
    if not user_entries:
        print(f"(no timestamped data for '{user}')")
        return
    evidence: list[str] = [f"CHRONOLOGICAL REPLAY: {user}"]
    evidence.append(f"Time span: {_fmt_dt(user_entries[0].ts)} to {_fmt_dt(user_entries[-1].ts)}")
    evidence.append(f"Total messages: {len(user_entries)}")
    evidence.append("")
    for e in user_entries[:100]:
        evidence.append(f"  [{e.ts.strftime('%H:%M:%S')}] {e.raw[:250]}")
    if len(user_entries) > 100:
        evidence.append(f"\n...({len(user_entries) - 100} more messages)")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are a narrative analyst. Given a chronological log of a user's messages, "
        "tell their story as a flowing narrative. Cover:\n\n"
        "1. THE ARC: What was their journey? Beginning, middle, end\n"
        "2. KEY MOMENTS: Turning points, breakthroughs, conflicts\n"
        "3. EVOLUTION: How did their behavior/style change over time?\n"
        "4. RELATIONSHIPS: Who did they interact with and how?\n"
        "5. THEMES: What were they consistently focused on?\n\n"
        "Write it like a character study — engaging but evidence-based."
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg=f"LLM replaying {user}'s story")
        print(f"\n{'='*80}\nCHRONOLOGICAL REPLAY: {user}\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Replay failed: {exc}")


def llm_predict(entries: list[Entry], user: str, llm_url: str, model: str,
                max_chars: int = 12000, cache: LLMCache | None = None) -> None:
    """Predict next likely actions/behavior based on observed patterns."""
    user_entries = [e for e in entries if line_matches_user(e, user)]
    if len(user_entries) < 10:
        print(f"(insufficient data for '{user}', need >=10 lines)")
        return
    profile = build_profile(user_entries, user)
    pol = pattern_of_life(user_entries, user)
    sentiment = user_sentiment(user_entries, user)
    churn = predict_churn(user_entries, user)
    recurrences = detect_recurrence(user_entries, user)
    lc = analyze_lifecycle(user_entries, user)

    evidence: list[str] = [
        f"PREDICTION ANALYSIS: {user}",
        f"Authored: {profile['authored']}, Active days: {len(profile['by_day'])}",
        f"Lifecycle: trend={lc.activity_trend}, stages={len(lc.stages)}",
        f"Churn risk: {churn.risk_score:.2f} ({', '.join(churn.factors)})",
        f"Consistency: {pol.consistency_score:.2f}, Peak hour: {pol.peak_hour}",
    ]
    if sentiment:
        evidence.append(f"Sentiment: compound={sentiment['mean_compound']:.3f}, pos={sentiment['pos_rate']:.1%}, neg={sentiment['neg_rate']:.1%}")
    for r in recurrences:
        evidence.append(f"Recurrence: [{r.pattern_type}] {r.description}")
    evidence.append(f"\nScore means: {json.dumps(profile['score_means'], default=str)}")
    evidence.append(f"\nRecent messages (last 40):")
    for e in user_entries[-40:]:
        evidence.append(f"  [{_fmt_dt(e.ts)}] {e.raw[:200]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are a behavioral forecaster. Based on the evidence, predict this user's "
        "likely future behavior:\n\n"
        "1. SHORT-TERM (next 24-48h): What will they likely do next?\n"
        "2. MEDIUM-TERM (next week): Trends and trajectory\n"
        "3. LONG-TERM (next month): Where is this heading?\n"
        "4. RISK SCENARIOS: What could go wrong? (churn, escalation, burnout)\n"
        "5. POSITIVE SCENARIOS: What could go well? (growth, engagement, leadership)\n"
        "6. INTERVENTION POINTS: Where could action change the trajectory?\n\n"
        "Be specific and cite evidence. Give probability estimates."
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg=f"LLM predicting behavior for {user}")
        print(f"\n{'='*80}\nBEHAVIORAL PREDICTION: {user}\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Prediction failed: {exc}")


def llm_motive(entries: list[Entry], user: str, llm_url: str, model: str,
               max_chars: int = 12000, cache: LLMCache | None = None) -> None:
    """Analyze motivations, intent, and psychological drivers."""
    user_entries = [e for e in entries if line_matches_user(e, user)]
    if len(user_entries) < 10:
        print(f"(insufficient data for '{user}', need >=10 lines)")
        return
    profile = build_profile(user_entries, user)
    sentiment = user_sentiment(user_entries, user)
    topics = user_topics(user_entries, user)

    evidence: list[str] = [
        f"MOTIVATION ANALYSIS: {user}",
        f"Messages: {profile['authored']}, Score means: {json.dumps(profile['score_means'], default=str)}",
    ]
    if sentiment:
        evidence.append(f"Sentiment: compound={sentiment['mean_compound']:.3f}, agreement={sentiment['agree_rate']:.1%}")
    if topics.get("keywords"):
        evidence.append(f"Top keywords: {', '.join(f'{kw}({n})' for kw, n in topics['keywords'][:10])}")
    if topics.get("bigrams"):
        evidence.append(f"Top bigrams: {', '.join(f'{bg}({n})' for bg, n in topics['bigrams'][:5])}")
    evidence.append(f"\nAll messages:")
    for e in user_entries[-80:]:
        evidence.append(f"  [{_fmt_dt(e.ts)}] {e.raw[:200]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are a motivational psychologist analyzing behavioral data. Determine what drives "
        "this person's participation:\n\n"
        "1. PRIMARY MOTIVATORS: What core needs drive their behavior? (achievement, belonging, "
        "   power, curiosity, validation, altruism, etc.)\n"
        "2. GOAL ORIENTATION: What are they trying to accomplish?\n"
        "3. EMOTIONAL DRIVERS: What emotions fuel their engagement?\n"
        "4. COGNITIVE STYLE: How do they think and process information?\n"
        "5. SOCIAL NEEDS: What do they seek from others?\n"
        "6. FRUSTRATION POINTS: What triggers negative responses?\n"
        "7. REWARD SENSITIVITY: What reinforces their behavior?\n"
        "8. UNDERLYING INTENT: What's their deeper agenda (conscious or unconscious)?"
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg=f"LLM analyzing motives for {user}")
        print(f"\n{'='*80}\nMOTIVATION ANALYSIS: {user}\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Motivation analysis failed: {exc}")


def llm_relationship(entries: list[Entry], a: str, b: str, llm_url: str, model: str,
                     max_chars: int = 12000, cache: LLMCache | None = None) -> None:
    """Deep relationship analysis between two users."""
    a_entries = [e for e in entries if line_matches_user(e, a)]
    b_entries = [e for e in entries if line_matches_user(e, b)]
    interactions = [e for e in entries if line_is_interaction(e, a, b)]
    if not interactions and not a_entries and not b_entries:
        print(f"(no data for {a} or {b})")
        return
    pa = build_profile(a_entries, a) if a_entries else None
    pb = build_profile(b_entries, b) if b_entries else None
    edges = build_edge_graph(entries)
    a_to_b = edges.get((a, b), 0)
    b_to_a = edges.get((b, a), 0)

    evidence: list[str] = [f"RELATIONSHIP ANALYSIS: {a} <-> {b}"]
    evidence.append(f"Direct interactions: {len(interactions)}")
    evidence.append(f"Edge weights: {a} -> {b}: {a_to_b}, {b} -> {a}: {b_to_a}")
    if pa:
        evidence.append(f"\n{a}: lines={pa['authored']}, scores={json.dumps(pa['score_means'], default=str)}")
    if pb:
        evidence.append(f"{b}: lines={pb['authored']}, scores={json.dumps(pb['score_means'], default=str)}")
    evidence.append(f"\nInteraction log:")
    for e in interactions[:60]:
        evidence.append(f"  [{_fmt_dt(e.ts)}] {e.user}: {(e.text or e.raw)[:200]}")
    if not interactions:
        evidence.append("  (no direct interactions — analyzing parallel behavior)")
        evidence.append(f"\n{a}'s recent messages:")
        for e in a_entries[-20:]:
            evidence.append(f"  [{_fmt_dt(e.ts)}] {e.raw[:200]}")
        evidence.append(f"\n{b}'s recent messages:")
        for e in b_entries[-20:]:
            evidence.append(f"  [{_fmt_dt(e.ts)}] {e.raw[:200]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are a relationship analyst. Analyze the dynamic between these two people:\n\n"
        "1. RELATIONSHIP TYPE: Mentor/mentee, peers, rivals, collaborators, etc.\n"
        "2. POWER DYNAMIC: Who leads? Who follows? Is it balanced?\n"
        "3. TRUST LEVEL: How much do they trust each other?\n"
        "4. COMMUNICATION PATTERN: Frequency, tone, depth, reciprocity\n"
        "5. CONFLICT AREAS: Where do they disagree? How do they handle it?\n"
        "6. SYNERGY: Do they produce better outcomes together?\n"
        "7. DEPENDENCY: Is one dependent on the other?\n"
        "8. TRAJECTORY: Is the relationship strengthening, weakening, or stable?\n"
        "9. HIDDEN DYNAMICS: What's not being said? Subtext?"
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg=f"LLM analyzing {a} <-> {b} relationship")
        print(f"\n{'='*80}\nRELATIONSHIP ANALYSIS: {a} <-> {b}\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Relationship analysis failed: {exc}")


def llm_audit(entries: list[Entry], llm_url: str, model: str,
              max_chars: int = 15000, cache: LLMCache | None = None,
              policy: str = "") -> None:
    """Compliance audit against security policies or best practices."""
    active = [e for e in entries if e.user]
    if not active:
        print("(no entries)")
        return
    s = summarize(entries, 30)
    entity_catalog = build_entity_catalog(active)
    error_entries = [e for e in entries if e.level and e.level.upper() in {"ERROR", "CRITICAL", "FATAL", "HIGH", "SUS"}
                     or ERROR_TOKENS.search(e.text or "")]

    evidence: list[str] = [
        f"SECURITY COMPLIANCE AUDIT ({len(entries)} entries, {len({e.user for e in entries if e.user})} users)",
        f"Time range: {_fmt_dt(s['first_ts'])} to {_fmt_dt(s['last_ts'])}",
    ]
    if policy:
        evidence.append(f"Policy focus: {policy}")
    evidence.append("")
    evidence.append("=== LEVELS/SEVERITIES ===")
    evidence.append(json.dumps(s["levels"], indent=2))
    evidence.append("")
    evidence.append("=== ENTITIES ===")
    for etype, ents in entity_catalog.items():
        if ents:
            for ent in sorted(ents, key=lambda x: -x.count)[:5]:
                evidence.append(f"  {etype}: {ent.value} ({ent.count}x)")
    evidence.append("")
    evidence.append(f"=== ERRORS/ALERTS ({len(error_entries)} total) ===")
    for e in error_entries[:40]:
        evidence.append(f"  [{_fmt_dt(e.ts)}] [{e.level or '?'}] {e.user or '?'}: {(e.text or e.raw)[:200]}")
    evidence.append("")
    evidence.append("=== TOP USERS ===")
    for u, n in s["top_users"][:20]:
        evidence.append(f"  {u}: {n}")
    evidence.append("")
    evidence.append("=== SAMPLE MESSAGES ===")
    for e in sorted(active, key=lambda x: x.ts or datetime.min)[-100:]:
        evidence.append(f"  [{_fmt_dt(e.ts)}] {e.user}: {(e.text or e.raw)[:200]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are a security compliance auditor. Review the log data against industry best practices:\n\n"
        "1. ACCESS CONTROL: Any signs of unauthorized access or privilege escalation?\n"
        "2. DATA HANDLING: Evidence of sensitive data exposure or mishandling?\n"
        "3. AUTHENTICATION: Brute force attempts, credential issues?\n"
        "4. AUDIT TRAIL: Is logging adequate? Any gaps or tampering signs?\n"
        "5. ERROR HANDLING: Are errors properly handled or do they leak information?\n"
        "6. POLICY COMPLIANCE: General adherence to security policies" + (f" (focus: {policy})" if policy else "") + "\n"
        "7. VULNERABILITY INDICATORS: Signs of exploitation or misconfiguration?\n"
        "8. INCIDENT READINESS: Would the current logging support incident response?\n\n"
        "For each finding: severity (Critical/High/Medium/Low), evidence, recommendation."
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg="LLM running compliance audit")
        print(f"\n{'='*80}\nSECURITY COMPLIANCE AUDIT\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Audit failed: {exc}")


def llm_risk_score(entries: list[Entry], user: str, llm_url: str, model: str,
                   max_chars: int = 12000, cache: LLMCache | None = None) -> None:
    """Quantified 0-100 risk score with weighted factor breakdown."""
    user_entries = [e for e in entries if line_matches_user(e, user)]
    if len(user_entries) < 5:
        print(f"(insufficient data for '{user}')")
        return
    profile = build_profile(user_entries, user)
    sentiment = user_sentiment(user_entries, user)
    anomalies = detect_behavioral_anomalies(entries, user)
    entity_catalog = build_entity_catalog(user_entries)
    pol = pattern_of_life(user_entries, user)
    churn = predict_churn(user_entries, user)

    evidence: list[str] = [
        f"RISK SCORING: {user}",
        f"Messages: {profile['authored']}, Active days: {len(profile['by_day'])}",
        f"Score means: {json.dumps(profile['score_means'], default=str)}",
        f"Sentiment: compound={sentiment.get('mean_compound', 0):.3f}" if sentiment else "",
        f"Anomalies: {len(anomalies)}",
        f"Consistency: {pol.consistency_score:.2f}",
        f"Churn risk: {churn.risk_score:.2f}",
    ]
    if anomalies:
        for a in sorted(anomalies, key=lambda x: abs(x.zscore), reverse=True)[:10]:
            evidence.append(f"  {a.metric}: z={a.zscore:+.2f}")
    if entity_catalog:
        for etype, ents in entity_catalog.items():
            if ents:
                evidence.append(f"  {etype}: {', '.join(e.value for e in ents[:5])}")
    evidence.append(f"\nRecent messages:")
    for e in user_entries[-50:]:
        evidence.append(f"  [{_fmt_dt(e.ts)}] {e.raw[:200]}")

    evidence_text = "\n".join(evidence)
    if len(evidence_text) > max_chars:
        evidence_text = evidence_text[:max_chars // 3] + "\n...[TRUNCATED]...\n" + evidence_text[-(2 * max_chars // 3):]

    system = (
        "You are a risk analyst. Assign a 0-100 risk score based on the evidence. "
        "Break down the score into weighted factors:\n\n"
        "1. BEHAVIORAL RISK (0-25): Anomalies, pattern changes, unusual activity\n"
        "2. SENTIMENT RISK (0-25): Negativity, aggression, instability\n"
        "3. ENTITY RISK (0-25): Suspicious IPs, URLs, files, emails\n"
        "4. SCORE RISK (0-25): High heuristic/binary/classifier/LLM scores\n\n"
        "Output format:\n"
        "- OVERALL SCORE: X/100 (Low/Medium/High/Critical)\n"
        "- FACTOR BREAKDOWN: Each factor with score and evidence\n"
        "- TOP 3 RISK DRIVERS: What contributes most to the score\n"
        "- TREND: Increasing, decreasing, or stable risk\n"
        "- ACTION THRESHOLD: At what score should action be taken?"
    )
    try:
        out = call_llm_cached(llm_url, model, system, evidence_text, cache=cache,
                              spinner_msg=f"LLM computing risk score for {user}")
        print(f"\n{'='*80}\nRISK SCORE: {user}\n{'='*80}\n{out}\n")
    except Exception as exc:
        print(f"Risk scoring failed: {exc}")


# ---------- Statistical / Analytical -----------------------------------------

def compute_stats(entries: list[Entry], user: str | None = None) -> dict:
    """Full statistical summary for scores, msg lengths, gaps."""
    filtered = [e for e in entries if line_matches_user(e, user)] if user else entries
    if not filtered:
        return {}
    scores = collect_scores(filtered, user)
    msg_lens: list[int] = []
    for e in filtered:
        s = _scores_from_raw(e.raw)
        if isinstance(s.get("msg_len"), int):
            msg_lens.append(s["msg_len"])
        elif s.get("msg"):
            msg_lens.append(len(str(s["msg"])))

    def _stats(vals: list[float], label: str) -> dict:
        if not vals:
            return {"label": label, "n": 0}
        s = sorted(vals)
        return {
            "label": label, "n": len(vals),
            "mean": statistics.mean(vals),
            "median": statistics.median(vals),
            "stdev": statistics.pstdev(vals) if len(vals) > 1 else 0,
            "min": min(vals), "max": max(vals),
            "p10": s[int(len(s) * 0.1)],
            "p25": s[int(len(s) * 0.25)],
            "p75": s[min(int(len(s) * 0.75), len(s) - 1)],
            "p90": s[min(int(len(s) * 0.9), len(s) - 1)],
        }

    result: dict[str, dict] = {}
    for k, vals in scores.items():
        result[k] = _stats(vals, k)
    result["msg_len"] = _stats(msg_lens, "msg_len")

    if len(filtered) >= 2 and all(e.ts for e in filtered):
        sorted_e = sorted(filtered, key=lambda e: e.ts)
        gaps = [(sorted_e[i+1].ts - sorted_e[i].ts).total_seconds() for i in range(len(sorted_e)-1)]
        result["gap_seconds"] = _stats(gaps, "gap_seconds")

    return result


def print_stats(stats: dict, user: str | None = None) -> None:
    label = f" for '{user}'" if user else " (all users)"
    print(f"\nStatistical summary{label}:")
    print(f"  {'Metric':<12s} {'n':>7s} {'mean':>8s} {'median':>8s} {'stdev':>8s} {'min':>8s} {'p25':>8s} {'p75':>8s} {'max':>8s}")
    print(f"  {'-'*12} {'-'*7} {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*8} {'-'*8}")
    for key in (*SCORE_KEYS, "msg_len", "gap_seconds"):
        s = stats.get(key)
        if not s or s.get("n", 0) == 0:
            continue
        print(f"  {s['label']:<12s} {s['n']:>7d} {s['mean']:>8.3f} {s['median']:>8.3f} "
              f"{s['stdev']:>8.3f} {s['min']:>8.3f} {s.get('p25', 0):>8.3f} "
              f"{s.get('p75', 0):>8.3f} {s['max']:>8.3f}")


def word_frequency(entries: list[Entry], top_n: int = 50,
                   extra_stopwords: set[str] | None = None) -> list[tuple[str, int]]:
    """Word/token frequency analysis across all logs."""
    counter: Counter = Counter()
    stops = set(STOPWORDS)
    if extra_stopwords:
        stops |= extra_stopwords
    stops |= {str(k) for k in SCORE_KEYS}
    token_re = re.compile(r"[A-Za-z][A-Za-z0-9_\-']{2,}")
    for e in entries:
        text = e.text or e.raw or ""
        for tok in token_re.findall(text.lower()):
            tok = tok.strip("'")
            if tok not in stops and len(tok) > 2:
                counter[tok] += 1
    return counter.most_common(top_n)


def print_word_frequency(freq: list[tuple[str, int]], top_n: int = 50) -> None:
    print(f"\nTop word frequencies ({len(freq)} shown):")
    max_count = freq[0][1] if freq else 1
    for word, count in freq[:top_n]:
        bar = "█" * int(40 * count / max_count)
        print(f"  {word:<20s} {count:>7d}  {bar}")


def user_cooccurrence(entries: list[Entry], window_minutes: int = 5,
                      top_n: int = 30) -> list[tuple[str, str, int]]:
    """Which users appear together most often in same time windows."""
    active = sorted([e for e in entries if e.user and e.ts], key=lambda e: e.ts)
    if not active:
        return []
    pair_counter: Counter = Counter()
    for i, e in enumerate(active):
        window_end = e.ts + timedelta(minutes=window_minutes)
        seen: set[str] = {e.user.lower()}
        for j in range(i + 1, len(active)):
            if active[j].ts > window_end:
                break
            if active[j].user.lower() not in seen:
                pair = tuple(sorted([e.user, active[j].user]))
                pair_counter[pair] += 1
                seen.add(active[j].user.lower())
    return [(a, b, c) for (a, b), c in pair_counter.most_common(top_n)]


def print_cooccurrence(pairs: list[tuple[str, str, int]]) -> None:
    if not pairs:
        print("(no co-occurrences)")
        return
    print(f"\nUser co-occurrences (shared time windows):")
    max_count = pairs[0][2] if pairs else 1
    for a, b, count in pairs[:30]:
        bar = "█" * int(30 * count / max_count)
        print(f"  {a:<20s} + {b:<20s}  {count:>5d}  {bar}")


def heatmap_user(entries: list[Entry], top_n: int = 20) -> None:
    """2D heatmap: users (rows) × hours (columns)."""
    users = Counter(e.user for e in entries if e.user).most_common(top_n)
    if not users:
        print("(no users)")
        return
    grid: dict[str, list[int]] = {}
    for u, _ in users:
        hourly: Counter = Counter()
        for e in entries:
            if e.user == u and e.ts:
                hourly[e.ts.hour] += 1
        grid[u] = [hourly.get(h, 0) for h in range(24)]
    max_val = max(v for row in grid.values() for v in row) or 1
    glyphs = " ░▒▓█"
    print(f"\nUser × Hour heatmap ({len(users)} users, 24 hours):")
    header = "       " + " ".join(f"{h:2d}" for h in range(24))
    print(header)
    print("       " + "-" * 71)
    for u, _ in users:
        row = grid[u]
        cells = "".join(glyphs[min(int(v / max_val * 4), 4)] for v in row)
        print(f"  {u[:15]:<15s} {cells}")


def log_coverage(entries: list[Entry]) -> dict:
    """Log coverage analysis — density, gaps, time range completeness."""
    ts_entries = sorted([e for e in entries if e.ts], key=lambda e: e.ts)
    if not ts_entries:
        return {"status": "no timestamps"}
    first, last = ts_entries[0].ts, ts_entries[-1].ts
    span_hours = (last - first).total_seconds() / 3600
    gaps = [(ts_entries[i+1].ts - ts_entries[i].ts).total_seconds() for i in range(len(ts_entries)-1)]
    big_gaps = [g for g in gaps if g > 3600]
    by_day = Counter(e.ts.date() for e in ts_entries)
    date_range = (last.date() - first.date()).days + 1
    return {
        "first": first, "last": last,
        "span_hours": round(span_hours, 1),
        "total_entries": len(entries),
        "ts_entries": len(ts_entries),
        "density_per_hour": round(len(ts_entries) / max(span_hours, 0.01), 1),
        "gaps_over_1h": len(big_gaps),
        "largest_gap_hours": round(max(gaps) / 3600, 1) if gaps else 0,
        "active_days": len(by_day),
        "date_range_days": date_range,
        "coverage_pct": round(len(by_day) / max(date_range, 1) * 100, 1),
    }


def print_coverage(cov: dict) -> None:
    if cov.get("status") == "no timestamps":
        print("(no timestamps for coverage analysis)")
        return
    print(f"\nLog coverage analysis:")
    print(f"  Time range:       {cov['first']} → {cov['last']}")
    print(f"  Span:             {cov['span_hours']:.1f} hours ({cov['date_range_days']} days)")
    print(f"  Total entries:    {cov['total_entries']}")
    print(f"  Timestamped:      {cov['ts_entries']}")
    print(f"  Density:          {cov['density_per_hour']} entries/hour")
    print(f"  Active days:      {cov['active_days']} / {cov['date_range_days']} ({cov['coverage_pct']}%)")
    print(f"  Gaps > 1 hour:    {cov['gaps_over_1h']}")
    print(f"  Largest gap:      {cov['largest_gap_hours']:.1f} hours")


# ---------- Export / Integration --------------------------------------------

def export_graphml(edges: Counter, path: str) -> None:
    """Export interaction graph as GraphML for Gephi/network analysis."""
    nodes: set[str] = set()
    for (a, b) in edges:
        nodes.add(a)
        nodes.add(b)
    with open(path, "w", encoding="utf-8") as f:
        f.write('<?xml version="1.0" encoding="UTF-8"?>\n')
        f.write('<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n')
        f.write('  <key id="weight" for="edge" attr.name="weight" attr.type="int"/>\n')
        f.write('  <graph id="interactions" edgedefault="directed">\n')
        for node in sorted(nodes):
            f.write(f'    <node id="{html_mod.escape(node)}"/>\n')
        for (a, b), w in edges.most_common():
            f.write(f'    <edge source="{html_mod.escape(a)}" target="{html_mod.escape(b)}">\n')
            f.write(f'      <data key="weight">{w}</data>\n')
            f.write(f'    </edge>\n')
        f.write('  </graph>\n</graphml>\n')
    print(f"GraphML exported to {path} ({len(nodes)} nodes, {len(edges)} edges)")


def merge_logs(paths: list[str], out_path: str) -> int:
    """Merge multiple log files chronologically."""
    all_entries: list[Entry] = []
    for p in paths:
        try:
            all_entries.extend(iter_entries(p))
        except FileNotFoundError:
            print(f"File not found: {p}", file=sys.stderr)
    all_entries.sort(key=lambda e: e.ts or datetime.min)
    with open(out_path, "w", encoding="utf-8") as f:
        for e in all_entries:
            f.write(e.raw + "\n")
    print(f"Merged {len(all_entries)} entries from {len(paths)} files → {out_path}")
    return len(all_entries)


def random_sample(entries: list[Entry], n: int) -> list[Entry]:
    """Random sample of N entries."""
    import random
    if n >= len(entries):
        return entries
    return random.sample(entries, n)


# ---------- Operational ------------------------------------------------------

def last_seen(entries: list[Entry], user: str | None = None, top_n: int = 20) -> None:
    """When was each user (or specific user) last active."""
    if user:
        u = user.lower()
        user_entries = [e for e in entries if e.user and e.user.lower() == u and e.ts]
        if not user_entries:
            print(f"(no data for '{user}')")
            return
        latest = max(user_entries, key=lambda e: e.ts)
        print(f"\nLast seen for '{user}':")
        print(f"  {_fmt_dt(latest.ts)}  ({(datetime.now() - latest.ts).days}d ago)")
        print(f"  {latest.raw[:200]}")
    else:
        latest_per_user: dict[str, Entry] = {}
        for e in entries:
            if e.user and e.ts:
                u = e.user
                if u not in latest_per_user or e.ts > latest_per_user[u].ts:
                    latest_per_user[u] = e
        sorted_users = sorted(latest_per_user.items(), key=lambda x: -x[1].ts.timestamp())
        print(f"\nLast seen (top {min(top_n, len(sorted_users))} users):")
        print(f"  {'User':<25s} {'Last seen':<20s} {'Ago':<10s} {'Message'}")
        print(f"  {'-'*25} {'-'*20} {'-'*10} {'-'*40}")
        for u, e in sorted_users[:top_n]:
            ago = (datetime.now() - e.ts).total_seconds()
            if ago < 3600:
                ago_str = f"{ago/60:.0f}m"
            elif ago < 86400:
                ago_str = f"{ago/3600:.1f}h"
            else:
                ago_str = f"{ago/86400:.0f}d"
            print(f"  {u:<25s} {_fmt_dt(e.ts):<20s} {ago_str:<10s} {(e.text or e.raw)[:60]}")


def whois(entries: list[Entry], user: str) -> None:
    """One-command dump: profile + sentiment + anomalies + edges for a user."""
    user_entries = [e for e in entries if line_matches_user(e, user)]
    if not user_entries:
        print(f"(no data for '{user}')")
        return
    profile = build_profile(user_entries, user)
    sentiment = user_sentiment(user_entries, user)
    anomalies = detect_anomalies(entries, user)
    edges = build_edge_graph(user_entries)
    pol = pattern_of_life(user_entries, user)
    churn = predict_churn(user_entries, user)

    print(f"\n{'='*60}")
    print(f"WHOIS: {user}")
    print(f"{'='*60}")
    print(f"  Authored: {profile['authored']}  |  Mentioned: {profile['mentioned_by_others']}")
    print(f"  First seen: {_fmt_dt(profile['first_ts'])}")
    print(f"  Last seen:  {_fmt_dt(profile['last_ts'])}")
    print(f"  Active days: {len(profile['by_day'])}  |  Peak: {_peak_hours(profile['by_hour'])}")
    print(f"  Top channels: {_top_str(profile['channels'], 3) or '—'}")
    print(f"  Flags: {_top_str(profile['flags'], 4) or '—'}")
    print(f"  Score means: heu={_fmt_score(profile['score_means']['heu'])} "
          f"bino={_fmt_score(profile['score_means']['bino'])} "
          f"cls={_fmt_score(profile['score_means']['cls'])} "
          f"llama={_fmt_score(profile['score_means']['llama'])}")
    if sentiment:
        print(f"  Sentiment: compound={sentiment['mean_compound']:.3f} "
              f"pos={sentiment['pos_rate']:.1%} neg={sentiment['neg_rate']:.1%}")
    if anomalies:
        print(f"  Anomalies: {len(anomalies)} (top: {anomalies[0].metric} z={anomalies[0].zscore:+.2f})")
    if edges:
        top_edges = edges.most_common(5)
        print(f"  Top edges: {', '.join(f'{a}->{b}({w})' for (a,b),w in top_edges)}")
    print(f"  Pattern consistency: {pol.consistency_score:.2f}  |  Peak hour: {pol.peak_hour}")
    level = "HIGH" if churn.risk_score > 0.6 else "MEDIUM" if churn.risk_score > 0.3 else "LOW"
    print(f"  Churn risk: {level} ({churn.risk_score:.2f})")


def diff_time(entries: list[Entry], since_str: str, until_str: str) -> None:
    """Compare activity in two time periods."""
    since_a = parse_iso_arg(since_str)
    until_a = parse_iso_arg(until_str)
    if not since_a or not until_a:
        print("Could not parse dates. Use ISO format or '5h ago'.")
        return
    span_a = (until_a - since_a).total_seconds()
    since_b = since_a - timedelta(seconds=span_a)
    until_b = since_a
    period_a = apply_time_filter(entries, since_a, until_a)
    period_b = apply_time_filter(entries, since_b, until_b)
    sa = summarize(period_a, 15)
    sb = summarize(period_b, 15)
    print(f"\nTime comparison:")
    print(f"  Period A: {since_a} → {until_a} ({sa['total']} entries)")
    print(f"  Period B: {since_b} → {until_b} ({sb['total']} entries)")
    delta = sa['total'] - sb['total']
    print(f"  Δ entries: {delta:+d} ({delta/max(sb['total'],1)*100:+.0f}%)")
    a_users = dict(sa["top_users"])
    b_users = dict(sb["top_users"])
    all_users = set(a_users) | set(b_users)
    deltas = sorted(((u, a_users.get(u, 0) - b_users.get(u, 0)) for u in all_users), key=lambda x: -abs(x[1]))
    print(f"\n  Top user deltas (A - B):")
    for u, d in deltas[:15]:
        print(f"    {d:+6d}  {u}")


def top_words(entries: list[Entry], top_n: int = 50) -> None:
    """Top N words/tokens across all log text."""
    freq = word_frequency(entries, top_n)
    print_word_frequency(freq, top_n)


# ---------- exports ---------------------------------------------------------

def serialize_profile(profile: dict, sample_cap: int = 200) -> dict:
    out = dict(profile)
    out["channels"] = dict(profile["channels"])
    out["flags"] = dict(profile["flags"])
    out["first_ts"] = profile["first_ts"].isoformat() if profile["first_ts"] else None
    out["last_ts"] = profile["last_ts"].isoformat() if profile["last_ts"] else None
    out["samples"] = profile["samples"][:sample_cap]
    return out


def serialize_summary(summary: dict) -> dict:
    out = dict(summary)
    out["formats"] = dict(summary["formats"])
    out["first_ts"] = summary["first_ts"].isoformat() if summary["first_ts"] else None
    out["last_ts"] = summary["last_ts"].isoformat() if summary["last_ts"] else None
    return out


def export_profile_json(profile: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(serialize_profile(profile), f, indent=2, default=str)


def export_profile_csv(profile: dict, path: str) -> None:
    rows: list[tuple[str, object]] = [
        ("user", profile["user"]),
        ("authored", profile["authored"]),
        ("mentioned_by_others", profile["mentioned_by_others"]),
        ("first_ts", profile["first_ts"].isoformat() if profile["first_ts"] else ""),
        ("last_ts", profile["last_ts"].isoformat() if profile["last_ts"] else ""),
        ("active_days", len(profile["by_day"])),
        ("msg_len_mean", profile["msg_len_mean"] if profile["msg_len_mean"] is not None else ""),
    ]
    for k in SCORE_KEYS:
        v = profile["score_means"].get(k)
        rows.append((f"{k}_mean", v if v is not None else ""))
    rows.append(("top_channels", _top_str(profile["channels"], 5)))
    rows.append(("flags", _top_str(profile["flags"], 5)))
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["metric", "value"])
        for k, v in rows:
            w.writerow([k, v])


def export_summary_json(summary: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(serialize_summary(summary), f, indent=2, default=str)


def export_edges_csv(edges: Counter, path: str) -> None:
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["source", "target", "weight"])
        for (a, b), n in edges.most_common():
            w.writerow([a, b, n])


def export_edges_dot(edges: Counter, path: str, top: int = 200) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write("digraph chat {\n")
        f.write('  rankdir=LR;\n  node [shape=box];\n')
        for (a, b), n in edges.most_common(top):
            pen = 1.0 + min(n, 10) / 2.0
            f.write(f'  "{a}" -> "{b}" [label="{n}", penwidth={pen:.1f}];\n')
        f.write("}\n")


# ---------- HTML report (#15) ------------------------------------------------

def generate_html_report(summary: dict, profiles: list[dict] | None = None,
                         title: str = "Log Analysis Report") -> str:
    def _esc(s):
        return html_mod.escape(str(s))
    body_parts: list[str] = []
    body_parts.append(f"<h2>Summary</h2><table>")
    body_parts.append(f"<tr><td>Total entries</td><td>{summary.get('total', 0)}</td></tr>")
    if summary.get("first_ts"):
        body_parts.append(f"<tr><td>Time range</td><td>{summary['first_ts']} &rarr; {summary['last_ts']}</td></tr>")
    body_parts.append("</table>")
    if summary.get("top_users"):
        body_parts.append("<h2>Top Users</h2><table><tr><th>User</th><th>Count</th></tr>")
        for name, n in summary["top_users"][:20]:
            body_parts.append(f"<tr><td>{_esc(name)}</td><td>{n}</td></tr>")
        body_parts.append("</table>")
    if summary.get("top_events"):
        body_parts.append("<h2>Top Events</h2><table><tr><th>Event</th><th>Count</th></tr>")
        for name, n in summary["top_events"][:20]:
            body_parts.append(f"<tr><td>{_esc(name)}</td><td>{n}</td></tr>")
        body_parts.append("</table>")
    if profiles:
        body_parts.append("<h2>User Profiles</h2>")
        for p in profiles:
            body_parts.append(f"<h3>{_esc(p.get('user', '?'))}</h3><table>")
            body_parts.append(f"<tr><td>Authored</td><td>{p.get('authored', 0)}</td></tr>")
            body_parts.append(f"<tr><td>Mentioned by others</td><td>{p.get('mentioned_by_others', 0)}</td></tr>")
            body_parts.append("</table>")
    html = f"""<!DOCTYPE html><html lang="en">
<head><meta charset="utf-8"><title>{_esc(title)}</title>
<style>body{{font-family:sans-serif;margin:2em;background:#fafafa}}
table{{border-collapse:collapse;margin:1em 0}}
td,th{{border:1px solid #ccc;padding:4px 8px;text-align:left}}
th{{background:#eee}} h2{{margin-top:2em}}</style></head>
<body><h1>{_esc(title)}</h1>
{"".join(body_parts)}
</body></html>"""
    return html

def write_html_report(path: str, summary: dict, profiles: list[dict] | None = None) -> None:
    html = generate_html_report(summary, profiles, os.path.basename(path))
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"Wrote HTML report to {path} ({len(html)} bytes)")

# ---------- SQLite export/query (#18) -----------------------------------------

def export_to_sqlite(entries: list[Entry], db_path: str) -> str:
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS entries (ts TEXT, user TEXT, target TEXT, level TEXT, event TEXT, text TEXT, raw TEXT, fmt TEXT)")
        conn.execute("DELETE FROM entries")
        rows = []
        for e in entries:
            rows.append((
                e.ts.isoformat() if e.ts else None,
                e.user, e.target, e.level, e.event, e.text, e.raw, e.fmt,
            ))
        conn.executemany("INSERT INTO entries VALUES (?,?,?,?,?,?,?,?)", rows)
        conn.commit()
        return f"Exported {len(rows)} rows to {db_path}"
    finally:
        conn.close()

def query_sqlite(db_path: str, query: str) -> list[dict]:
    conn = sqlite3.connect(db_path)
    try:
        conn.row_factory = sqlite3.Row
        cur = conn.execute(query)
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()

# ---------- Prometheus metrics (#17) ------------------------------------------

def prometheus_metrics(entries: list[Entry]) -> str:
    lines: list[str] = []
    lines.append("# HELP analyzelog_entries_total Total log entries")
    lines.append("# TYPE analyzelog_entries_total counter")
    lines.append(f"analyzelog_entries_total {len(entries)}")
    users: Counter = Counter()
    levels: Counter = Counter()
    targets: Counter = Counter()
    for e in entries:
        if e.user:
            users[e.user] += 1
        if e.level:
            levels[e.level.upper()] += 1
        if e.target:
            targets[e.target] += 1
    lines.append("# HELP analyzelog_user_lines Lines per user")
    lines.append("# TYPE analyzelog_user_lines gauge")
    for u, n in users.most_common(50):
        lines.append(f'analyzelog_user_lines{{user="{u}"}} {n}')
    lines.append("# HELP analyzelog_level_counts Entries per severity level")
    lines.append("# TYPE analyzelog_level_counts gauge")
    for lv, n in levels.items():
        lines.append(f'analyzelog_level_counts{{level="{lv}"}} {n}')
    lines.append("# HELP analyzelog_target_counts Entries per target")
    lines.append("# TYPE analyzelog_target_counts gauge")
    for t, n in targets.most_common(50):
        lines.append(f'analyzelog_target_counts{{target="{t}"}} {n}')
    return "\n".join(lines)

# ---------- Multi-file aggregation (#27) --------------------------------------

class MultiLogAggregator:
    def __init__(self) -> None:
        self.sources: dict[str, list[Entry]] = {}

    def add_file(self, label: str, path: str) -> None:
        entries = list(iter_entries(path))
        self.sources[label] = entries

    @property
    def all_entries(self) -> list[Entry]:
        result: list[Entry] = []
        for entries in self.sources.values():
            result.extend(entries)
        return result

    def summary_by_source(self) -> dict[str, dict]:
        return {label: summarize(entries, 50) for label, entries in self.sources.items()}

# ---------- diff between two log files --------------------------------------

def diff_summaries(a: dict, b: dict, top: int = 25) -> dict:
    a_users = dict(a["top_users"])
    b_users = dict(b["top_users"])
    all_users = set(a_users) | set(b_users)
    user_deltas = sorted(
        ((u, b_users.get(u, 0) - a_users.get(u, 0),
          a_users.get(u, 0), b_users.get(u, 0)) for u in all_users),
        key=lambda r: -abs(r[1])
    )[:top]
    return {
        "totals": (a["total"], b["total"], b["total"] - a["total"]),
        "first_ts": (a["first_ts"], b["first_ts"]),
        "last_ts": (a["last_ts"], b["last_ts"]),
        "user_deltas": user_deltas,
    }


def print_log_diff(path_a: str, path_b: str, diff: dict) -> None:
    ta, tb, dt = diff["totals"]
    print(f"\nDiff: {path_a}  →  {path_b}")
    print(f"  totals: {ta} → {tb}  (Δ {dt:+d})")
    fa, fb = diff["first_ts"]
    la, lb = diff["last_ts"]
    print(f"  range A: {fa} → {la}")
    print(f"  range B: {fb} → {lb}")
    print(f"  top user-count deltas (B - A):")
    for u, d, av, bv in diff["user_deltas"]:
        print(f"    {d:+6d}  {u:30s}  {av} → {bv}")


# ---------- watch / tail ----------------------------------------------------

def watch_loop(path: str, on_new, poll_seconds: float = 2.0) -> None:
    """Tail-like watcher; calls on_new(list[Entry]) for newly appended lines."""
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    while True:
        try:
            time.sleep(poll_seconds)
            try:
                cur = os.path.getsize(path)
            except OSError:
                continue
            if cur < size:
                size = 0
            if cur == size:
                continue
            new_entries: list[Entry] = []
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                f.seek(size)
                for line in f:
                    e = parse_line(line)
                    if e is not None:
                        new_entries.append(e)
            size = cur
            if new_entries:
                on_new(new_entries)
        except KeyboardInterrupt:
            print("\n(watch stopped)")
            return


def watch_callback_default(new: list[Entry]) -> None:
    print(f"\n[watch] +{len(new)} new lines")
    for e in new[-10:]:
        ts = _fmt_dt(e.ts)
        u = e.user or "—"
        t = e.target or ""
        print(f"  {ts}  {u:>15}  {t:>10}  {(e.text or e.raw)[:160]}")


class WatchBg:
    """Background tail thread: appends new entries to shell.state.entries and
    bumps a counter the prompt can read."""

    def __init__(self, shell: "LogShell", poll: float = 2.0) -> None:
        self.shell = shell
        self.poll = poll
        self._stop = threading.Event()
        self.new_count = 0
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None

    def _run(self) -> None:
        path = self.shell.state.log_path
        try:
            size = os.path.getsize(path)
        except OSError:
            size = 0
        while not self._stop.wait(self.poll):
            try:
                cur = os.path.getsize(path)
            except OSError:
                continue
            if cur < size:
                size = 0
            if cur == size:
                continue
            new_entries: list[Entry] = []
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    f.seek(size)
                    for line in f:
                        e = parse_line(line)
                        if e is not None:
                            new_entries.append(e)
            except OSError:
                continue
            size = cur
            if new_entries:
                self.shell.state.entries.extend(new_entries)
                self.new_count += len(new_entries)


# ---------- Plugin system (#23) -----------------------------------------------

class AnalysisPlugin:
    name: str = "base"
    def analyze(self, entries: list[Entry]) -> str:
        return ""
    def commands(self) -> dict[str, str]:
        return {}

_plugins: list[AnalysisPlugin] = []

def register_plugin(plugin: AnalysisPlugin) -> None:
    _plugins.append(plugin)

def load_plugins_from(path: str) -> None:
    if not os.path.isdir(path):
        return
    import importlib.util
    for fname in sorted(os.listdir(path)):
        if not fname.endswith(".py") or fname.startswith("_"):
            continue
        fpath = os.path.join(path, fname)
        try:
            spec = importlib.util.spec_from_file_location(fname[:-3], fpath)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for attr in dir(mod):
                    obj = getattr(mod, attr)
                    if isinstance(obj, type) and issubclass(obj, AnalysisPlugin) and obj is not AnalysisPlugin:
                        register_plugin(obj())
        except Exception as exc:
            print(f"Plugin load error {fname}: {exc}", file=sys.stderr)

# ---------- Web API / Web UI (#24) --------------------------------------------

_web_entries: list[Entry] = []
_web_queue: Queue = Queue()

class WebAPIHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/metrics":
            self._json_response(prometheus_metrics(_web_entries))
        elif parsed.path == "/api/summary":
            self._json_dict(summarize(_web_entries, 25))
        elif parsed.path == "/api/entries":
            n_str = urllib.parse.parse_qs(parsed.query).get("n", ["50"])[0]
            try:
                n = int(n_str)
            except ValueError:
                n = 50
            recent = [{"ts": str(e.ts), "user": e.user, "target": e.target,
                       "level": e.level, "event": e.event, "text": e.text[:200]}
                      for e in _web_entries[-n:]]
            self._json_list(recent)
        elif parsed.path == "/api/users":
            users = sorted({e.user for e in _web_entries if e.user})
            self._json_list(users)
        elif parsed.path == "/" or parsed.path == "/index.html":
            self._html_response("<html><body><h1>Log Analyzer</h1>"
                                f"<p>{len(_web_entries)} entries loaded.</p>"
                                "<ul><li><a href='/api/summary'>/api/summary</a></li>"
                                "<li><a href='/api/entries'>/api/entries</a></li>"
                                "<li><a href='/api/users'>/api/users</a></li>"
                                "<li><a href='/metrics'>/metrics</a></li></ul></body></html>")
        else:
            self.send_error(404)
    def _json_response(self, data: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(data.encode())
    def _json_dict(self, d: dict) -> None:
        self._json_response(json.dumps(d, indent=2, default=str))
    def _json_list(self, lst: list) -> None:
        self._json_response(json.dumps(lst, indent=2, default=str))
    def _html_response(self, html: str) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())
    def log_message(self, format, *args) -> None:  # type: ignore[override]
        pass

def start_web_server(port: int = 8088, daemon: bool = True) -> HTTPServer:
    server = HTTPServer(("127.0.0.1", port), WebAPIHandler)
    t = threading.Thread(target=server.serve_forever, daemon=daemon)
    t.start()
    return server

# ---------- NEW: Web Portal (#30) ----------------------------------------------

PORTAL_COMMANDS: list[tuple[str, str, str]] = [
    ("load", "load <path>", "Load a different log file."),
    ("reload", "reload", "Re-read the current log file from disk."),
    ("user", "user <nick>", "Focus on a user (empty arg clears)."),
    ("clear_filters", "clear_filters", "Clear all global filters."),
    ("back", "back", "Restore previous focus state."),
    ("forward", "forward", "Re-apply focus undone by 'back'."),
    ("report", "report [user]", "Full stats report."),
    ("users", "users [N]", "Top N users by activity."),
    ("events", "events [N]", "Top N event types."),
    ("focus", "focus <nick>", "Filter view to a user."),
    ("target", "target <chan>", "Filter view to a channel."),
    ("since", "since <when>", "Lower time bound (ISO / '5h ago')."),
    ("until", "until <when>", "Upper time bound."),
    ("top", "top <what> [N]", "Show a top-N ranking."),
    ("hours", "hours [compact]", "Hour-of-day histogram."),
    ("days", "days [compact]", "Date histogram."),
    ("errors", "errors", "Error-like entries."),
    ("grep", "grep <regex>", "Regex search (cap 50)."),
    ("search", "search <text>", "Free-text search."),
    ("show", "show [nick] [N]", "Print raw lines for user."),
    ("pick", "pick <N>", "Focus Nth item from last listing."),
    ("inspect", "inspect <N>", "Full details for Nth entry."),
    ("last", "last", "Re-print last output."),
    ("info", "info [user]", "One-line user summary."),
    ("settings", "settings", "Show current settings."),
    ("config", "config [view|set|reset|llm|display|filters|system]", "View/set grouped configuration."),
    ("set", "set <key> <val>", "Set config (top, llm_url, ...)."),
    ("alias", "alias [<name>=<cmd>]", "Define/list/remove aliases."),
    ("ignore", "ignore [add|drop|list]", "Manage ignore list."),
    ("note", "note <user> [text]", "Attach/del user note."),
    # --- user analysis ---
    ("sentiment", "sentiment [user]", "Sentiment analysis for a user."),
    ("topics", "topics [user]", "Keyword / n-gram extraction for a user."),
    ("lifecycle", "lifecycle [user]", "User lifecycle analysis."),
    ("churn", "churn [user]", "Predict churn risk for a user."),
    ("pattern", "pattern [user]", "Pattern-of-life analysis for a user."),
    ("anomalies", "anomalies [user] [z]", "Detect behavioral anomalies."),
    ("changepoints", "changepoints [user] [days]", "Detect behavioral change points."),
    ("multifactor", "multifactor [user]", "Multi-factor anomaly score."),
    ("forecast", "forecast [user] [days]", "Forecast future activity."),
    ("forecast_anomaly", "forecast_anomaly <user> [z] [days]", "Anomaly detection using forecast baseline."),
    ("recurrence", "recurrence [user]", "Detect periodic patterns in a user's activity."),
    ("recurrence_breach", "recurrence_breach <user> [days]", "Check if user breaks recurrence pattern."),
    ("drift", "drift <user> [args]", "Detect behavioral drift across time windows."),
    # --- interaction analysis ---
    ("response_times", "response_times [user] [window]", "Response time analysis."),
    ("session_times", "session_times <A> <B> [gap]", "Response times grouped by session."),
    ("influence", "influence <seed> [hops] [window]", "Trace multi-hop reply chains."),
    ("sequences", "sequences [min_support]", "Find common user interaction sequences."),
    ("rootcause", "rootcause <user> [lookback]", "Root cause tracing for a user's activity."),
    ("correlate", "correlate <path> [window]", "Cross-log event correlation."),
    ("pareto", "pareto [users|events|targets|levels]", "Pareto analysis (80/20 rule)."),
    # --- visualization ---
    ("timeline", "timeline [user] [width]", "ASCII timeline visualization."),
    ("heatmap", "heatmap [user] [months]", "Calendar activity heatmap."),
    ("net", "net [N]", "ASCII network graph of top interaction edges."),
    ("templates", "templates [N]", "Extract common log line templates."),
    ("template_filter", "template_filter <id>", "Filter current view by template ID."),
    ("prometheus", "prometheus", "Print Prometheus metrics."),
    ("dataframe", "dataframe [expr]", "View entries as pandas DataFrame."),
    # --- LLM ---
    ("analyze", "analyze [nick]", "LLM behavior analysis."),
    ("ask", 'ask [nick] "Q"', "Free-form LLM question."),
    ("askall", 'askall "Q"', "Ask LLM a question about the entire log."),
    ("interact", "interact <A> <B>", "User interaction analysis."),
    ("compare", "compare <A> <B>...", "Multi-user comparison."),
    ("compare-auto", "compare-auto <A> <B>", "Compare users then auto-explain with LLM."),
    ("tag", "tag <user>", "LLM auto-tag a user with behavioral labels."),
    ("tagall", "tagall [N]", "LLM auto-tag top N users."),
    ("explain", "explain <user>", "LLM explains anomalies for a user."),
    ("summarize", "summarize <A> <B>", "LLM conversation summarization."),
    ("cluster", "cluster [min_lines] [N]", "LLM cluster users into behavioral groups."),
    ("auto_report", "auto_report", "LLM-generated narrative report of the log."),
    ("drift-explain", "drift-explain <user>", "Drift detection with LLM explanation."),
    # --- analysis ---
    ("similar", "similar [threshold]", "Find similar user pairs."),
    ("bursts", "bursts [user]", "Detect activity bursts."),
    ("threads", "threads [user]", "Reply/mention reconstruction."),
    ("edges", "edges [N]", "Top interaction edges."),
    ("sessions", "sessions [user]", "Detect user sessions."),
    ("dist", "dist [user]", "Score distributions."),
    ("zscores", "zscores [user]", "Per-score z-scores."),
    ("flagged", "flagged <expr>", "Lines matching score expr."),
    ("diff", "diff <other.log>", "Diff against another log."),
    ("export", "export <type> <path>", "Serialize data."),
    ("view", "view {save|load|drop|show}", "Named filter sets."),
    ("script", "script <path>", "Run commands from file."),
    # --- forensic ---
    ("entities", "entities [user]", "Forensic entity extraction."),
    ("gaps", "gaps [user]", "Detect timeline gaps."),
    ("reconstruct", "reconstruct [user]", "Chronological timeline."),
    ("forensic_report", "forensic_report <user>", "LLM forensic report."),
    ("timeline_narrative", "timeline_narrative <user>", "LLM timeline story."),
    ("evidence", "evidence <user>", "LLM evidence extraction."),
    ("tamper_detect", "tamper_detect [user] [--strict]", "Detect log tampering/manipulation."),
    ("llm_search", 'llm_search "<query>"', "Natural language semantic search."),
    ("llm_threat", "llm_threat [user]", "LLM threat assessment."),
    ("llm_bot", "llm_bot [user]", "Bot/automation detection."),
    ("llm_profile", "llm_profile [user]", "Deep psychological/behavioral profile."),
    ("llm_insider", "llm_insider [user]", "Insider threat analysis."),
    ("llm_social", "llm_social [N]", "Social dynamics & group structure."),
    ("llm_incident", "llm_incident [query]", "Incident timeline reconstruction."),
    ("llm_topics", "llm_topics [N]", "Topic map across users."),
    ("llm_sessions", "llm_sessions [user]", "Compare behavior across sessions."),
    ("llm_baseline", "llm_baseline [user]", "Behavioral baseline & deviations."),
    ("llm_summary", "llm_summary", "LLM summary of entire log."),
    ("llm_replay", "llm_replay [user]", "LLM chronological story replay."),
    ("llm_predict", "llm_predict [user]", "Predict future behavior."),
    ("llm_motive", "llm_motive [user]", "Motivation & intent analysis."),
    ("llm_relationship", "llm_relationship <A> <B>", "Deep relationship analysis."),
    ("llm_audit", "llm_audit [policy]", "Security compliance audit."),
    ("llm_risk", "llm_risk [user]", "Quantified 0-100 risk score."),
    ("stats", "stats [user]", "Statistical summary (mean/median/stdev)."),
    ("frequency", "frequency [N]", "Word/token frequency analysis."),
    ("cooccurrence", "cooccurrence [window]", "User co-occurrence in time windows."),
    ("heatmap_user", "heatmap_user [N]", "2D user×hour heatmap."),
    ("coverage", "coverage", "Log coverage analysis."),
    ("export_graphml", "export_graphml <path>", "Export graph as GraphML."),
    ("merge", "merge <f1> <f2> ... <out>", "Merge log files chronologically."),
    ("sample", "sample <N>", "Random sample of N entries."),
    ("last_seen", "last_seen [user]", "Last active time per user."),
    ("whois", "whois <user>", "One-command user dump."),
    ("diff_time", "diff_time <since> <until>", "Compare two time periods."),
    ("top_words", "top_words [N]", "Top N words across logs."),
    # --- multi-log / export ---
    ("multi", "multi {add|list|clear|report}", "Multi-log aggregation."),
    ("aggregate", "aggregate", "Alias for multi report."),
    ("export_html", "export_html <path> [user...]", "Generate HTML report."),
    ("export_html_drilldown", "export_html_drilldown <path> [user...]", "Collapsible HTML report."),
    ("export_sql", "export_sql <path>", "Export entries to SQLite."),
    ("sql", "sql <db> <query>", "Query a SQLite export."),
    ("save_profile", "save_profile <user> <path>", "Save user profile to JSON."),
    ("load_profile", "load_profile <path>", "Load and display a saved profile."),
    ("compare_profiles", "compare_profiles <path1> <path2> [...]", "Compare saved profiles."),
    # --- system ---
    ("web", "web {start|stop|status}", "Web API server."),
    ("webportal", "webportal {start|stop|status}", "Portal server."),
    ("webhook", "webhook {set|test|clear}", "Slack/Discord webhook."),
    ("cron", "cron [--output <path>]", "Cron mode analysis."),
    ("dashboard", "dashboard", "Curses real-time dashboard."),
    ("watch", "watch [poll_sec]", "Tail log file."),
    ("watch_alert", "watch_alert [poll_sec]", "Tail log with alert evaluation."),
    ("chart", "chart <type> <path>", "Generate matplotlib chart."),
    ("rules", "rules [add|remove|toggle]", "Alert rules."),
    ("alert_fatigue", "alert_fatigue [hours]", "Compute alert fatigue scores."),
    ("save_config", "save_config", "Persist config to disk."),
    ("load_config", "load_config", "Reload config from disk."),
    ("commands", "commands", "Print this reference."),
    ("help", "help [name]", "Built-in help."),
            ("quit", "quit", "Exit the shell."),
            ("case", "case {create|list|show|add|...}", "Manage investigation cases."),
            ("future_diag", "future_diag [user] [--auto-case]", "Predictive diagnostics and forecasting."),
        ]

_PORTAL_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>analyzelog portal</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{background:#000;color:#0f0;font-family:'Courier New',monospace;height:100vh;display:flex;flex-direction:column;overflow:hidden}
  #header{padding:6px 10px;border-bottom:1px solid #030;font-size:12px;color:#080;display:flex;justify-content:space-between;align-items:center;flex-shrink:0}
  #header span{color:#0f0}
  #tabs{display:flex;gap:0;border-bottom:1px solid #030;flex-shrink:0}
  #tabs button{background:#000;color:#060;border:1px solid #030;border-bottom:none;padding:5px 16px;font-family:'Courier New',monospace;font-size:12px;cursor:pointer;border-radius:3px 3px 0 0}
  #tabs button:hover{color:#0f0;border-color:#060}
  #tabs button.active{color:#0f0;border-color:#0f0;background:#001a00}
  #main{flex:1;overflow:hidden;display:flex;flex-direction:column}
  .tab-content{display:none;flex-direction:column;flex:1;overflow:hidden}
  .tab-content.active{display:flex}
  #messages{flex:1;overflow-y:auto;padding:6px 10px;font-size:13px;line-height:1.5}
  #messages .msg{padding:2px 0;border-bottom:1px solid #001a00;animation:fadeIn .15s;display:flex;align-items:baseline;gap:4px}
  @keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
  .ts{color:#060;white-space:nowrap;flex-shrink:0;font-size:11px}
  .user{color:#0f0;font-weight:bold;flex-shrink:0;white-space:pre-wrap;word-break:break-all}
  .lvl{color:#0a0;flex-shrink:0;white-space:pre-wrap;word-break:break-all}
  .txt{color:#0c0;flex:1;min-width:0;white-space:pre-wrap;word-break:break-all}
  .highlight{background:#0f01;border-left:2px solid #0f0;padding-left:6px}
  .cmd{color:#ff0;font-weight:bold;border-left:2px solid #ff0;padding-left:6px;margin-top:4px}
  .out{color:#0f0;white-space:pre-wrap;padding-left:6px;margin-bottom:4px;border-left:2px solid #060}
  .sep{color:#030;text-align:center;font-size:10px;padding:4px 0}
  #menu{flex:1;overflow-y:auto;padding:10px 14px;font-size:12px;line-height:1.5;max-width:420px}
  #menu .mc{color:#060;font-size:11px;margin-bottom:6px;padding-bottom:3px;border-bottom:1px solid #030}
  #menu .mr{display:flex;padding:1px 0}
  #menu .mr .mn{color:#0f0;width:110px;flex-shrink:0;font-weight:bold;white-space:pre-wrap;word-break:break-all}
  #menu .mr .mu{color:#080;width:140px;flex-shrink:0;white-space:pre-wrap;word-break:break-all}
  #menu .mr .md{color:#0a0;flex:1;min-width:0;white-space:pre-wrap;word-break:break-all}
  #menu .mr:hover{background:#0f01}
  #tabMenuView{flex-direction:row!important}
  #output{flex:1;overflow-y:auto;padding:6px 10px;font-size:13px;line-height:1.5;min-width:0;border-right:1px solid #030}
  #output .cmd{color:#ff0;font-weight:bold;border-left:2px solid #ff0;padding-left:6px;margin-top:4px}
  #output .out{color:#0f0;white-space:pre-wrap;padding-left:6px;margin-bottom:4px;border-left:2px solid #060}
  #output .sep{color:#030;text-align:center;font-size:10px;padding:4px 0}
  #dash{flex:1;overflow-y:auto;padding:10px 14px;font-size:13px;line-height:1.6}
  #dash .dg{margin-bottom:14px}
  #dash .dg h3{color:#0f0;font-size:13px;margin-bottom:4px;border-bottom:1px solid #030;padding-bottom:2px}
  #dash .dg .num{color:#0f0;font-size:22px;font-weight:bold}
  #dash .dg .lbl{color:#060;font-size:11px}
  #dash .dg .row{display:flex;justify-content:space-between;padding:1px 0}
  #dash .dg .row .k{color:#080}
  #dash .dg .row .v{color:#0f0}
  #dash .bar{display:flex;align-items:center;gap:6px;margin:1px 0}
  #dash .bar .bk{color:#0f0;width:90px;text-align:right;font-size:11px;flex-shrink:0;white-space:pre-wrap;word-break:break-all;font-weight:bold}
  #dash .bar .bf{height:12px;background:#0f0;border-radius:1px;min-width:2px;transition:width .3s}
  #dash .bar .bv{color:#060;font-size:11px;flex-shrink:0;width:30px;text-align:right}
  #dash .dp{color:#030;font-size:10px}
  #dash .dph{display:flex;align-items:flex-end;gap:2px;padding:4px 0;height:50px}
  #dash .dph .hb{width:20px;background:#0f0;border-radius:1px 1px 0 0;min-height:1px;transition:height .3s}
  #dash .dph .hbl{color:#060;font-size:9px;text-align:center;width:20px;padding-top:2px}
  #dash .dpd{display:flex;align-items:flex-end;gap:1px;padding:4px 0;height:36px;overflow-x:auto}
  #dash .dpd .db{width:8px;background:#0f0;border-radius:1px 1px 0 0;min-height:1px;flex-shrink:0;transition:height .15s}
  #dash .errs{color:#f00;font-size:11px}
  #dash .errs .er{color:#f44;padding:1px 0;border-bottom:1px solid #300;white-space:pre-wrap;word-break:break-all}
  #footer{display:flex;align-items:center;border-top:1px solid #030;padding:6px 10px;gap:6px;background:#000;flex-shrink:0}
  #footer .prompt{color:#0f0;font-weight:bold}
  #footer input{flex:1;background:#000;color:#0f0;border:1px solid #030;padding:7px 10px;font-family:'Courier New',monospace;font-size:13px;outline:none}
  #footer input:focus{border-color:#0f0}
  #footer input::placeholder{color:#060}
  #status{font-size:11px;color:#060;margin-left:auto}
  #autocomplete{position:absolute;bottom:100%;left:0;right:0;background:#001a00;border:1px solid #0f0;border-bottom:none;display:none;max-height:220px;overflow-y:auto;z-index:100}
  #autocomplete .ac-item{padding:3px 10px;cursor:pointer;font-size:13px;display:flex;align-items:baseline;gap:6px}
  #autocomplete .ac-item:hover,#autocomplete .ac-item.ac-sel{background:#003300;color:#0f0}
  #autocomplete .ac-item .ac-n{color:#0f0;font-weight:bold;min-width:110px;flex-shrink:0;font-family:'Courier New',monospace;font-size:12px}
  #autocomplete .ac-item .ac-u{color:#060;font-size:11px;min-width:130px;flex-shrink:0}
  #autocomplete .ac-item .ac-d{color:#0a0;font-size:11px;flex:1;min-width:0}
  #footer-wrapper{position:relative}
  ::-webkit-scrollbar{width:6px}
  ::-webkit-scrollbar-track{background:#000}
  ::-webkit-scrollbar-thumb{background:#030;border-radius:3px}
</style>
</head>
<body>
<div id="header">analyzelog portal <span id="count">0</span> entries</div>
<div id="tabs">
  <button id="tabMenu" class="active" onclick="switchTab('menu')">Main Menu</button>
  <button id="tabDash" onclick="switchTab('dash')">Dashboard</button>
  <button id="tabLogs" onclick="switchTab('logs')">Logs</button>
</div>
<div id="main">
  <div id="tabMenuView" class="tab-content active"><div id="output"></div><div id="menu"></div></div>
  <div id="tabDashView" class="tab-content"><div id="dash"></div></div>
  <div id="tabLogsView" class="tab-content"><div id="messages"></div></div>
</div>
<div id="footer-wrapper">
  <div id="autocomplete"></div>
  <div id="footer">
    <span class="prompt">$</span>
    <input id="input" type="text" placeholder="type a command and press Enter" autocomplete="off" autofocus spellcheck="false">
    <span id="status">ready</span>
  </div>
</div>
<script>
const el=document.getElementById.bind(document);
const msg=el('messages'), menu=el('menu'), dash=el('dash'), inp=el('input'), cnt=el('count'), sts=el('status'), output=el('output'), ac=el('autocomplete');
let lastId=0, activeTab='menu', cmds=null;
let cmdHistory=JSON.parse(localStorage.getItem('al_cmd_history')||'[]');
let histIdx=cmdHistory.length;
let acList=[], acSel=-1, acOpen=false;

function switchTab(tab){
  activeTab=tab;
  el('tabMenu').className=tab==='menu'?'active':'';
  el('tabDash').className=tab==='dash'?'active':'';
  el('tabLogs').className=tab==='logs'?'active':'';
  el('tabMenuView').className='tab-content'+(tab==='menu'?' active':'');
  el('tabDashView').className='tab-content'+(tab==='dash'?' active':'');
  el('tabLogsView').className='tab-content'+(tab==='logs'?' active':'');
  if(tab==='menu'&&!cmds)fetchCmds();
  if(tab==='dash'&&!dash.dataset.loaded)fetchDash();
}

let nearBottom=true;
msg.addEventListener('scroll',function(){nearBottom=msg.scrollHeight-msg.scrollTop-msg.clientHeight<60;});

function addEntry(e){
  const d=document.createElement('div');d.className='msg';
  if(e._type==='cmd'){
    d.className='msg cmd';d.textContent='$ '+e.text;
  }else if(e._type==='out'){
    d.className='msg out';d.textContent=e.text;
  }else if(e._type==='sep'){
    d.className='msg sep';d.textContent=e.text||'\u2500'+'\u2500'.repeat(40);
  }else{
    const ts=document.createElement('span');ts.className='ts';ts.textContent=(e.ts||'').slice(0,19)+' ';
    const us=document.createElement('span');us.className='user';us.textContent=(e.user||'?')+' ';
    const lv=document.createElement('span');lv.className='lvl';lv.textContent=(e.level||e.event||'')?'['+(e.level||e.event||'')+'] ':'';
    const tx=document.createElement('span');tx.className='txt';tx.textContent=(e.text||e.raw||'');
    d.append(ts,us,lv,tx);
  }
  msg.append(d);
  if(nearBottom)msg.scrollTop=msg.scrollHeight;
}

function addOutput(e){
  const d=document.createElement('div');d.className='msg';
  if(e._type==='cmd'){
    d.className='msg cmd';d.textContent='$ '+e.text;
  }else if(e._type==='out'){
    d.className='msg out';d.textContent=e.text;
  }else if(e._type==='sep'){
    d.className='msg sep';d.textContent=e.text||'\u2500'+'\u2500'.repeat(40);
  }else{
    d.className='msg';
    const ts=document.createElement('span');ts.className='ts';ts.textContent=(e.ts||'').slice(0,19)+' ';
    const us=document.createElement('span');us.className='user';us.textContent=(e.user||'?')+' ';
    const lv=document.createElement('span');lv.className='lvl';lv.textContent=(e.level||e.event||'')?'['+(e.level||e.event||'')+'] ':'';
    const tx=document.createElement('span');tx.className='txt';tx.textContent=(e.text||e.raw||'');
    d.append(ts,us,lv,tx);
  }
  output.append(d);
  output.scrollTop=output.scrollHeight;
}

function fetchLog(){
  fetch('/api/log').then(r=>r.json()).then(data=>{
    cnt.textContent=data.length;
    const startFrom=lastId?data.findIndex(e=>e.id===lastId)+1:0;
    if(startFrom>0&&startFrom<data.length){
      data.slice(startFrom).forEach(addEntry);
    }else if(!lastId&&data.length){
      const wasNear=nearBottom;
      msg.innerHTML='';data.forEach(addEntry);
      if(wasNear)msg.scrollTop=msg.scrollHeight;
    }
    if(data.length)lastId=data[data.length-1].id;
    if(nearBottom)msg.scrollTop=msg.scrollHeight;
  }).catch(()=>{});
}

function renderMenu(data){
  cmds=data;
  var html='<div class="mc">available commands — '+data.length+' total</div>';
  var cat='';var order=['nav','analysis','viewing','filters','interaction','forensic','llm','multi','config','system'];
  var cats={'nav':['user','clear_filters','back','forward'],
            'analysis':['report','users','events','top','hours','days','errors','dist','zscores','flagged','sessions','bursts','edges','threads','similar','diff','sentiment','topics','lifecycle','churn','pattern','anomalies','changepoints','multifactor','forecast','forecast_anomaly','recurrence','recurrence_breach','drift','templates','pareto'],
            'viewing':['show','pick','inspect','last','info','grep','search','timeline','heatmap','net','dataframe','template_filter','prometheus'],
            'filters':['focus','target','since','until','view','ignore'],
            'interaction':['response_times','session_times','influence','sequences','rootcause','correlate'],
            'forensic':['entities','gaps','reconstruct','forensic_report','timeline_narrative','evidence','tamper_detect'],
            'llm':['analyze','ask','askall','interact','compare','compare-auto','tag','tagall','explain','summarize','cluster','auto_report','drift-explain','llm_search','llm_threat','llm_bot','llm_profile','llm_insider','llm_social','llm_incident','llm_topics','llm_sessions','llm_baseline','llm_summary','llm_replay','llm_predict','llm_motive','llm_relationship','llm_audit','llm_risk'],
            'multi':['multi','aggregate','export_html','export_html_drilldown','export_sql','sql','save_profile','load_profile','compare_profiles'],
            'config':['config','settings','set','alias','note','load','reload','save_config','load_config','rules','web','webportal','webhook'],
            'case':['case'],
            'system':['commands','help','quit','script','export','cron','dashboard','watch','watch_alert','alert_fatigue']};
  var catLabel={'nav':'navigation','analysis':'analysis','viewing':'viewing','filters':'filters','interaction':'interaction','forensic':'forensic','llm':'llm','multi':'multi-log / export','config':'config','case':'case management','system':'system'};
  var done={};
  for(var ci=0;ci<order.length;ci++){
    var g=order[ci];var items=cats[g];
    if(!items)continue;
    html+='<div class="mc">'+catLabel[g]+'</div>';
    for(var ii=0;ii<items.length;ii++){
      done[items[ii]]=true;
      for(var di=0;di<data.length;di++){
        if(data[di][0]===items[ii]){
          html+='<div class="mr"><span class="mn">'+esc(data[di][0])+'</span><span class="mu">'+esc(data[di][1])+'</span><span class="md">'+esc(data[di][2])+'</span></div>';
          break;
        }
      }
    }
  }
  menu.innerHTML=html;
}

function esc(s){return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');}

function fetchCmds(){fetch('/api/commands').then(r=>r.json()).then(function(d){renderMenu(d);}).catch(function(){});}

function renderDash(d){
  dash.dataset.loaded='1';
  var html='';
  html+='<div class="dg"><div class="num">'+d.total+'</div><div class="lbl">total entries</div></div>';
  html+='<div class="dg"><span class="lbl">'+(d.first_ts||'?')+'</span> &rarr; <span class="lbl">'+(d.last_ts||'?')+'</span></div>';
  var maxUser=d.top_users&&d.top_users.length?d.top_users[0][1]:1;
  html+='<div class="dg"><h3>top users</h3>';
  if(d.top_users)for(var i=0;i<d.top_users.length;i++){
    var u=d.top_users[i],pct=Math.round(u[1]/maxUser*100);
    html+='<div class="bar"><span class="bk">'+esc(u[0])+'</span><div class="bf" style="width:'+pct+'%"></div><span class="bv">'+u[1]+'</span></div>';
  }
  html+='</div>';
  var maxHour=1;
  if(d.by_hour)for(var k in d.by_hour)if(d.by_hour[k]>maxHour)maxHour=d.by_hour[k];
  html+='<div class="dg"><h3>activity by hour</h3><div class="dph">';
  for(var h=0;h<24;h++){
    var hv=d.by_hour&&d.by_hour[h]?d.by_hour[h]:0;
    var ht=Math.round(hv/maxHour*44)+1;
    html+='<div><div class="hb" style="height:'+ht+'px" title="'+h+':00 = '+hv+'"></div><div class="hbl">'+h+'</div></div>';
  }
  html+='</div></div>';
  var maxDay=1,dayKeys=[];
  if(d.by_day){for(var k in d.by_day){dayKeys.push(k);if(d.by_day[k]>maxDay)maxDay=d.by_day[k];}}
  dayKeys.sort();var showDays=dayKeys.slice(-60);
  html+='<div class="dg"><h3>daily activity (last 60 days)</h3><div class="dpd">';
  for(var i=0;i<showDays.length;i++){
    var dv=d.by_day[showDays[i]],dt=Math.round(dv/maxDay*30)+1;
    html+='<div class="db" style="height:'+dt+'px" title="'+showDays[i]+' = '+dv+'"></div>';
  }
  html+='</div></div>';
  html+='<div class="dg"><h3>top events</h3>';
  if(d.top_events)for(var i=0;i<d.top_events.length;i++){
    html+='<div class="row"><span class="k">'+esc(d.top_events[i][0])+'</span><span class="v">'+d.top_events[i][1]+'</span></div>';
  }
  html+='</div>';
  html+='<div class="dg"><h3>levels</h3>';
  if(d.levels)for(var k in d.levels){
    html+='<div class="row"><span class="k">'+k+'</span><span class="v">'+d.levels[k]+'</span></div>';
  }
  html+='</div>';
  if(d.errors&&d.errors.length){
    html+='<div class="dg"><h3>errors &amp; warnings ('+d.errors.length+')</h3><div class="errs">';
    for(var i=0;i<Math.min(d.errors.length,10);i++){
      html+='<div class="er">'+esc(d.errors[i])+'</div>';
    }
    if(d.errors.length>10)html+='<div class="dp">... and '+(d.errors.length-10)+' more</div>';
    html+='</div></div>';
  }
  html+='<div class="dg" style="margin-top:10px"><span class="lbl">last updated: '+new Date().toLocaleTimeString()+'</span></div>';
  dash.innerHTML=html;
}

function fetchDash(){fetch('/api/dashboard').then(r=>r.json()).then(function(d){renderDash(d);}).catch(function(){});}

function sendCmd(cmd){
  sts.textContent='executing...';
  const sep={_type:'sep',id:Date.now(),text:'\u2500 cmd: '+cmd+' \u2500'+'\u2500'.repeat(Math.max(0,40-cmd.length-8))};
  addOutput(sep);
  const cmdEntry={_type:'cmd',id:Date.now()+1,text:cmd};
  addOutput(cmdEntry);
  fetch('/api/command',{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({command:cmd})
  }).then(r=>r.json()).then(data=>{
    if(data.output&&data.output.trim()){
      const outEntry={_type:'out',id:Date.now()+2,text:data.output};
      addOutput(outEntry);
    }else{
      const outEntry={_type:'out',id:Date.now()+2,text:'(no output)'};
      addOutput(outEntry);
    }
    sts.textContent='ready';
    if(nearBottom)output.scrollTop=output.scrollHeight;
  }).catch(()=>{
    const err={_type:'out',id:Date.now()+2,text:'Error: command failed or portal disconnected'};
    addOutput(err);
    sts.textContent='error';
  });
}

function historyPush(cmd){
  if(!cmd||cmd===cmdHistory[cmdHistory.length-1])return;
  cmdHistory.push(cmd);
  if(cmdHistory.length>200)cmdHistory=cmdHistory.slice(-200);
  histIdx=cmdHistory.length;
  try{localStorage.setItem('al_cmd_history',JSON.stringify(cmdHistory));}catch(e){}
}
function historyUp(){
  if(histIdx>0){histIdx--;inp.value=cmdHistory[histIdx];}
  closeAc();
}
function historyDown(){
  if(histIdx<cmdHistory.length-1){histIdx++;inp.value=cmdHistory[histIdx];}
  else{histIdx=cmdHistory.length;inp.value='';}
  closeAc();
}

function buildAcItems(filter){
  if(!cmds)return[];
  var f=filter.toLowerCase().split(/\s+/)[0]||'';
  var items=[];
  for(var i=0;i<cmds.length;i++){
    var n=cmds[i][0],u=cmds[i][1]||'',d=cmds[i][2]||'';
    if(!f||n.toLowerCase().indexOf(f)===0)items.push({name:n,usage:u,desc:d});
  }
  return items.slice(0,20);
}

function renderAc(items,typedWord){
  var html='';
  for(var i=0;i<items.length;i++){
    var it=items[i];
    html+='<div class="ac-item'+(i===acSel?' ac-sel':'')+'" data-idx="'+i+'" data-cmd="'+esc(it.usage||it.name)+'">';
    html+='<span class="ac-n">'+esc(it.name)+'</span>';
    html+='<span class="ac-u">'+esc(it.usage)+'</span>';
    html+='<span class="ac-d">'+esc(it.desc)+'</span>';
    html+='</div>';
  }
  ac.innerHTML=html;
  ac.style.display=items.length?'block':'none';
  acOpen=items.length>0;
  var acNodes=ac.querySelectorAll('.ac-item');
  for(var j=0;j<acNodes.length;j++){
    acNodes[j].addEventListener('mousedown',function(ev){
      ev.preventDefault();
      var cmd=this.getAttribute('data-cmd');
      inp.value=cmd+' ';
      inp.focus();
      closeAc();
    });
  }
}

function openAc(){
  var val=inp.value.trim();
  var word=val.split(/\s+/)[0]||'';
  acList=buildAcItems(word);
  acSel=-1;
  renderAc(acList,word);
}

function closeAc(){
  ac.style.display='none';
  acOpen=false;
  acSel=-1;
  acList=[];
}

function acNav(dir){
  if(!acOpen)return false;
  acSel+=dir;
  if(acSel<0)acSel=0;
  if(acSel>=acList.length)acSel=acList.length-1;
  renderAc(acList,'');
  return true;
}

function acComplete(){
  if(acOpen&&acSel>=0&&acSel<acList.length){
    inp.value=(acList[acSel].usage||acList[acSel].name)+' ';
    closeAc();
    return true;
  }
  return false;
}

inp.addEventListener('input',function(){
  openAc();
});

inp.addEventListener('keydown',function(e){
  if(e.key==='Enter'){
    var cmd=this.value.trim();
    this.value='';
    closeAc();
    if(!cmd)return;
    historyPush(cmd);
    sendCmd(cmd);
    return;
  }
  if(e.key==='ArrowUp'){
    if(acOpen){e.preventDefault();acNav(-1);return;}
    e.preventDefault();historyUp();return;
  }
  if(e.key==='ArrowDown'){
    if(acOpen){e.preventDefault();acNav(1);return;}
    e.preventDefault();historyDown();return;
  }
  if(e.key==='Tab'){
    e.preventDefault();
    acComplete();
    return;
  }
  if(e.key==='Escape'){
    if(acOpen){closeAc();return;}
  }
});

document.addEventListener('click',function(e){
  if(acOpen&&!ac.contains(e.target)&&e.target!==inp)closeAc();
});

fetchLog();setInterval(fetchLog,3000);
fetchCmds();
setInterval(function(){if(activeTab==='dash')fetchDash();},5000);
</script>
</body>
</html>"""

_portal_entries: list[Entry] = []

class WebPortalHandler(BaseHTTPRequestHandler):
    _id_counter: int = 0

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(_PORTAL_HTML.encode("utf-8"))
        elif parsed.path == "/api/log":
            n_str = urllib.parse.parse_qs(parsed.query).get("n", ["200"])[0]
            try:
                n = int(n_str)
            except ValueError:
                n = 200
            recent = []
            for e in _portal_entries[-n:]:
                WebPortalHandler._id_counter += 1
                recent.append({
                    "id": WebPortalHandler._id_counter,
                    "ts": e.ts.isoformat() if e.ts else None,
                    "user": e.user,
                    "target": e.target,
                    "level": e.level,
                    "event": e.event,
                    "text": e.text or e.raw,
                })
            self._json_list(recent)
        elif parsed.path == "/api/dashboard":
            s = summarize(_portal_entries, 10)
            self._json_dict({
                "total": s["total"],
                "first_ts": s["first_ts"].isoformat() if s["first_ts"] else None,
                "last_ts": s["last_ts"].isoformat() if s["last_ts"] else None,
                "top_users": s["top_users"],
                "top_events": s["top_events"],
                "levels": s["levels"],
                "by_hour": s["by_hour"],
                "by_day": s["by_day"],
                "errors": s["errors"],
            })
        elif parsed.path == "/api/commands":
            self._json_list(PORTAL_COMMANDS)
        else:
            self.send_error(404)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/api/command":
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                self._json_dict({"output": "", "error": "empty body"})
                return
            body = self.rfile.read(length).decode("utf-8", errors="replace")
            try:
                data = json.loads(body)
            except json.JSONDecodeError:
                self._json_dict({"output": "", "error": "bad json"})
                return
            command = data.get("command", "").strip()
            if not command:
                self._json_dict({"output": "", "error": "empty command"})
                return
            shell = _current_shell.get("shell")
            if shell is None:
                self._json_dict({"output": "", "error": "shell not available"})
                return
            try:
                buf = io.StringIO()
                with contextlib.redirect_stdout(buf):
                    shell.onecmd(command)
                output = buf.getvalue()
                if not output:
                    output = shell.state.last_output or ""
                self._json_dict({"output": output, "error": ""})
            except Exception as exc:
                self._json_dict({"output": "", "error": str(exc)})
        else:
            self.send_error(404)

    def _json_dict(self, d: dict) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(d, indent=2, default=str).encode())

    def _json_list(self, lst: list) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(lst, indent=2, default=str).encode())

    def log_message(self, format, *args) -> None:
        pass


def start_portal_server(entries: list[Entry], port: int = 80,
                        daemon: bool = True) -> HTTPServer:
    global _portal_entries  # noqa: PLW0603
    if not entries:
        log_path = os.path.join(os.getcwd(), "ai_scores.log")
        if os.path.isfile(log_path):
            try:
                entries = list(iter_entries(log_path))
                print(f"Auto-loaded {len(entries)} entries from {log_path}")
            except Exception as exc:
                print(f"Could not auto-load {log_path}: {exc}", file=sys.stderr)
        else:
            print(f"(no entries provided and {log_path} not found; portal will be empty)")
    _portal_entries = entries
    server = HTTPServer(("127.0.0.1", port), WebPortalHandler)
    t = threading.Thread(target=server.serve_forever, daemon=daemon)
    t.start()
    return server


# ---------- Slack/Discord webhook (#25) ---------------------------------------

def send_webhook(url: str, message: str, webhook_type: str = "slack") -> bool:
    if webhook_type == "slack":
        payload = json.dumps({"text": message}).encode()
    elif webhook_type == "discord":
        payload = json.dumps({"content": message}).encode()
    else:
        payload = json.dumps({"text": message}).encode()
    try:
        req = urllib.request.Request(url, data=payload,
                                     headers={"Content-Type": "application/json"},
                                     method="POST")
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200 or resp.status == 204
    except (urllib.error.URLError, OSError) as exc:
        print(f"Webhook send failed: {exc}", file=sys.stderr)
        return False

# ---------- Cron mode (#26) ---------------------------------------------------

def cron_mode(entries: list[Entry], alert_engine: AlertEngine | None = None,
              webhook_url: str | None = None, output_path: str | None = None) -> int:
    s = summarize(entries, 15)
    output = io.StringIO()
    with contextlib.redirect_stdout(output):
        print(f"=== Cron run at {datetime.now().isoformat()} ===")
        print_report(s)
        if alert_engine:
            triggered: list[str] = []
            for e in entries:
                triggered.extend(alert_engine.evaluate(e))
            if triggered:
                print(f"\n=== Alert triggers ({len(triggered)}) ===")
                for msg in triggered:
                    print(f"  ALERT: {msg}")
    result = output.getvalue()
    print(result)
    if output_path:
        with open(output_path, "a", encoding="utf-8") as f:
            f.write(result)
    if webhook_url and alert_engine:
        triggered_msgs = []
        for e in entries:
            triggered_msgs.extend(alert_engine.evaluate(e))
        if triggered_msgs:
            send_webhook(webhook_url, "\n".join(triggered_msgs[:5]))
    return 0

# ---------- TUI --------------------------------------------------------------

@dataclass
class ShellState:
    log_path: str
    entries: list[Entry] = field(default_factory=list)
    focused_user: str | None = None
    focused_target: str | None = None
    since: datetime | None = None
    until: datetime | None = None
    top_n: int = 15
    llm_url: str = "http://127.0.0.1:8033/"
    llm_model: str = "local"
    max_chunk_chars: int = 12000
    llm_cache: LLMCache | None = None
    views: dict[str, View] = field(default_factory=dict)
    # New (TUI features 1-20):
    aliases: dict[str, str] = field(default_factory=dict)
    ignore_set: set[str] = field(default_factory=set)
    notes: dict[str, str] = field(default_factory=dict)
    last_output: str = ""
    last_listing: list[str] = field(default_factory=list)   # for `pick`
    last_entries: list[Entry] = field(default_factory=list)  # for `inspect`
    focus_back: list[tuple] = field(default_factory=list)
    focus_forward: list[tuple] = field(default_factory=list)
    pager_enabled: bool = True
    color_enabled: bool = True
    watch_bg: "WatchBg | None" = None
    # NEW feature fields:
    alert_engine: AlertEngine = field(default_factory=AlertEngine)
    aggregator: MultiLogAggregator = field(default_factory=MultiLogAggregator)
    web_server: "HTTPServer | None" = None
    webhook_url: str = ""
    webhook_type: str = "slack"
    cron_output: str = ""
    multi_log_sources: dict[str, list[Entry]] = field(default_factory=dict)
    plugin_dir: str = ""
    # Dashboard + 12 new features:
    dashboard_running: bool = False
    auto_tag_cache: dict[str, str] = field(default_factory=dict)
    profile_dir: str = ""
    template_filter: str = ""
    saved_profiles: dict[str, str] = field(default_factory=dict)
    portal_server: "HTTPServer | None" = None
    case_store: "CaseStore | None" = None
    # Advanced user settings:
    default_z_threshold: float = 2.5
    default_anomaly_window: int = 14
    default_forecast_days: int = 30
    default_burst_window: int = 60
    default_burst_z: float = 3.0
    default_session_gap: int = 30
    default_response_window: int = 300
    output_format: str = "table"
    command_timing: bool = False
    debug_mode: bool = False
    quiet_mode: bool = False
    default_export_dir: str = ""
    score_flag_threshold: float = 0.8
    macro_recording: bool = False
    macro_buffer: list[str] = field(default_factory=list)
    presets: dict[str, dict[str, Any]] = field(default_factory=dict)
    command_times: dict[str, list[float]] = field(default_factory=dict)
    max_output_lines: int = 500
    auto_refresh_interval: float = 0.0


class LogShell(cmd.Cmd):
    intro = (
        "analyzelog interactive shell.  Type 'commands' for a full reference, "
        "'help <name>' for one command, 'quit' to exit.\n"
    )
    prompt = "(log) "

    NO_CAPTURE_CMDS = {"watch", "webportal"}
    _REDIRECT_RE = re.compile(r"^(.*?)\s+(>>|>)\s+(\S+)\s*$")

    def __init__(self, state: ShellState) -> None:
        super().__init__()
        self.state = state
        # Load persistent config
        loaded_aliases = _load_json(_aliases_path(), {})
        if isinstance(loaded_aliases, dict):
            self.state.aliases.update({k: v for k, v in loaded_aliases.items() if isinstance(v, str)})
        loaded_ignore = _load_json(_ignore_path(), [])
        if isinstance(loaded_ignore, list):
            self.state.ignore_set.update(str(u) for u in loaded_ignore if isinstance(u, str))
        loaded_notes = _load_json(_notes_path(), {})
        if isinstance(loaded_notes, dict):
            self.state.notes.update({k: v for k, v in loaded_notes.items() if isinstance(v, str)})
        self._in_script = False
        self._setup_readline()
        self._refresh_prompt()

    # --- helpers -------------------------------------------------------------

    def _setup_readline(self) -> None:
        if readline is None:
            return
        try:
            readline.read_history_file(_history_path())
        except (FileNotFoundError, OSError):
            pass
        try:
            readline.set_history_length(2000)
        except Exception:  # noqa: BLE001
            pass
        atexit.register(self._save_history)

    def _save_history(self) -> None:
        if readline is None:
            return
        try:
            readline.write_history_file(_history_path())
        except OSError:
            pass

    def _refresh_prompt(self) -> None:
        path = self.state.log_path
        n_total = len(self.state.entries)
        n_active = len(self._active_entries())
        bits = []
        if self.state.focused_user:
            bits.append(f"user={self.state.focused_user}")
        if self.state.focused_target:
            bits.append(f"target={self.state.focused_target}")
        if self.state.since:
            bits.append(f"since={self.state.since.date()}")
        if self.state.until:
            bits.append(f"until={self.state.until.date()}")
        tag = (" [" + " ".join(bits) + "]") if bits else ""
        count_str = f"n={n_active}/{n_total}" if n_active != n_total else f"n={n_total}"
        bg_str = ""
        if self.state.watch_bg and self.state.watch_bg.new_count > 0:
            bg_str = f" +{self.state.watch_bg.new_count}new"
        self.prompt = f"(log {path} {count_str}{tag}{bg_str}) "

    def _time_filtered(self) -> list[Entry]:
        """Time-filtered entries, ignoring the global ignore_set.
        Used when a user is named explicitly."""
        return apply_time_filter(self.state.entries, self.state.since, self.state.until)

    def _active_entries(self) -> list[Entry]:
        """Time-filtered + ignore_set applied. Used for stats / global commands."""
        base = self._time_filtered()
        if not self.state.ignore_set:
            return base
        ig = {u.lower() for u in self.state.ignore_set}
        return [e for e in base if not (e.user and e.user.lower() in ig)]

    def _resolve_user(self, arg: str) -> str | None:
        arg = arg.strip()
        if arg:
            return arg
        if self.state.focused_user:
            return self.state.focused_user
        print("No user given and no focused user. Try: user <nick>")
        return None

    def _filtered(self, user: str) -> list[Entry]:
        return [e for e in self._time_filtered() if line_matches_user(e, user)]

    def _filtered_by_target(self, target: str) -> list[Entry]:
        t = target.lower()
        return [e for e in self._active_entries()
                if e.target and e.target.lower() == t]

    def _split(self, line: str) -> list[str]:
        try:
            return shlex.split(line)
        except ValueError:
            return line.split()

    def _push_focus(self) -> None:
        snap = (self.state.focused_user, self.state.focused_target,
                self.state.since, self.state.until)
        self.state.focus_back.append(snap)
        self.state.focus_forward.clear()

    @staticmethod
    def _split_chained(line: str) -> list[str]:
        """Split line on top-level ';' respecting quotes."""
        parts: list[str] = []
        buf: list[str] = []
        in_q: str | None = None
        for ch in line:
            if in_q:
                if ch == in_q:
                    in_q = None
                buf.append(ch)
            elif ch in ('"', "'"):
                in_q = ch
                buf.append(ch)
            elif ch == ";":
                parts.append("".join(buf).strip())
                buf = []
            else:
                buf.append(ch)
        parts.append("".join(buf).strip())
        return [p for p in parts if p]

    def _should_page(self, output: str) -> bool:
        if not output:
            return False
        if not getattr(sys.__stdout__, "isatty", lambda: False)():
            return False
        try:
            rows = shutil.get_terminal_size().lines
        except OSError:
            return False
        return output.count("\n") > max(rows - 2, 10)

    # --- nick / target / view completion sources -----------------------------

    def _nicks(self) -> list[str]:
        return sorted({e.user for e in self.state.entries if e.user})

    def _targets(self) -> list[str]:
        return sorted({e.target for e in self.state.entries if e.target})

    def _complete_prefix(self, text: str, options: Iterable[str]) -> list[str]:
        tl = text.lower()
        return [o for o in options if o.lower().startswith(tl)]

    def _complete_path(self, text: str) -> list[str]:
        head, tail = os.path.split(text)
        base = head or "."
        try:
            items = os.listdir(base)
        except OSError:
            return []
        out = []
        for it in items:
            if not it.startswith(tail):
                continue
            full = os.path.join(head, it) if head else it
            if os.path.isdir(os.path.join(base, it)):
                full += os.sep
            out.append(full)
        return out

    # --- input pipeline (alias / chaining / redirect / capture / pager) -----

    def onecmd(self, line: str) -> bool:  # type: ignore[override]
        if not isinstance(line, str):
            return super().onecmd(line)
        line = line.strip()
        if not line:
            return super().onecmd(line)

        # Macro recording: capture non-macro commands
        if self.state.macro_recording and not line.startswith("macro "):
            self.state.macro_buffer.append(line)

        # Command timing: measure execution time
        import time
        cmd_start = time.perf_counter()
        head_token = line.split()[0] if line.split() else ""

        # ?? → commands
        if line == "??":
            line = "commands"

        # Alias expansion (first whitespace-separated token only)
        head, sep, rest = line.partition(" ")
        if head in self.state.aliases:
            line = self.state.aliases[head] + (sep + rest if sep else "")

        # ; chaining: dispatch each sub-command via onecmd recursively
        if ";" in line:
            parts = self._split_chained(line)
            if len(parts) > 1:
                stop = False
                for sub in parts:
                    stop = bool(self.onecmd(sub))
                    if stop:
                        break
                return stop

        # Trailing redirect
        redirect: tuple[str, str] | None = None
        m = self._REDIRECT_RE.match(line)
        if m:
            line = m.group(1)
            op, path = m.group(2), m.group(3)
            redirect = (path, "a" if op == ">>" else "w")

        # Real-time commands bypass capture (so foreground watch streams)
        if head_token in self.NO_CAPTURE_CMDS:
            return super().onecmd(line)

        # Capture stdout for last/pager/redirect
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                result = super().onecmd(line)
            except Exception as exc:  # noqa: BLE001
                if self.state.debug_mode:
                    import traceback
                    traceback.print_exc()
                print(f"Error: {exc}")
                result = False
        output = buf.getvalue()
        self.state.last_output = output

        # Command timing: record and display
        cmd_elapsed = time.perf_counter() - cmd_start
        if self.state.command_timing:
            if head_token not in self.state.command_times:
                self.state.command_times[head_token] = []
            self.state.command_times[head_token].append(cmd_elapsed)
            # Keep only last 50 runs per command
            if len(self.state.command_times[head_token]) > 50:
                self.state.command_times[head_token] = self.state.command_times[head_token][-50:]
            sys.stdout.write(f"[{cmd_elapsed:.3f}s] ")

        if redirect:
            path, mode = redirect
            try:
                with open(path, mode, encoding="utf-8") as f:
                    f.write(output)
                sys.stdout.write(f"Wrote {len(output)} chars to {path}\n")
            except OSError as exc:
                sys.stdout.write(f"Could not write {path}: {exc}\n")
        elif self.state.pager_enabled and not self._in_script and self._should_page(output):
            try:
                pydoc.pager(output)
            except Exception:  # noqa: BLE001
                sys.stdout.write(output)
        else:
            sys.stdout.write(output)
        return result

    def postcmd(self, stop, line):  # type: ignore[override]
        self._refresh_prompt()
        return stop

    # --- commands ------------------------------------------------------------

    def do_load(self, arg: str) -> None:
        """load <path>   Load a different log file."""
        path = arg.strip().strip('"').strip("'")
        if not path:
            print(f"Currently loaded: {self.state.log_path} ({len(self.state.entries)} entries)")
            return
        try:
            entries = list(iter_entries(path))
        except FileNotFoundError:
            print(f"File not found: {path}")
            return
        self.state.log_path = path
        self.state.entries = entries
        print(f"Loaded {len(entries)} entries from {path}")
        self._refresh_prompt()

    def do_reload(self, arg: str) -> None:
        """reload   Re-read the current log file from disk."""
        try:
            self.state.entries = list(iter_entries(self.state.log_path))
            print(f"Reloaded {len(self.state.entries)} entries from {self.state.log_path}")
            self._refresh_prompt()
        except FileNotFoundError:
            print(f"File not found: {self.state.log_path}")

    def do_report(self, arg: str) -> None:
        """report [user]   Full stats report. With a user, restrict to lines for/about them."""
        user = arg.strip() or self.state.focused_user
        if user:
            entries = self._filtered(user)
            print(f"=== {self.state.log_path}  filtered to user '{user}' ===")
        elif self.state.focused_target:
            entries = self._filtered_by_target(self.state.focused_target)
            print(f"=== {self.state.log_path}  filtered to target '{self.state.focused_target}' ===")
        else:
            entries = self._active_entries()
            print(f"=== {self.state.log_path} ===")
        print_report(summarize(entries, self.state.top_n))

    def do_user(self, arg: str) -> None:
        """user <nick>   Focus on a user (empty arg clears)."""
        nick = arg.strip()
        self._push_focus()
        if not nick:
            self.state.focused_user = None
            print("Cleared focused user.")
        else:
            self.state.focused_user = nick
            matched = self._filtered(nick)
            print(f"Focused on '{nick}' — {len(matched)} matching lines.")
        self._refresh_prompt()

    def do_target(self, arg: str) -> None:
        """target <chan>   Focus on a target/channel (empty arg clears)."""
        t = arg.strip()
        self._push_focus()
        if not t:
            self.state.focused_target = None
            print("Cleared focused target.")
        else:
            self.state.focused_target = t
            matched = self._filtered_by_target(t)
            print(f"Focused on target '{t}' — {len(matched)} matching lines.")
        self._refresh_prompt()

    def do_since(self, arg: str) -> None:
        """since <when>   Lower time bound (ISO date, '5h ago', 'now'; empty clears)."""
        s = arg.strip()
        self._push_focus()
        if not s:
            self.state.since = None
            print("Cleared 'since'.")
        else:
            ts = parse_iso_arg(s)
            if not ts:
                self.state.focus_back.pop()
                print(f"Could not parse: {s!r}")
                return
            self.state.since = ts
            print(f"since = {ts}")
        self._refresh_prompt()

    def do_until(self, arg: str) -> None:
        """until <when>   Upper time bound (ISO date, '5h ago', 'now'; empty clears)."""
        s = arg.strip()
        self._push_focus()
        if not s:
            self.state.until = None
            print("Cleared 'until'.")
        else:
            ts = parse_iso_arg(s)
            if not ts:
                self.state.focus_back.pop()
                print(f"Could not parse: {s!r}")
                return
            self.state.until = ts
            print(f"until = {ts}")
        self._refresh_prompt()

    def do_clear_filters(self, arg: str) -> None:
        """clear_filters   Clear focused user/target and since/until."""
        self._push_focus()
        self.state.focused_user = None
        self.state.focused_target = None
        self.state.since = None
        self.state.until = None
        print("Cleared all global filters.")
        self._refresh_prompt()

    def do_back(self, arg: str) -> None:
        """back   Restore previous focus state."""
        if not self.state.focus_back:
            print("(no previous focus)")
            return
        cur = (self.state.focused_user, self.state.focused_target,
               self.state.since, self.state.until)
        self.state.focus_forward.append(cur)
        prev = self.state.focus_back.pop()
        (self.state.focused_user, self.state.focused_target,
         self.state.since, self.state.until) = prev
        print("Restored previous focus.")
        self._refresh_prompt()

    def do_forward(self, arg: str) -> None:
        """forward   Re-apply focus undone by 'back'."""
        if not self.state.focus_forward:
            print("(no forward focus)")
            return
        cur = (self.state.focused_user, self.state.focused_target,
               self.state.since, self.state.until)
        self.state.focus_back.append(cur)
        nxt = self.state.focus_forward.pop()
        (self.state.focused_user, self.state.focused_target,
         self.state.since, self.state.until) = nxt
        print("Reapplied focus.")
        self._refresh_prompt()

    def do_analyze(self, arg: str) -> None:
        """analyze [nick]   LLM behavior analysis on a user's lines."""
        user = self._resolve_user(arg)
        if not user:
            return
        u = user.lower()
        authored = [e for e in self._time_filtered() if e.user and e.user.lower() == u]
        if not authored:
            print(f"No lines authored by '{user}'.")
            return
        analyze_user_with_llm(
            user, [e.raw for e in authored],
            self.state.llm_url, self.state.llm_model,
            self.state.max_chunk_chars, cache=self.state.llm_cache,
        )

    def do_ask(self, arg: str) -> None:
        """ask [nick] "<question>"   Free-form LLM question about a user's lines."""
        parts = self._split(arg)
        if not parts:
            print('Usage: ask [nick] "<question>"')
            return
        if len(parts) >= 2 and any(
            e.user and e.user.lower() == parts[0].lower()
            for e in self._active_entries()
        ):
            nick = parts[0]
            question = " ".join(parts[1:])
        else:
            nick = self.state.focused_user
            question = " ".join(parts)
        if not nick:
            print('Usage: ask <nick> "<question>"  (or set "user <nick>" first)')
            return
        u = nick.lower()
        authored = [e for e in self._time_filtered() if e.user and e.user.lower() == u]
        if not authored:
            print(f"No lines authored by '{nick}'.")
            return
        ask_about_user_with_llm(
            nick, question, [e.raw for e in authored],
            self.state.llm_url, self.state.llm_model,
            self.state.max_chunk_chars, cache=self.state.llm_cache,
        )

    def do_show(self, arg: str) -> None:
        """show [nick] [N]   Print up to N raw lines for the user (default 10)."""
        parts = self._split(arg)
        nick = None
        n = 10
        for p in parts:
            if p.isdigit():
                n = int(p)
            else:
                nick = p
        user = self._resolve_user(nick or "")
        if not user:
            return
        matched = self._filtered(user)
        if not matched:
            print(f"No lines match '{user}'.")
            return
        self.state.last_entries = matched[:n]
        print(f"First {min(n, len(matched))}/{len(matched)} lines for '{user}':")
        for e in matched[:n]:
            print(f"  {e.raw[:300]}")

    def do_interact(self, arg: str) -> None:
        """interact <userA> <userB> [--no-llm] [--show N]"""
        parts = self._split(arg)
        if len(parts) < 2:
            print("Usage: interact <userA> <userB> [--no-llm] [--show N]")
            return
        a, b = parts[0], parts[1]
        no_llm = False
        show_n = 0
        i = 2
        while i < len(parts):
            tok = parts[i]
            if tok == "--no-llm":
                no_llm = True
            elif tok == "--show" and i + 1 < len(parts) and parts[i + 1].isdigit():
                show_n = int(parts[i + 1])
                i += 1
            else:
                print(f"Unknown option: {tok}")
                return
            i += 1

        matched = [e for e in self._active_entries() if line_is_interaction(e, a, b)]
        if not matched:
            print(f"No direct interactions found between '{a}' and '{b}'.")
            return

        print(f"=== {self.state.log_path}  interactions: {a} ↔ {b} ({len(matched)} lines) ===")
        by_author = Counter(e.user for e in matched if e.user)
        print("Lines per author:")
        for nick, n in by_author.most_common():
            print(f"  {n:>7}  {nick}")
        by_target = Counter(e.target for e in matched if e.target)
        if by_target:
            print("Where they interact:")
            for tgt, n in by_target.most_common(10):
                print(f"  {n:>7}  {tgt}")
        ts_list = [e.ts for e in matched if e.ts]
        if ts_list:
            print(f"Time range: {min(ts_list)}  →  {max(ts_list)}")

        if show_n:
            print(f"\nFirst {min(show_n, len(matched))} interaction lines:")
            for e in matched[:show_n]:
                print(f"  {e.text[:300]}")

        if not no_llm:
            analyze_interaction_with_llm(
                a, b, [e.text for e in matched],
                self.state.llm_url, self.state.llm_model,
                self.state.max_chunk_chars, cache=self.state.llm_cache,
            )

    def do_compare(self, arg: str) -> None:
        """compare <userA> <userB> [<userC> ...] [--no-llm]
        Multi-user behavior comparison: side-by-side table + LLM."""
        parts = self._split(arg)
        users = [p for p in parts if not p.startswith("--")]
        flags = [p for p in parts if p.startswith("--")]
        if len(users) < 2:
            print("Usage: compare <userA> <userB> [<userC> ...] [--no-llm]")
            return
        no_llm = "--no-llm" in flags

        active = self._active_entries()
        profiles = [build_profile(active, u) for u in users]

        print(f"=== {self.state.log_path}  compare: {' vs '.join(users)} ===")
        if not any(p["authored"] for p in profiles):
            print(f"None of {users} authored lines in this log.")
            return
        for p in profiles:
            if p["authored"] == 0:
                print(f"Note: '{p['user']}' has no authored lines; only mentions count.")

        print_compare_table_n(profiles)

        if not no_llm:
            compare_n_users_with_llm(profiles, self.state.llm_url,
                                     self.state.llm_model,
                                     self.state.max_chunk_chars,
                                     cache=self.state.llm_cache)

    def do_top(self, arg: str) -> None:
        """top [users|events|targets|levels] [N]"""
        parts = self._split(arg) or ["users"]
        kind = parts[0].lower()
        n = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else self.state.top_n
        s = summarize(self._active_entries(), n)
        key = {"users": "top_users", "events": "top_events",
               "targets": "top_targets", "channels": "top_targets",
               "levels": None}.get(kind)
        if kind == "levels":
            print(s["levels"] or "(none)")
            return
        if not key or not s.get(key):
            print(f"Unknown or empty: {kind}. Try: users | events | targets | levels")
            return
        rows = s[key]
        self.state.last_listing = [name for name, _ in rows]
        for name, count in rows:
            note = self.state.notes.get(name, "") if kind == "users" else ""
            note_str = f"  // {note}" if note else ""
            print(f"  {count:>7}  {name}{note_str}")

    def do_hours(self, arg: str) -> None:
        """hours [compact]   Activity histogram by hour-of-day. Auto-compact when narrow."""
        s = summarize(self._active_entries(), self.state.top_n)
        if not s["by_hour"]:
            print("(no timestamps)")
            return
        try:
            width = shutil.get_terminal_size().columns
        except OSError:
            width = 80
        compact = arg.strip() == "compact" or width < 60
        if compact:
            all_hours = [s["by_hour"].get(h, 0) for h in range(24)]
            print(f"  {sparkline(all_hours)}  (00..23)  total={sum(all_hours)}")
            return
        peak = max(s["by_hour"].values()) or 1
        for h, n in s["by_hour"].items():
            bar = "█" * int(40 * n / peak)
            print(f"  {h:02d}  {n:>7}  {bar}")

    def do_days(self, arg: str) -> None:
        """days [compact]   Activity histogram by date. Auto-compact when narrow."""
        s = summarize(self._active_entries(), self.state.top_n)
        if not s["by_day"]:
            print("(no timestamps)")
            return
        try:
            width = shutil.get_terminal_size().columns
        except OSError:
            width = 80
        compact = arg.strip() == "compact" or width < 60
        if compact:
            days = sorted(s["by_day"].items())
            counts = [n for _, n in days]
            print(f"  {sparkline(counts)}  ({days[0][0]}..{days[-1][0]})  total={sum(counts)}")
            return
        peak = max(s["by_day"].values()) or 1
        for d, n in s["by_day"].items():
            bar = "█" * int(40 * n / peak)
            print(f"  {d}  {n:>7}  {bar}")

    def do_errors(self, arg: str) -> None:
        """errors   Error-like entries."""
        active = self._active_entries()
        s = summarize(active, self.state.top_n)
        if not s["errors"]:
            print("(none)")
            return
        # Re-derive Entry objects to populate last_entries (summarize loses them).
        err_entries: list[Entry] = []
        seen_raw = set(s["errors"])
        for e in active:
            if e.raw in seen_raw:
                err_entries.append(e)
                if len(err_entries) >= len(s["errors"]):
                    break
        self.state.last_entries = err_entries
        for line in s["errors"]:
            print(f"  {line[:300]}")

    def do_grep(self, arg: str) -> None:
        """grep [--user U] [--target T] [--since W] [--until W] [--score 'EXPR'] <regex>"""
        parts = self._split(arg)
        user = self.state.focused_user
        target = self.state.focused_target
        since = self.state.since
        until = self.state.until
        score_filters: list[tuple[str, str, float]] = []
        positional: list[str] = []
        i = 0
        while i < len(parts):
            tok = parts[i]
            if tok == "--user" and i + 1 < len(parts):
                user = parts[i + 1]; i += 2; continue
            if tok == "--target" and i + 1 < len(parts):
                target = parts[i + 1]; i += 2; continue
            if tok == "--since" and i + 1 < len(parts):
                since = parse_iso_arg(parts[i + 1]); i += 2; continue
            if tok == "--until" and i + 1 < len(parts):
                until = parse_iso_arg(parts[i + 1]); i += 2; continue
            if tok == "--score" and i + 1 < len(parts):
                try:
                    score_filters = parse_score_filter(parts[i + 1])
                except ValueError as exc:
                    print(f"Bad score filter: {exc}"); return
                i += 2; continue
            positional.append(tok); i += 1
        if not positional:
            print("Usage: grep [--user U] [--target T] [--since W] [--until W] [--score 'EXPR'] <regex>")
            return
        pattern = " ".join(positional)
        try:
            rx = re.compile(pattern, re.I)
        except re.error as exc:
            print(f"Bad regex: {exc}")
            return
        u_l = user.lower() if user else None
        t_l = target.lower() if target else None
        matched: list[Entry] = []
        for e in self.state.entries:
            if not in_time_range(e.ts, since, until):
                continue
            if u_l and not (e.user and e.user.lower() == u_l) and not _mentions(e.raw or "", user):
                continue
            if t_l and not (e.target and e.target.lower() == t_l):
                continue
            if score_filters and not matches_score_filter(e, score_filters):
                continue
            if rx.search(e.raw):
                matched.append(e)
                print(f"  {e.raw[:300]}")
                if len(matched) >= 50:
                    print("(truncated at 50 matches — refine your pattern)")
                    break
        self.state.last_entries = matched
        if not matched:
            print("(no matches)")

    # --- new analytic commands ----------------------------------------------

    def do_flagged(self, arg: str) -> None:
        """flagged "EXPR" [user]   Lines where score expr matches.
        e.g. flagged "llama>0.8"     flagged "llama>=0.7 heu>0.5" cfuser"""
        parts = self._split(arg)
        if not parts:
            print('Usage: flagged "EXPR" [user]   e.g. flagged "llama>0.8"')
            return
        expr = parts[0]
        user = parts[1] if len(parts) > 1 else self.state.focused_user
        try:
            filters = parse_score_filter(expr)
        except ValueError as exc:
            print(f"Bad score expression: {exc}")
            return
        u_l = user.lower() if user else None
        cap = 100
        matched: list[Entry] = []
        for e in self._active_entries():
            if u_l and not (e.user and e.user.lower() == u_l):
                continue
            if not matches_score_filter(e, filters):
                continue
            matched.append(e)
            print(f"  {e.raw[:300]}")
            if len(matched) >= cap:
                print(f"(truncated at {cap} matches — refine your filter)")
                break
        self.state.last_entries = matched
        if not matched:
            print("(no matches)")
        else:
            print(f"({len(matched)} match{'es' if len(matched) != 1 else ''})")

    def do_dist(self, arg: str) -> None:
        """dist [user]   Score distributions / percentiles. No user → population."""
        user = arg.strip() or self.state.focused_user
        active = self._active_entries()
        if user:
            scores = collect_scores(active, user)
            label = user
        else:
            scores = collect_scores(active)
            label = "(population)"
        print_score_dist(label, scores)

    def do_zscores(self, arg: str) -> None:
        """zscores [user]   Per-score z-scores for user vs population."""
        user = self._resolve_user(arg)
        if not user:
            return
        active = self._active_entries()
        profile = build_profile(active, user)
        pop = population_score_stats(active)
        print_zscores(profile, pop)

    def do_similar(self, arg: str) -> None:
        """similar [threshold] [min_lines]   Find user pairs with similar fingerprints."""
        parts = self._split(arg)
        threshold = 0.95
        min_lines = 5
        if len(parts) >= 1:
            try:
                threshold = float(parts[0])
            except ValueError:
                print("threshold must be a float between 0 and 1"); return
        if len(parts) >= 2:
            try:
                min_lines = int(parts[1])
            except ValueError:
                print("min_lines must be int"); return
        pairs = find_similar_users(self._active_entries(),
                                   min_lines=min_lines, threshold=threshold)
        # Record both members of each pair for `pick`
        seen: list[str] = []
        for a, b, *_ in pairs:
            if a not in seen:
                seen.append(a)
            if b not in seen:
                seen.append(b)
        self.state.last_listing = seen
        print_similar_users(pairs)

    def do_bursts(self, arg: str) -> None:
        """bursts [user] [window_seconds] [z_threshold]   Detect activity bursts."""
        parts = self._split(arg)
        nick = None
        window = 60
        z = 3.0
        floats: list[float] = []
        for p in parts:
            try:
                v = float(p)
                floats.append(v)
            except ValueError:
                if nick is None:
                    nick = p
        if len(floats) >= 1:
            window = int(floats[0])
        if len(floats) >= 2:
            z = floats[1]
        user = self._resolve_user(nick or "")
        if not user:
            return
        bursts = detect_bursts(self._active_entries(), user,
                               window_seconds=window, z_threshold=z)
        print_bursts(user, bursts, window)

    def do_threads(self, arg: str) -> None:
        """threads [user]   Reply/mention reconstruction around a user."""
        user = self._resolve_user(arg)
        if not user:
            return
        thread = build_thread_for_user(self._active_entries(), user)
        if not thread:
            print(f"No thread lines for {user}.")
            return
        self.state.last_entries = [e for e, _ in thread[:200]]
        print(f"\nThread reconstruction for {user} ({len(thread)} lines):")
        for e, tgt in thread[:200]:
            arrow = f" -> {tgt}" if tgt else ""
            ts = _fmt_dt(e.ts)
            print(f"  {ts}  {(e.user or '?'):>15}{arrow:<20}  {(e.text or e.raw)[:160]}")
        if len(thread) > 200:
            print(f"(showing first 200 of {len(thread)})")

    def do_edges(self, arg: str) -> None:
        """edges [N]   Top N reply/mention edges."""
        parts = self._split(arg)
        n = int(parts[0]) if parts and parts[0].isdigit() else 25
        edges = build_edge_graph(self._active_entries())
        if not edges:
            print("(no edges detected)")
            return
        print(f"\nTop {min(n, len(edges))} edges (source -> target, weight):")
        for (a, b), w in edges.most_common(n):
            print(f"  {w:>5}  {a} -> {b}")

    def do_view(self, arg: str) -> None:
        """view {save NAME | load NAME | list | drop NAME | show NAME}
        Save the current global filters as a named view."""
        parts = self._split(arg)
        if not parts:
            self.do_view("list")
            return
        cmd_ = parts[0].lower()
        if cmd_ == "list":
            if not self.state.views:
                print("(no saved views)")
                return
            for name, v in self.state.views.items():
                print(f"  {name}: {view_describe(v)}")
            return
        if cmd_ == "save":
            if len(parts) < 2:
                print("Usage: view save NAME"); return
            name = parts[1]
            self.state.views[name] = View(
                name=name,
                user=self.state.focused_user,
                target=self.state.focused_target,
                since=self.state.since,
                until=self.state.until,
            )
            print(f"Saved view '{name}': {view_describe(self.state.views[name])}")
            return
        if cmd_ == "load":
            if len(parts) < 2 or parts[1] not in self.state.views:
                print("Usage: view load NAME (existing: " + ", ".join(self.state.views) + ")")
                return
            v = self.state.views[parts[1]]
            self.state.focused_user = v.user
            self.state.focused_target = v.target
            self.state.since = v.since
            self.state.until = v.until
            print(f"Loaded view '{v.name}': {view_describe(v)}")
            self._refresh_prompt()
            return
        if cmd_ == "drop":
            if len(parts) < 2:
                print("Usage: view drop NAME"); return
            self.state.views.pop(parts[1], None)
            print(f"Dropped view '{parts[1]}'.")
            return
        if cmd_ == "show":
            if len(parts) < 2 or parts[1] not in self.state.views:
                print("Usage: view show NAME"); return
            v = self.state.views[parts[1]]
            print(f"  {v.name}: {view_describe(v)}")
            return
        print(f"Unknown view subcommand: {cmd_}")

    def do_export(self, arg: str) -> None:
        """export {profile <user> <path.json|csv> | report <path.json> | edges <path.csv|dot>}"""
        parts = self._split(arg)
        if len(parts) < 2:
            print("Usage: export profile <user> <path>  |  export report <path>  |  export edges <path>")
            return
        kind = parts[0].lower()
        if kind == "profile":
            if len(parts) < 3:
                print("Usage: export profile <user> <path>"); return
            user, path = parts[1], parts[2]
            profile = build_profile(self._active_entries(), user)
            ext = os.path.splitext(path)[1].lower()
            if ext == ".csv":
                export_profile_csv(profile, path)
            else:
                export_profile_json(profile, path)
            print(f"Wrote {path}")
            return
        if kind == "report":
            path = parts[1]
            export_summary_json(summarize(self._active_entries(), self.state.top_n), path)
            print(f"Wrote {path}")
            return
        if kind == "edges":
            path = parts[1]
            edges = build_edge_graph(self._active_entries())
            ext = os.path.splitext(path)[1].lower()
            if ext == ".dot":
                export_edges_dot(edges, path)
            else:
                export_edges_csv(edges, path)
            print(f"Wrote {path} ({len(edges)} edges)")
            return
        print(f"Unknown export kind: {kind}")

    def do_diff(self, arg: str) -> None:
        """diff <other.log>   Diff current log against another."""
        path = arg.strip()
        if not path:
            print("Usage: diff <other.log>"); return
        try:
            other = list(iter_entries(path))
        except FileNotFoundError:
            print(f"File not found: {path}"); return
        a = summarize(self._active_entries(), 1000)
        b = summarize(other, 1000)
        print_log_diff(self.state.log_path, path, diff_summaries(a, b))

    def do_watch(self, arg: str) -> None:
        """watch [poll_seconds] [--bg | --stop]
        Tail the current log file. --bg runs in a background thread (prompt
        shows '+N new'); --stop terminates a running background watch."""
        parts = self._split(arg)
        if "--stop" in parts:
            if self.state.watch_bg:
                self.state.watch_bg.stop()
                self.state.watch_bg = None
                print("Stopped background watch.")
            else:
                print("(no background watch running)")
            return
        bg = "--bg" in parts
        nums = [p for p in parts if p not in ("--bg", "--stop")]
        poll = 2.0
        if nums:
            try:
                poll = float(nums[0])
            except ValueError:
                print("poll_seconds must be a number"); return
        if bg:
            if self.state.watch_bg:
                print("(background watch already running; use 'watch --stop')")
                return
            self.state.watch_bg = WatchBg(self, poll=poll)
            self.state.watch_bg.start()
            print(f"Watching {self.state.log_path} in background (poll={poll}s). 'watch --stop' to halt.")
            return

        def on_new(new: list[Entry]) -> None:
            self.state.entries.extend(new)
            watch_callback_default(new)
            self._refresh_prompt()

        print(f"Watching {self.state.log_path} (poll={poll}s). Ctrl-C to stop.")
        watch_loop(self.state.log_path, on_new, poll_seconds=poll)

    def do_set(self, arg: str) -> None:
        """set <key> <value>   Configure: top, llm_url, llm_model, max_chunk_chars,
        llm_cache, pager (on/off), color (on/off)."""
        parts = self._split(arg)
        if len(parts) < 2:
            self.do_settings("")
            return
        key, value = parts[0], " ".join(parts[1:])
        bool_yes = {"on", "yes", "true", "1"}
        if key == "top":
            try:
                self.state.top_n = int(value)
            except ValueError:
                print("top must be an integer"); return
        elif key == "llm_url":
            self.state.llm_url = value
        elif key == "llm_model":
            self.state.llm_model = value
        elif key == "max_chunk_chars":
            try:
                self.state.max_chunk_chars = int(value)
            except ValueError:
                print("max_chunk_chars must be an integer"); return
        elif key == "llm_cache":
            if value.lower() in {"none", "off", ""}:
                self.state.llm_cache = None
            else:
                self.state.llm_cache = LLMCache(value)
            print(f"llm_cache = {value or '(off)'}")
            return
        elif key == "pager":
            self.state.pager_enabled = value.lower() in bool_yes
            print(f"pager = {self.state.pager_enabled}")
            return
        elif key == "color":
            on = value.lower() in bool_yes
            self.state.color_enabled = on
            _Color.enabled = on
            print(f"color = {on}")
            return
        elif key == "webhook_url":
            self.state.webhook_url = value
        elif key == "webhook_type":
            self.state.webhook_type = value
        elif key == "plugin_dir":
            self.state.plugin_dir = value
        else:
            print(f"Unknown setting: {key}. See 'settings'.")
            return
        attr = "top_n" if key == "top" else key
        print(f"{key} = {getattr(self.state, attr)}")

    def do_settings(self, arg: str) -> None:
        """settings   Show current settings."""
        st = self.state
        print(f"  log_path        = {st.log_path}")
        print(f"  entries         = {len(st.entries)}  active = {len(self._active_entries())}")
        print(f"  focused_user    = {st.focused_user}")
        print(f"  focused_target  = {st.focused_target}")
        print(f"  since           = {st.since}")
        print(f"  until           = {st.until}")
        print(f"  top             = {st.top_n}")
        print(f"  llm_url         = {st.llm_url}")
        print(f"  llm_model       = {st.llm_model}")
        print(f"  max_chunk_chars = {st.max_chunk_chars}")
        if st.llm_cache:
            print(f"  llm_cache       = {st.llm_cache.path}  ({len(st.llm_cache)} entries)")
        else:
            print(f"  llm_cache       = (off)")
        print(f"  pager           = {st.pager_enabled}")
        print(f"  color           = {st.color_enabled}")
        if st.views:
            print(f"  views           = {', '.join(st.views)}")
        if st.aliases:
            print(f"  aliases         = {len(st.aliases)} ({', '.join(list(st.aliases)[:5])}{'...' if len(st.aliases) > 5 else ''})")
        if st.ignore_set:
            print(f"  ignored         = {len(st.ignore_set)} users")
        if st.notes:
            print(f"  notes           = {len(st.notes)} users")
        if st.watch_bg:
            print(f"  watch_bg        = running (+{st.watch_bg.new_count} new since last check)")
        print(f"  webhook_url     = {st.webhook_url or '(not set)'}")
        print(f"  webhook_type    = {st.webhook_type}")
        print(f"  plugin_dir      = {st.plugin_dir or '(not set)'}")
        print(f"  rules           = {len(st.alert_engine.rules)} alert rules")
        print(f"  multi_sources   = {len(st.multi_log_sources)} sources")
        if st.web_server:
            print(f"  web_server      = running (:{st.web_server.server_port})")
        if st.portal_server:
            print(f"  webportal       = running (:{st.portal_server.server_port})")
        else:
            print(f"  webportal       = (off)")
        print(f"  back/fwd        = {len(st.focus_back)}/{len(st.focus_forward)}")

    def do_config(self, arg: str) -> None:
        """config [view|set|reset|llm|display|filters|system]   View/set configuration.

        Sub-commands:
          config            Show all config grouped by category
          config view       Same as above
          config set KEY VAL  Set a config key (same keys as 'set')
          config reset KEY  Reset a config key to its default
          config llm        Show LLM-related settings
          config display    Show display settings (pager, color)
          config filters    Show active filters (focus, target, since, until)
          config system     Show system info (entries, servers, webhooks)
        """
        parts = self._split(arg)
        if not parts or parts[0] in ("view", ""):
            self._config_view()
        elif parts[0] == "set":
            if len(parts) < 3:
                print("Usage: config set <key> <value>")
                print("Keys: top, llm_url, llm_model, max_chunk_chars, llm_cache, pager, color, webhook_url, webhook_type, plugin_dir")
                return
            self.do_set(f"{parts[1]} {' '.join(parts[2:])}")
        elif parts[0] == "reset":
            if len(parts) < 2:
                print("Usage: config reset <key>")
                print("Resets a key to its default value.")
                return
            self._config_reset(parts[1])
        elif parts[0] == "llm":
            self._config_llm()
        elif parts[0] == "display":
            self._config_display()
        elif parts[0] == "filters":
            self._config_filters()
        elif parts[0] == "system":
            self._config_system()
        else:
            print(f"Unknown sub-command: {parts[0]}")
            print("Use: config [view|set|reset|llm|display|filters|system]")

    def _config_view(self) -> None:
        st = self.state
        print("=== LLM ===")
        print(f"  llm_url         = {st.llm_url}")
        print(f"  llm_model       = {st.llm_model}")
        print(f"  max_chunk_chars = {st.max_chunk_chars}")
        if st.llm_cache:
            print(f"  llm_cache       = {st.llm_cache.path}  ({len(st.llm_cache)} entries)")
        else:
            print(f"  llm_cache       = (off)")
        print()
        print("=== Display ===")
        print(f"  pager           = {st.pager_enabled}")
        print(f"  color           = {st.color_enabled}")
        print(f"  top             = {st.top_n}")
        print()
        print("=== Filters ===")
        print(f"  focused_user    = {st.focused_user or '(none)'}")
        print(f"  focused_target  = {st.focused_target or '(none)'}")
        print(f"  since           = {st.since or '(none)'}")
        print(f"  until           = {st.until or '(none)'}")
        if st.ignore_set:
            print(f"  ignored         = {len(st.ignore_set)} users")
        if st.views:
            print(f"  views           = {', '.join(st.views)}")
        print()
        print("=== System ===")
        print(f"  log_path        = {st.log_path}")
        print(f"  entries         = {len(st.entries)}  active = {len(self._active_entries())}")
        if st.web_server:
            print(f"  web_server      = running (:{st.web_server.server_port})")
        if st.portal_server:
            print(f"  webportal       = running (:{st.portal_server.server_port})")
        else:
            print(f"  webportal       = (off)")
        print(f"  webhook_url     = {st.webhook_url or '(not set)'}")
        print(f"  webhook_type    = {st.webhook_type}")
        print(f"  plugin_dir      = {st.plugin_dir or '(not set)'}")
        print(f"  rules           = {len(st.alert_engine.rules)} alert rules")
        print(f"  multi_sources   = {len(st.multi_log_sources)} sources")
        if st.aliases:
            print(f"  aliases         = {len(st.aliases)} ({', '.join(list(st.aliases)[:5])}{'...' if len(st.aliases) > 5 else ''})")
        if st.notes:
            print(f"  notes           = {len(st.notes)} users")
        if st.watch_bg:
            print(f"  watch_bg        = running (+{st.watch_bg.new_count} new)")
        print(f"  back/fwd        = {len(st.focus_back)}/{len(st.focus_forward)}")

    def _config_llm(self) -> None:
        st = self.state
        print("=== LLM Configuration ===")
        print(f"  llm_url         = {st.llm_url}")
        print(f"  llm_model       = {st.llm_model}")
        print(f"  max_chunk_chars = {st.max_chunk_chars}")
        if st.llm_cache:
            print(f"  llm_cache       = {st.llm_cache.path}  ({len(st.llm_cache)} entries)")
        else:
            print(f"  llm_cache       = (off)")

    def _config_display(self) -> None:
        st = self.state
        print("=== Display Configuration ===")
        print(f"  pager           = {st.pager_enabled}")
        print(f"  color           = {st.color_enabled}")
        print(f"  top             = {st.top_n}")

    def _config_filters(self) -> None:
        st = self.state
        print("=== Active Filters ===")
        print(f"  focused_user    = {st.focused_user or '(none)'}")
        print(f"  focused_target  = {st.focused_target or '(none)'}")
        print(f"  since           = {st.since or '(none)'}")
        print(f"  until           = {st.until or '(none)'}")
        if st.ignore_set:
            print(f"  ignored         = {len(st.ignore_set)} users: {', '.join(sorted(st.ignore_set)[:10])}{'...' if len(st.ignore_set) > 10 else ''}")
        if st.views:
            print(f"  views           = {', '.join(st.views)}")
        active = self._active_entries()
        print(f"  active entries  = {len(active)} / {len(st.entries)} total")

    def _config_system(self) -> None:
        st = self.state
        print("=== System ===")
        print(f"  log_path        = {st.log_path}")
        print(f"  entries         = {len(st.entries)}  active = {len(self._active_entries())}")
        if st.web_server:
            print(f"  web_server      = running (:{st.web_server.server_port})")
        if st.portal_server:
            print(f"  webportal       = running (:{st.portal_server.server_port})")
        else:
            print(f"  webportal       = (off)")
        print(f"  webhook_url     = {st.webhook_url or '(not set)'}")
        print(f"  webhook_type    = {st.webhook_type}")
        print(f"  plugin_dir      = {st.plugin_dir or '(not set)'}")
        print(f"  rules           = {len(st.alert_engine.rules)} alert rules")
        print(f"  multi_sources   = {len(st.multi_log_sources)} sources")
        if st.aliases:
            print(f"  aliases         = {len(st.aliases)} ({', '.join(list(st.aliases)[:5])}{'...' if len(st.aliases) > 5 else ''})")
        if st.notes:
            print(f"  notes           = {len(st.notes)} users")
        if st.watch_bg:
            print(f"  watch_bg        = running (+{st.watch_bg.new_count} new)")
        print(f"  back/fwd        = {len(st.focus_back)}/{len(st.focus_forward)}")

    CONFIG_DEFAULTS: dict[str, object] = {
        "top": 15,
        "top_n": 15,
        "llm_url": "http://127.0.0.1:8033/",
        "llm_model": "local",
        "max_chunk_chars": 12000,
        "llm_cache": None,
        "pager": True,
        "pager_enabled": True,
        "color": True,
        "color_enabled": True,
        "webhook_url": "",
        "webhook_type": "slack",
        "plugin_dir": "",
    }

    def _config_reset(self, key: str) -> None:
        defaults = self.CONFIG_DEFAULTS
        if key not in defaults and key not in ("focused_user", "focused_target", "since", "until"):
            print(f"Unknown key: {key}. Cannot reset.")
            return
        if key == "focused_user":
            self.state.focused_user = None
            print("focused_user = (none)")
        elif key == "focused_target":
            self.state.focused_target = None
            print("focused_target = (none)")
        elif key == "since":
            self.state.since = None
            print("since = (none)")
        elif key == "until":
            self.state.until = None
            print("until = (none)")
        elif key in defaults:
            val = defaults[key]
            setattr(self.state, key, val)
            if key in ("color", "color_enabled"):
                _Color.enabled = True
            print(f"{key} = {val}")

    def do_commands(self, arg: str) -> None:
        """commands   Print all commands with a short description and usage."""
        ref: list[tuple[str, str, str]] = [
            ("load", "load <path>", "Load a different log file."),
            ("reload", "reload", "Re-read the current log file from disk."),
            ("watch", "watch [poll_seconds] [--bg | --stop]",
             "Tail the log (foreground or background)."),
            ("report", "report [user]", "Full stats report (honors since/until/focused_target)."),
            ("info", "info [user]", "One-line summary of a user (with note if any)."),
            ("user", "user <nick>", "Set the focused user."),
            ("target", "target <chan>", "Set the focused target/channel."),
            ("since", "since <when>", "Lower time bound (ISO date or '5h ago')."),
            ("until", "until <when>", "Upper time bound."),
            ("back", "back", "Restore previous focus state."),
            ("forward", "forward", "Re-apply focus undone by 'back'."),
            ("clear_filters", "clear_filters", "Clear focused user/target and since/until."),
            ("analyze", "analyze [nick]", "LLM behavior analysis on a user's lines."),
            ("ask", 'ask [nick] "<question>"', "Free-form LLM question via the chunking pipeline."),
            ("interact", "interact <A> <B> [--show N] [--no-llm]",
             "Direct exchanges between two users + LLM relationship analysis."),
            ("compare", "compare <A> <B> [<C>...] [--no-llm]",
             "Multi-user behavior comparison: side-by-side table + LLM."),
            ("show", "show [nick] [N]", "Print up to N raw lines for the user (default 10)."),
            ("flagged", 'flagged "EXPR" [user]',
             'Lines where score expression matches (e.g. "llama>0.8 heu>0.5").'),
            ("dist", "dist [user]", "Score distributions / percentiles (no user = population)."),
            ("zscores", "zscores [user]", "Per-score z-scores for user vs population."),
            ("similar", "similar [threshold] [min_lines]", "Find user pairs with similar fingerprints."),
            ("bursts", "bursts [user] [window_s] [z]", "Detect activity bursts."),
            ("threads", "threads [user]", "Reply/mention reconstruction around a user."),
            ("edges", "edges [N]", "Top N reply/mention edges in the corpus."),
            ("top", "top [users|events|targets|levels] [N]", "Show a top-N ranking."),
            ("hours", "hours [compact]", "Activity histogram by hour-of-day (sparkline if narrow)."),
            ("days", "days [compact]", "Activity histogram by date (sparkline if narrow)."),
            ("errors", "errors", "Error-like entries."),
            ("grep", "grep [--user U] [--target T] [--since W] [--until W] [--score E] <regex>",
             "Filtered regex search (cap 50)."),
            ("pick", "pick <N>", "Focus on the Nth item from the previous listing."),
            ("inspect", "inspect <N>", "Show full details for the Nth entry from the previous listing."),
            ("last", "last", "Re-print the previous command's output."),
            ("view", "view {save|load|drop|show|list} [NAME]", "Save/load named filter sets."),
            ("export", "export {profile <user> <path> | report <path> | edges <path>}",
             "Serialize profiles, summary, or edge graph."),
            ("diff", "diff <other.log>", "Diff current log against another."),
            ("script", "script <path>", "Run TUI commands from a file (one per line; # comments)."),
            ("alias", "alias [<name> = <command>]",
             "Define/list/remove aliases (persisted)."),
            ("ignore", "ignore [add|drop|list] <user...>",
             "Maintain global ignore list (excluded from analyses)."),
            ("note", "note <user> [<text> | --del]", "Attach a note to a user (persisted)."),
            ("set", "set <key> <value>",
             "Configure: top, llm_url, llm_model, max_chunk_chars, llm_cache, pager, color, webhook_url, webhook_type, plugin_dir."),
("settings", "settings", "Show current settings."),
            ("config", "config [view|set|reset|llm|display|filters|system]", "View/set grouped configuration."),
            ("sessions", "sessions [user] [gap_min]", "Detect user sessions with configurable gap."),
            ("response_times", "response_times [user] [window_sec]", "Response time analysis between users."),
            ("sentiment", "sentiment [user]", "Sentiment analysis for a user."),
            ("topics", "topics [user]", "Keyword and n-gram extraction for a user."),
            ("sequences", "sequences [min_support]", "Common user interaction sequences."),
            ("anomalies", "anomalies [user] [z]", "Detect behavioral anomalies."),
            ("lifecycle", "lifecycle [user]", "User lifecycle analysis (first/last seen, trend, stages)."),
            ("pattern", "pattern [user]", "Pattern-of-life analysis (hourly/weekly profile)."),
            ("rules", "rules [add|remove|toggle] ...", "Manage alert rules engine."),
            ("correlate", "correlate <path> [window_s]", "Cross-log event correlation."),
            ("timeline", "timeline [user] [width]", "ASCII timeline visualization."),
            ("heatmap", "heatmap [user] [months]", "Calendar activity heatmap."),
            ("net", "net [N]", "ASCII network graph of top interaction edges."),
            ("export_html", "export_html <path> [user...]", "Generate HTML report."),
            ("export_sql", "export_sql <path>", "Export entries to SQLite database."),
            ("sql", "sql <db> <query>", "Query a SQLite export."),
            ("prometheus", "prometheus", "Print Prometheus metrics."),
            ("multi", "multi {add|list|clear|report} ...", "Multi-log aggregation."),
            ("aggregate", "aggregate", "Alias for 'multi report'."),
            ("llm_explain", "llm_explain [user] [z]", "Detect anomalies and have LLM explain them."),
            ("summarize", "summarize <A> <B>", "LLM conversation summarization."),
            ("cluster", "cluster [min_lines] [N]", "LLM clustering of user behavior."),
            ("auto_report", "auto_report", "LLM-generated narrative report."),
            ("plugin", "plugin {load|list|reload} [dir]", "Manage analysis plugins."),
            ("web", "web {start|stop|status} [port]", "Start/stop the web API server."),
            ("webportal", "webportal {start|stop|status} [port]",
             "Start/stop the portal (black+green chat UI, default :80)."),
            ("webhook", "webhook {set|test|clear} ...", "Configure Slack/Discord webhook."),
            ("cron", "cron [--output <path>] [--webhook-url <url>]", "Run analysis in cron mode."),
            ("templates", "templates [N]", "Extract common log line templates."),
            ("changepoints", "changepoints [user] [window_days]", "Detect behavioral change points."),
            ("rootcause", "rootcause <user> [lookback_sec]", "Find root causes preceding a user's activity."),
            ("forecast", "forecast [user] [days]", "Forecast future activity volume."),
            ("multifactor", "multifactor [user]", "Multi-factor anomaly score."),
            ("chart", "chart {timeline|histogram|network} <path> ...", "Generate matplotlib charts."),
            ("dataframe", "dataframe [expression]", "View entries as pandas DataFrame."),
            ("recurrence", "recurrence [user]", "Detect periodic patterns (weekly/daily/hourly)."),
            ("churn", "churn [user]", "Predict churn risk for a user."),
            ("pareto", "pareto [users|events|targets|levels]", "Pareto analysis (80/20 rule)."),
            ("dashboard", "dashboard", "Launch curses real-time dashboard."),
            ("watch_alert", "watch_alert [poll_sec]", "Tail log with alert-engine evaluation + webhook."),
            ("forecast_anomaly", "forecast_anomaly <user> [z] [days]", "Anomaly detection using forecast baseline."),
            ("alert_fatigue", "alert_fatigue [window_h]", "Alert fatigue scores for each rule."),
            ("export_html_drilldown", "export_html_drilldown <path> [user...]", "Collapsible HTML report."),
            ("session_times", "session_times <A> <B> [gap]", "Response times per session."),
            ("influence", "influence <seed> [hops] [win_s]", "Trace multi-hop reply chains."),
            ("template_filter", "template_filter <id>", "Filter current view by template ID."),
            ("drift", "drift <user> [wa_days] [wb_days] [gap]", "Detect behavioral drift across windows."),
            ("save_profile", "save_profile <user> <path>", "Compute and save user profile to JSON."),
            ("load_profile", "load_profile <path>", "Load and display a saved profile."),
            ("compare_profiles", "compare_profiles <path1> <path2> ...", "Compare saved profiles."),
            ("auto_tag", "auto_tag [user]", "LLM-based auto-tagging of a user."),
            ("auto_tag_bulk", "auto_tag_bulk [N]", "Auto-tag top N users by activity."),
            ("recurrence_breach", "recurrence_breach <user> [days]", "Check recurrence pattern breach."),
            ("save_config", "save_config", "Persist current shell config to disk."),
            ("load_config", "load_config", "Reload shell config from disk."),
            # Forensic commands
            ("entities", "entities [user]", "Extract forensic entities (IPs, URLs, emails, hashes, file paths)."),
            ("gaps", "gaps [user] [threshold_min]", "Detect gaps in activity timeline."),
            ("reconstruct", "reconstruct [user] [--entities]", "Chronological timeline reconstruction."),
            ("forensic_report", "forensic_report <user>", "LLM-powered comprehensive forensic report."),
            ("timeline_narrative", "timeline_narrative <user>", "LLM-generated narrative from timeline events."),
            ("evidence", "evidence <user>", "LLM-based structured evidence extraction."),
            ("tamper_detect", "tamper_detect [user] [--strict]", "Detect log tampering (timestamps, duplicates, entropy, sequence gaps)."),
            # Advanced LLM commands
            ("llm_search", 'llm_search "<query>"', "Natural language semantic search across all logs."),
            ("llm_threat", "llm_threat [user]", "LLM threat assessment (risk level, TTPs, indicators)."),
            ("llm_bot", "llm_bot [user]", "Bot/automation detection with sophistication analysis."),
            ("llm_profile", "llm_profile [user]", "Deep psychological/behavioral profile (Big Five, roles, motivations)."),
            ("llm_insider", "llm_insider [user]", "Insider threat analysis (exfiltration, policy violations)."),
            ("llm_social", "llm_social [N]", "Social dynamics: power structure, clusters, influence patterns."),
            ("llm_incident", "llm_incident [query]", "Incident timeline reconstruction with LLM narrative."),
            ("llm_topics", "llm_topics [N]", "Topic map: discussion topics and cross-user connections."),
            ("llm_sessions", "llm_sessions [user]", "Compare user behavior across different sessions."),
            ("llm_baseline", "llm_baseline [user]", "Establish behavioral baseline and flag deviations."),
            ("llm_summary", "llm_summary", "LLM summary of entire log (key events, trends, anomalies)."),
            ("llm_replay", "llm_replay [user]", "LLM narrates user's activity as chronological story."),
            ("llm_predict", "llm_predict [user]", "Predict next likely actions/behavior."),
            ("llm_motive", "llm_motive [user]", "Analyze motivations, intent, psychological drivers."),
            ("llm_relationship", "llm_relationship <A> <B>", "Deep relationship analysis between two users."),
            ("llm_audit", "llm_audit [policy]", "Security compliance audit against best practices."),
            ("llm_risk", "llm_risk [user]", "Quantified 0-100 risk score with factor breakdown."),
            ("stats", "stats [user]", "Full statistical summary (mean/median/stdev/percentiles)."),
            ("frequency", "frequency [N]", "Word/token frequency analysis across all logs."),
            ("cooccurrence", "cooccurrence [window_min]", "User co-occurrence in time windows."),
            ("heatmap_user", "heatmap_user [N]", "2D heatmap: users (rows) × hours (columns)."),
            ("coverage", "coverage", "Log coverage analysis — density, gaps, completeness."),
            ("export_graphml", "export_graphml <path>", "Export interaction graph as GraphML for Gephi."),
            ("merge", "merge <f1> <f2> ... <out>", "Merge multiple log files chronologically."),
            ("sample", "sample <N>", "Random sample of N entries."),
            ("last_seen", "last_seen [user]", "When was each user (or specific user) last active."),
            ("whois", "whois <user>", "One-command dump: profile+sentiment+anomalies+edges."),
            ("diff_time", "diff_time <since> <until>", "Compare activity in two equal time periods."),
            ("top_words", "top_words [N]", "Top N words/tokens across all log text."),
            ("commands", "commands  (or ??)", "Print this reference."),
            ("help", "help [name]  (or ?<name>)", "Built-in help."),
            ("quit", "quit  (exit, Ctrl-D)", "Exit the shell."),
            # Case management
            ("case", "case {create|list|show|add|...}", "Manage investigation cases and findings."),
            # Future diagnostics
            ("future_diag", "future_diag [user] [--lookback N] [--forecast N] [--auto-case] [--json]",
             "Predictive diagnostics: health, warnings, degradation, risk trajectories, scenarios."),
            # Advanced settings & commands
            ("preset", "preset {list|save|load|delete|show|apply} [name]", "Manage analysis presets (saved parameter sets)."),
            ("macro", "macro {record|stop|play|list|delete|show} [name]", "Record and replay command sequences."),
            ("timing", "timing [on|off]", "Toggle command execution timing display."),
            ("debug", "debug [on|off]", "Toggle debug mode (verbose error traces)."),
            ("quiet", "quiet [on|off]", "Toggle quiet mode (suppress non-essential output)."),
            ("env", "env", "Show environment and system information."),
            ("memory", "memory", "Show memory usage breakdown."),
            ("reset", "reset [all|filters|settings|aliases|notes|ignore]", "Reset configuration to defaults."),
            ("export_config", "export_config <path>", "Export all configuration to a portable JSON file."),
            ("import_config", "import_config <path>", "Import configuration from a portable JSON file."),
            ("benchmark", "benchmark [N]", "Run performance benchmarks (default N=1000 entries)."),
            ("set_default", "set_default <key> <value>", "Set advanced default parameters."),
            ("show_defaults", "show_defaults", "Display all advanced default parameters."),
        ]
        usage_w = min(max(len(u) for _, u, _ in ref), 70)
        print(f"\n  {'COMMAND'.ljust(usage_w)}   DESCRIPTION")
        print(f"  {'-' * usage_w}   {'-' * 40}")
        for _name, usage, desc in ref:
            print(f"  {usage[:usage_w].ljust(usage_w)}   {desc}")
        print(
            "\n  Tips:\n"
            "    - Quote args containing spaces.\n"
            "    - Global filters (user/target/since/until) apply to most commands.\n"
            "    - 'view save NAME' captures the current global filters.\n"
            "    - 'set llm_url http://host:port/' switches the LLM endpoint at runtime.\n"
            "    - Launch with --c to print this reference on startup."
        )

    # --- NEW: sessions (#5) -------------------------------------------------
    def do_sessions(self, arg: str) -> None:
        """sessions [user] [gap_minutes]   Detect user sessions."""
        parts = self._split(arg)
        user = parts[0] if parts and not parts[0].replace(".", "").isdigit() else self.state.focused_user
        gap = 30
        for p in parts:
            try:
                gap = int(p)
            except ValueError:
                if user is None:
                    user = p
        user = self._resolve_user(user or "")
        if not user:
            return
        sessions = detect_sessions(self._active_entries(), user, gap)
        if not sessions:
            print(f"No sessions for '{user}'.")
            return
        print(f"\nSessions for '{user}' (gap={gap}min):")
        total_lines = sum(s.line_count for s in sessions)
        for i, s in enumerate(sessions, 1):
            dur = (s.end - s.start).total_seconds()
            dur_s = f"{dur / 60:.0f}min" if dur < 3600 else f"{dur / 3600:.1f}h"
            print(f"  #{i:<3d}  {s.start:%H:%M} - {s.end:%H:%M}  {dur_s:>10}  {s.line_count:>4d} lines")
        print(f"  Total: {len(sessions)} sessions, {total_lines} lines")

    # --- NEW: response_times (#6) -------------------------------------------
    def do_response_times(self, arg: str) -> None:
        """response_times [user] [window_sec]   Response time analysis."""
        parts = self._split(arg)
        user = parts[0] if parts else None
        window = 300
        for p in parts:
            try:
                window = int(p)
            except ValueError:
                user = p
        rts = compute_response_times(self._active_entries(), window)
        if user:
            u = user.lower()
            rts = [r for r in rts if r.responder.lower() == u or r.responded_to.lower() == u]
        if not rts:
            print("(no response time data)")
            return
        delays = [r.delay_seconds for r in rts]
        mean_d = statistics.mean(delays)
        print(f"\nResponse times ({len(rts)} exchanges):")
        print(f"  Mean: {mean_d:.0f}s  Median: {statistics.median(delays):.0f}s")
        by_responder: Counter = Counter()
        for r in rts:
            by_responder[f"{r.responder} -> {r.responded_to}"] += 1
        print("  Top responder pairs:")
        for pair, cnt in by_responder.most_common(10):
            avg = statistics.mean([r.delay_seconds for r in rts if f"{r.responder} -> {r.responded_to}" == pair])
            print(f"    {cnt:>4d}x  {pair:<30s}  avg={avg:.0f}s")

    # --- NEW: sentiment (#4) -------------------------------------------------
    def do_sentiment(self, arg: str) -> None:
        """sentiment [user]   Sentiment analysis for a user (or focused)."""
        user = self._resolve_user(arg)
        if not user:
            return
        s = user_sentiment(self._active_entries(), user)
        if not s:
            print(f"(no data for '{user}')")
            return
        print(f"\nSentiment for '{user}':")
        print(f"  n={s['n']}")
        print(f"  mean compound: {s['mean_compound']:.3f}")
        print(f"  positive rate: {s['pos_rate']:.1%}")
        print(f"  negative rate: {s['neg_rate']:.1%}")
        print(f"  agreement rate: {s['agree_rate']:.1%}")

    # --- NEW: topics (#3) ----------------------------------------------------
    def do_topics(self, arg: str) -> None:
        """topics [user]   Keyword and n-gram extraction for a user (or focused)."""
        user = self._resolve_user(arg)
        if not user:
            return
        t = user_topics(self._active_entries(), user)
        if not t or not t.get("keywords"):
            print(f"(no topic data for '{user}')")
            return
        print(f"\nTopics for '{user}':")
        print("  Top keywords:")
        for kw, n in t["keywords"][:15]:
            print(f"    {n:>5d}  {kw}")
        print("  Top bigrams:")
        for kw, n in t["bigrams"][:10]:
            print(f"    {n:>5d}  {kw}")
        print("  Top trigrams:")
        for kw, n in t["trigrams"][:5]:
            print(f"    {n:>5d}  {kw}")

    # --- NEW: sequences (#14) ------------------------------------------------
    def do_sequences(self, arg: str) -> None:
        """sequences [min_support]   Find common user interaction sequences."""
        min_support = int(arg.strip()) if arg.strip().isdigit() else 3
        seqs = find_common_sequences(self._active_entries(), min_support=min_support)
        if not seqs:
            print("(no sequences found)")
            return
        print(f"\nCommon sequences (min_support={min_support}):")
        for s in seqs:
            pat = " -> ".join(s.pattern)
            print(f"  {s.count:>5d}x  {pat}")

    # --- NEW: anomalies (#8) -------------------------------------------------
    def do_anomalies(self, arg: str) -> None:
        """anomalies [user] [z_threshold]   Detect behavioral anomalies."""
        parts = self._split(arg)
        user = parts[0] if parts else self.state.focused_user
        z = 2.5
        for p in parts:
            try:
                z = float(p)
            except ValueError:
                user = p
        user = self._resolve_user(user or "")
        if not user:
            return
        anoms = detect_anomalies(self._active_entries(), user, z)
        anoms += detect_behavioral_anomalies(self._active_entries(), user, z)
        if not anoms:
            print(f"(no anomalies for '{user}' at z>={z})")
            return
        print(f"\nAnomalies for '{user}' (z>={z}):")
        # Deduplicate and sort by Z-score
        seen = set()
        unique_anoms = []
        for a in anoms:
            key = (a.metric, a.day, a.hour)
            if key not in seen:
                seen.add(key)
                unique_anoms.append(a)
        unique_anoms.sort(key=lambda x: abs(x.zscore), reverse=True)
        for a in unique_anoms:
            dir_ = "HIGH" if a.value > a.expected else "LOW"
            print(f"  {dir_:>4}  {a.metric:<20s} value={a.value:.1f} expected={a.expected:.1f} z={a.zscore:.2f}  {a.day or ''} h{a.hour or ''}")

    # --- NEW: lifecycle (#10) ------------------------------------------------
    def do_lifecycle(self, arg: str) -> None:
        """lifecycle [user]   User lifecycle analysis."""
        user = self._resolve_user(arg)
        if not user:
            return
        lc = analyze_lifecycle(self._active_entries(), user)
        if not lc.first_seen:
            print(f"(no data for '{user}')")
            return
        print(f"\nLifecycle for '{user}':")
        print(f"  First seen: {_fmt_dt(lc.first_seen)}")
        print(f"  Last seen:  {_fmt_dt(lc.last_seen)}")
        print(f"  Active days: {lc.active_days} / {lc.total_days} total ({lc.active_days / max(lc.total_days, 1) * 100:.0f}%)")
        print(f"  Trend: {lc.activity_trend}")
        print(f"  Stages ({len(lc.stages)}):")
        for i, (stage, st, en) in enumerate(lc.stages, 1):
            dur = (en - st).days
            print(f"    #{i} {stage}  {st.date()} - {en.date()}  ({dur}d)")

    # --- NEW: pattern (#11) --------------------------------------------------
    def do_pattern(self, arg: str) -> None:
        """pattern [user]   Pattern-of-life analysis for a user."""
        user = self._resolve_user(arg)
        if not user:
            return
        pol = pattern_of_life(self._active_entries(), user)
        if not pol.hourly_profile:
            print(f"(insufficient data for '{user}')")
            return
        print(f"\nPattern of life for '{user}' (consistency={pol.consistency_score:.2f}):")
        print("  Hourly activity profile (normalized):")
        glyphs = "▁▂▃▄▅▆▇█"
        vals = [pol.hourly_profile.get(h, 0) for h in range(24)]
        peak_v = max(vals) or 1
        bar = "".join(glyphs[min(int(v / peak_v * 7), 7)] for v in vals)
        print(f"    {bar}  (00..23)")
        print(f"  Peak hour: {pol.peak_hour}:00")
        print(f"  Quiet hours: {', '.join(f'{h}:00' for h in pol.quiet_hours) or 'none'}")
        print("  Weekday profile:")
        days = "Mon Tue Wed Thu Fri Sat Sun".split()
        for d in range(7):
            bar_len = int(pol.weekday_profile.get(d, 0) / (max(pol.weekday_profile.values()) or 1) * 20)
            print(f"    {days[d]}: {'█' * bar_len}")

    # --- NEW: rules / alert (#13) --------------------------------------------
    def do_rules(self, arg: str) -> None:
        """rules   List alert rules.
        rules add <name> <field> <op> <value> <message>
        rules remove <name>
        rules toggle <name>"""
        parts = self._split(arg)
        if not parts:
            if not self.state.alert_engine.rules:
                print("(no alert rules)")
                return
            print("Alert rules:")
            for r in self.state.alert_engine.rules:
                status = "ON" if r.enabled else "OFF"
                print(f"  [{status}] {r.name}: if {r.field} {r.op} {r.value!r} -> {r.message}")
            return
        sub = parts[0].lower()
        if sub == "add" and len(parts) >= 6:
            self.state.alert_engine.add(AlertRule(parts[1], parts[2], parts[3], parts[4], " ".join(parts[5:])))
            print(f"Added rule '{parts[1]}'.")
        elif sub == "remove" and len(parts) >= 2:
            if self.state.alert_engine.remove(parts[1]):
                print(f"Removed rule '{parts[1]}'.")
            else:
                print(f"(no rule '{parts[1]}')")
        elif sub == "toggle" and len(parts) >= 2:
            for r in self.state.alert_engine.rules:
                if r.name == parts[1]:
                    r.enabled = not r.enabled
                    print(f"Rule '{parts[1]}' toggled {'ON' if r.enabled else 'OFF'}")
                    return
            print(f"(no rule '{parts[1]}')")
        else:
            print("Usage: rules [add <name> <field> <op> <value> <message> | remove <name> | toggle <name>]")

    # --- NEW: correlate (#12) ------------------------------------------------
    def do_correlate(self, arg: str) -> None:
        """correlate <path> [window_sec]   Cross-log event correlation."""
        parts = self._split(arg)
        if not parts:
            print("Usage: correlate <other_log_path> [window_seconds]")
            return
        path = parts[0]
        window = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 60
        try:
            other = list(iter_entries(path))
        except FileNotFoundError:
            print(f"File not found: {path}")
            return
        corr = correlate_logs(self.state.entries, other, window)
        if not corr:
            print("(no correlations found)")
            return
        print(f"\nCorrelations (window={window}s, {len(corr)} pairs):")
        for c in corr[:20]:
            print(f"  {c.count:>5d}x  {c.event_a:<25s}  ~~  {c.event_b:<25s}  avg_delay={c.avg_delay_seconds:.0f}s")

    # --- NEW: timeline (#1) --------------------------------------------------
    def do_timeline(self, arg: str) -> None:
        """timeline [user] [width]   ASCII timeline visualization."""
        parts = self._split(arg)
        user = parts[0] if parts and not parts[0].isdigit() else self.state.focused_user
        width = 60
        for p in parts:
            if p.isdigit():
                width = min(int(p), 200)
        lines = ascii_timeline(self._active_entries(), user, width=width)
        print(f"\n{lines}")

    # --- NEW: heatmap (#2) ---------------------------------------------------
    def do_heatmap(self, arg: str) -> None:
        """heatmap [user] [months]   Calendar activity heatmap."""
        parts = self._split(arg)
        user = parts[0] if parts and not parts[0].isdigit() else self.state.focused_user
        months = 3
        for p in parts:
            if p.isdigit():
                months = min(int(p), 12)
        print(f"\n{calendar_heatmap(self._active_entries(), user, months)}")

    # --- NEW: net (#7) -------------------------------------------------------
    def do_net(self, arg: str) -> None:
        """net [N]   ASCII network graph of top interaction edges."""
        n = int(arg.strip()) if arg.strip().isdigit() else 15
        edges = build_edge_graph(self._active_entries())
        print(f"\n{ascii_network_graph(edges, top_n=n)}")

    # --- NEW: export_html / export_sql (#15, #18) ----------------------------
    def do_export_html(self, arg: str) -> None:
        """export_html <path> [user...]   Generate HTML report."""
        parts = self._split(arg)
        if not parts:
            print("Usage: export_html <path> [user...]")
            return
        path = parts[0]
        users = parts[1:] if len(parts) > 1 else None
        s = summarize(self._active_entries(), self.state.top_n)
        profiles = None
        if users:
            profiles = [build_profile(self._active_entries(), u) for u in users]
        write_html_report(path, s, profiles)

    def do_export_sql(self, arg: str) -> None:
        """export_sql <path>   Export entries to SQLite database."""
        path = arg.strip()
        if not path:
            print("Usage: export_sql <path>")
            return
        print(export_to_sqlite(self.state.entries, path))

    def do_sql(self, arg: str) -> None:
        """sql <db_path> <query>   Query a previously exported SQLite database."""
        parts = self._split(arg)
        if len(parts) < 2:
            print("Usage: sql <db_path> <query>")
            return
        db_path, query = parts[0], " ".join(parts[1:])
        try:
            rows = query_sqlite(db_path, query)
        except sqlite3.Error as exc:
            print(f"SQL error: {exc}")
            return
        if not rows:
            print("(no results)")
            return
        headers = list(rows[0].keys())
        print("  " + "  ".join(f"{h:<20s}" for h in headers))
        print("  " + "-" * (20 * len(headers)))
        for row in rows[:100]:
            print("  " + "  ".join(f"{str(row.get(h, ''))[:20]:<20s}" for h in headers))
        if len(rows) > 100:
            print(f"  ...({len(rows) - 100} more rows)")

    # --- NEW: prometheus (#17) -----------------------------------------------
    def do_prometheus(self, arg: str) -> None:
        """prometheus   Print Prometheus metrics for the current log."""
        print(prometheus_metrics(self._active_entries()))

    # --- NEW: multi / aggregate (#27) ----------------------------------------
    def do_multi(self, arg: str) -> None:
        """multi {add <label> <path> | list | clear | report}   Multi-log aggregation."""
        parts = self._split(arg)
        if not parts:
            print("Usage: multi add <label> <path>  |  multi list  |  multi clear  |  multi report")
            return
        sub = parts[0].lower()
        if sub == "add" and len(parts) >= 3:
            label, path = parts[1], parts[2]
            try:
                entries = list(iter_entries(path))
            except FileNotFoundError:
                print(f"File not found: {path}")
                return
            self.state.multi_log_sources[label] = entries
            print(f"Added '{label}': {len(entries)} entries from {path}")
        elif sub == "list":
            if not self.state.multi_log_sources:
                print("(no sources)")
                return
            for label, entries in self.state.multi_log_sources.items():
                print(f"  {label}: {len(entries)} entries")
        elif sub == "clear":
            self.state.multi_log_sources.clear()
            print("Cleared all multi-log sources.")
        elif sub == "report":
            if not self.state.multi_log_sources:
                print("(no sources)")
                return
            for label, entries in self.state.multi_log_sources.items():
                s = summarize(entries, self.state.top_n)
                print(f"\n=== {label} ===")
                print_report(s)
        else:
            print(f"Unknown subcommand: {sub}")

    # --- NEW: llm_explain (#19) ----------------------------------------------
    def do_llm_explain(self, arg: str) -> None:
        """llm_explain [user] [z]   Detect anomalies and have LLM explain them."""
        parts = self._split(arg)
        user = parts[0] if parts else self.state.focused_user
        z = 2.5
        for p in parts:
            try:
                z = float(p)
            except ValueError:
                user = p
        user = self._resolve_user(user or "")
        if not user:
            return
        anoms = detect_anomalies(self._active_entries(), user, z)
        if not anoms:
            print(f"(no anomalies for '{user}')")
            return
        context = [e.text or e.raw for e in self._filtered(user)[-100:]]
        llm_explain_anomalies(anoms, context, self.state.llm_url, self.state.llm_model,
                              self.state.max_chunk_chars, cache=self.state.llm_cache)

    # --- NEW: summarize (#20) ------------------------------------------------
    def do_summarize(self, arg: str) -> None:
        """summarize <userA> <userB>   LLM conversation summarization."""
        parts = self._split(arg)
        if len(parts) < 2:
            print("Usage: summarize <userA> <userB>")
            return
        a, b = parts[0], parts[1]
        matched = [e for e in self._active_entries() if line_is_interaction(e, a, b)]
        if not matched:
            print(f"(no interaction data between {a} and {b})")
            return
        llm_summarize_conversation(a, b, [e.text for e in matched],
                                   self.state.llm_url, self.state.llm_model,
                                   self.state.max_chunk_chars, cache=self.state.llm_cache)

    # --- NEW: cluster (#21) --------------------------------------------------
    def do_cluster(self, arg: str) -> None:
        """cluster [min_lines] [N]   LLM clustering of user behavior."""
        parts = self._split(arg)
        min_lines = 5
        max_users = 15
        for p in parts:
            if p.isdigit():
                if min_lines == 5:
                    min_lines = int(p)
                else:
                    max_users = int(p)
        counts: Counter = Counter(e.user for e in self._active_entries() if e.user)
        candidates = sorted((u for u, n in counts.items() if n >= min_lines), key=lambda u: -counts[u])[:max_users]
        if len(candidates) < 3:
            print("Need at least 3 users with sufficient data.")
            return
        profiles = [build_profile(self._active_entries(), u) for u in candidates]
        llm_cluster_users(profiles, self.state.llm_url, self.state.llm_model,
                          self.state.max_chunk_chars, cache=self.state.llm_cache)

    # --- NEW: auto_report (#22) ----------------------------------------------
    def do_auto_report(self, arg: str) -> None:
        """auto_report   LLM-generated narrative report of the log."""
        s = summarize(self._active_entries(), self.state.top_n)
        counts: Counter = Counter(e.user for e in self._active_entries() if e.user)
        top_users = [u for u, _ in counts.most_common(10)]
        profiles = [build_profile(self._active_entries(), u) for u in top_users]
        llm_auto_report(s, profiles, self.state.llm_url, self.state.llm_model,
                        self.state.max_chunk_chars, cache=self.state.llm_cache)

    # --- tag (#31) ------------------------------------------------------------
    def do_tag(self, arg: str) -> None:
        """tag <user>   LLM auto-tag a user with behavioral labels."""
        user = self._resolve_user(arg)
        if not user:
            return
        matched = self._filtered(user)
        if not matched:
            print(f"No lines match '{user}'.")
            return
        result = auto_tag_user(matched, user, self.state.llm_url,
                                self.state.llm_model, self.state.max_chunk_chars,
                                cache=self.state.llm_cache)
        print(f"\nTags for {user}: {result}")

    def do_tagall(self, arg: str) -> None:
        """tagall [N]   LLM auto-tag top N users."""
        parts = self._split(arg)
        n = 10
        if parts and parts[0].isdigit():
            n = int(parts[0])
        results = auto_tag_bulk(self._active_entries(), self.state.llm_url,
                                self.state.llm_model, self.state.max_chunk_chars,
                                cache=self.state.llm_cache, top_n=n)
        if not results:
            print("(no users to tag)")
            return
        print(f"\nAuto-tags for top {len(results)} users:")
        for user, tags in results.items():
            print(f"  {user:<20s}  {tags}")

    def do_explain(self, arg: str) -> None:
        """explain <user>   LLM explains anomalies for a user."""
        user = self._resolve_user(arg)
        if not user:
            return
        matched = self._filtered(user)
        if len(matched) < 7:
            print(f"Not enough data for '{user}' (need >=7 lines).")
            return
        anomalies = detect_anomalies(matched, user)
        if not anomalies:
            print(f"(no anomalies detected for {user})")
            return
        context = [e.text for e in matched[-30:]]
        llm_explain_anomalies(anomalies, context, self.state.llm_url,
                              self.state.llm_model, self.state.max_chunk_chars,
                              cache=self.state.llm_cache)

    def do_askall(self, arg: str) -> None:
        """askall "<question>"   Ask LLM a free-form question about the entire log."""
        if not arg.strip():
            print('Usage: askall "<question>"')
            return
        question = arg.strip()
        lines = [e.text for e in self._active_entries() if e.text]
        if not lines:
            print("(no text entries to analyze)")
            return
        chunks = chunk_lines(lines, self.state.max_chunk_chars)
        print(f"\nAsking LLM about entire log ({len(chunks)} chunk(s)) at {self.state.llm_url} (model={self.state.llm_model}).")
        system = (
            "You are a log-analysis assistant. Given the complete set of log lines, "
            "answer the operator's question concretely, citing evidence from the data. "
            "If the data does not contain enough information to answer, say so."
        )
        partials = []
        for i, chunk in enumerate(chunks, 1):
            prompt = (
                f"Chunk {i}/{len(chunks)} of the full log:\n\n{chunk}\n\n"
                f"Question: {question}\n\n"
                f"Answer for this chunk, citing specific lines when useful."
            )
            try:
                out = call_llm_cached(self.state.llm_url, self.state.llm_model, system, prompt,
                                      cache=self.state.llm_cache, spinner_msg=f"LLM chunk {i}/{len(chunks)}")
            except Exception as exc:
                print(f"  [chunk {i}] error: {exc}", file=sys.stderr)
                return
            partials.append(out)
            print(f"\n--- Chunk {i}/{len(chunks)} answer ---\n{out}")
        if len(partials) > 1:
            merge = (
                f"Question: {question}\n\n"
                f"Combine the per-chunk answers below into one coherent response. "
                f"Resolve contradictions and cite the strongest evidence.\n\n"
                + "\n\n---\n\n".join(f"Chunk {i+1}:\n{p}" for i, p in enumerate(partials))
            )
            try:
                final = call_llm_cached(self.state.llm_url, self.state.llm_model, system, merge,
                                        cache=self.state.llm_cache, spinner_msg="LLM merging answers")
                print(f"\n=== Final answer ===\n{final}")
            except Exception as exc:
                print(f"Merge failed: {exc}")

    def do_compare_auto(self, arg: str) -> None:
        """compare-auto <A> <B>   Compare two users then auto-explain differences with LLM."""
        parts = self._split(arg)
        if len(parts) < 2:
            print("Usage: compare-auto <userA> <userB>")
            return
        a, b = parts[0], parts[1]
        pa = build_profile(self._time_filtered(), a)
        pb = build_profile(self._time_filtered(), b)
        if not pa["authored"] and not pb["authored"]:
            print(f"Neither '{a}' nor '{b}' authored lines in this log.")
            return
        # Print the comparison table then feed to LLM
        print_compare_table(pa, pb)
        print()
        compare_n_users_with_llm([pa, pb], self.state.llm_url, self.state.llm_model,
                                 self.state.max_chunk_chars, cache=self.state.llm_cache)

    def do_drift_explain(self, arg: str) -> None:
        """drift-explain <user>   Drift detection with LLM explanation."""
        user = self._resolve_user(arg)
        if not user:
            return
        result = drift_detection(self._active_entries(), user)
        if result.get("drift_detected"):
            print(f"\nDrift detected for '{user}':")
            print(f"  drift_score: {result.get('drift_score', '?')}")
            print(f"  avg_hourly_delta: {result.get('avg_hourly_delta', '?')}")
            print(f"  max_hourly_delta: {result.get('max_hourly_delta', '?')}")
            lines = [e.text for e in self._filtered(user)[-50:] if e.text]
            if lines and self.state.llm_url:
                system = "You are a behavioral drift analyst. Explain the detected behavioral drift concisely."
                prompt = (
                    f"User '{user}' shows behavioral drift. drift_score={result.get('drift_score')}, "
                    f"avg_hourly_delta={result.get('avg_hourly_delta')}, "
                    f"max_hourly_delta={result.get('max_hourly_delta')}.\n\n"
                    f"Recent lines from this user:\n" + "\n".join(lines) + "\n\n"
                    f"Explain what might be causing this drift and whether it's concerning."
                )
                try:
                    explanation = call_llm_cached(self.state.llm_url, self.state.llm_model, system, prompt,
                                                  cache=self.state.llm_cache, spinner_msg="LLM explaining drift")
                    print(f"\n=== LLM drift explanation ===\n{explanation}")
                except Exception as exc:
                    print(f"LLM drift explanation failed: {exc}")
        else:
            print(f"(no drift detected for '{user}' — {result.get('note', '')})")

    # --- NEW: plugin (#23) ---------------------------------------------------
    def do_plugin(self, arg: str) -> None:
        """plugin {load <dir> | list | reload}   Manage analysis plugins."""
        parts = self._split(arg)
        if not parts:
            if not _plugins:
                print("(no plugins loaded)")
                return
            print("Loaded plugins:")
            for p in _plugins:
                print(f"  {p.name}")
            return
        sub = parts[0].lower()
        if sub == "load" and len(parts) >= 2:
            path = parts[1]
            if not os.path.isdir(path):
                print(f"Not a directory: {path}")
                return
            load_plugins_from(path)
            print(f"Loaded {len(_plugins)} plugins from {path}")
        elif sub == "list":
            print(f"Plugins: {len(_plugins)} loaded")
        elif sub == "reload":
            _plugins.clear()
            if self.state.plugin_dir:
                load_plugins_from(self.state.plugin_dir)
            print(f"Reloaded: {len(_plugins)} plugins")
        else:
            print(f"Unknown: {sub}")

    # --- NEW: web (#24) ------------------------------------------------------
    def do_web(self, arg: str) -> None:
        """web {start [port] | stop | status}   Start/stop the web API server."""
        parts = self._split(arg)
        if not parts or parts[0].lower() == "status":
            if self.state.web_server:
                print(f"Web server running on port {self.state.web_server.server_port}")
            else:
                print("(web server not running)")
            return
        sub = parts[0].lower()
        if sub == "start":
            if self.state.web_server:
                print("(web server already running)")
                return
            port = int(parts[1]) if len(parts) > 1 else 8088
            global _web_entries  # noqa: PLW0603
            _web_entries = self.state.entries
            self.state.web_server = start_web_server(port)
            print(f"Web server started at http://127.0.0.1:{port}")
        elif sub == "stop":
            if self.state.web_server:
                self.state.web_server.shutdown()
                self.state.web_server = None
                print("Web server stopped.")
            else:
                print("(not running)")

    def do_webportal(self, arg: str) -> None:
        """webportal {start | stop | status}   Start/stop the web portal (black+green chat UI on :80)."""
        parts = self._split(arg)
        sub = parts[0].lower() if parts else "status"
        if sub == "status":
            if self.state.portal_server:
                print(f"Web portal running at http://127.0.0.1:{self.state.portal_server.server_port}")
            else:
                print("(web portal not running)")
        elif sub == "start":
            if self.state.portal_server:
                print("(web portal already running)")
                return
            port = int(parts[1]) if len(parts) > 1 else 80
            try:
                self.state.portal_server = start_portal_server(self.state.entries, port)
                print(f"Web portal started at http://127.0.0.1:{port}  (black background, green text)")
            except OSError as exc:
                print(f"Could not start portal on port {port}: {exc}")
                self.state.portal_server = None
        elif sub == "stop":
            if self.state.portal_server:
                self.state.portal_server.shutdown()
                self.state.portal_server = None
                print("Web portal stopped.")
            else:
                print("(not running)")
        else:
            print("Usage: webportal {start [port] | stop | status}")

    # --- NEW: webhook (#25) --------------------------------------------------
    def do_webhook(self, arg: str) -> None:
        """webhook {set <url> [slack|discord] | test <message> | clear}   Configure webhook."""
        parts = self._split(arg)
        if not parts:
            if self.state.webhook_url:
                print(f"Webhook: {self.state.webhook_url} ({self.state.webhook_type})")
            else:
                print("(no webhook configured)")
            return
        sub = parts[0].lower()
        if sub == "set" and len(parts) >= 2:
            self.state.webhook_url = parts[1]
            self.state.webhook_type = parts[2] if len(parts) > 2 else "slack"
            print(f"Webhook set to {self.state.webhook_url} ({self.state.webhook_type})")
        elif sub == "test" and len(parts) >= 2:
            if not self.state.webhook_url:
                print("(no webhook configured)")
                return
            ok = send_webhook(self.state.webhook_url, " ".join(parts[1:]), self.state.webhook_type)
            print(f"Webhook test: {'OK' if ok else 'FAILED'}")
        elif sub == "clear":
            self.state.webhook_url = ""
            print("Webhook cleared.")

    # --- NEW: cron (#26) -----------------------------------------------------
    def do_cron(self, arg: str) -> None:
        """cron [--output <path>] [--webhook-url <url>]   Run analysis in cron mode."""
        parts = self._split(arg)
        output_path = None
        wh_url = self.state.webhook_url
        i = 0
        while i < len(parts):
            if parts[i] == "--output" and i + 1 < len(parts):
                output_path = parts[i + 1]; i += 2
            elif parts[i] == "--webhook-url" and i + 1 < len(parts):
                wh_url = parts[i + 1]; i += 2
            else:
                i += 1
        cron_mode(self._active_entries(), self.state.alert_engine, wh_url, output_path)

    # --- NEW: multi-file analysis clustering / aggregate command alias --------
    def do_aggregate(self, arg: str) -> None:
        """aggregate   Alias for 'multi report'."""
        self.do_multi("report")

    # --- NEW 10 features: templates / changepoints / rootcause / forecast / multifactor / chart / dataframe / recurrence / churn / pareto ---

    def do_templates(self, arg: str) -> None:
        """templates [N]   Extract common log line templates."""
        n = int(arg.strip()) if arg.strip().isdigit() else 20
        templates = extract_log_templates(self._active_entries(), n)
        if not templates:
            print("(no templates)")
            return
        print(f"\nLog templates ({len(templates)}):")
        for template, count, sample in templates:
            print(f"  {count:>5d}x  {template[:160]}")

    def do_changepoints(self, arg: str) -> None:
        """changepoints [user] [window_days]   Detect behavioral change points."""
        parts = self._split(arg)
        user = parts[0] if parts else self.state.focused_user
        window = 3
        for p in parts:
            try:
                window = int(p)
            except ValueError:
                user = p
        user = self._resolve_user(user or "")
        if not user:
            return
        cps = detect_change_points(self._active_entries(), user, window)
        if not cps:
            print(f"(no change points for '{user}')")
            return
        print(f"\nChange points for '{user}':")
        for cp in cps:
            dir_ = "UP" if cp.after_val > cp.before_val else "DOWN"
            print(f"  {dir_:>4}  {cp.metric:<15s}  at {cp.at.date()}  {cp.before_val:.1f} -> {cp.after_val:.1f}  (effect={cp.effect_size:.2f})")

    def do_rootcause(self, arg: str) -> None:
        """rootcause <user> [lookback_sec]   Find root causes preceding a user's activity."""
        parts = self._split(arg)
        if not parts:
            print("Usage: rootcause <user> [lookback_seconds]")
            return
        user = parts[0]
        lookback = int(parts[1]) if len(parts) > 1 else 120
        causes = trace_root_causes(self._active_entries(), user, lookback)
        if not causes:
            print(f"(no root causes found for '{user}')")
            return
        print(f"\nRoot causes for '{user}' (lookback={lookback}s):")
        for rc in causes[:15]:
            print(f"  {rc.occurrences:>4d}x  corr={rc.correlation:.2f}  lag={rc.avg_lag_seconds:.0f}s  {rc.preceding_user:<20s} {rc.preceding_event}")

    def do_forecast(self, arg: str) -> None:
        """forecast [user] [days]   Forecast future activity."""
        parts = self._split(arg)
        user = parts[0] if parts else self.state.focused_user
        days = 7
        for p in parts:
            try:
                days = int(p)
            except ValueError:
                user = p
        fc = forecast_activity(self._active_entries(), user, days)
        if not fc.predictions:
            print("(insufficient data for forecast)")
            return
        label = f" for '{user}'" if user else ""
        print(f"\nForecast{label}: trend={fc.trend}")
        dates = sorted(fc.daily_counts.keys())
        counts = [fc.daily_counts[d] for d in dates]
        if len(counts) > 1:
            glyphs = "▁▂▃▄▅▆▇█"
            peak = max(counts) or 1
            bar = "".join(glyphs[min(int(c / peak * 7), 7)] for c in counts[-min(len(counts), 30):])
            print(f"  Recent activity: {bar}")
        print(f"  Predictions ({days}d ahead):")
        for d, v in fc.predictions:
            print(f"    {d}:  {v:.0f}")

    def do_multifactor(self, arg: str) -> None:
        """multifactor [user]   Multi-factor anomaly score."""
        user = self._resolve_user(arg)
        if not user:
            return
        mf = multi_factor_anomaly(self._active_entries(), user)
        if not mf:
            print(f"(insufficient data for '{user}')")
            return
        print(f"\nMulti-factor anomaly for '{user}':")
        print(f"  Composite score: {mf.composite_score:+.3f}  ({'ANOMALOUS' if abs(mf.composite_score) > 1.5 else 'normal'})")
        print(f"  Daily volume z:  {mf.daily_z:+.2f}" if mf.daily_z is not None else "  Daily volume z:  N/A")
        print(f"  Hourly z:        {mf.hourly_z:+.2f}" if mf.hourly_z is not None else "  Hourly z:        N/A")
        print(f"  Sentiment z:     {mf.sentiment_z:+.2f}" if mf.sentiment_z is not None else "  Sentiment z:     N/A")

    def do_chart(self, arg: str) -> None:
        """chart {timeline <path> [user] | histogram <path> [key] [user] | network <path> [N]}
        Generate matplotlib charts."""
        parts = self._split(arg)
        if not parts:
            print("Usage: chart timeline <path> [user]  |  chart histogram <path> [key] [user]  |  chart network <path> [N]")
            return
        sub = parts[0].lower()
        if sub == "timeline" and len(parts) >= 2:
            path = parts[1]
            user = parts[2] if len(parts) > 2 else None
            chart_timeline(self._active_entries(), path, user)
        elif sub == "histogram" and len(parts) >= 2:
            path = parts[1]
            user = parts[3] if len(parts) > 3 else None
            if user:
                scores = collect_scores(self._active_entries(), user)
                for key in SCORE_KEYS:
                    if scores.get(key):
                        chart_histogram(scores[key], path.replace(".png", f"_{key}.png"), label=f"{key} ({user})")
                        print(f"  Chart saved: {path.replace('.png', f'_{key}.png')}")
            else:
                scores = collect_scores(self._active_entries())
                for key in SCORE_KEYS:
                    if scores.get(key):
                        chart_histogram(scores[key], path.replace(".png", f"_{key}.png"), label=f"{key} (population)")
        elif sub == "network" and len(parts) >= 2:
            path = parts[1]
            n = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 15
            edges = build_edge_graph(self._active_entries())
            chart_network(edges, path, n)
        else:
            print("Usage: chart timeline <path> [user]  |  chart histogram <path> [key] [user]  |  chart network <path> [N]")

    def do_dataframe(self, arg: str) -> None:
        """dataframe [expression]   View entries as pandas DataFrame with optional eval expression."""
        print(dataframe_view(self._active_entries(), arg.strip()))

    def do_recurrence(self, arg: str) -> None:
        """recurrence [user]   Detect periodic patterns in a user's activity."""
        user = self._resolve_user(arg)
        if not user:
            return
        recs = detect_recurrence(self._active_entries(), user)
        if not recs:
            print(f"(no recurrence patterns for '{user}')")
            return
        print(f"\nRecurrence patterns for '{user}':")
        for r in recs:
            print(f"  [{r.pattern_type:>7}]  confidence={r.confidence:.0%}  {r.description}")

    def do_churn(self, arg: str) -> None:
        """churn [user]   Predict churn risk for a user."""
        user = self._resolve_user(arg)
        if not user:
            return
        pred = predict_churn(self._active_entries(), user)
        level = "HIGH" if pred.risk_score > 0.6 else "MEDIUM" if pred.risk_score > 0.3 else "LOW"
        print(f"\nChurn prediction for '{user}': risk={level} ({pred.risk_score:.2f})")
        if pred.factors:
            print("  Factors:")
            for f in pred.factors:
                print(f"    - {f}")

    def do_pareto(self, arg: str) -> None:
        """pareto [users|events|targets|levels]   Pareto analysis (80/20 rule)."""
        cat = arg.strip() or "users"
        p = pareto_analysis(self._active_entries(), cat)
        if not p.items:
            print(f"(no data for {cat})")
            return
        print(f"\nPareto analysis ({cat}): top {p.top_80_pct_count} account for ~80% of activity")
        for name, count, cum in p.items[:25]:
            bar = "█" * int(cum / 5)
            print(f"  {cum:>5.0f}%  {bar:<20s}  {count:>7d}  {name}")
        if len(p.items) > 25:
            print(f"  ...({len(p.items) - 25} more)")

    # --- Dashboard mode (#16) -------------------------------------------------
    def do_dashboard(self, arg: str) -> None:
        """dashboard   Launch curses real-time dashboard."""
        run_dashboard(self.state.entries, self.state.alert_engine, self.state.log_path)

    # --- Watch-mode alerting (feature a) --------------------------------------
    def do_watch_alert(self, arg: str) -> None:
        """watch_alert [poll_sec]   Tail log with alert-engine evaluation + webhook."""
        poll = float(arg.strip()) if arg.strip() else 2.0
        print(f"Watching {self.state.log_path} with alerts. Ctrl-C to stop.")
        watch_with_alerts(self.state.log_path, self.state.alert_engine,
                          self.state.webhook_url, self.state.webhook_type, poll)

    # --- Forecast-aware anomaly (feature b) -----------------------------------
    def do_forecast_anomaly(self, arg: str) -> None:
        """forecast_anomaly <user> [z] [forecast_days]   Anomaly detection using forecast baseline."""
        parts = arg.strip().split()
        if not parts:
            print("Usage: forecast_anomaly <user> [z] [forecast_days]")
            return
        user = parts[0]
        z = float(parts[1]) if len(parts) > 1 else 2.5
        fdays = int(parts[2]) if len(parts) > 2 else 7
        result = forecast_aware_anomaly(self.state.entries, user, z, fdays)
        if result.get("anomalies"):
            print(f"\nForecast-based anomalies for {user}:")
            for a in result["anomalies"]:
                print(f"  {a['date']}: actual={a['actual']} expected={a['expected']:.1f}")
        else:
            print(f"No forecast-based anomalies for {user}")

    # --- Alert fatigue scoring (feature c) ------------------------------------
    def do_alert_fatigue(self, arg: str) -> None:
        """alert_fatigue [window_hours]   Compute alert fatigue scores for each rule."""
        window = int(arg.strip()) if arg.strip() else 1
        scores = alert_fatigue_scores(self.state.alert_engine, self.state.entries, window)
        if not scores:
            print("(no alert rules defined)")
            return
        print(f"\nAlert fatigue scores (last {window}h window):")
        for s in scores:
            bar = "█" * int(s.signal_rate * 20)
            print(f"  {s.rule_name:<20s}  fires={s.fires_total:<5d}  rate={s.signal_rate:.0%}  {bar:<20s}  {s.suggestion}")

    # --- Drill-down HTML report (feature d) -----------------------------------
    def do_export_html_drilldown(self, arg: str) -> None:
        """export_html_drilldown <path> [user...]   Collapsible HTML report."""
        parts = arg.strip().split()
        if not parts:
            print("Usage: export_html_drilldown <path> [user...]")
            return
        path = parts[0]
        users = parts[1:] or [self.state.focused_user] if self.state.focused_user else []
        s = summarize(self._active_entries(), self.state.top_n)
        profiles = [build_profile(self._active_entries(), u) for u in users if u] if users else None
        write_html_report_drilldown(path, s, profiles)
        print(f"Drill-down HTML report written to {path}")

    # --- Session-aware metrics (feature e) ------------------------------------
    def do_session_times(self, arg: str) -> None:
        """session_times <user_a> <user_b> [gap_min]   Response times per session."""
        parts = arg.strip().split()
        if len(parts) < 2:
            print("Usage: session_times <user_a> <user_b> [gap_min]")
            return
        ua, ub = parts[0], parts[1]
        gap = int(parts[2]) if len(parts) > 2 else 30
        results = session_response_times(self.state.entries, ua, ub, gap)
        if not results:
            print("(no session data)")
            return
        print(f"\nSession-aware response times ({ua} <-> {ub}):")
        for r in results[:20]:
            print(f"  [{r['session_start']}] {r['responder']} responded in {r['delay_seconds']:.0f}s")
        if len(results) > 20:
            print(f"  ...({len(results) - 20} more)")

    # --- Influence chain tracking (feature f) ----------------------------------
    def do_influence(self, arg: str) -> None:
        """influence <seed_user> [max_hops] [window_s]   Trace multi-hop reply chains."""
        parts = arg.strip().split()
        if not parts:
            print("Usage: influence <seed_user> [max_hops] [window_s]")
            return
        user = parts[0]
        hops = int(parts[1]) if len(parts) > 1 else 3
        win = int(parts[2]) if len(parts) > 2 else 300
        chains = influence_chains(self.state.entries, user, hops, win)
        if not chains:
            print(f"(no chains found for {user})")
            return
        print(f"\nInfluence chains from {user} ({len(chains)} chains):")
        for i, ch in enumerate(chains[:20], 1):
            labels = [c["user"] for c in ch]
            print(f"  #{i:3d}  {' -> '.join(labels)}")
        if len(chains) > 20:
            print(f"  ...({len(chains) - 20} more)")

    # --- Template-based filtering (feature g) ---------------------------------
    def do_template_filter(self, arg: str) -> None:
        """template_filter <template_id>   Filter current view by template ID."""
        tid = arg.strip()
        if not tid:
            print("Usage: template_filter <template_id>")
            return
        self.state.template_filter = tid
        filtered = filter_by_template(self._active_entries(), tid)
        if not filtered:
            print(f"(no entries match template {tid})")
            return
        print(f"\nEntries matching template '{tid}' ({len(filtered)}):")
        for e in filtered[:30]:
            print(f"  {e.raw[:200]}")
        if len(filtered) > 30:
            print(f"  ...({len(filtered) - 30} more)")

    # --- Drift monitoring (feature h) -----------------------------------------
    def do_drift(self, arg: str) -> None:
        """drift <user> [window_a_days] [window_b_days] [gap_days]   Detect behavioral drift."""
        parts = arg.strip().split()
        if not parts:
            print("Usage: drift <user> [window_a_days] [window_b_days] [gap_days]")
            return
        user = parts[0]
        wa = int(parts[1]) if len(parts) > 1 else 7
        wb = int(parts[2]) if len(parts) > 2 else 7
        gap = int(parts[3]) if len(parts) > 3 else 0
        result = drift_detection(self.state.entries, user, wa, wb, gap)
        print(f"\nDrift analysis for {user}:")
        if result.get("drift_detected"):
            print(f"  DRIFT DETECTED: score={result['drift_score']}")
            print(f"  avg hourly delta={result['avg_hourly_delta']}  max={result['max_hourly_delta']}")
        elif result.get("note"):
            print(f"  {result['note']}")
        else:
            print(f"  No significant drift (score={result.get('drift_score', '?')})")

    # --- Behavioral profile persistence (feature i) ---------------------------
    def do_save_profile(self, arg: str) -> None:
        """save_profile <user> <path>   Compute and save a user profile to JSON."""
        parts = arg.strip().split()
        if len(parts) < 2:
            print("Usage: save_profile <user> <path>")
            return
        user, path = parts[0], parts[1]
        msg = save_profile(user, self._active_entries(), path)
        print(msg)

    def do_load_profile(self, arg: str) -> None:
        """load_profile <path>   Load and display a saved profile."""
        path = arg.strip()
        if not path:
            print("Usage: load_profile <path>")
            return
        prof = load_profile(path)
        if prof:
            print(f"\nLoaded profile from {path}:")
            print(json.dumps(prof, indent=2, default=str)[:2000])

    def do_compare_profiles(self, arg: str) -> None:
        """compare_profiles <path1> <path2> [...]   Compare saved profiles."""
        paths = arg.strip().split()
        if len(paths) < 2:
            print("Usage: compare_profiles <path1> <path2> [...]")
            return
        profiles = compare_saved_profiles(paths)
        if len(profiles) < 2:
            print("(could not load enough profiles)")
            return
        print(f"\nComparing {len(profiles)} saved profiles:")
        for p in profiles:
            user = p.get("user") or p.get("nick") or "?"
            sm = p.get("score_means", {})
            scores = " ".join(f"{k}={v:.3f}" for k, v in sm.items() if isinstance(v, float))
            print(f"  {user:<20s}  lines={p.get('authored', '?'):>6s}  {scores}")

    # --- Auto-tagging (feature j) ---------------------------------------------
    def do_auto_tag(self, arg: str) -> None:
        """auto_tag [user]   LLM-based auto-tagging of a user (uses focused_user if no arg)."""
        user = self._resolve_user(arg)
        if not user:
            return
        tag = auto_tag_user(self._active_entries(), user,
                            self.state.llm_url, self.state.llm_model,
                            self.state.max_chunk_chars, self.state.llm_cache)
        self.state.auto_tag_cache[user] = tag
        print(f"\nTags for {user}: {tag}")

    def do_auto_tag_bulk(self, arg: str) -> None:
        """auto_tag_bulk [N]   Auto-tag top N users by activity."""
        n = int(arg.strip()) if arg.strip() else 10
        tags = auto_tag_bulk(self._active_entries(), self.state.llm_url, self.state.llm_model,
                             self.state.max_chunk_chars, self.state.llm_cache, n)
        if not tags:
            print("(no data)")
            return
        print(f"\nAuto-tags for top {n} users:")
        for user, tag in tags.items():
            print(f"  {user:<20s}  {tag}")

    # --- Recurrence breach alert (feature k) ----------------------------------
    def do_recurrence_breach(self, arg: str) -> None:
        """recurrence_breach <user> [recent_days]   Check if user breaks their recurrence pattern."""
        parts = arg.strip().split()
        if not parts:
            print("Usage: recurrence_breach <user> [recent_days]")
            return
        user = parts[0]
        days = int(parts[1]) if len(parts) > 1 else 3
        result = check_recurrence_breach(self.state.entries, user, days)
        if result.get("breach"):
            print(f"\nRECURRENCE BREACH for {user}:")
            for b in result.get("breaches", []):
                print(f"  {json.dumps(b)}")
        else:
            print(f"No recurrence breach for {user}: {result.get('note', 'pattern intact')}")

    # --- Config persistence (feature l) --------------------------------------
    def do_save_config(self, arg: str) -> None:
        """save_config   Persist current shell config (rules, webhook, etc.)."""
        save_shell_config(self.state)
        print(f"Config saved to {_SHELL_CONFIG_PATH}")

    def do_load_config(self, arg: str) -> None:
        """load_config   Reload shell config from disk."""
        load_shell_config(self.state)
        print(f"Config loaded from {_SHELL_CONFIG_PATH}")

    # --- advanced settings & commands ----------------------------------------

    def do_preset(self, arg: str) -> None:
        """preset   Manage analysis presets (saved parameter sets).

        preset list
        preset save <name> [--desc "..."]
        preset load <name>
        preset delete <name>
        preset show <name>
        preset apply <name>   Apply preset and run current command context
        """
        parts = self._split(arg)
        if not parts:
            self.do_preset("list")
            return
        sub = parts[0].lower()
        if sub == "list":
            if not self.state.presets:
                print("(no presets)")
                return
            print("  Presets:")
            for name, p in sorted(self.state.presets.items()):
                desc = p.get("desc", "")
                keys = ", ".join(k for k in p if k != "desc")
                print(f"    {name:<20s}  {desc or keys}")
        elif sub == "save":
            if len(parts) < 2:
                print("Usage: preset save <name> [--desc ...]")
                return
            name = parts[1]
            desc = ""
            i = 2
            while i < len(parts):
                if parts[i] == "--desc" and i + 1 < len(parts):
                    desc = parts[i + 1]; i += 2
                else:
                    i += 1
            self.state.presets[name] = {
                "desc": desc,
                "z_threshold": self.state.default_z_threshold,
                "anomaly_window": self.state.default_anomaly_window,
                "forecast_days": self.state.default_forecast_days,
                "burst_window": self.state.default_burst_window,
                "burst_z": self.state.default_burst_z,
                "session_gap": self.state.default_session_gap,
                "response_window": self.state.default_response_window,
                "output_format": self.state.output_format,
                "score_flag_threshold": self.state.score_flag_threshold,
                "max_output_lines": self.state.max_output_lines,
            }
            _save_json(os.path.join(_config_dir(), "presets.json"), self.state.presets)
            print(f"Saved preset '{name}'")
        elif sub == "load":
            if len(parts) < 2:
                print("Usage: preset load <name>"); return
            p = self.state.presets.get(parts[1])
            if not p:
                print(f"Preset '{parts[1]}' not found"); return
            for key in ("z_threshold", "anomaly_window", "forecast_days", "burst_window",
                        "burst_z", "session_gap", "response_window", "output_format",
                        "score_flag_threshold", "max_output_lines"):
                if key in p:
                    setattr(self.state, key, p[key])
            print(f"Loaded preset '{parts[1]}'")
        elif sub == "delete":
            if len(parts) < 2:
                print("Usage: preset delete <name>"); return
            self.state.presets.pop(parts[1], None)
            _save_json(os.path.join(_config_dir(), "presets.json"), self.state.presets)
            print(f"Deleted preset '{parts[1]}'")
        elif sub == "show":
            if len(parts) < 2:
                print("Usage: preset show <name>"); return
            p = self.state.presets.get(parts[1])
            if not p:
                print(f"Preset '{parts[1]}' not found"); return
            print(f"  Preset: {parts[1]}")
            for k, v in sorted(p.items()):
                if k != "desc":
                    print(f"    {k}: {v}")
        else:
            print(f"Unknown preset subcommand: {sub}")

    def do_macro(self, arg: str) -> None:
        """macro   Record and replay command sequences.

        macro record <name>    Start recording commands
        macro stop             Stop recording
        macro play <name>      Replay recorded sequence
        macro list             List saved macros
        macro delete <name>    Delete a macro
        macro show <name>      Show macro commands
        """
        parts = self._split(arg)
        if not parts:
            self.do_macro("list")
            return
        sub = parts[0].lower()
        macro_path = os.path.join(_config_dir(), "macros.json")
        macros = _load_json(macro_path, {})
        if sub == "record":
            if len(parts) < 2:
                print("Usage: macro record <name>"); return
            self.state.macro_recording = True
            self.state.macro_buffer = []
            print(f"Recording macro '{parts[1]}'... (macro stop to finish)")
        elif sub == "stop":
            if not self.state.macro_recording:
                print("(not recording)"); return
            self.state.macro_recording = False
            name = parts[1] if len(parts) > 1 else "unnamed"
            macros[name] = list(self.state.macro_buffer)
            _save_json(macro_path, macros)
            print(f"Saved macro '{name}' ({len(self.state.macro_buffer)} commands)")
            self.state.macro_buffer = []
        elif sub == "play":
            if len(parts) < 2:
                print("Usage: macro play <name>"); return
            cmds = macros.get(parts[1])
            if not cmds:
                print(f"Macro '{parts[1]}' not found"); return
            print(f"Playing macro '{parts[1]}' ({len(cmds)} commands):")
            for cmd in cmds:
                print(f"  {self.prompt}{cmd}")
                if self.onecmd(cmd):
                    break
        elif sub == "list":
            if not macros:
                print("(no macros)")
                return
            for name, cmds in sorted(macros.items()):
                preview = "; ".join(cmds[:3])
                if len(cmds) > 3:
                    preview += "..."
                print(f"  {name:<20s}  ({len(cmds)} cmds) {preview}")
        elif sub == "delete":
            if len(parts) < 2:
                print("Usage: macro delete <name>"); return
            macros.pop(parts[1], None)
            _save_json(macro_path, macros)
            print(f"Deleted macro '{parts[1]}'")
        elif sub == "show":
            if len(parts) < 2:
                print("Usage: macro show <name>"); return
            cmds = macros.get(parts[1])
            if not cmds:
                print(f"Macro '{parts[1]}' not found"); return
            print(f"  Macro: {parts[1]}")
            for i, cmd in enumerate(cmds, 1):
                print(f"    {i:>3d}. {cmd}")
        else:
            print(f"Unknown macro subcommand: {sub}")

    def do_timing(self, arg: str) -> None:
        """timing [on|off]   Toggle command execution timing display."""
        parts = self._split(arg)
        if not parts:
            self.state.command_timing = not self.state.command_timing
        elif parts[0].lower() in ("on", "yes", "true", "1"):
            self.state.command_timing = True
        elif parts[0].lower() in ("off", "no", "false", "0"):
            self.state.command_timing = False
        else:
            print("Usage: timing [on|off]")
            return
        print(f"Command timing: {'ON' if self.state.command_timing else 'OFF'}")
        if self.state.command_timing and self.state.command_times:
            print("\n  Command execution times (avg):")
            for cmd, times in sorted(self.state.command_times.items(),
                                     key=lambda x: -statistics.mean(x[1])):
                avg = statistics.mean(times)
                print(f"    {cmd:<25s}  {avg:>8.3f}s  ({len(times)} runs)")

    def do_debug(self, arg: str) -> None:
        """debug [on|off]   Toggle debug mode (verbose error traces)."""
        parts = self._split(arg)
        if not parts:
            self.state.debug_mode = not self.state.debug_mode
        elif parts[0].lower() in ("on", "yes", "true", "1"):
            self.state.debug_mode = True
        elif parts[0].lower() in ("off", "no", "false", "0"):
            self.state.debug_mode = False
        else:
            print("Usage: debug [on|off]")
            return
        print(f"Debug mode: {'ON' if self.state.debug_mode else 'OFF'}")

    def do_quiet(self, arg: str) -> None:
        """quiet [on|off]   Toggle quiet mode (suppress non-essential output)."""
        parts = self._split(arg)
        if not parts:
            self.state.quiet_mode = not self.state.quiet_mode
        elif parts[0].lower() in ("on", "yes", "true", "1"):
            self.state.quiet_mode = True
        elif parts[0].lower() in ("off", "no", "false", "0"):
            self.state.quiet_mode = False
        else:
            print("Usage: quiet [on|off]")
            return
        print(f"Quiet mode: {'ON' if self.state.quiet_mode else 'OFF'}")

    def do_env(self, arg: str) -> None:
        """env   Show environment and system information."""
        import platform
        import resource
        try:
            mem = resource.getrusage(resource.RUSAGE_SELF)
            mem_mb = mem.ru_maxrss / 1024
        except Exception:
            mem_mb = 0
        print(f"\n  Environment:")
        print(f"    Platform:       {platform.platform()}")
        print(f"    Python:         {platform.python_version()}")
        print(f"    Working dir:    {os.getcwd()}")
        print(f"    Log file:       {self.state.log_path}")
        print(f"    Entries:        {len(self.state.entries)}")
        print(f"    Active entries: {len(self._active_entries())}")
        print(f"    Memory (RSS):   {mem_mb:.1f} MB")
        print(f"    Config dir:     {_config_dir()}")
        print(f"    LLM cache:      {self.state.llm_cache.path if self.state.llm_cache else '(off)'}")
        if self.state.llm_cache:
            print(f"    LLM cache size: {len(self.state.llm_cache)} entries")
        print(f"    Web server:     {self.state.web_server.server_port if self.state.web_server else '(off)'}")
        print(f"    Web portal:     {self.state.portal_server.server_address[1] if self.state.portal_server else '(off)'}")
        print(f"    Watch BG:       {'running' if self.state.watch_bg else '(off)'}")
        print(f"    Plugins:        {len(_plugins)} loaded")
        print(f"    Aliases:        {len(self.state.aliases)}")
        print(f"    Ignored users:  {len(self.state.ignore_set)}")
        print(f"    Saved views:    {len(self.state.views)}")
        print(f"    Alert rules:    {len(self.state.alert_engine.rules)}")
        if self.state.case_store:
            print(f"    Cases:          {len(self.state.case_store.cases)}")

    def do_memory(self, arg: str) -> None:
        """memory   Show memory usage breakdown."""
        import resource
        try:
            mem = resource.getrusage(resource.RUSAGE_SELF)
            mem_mb = mem.ru_maxrss / 1024
            print(f"\n  Memory Usage:")
            print(f"    RSS (max):      {mem_mb:.1f} MB")
            print(f"    User time:      {mem.ru_utime:.2f}s")
            print(f"    System time:    {mem.ru_stime:.2f}s")
            print(f"    Page faults:    {mem.ru_majflt} (major) / {mem.ru_minflt} (minor)")
        except Exception as exc:
            print(f"Memory info unavailable: {exc}")
        entry_mb = len(self.state.entries) * 500 / 1_000_000
        print(f"    Entries (~500B each): {entry_mb:.1f} MB")
        if self.state.llm_cache:
            cache_mb = len(json.dumps(self.state.llm_cache.data)) / 1_000_000
            print(f"    LLM cache:      {cache_mb:.1f} MB ({len(self.state.llm_cache)} entries)")

    def do_reset(self, arg: str) -> None:
        """reset [all|filters|settings|aliases|notes|ignore]   Reset configuration."""
        parts = self._split(arg)
        target = parts[0].lower() if parts else "all"
        if target == "all":
            self.state.focused_user = None
            self.state.focused_target = None
            self.state.since = None
            self.state.until = None
            self.state.top_n = 15
            self.state.llm_url = "http://127.0.0.1:8033/"
            self.state.llm_model = "local"
            self.state.max_chunk_chars = 12000
            self.state.pager_enabled = True
            self.state.color_enabled = True
            _Color.enabled = True
            self.state.aliases.clear()
            self.state.notes.clear()
            self.state.ignore_set.clear()
            self.state.views.clear()
            self.state.alert_engine.rules.clear()
            self.state.default_z_threshold = 2.5
            self.state.default_anomaly_window = 14
            self.state.default_forecast_days = 30
            self.state.output_format = "table"
            self.state.command_timing = False
            self.state.debug_mode = False
            self.state.quiet_mode = False
            self.state.max_output_lines = 500
            print("Reset all settings to defaults.")
        elif target == "filters":
            self.state.focused_user = None
            self.state.focused_target = None
            self.state.since = None
            self.state.until = None
            print("Reset filters.")
        elif target == "settings":
            self.state.top_n = 15
            self.state.llm_url = "http://127.0.0.1:8033/"
            self.state.llm_model = "local"
            self.state.max_chunk_chars = 12000
            self.state.pager_enabled = True
            self.state.color_enabled = True
            _Color.enabled = True
            print("Reset settings.")
        elif target == "aliases":
            self.state.aliases.clear()
            _save_json(_aliases_path(), {})
            print("Reset aliases.")
        elif target == "notes":
            self.state.notes.clear()
            _save_json(_notes_path(), {})
            print("Reset notes.")
        elif target == "ignore":
            self.state.ignore_set.clear()
            _save_json(_ignore_path(), [])
            print("Reset ignore list.")
        else:
            print(f"Usage: reset [all|filters|settings|aliases|notes|ignore]")

    def do_export_config(self, arg: str) -> None:
        """export_config <path>   Export all configuration to a portable JSON file."""
        path = arg.strip()
        if not path:
            print("Usage: export_config <path>"); return
        config = {
            "aliases": self.state.aliases,
            "ignore_set": sorted(self.state.ignore_set),
            "notes": self.state.notes,
            "views": {n: {"user": v.user, "target": v.target,
                          "since": v.since.isoformat() if v.since else None,
                          "until": v.until.isoformat() if v.until else None,
                          "regex": v.regex,
                          "score_filter": v.score_filter}
                      for n, v in self.state.views.items()},
            "rules": [{"name": r.name, "field": r.field, "op": r.op,
                       "value": r.value, "message": r.message, "enabled": r.enabled}
                      for r in self.state.alert_engine.rules],
            "presets": self.state.presets,
            "advanced": {
                "default_z_threshold": self.state.default_z_threshold,
                "default_anomaly_window": self.state.default_anomaly_window,
                "default_forecast_days": self.state.default_forecast_days,
                "default_burst_window": self.state.default_burst_window,
                "default_burst_z": self.state.default_burst_z,
                "default_session_gap": self.state.default_session_gap,
                "default_response_window": self.state.default_response_window,
                "output_format": self.state.output_format,
                "command_timing": self.state.command_timing,
                "debug_mode": self.state.debug_mode,
                "quiet_mode": self.state.quiet_mode,
                "score_flag_threshold": self.state.score_flag_threshold,
                "max_output_lines": self.state.max_output_lines,
            },
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2, default=str)
            print(f"Exported config to {path}")
        except OSError as exc:
            print(f"Export failed: {exc}")

    def do_import_config(self, arg: str) -> None:
        """import_config <path>   Import configuration from a portable JSON file."""
        path = arg.strip()
        if not path:
            print("Usage: import_config <path>"); return
        try:
            with open(path, "r", encoding="utf-8") as f:
                config = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            print(f"Import failed: {exc}"); return
        if "aliases" in config:
            self.state.aliases.update(config["aliases"])
            _save_json(_aliases_path(), self.state.aliases)
        if "ignore_set" in config:
            self.state.ignore_set.update(config["ignore_set"])
            _save_json(_ignore_path(), sorted(self.state.ignore_set))
        if "notes" in config:
            self.state.notes.update(config["notes"])
            _save_json(_notes_path(), self.state.notes)
        if "views" in config:
            for name, vd in config["views"].items():
                self.state.views[name] = View(
                    name=name, user=vd.get("user"), target=vd.get("target"),
                    since=parse_iso_arg(vd["since"]) if vd.get("since") else None,
                    until=parse_iso_arg(vd["until"]) if vd.get("until") else None,
                    regex=vd.get("regex"), score_filter=vd.get("score_filter", []),
                )
        if "rules" in config:
            for rd in config["rules"]:
                self.state.alert_engine.add(AlertRule(**rd))
        if "presets" in config:
            self.state.presets.update(config["presets"])
        if "advanced" in config:
            adv = config["advanced"]
            for key in ("default_z_threshold", "default_anomaly_window", "default_forecast_days",
                        "default_burst_window", "default_burst_z", "default_session_gap",
                        "default_response_window", "output_format", "command_timing",
                        "debug_mode", "quiet_mode", "score_flag_threshold", "max_output_lines"):
                if key in adv:
                    setattr(self.state, key, adv[key])
        print(f"Imported config from {path}")

    def do_benchmark(self, arg: str) -> None:
        """benchmark [N]   Run performance benchmarks (default N=1000 entries)."""
        n = int(arg.strip()) if arg.strip().isdigit() else 1000
        entries = self._active_entries()[:n]
        if not entries:
            print("(no entries to benchmark)"); return
        print(f"\n  Benchmarking with {len(entries)} entries...")
        import time
        results: list[tuple[str, float]] = []
        ops = [
            ("summarize", lambda: summarize(entries, 15)),
            ("build_profile", lambda: build_profile(entries, entries[0].user) if entries[0].user else None),
            ("build_edge_graph", lambda: build_edge_graph(entries)),
            ("detect_tampering", lambda: detect_tampering(entries)),
            ("extract_entities", lambda: build_entity_catalog(entries)),
            ("detect_anomalies", lambda: detect_anomalies(entries, entries[0].user) if entries[0].user else []),
            ("word_frequency", lambda: word_frequency(entries, 50)),
            ("log_coverage", lambda: log_coverage(entries)),
            ("compute_stats", lambda: compute_stats(entries)),
            ("user_sentiment", lambda: user_sentiment(entries, entries[0].user) if entries[0].user else {}),
        ]
        for name, fn in ops:
            start = time.perf_counter()
            try:
                fn()
            except Exception:
                pass
            elapsed = time.perf_counter() - start
            results.append((name, elapsed))
            print(f"    {name:<25s}  {elapsed:>8.4f}s")
        total = sum(t for _, t in results)
        print(f"\n  Total: {total:.4f}s  ({len(entries)} entries)")
        if total > 0:
            print(f"  Rate: {len(entries) / total:,.0f} entries/sec")

    def do_set_default(self, arg: str) -> None:
        """set_default <key> <value>   Set advanced default parameters.

        Keys:
          z_threshold        Default z-score for anomaly detection (default 2.5)
          anomaly_window     Default lookback window for diagnostics (default 14)
          forecast_days      Default forecast horizon (default 30)
          burst_window       Default burst detection window in seconds (default 60)
          burst_z            Default burst z-score threshold (default 3.0)
          session_gap        Default session gap in minutes (default 30)
          response_window    Default response time window in seconds (default 300)
          score_flag_threshold  Default score threshold for flagging (default 0.8)
          output_format      Default output format: table|json|plain (default table)
          max_output_lines   Max lines before pager triggers (default 500)
        """
        parts = self._split(arg)
        if len(parts) < 2:
            print("Usage: set_default <key> <value>")
            print("Keys: z_threshold, anomaly_window, forecast_days, burst_window,")
            print("      burst_z, session_gap, response_window, score_flag_threshold,")
            print("      output_format, max_output_lines")
            return
        key, value = parts[0], " ".join(parts[1:])
        float_keys = {"z_threshold", "burst_z", "score_flag_threshold"}
        int_keys = {"anomaly_window", "forecast_days", "burst_window",
                    "session_gap", "response_window", "max_output_lines"}
        if key in float_keys:
            try:
                setattr(self.state, f"default_{key}" if key != "score_flag_threshold" else key, float(value))
            except ValueError:
                print(f"{key} must be a float"); return
        elif key in int_keys:
            try:
                setattr(self.state, key, int(value))
            except ValueError:
                print(f"{key} must be an integer"); return
        elif key == "output_format":
            if value.lower() not in ("table", "json", "plain"):
                print("output_format must be table|json|plain"); return
            self.state.output_format = value.lower()
        else:
            print(f"Unknown key: {key}"); return
        print(f"{key} = {value}")

    def do_show_defaults(self, arg: str) -> None:
        """show_defaults   Display all advanced default parameters."""
        s = self.state
        print(f"\n  Advanced Defaults:")
        print(f"    z_threshold:          {s.default_z_threshold}")
        print(f"    anomaly_window:       {s.default_anomaly_window} days")
        print(f"    forecast_days:        {s.default_forecast_days} days")
        print(f"    burst_window:         {s.default_burst_window}s")
        print(f"    burst_z:              {s.default_burst_z}")
        print(f"    session_gap:          {s.default_session_gap}min")
        print(f"    response_window:      {s.default_response_window}s")
        print(f"    score_flag_threshold: {s.score_flag_threshold}")
        print(f"    output_format:        {s.output_format}")
        print(f"    command_timing:       {s.command_timing}")
        print(f"    debug_mode:           {s.debug_mode}")
        print(f"    quiet_mode:           {s.quiet_mode}")
        print(f"    max_output_lines:     {s.max_output_lines}")

    def do_quit(self, arg: str) -> bool:
        """quit   Exit the shell."""
        save_shell_config(self.state)
        if self.state.watch_bg:
            self.state.watch_bg.stop()
            self.state.watch_bg = None
        if self.state.web_server:
            self.state.web_server.shutdown()
            self.state.web_server = None
        if self.state.portal_server:
            self.state.portal_server.shutdown()
            self.state.portal_server = None
        if self.state.llm_cache:
            self.state.llm_cache.save()
        self._save_history()
        return True

    do_exit = do_quit
    do_EOF = do_quit

    def emptyline(self) -> bool:
        return False

    def default(self, line: str) -> None:
        print(f"Unknown command: {line.split()[0] if line.split() else ''}. Try 'help'.")

    # --- new commands: info / pick / inspect / last / script / alias / ignore / note ---

    def do_info(self, arg: str) -> None:
        """info [user]   One-line user summary (uses focused_user if no arg)."""
        user = self._resolve_user(arg)
        if not user:
            return
        profile = build_profile(self._time_filtered(), user)
        sm = profile["score_means"]
        peak = _peak_hours(profile["by_hour"]).split(",")[0] or "—"
        top_chan = _top_str(profile["channels"], 1) or "—"
        score_strs = []
        for k in SCORE_KEYS:
            v = sm.get(k)
            score_strs.append(f"{k}={_color_score(v) if isinstance(v, float) else '—'}")
        note = self.state.notes.get(user, "")
        bits = [
            user,
            f"lines={profile['authored']}",
            f"days={len(profile['by_day'])}",
            f"peak={peak}",
            f"top_chan={top_chan}",
            *score_strs,
        ]
        if note:
            bits.append(f"note=\"{note}\"")
        if user in self.state.ignore_set:
            bits.append("[IGNORED]")
        print("  " + "  ".join(bits))

    def do_pick(self, arg: str) -> None:
        """pick <N>   Focus on the Nth item from the previous listing (1-indexed).
        Falls back to the author of the Nth entry from the previous entry list."""
        parts = self._split(arg)
        if not parts or not parts[0].isdigit():
            print("Usage: pick <N>"); return
        idx = int(parts[0]) - 1
        listing = self.state.last_listing
        if not listing and self.state.last_entries:
            seen: list[str] = []
            for e in self.state.last_entries:
                if e.user and e.user not in seen:
                    seen.append(e.user)
            listing = seen
        if idx < 0 or idx >= len(listing):
            print(f"No item {idx + 1} in last listing (have {len(listing)}).")
            return
        pick = listing[idx]
        self._push_focus()
        self.state.focused_user = pick
        print(f"Focused user = {pick}")
        self._refresh_prompt()

    def do_inspect(self, arg: str) -> None:
        """inspect <N>   Show full raw line / pretty-printed JSON for entry N from the
        previous listing (flagged, errors, grep, show, threads)."""
        parts = self._split(arg)
        if not parts or not parts[0].isdigit():
            print("Usage: inspect <N>"); return
        idx = int(parts[0]) - 1
        if idx < 0 or idx >= len(self.state.last_entries):
            print(f"No entry {idx + 1} in last listing (have {len(self.state.last_entries)}).")
            return
        e = self.state.last_entries[idx]
        print(f"=== Entry {idx + 1} ({e.fmt}) ===")
        print(f"  ts:     {e.ts}")
        print(f"  user:   {e.user}")
        print(f"  target: {e.target}")
        print(f"  level:  {e.level}")
        print(f"  event:  {e.event}")
        print(f"  text:   {e.text}")
        if e.fmt == "json":
            try:
                obj = json.loads(e.raw)
                print("  json:")
                print(json.dumps(obj, indent=2, default=str))
                return
            except json.JSONDecodeError:
                pass
        print(f"  raw:    {e.raw}")

    def do_last(self, arg: str) -> None:
        """last   Re-print the captured output of the previous command."""
        if not self.state.last_output:
            print("(no previous output)")
            return
        sys.stdout.write(self.state.last_output)

    def do_script(self, arg: str) -> None:
        """script <path>   Run TUI commands from a file (one per line; # comments)."""
        path = arg.strip().strip('"').strip("'")
        if not path:
            print("Usage: script <path>"); return
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except OSError as exc:
            print(f"Could not read {path}: {exc}"); return
        saved_pager = self.state.pager_enabled
        saved_in_script = self._in_script
        self.state.pager_enabled = False
        self._in_script = True
        try:
            for raw in lines:
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                print(f"{self.prompt}{line}")
                if self.onecmd(line):
                    return
                self._refresh_prompt()
        finally:
            self.state.pager_enabled = saved_pager
            self._in_script = saved_in_script

    def do_alias(self, arg: str) -> None:
        """alias                       List all aliases.
        alias <name>                 Show one alias.
        alias <name> = <command>     Define/replace.
        alias <name> =               Remove."""
        s = arg.strip()
        if not s:
            if not self.state.aliases:
                print("(no aliases)")
                return
            for name, cmd_ in sorted(self.state.aliases.items()):
                print(f"  {name} = {cmd_}")
            return
        if "=" in s:
            name, _, body = s.partition("=")
            name = name.strip()
            body = body.strip()
            if not name:
                print("Usage: alias <name> = <command>"); return
            if not body:
                self.state.aliases.pop(name, None)
                _save_json(_aliases_path(), self.state.aliases)
                print(f"Removed alias '{name}'.")
                return
            self.state.aliases[name] = body
            _save_json(_aliases_path(), self.state.aliases)
            print(f"alias {name} = {body}")
        else:
            if s in self.state.aliases:
                print(f"  {s} = {self.state.aliases[s]}")
            else:
                print(f"(no alias '{s}')")

    def do_ignore(self, arg: str) -> None:
        """ignore                       List ignored users.
        ignore <user>...             Add to ignore list.
        ignore add <user>...         Add (explicit).
        ignore drop <user>...        Remove from ignore list.
        ignore list                  List ignored users."""
        parts = self._split(arg)
        if not parts or (len(parts) == 1 and parts[0].lower() == "list"):
            if not self.state.ignore_set:
                print("(ignore list empty)")
                return
            for u in sorted(self.state.ignore_set):
                print(f"  {u}")
            return
        sub = parts[0].lower()
        if sub == "add" and len(parts) >= 2:
            for u in parts[1:]:
                self.state.ignore_set.add(u)
        elif sub == "drop" and len(parts) >= 2:
            for u in parts[1:]:
                self.state.ignore_set.discard(u)
        else:
            for u in parts:
                self.state.ignore_set.add(u)
        _save_json(_ignore_path(), sorted(self.state.ignore_set))
        print(f"Ignore list now: {len(self.state.ignore_set)} users.")
        self._refresh_prompt()

    def do_note(self, arg: str) -> None:
        """note                       List notes.
        note <user>                 Show note.
        note <user> <text>          Set note.
        note <user> --del           Remove note."""
        s = arg.strip()
        if not s:
            if not self.state.notes:
                print("(no notes)")
                return
            for u, n in sorted(self.state.notes.items()):
                print(f"  {u}: {n}")
            return
        head, _, body = s.partition(" ")
        user = head
        body = body.strip()
        if not body:
            if user in self.state.notes:
                print(f"  {user}: {self.state.notes[user]}")
            else:
                print(f"(no note for '{user}')")
            return
        if body in {"--del", "--delete", "-d"}:
            removed = self.state.notes.pop(user, None)
            _save_json(_notes_path(), self.state.notes)
            if removed is not None:
                print(f"Removed note for '{user}'.")
            else:
                print(f"(no note for '{user}')")
            return
        self.state.notes[user] = body
        _save_json(_notes_path(), self.state.notes)
        print(f"  {user}: {body}")

    # --- future diagnostics ----------------------------------------------------

    def do_future_diag(self, arg: str) -> None:
        """future_diag [user] [--lookback N] [--forecast N] [--auto-case]
        Predictive diagnostics: health metrics, early warnings, degradation signals,
        risk trajectories, and scenario forecasting.

        Options:
          --lookback N    Days of history to analyze (default 14)
          --forecast N    Days to project forward (default 30)
          --auto-case     Auto-create a case if critical warnings are found
          --json          Output as JSON
        """
        parts = self._split(arg)
        user = None
        lookback = 14
        forecast = 30
        auto_case = False
        as_json = False
        i = 0
        while i < len(parts):
            if parts[i] == "--lookback" and i + 1 < len(parts):
                try:
                    lookback = int(parts[i + 1])
                except ValueError:
                    pass
                i += 2
            elif parts[i] == "--forecast" and i + 1 < len(parts):
                try:
                    forecast = int(parts[i + 1])
                except ValueError:
                    pass
                i += 2
            elif parts[i] == "--auto-case":
                auto_case = True; i += 1
            elif parts[i] == "--json":
                as_json = True; i += 1
            elif not parts[i].startswith("--"):
                user = parts[i]; i += 1
            else:
                i += 1
        entries = self._filtered(user) if user else self._active_entries()
        if not entries:
            print("(no data for diagnostics)")
            return
        diag = compute_future_diagnostics(entries, lookback, forecast)
        if as_json:
            out = {
                "timestamp": diag.timestamp,
                "overall_health": diag.overall_health,
                "overall_risk_trend": diag.overall_risk_trend,
                "summary": diag.summary,
                "health_metrics": [
                    {"name": m.name, "current": m.current, "baseline": m.baseline,
                     "trend": m.trend, "trajectory_7d": m.trajectory_7d,
                     "trajectory_30d": m.trajectory_30d, "status": m.status,
                     "details": m.details}
                    for m in diag.health_metrics
                ],
                "early_warnings": [
                    {"indicator": w.indicator, "current_value": w.current_value,
                     "threshold": w.threshold, "projected_breach": w.projected_breach,
                     "confidence": w.confidence, "trend": w.trend,
                     "severity": w.severity, "recommendation": w.recommendation}
                    for w in diag.early_warnings
                ],
                "degradations": [
                    {"metric": d.metric, "user": d.user, "rate_per_day": d.rate_per_day,
                     "current_level": d.current_level, "critical_level": d.critical_level,
                     "eta_days": d.eta_days, "severity": d.severity}
                    for d in diag.degradations
                ],
                "risk_trajectories": [
                    {"user": r.user, "current_risk": r.current_risk,
                     "risk_7d": r.risk_7d, "risk_30d": r.risk_30d,
                     "direction": r.direction, "acceleration": r.acceleration,
                     "drivers": r.drivers}
                    for r in diag.risk_trajectories
                ],
                "scenarios": [
                    {"name": s.name, "description": s.description,
                     "probability": s.probability, "impact": s.impact,
                     "indicators": s.indicators, "mitigation": s.mitigation}
                    for s in diag.scenarios
                ],
            }
            print(json.dumps(out, indent=2, default=str))
        else:
            print_future_diagnostics(diag)
        if auto_case and (diag.early_warnings or diag.degradations):
            cs = self.state.case_store
            if cs:
                high_sev = [w for w in diag.early_warnings if w.severity == "high"]
                if high_sev or diag.degradations:
                    name = f"Auto: {diag.overall_health} diagnostics"
                    desc = diag.summary
                    c = cs.create(name, desc, priority="high" if diag.overall_health == "critical" else "medium",
                                  tags=["auto-generated", "future-diagnostics"])
                    for w in high_sev:
                        cs.add_finding(c.id, evidence_text=f"WARNING: {w.indicator} — {w.recommendation}",
                                       category="early_warning", severity=w.severity,
                                       note=f"Current: {w.current_value:.2f}, Threshold: {w.threshold:.2f}, ETA: {w.projected_breach}")
                    for d in diag.degradations:
                        cs.add_finding(c.id, evidence_text=f"DEGRADATION: {d.metric} rate={d.rate_per_day:+.3f}/day",
                                       category="degradation", severity=d.severity,
                                       note=f"ETA to critical: {d.eta_days:.0f}d" if d.eta_days else "No ETA")
                    print(f"\nAuto-created case {c.id} with {len(high_sev) + len(diag.degradations)} findings.")

    # --- case management -------------------------------------------------------

    def do_case(self, arg: str) -> None:
        """case   Manage investigation cases.

        case create <name> [--desc "..." --priority high --tag foo --assign alice]
        case list [--status open --tag foo]
        case show <id>
        case add <id> [--user X --evidence "..." --category anomaly --severity high --note "..."]
        case add-from <id> --grep "<regex>" [--category anomaly --severity high]
        case add-from <id> --flagged "llama>0.8" [--category anomaly --severity high]
        case add-from <id> --user <nick> [--category behavior --severity medium]
        case status <id> <new_status>
        case tag <id> <tag>
        case untag <id> <tag>
        case assign <id> <person>
        case rm-finding <case_id> <finding_id>
        case delete <id>
        case export <id> [path]
        case search <query>
        case stats
        """
        parts = self._split(arg)
        if not parts:
            self.do_case("list")
            return
        sub = parts[0].lower()

        if sub == "create":
            name = parts[1] if len(parts) > 1 else None
            if not name:
                print("Usage: case create <name> [--desc ... --priority high --tag foo --assign alice]")
                return
            desc = ""
            priority = "medium"
            tags: list[str] = []
            assigned = ""
            i = 2
            while i < len(parts):
                if parts[i] == "--desc" and i + 1 < len(parts):
                    desc = parts[i + 1]; i += 2
                elif parts[i] == "--priority" and i + 1 < len(parts):
                    priority = parts[i + 1]; i += 2
                elif parts[i] == "--tag" and i + 1 < len(parts):
                    tags.append(parts[i + 1]); i += 2
                elif parts[i] == "--assign" and i + 1 < len(parts):
                    assigned = parts[i + 1]; i += 2
                else:
                    i += 1
            c = self.state.case_store.create(name, desc, priority, tags, assigned)
            print(f"Created {c.id}: {c.name} (priority={c.priority}, status={c.status})")

        elif sub == "list":
            status = None
            tag = None
            i = 1
            while i < len(parts):
                if parts[i] == "--status" and i + 1 < len(parts):
                    status = parts[i + 1]; i += 2
                elif parts[i] == "--tag" and i + 1 < len(parts):
                    tag = parts[i + 1]; i += 2
                else:
                    i += 1
            cases = self.state.case_store.list_cases(status, tag)
            if not cases:
                print("(no cases)")
                return
            hdr = f"  {'ID':<12s} {'Status':<16s} {'Pri':<8s} {'Name':<30s} {'Findings':>8s}  Tags"
            print(hdr)
            print("  " + "-" * (len(hdr) - 2))
            for c in cases:
                tag_str = ", ".join(c.tags[:3])
                if len(c.tags) > 3:
                    tag_str += "..."
                print(f"  {c.id:<12s} {c.status:<16s} {c.priority:<8s} {c.name[:30]:<30s} {len(c.findings):>8d}  {tag_str}")

        elif sub == "show":
            if len(parts) < 2:
                print("Usage: case show <id>")
                return
            c = self.state.case_store.get(parts[1])
            if not c:
                print(f"Case {parts[1]} not found")
                return
            print(f"  ID:         {c.id}")
            print(f"  Name:       {c.name}")
            print(f"  Status:     {c.status}")
            print(f"  Priority:   {c.priority}")
            print(f"  Assigned:   {c.assigned_to or '(unassigned)'}")
            print(f"  Tags:       {', '.join(c.tags) or '(none)'}")
            print(f"  Created:    {c.created}")
            print(f"  Updated:    {c.updated}")
            print(f"  Findings:   {len(c.findings)}")
            print(f"  Description:")
            for line in c.description.split("\n"):
                print(f"    {line}")
            if c.findings:
                print(f"\n  Findings:")
                for f in c.findings:
                    sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "ℹ️"}.get(f.severity, "•")
                    print(f"    {sev_icon} {f.id}  [{f.severity:>8s}] {f.category}")
                    if f.user:
                        print(f"       user={f.user}")
                    if f.entry_id is not None:
                        print(f"       entry=#{f.entry_id}")
                    if f.evidence_text:
                        print(f"       evidence: {f.evidence_text[:150]}")
                    if f.note:
                        print(f"       note: {f.note}")
                    print(f"       added: {f.ts_added}")

        elif sub == "add":
            if len(parts) < 2:
                print("Usage: case add <id> [--user X --evidence ... --category anomaly --severity high --note ...]")
                return
            cid = parts[1]
            user = None
            evidence = ""
            category = "other"
            severity = "medium"
            note = ""
            entry_id = None
            i = 2
            while i < len(parts):
                if parts[i] == "--user" and i + 1 < len(parts):
                    user = parts[i + 1]; i += 2
                elif parts[i] == "--evidence" and i + 1 < len(parts):
                    evidence = parts[i + 1]; i += 2
                elif parts[i] == "--category" and i + 1 < len(parts):
                    category = parts[i + 1]; i += 2
                elif parts[i] == "--severity" and i + 1 < len(parts):
                    severity = parts[i + 1]; i += 2
                elif parts[i] == "--note" and i + 1 < len(parts):
                    note = parts[i + 1]; i += 2
                elif parts[i] == "--entry" and i + 1 < len(parts):
                    try:
                        entry_id = int(parts[i + 1])
                    except ValueError:
                        pass
                    i += 2
                else:
                    i += 1
            f = self.state.case_store.add_finding(cid, entry_id, user, evidence, category, severity, note)
            if f:
                print(f"Added finding {f.id} to {cid}")
            else:
                print(f"Case {cid} not found")

        elif sub == "add-from":
            if len(parts) < 2:
                print("Usage: case add-from <id> --grep '<regex>' [--category ... --severity ...]")
                return
            cid = parts[1]
            c = self.state.case_store.get(cid)
            if not c:
                print(f"Case {cid} not found")
                return
            category = "other"
            severity = "medium"
            grep_pat = None
            flagged_expr = None
            filter_user = None
            i = 2
            while i < len(parts):
                if parts[i] == "--grep" and i + 1 < len(parts):
                    grep_pat = parts[i + 1]; i += 2
                elif parts[i] == "--flagged" and i + 1 < len(parts):
                    flagged_expr = parts[i + 1]; i += 2
                elif parts[i] == "--user" and i + 1 < len(parts):
                    filter_user = parts[i + 1]; i += 2
                elif parts[i] == "--category" and i + 1 < len(parts):
                    category = parts[i + 1]; i += 2
                elif parts[i] == "--severity" and i + 1 < len(parts):
                    severity = parts[i + 1]; i += 2
                else:
                    i += 1
            if not grep_pat and not flagged_expr and not filter_user:
                print("Specify --grep, --flagged, or --user")
                return
            matched: list[Entry] = []
            if grep_pat:
                try:
                    rx = re.compile(grep_pat, re.I)
                except re.error as exc:
                    print(f"Bad regex: {exc}"); return
                for idx, e in enumerate(self._active_entries()):
                    if rx.search(e.raw):
                        matched.append(e)
            if flagged_expr:
                try:
                    filters = parse_score_filter(flagged_expr)
                except ValueError as exc:
                    print(f"Bad score filter: {exc}"); return
                for e in self._active_entries():
                    if matches_score_filter(e, filters):
                        if e not in matched:
                            matched.append(e)
            if filter_user:
                for e in self._active_entries():
                    if line_matches_user(e, filter_user):
                        if e not in matched:
                            matched.append(e)
            if not matched:
                print("(no matching entries)")
                return
            added = 0
            for e in matched[:50]:
                uid = self.state.entries.index(e) + 1 if e in self.state.entries else None
                self.state.case_store.add_finding(
                    cid, entry_id=uid, user=e.user,
                    evidence_text=e.raw[:200], category=category, severity=severity,
                    note=f"auto-added via add-from")
                added += 1
            if len(matched) > 50:
                print(f"Added {added}/50 findings to {cid} (truncated from {len(matched)})")
            else:
                print(f"Added {added} findings to {cid}")

        elif sub == "status":
            if len(parts) < 3:
                print("Usage: case status <id> <open|investigating|resolved|closed|false-positive>")
                return
            ok = self.state.case_store.update_status(parts[1], parts[2])
            if ok:
                print(f"Case {parts[1]} status → {parts[2]}")
            else:
                print(f"Case {parts[1]} not found")

        elif sub == "tag":
            if len(parts) < 3:
                print("Usage: case tag <id> <tag>")
                return
            c = self.state.case_store.get(parts[1])
            if not c:
                print(f"Case {parts[1]} not found"); return
            if parts[2] not in c.tags:
                c.tags.append(parts[2])
                c.updated = datetime.now().isoformat()
                self.state.case_store._save()
                print(f"Tagged {parts[1]} with '{parts[2]}'")

        elif sub == "untag":
            if len(parts) < 3:
                print("Usage: case untag <id> <tag>")
                return
            c = self.state.case_store.get(parts[1])
            if not c:
                print(f"Case {parts[1]} not found"); return
            if parts[2] in c.tags:
                c.tags.remove(parts[2])
                c.updated = datetime.now().isoformat()
                self.state.case_store._save()
                print(f"Removed tag '{parts[2]}' from {parts[1]}")

        elif sub == "assign":
            if len(parts) < 3:
                print("Usage: case assign <id> <person>")
                return
            c = self.state.case_store.get(parts[1])
            if not c:
                print(f"Case {parts[1]} not found"); return
            c.assigned_to = parts[2]
            c.updated = datetime.now().isoformat()
            self.state.case_store._save()
            print(f"Assigned {parts[1]} to {parts[2]}")

        elif sub == "rm-finding":
            if len(parts) < 3:
                print("Usage: case rm-finding <case_id> <finding_id>")
                return
            ok = self.state.case_store.remove_finding(parts[1], parts[2])
            if ok:
                print(f"Removed finding {parts[2]}")
            else:
                print(f"Case/finding not found")

        elif sub == "delete":
            if len(parts) < 2:
                print("Usage: case delete <id>")
                return
            ok = self.state.case_store.delete(parts[1])
            if ok:
                print(f"Deleted {parts[1]}")
            else:
                print(f"Case {parts[1]} not found")

        elif sub == "export":
            if len(parts) < 2:
                print("Usage: case export <id> [path]")
                return
            report = self.state.case_store.export_report(parts[1])
            if len(parts) >= 3:
                try:
                    with open(parts[2], "w", encoding="utf-8") as f:
                        f.write(report)
                    print(f"Exported to {parts[2]}")
                except OSError as exc:
                    print(f"Export failed: {exc}")
            else:
                print(report)

        elif sub == "search":
            if len(parts) < 2:
                print("Usage: case search <query>")
                return
            results = self.state.case_store.search(" ".join(parts[1:]))
            if not results:
                print("(no matches)")
                return
            for c, f in results:
                if f:
                    print(f"  {c.id} [{c.status}] {c.name} → finding {f.id}: {f.evidence_text[:100]}")
                else:
                    print(f"  {c.id} [{c.status}] {c.name} (case-level match)")

        elif sub == "stats":
            st = self.state.case_store.summary_stats()
            print(f"\nCase Management Stats:")
            print(f"  Total cases:    {st['total_cases']}")
            print(f"  Total findings: {st['total_findings']}")
            if st["by_status"]:
                print(f"  By status:      {', '.join(f'{k}={v}' for k, v in sorted(st['by_status'].items()))}")
            if st["by_priority"]:
                print(f"  By priority:    {', '.join(f'{k}={v}' for k, v in sorted(st['by_priority'].items()))}")
            if st["by_severity"]:
                print(f"  By severity:    {', '.join(f'{k}={v}' for k, v in sorted(st['by_severity'].items()))}")
            if st["by_category"]:
                print(f"  By category:    {', '.join(f'{k}={v}' for k, v in sorted(st['by_category'].items()))}")

        else:
            print(f"Unknown case subcommand: {sub}")

    # --- forensic commands ---------------------------------------------------

    def do_entities(self, arg: str) -> None:
        """entities [user]   Extract forensic entities (IPs, URLs, emails, hashes, file paths)."""
        user = arg.strip() or self.state.focused_user
        entries = self._filtered(user) if user else self._active_entries()
        if not entries:
            print("(no data)")
            return
        catalog = build_entity_catalog(entries)
        print_entity_report(catalog)

    def do_gaps(self, arg: str) -> None:
        """gaps [user] [threshold_min]   Detect gaps in activity timeline."""
        parts = self._split(arg)
        user = None
        threshold = 60
        for p in parts:
            try:
                threshold = int(p)
            except ValueError:
                user = p
        user = self._resolve_user(user or "") if user else None
        entries = self._filtered(user) if user else self._active_entries()
        gaps = detect_timeline_gaps(entries, user, threshold)
        print_timeline_gaps(gaps, user)

    def do_reconstruct(self, arg: str) -> None:
        """reconstruct [user] [--entities]   Chronological timeline reconstruction."""
        parts = self._split(arg)
        user = None
        show_entities = False
        for p in parts:
            if p == "--entities":
                show_entities = True
            elif not p.startswith("--"):
                user = p
        user = self._resolve_user(user or "") if user else None
        entries = self._filtered(user) if user else self._active_entries()
        timeline = reconstruct_timeline(entries, user)
        print_timeline_reconstruction(timeline, show_entities)

    def do_forensic_report(self, arg: str) -> None:
        """forensic_report <user>   LLM-powered comprehensive forensic report."""
        user = self._resolve_user(arg)
        if not user:
            return
        llm_forensic_report(
            self.state.entries, user,
            self.state.llm_url, self.state.llm_model,
            self.state.max_chunk_chars, cache=self.state.llm_cache,
        )

    def do_timeline_narrative(self, arg: str) -> None:
        """timeline_narrative <user>   LLM-generated narrative from timeline events."""
        user = self._resolve_user(arg)
        if not user:
            return
        llm_timeline_narrative(
            self.state.entries, user,
            self.state.llm_url, self.state.llm_model,
            self.state.max_chunk_chars, cache=self.state.llm_cache,
        )

    def do_evidence(self, arg: str) -> None:
        """evidence <user>   LLM-based structured evidence extraction."""
        user = self._resolve_user(arg)
        if not user:
            return
        llm_evidence_extraction(
            self.state.entries, user,
            self.state.llm_url, self.state.llm_model,
            self.state.max_chunk_chars, cache=self.state.llm_cache,
        )

    def do_tamper_detect(self, arg: str) -> None:
        """tamper_detect [user] [--strict]   Detect signs of log manipulation."""
        parts = self._split(arg)
        user = None
        strict = False
        for p in parts:
            if p == "--strict":
                strict = True
            elif not p.startswith("--"):
                user = p
        user = self._resolve_user(user or "") if user else None
        entries = self._filtered(user) if user else self._active_entries()
        if not entries:
            print("(no data)")
            return
        report = detect_tampering(entries, user, strict_mode=strict)
        print_tamper_report(report, user)

    # --- NEW LLM commands ----------------------------------------------------

    def do_llm_search(self, arg: str) -> None:
        """llm_search "<query>"   Natural language semantic search across all logs."""
        if not arg.strip():
            print('Usage: llm_search "<natural language query>"')
            return
        llm_search(self._active_entries(), arg.strip(),
                   self.state.llm_url, self.state.llm_model,
                   self.state.max_chunk_chars, cache=self.state.llm_cache)

    def do_llm_threat(self, arg: str) -> None:
        """llm_threat [user]   LLM threat assessment for a user."""
        user = self._resolve_user(arg)
        if not user:
            return
        llm_threat_assessment(self.state.entries, user,
                              self.state.llm_url, self.state.llm_model,
                              self.state.max_chunk_chars, cache=self.state.llm_cache)

    def do_llm_bot(self, arg: str) -> None:
        """llm_bot [user]   LLM bot/automation detection for a user."""
        user = self._resolve_user(arg)
        if not user:
            return
        llm_bot_detection(self.state.entries, user,
                          self.state.llm_url, self.state.llm_model,
                          self.state.max_chunk_chars, cache=self.state.llm_cache)

    def do_llm_profile(self, arg: str) -> None:
        """llm_profile [user]   Deep psychological/behavioral profile."""
        user = self._resolve_user(arg)
        if not user:
            return
        llm_deep_profile(self.state.entries, user,
                         self.state.llm_url, self.state.llm_model,
                         self.state.max_chunk_chars, cache=self.state.llm_cache)

    def do_llm_insider(self, arg: str) -> None:
        """llm_insider [user]   Insider threat analysis (exfiltration, policy violations)."""
        user = self._resolve_user(arg)
        if not user:
            return
        llm_insider_threat(self.state.entries, user,
                           self.state.llm_url, self.state.llm_model,
                           self.state.max_chunk_chars, cache=self.state.llm_cache)

    def do_llm_social(self, arg: str) -> None:
        """llm_social [N]   Social dynamics analysis (group structure, influence)."""
        n = int(arg.strip()) if arg.strip().isdigit() else 15
        llm_social_dynamics(self.state.entries, self.state.llm_url,
                            self.state.llm_model, self.state.max_chunk_chars,
                            cache=self.state.llm_cache, top_users=n)

    def do_llm_incident(self, arg: str) -> None:
        """llm_incident [query]   Incident timeline reconstruction with LLM narrative."""
        llm_incident_timeline(self.state.entries, self.state.llm_url,
                              self.state.llm_model, self.state.max_chunk_chars,
                              cache=self.state.llm_cache, query=arg.strip())

    def do_llm_topics(self, arg: str) -> None:
        """llm_topics [N]   Topic map: what users discuss and how topics connect."""
        n = int(arg.strip()) if arg.strip().isdigit() else 10
        llm_topic_map(self.state.entries, self.state.llm_url,
                      self.state.llm_model, self.state.max_chunk_chars,
                      cache=self.state.llm_cache, top_users=n)

    def do_llm_sessions(self, arg: str) -> None:
        """llm_sessions [user] [gap_min]   Compare user behavior across sessions."""
        parts = self._split(arg)
        user = parts[0] if parts else self.state.focused_user
        gap = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 60
        user = self._resolve_user(user or "")
        if not user:
            return
        llm_compare_sessions(self.state.entries, user, self.state.llm_url,
                             self.state.llm_model, self.state.max_chunk_chars,
                             cache=self.state.llm_cache, gap_minutes=gap)

    def do_llm_baseline(self, arg: str) -> None:
        """llm_baseline [user]   Establish behavioral baseline and flag deviations."""
        user = self._resolve_user(arg)
        if not user:
            return
        llm_baseline(self.state.entries, user, self.state.llm_url,
                     self.state.llm_model, self.state.max_chunk_chars,
                     cache=self.state.llm_cache)

    def do_llm_summary(self, arg: str) -> None:
        """llm_summary   LLM summary of the entire log."""
        llm_summary(self.state.entries, self.state.llm_url,
                    self.state.llm_model, self.state.max_chunk_chars,
                    cache=self.state.llm_cache)

    def do_llm_replay(self, arg: str) -> None:
        """llm_replay [user]   LLM narrates a user's activity as a story."""
        user = self._resolve_user(arg)
        if not user:
            return
        llm_replay(self.state.entries, user, self.state.llm_url,
                   self.state.llm_model, self.state.max_chunk_chars,
                   cache=self.state.llm_cache)

    def do_llm_predict(self, arg: str) -> None:
        """llm_predict [user]   Predict next likely actions/behavior."""
        user = self._resolve_user(arg)
        if not user:
            return
        llm_predict(self.state.entries, user, self.state.llm_url,
                    self.state.llm_model, self.state.max_chunk_chars,
                    cache=self.state.llm_cache)

    def do_llm_motive(self, arg: str) -> None:
        """llm_motive [user]   Analyze motivations and psychological drivers."""
        user = self._resolve_user(arg)
        if not user:
            return
        llm_motive(self.state.entries, user, self.state.llm_url,
                   self.state.llm_model, self.state.max_chunk_chars,
                   cache=self.state.llm_cache)

    def do_llm_relationship(self, arg: str) -> None:
        """llm_relationship <A> <B>   Deep relationship analysis between two users."""
        parts = self._split(arg)
        if len(parts) < 2:
            print("Usage: llm_relationship <userA> <userB>")
            return
        llm_relationship(self.state.entries, parts[0], parts[1],
                         self.state.llm_url, self.state.llm_model,
                         self.state.max_chunk_chars, cache=self.state.llm_cache)

    def do_llm_audit(self, arg: str) -> None:
        """llm_audit [policy]   Compliance audit against security policies."""
        llm_audit(self.state.entries, self.state.llm_url,
                  self.state.llm_model, self.state.max_chunk_chars,
                  cache=self.state.llm_cache, policy=arg.strip())

    def do_llm_risk(self, arg: str) -> None:
        """llm_risk [user]   Quantified 0-100 risk score with factor breakdown."""
        user = self._resolve_user(arg)
        if not user:
            return
        llm_risk_score(self.state.entries, user, self.state.llm_url,
                       self.state.llm_model, self.state.max_chunk_chars,
                       cache=self.state.llm_cache)

    # --- Statistical / Analytical -------------------------------------------

    def do_stats(self, arg: str) -> None:
        """stats [user]   Full statistical summary (mean/median/stdev/percentiles)."""
        user = arg.strip() or None
        stats = compute_stats(self._active_entries(), user)
        if not stats:
            print(f"(no data{' for ' + user if user else ''})")
            return
        print_stats(stats, user)

    def do_frequency(self, arg: str) -> None:
        """frequency [N]   Word/token frequency analysis across all logs."""
        n = int(arg.strip()) if arg.strip().isdigit() else 50
        freq = word_frequency(self._active_entries(), n)
        print_word_frequency(freq, n)

    def do_cooccurrence(self, arg: str) -> None:
        """cooccurrence [window_min]   Users appearing together in time windows."""
        window = int(arg.strip()) if arg.strip().isdigit() else 5
        pairs = user_cooccurrence(self._active_entries(), window)
        print_cooccurrence(pairs)

    def do_heatmap_user(self, arg: str) -> None:
        """heatmap_user [N]   2D heatmap: users (rows) × hours (columns)."""
        n = int(arg.strip()) if arg.strip().isdigit() else 20
        heatmap_user(self._active_entries(), n)

    def do_coverage(self, arg: str) -> None:
        """coverage   Log coverage analysis — density, gaps, completeness."""
        cov = log_coverage(self.state.entries)
        print_coverage(cov)

    # --- Export / Integration -----------------------------------------------

    def do_export_graphml(self, arg: str) -> None:
        """export_graphml <path>   Export interaction graph as GraphML for Gephi."""
        path = arg.strip()
        if not path:
            print("Usage: export_graphml <path>")
            return
        edges = build_edge_graph(self._active_entries())
        if not edges:
            print("(no edges to export)")
            return
        export_graphml(edges, path)

    def do_merge(self, arg: str) -> None:
        """merge <file1> <file2> ... <output>   Merge multiple log files chronologically."""
        parts = self._split(arg)
        if len(parts) < 3:
            print("Usage: merge <file1> <file2> ... <output>")
            return
        merge_logs(parts[:-1], parts[-1])

    def do_sample(self, arg: str) -> None:
        """sample <N>   Random sample of N entries."""
        parts = self._split(arg)
        if not parts or not parts[0].isdigit():
            print("Usage: sample <N>")
            return
        n = int(parts[0])
        sampled = random_sample(self._active_entries(), n)
        print(f"\nRandom sample ({n} of {len(self._active_entries())} entries):")
        for i, e in enumerate(sampled, 1):
            print(f"  [{i}] {_fmt_dt(e.ts)}  {e.user or '?':>15s}  {e.raw[:200]}")

    # --- Operational --------------------------------------------------------

    def do_last_seen(self, arg: str) -> None:
        """last_seen [user]   When was each user (or specific user) last active."""
        user = arg.strip() or None
        last_seen(self._active_entries(), user)

    def do_whois(self, arg: str) -> None:
        """whois <user>   One-command dump: profile + sentiment + anomalies + edges."""
        user = self._resolve_user(arg)
        if not user:
            return
        whois(self._active_entries(), user)

    def do_diff_time(self, arg: str) -> None:
        """diff_time <since> <until>   Compare activity in two equal time periods."""
        parts = self._split(arg)
        if len(parts) < 2:
            print("Usage: diff_time <since> <until>")
            return
        diff_time(self._active_entries(), parts[0], parts[1])

    def do_top_words(self, arg: str) -> None:
        """top_words [N]   Top N words/tokens across all log text."""
        n = int(arg.strip()) if arg.strip().isdigit() else 50
        top_words(self._active_entries(), n)

    # --- tab completion ------------------------------------------------------

    def complete_user(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_analyze(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_ask(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_compare(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_interact(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_show(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_info(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_dist(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_zscores(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_bursts(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_threads(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())

    def complete_flagged(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) >= 2:
            return self._complete_prefix(text, self._nicks())
        return []

    def complete_target(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._targets())

    def complete_load(self, text, line, begidx, endidx):
        return self._complete_path(text)

    def complete_diff(self, text, line, begidx, endidx):
        return self._complete_path(text)

    def complete_script(self, text, line, begidx, endidx):
        return self._complete_path(text)

    def complete_config(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["view", "set", "reset", "llm", "display", "filters", "system"])
        if prev[1] == "set":
            if len(prev) == 2:
                return self._complete_prefix(text, ["top", "llm_url", "llm_model",
                                                     "max_chunk_chars", "llm_cache",
                                                     "pager", "color", "webhook_url",
                                                     "webhook_type", "plugin_dir"])
            return []
        if prev[1] == "reset":
            if len(prev) == 2:
                return self._complete_prefix(text, ["top", "llm_url", "llm_model",
                                                     "max_chunk_chars", "llm_cache",
                                                     "pager", "color", "webhook_url",
                                                     "webhook_type", "plugin_dir",
                                                     "focused_user", "focused_target",
                                                     "since", "until"])
            return []
        return []

    def complete_view(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["save", "load", "drop", "show", "list"])
        if len(prev) == 2 and prev[1] in ("load", "drop", "show"):
            return self._complete_prefix(text, list(self.state.views))
        return []

    def complete_export(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["profile", "report", "edges"])
        if len(prev) == 2 and prev[1] == "profile":
            return self._complete_prefix(text, self._nicks())
        return self._complete_path(text)

    def complete_set(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["top", "llm_url", "llm_model",
                                                "max_chunk_chars", "llm_cache",
                                                "pager", "color"])
        return []

    def complete_alias(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, list(self.state.aliases))
        return []

    def complete_ignore(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["add", "drop", "list"] + self._nicks())
        if len(prev) >= 2 and prev[1] == "drop":
            return self._complete_prefix(text, sorted(self.state.ignore_set))
        return self._complete_prefix(text, self._nicks())

    def complete_note(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, self._nicks())
        return []

    def complete_watch(self, text, line, begidx, endidx):
        return self._complete_prefix(text, ["--bg", "--stop"])

    # --- new completions ----------------------------------------------------
    def complete_sessions(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_sentiment(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_topics(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_anomalies(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_lifecycle(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_pattern(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_timeline(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_heatmap(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_llm_explain(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_summarize(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_multi(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["add", "list", "clear", "report"])
        if len(prev) == 2 and prev[1] == "add":
            return self._complete_prefix(text, self._nicks())
        return []
    def complete_web(self, text, line, begidx, endidx):
        return self._complete_prefix(text, ["start", "stop", "status"])
    def complete_webportal(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["start", "stop", "status"])
        return []
    def complete_webhook(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["set", "test", "clear"])
        return []
    def complete_plugin(self, text, line, begidx, endidx):
        return self._complete_prefix(text, ["load", "list", "reload"])
    def complete_rules(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["add", "remove", "toggle"])
        return []
    def complete_export_html(self, text, line, begidx, endidx):
        return self._complete_path(text)
    def complete_export_sql(self, text, line, begidx, endidx):
        return self._complete_path(text)
    # completions for 10 new features
    def complete_templates(self, text, line, begidx, endidx):
        return []
    def complete_changepoints(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_rootcause(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_forecast(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_multifactor(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_chart(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["timeline", "histogram", "network"])
        return self._complete_path(text)
    def complete_dataframe(self, text, line, begidx, endidx):
        return []
    def complete_recurrence(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_churn(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_pareto(self, text, line, begidx, endidx):
        return self._complete_prefix(text, ["users", "events", "targets", "levels"])
    # completions for dashboard + 12 new features
    def complete_dashboard(self, text, line, begidx, endidx):
        return []
    def complete_watch_alert(self, text, line, begidx, endidx):
        return []
    def complete_forecast_anomaly(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_alert_fatigue(self, text, line, begidx, endidx):
        return []
    def complete_export_html_drilldown(self, text, line, begidx, endidx):
        return self._complete_path(text)
    def complete_session_times(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_influence(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_template_filter(self, text, line, begidx, endidx):
        return []
    def complete_drift(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_save_profile(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, self._nicks())
        return self._complete_path(text)
    def complete_load_profile(self, text, line, begidx, endidx):
        return self._complete_path(text)
    def complete_compare_profiles(self, text, line, begidx, endidx):
        return self._complete_path(text)
    def complete_auto_tag(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_auto_tag_bulk(self, text, line, begidx, endidx):
        return []
    def complete_recurrence_breach(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_save_config(self, text, line, begidx, endidx):
        return []
    def complete_load_config(self, text, line, begidx, endidx):
        return []
    # completions for forensic commands
    def complete_entities(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_gaps(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, self._nicks())
        return []
    def complete_reconstruct(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, self._nicks() + ["--entities"])
        return self._complete_prefix(text, ["--entities"])
    def complete_forensic_report(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_timeline_narrative(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_evidence(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_tamper_detect(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, self._nicks() + ["--strict"])
        return []
    def complete_llm_search(self, text, line, begidx, endidx):
        return []
    def complete_llm_threat(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_llm_bot(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_llm_profile(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_llm_insider(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_llm_social(self, text, line, begidx, endidx):
        return []
    def complete_llm_incident(self, text, line, begidx, endidx):
        return []
    def complete_llm_topics(self, text, line, begidx, endidx):
        return []
    def complete_llm_sessions(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_llm_baseline(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_llm_summary(self, text, line, begidx, endidx):
        return []
    def complete_llm_replay(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_llm_predict(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_llm_motive(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_llm_relationship(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_llm_audit(self, text, line, begidx, endidx):
        return []
    def complete_llm_risk(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_stats(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_frequency(self, text, line, begidx, endidx):
        return []
    def complete_cooccurrence(self, text, line, begidx, endidx):
        return []
    def complete_heatmap_user(self, text, line, begidx, endidx):
        return []
    def complete_coverage(self, text, line, begidx, endidx):
        return []
    def complete_export_graphml(self, text, line, begidx, endidx):
        return self._complete_path(text)
    def complete_merge(self, text, line, begidx, endidx):
        return self._complete_path(text)
    def complete_sample(self, text, line, begidx, endidx):
        return []
    def complete_last_seen(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_whois(self, text, line, begidx, endidx):
        return self._complete_prefix(text, self._nicks())
    def complete_diff_time(self, text, line, begidx, endidx):
        return []
    def complete_top_words(self, text, line, begidx, endidx):
        return []

    def complete_future_diag(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        return self._complete_prefix(text, self._nicks() + ["--lookback", "--forecast", "--auto-case", "--json"])

    def complete_case(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, [
                "create", "list", "show", "add", "add-from", "status",
                "tag", "untag", "assign", "rm-finding", "delete",
                "export", "search", "stats",
            ])
        sub = prev[1]
        if sub in ("show", "status", "tag", "untag", "assign", "delete", "export", "rm-finding"):
            if len(prev) == 2 or (sub == "rm-finding" and len(prev) == 2):
                return self._complete_prefix(text, list(self.state.case_store.cases.keys()))
        if sub == "status" and len(prev) == 3:
            return self._complete_prefix(text, ["open", "investigating", "resolved", "closed", "false-positive"])
        if sub == "create" and len(prev) == 2:
            return self._complete_prefix(text, ["--desc", "--priority", "--tag", "--assign"])
        if sub == "list" and len(prev) == 2:
            return self._complete_prefix(text, ["--status", "--tag"])
        if sub == "add" and len(prev) >= 2:
            return self._complete_prefix(text, ["--user", "--evidence", "--category", "--severity", "--note", "--entry"])
        if sub == "add-from" and len(prev) >= 2:
            return self._complete_prefix(text, ["--grep", "--flagged", "--user", "--category", "--severity"])
        return []

    def complete_preset(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["list", "save", "load", "delete", "show", "apply"])
        sub = prev[1]
        if sub in ("load", "delete", "show", "apply"):
            return self._complete_prefix(text, list(self.state.presets.keys()))
        if sub == "save" and len(prev) == 2:
            return []
        return []

    def complete_macro(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, ["record", "stop", "play", "list", "delete", "show"])
        sub = prev[1]
        if sub in ("play", "delete", "show"):
            macro_path = os.path.join(_config_dir(), "macros.json")
            macros = _load_json(macro_path, {})
            return self._complete_prefix(text, list(macros.keys()))
        return []

    def complete_timing(self, text, line, begidx, endidx):
        return self._complete_prefix(text, ["on", "off"])

    def complete_debug(self, text, line, begidx, endidx):
        return self._complete_prefix(text, ["on", "off"])

    def complete_quiet(self, text, line, begidx, endidx):
        return self._complete_prefix(text, ["on", "off"])

    def complete_reset(self, text, line, begidx, endidx):
        return self._complete_prefix(text, ["all", "filters", "settings", "aliases", "notes", "ignore"])

    def complete_set_default(self, text, line, begidx, endidx):
        prev = line[:begidx].split()
        if len(prev) <= 1:
            return self._complete_prefix(text, [
                "z_threshold", "anomaly_window", "forecast_days", "burst_window",
                "burst_z", "session_gap", "response_window", "score_flag_threshold",
                "output_format", "max_output_lines",
            ])
        if len(prev) == 2:
            key = prev[1]
            if key == "output_format":
                return self._complete_prefix(text, ["table", "json", "plain"])
            if key in ("z_threshold", "burst_z", "score_flag_threshold"):
                return self._complete_prefix(text, ["1.0", "1.5", "2.0", "2.5", "3.0", "3.5", "4.0"])
        return []

    def complete_show_defaults(self, text, line, begidx, endidx):
        return []

    def complete_env(self, text, line, begidx, endidx):
        return []

    def complete_memory(self, text, line, begidx, endidx):
        return []

    def complete_benchmark(self, text, line, begidx, endidx):
        return self._complete_prefix(text, ["100", "500", "1000", "5000", "10000"])

    def complete_export_config(self, text, line, begidx, endidx):
        return []

    def complete_import_config(self, text, line, begidx, endidx):
        return []


# ---------- Future Diagnostics ------------------------------------------------

@dataclass
class EarlyWarning:
    indicator: str
    current_value: float
    threshold: float
    projected_breach: str | None
    confidence: float
    trend: str
    severity: str
    recommendation: str

@dataclass
class HealthMetric:
    name: str
    current: float
    baseline: float
    trend: str
    trajectory_7d: float
    trajectory_30d: float
    status: str
    details: str

@dataclass
class DegradationSignal:
    metric: str
    user: str | None
    started: datetime | None
    rate_per_day: float
    current_level: float
    critical_level: float
    eta_days: float | None
    severity: str

@dataclass
class RiskTrajectory:
    user: str | None
    current_risk: float
    risk_7d: float
    risk_30d: float
    direction: str
    acceleration: float
    drivers: list[str]

@dataclass
class ScenarioResult:
    name: str
    description: str
    probability: float
    impact: str
    indicators: list[str]
    mitigation: str

@dataclass
class FutureDiagnostic:
    timestamp: str
    health_metrics: list[HealthMetric]
    early_warnings: list[EarlyWarning]
    degradations: list[DegradationSignal]
    risk_trajectories: list[RiskTrajectory]
    scenarios: list[ScenarioResult]
    overall_health: str
    overall_risk_trend: str
    summary: str

def _linear_forecast(values: list[float], days_ahead: int) -> tuple[float, float]:
    if len(values) < 3:
        return (values[-1] if values else 0.0, 0.0)
    n = len(values)
    xs = list(range(n))
    mean_x = statistics.mean(xs)
    mean_y = statistics.mean(values)
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, values))
    den = sum((x - mean_x) ** 2 for x in xs) or 1
    slope = num / den
    intercept = mean_y - slope * mean_x
    forecast = intercept + slope * (n + days_ahead - 1)
    return (forecast, slope)

def _trend_label(slope: float, threshold: float = 0.01) -> str:
    if slope > threshold:
        return "increasing"
    if slope < -threshold:
        return "decreasing"
    return "stable"

def _direction_label(slope: float, threshold: float = 0.01) -> str:
    if slope > threshold:
        return "worsening"
    if slope < -threshold:
        return "improving"
    return "steady"

def _eta_days(current: float, critical: float, slope: float) -> float | None:
    if slope == 0:
        return None
    remaining = abs(critical - current)
    if (critical > current and slope < 0) or (critical < current and slope > 0):
        return None
    days = remaining / abs(slope)
    return max(0, days)

def compute_future_diagnostics(entries: list[Entry], days_lookback: int = 14,
                               days_forecast: int = 30) -> FutureDiagnostic:
    ts_entries = sorted([e for e in entries if e.ts], key=lambda e: e.ts)
    if not ts_entries:
        return FutureDiagnostic(
            timestamp=datetime.now().isoformat(), health_metrics=[], early_warnings=[],
            degradations=[], risk_trajectories=[], scenarios=[],
            overall_health="unknown", overall_risk_trend="unknown",
            summary="No timestamped data available for diagnostics.",
        )
    now = ts_entries[-1].ts
    lookback_start = now - timedelta(days=days_lookback)
    recent = [e for e in ts_entries if e.ts >= lookback_start]
    health_metrics: list[HealthMetric] = []
    early_warnings: list[EarlyWarning] = []
    degradations: list[DegradationSignal] = []
    risk_trajectories: list[RiskTrajectory] = []
    scenarios: list[ScenarioResult] = []

    # 1. Activity volume health
    by_day: dict[str, int] = {}
    for e in ts_entries:
        d = e.ts.date().isoformat()
        by_day[d] = by_day.get(d, 0) + 1
    dates = sorted(by_day.keys())
    daily_counts = [by_day[d] for d in dates]
    if len(daily_counts) >= 3:
        recent_counts = daily_counts[-min(len(daily_counts), days_lookback):]
        baseline = statistics.mean(daily_counts) if daily_counts else 0
        current = statistics.mean(recent_counts) if recent_counts else 0
        fc_7, sl_7 = _linear_forecast(recent_counts, 7)
        fc_30, sl_30 = _linear_forecast(recent_counts, 30)
        trend = _trend_label(sl_7)
        if current > baseline * 1.5:
            status = "elevated"
        elif current < baseline * 0.5:
            status = "low"
        else:
            status = "normal"
        health_metrics.append(HealthMetric(
            name="activity_volume", current=current, baseline=baseline,
            trend=trend, trajectory_7d=fc_7, trajectory_30d=fc_30,
            status=status,
            details=f"Daily avg: {current:.0f} (baseline {baseline:.0f}), 7d forecast: {fc_7:.0f}",
        ))
        if sl_7 < 0 and current < baseline * 0.7:
            eta = _eta_days(current, baseline * 0.2, sl_7)
            early_warnings.append(EarlyWarning(
                indicator="activity_decline", current_value=current,
                threshold=baseline * 0.2,
                projected_breach=f"{eta:.0f}d" if eta else "uncertain",
                confidence=min(0.95, 0.5 + abs(sl_7) * 2),
                trend="decreasing", severity="medium" if eta and eta > 7 else "high",
                recommendation="Investigate cause of declining activity; check for outages or user churn.",
            ))

    # 2. Error rate health
    error_by_day: dict[str, int] = {}
    total_by_day_err: dict[str, int] = {}
    for e in ts_entries:
        d = e.ts.date().isoformat()
        total_by_day_err[d] = total_by_day_err.get(d, 0) + 1
        if e.level and e.level.upper() in {"ERROR", "CRITICAL", "FATAL", "HIGH", "SUS"} \
                or ERROR_TOKENS.search(e.text or ""):
            error_by_day[d] = error_by_day.get(d, 0) + 1
    err_rates = [error_by_day.get(d, 0) / max(total_by_day_err.get(d, 1), 1) for d in dates if d in total_by_day_err]
    if len(err_rates) >= 3:
        recent_err = err_rates[-min(len(err_rates), days_lookback):]
        baseline_err = statistics.mean(err_rates)
        current_err = statistics.mean(recent_err) if recent_err else 0
        fc_7e, sl_7e = _linear_forecast(recent_err, 7)
        fc_30e, sl_30e = _linear_forecast(recent_err, 30)
        trend_e = _trend_label(sl_7e)
        status_e = "critical" if current_err > 0.3 else "warning" if current_err > 0.1 else "normal"
        health_metrics.append(HealthMetric(
            name="error_rate", current=current_err, baseline=baseline_err,
            trend=trend_e, trajectory_7d=fc_7e, trajectory_30d=fc_30e,
            status=status_e,
            details=f"Error rate: {current_err:.1%} (baseline {baseline_err:.1%}), 7d forecast: {fc_7e:.1%}",
        ))
        if sl_7e > 0.005:
            eta_e = _eta_days(current_err, 0.5, sl_7e)
            early_warnings.append(EarlyWarning(
                indicator="error_rate_rising", current_value=current_err,
                threshold=0.5,
                projected_breach=f"{eta_e:.0f}d" if eta_e else "uncertain",
                confidence=min(0.9, 0.4 + sl_7e * 10),
                trend="increasing", severity="high",
                recommendation="Error rate is climbing; review recent changes and error patterns.",
            ))

    # 3. User engagement degradation
    active_users_by_day: dict[str, set[str]] = {}
    for e in ts_entries:
        if e.user and e.ts:
            d = e.ts.date().isoformat()
            active_users_by_day.setdefault(d, set()).add(e.user)
    user_counts = [len(u) for u in [active_users_by_day.get(d, set()) for d in dates]]
    if len(user_counts) >= 3:
        recent_uc = user_counts[-min(len(user_counts), days_lookback):]
        baseline_uc = statistics.mean(user_counts)
        current_uc = statistics.mean(recent_uc) if recent_uc else 0
        fc_7u, sl_7u = _linear_forecast(recent_uc, 7)
        fc_30u, sl_30u = _linear_forecast(recent_uc, 30)
        health_metrics.append(HealthMetric(
            name="active_users", current=current_uc, baseline=baseline_uc,
            trend=_trend_label(sl_7u), trajectory_7d=fc_7u, trajectory_30d=fc_30u,
            status="declining" if current_uc < baseline_uc * 0.7 else "normal",
            details=f"Active users/day: {current_uc:.0f} (baseline {baseline_uc:.0f}), 7d: {fc_7u:.0f}",
        ))
        if sl_7u < -0.1:
            eta_u = _eta_days(current_uc, 1, sl_7u)
            degradations.append(DegradationSignal(
                metric="active_users", user=None,
                started=None, rate_per_day=sl_7u,
                current_level=current_uc, critical_level=1,
                eta_days=eta_u,
                severity="high" if eta_u and eta_u < 14 else "medium",
            ))

    # 4. Per-user risk trajectories
    users = sorted({e.user for e in entries if e.user})
    for user in users[:50]:
        user_entries = [e for e in entries if line_matches_user(e, user) and e.ts]
        if len(user_entries) < 5:
            continue
        profile = build_profile(user_entries, user)
        sentiment = user_sentiment(user_entries, user)
        anomalies = detect_anomalies(user_entries, user)
        churn = predict_churn(user_entries, user)
        risk_score = 0.0
        drivers: list[str] = []
        if sentiment and sentiment.get("mean_compound", 0) < -0.1:
            risk_score += 0.25
            drivers.append(f"negative sentiment ({sentiment['mean_compound']:.2f})")
        if len(anomalies) > 3:
            risk_score += 0.25
            drivers.append(f"{len(anomalies)} anomalies detected")
        if churn.risk_score > 0.5:
            risk_score += 0.25
            drivers.append(f"churn risk {churn.risk_score:.2f}")
        sm = profile.get("score_means", {})
        high_scores = sum(1 for v in sm.values() if isinstance(v, float) and v > 0.8)
        if high_scores > 0:
            risk_score += 0.25
            drivers.append(f"{high_scores} high score(s)")
        risk_score = min(1.0, risk_score)
        user_days: dict[str, int] = {}
        for e in user_entries:
            if e.ts:
                d = e.ts.date().isoformat()
                user_days[d] = user_days.get(d, 0) + 1
        u_dates = sorted(user_days.keys())
        u_risk_series: list[float] = []
        for d in u_dates:
            day_entries = [e for e in user_entries if e.ts and e.ts.date().isoformat() == d]
            day_sent = user_sentiment(day_entries, user)
            day_anom = len(detect_anomalies(day_entries, user))
            r = 0.0
            if day_sent and day_sent.get("mean_compound", 0) < -0.1:
                r += 0.3
            if day_anom > 0:
                r += 0.3 * min(1, day_anom / 3)
            u_risk_series.append(min(1.0, r))
        if len(u_risk_series) >= 3:
            fc_7r, sl_7r = _linear_forecast(u_risk_series, 7)
            fc_30r, sl_30r = _linear_forecast(u_risk_series, 30)
            risk_trajectories.append(RiskTrajectory(
                user=user, current_risk=risk_score,
                risk_7d=min(1.0, max(0.0, fc_7r)),
                risk_30d=min(1.0, max(0.0, fc_30r)),
                direction=_direction_label(sl_7r),
                acceleration=sl_7r,
                drivers=drivers,
            ))

    # 5. Scenario generation
    if err_rates and len(err_rates) >= 3:
        recent_err_mean = statistics.mean(err_rates[-min(len(err_rates), 7):])
        if recent_err_mean > 0.15:
            scenarios.append(ScenarioResult(
                name="error_cascade", description="Error rate triggers cascading failures",
                probability=min(0.8, recent_err_mean * 2), impact="high",
                indicators=["rising error rate", "increasing anomaly count"],
                mitigation="Implement circuit breakers; review error root causes.",
            ))
    if user_counts and len(user_counts) >= 3:
        recent_uc_mean = statistics.mean(user_counts[-min(len(user_counts), 7):])
        baseline_uc_mean = statistics.mean(user_counts)
        if recent_uc_mean < baseline_uc_mean * 0.6:
            scenarios.append(ScenarioResult(
                name="mass_exodus", description="Significant user base decline",
                probability=min(0.7, (1 - recent_uc_mean / max(baseline_uc_mean, 1)) * 1.5),
                impact="critical",
                indicators=["declining active users", "negative sentiment trend"],
                mitigation="Engage at-risk users; investigate platform issues.",
            ))
    high_risk_users = [rt for rt in risk_trajectories if rt.current_risk > 0.5 and rt.direction == "worsening"]
    if high_risk_users:
        scenarios.append(ScenarioResult(
            name="insider_escalation",
            description=f"{len(high_risk_users)} user(s) show escalating risk profiles",
            probability=min(0.6, len(high_risk_users) * 0.15),
            impact="high",
            indicators=[f"{rt.user}: risk {rt.current_risk:.2f} ({rt.direction})" for rt in high_risk_users[:5]],
            mitigation="Review high-risk user activity; apply additional monitoring.",
        ))

    # 6. Overall assessment
    critical_health = [m for m in health_metrics if m.status in ("critical", "elevated")]
    high_warnings = [w for w in early_warnings if w.severity == "high"]
    severe_degradations = [d for d in degradations if d.severity == "high"]
    worsening_risks = [r for r in risk_trajectories if r.direction == "worsening" and r.current_risk > 0.3]
    if critical_health or len(high_warnings) >= 2:
        overall_health = "critical"
    elif len(high_warnings) == 1 or len(severe_degradations) > 0:
        overall_health = "degraded"
    elif len(early_warnings) > 0:
        overall_health = "warning"
    else:
        overall_health = "healthy"
    if worsening_risks:
        overall_risk_trend = "escalating"
    elif all(r.direction == "improving" for r in risk_trajectories if r.user):
        overall_risk_trend = "improving"
    else:
        overall_risk_trend = "stable"
    summary_parts: list[str] = []
    summary_parts.append(f"Overall health: {overall_health}. ")
    if early_warnings:
        summary_parts.append(f"{len(early_warnings)} early warning(s): ")
        summary_parts.append(", ".join(w.indicator for w in early_warnings[:3]))
        summary_parts.append(". ")
    if degradations:
        summary_parts.append(f"{len(degradations)} degradation signal(s) detected. ")
    if high_risk_users:
        summary_parts.append(f"{len(high_risk_users)} user(s) with worsening risk. ")
    if not summary_parts[1:]:
        summary_parts.append("No significant concerns detected.")
    return FutureDiagnostic(
        timestamp=datetime.now().isoformat(),
        health_metrics=health_metrics,
        early_warnings=early_warnings,
        degradations=degradations,
        risk_trajectories=risk_trajectories,
        scenarios=scenarios,
        overall_health=overall_health,
        overall_risk_trend=overall_risk_trend,
        summary="".join(summary_parts),
    )

def print_future_diagnostics(diag: FutureDiagnostic, top_users: int = 15) -> None:
    health_icon = {"critical": "🔴", "degraded": "🟠", "warning": "🟡", "healthy": "🟢", "unknown": "⚪"}
    trend_icon = {"escalating": "📈", "improving": "📉", "stable": "➡️", "unknown": "❓"}
    print(f"\n{'='*70}")
    print(f"FUTURE DIAGNOSTICS REPORT")
    print(f"{'='*70}")
    print(f"  Generated:        {diag.timestamp}")
    print(f"  Overall health:   {health_icon.get(diag.overall_health, '?')} {diag.overall_health}")
    print(f"  Risk trend:       {trend_icon.get(diag.overall_risk_trend, '?')} {diag.overall_risk_trend}")
    print(f"\n  {diag.summary}")
    print(f"{'='*70}")

    if diag.health_metrics:
        print(f"\n  HEALTH METRICS:")
        print(f"  {'Metric':<20s} {'Current':>10s} {'Baseline':>10s} {'Trend':<12s} {'7d Forecast':>12s} {'30d Forecast':>12s} {'Status':<10s}")
        print(f"  {'-'*20} {'-'*10} {'-'*10} {'-'*12} {'-'*12} {'-'*12} {'-'*10}")
        for m in diag.health_metrics:
            print(f"  {m.name:<20s} {m.current:>10.2f} {m.baseline:>10.2f} {m.trend:<12s} {m.trajectory_7d:>12.2f} {m.trajectory_30d:>12.2f} {m.status:<10s}")
            print(f"    {m.details}")

    if diag.early_warnings:
        print(f"\n  EARLY WARNINGS ({len(diag.early_warnings)}):")
        for w in diag.early_warnings:
            sev = {"high": "🔴", "medium": "🟡", "low": "🔵"}.get(w.severity, "•")
            print(f"  {sev} [{w.severity:>6s}] {w.indicator}")
            print(f"       Current: {w.current_value:.2f}  Threshold: {w.threshold:.2f}  Breach ETA: {w.projected_breach}")
            print(f"       Confidence: {w.confidence:.0%}  Trend: {w.trend}")
            print(f"       → {w.recommendation}")

    if diag.degradations:
        print(f"\n  DEGRADATION SIGNALS ({len(diag.degradations)}):")
        for d in diag.degradations:
            eta_str = f"{d.eta_days:.0f}d" if d.eta_days else "N/A"
            print(f"  {'🟠' if d.severity == 'high' else '🟡'} [{d.severity:>6s}] {d.metric} (user={d.user or 'all'})")
            print(f"       Rate: {d.rate_per_day:+.3f}/day  Current: {d.current_level:.1f}  Critical: {d.critical_level:.1f}  ETA: {eta_str}")

    if diag.risk_trajectories:
        worsening = [r for r in diag.risk_trajectories if r.direction == "worsening"]
        print(f"\n  RISK TRAJECTORIES ({len(diag.risk_trajectories)} users, {len(worsening)} worsening):")
        print(f"  {'User':<20s} {'Current':>8s} {'7d Risk':>8s} {'30d Risk':>8s} {'Direction':<12s} {'Acceleration':>14s}")
        print(f"  {'-'*20} {'-'*8} {'-'*8} {'-'*8} {'-'*12} {'-'*14}")
        sorted_rt = sorted(diag.risk_trajectories, key=lambda r: -r.current_risk)
        for r in sorted_rt[:top_users]:
            print(f"  {r.user:<20s} {r.current_risk:>8.2f} {r.risk_7d:>8.2f} {r.risk_30d:>8.2f} {r.direction:<12s} {r.acceleration:>+.4f}")
            if r.drivers:
                print(f"    Drivers: {', '.join(r.drivers[:3])}")

    if diag.scenarios:
        print(f"\n  PREDICTED SCENARIOS ({len(diag.scenarios)}):")
        for s in diag.scenarios:
            prob_bar = "█" * int(s.probability * 20)
            print(f"  ⚠ {s.name} (P={s.probability:.0%} {prob_bar})")
            print(f"    Impact: {s.impact}  Description: {s.description}")
            print(f"    Indicators: {', '.join(s.indicators[:3])}")
            print(f"    Mitigation: {s.mitigation}")

    print(f"\n{'='*70}")


# ---------- Case Management ---------------------------------------------------

@dataclass
class CaseFinding:
    id: str
    entry_id: int | None
    user: str | None
    evidence_text: str
    category: str
    severity: str
    note: str
    ts_added: str

@dataclass
class Case:
    id: str
    name: str
    description: str
    status: str
    priority: str
    created: str
    updated: str
    tags: list[str]
    findings: list[CaseFinding]
    assigned_to: str = ""

class CaseStore:
    def __init__(self, path: str | None = None) -> None:
        self.path = path or os.path.join(_config_dir(), "cases.json")
        self.cases: dict[str, Case] = {}
        self._counter = 0
        self._load()

    def _next_id(self) -> str:
        self._counter += 1
        return f"CASE-{self._counter:04d}"

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._counter = data.get("_counter", 0)
                for cid, cdata in data.get("cases", {}).items():
                    findings = [CaseFinding(**fd) for fd in cdata.get("findings", [])]
                    self.cases[cid] = Case(
                        id=cid, name=cdata["name"], description=cdata.get("description", ""),
                        status=cdata.get("status", "open"), priority=cdata.get("priority", "medium"),
                        created=cdata.get("created", ""), updated=cdata.get("updated", ""),
                        tags=cdata.get("tags", []), findings=findings,
                        assigned_to=cdata.get("assigned_to", ""),
                    )
        except (OSError, json.JSONDecodeError, KeyError):
            pass

    def _save(self) -> None:
        try:
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            data: dict[str, Any] = {"_counter": self._counter, "cases": {}}
            for cid, c in self.cases.items():
                data["cases"][cid] = {
                    "name": c.name, "description": c.description, "status": c.status,
                    "priority": c.priority, "created": c.created, "updated": c.updated,
                    "tags": c.tags, "assigned_to": c.assigned_to,
                    "findings": [
                        {"id": f.id, "entry_id": f.entry_id, "user": f.user,
                         "evidence_text": f.evidence_text, "category": f.category,
                         "severity": f.severity, "note": f.note, "ts_added": f.ts_added}
                        for f in c.findings
                    ],
                }
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            os.replace(tmp, self.path)
        except OSError as exc:
            print(f"Case store save failed: {exc}", file=sys.stderr)

    def create(self, name: str, description: str = "", priority: str = "medium",
               tags: list[str] | None = None, assigned_to: str = "") -> Case:
        cid = self._next_id()
        now = datetime.now().isoformat()
        case = Case(id=cid, name=name, description=description, status="open",
                    priority=priority, created=now, updated=now,
                    tags=tags or [], findings=[], assigned_to=assigned_to)
        self.cases[cid] = case
        self._save()
        return case

    def get(self, case_id: str) -> Case | None:
        return self.cases.get(case_id)

    def list_cases(self, status: str | None = None, tag: str | None = None) -> list[Case]:
        result = list(self.cases.values())
        if status:
            result = [c for c in result if c.status == status]
        if tag:
            result = [c for c in result if tag.lower() in [t.lower() for t in c.tags]]
        return sorted(result, key=lambda c: c.updated, reverse=True)

    def update_status(self, case_id: str, status: str) -> bool:
        c = self.cases.get(case_id)
        if not c:
            return False
        c.status = status
        c.updated = datetime.now().isoformat()
        self._save()
        return True

    def add_finding(self, case_id: str, entry_id: int | None = None, user: str | None = None,
                    evidence_text: str = "", category: str = "other", severity: str = "medium",
                    note: str = "") -> CaseFinding | None:
        c = self.cases.get(case_id)
        if not c:
            return None
        fid = f"{case_id}-F{len(c.findings) + 1:03d}"
        finding = CaseFinding(id=fid, entry_id=entry_id, user=user, evidence_text=evidence_text,
                              category=category, severity=severity, note=note,
                              ts_added=datetime.now().isoformat())
        c.findings.append(finding)
        c.updated = datetime.now().isoformat()
        self._save()
        return finding

    def remove_finding(self, case_id: str, finding_id: str) -> bool:
        c = self.cases.get(case_id)
        if not c:
            return False
        before = len(c.findings)
        c.findings = [f for f in c.findings if f.id != finding_id]
        if len(c.findings) < before:
            c.updated = datetime.now().isoformat()
            self._save()
            return True
        return False

    def delete(self, case_id: str) -> bool:
        if case_id in self.cases:
            del self.cases[case_id]
            self._save()
            return True
        return False

    def search(self, query: str) -> list[tuple[Case, CaseFinding | None]]:
        q = query.lower()
        results: list[tuple[Case, CaseFinding | None]] = []
        for c in self.cases.values():
            if q in c.name.lower() or q in c.description.lower() or q in " ".join(c.tags).lower():
                results.append((c, None))
            for f in c.findings:
                if q in f.evidence_text.lower() or q in f.note.lower() or (f.user and q in f.user.lower()):
                    results.append((c, f))
        return results

    def export_report(self, case_id: str) -> str:
        c = self.cases.get(case_id)
        if not c:
            return f"Case {case_id} not found"
        lines = [
            f"{'='*60}",
            f"CASE REPORT: {c.id} — {c.name}",
            f"{'='*60}",
            f"  Status:     {c.status}",
            f"  Priority:   {c.priority}",
            f"  Created:    {c.created}",
            f"  Updated:    {c.updated}",
            f"  Assigned:   {c.assigned_to or '(unassigned)'}",
            f"  Tags:       {', '.join(c.tags) or '(none)'}",
            f"  Findings:   {len(c.findings)}",
            f"",
            f"  Description:",
            f"    {c.description}",
            f"",
        ]
        if c.findings:
            lines.append(f"  Findings:")
            for f in c.findings:
                lines.append(f"    [{f.severity.upper():>8s}] {f.id}  category={f.category}")
                if f.user:
                    lines.append(f"               user={f.user}")
                if f.entry_id is not None:
                    lines.append(f"               entry=#{f.entry_id}")
                if f.evidence_text:
                    lines.append(f"               evidence: {f.evidence_text[:120]}")
                if f.note:
                    lines.append(f"               note: {f.note}")
                lines.append(f"               added: {f.ts_added}")
                lines.append("")
        lines.append(f"{'='*60}")
        return "\n".join(lines)

    def summary_stats(self) -> dict:
        total = len(self.cases)
        by_status: Counter = Counter()
        by_priority: Counter = Counter()
        total_findings = 0
        by_category: Counter = Counter()
        by_severity: Counter = Counter()
        for c in self.cases.values():
            by_status[c.status] += 1
            by_priority[c.priority] += 1
            total_findings += len(c.findings)
            for f in c.findings:
                by_category[f.category] += 1
                by_severity[f.severity] += 1
        return {
            "total_cases": total,
            "total_findings": total_findings,
            "by_status": dict(by_status),
            "by_priority": dict(by_priority),
            "by_category": dict(by_category),
            "by_severity": dict(by_severity),
        }


# ---------- main -------------------------------------------------------------

def _default_llm_cache_path() -> str:
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "analyzelog_llm.json")


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError):
            pass
    _Color.auto_disable()

    p = argparse.ArgumentParser(description="Interactive log analyzer (TUI by default; --batch for one-shot).")
    p.add_argument("--log", default="ai_scores.log")
    p.add_argument("--user")
    p.add_argument("--users", help="Pair 'A,B' for interaction analysis (--batch only)")
    p.add_argument("--compare", help="Comma list 'A,B[,C,...]' for behavior comparison (--batch only)")
    p.add_argument("--top", type=int, default=15)
    p.add_argument("--llm-url", default="http://127.0.0.1:8033/")
    p.add_argument("--llm-model", default="local")
    p.add_argument("--max-chunk-chars", type=int, default=12000)
    p.add_argument("--llm-cache", default=_default_llm_cache_path(),
                   help="Path to LLM response cache JSON ('none' to disable)")
    p.add_argument("--since", help="Time-range lower bound (ISO date or '5h ago')")
    p.add_argument("--until", help="Time-range upper bound (ISO date or '5h ago')")
    p.add_argument("--batch", action="store_true")
    p.add_argument("--no-llm", action="store_true")
    p.add_argument("--show-lines", type=int, default=0)
    p.add_argument("--ask", help="With --batch and --user, ask a free-form question")
    p.add_argument("--flagged", help="With --batch, list lines matching score expression")
    p.add_argument("--dist", action="store_true",
                   help="With --batch, show score distributions (whole log or --user)")
    p.add_argument("--zscores", action="store_true",
                   help="With --batch and --user, show z-scores vs population")
    p.add_argument("--similar", action="store_true")
    p.add_argument("--similar-threshold", type=float, default=0.95)
    p.add_argument("--similar-min-lines", type=int, default=5)
    p.add_argument("--bursts", help="With --batch, detect bursts for the given user")
    p.add_argument("--bursts-window", type=int, default=60)
    p.add_argument("--bursts-z", type=float, default=3.0)
    p.add_argument("--diff", help="With --batch, diff against another log file")
    p.add_argument("--export-profile", help="With --batch and --user, write profile to this path")
    p.add_argument("--export-report", help="With --batch, write report JSON to this path")
    p.add_argument("--export-edges", help="With --batch, write edges (.csv or .dot)")
    p.add_argument("--watch", action="store_true",
                   help="Tail the log file and print new entries; runs forever")
    p.add_argument("-c", "--cmd", action="append", default=[],
                   help="Run TUI command(s) before the prompt (repeatable). Use 'quit' to exit after.")
    p.add_argument("--c", dest="show_commands", action="store_true",
                   help="On startup, open the TUI and print the full command reference.")
    p.add_argument("--prometheus", action="store_true", help="With --batch, print Prometheus metrics")
    p.add_argument("--export-html", help="With --batch, write HTML report to this path")
    p.add_argument("--export-sql", help="With --batch, export entries to SQLite database")
    p.add_argument("--sessions", help="With --batch, detect sessions for the given user")
    p.add_argument("--sessions-gap", type=int, default=30, help="Session gap in minutes")
    p.add_argument("--sentiment", help="With --batch, show sentiment for the given user")
    p.add_argument("--topics", help="With --batch, show topics/keywords for the given user")
    p.add_argument("--lifecycle", help="With --batch, lifecycle analysis for the given user")
    p.add_argument("--pattern", help="With --batch, pattern-of-life for the given user")
    p.add_argument("--anomalies", help="With --batch, detect anomalies for the given user")
    p.add_argument("--anomalies-z", type=float, default=2.5)
    p.add_argument("--sequences", type=int, nargs="?", const=3, default=0,
                   help="With --batch, find common interaction sequences (optional min_support)")
    p.add_argument("--timeline", help="With --batch, ASCII timeline for the given user")
    p.add_argument("--heatmap", help="With --batch, calendar heatmap for the given user")
    p.add_argument("--net", type=int, nargs="?", const=15, default=0,
                   help="With --batch, show network graph (optional top N edges)")
    p.add_argument("--correlate", nargs=2, metavar=("PATH", "WINDOW"),
                   help="With --batch, cross-log correlation: --correlate other.log 60")
    p.add_argument("--auto-report", action="store_true", help="With --batch, LLM-generated narrative report")
    p.add_argument("--web", type=int, nargs="?", const=8088, default=0,
                   help="Start web API server on given port")
    p.add_argument("--plugin-dir", help="Directory to load analysis plugins from")
    p.add_argument("--cron", action="store_true", help="Run in cron mode (batch with optional alerts)")
    p.add_argument("--cron-output", help="Append cron output to this file")
    p.add_argument("--webhook-url", help="Webhook URL for alerts (cron mode)")
    p.add_argument("--templates", type=int, nargs="?", const=20, default=0,
                   help="With --batch, extract log templates (optional N)")
    p.add_argument("--changepoints", help="With --batch, detect change points for the given user")
    p.add_argument("--changepoints-window", type=int, default=3, help="Window in days for change point detection")
    p.add_argument("--rootcause", nargs="+", metavar=("USER [LOOKBACK]"),
                   help="With --batch, find root causes: --rootcause user [lookback_sec]")
    p.add_argument("--forecast", help="With --batch, forecast activity for the given user")
    p.add_argument("--forecast-days", type=int, default=7)
    p.add_argument("--multifactor", help="With --batch, multi-factor anomaly score for the user")
    p.add_argument("--chart", nargs="+", metavar=("TYPE PATH [USER]"),
                   help="With --batch, generate chart: --chart timeline out.png [user]")
    p.add_argument("--dataframe", nargs="?", const="", default=None,
                   help="With --batch, view as DataFrame (optional expression)")
    p.add_argument("--recurrence", help="With --batch, detect recurrence patterns for user")
    p.add_argument("--churn", help="With --batch, predict churn risk for user")
    p.add_argument("--pareto", nargs="?", const="users", default=None,
                   help="With --batch, Pareto analysis (users|events|targets|levels)")
    # Dashboard + 12 new feature CLI flags
    p.add_argument("--dashboard", action="store_true", help="Launch curses real-time dashboard")
    p.add_argument("--forecast-anomaly", nargs=3, metavar=("USER", "Z", "DAYS"),
                   help="Forecast-aware anomaly detection: --forecast-anomaly user 2.5 7")
    p.add_argument("--alert-fatigue", type=int, nargs="?", const=1, default=0,
                   help="With --batch, compute alert fatigue scores (optional window hours)")
    p.add_argument("--export-html-drilldown", nargs="+", metavar=("PATH [USER...]"),
                   help="Write collapsible HTML report: --export-html-drilldown report.html [user]")
    p.add_argument("--session-times", nargs=3, metavar=("A", "B", "GAP"),
                   help="Session-aware response times: --session-times user_a user_b 30")
    p.add_argument("--influence", nargs=3, metavar=("SEED", "HOPS", "WIN"),
                   help="Influence chain tracking: --influence user 3 300")
    p.add_argument("--template-filter", help="Filter current view by template ID")
    p.add_argument("--drift", nargs=4, metavar=("USER", "WA", "WB", "GAP"),
                   help="Drift detection: --drift user 7 7 0")
    p.add_argument("--save-profile", nargs=2, metavar=("USER", "PATH"),
                   help="Save user profile to JSON: --save-profile user path.json")
    p.add_argument("--load-profile", help="Load and display a saved profile")
    p.add_argument("--auto-tag", help="With --batch, auto-tag a user using LLM")
    p.add_argument("--auto-tag-bulk", type=int, nargs="?", const=10, default=0,
                   help="With --batch, auto-tag top N users")
    p.add_argument("--recurrence-breach", nargs="+", metavar=("USER [DAYS]"),
                   help="Check recurrence breach: --recurrence-breach user [3]")
    p.add_argument("--dashboard-alerts", action="store_true",
                   help="Show alert fatigue dashboard summary")
    # Forensic CLI flags
    p.add_argument("--entities", nargs="?", const=True, default=None,
                   help="With --batch, extract forensic entities (optional user)")
    p.add_argument("--gaps", nargs="*", metavar=("[USER] [THRESHOLD_MIN]"),
                   help="With --batch, detect timeline gaps: --gaps [user] [60]")
    p.add_argument("--reconstruct", nargs="?", const=True, default=None,
                   help="With --batch, reconstruct timeline (optional user)")
    p.add_argument("--forensic-report", help="With --batch, generate LLM forensic report for user")
    p.add_argument("--timeline-narrative", help="With --batch, LLM timeline narrative for user")
    p.add_argument("--evidence", help="With --batch, LLM evidence extraction for user")
    # Advanced LLM CLI flags
    p.add_argument("--llm-search", help="With --batch, natural language semantic search query")
    p.add_argument("--llm-threat", help="With --batch, threat assessment for user")
    p.add_argument("--llm-bot", help="With --batch, bot detection for user")
    p.add_argument("--llm-profile", help="With --batch, deep behavioral profile for user")
    p.add_argument("--llm-insider", help="With --batch, insider threat analysis for user")
    p.add_argument("--llm-social", type=int, nargs="?", const=15, default=0,
                   help="With --batch, social dynamics analysis (optional top N users)")
    p.add_argument("--llm-incident", nargs="?", const="", default=None,
                   help="With --batch, incident timeline reconstruction (optional query)")
    p.add_argument("--llm-topics", type=int, nargs="?", const=10, default=0,
                   help="With --batch, topic map analysis (optional top N users)")
    p.add_argument("--llm-sessions", nargs=2, metavar=("USER", "GAP"),
                   help="With --batch, compare sessions: --llm-sessions user 60")
    p.add_argument("--llm-baseline", help="With --batch, behavioral baseline for user")
    p.add_argument("--llm-summary", action="store_true",
                   help="With --batch, LLM summary of entire log")
    p.add_argument("--llm-replay", help="With --batch, LLM chronological replay for user")
    p.add_argument("--llm-predict", help="With --batch, predict behavior for user")
    p.add_argument("--llm-motive", help="With --batch, motivation analysis for user")
    p.add_argument("--llm-relationship", nargs=2, metavar=("A", "B"),
                   help="With --batch, relationship analysis: --llm-relationship userA userB")
    p.add_argument("--llm-audit", nargs="?", const="", default=None,
                   help="With --batch, compliance audit (optional policy focus)")
    p.add_argument("--llm-risk", help="With --batch, risk score for user")
    p.add_argument("--stats", nargs="?", const=True, default=None,
                   help="With --batch, statistical summary (optional user)")
    p.add_argument("--frequency", type=int, nargs="?", const=50, default=0,
                   help="With --batch, word frequency analysis (optional top N)")
    p.add_argument("--cooccurrence", type=int, nargs="?", const=5, default=0,
                   help="With --batch, user co-occurrence (optional window min)")
    p.add_argument("--heatmap-user", type=int, nargs="?", const=20, default=0,
                   help="With --batch, user×hour heatmap (optional top N)")
    p.add_argument("--coverage", action="store_true",
                   help="With --batch, log coverage analysis")
    p.add_argument("--export-graphml", help="With --batch, export graph as GraphML to path")
    p.add_argument("--merge", nargs="+", metavar="PATH",
                   help="With --batch, merge log files: --merge f1.log f2.log out.log")
    p.add_argument("--sample", type=int, help="With --batch, random sample of N entries")
    p.add_argument("--last-seen", nargs="?", const=True, default=None,
                   help="With --batch, last seen times (optional user)")
    p.add_argument("--whois", help="With --batch, one-command user dump")
    p.add_argument("--tamper-detect", nargs="?", const=True, default=None,
                   help="With --batch, detect log tampering (optional user, --strict for stricter checks)")
    p.add_argument("--diff-time", nargs=2, metavar=("SINCE", "UNTIL"),
                   help="With --batch, compare two time periods")
    p.add_argument("--top-words", type=int, nargs="?", const=50, default=0,
                   help="With --batch, top N words across logs")
    p.add_argument("--config", nargs="?", const="view", default=None,
                   help="With --batch, view/set configuration: --config [view|llm|display|filters|system]")
    # Case management CLI flags
    p.add_argument("--case-create", nargs=2, metavar=("NAME", "DESC"),
                   help="Create a new case: --case-create 'Suspicious Activity' 'User X shows anomalies'")
    p.add_argument("--case-list", nargs="?", const=True, default=None,
                   help="List cases (optional status filter: --case-list open)")
    p.add_argument("--case-show", help="Show case details: --case-show CASE-0001")
    p.add_argument("--case-export", nargs=2, metavar=("ID", "PATH"),
                   help="Export case report: --case-export CASE-0001 report.txt")
    p.add_argument("--case-stats", action="store_true",
                   help="With --batch, show case management statistics")
    p.add_argument("--case-search", help="Search cases: --case-search 'suspicious'")
    p.add_argument("--case-status", nargs=2, metavar=("ID", "STATUS"),
                   help="Update case status: --case-status CASE-0001 investigating")
    p.add_argument("--case-delete", help="Delete a case: --case-delete CASE-0001")
    # Future diagnostics CLI flags
    p.add_argument("--future-diag", nargs="?", const=True, default=None,
                   help="With --batch, run predictive diagnostics (optional user)")
    p.add_argument("--diag-lookback", type=int, default=14,
                   help="Days of history for diagnostics (default 14)")
    p.add_argument("--diag-forecast", type=int, default=30,
                   help="Days to forecast forward (default 30)")
    p.add_argument("--diag-auto-case", action="store_true",
                   help="Auto-create case if critical warnings found")
    p.add_argument("--diag-json", action="store_true",
                   help="Output diagnostics as JSON")
    # Advanced settings CLI flags
    p.add_argument("--preset", help="Load a preset configuration by name")
    p.add_argument("--preset-save", nargs="+", metavar="ARG",
                   help="Save current settings as a preset: --preset-save NAME [--desc DESC]")
    p.add_argument("--preset-list", action="store_true",
                   help="List all saved presets")
    p.add_argument("--preset-show", help="Show details of a preset")
    p.add_argument("--preset-delete", help="Delete a preset")
    p.add_argument("--macro-play", help="Play a recorded macro by name")
    p.add_argument("--macro-list", action="store_true",
                   help="List all saved macros")
    p.add_argument("--benchmark", type=int, nargs="?", const=1000, default=0,
                   help="Run performance benchmarks (optional entry count)")
    p.add_argument("--env", action="store_true",
                   help="Show environment and system information")
    p.add_argument("--memory", action="store_true",
                   help="Show memory usage breakdown")
    p.add_argument("--export-config", help="Export all configuration to a JSON file")
    p.add_argument("--import-config", help="Import configuration from a JSON file")
    p.add_argument("--set-default", nargs=2, metavar=("KEY", "VALUE"), action="append",
                   help="Set advanced default parameters (can be repeated)")
    p.add_argument("--show-defaults", action="store_true",
                   help="Display all advanced default parameters")
    p.add_argument("--reset-config", nargs="?", const="all", default=None,
                   help="Reset configuration: --reset-config [all|filters|settings|aliases|notes|ignore]")
    p.add_argument("--timing", action="store_true",
                   help="Enable command timing display")
    p.add_argument("--debug", action="store_true",
                   help="Enable debug mode (verbose error traces)")
    p.add_argument("--quiet", action="store_true",
                   help="Enable quiet mode (suppress non-essential output)")
    args = p.parse_args(argv)

    since = parse_iso_arg(args.since) if args.since else None
    until = parse_iso_arg(args.until) if args.until else None
    if args.since and not since:
        print(f"Could not parse --since {args.since!r}", file=sys.stderr); return 2
    if args.until and not until:
        print(f"Could not parse --until {args.until!r}", file=sys.stderr); return 2

    # PERFORMANCE OPTIMIZATION:
    # If we are doing a focused batch operation on a specific user, we stream the file
    # and only load that user's entries into memory. This allows processing 10GB+ logs.
    is_focused_batch = args.batch and args.user and not any([
        args.export_html, args.export_sql, args.prometheus, args.diff, args.similar
    ])

    if is_focused_batch:
        u = args.user.lower()
        active = []
        try:
            for e in iter_entries(args.log):
                if in_time_range(e.ts, since, until):
                    if e.user and e.user.lower() == u:
                        active.append(e)
            all_entries = active # For focused batch, population == focused set
        except FileNotFoundError:
            print(f"File not found: {args.log}", file=sys.stderr)
            return 1
    else:
        try:
            all_entries = list(iter_entries(args.log))
        except FileNotFoundError:
            print(f"File not found: {args.log}", file=sys.stderr)
            return 1
        active = apply_time_filter(all_entries, since, until)

    cache_path = args.llm_cache
    if cache_path and cache_path.lower() in {"none", "off", ""}:
        cache_path = None
    if cache_path:
        cache_dir = os.path.dirname(cache_path)
        if cache_dir:
            try:
                os.makedirs(cache_dir, exist_ok=True)
            except OSError:
                pass
    cache = LLMCache(cache_path) if cache_path else None

    if args.watch:
        print(f"Watching {args.log}. Ctrl-C to stop.")
        watch_loop(args.log, watch_callback_default)
        return 0

    if args.batch:
        if args.diff:
            try:
                other = list(iter_entries(args.diff))
            except FileNotFoundError:
                print(f"File not found: {args.diff}", file=sys.stderr); return 1
            sa = summarize(active, 1000)
            sb = summarize(other, 1000)
            print_log_diff(args.log, args.diff, diff_summaries(sa, sb))
            return 0

        if args.prometheus:
            print(prometheus_metrics(active))
            return 0

        if args.export_html:
            s = summarize(active, args.top)
            profiles = None
            if args.user:
                profiles = [build_profile(active, args.user)]
            write_html_report(args.export_html, s, profiles)
            return 0

        if args.export_sql:
            print(export_to_sqlite(active, args.export_sql))
            return 0

        if args.sessions:
            sessions = detect_sessions(active, args.sessions, args.sessions_gap)
            for i, s in enumerate(sessions, 1):
                dur = (s.end - s.start).total_seconds()
                dur_s = f"{dur / 60:.0f}min" if dur < 3600 else f"{dur / 3600:.1f}h"
                print(f"#{i:<3d}  {s.start:%Y-%m-%d %H:%M} - {s.end:%H:%M}  {dur_s:>10}  {s.line_count:>4d} lines")
            if not sessions:
                print("(no sessions)")
            return 0

        if args.sentiment:
            s = user_sentiment(active, args.sentiment)
            if s:
                print(f"Sentiment for {args.sentiment}: compound={s['mean_compound']:.3f} pos={s['pos_rate']:.1%} neg={s['neg_rate']:.1%} agree={s['agree_rate']:.1%}")
            else:
                print(f"(no data for {args.sentiment})")
            return 0

        if args.topics:
            t = user_topics(active, args.topics)
            if t.get("keywords"):
                print(f"Keywords for {args.topics}:")
                for kw, n in t["keywords"][:15]:
                    print(f"  {n:>5d}  {kw}")
            return 0

        if args.lifecycle:
            lc = analyze_lifecycle(active, args.lifecycle)
            if lc.first_seen:
                print(f"Lifecycle for {args.lifecycle}: first={_fmt_dt(lc.first_seen)} last={_fmt_dt(lc.last_seen)} trend={lc.activity_trend} stages={len(lc.stages)}")
            return 0

        if args.pattern:
            pol = pattern_of_life(active, args.pattern)
            if pol.hourly_profile:
                glyphs = "▁▂▃▄▅▆▇█"
                vals = [pol.hourly_profile.get(h, 0) for h in range(24)]
                peak_v = max(vals) or 1
                bar = "".join(glyphs[min(int(v / peak_v * 7), 7)] for v in vals)
                print(f"Pattern for {args.pattern}: peak={pol.peak_hour}:00 quiet={pol.quiet_hours} consistency={pol.consistency_score:.2f}")
                print(f"  {bar}  (00..23)")
            return 0

        if args.anomalies:
            anoms = detect_anomalies(active, args.anomalies, args.anomalies_z)
            anoms += detect_behavioral_anomalies(active, args.anomalies, args.anomalies_z)
            # Deduplicate and sort
            seen = set()
            unique = []
            for a in anoms:
                k = (a.metric, a.day, a.hour)
                if k not in seen:
                    seen.add(k)
                    unique.append(a)
            unique.sort(key=lambda x: abs(x.zscore), reverse=True)
            for a in unique:
                print(f"  {a.metric:<20s} z={a.zscore:+.2f} value={a.value:.1f} expected={a.expected:.1f}  {a.day or ''} h{a.hour or ''}")
            if not unique:
                print("(no anomalies)")
            return 0

        if args.sequences:
            seqs = find_common_sequences(active, min_support=args.sequences)
            for s in seqs:
                print(f"  {s.count:>5d}x  {' -> '.join(s.pattern)}")
            if not seqs:
                print("(no sequences)")
            return 0

        if args.timeline:
            print(ascii_timeline(active, args.timeline))
            return 0

        if args.heatmap:
            print(calendar_heatmap(active, args.heatmap))
            return 0

        if args.net:
            edges = build_edge_graph(active)
            print(ascii_network_graph(edges, top_n=args.net))
            return 0

        if args.correlate:
            path, window_str = args.correlate
            try:
                other = list(iter_entries(path))
            except FileNotFoundError:
                print(f"File not found: {path}", file=sys.stderr); return 1
            corr = correlate_logs(active, other, int(window_str))
            for c in corr[:20]:
                print(f"  {c.count:>5d}x  {c.event_a} ~~ {c.event_b}  delay={c.avg_delay_seconds:.0f}s")
            return 0

        if args.auto_report:
            s = summarize(active, args.top)
            counts: Counter = Counter(e.user for e in active if e.user)
            top_users_list = [u for u, _ in counts.most_common(10)]
            profiles_list = [build_profile(active, u) for u in top_users_list]
            llm_auto_report(s, profiles_list, args.llm_url, args.llm_model,
                            args.max_chunk_chars, cache=cache)
            return 0

        if args.cron:
            alert_engine = AlertEngine()
            return cron_mode(active, alert_engine, args.webhook_url, args.cron_output)

        if args.templates:
            templates = extract_log_templates(active, args.templates)
            for template, count, sample in templates:
                print(f"  {count:>5d}x  {template[:160]}")
            return 0

        if args.changepoints:
            cps = detect_change_points(active, args.changepoints, args.changepoints_window)
            for cp in cps:
                dir_ = "UP" if cp.after_val > cp.before_val else "DOWN"
                print(f"  {dir_} {cp.metric} at {cp.at.date()} {cp.before_val:.1f}->{cp.after_val:.1f} effect={cp.effect_size:.2f}")
            if not cps:
                print("(no change points)")
            return 0

        if args.rootcause:
            user = args.rootcause[0]
            lookback = int(args.rootcause[1]) if len(args.rootcause) > 1 else 120
            causes = trace_root_causes(active, user, lookback)
            for rc in causes[:15]:
                print(f"  {rc.occurrences:>4d}x  corr={rc.correlation:.2f}  lag={rc.avg_lag_seconds:.0f}s  {rc.preceding_user:<20s} {rc.preceding_event}")
            if not causes:
                print("(no root causes)")
            return 0

        if args.forecast:
            fc = forecast_activity(active, args.forecast, args.forecast_days)
            print(f"Forecast for {args.forecast}: trend={fc.trend}")
            for d, v in fc.predictions:
                print(f"  {d}: {v:.0f}")
            return 0

        if args.multifactor:
            mf = multi_factor_anomaly(active, args.multifactor)
            if mf:
                print(f"Multi-factor anomaly for {args.multifactor}: composite={mf.composite_score:+.3f}")
            else:
                print("(insufficient data)")
            return 0

        if args.chart:
            sub = args.chart[0]
            if sub == "timeline" and len(args.chart) >= 2:
                path = args.chart[1]
                user = args.chart[2] if len(args.chart) > 2 else None
                chart_timeline(active, path, user)
            else:
                print("Usage: --chart timeline <path> [user]")
            return 0

        if args.dataframe is not None:
            print(dataframe_view(active, args.dataframe))
            return 0

        if args.recurrence:
            recs = detect_recurrence(active, args.recurrence)
            for r in recs:
                print(f"  [{r.pattern_type:>7}]  confidence={r.confidence:.0%}  {r.description}")
            if not recs:
                print("(no recurrence patterns)")
            return 0

        if args.churn:
            pred = predict_churn(active, args.churn)
            level = "HIGH" if pred.risk_score > 0.6 else "MEDIUM" if pred.risk_score > 0.3 else "LOW"
            print(f"Churn for {args.churn}: risk={level} ({pred.risk_score:.2f})")
            for f in pred.factors:
                print(f"  - {f}")
            return 0

        if args.pareto:
            p = pareto_analysis(active, args.pareto)
            print(f"Pareto ({args.pareto}): top {p.top_80_pct_count} items account for ~80%")
            for name, count, cum in p.items[:25]:
                print(f"  {cum:>5.0f}%  {count:>7d}  {name}")
            return 0

        if args.dashboard:
            run_dashboard(all_entries, cache and AlertEngine() or None, args.log)
            return 0

        if args.forecast_anomaly:
            user, z_s, days_s = args.forecast_anomaly
            fa = forecast_aware_anomaly(active, user, float(z_s), int(days_s))
            print(json.dumps(fa, indent=2))
            return 0

        if args.alert_fatigue:
            scores = alert_fatigue_scores(AlertEngine(), active, args.alert_fatigue)
            for s in scores:
                print(f"  {s.rule_name:<20s}  fires={s.fires_total:<5d}  rate={s.signal_rate:.0%}  {s.suggestion}")
            return 0

        if args.export_html_drilldown:
            path = args.export_html_drilldown[0]
            users = args.export_html_drilldown[1:] or ([args.user] if args.user else [])
            s = summarize(active, args.top)
            profiles = [build_profile(active, u) for u in users if u] if users else None
            write_html_report_drilldown(path, s, profiles)
            print(f"Drill-down HTML report written to {path}")
            return 0

        if args.session_times:
            ua, ub, gap_s = args.session_times
            results = session_response_times(active, ua, ub, int(gap_s))
            if not results:
                print("(no session data)")
            else:
                print(f"Session-aware response times ({ua} <-> {ub}):")
                for r in results[:20]:
                    print(f"  [{r['session_start']}] {r['responder']} responded in {r['delay_seconds']:.0f}s")
            return 0

        if args.influence:
            seed, hops_s, win_s = args.influence
            chains = influence_chains(active, seed, int(hops_s), int(win_s))
            if not chains:
                print(f"(no chains for {seed})")
            else:
                print(f"Influence chains ({len(chains)}):")
                for ch in chains[:20]:
                    print("  " + " -> ".join(c["user"] for c in ch))
            return 0

        if args.template_filter:
            filtered = filter_by_template(active, args.template_filter)
            if not filtered:
                print(f"(no matches for template {args.template_filter})")
            else:
                print(f"Template '{args.template_filter}' ({len(filtered)} entries):")
                for e in filtered[:30]:
                    print(f"  {e.raw[:200]}")
            return 0

        if args.drift:
            user, wa_s, wb_s, gap_s = args.drift
            result = drift_detection(active, user, int(wa_s), int(wb_s), int(gap_s))
            print(json.dumps(result, indent=2))
            return 0

        if args.save_profile:
            user, path = args.save_profile
            print(save_profile(user, active, path))
            return 0

        if args.load_profile:
            prof = load_profile(args.load_profile)
            if prof:
                print(json.dumps(prof, indent=2, default=str)[:2000])
            return 0

        if args.auto_tag:
            tag = auto_tag_user(active, args.auto_tag, args.llm_url, args.llm_model,
                                args.max_chunk_chars, cache)
            print(f"Tags for {args.auto_tag}: {tag}")
            return 0

        if args.auto_tag_bulk:
            tags = auto_tag_bulk(active, args.llm_url, args.llm_model,
                                 args.max_chunk_chars, cache, args.auto_tag_bulk)
            for user, tag in tags.items():
                print(f"  {user:<20s}  {tag}")
            return 0

        if args.recurrence_breach:
            parts = args.recurrence_breach
            user = parts[0]
            days = int(parts[1]) if len(parts) > 1 else 3
            result = check_recurrence_breach(active, user, days)
            print(json.dumps(result, indent=2))
            return 0

        if args.dashboard_alerts:
            engine = AlertEngine()
            scores = alert_fatigue_scores(engine, active, 1)
            if not scores:
                print("(no rules to score)")
            else:
                for s in scores:
                    print(f"  {s.rule_name:<20s}  rate={s.signal_rate:.0%}")
            return 0

        if args.entities is not None:
            user = args.entities if isinstance(args.entities, str) else args.user
            entries = [e for e in active if line_matches_user(e, user)] if user else active
            catalog = build_entity_catalog(entries)
            print_entity_report(catalog)
            return 0

        if args.gaps is not None:
            user = None
            threshold = 60
            for item in args.gaps:
                try:
                    threshold = int(item)
                except (ValueError, TypeError):
                    user = item
            if not user and args.user:
                user = args.user
            entries = [e for e in active if line_matches_user(e, user)] if user else active
            gaps = detect_timeline_gaps(entries, user, threshold)
            print_timeline_gaps(gaps, user)
            return 0

        if args.reconstruct is not None:
            user = args.reconstruct if isinstance(args.reconstruct, str) else args.user
            entries = [e for e in active if line_matches_user(e, user)] if user else active
            timeline = reconstruct_timeline(entries, user)
            print_timeline_reconstruction(timeline, show_entities=False)
            return 0

        if args.forensic_report:
            llm_forensic_report(active, args.forensic_report, args.llm_url, args.llm_model,
                                args.max_chunk_chars, cache=cache)
            return 0

        if args.timeline_narrative:
            llm_timeline_narrative(active, args.timeline_narrative, args.llm_url, args.llm_model,
                                   args.max_chunk_chars, cache=cache)
            return 0

        if args.evidence:
            llm_evidence_extraction(active, args.evidence, args.llm_url, args.llm_model,
                                    args.max_chunk_chars, cache=cache)
            return 0

        if args.llm_search:
            llm_search(active, args.llm_search, args.llm_url, args.llm_model,
                       args.max_chunk_chars, cache=cache)
            return 0

        if args.llm_threat:
            llm_threat_assessment(active, args.llm_threat, args.llm_url, args.llm_model,
                                  args.max_chunk_chars, cache=cache)
            return 0

        if args.llm_bot:
            llm_bot_detection(active, args.llm_bot, args.llm_url, args.llm_model,
                              args.max_chunk_chars, cache=cache)
            return 0

        if args.llm_profile:
            llm_deep_profile(active, args.llm_profile, args.llm_url, args.llm_model,
                             args.max_chunk_chars, cache=cache)
            return 0

        if args.llm_insider:
            llm_insider_threat(active, args.llm_insider, args.llm_url, args.llm_model,
                               args.max_chunk_chars, cache=cache)
            return 0

        if args.llm_social:
            llm_social_dynamics(active, args.llm_url, args.llm_model,
                                args.max_chunk_chars, cache=cache, top_users=args.llm_social)
            return 0

        if args.llm_incident is not None:
            llm_incident_timeline(active, args.llm_url, args.llm_model,
                                  args.max_chunk_chars, cache=cache, query=args.llm_incident)
            return 0

        if args.llm_topics:
            llm_topic_map(active, args.llm_url, args.llm_model,
                          args.max_chunk_chars, cache=cache, top_users=args.llm_topics)
            return 0

        if args.llm_sessions:
            user, gap_s = args.llm_sessions
            llm_compare_sessions(active, user, args.llm_url, args.llm_model,
                                 args.max_chunk_chars, cache=cache, gap_minutes=int(gap_s))
            return 0

        if args.llm_baseline:
            llm_baseline(active, args.llm_baseline, args.llm_url, args.llm_model,
                         args.max_chunk_chars, cache=cache)
            return 0

        if args.llm_summary:
            llm_summary(active, args.llm_url, args.llm_model,
                        args.max_chunk_chars, cache=cache)
            return 0

        if args.llm_replay:
            llm_replay(active, args.llm_replay, args.llm_url, args.llm_model,
                       args.max_chunk_chars, cache=cache)
            return 0

        if args.llm_predict:
            llm_predict(active, args.llm_predict, args.llm_url, args.llm_model,
                        args.max_chunk_chars, cache=cache)
            return 0

        if args.llm_motive:
            llm_motive(active, args.llm_motive, args.llm_url, args.llm_model,
                       args.max_chunk_chars, cache=cache)
            return 0

        if args.llm_relationship:
            a, b = args.llm_relationship
            llm_relationship(active, a, b, args.llm_url, args.llm_model,
                             args.max_chunk_chars, cache=cache)
            return 0

        if args.llm_audit is not None:
            llm_audit(active, args.llm_url, args.llm_model,
                      args.max_chunk_chars, cache=cache, policy=args.llm_audit)
            return 0

        if args.llm_risk:
            llm_risk_score(active, args.llm_risk, args.llm_url, args.llm_model,
                           args.max_chunk_chars, cache=cache)
            return 0

        if args.stats is not None:
            user = args.stats if isinstance(args.stats, str) else args.user
            stats = compute_stats(active, user)
            if stats:
                print_stats(stats, user)
            else:
                print(f"(no data{' for ' + user if user else ''})")
            return 0

        if args.frequency:
            top_words(active, args.frequency)
            return 0

        if args.cooccurrence:
            pairs = user_cooccurrence(active, args.cooccurrence)
            print_cooccurrence(pairs)
            return 0

        if args.heatmap_user:
            heatmap_user(active, args.heatmap_user)
            return 0

        if args.coverage:
            cov = log_coverage(active)
            print_coverage(cov)
            return 0

        if args.export_graphml:
            edges = build_edge_graph(active)
            if edges:
                export_graphml(edges, args.export_graphml)
            else:
                print("(no edges to export)")
            return 0

        if args.merge:
            merge_logs(args.merge[:-1], args.merge[-1])
            return 0

        if args.sample:
            sampled = random_sample(active, args.sample)
            print(f"\nRandom sample ({args.sample} of {len(active)} entries):")
            for i, e in enumerate(sampled, 1):
                print(f"  [{i}] {_fmt_dt(e.ts)}  {e.user or '?':>15s}  {e.raw[:200]}")
            return 0

        if args.last_seen is not None:
            user = args.last_seen if isinstance(args.last_seen, str) else None
            last_seen(active, user)
            return 0

        if args.whois:
            whois(active, args.whois)
            return 0

        if args.tamper_detect is not None:
            user = args.tamper_detect if isinstance(args.tamper_detect, str) else args.user
            strict = "--strict" in (sys.argv if sys.argv else [])
            entries_for_tamper = [e for e in active if line_matches_user(e, user)] if user else active
            report = detect_tampering(entries_for_tamper, user, strict_mode=strict)
            print_tamper_report(report, user)
            return 0

        if args.diff_time:
            diff_time(active, args.diff_time[0], args.diff_time[1])
            return 0

        if args.top_words:
            top_words(active, args.top_words)
            return 0

        if args.config:
            st_for_config = ShellState(log_path=args.log, entries=active)
            st_for_config.top_n = args.top
            st_for_config.llm_url = args.llm_url
            st_for_config.llm_model = args.llm_model
            st_for_config.max_chunk_chars = args.max_chunk_chars
            st_for_config.since = since
            st_for_config.until = until
            if args.user:
                st_for_config.focused_user = args.user
            shell_tmp = LogShell()
            shell_tmp.state = st_for_config
            shell_tmp.do_config(args.config if args.config else "view")
            return 0

        # Case management batch commands
        case_store = CaseStore()

        if args.case_create:
            name, desc = args.case_create
            c = case_store.create(name, desc)
            print(f"Created {c.id}: {c.name}")
            return 0

        if args.case_list is not None:
            status = args.case_list if isinstance(args.case_list, str) else None
            cases = case_store.list_cases(status)
            if not cases:
                print("(no cases)")
            else:
                hdr = f"  {'ID':<12s} {'Status':<16s} {'Pri':<8s} {'Name':<30s} {'Findings':>8s}  Tags"
                print(hdr)
                print("  " + "-" * (len(hdr) - 2))
                for c in cases:
                    tag_str = ", ".join(c.tags[:3])
                    if len(c.tags) > 3:
                        tag_str += "..."
                    print(f"  {c.id:<12s} {c.status:<16s} {c.priority:<8s} {c.name[:30]:<30s} {len(c.findings):>8d}  {tag_str}")
            return 0

        if args.case_show:
            report = case_store.export_report(args.case_show)
            print(report)
            return 0

        if args.case_export:
            cid, path = args.case_export
            report = case_store.export_report(cid)
            try:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(report)
                print(f"Exported {cid} to {path}")
            except OSError as exc:
                print(f"Export failed: {exc}")
            return 0

        if args.case_stats:
            st = case_store.summary_stats()
            print(f"Case Management Stats:")
            print(f"  Total cases:    {st['total_cases']}")
            print(f"  Total findings: {st['total_findings']}")
            if st["by_status"]:
                print(f"  By status:      {', '.join(f'{k}={v}' for k, v in sorted(st['by_status'].items()))}")
            if st["by_priority"]:
                print(f"  By priority:    {', '.join(f'{k}={v}' for k, v in sorted(st['by_priority'].items()))}")
            if st["by_severity"]:
                print(f"  By severity:    {', '.join(f'{k}={v}' for k, v in sorted(st['by_severity'].items()))}")
            if st["by_category"]:
                print(f"  By category:    {', '.join(f'{k}={v}' for k, v in sorted(st['by_category'].items()))}")
            return 0

        if args.case_search:
            results = case_store.search(args.case_search)
            if not results:
                print("(no matches)")
            else:
                for c, f in results:
                    if f:
                        print(f"  {c.id} [{c.status}] {c.name} → finding {f.id}: {f.evidence_text[:100]}")
                    else:
                        print(f"  {c.id} [{c.status}] {c.name} (case-level match)")
            return 0

        if args.case_status:
            cid, new_status = args.case_status
            ok = case_store.update_status(cid, new_status)
            if ok:
                print(f"Case {cid} status → {new_status}")
            else:
                print(f"Case {cid} not found")
            return 0

        if args.case_delete:
            ok = case_store.delete(args.case_delete)
            if ok:
                print(f"Deleted {args.case_delete}")
            else:
                print(f"Case {args.case_delete} not found")
            return 0

        if args.future_diag is not None:
            user = args.future_diag if isinstance(args.future_diag, str) else args.user
            entries_fd = [e for e in active if line_matches_user(e, user)] if user else active
            diag = compute_future_diagnostics(entries_fd, args.diag_lookback, args.diag_forecast)
            if args.diag_json:
                out = {
                    "timestamp": diag.timestamp, "overall_health": diag.overall_health,
                    "overall_risk_trend": diag.overall_risk_trend, "summary": diag.summary,
                    "health_metrics": [
                        {"name": m.name, "current": m.current, "baseline": m.baseline,
                         "trend": m.trend, "trajectory_7d": m.trajectory_7d,
                         "trajectory_30d": m.trajectory_30d, "status": m.status}
                        for m in diag.health_metrics
                    ],
                    "early_warnings": [
                        {"indicator": w.indicator, "severity": w.severity,
                         "current_value": w.current_value, "threshold": w.threshold,
                         "projected_breach": w.projected_breach, "confidence": w.confidence}
                        for w in diag.early_warnings
                    ],
                    "degradations": [
                        {"metric": d.metric, "user": d.user, "severity": d.severity,
                         "rate_per_day": d.rate_per_day, "eta_days": d.eta_days}
                        for d in diag.degradations
                    ],
                    "risk_trajectories": [
                        {"user": r.user, "current_risk": r.current_risk,
                         "risk_7d": r.risk_7d, "risk_30d": r.risk_30d,
                         "direction": r.direction, "drivers": r.drivers}
                        for r in diag.risk_trajectories[:20]
                    ],
                    "scenarios": [
                        {"name": s.name, "probability": s.probability,
                         "impact": s.impact, "description": s.description}
                        for s in diag.scenarios
                    ],
                }
                print(json.dumps(out, indent=2, default=str))
            else:
                print_future_diagnostics(diag)
            if args.diag_auto_case and (diag.early_warnings or diag.degradations):
                high_sev = [w for w in diag.early_warnings if w.severity == "high"]
                if high_sev or diag.degradations:
                    name = f"Auto: {diag.overall_health} diagnostics"
                    c = case_store.create(name, diag.summary,
                                          priority="high" if diag.overall_health == "critical" else "medium",
                                          tags=["auto-generated", "future-diagnostics"])
                    for w in high_sev:
                        case_store.add_finding(c.id, evidence_text=f"WARNING: {w.indicator} — {w.recommendation}",
                                               category="early_warning", severity=w.severity,
                                               note=f"Current: {w.current_value:.2f}, ETA: {w.projected_breach}")
                    for d in diag.degradations:
                        case_store.add_finding(c.id, evidence_text=f"DEGRADATION: {d.metric}",
                                               category="degradation", severity=d.severity,
                                               note=f"Rate: {d.rate_per_day:+.3f}/day, ETA: {d.eta_days:.0f}d" if d.eta_days else "No ETA")
                    print(f"\nAuto-created case {c.id} with {len(high_sev) + len(diag.degradations)} findings.")
            return 0

        # Advanced settings batch handlers
        if args.preset_list:
            presets = _load_json(os.path.join(_config_dir(), "presets.json"), {})
            if not presets:
                print("(no presets)")
            else:
                print("  Presets:")
                for name, p in sorted(presets.items()):
                    desc = p.get("desc", "")
                    keys = ", ".join(k for k in p if k != "desc")
                    print(f"    {name:<20s}  {desc or keys}")
            return 0

        if args.preset_show:
            presets = _load_json(os.path.join(_config_dir(), "presets.json"), {})
            p = presets.get(args.preset_show)
            if not p:
                print(f"Preset '{args.preset_show}' not found"); return 1
            print(f"  Preset: {args.preset_show}")
            for k, v in sorted(p.items()):
                if k != "desc":
                    print(f"    {k}: {v}")
            return 0

        if args.preset_delete:
            presets = _load_json(os.path.join(_config_dir(), "presets.json"), {})
            if args.preset_delete not in presets:
                print(f"Preset '{args.preset_delete}' not found"); return 1
            del presets[args.preset_delete]
            _save_json(os.path.join(_config_dir(), "presets.json"), presets)
            print(f"Deleted preset '{args.preset_delete}'")
            return 0

        if args.preset_save:
            name = args.preset_save[0]
            desc = ""
            if "--desc" in args.preset_save:
                idx = args.preset_save.index("--desc")
                if idx + 1 < len(args.preset_save):
                    desc = args.preset_save[idx + 1]
            presets = _load_json(os.path.join(_config_dir(), "presets.json"), {})
            presets[name] = {
                "desc": desc,
                "z_threshold": 2.5, "anomaly_window": 14, "forecast_days": 30,
                "burst_window": 60, "burst_z": 3.0, "session_gap": 30,
                "response_window": 300, "output_format": "table",
                "score_flag_threshold": 0.8, "max_output_lines": 500,
            }
            _save_json(os.path.join(_config_dir(), "presets.json"), presets)
            print(f"Saved preset '{name}'")
            return 0

        if args.preset:
            presets = _load_json(os.path.join(_config_dir(), "presets.json"), {})
            p = presets.get(args.preset)
            if not p:
                print(f"Preset '{args.preset}' not found"); return 1
            print(f"Loaded preset '{args.preset}'")

        if args.macro_list:
            macros = _load_json(os.path.join(_config_dir(), "macros.json"), {})
            if not macros:
                print("(no macros)")
            else:
                for name, cmds in sorted(macros.items()):
                    preview = "; ".join(cmds[:3])
                    if len(cmds) > 3:
                        preview += "..."
                    print(f"  {name:<20s}  ({len(cmds)} cmds) {preview}")
            return 0

        if args.macro_play:
            macros = _load_json(os.path.join(_config_dir(), "macros.json"), {})
            cmds = macros.get(args.macro_play)
            if not cmds:
                print(f"Macro '{args.macro_play}' not found"); return 1
            print(f"Macro '{args.macro_play}' ({len(cmds)} commands):")
            for cmd in cmds:
                print(f"  {cmd}")
            return 0

        if args.benchmark:
            n = args.benchmark
            entries_bm = active[:n] if len(active) > n else active
            if not entries_bm:
                print("(no entries to benchmark)"); return 1
            print(f"\n  Benchmarking with {len(entries_bm)} entries...")
            import time
            results: list[tuple[str, float]] = []
            ops = [
                ("summarize", lambda: summarize(entries_bm, 15)),
                ("build_profile", lambda: build_profile(entries_bm, entries_bm[0].user) if entries_bm and entries_bm[0].user else None),
                ("build_edge_graph", lambda: build_edge_graph(entries_bm)),
                ("detect_tampering", lambda: detect_tampering(entries_bm)),
                ("extract_entities", lambda: build_entity_catalog(entries_bm)),
                ("word_frequency", lambda: word_frequency(entries_bm, 50)),
                ("log_coverage", lambda: log_coverage(entries_bm)),
                ("compute_stats", lambda: compute_stats(entries_bm)),
            ]
            for name, fn in ops:
                start = time.perf_counter()
                try:
                    fn()
                except Exception:
                    pass
                elapsed = time.perf_counter() - start
                results.append((name, elapsed))
                print(f"    {name:<25s}  {elapsed:>8.4f}s")
            total = sum(t for _, t in results)
            print(f"\n  Total: {total:.4f}s  ({len(entries_bm)} entries)")
            if total > 0:
                print(f"  Rate: {len(entries_bm) / total:,.0f} entries/sec")
            return 0

        if args.env:
            import platform
            import resource
            try:
                mem = resource.getrusage(resource.RUSAGE_SELF)
                mem_mb = mem.ru_maxrss / 1024
            except Exception:
                mem_mb = 0
            print(f"\n  Environment:")
            print(f"    Platform:       {platform.platform()}")
            print(f"    Python:         {platform.python_version()}")
            print(f"    Working dir:    {os.getcwd()}")
            print(f"    Log file:       {args.log}")
            print(f"    Entries:        {len(all_entries)}")
            print(f"    Active entries: {len(active)}")
            print(f"    Memory (RSS):   {mem_mb:.1f} MB")
            print(f"    Config dir:     {_config_dir()}")
            return 0

        if args.memory:
            import resource
            try:
                mem = resource.getrusage(resource.RUSAGE_SELF)
                mem_mb = mem.ru_maxrss / 1024
                print(f"\n  Memory Usage:")
                print(f"    RSS (max):      {mem_mb:.1f} MB")
                print(f"    User time:      {mem.ru_utime:.2f}s")
                print(f"    System time:    {mem.ru_stime:.2f}s")
                print(f"    Page faults:    {mem.ru_majflt} (major) / {mem.ru_minflt} (minor)")
            except Exception as exc:
                print(f"Memory info unavailable: {exc}")
            entry_mb = len(all_entries) * 500 / 1_000_000
            print(f"    Entries (~500B each): {entry_mb:.1f} MB")
            return 0

        if args.export_config:
            config = {
                "aliases": _load_json(_aliases_path(), {}),
                "ignore_set": sorted(_load_json(_ignore_path(), [])),
                "notes": _load_json(_notes_path(), {}),
                "presets": _load_json(os.path.join(_config_dir(), "presets.json"), {}),
                "advanced": {
                    "default_z_threshold": 2.5, "default_anomaly_window": 14,
                    "default_forecast_days": 30, "default_burst_window": 60,
                    "default_burst_z": 3.0, "default_session_gap": 30,
                    "default_response_window": 300, "output_format": "table",
                    "command_timing": args.timing, "debug_mode": args.debug,
                    "quiet_mode": args.quiet, "score_flag_threshold": 0.8,
                    "max_output_lines": 500,
                },
            }
            if args.set_default:
                for key, value in args.set_default:
                    if key in config["advanced"]:
                        try:
                            config["advanced"][key] = float(value) if "." in value else int(value)
                        except ValueError:
                            config["advanced"][key] = value
            try:
                with open(args.export_config, "w", encoding="utf-8") as f:
                    json.dump(config, f, indent=2, default=str)
                print(f"Exported config to {args.export_config}")
            except OSError as exc:
                print(f"Export failed: {exc}"); return 1
            return 0

        if args.import_config:
            try:
                with open(args.import_config, "r", encoding="utf-8") as f:
                    config = json.load(f)
            except (OSError, json.JSONDecodeError) as exc:
                print(f"Import failed: {exc}"); return 1
            if "aliases" in config:
                _save_json(_aliases_path(), config["aliases"])
            if "ignore_set" in config:
                _save_json(_ignore_path(), config["ignore_set"])
            if "notes" in config:
                _save_json(_notes_path(), config["notes"])
            if "presets" in config:
                _save_json(os.path.join(_config_dir(), "presets.json"), config["presets"])
            print(f"Imported config from {args.import_config}")
            return 0

        if args.show_defaults:
            print(f"\n  Advanced Defaults:")
            print(f"    z_threshold:          2.5")
            print(f"    anomaly_window:       14 days")
            print(f"    forecast_days:        30 days")
            print(f"    burst_window:         60s")
            print(f"    burst_z:              3.0")
            print(f"    session_gap:          30min")
            print(f"    response_window:      300s")
            print(f"    score_flag_threshold: 0.8")
            print(f"    output_format:        table")
            print(f"    command_timing:       {args.timing}")
            print(f"    debug_mode:           {args.debug}")
            print(f"    quiet_mode:           {args.quiet}")
            print(f"    max_output_lines:     500")
            return 0

        if args.reset_config:
            target = args.reset_config
            if target == "all":
                _save_json(_aliases_path(), {})
                _save_json(_ignore_path(), [])
                _save_json(_notes_path(), {})
                print("Reset all configuration.")
            elif target == "aliases":
                _save_json(_aliases_path(), {})
                print("Reset aliases.")
            elif target == "ignore":
                _save_json(_ignore_path(), [])
                print("Reset ignore list.")
            elif target == "notes":
                _save_json(_notes_path(), {})
                print("Reset notes.")
            else:
                print(f"Unknown reset target: {target}"); return 1
            return 0

        if args.set_default:
            presets = _load_json(os.path.join(_config_dir(), "presets.json"), {})
            for key, value in args.set_default:
                print(f"{key} = {value}")
            return 0

        if args.similar:
            pairs = find_similar_users(active,
                                       min_lines=args.similar_min_lines,
                                       threshold=args.similar_threshold)
            print_similar_users(pairs)
            return 0

        if args.flagged:
            try:
                filters = parse_score_filter(args.flagged)
            except ValueError as exc:
                print(f"Bad score expression: {exc}", file=sys.stderr); return 2
            u_l = args.user.lower() if args.user else None
            count = 0
            for e in active:
                if u_l and not (e.user and e.user.lower() == u_l):
                    continue
                if matches_score_filter(e, filters):
                    print(e.raw)
                    count += 1
            print(f"# {count} matches", file=sys.stderr)
            return 0

        if args.bursts:
            bursts = detect_bursts(active, args.bursts,
                                   window_seconds=args.bursts_window,
                                   z_threshold=args.bursts_z)
            print_bursts(args.bursts, bursts, args.bursts_window)
            return 0

        if args.zscores:
            if not args.user:
                print("--zscores requires --user", file=sys.stderr); return 2
            profile = build_profile(active, args.user)
            pop = population_score_stats(active)
            print_zscores(profile, pop)
            return 0

        if args.dist:
            if args.user:
                print_score_dist(args.user, collect_scores(active, args.user))
            else:
                print_score_dist("(population)", collect_scores(active))
            return 0

        if args.export_edges:
            edges = build_edge_graph(active)
            ext = os.path.splitext(args.export_edges)[1].lower()
            if ext == ".dot":
                export_edges_dot(edges, args.export_edges)
            else:
                export_edges_csv(edges, args.export_edges)
            print(f"Wrote {args.export_edges} ({len(edges)} edges)")
            return 0
        if args.export_report:
            export_summary_json(summarize(active, args.top), args.export_report)
            print(f"Wrote {args.export_report}")
            return 0
        if args.export_profile:
            if not args.user:
                print("--export-profile requires --user", file=sys.stderr); return 2
            profile = build_profile(active, args.user)
            ext = os.path.splitext(args.export_profile)[1].lower()
            if ext == ".csv":
                export_profile_csv(profile, args.export_profile)
            else:
                export_profile_json(profile, args.export_profile)
            print(f"Wrote {args.export_profile}")
            return 0

        if args.compare:
            users = [u.strip() for u in args.compare.split(",") if u.strip()]
            if len(users) < 2:
                print("--compare must be at least 'A,B'", file=sys.stderr); return 2
            profiles = [build_profile(active, u) for u in users]
            print(f"=== {args.log}  compare: {' vs '.join(users)} ===")
            print_compare_table_n(profiles)
            if not args.no_llm:
                compare_n_users_with_llm(profiles, args.llm_url, args.llm_model,
                                         args.max_chunk_chars, cache=cache)
            return 0

        if args.users:
            pair = [u.strip() for u in args.users.split(",") if u.strip()]
            if len(pair) != 2:
                print("--users must be 'A,B'", file=sys.stderr); return 2
            a, b = pair
            matched = [e for e in active if line_is_interaction(e, a, b)]
            print(f"=== {args.log}  interactions: {a} <-> {b} ({len(matched)} lines) ===")
            if args.show_lines:
                for e in matched[:args.show_lines]:
                    print(f"  {e.text[:300]}")
            if not args.no_llm:
                analyze_interaction_with_llm(
                    a, b, [e.text for e in matched],
                    args.llm_url, args.llm_model, args.max_chunk_chars, cache=cache,
                )
            return 0

        if args.ask:
            if not args.user:
                print("--ask requires --user", file=sys.stderr); return 2
            matched = [e for e in active if line_matches_user(e, args.user)]
            print(f"=== {args.log}  ask about '{args.user}': {args.ask} ===")
            if not args.no_llm:
                ask_about_user_with_llm(
                    args.user, args.ask, [e.text for e in matched],
                    args.llm_url, args.llm_model, args.max_chunk_chars, cache=cache,
                )
            return 0

        if args.user:
            matched = [e for e in active if line_matches_user(e, args.user)]
            print(f"=== {args.log}  filtered to user '{args.user}' ===")
            print_report(summarize(matched, args.top))

            if args.show_lines:
                print(f"\nFirst {min(args.show_lines, len(matched))} matched lines:")
                for e in matched[:args.show_lines]:
                    print(f"  {e.raw[:300]}")

            if not args.no_llm:
                analyze_user_with_llm(
                    args.user, [e.text for e in matched],
                    args.llm_url, args.llm_model, args.max_chunk_chars, cache=cache,
                )
        else:
            print(f"=== {args.log} ===")
            print_report(summarize(active, args.top))
        return 0

    state = ShellState(
        log_path=args.log,
        entries=all_entries,
        focused_user=args.user,
        since=since,
        until=until,
        top_n=args.top,
        llm_url=args.llm_url,
        llm_model=args.llm_model,
        max_chunk_chars=args.max_chunk_chars,
        llm_cache=cache,
        webhook_url=args.webhook_url or "",
        plugin_dir=args.plugin_dir or "",
        template_filter=args.template_filter or "",
        profile_dir=os.path.join(os.path.dirname(args.log) or ".", "profiles"),
        case_store=CaseStore(),
    )
    load_shell_config(state)
    if args.plugin_dir:
        load_plugins_from(args.plugin_dir)
    if args.web:
        global _web_entries  # noqa: PLW0603
        _web_entries = all_entries
        state.web_server = start_web_server(args.web)
        print(f"Web API server started at http://127.0.0.1:{args.web}")
    shell = LogShell(state)
    _set_current_shell(shell)
    shell._refresh_prompt()

    try:
        startup_cmds: list[str] = []
        if args.show_commands:
            startup_cmds.append("commands")
        startup_cmds.extend(args.cmd)

        if startup_cmds:
            print(shell.intro, end="")
            for c in startup_cmds:
                print(f"{shell.prompt}{c}")
                if shell.onecmd(c):
                    return 0
                shell._refresh_prompt()
            shell.cmdloop(intro="")
        else:
            shell.cmdloop()
    except KeyboardInterrupt:
        print()
    finally:
        if state.llm_cache:
            state.llm_cache.save()
    return 0


if __name__ == "__main__":
    sys.exit(main())
