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

IRC_MSG_RE = re.compile(r"^\[(?P<ts>\d{1,2}:\d{2}(?::\d{2})?)\]\s+<(?P<nick>[^>]+)>\s+(?P<msg>.*)$")
IRC_ACT_RE = re.compile(r"^\[(?P<ts>\d{1,2}:\d{2}(?::\d{2})?)\]\s+\*\s+(?P<rest>.*)$")
SYSLOG_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)"
    r"\s+\[?(?P<level>[A-Z]{3,8})\]?\s+(?P<comp>[\w.\-/:]+):\s*(?P<msg>.*)$"
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


def parse_line(line: str) -> Entry | None:
    line = line.rstrip("\r\n")
    if not line.strip():
        return None

    if line.lstrip().startswith("{"):
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            obj = None
        if isinstance(obj, dict):
            ts_str = obj.get("timestamp") or obj.get("dt") or obj.get("ts") or obj.get("time")
            ts = None
            if isinstance(ts_str, str):
                ts = _parse_iso(ts_str)
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

    m = SYSLOG_RE.match(line)
    if m:
        ts = _parse_iso(m["ts"])
        return Entry(line, ts, m["comp"], m["level"], None, None, m["msg"], "syslog")

    m = IRC_MSG_RE.match(line)
    if m:
        ts = _parse_irc_time(m["ts"])
        return Entry(line, ts, m["nick"], None, "msg", None, m["msg"], "irc")

    m = IRC_ACT_RE.match(line)
    if m:
        ts = _parse_irc_time(m["ts"])
        rest = m["rest"]
        nick = rest.split(" ", 1)[0] if rest else None
        event = "action"
        for kw in ("joined", "left", "quit", "is now known", "kicked", "set mode", "Topic"):
            if kw in rest:
                event = kw.split()[0].lower()
                break
        return Entry(line, ts, nick, None, event, None, rest, "irc")

    return Entry(line, None, None, None, None, None, line, "raw")


def _parse_irc_time(ts: str) -> datetime | None:
    parts = ts.split(":")
    try:
        h, mi = int(parts[0]), int(parts[1])
        s = int(parts[2]) if len(parts) > 2 else 0
        return datetime(1970, 1, 1, h, mi, s)
    except (ValueError, IndexError):
        return None


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
    if entry.user and entry.user.lower() == u:
        return True
    return u in entry.raw.lower()


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

SENTIMENT_POS = re.compile(r"\b(good|great|awesome|thanks|nice|love|perfect|helpful|excellent|amazing|beautiful|wonderful|fantastic|brilliant|outstanding|superb|glad|happy|correct|agree|works|fixed|solved|appreciate|thank|please|yes|ok|okay)\b", re.I)
SENTIMENT_NEG = re.compile(r"\b(bad|terrible|awful|hate|ugly|horrible|wrong|broken|fails|failed|error|crash|stupid|annoying|useless|worst|sucks|horrible|crap|damn|bug|issue|problem|disaster|fault|never|refuse|reject|no|not|can't|cannot|won't)\b", re.I)
SENTIMENT_AGREE = re.compile(r"\b(agree|yes|correct|right|indeed|exactly|true|same)\b", re.I)
SENTIMENT_DISAGREE = re.compile(r"\b(disagree|no|wrong|incorrect|false|nonsense|dispute|reject)\b", re.I)

@dataclass
class SentimentScore:
    positive: float
    negative: float
    agreement: float
    disagreement: float
    compound: float

def score_sentiment(text: str) -> SentimentScore:
    pos = len(SENTIMENT_POS.findall(text))
    neg = len(SENTIMENT_NEG.findall(text))
    agr = len(SENTIMENT_AGREE.findall(text))
    dagr = len(SENTIMENT_DISAGREE.findall(text))
    total = pos + neg + 1
    return SentimentScore(
        positive=pos / total,
        negative=neg / total,
        agreement=agr / (agr + dagr + 1),
        disagreement=dagr / (agr + dagr + 1),
        compound=(pos - neg) / total,
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
        "mean_positive": statistics.mean(s.compound for s in scores),
        "mean_compound": statistics.mean(s.compound for s in scores),
        "pos_rate": sum(1 for s in scores if s.compound > 0) / len(scores),
        "neg_rate": sum(1 for s in scores if s.compound < 0) / len(scores),
        "agree_rate": statistics.mean(s.agreement for s in scores),
    }

# ---------- NEW: Topic/keyword extraction (#3) --------------------------------

STOPWORDS = set("the a an is in to of and it you that on for with as at by this are be has have had not was were will can its or do if from they what which who " "all about but just like so up no out one also get would could".split())

def extract_keywords(texts: list[str], top_n: int = 20) -> list[tuple[str, int]]:
    counter: Counter = Counter()
    token_re = re.compile(r"[A-Za-z][A-Za-z0-9_\-']{2,}")
    for t in texts:
        for tok in token_re.findall(t.lower()):
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
    return {
        "user": user,
        "keywords": extract_keywords(texts, top_n),
        "bigrams": extract_ngrams(texts, 2, top_n),
        "trigrams": extract_ngrams(texts, 3, top_n),
    }

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
            if dev > z * (statistics.mean([abs(actual - v) for v in forecast_map.values() if v > 0]) or 1):
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
    }
    for rule in state.alert_engine.rules:
        data["rules"].append({
            "name": rule.name, "field": rule.field, "op": rule.op,
            "value": rule.value, "message": rule.message, "enabled": rule.enabled,
        })
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
            ok = (e.user and e.user.lower() == u) or (u in (e.raw or "").lower())
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
        "You are a log-analysis assistant. Given log lines that all relate to a "
        "single user/identifier, summarize that user's behavior: what they do, "
        "when they are active, who/what they interact with, anomalies, and any "
        "signs of trouble. Be concrete, cite line patterns, and keep it tight."
    )

    partials: list[str] = []
    for i, chunk in enumerate(chunks, 1):
        prompt = (
            f"User of interest: {user}\n"
            f"Chunk {i}/{len(chunks)} of log lines mentioning this user:\n\n"
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


class LogShell(cmd.Cmd):
    intro = (
        "analyzelog interactive shell.  Type 'commands' for a full reference, "
        "'help <name>' for one command, 'quit' to exit.\n"
    )
    prompt = "(log) "

    NO_CAPTURE_CMDS = {"watch"}
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
        head_token = line.split()[0] if line.split() else ""
        if head_token in self.NO_CAPTURE_CMDS:
            return super().onecmd(line)

        # Capture stdout for last/pager/redirect
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            try:
                result = super().onecmd(line)
            except Exception as exc:  # noqa: BLE001
                print(f"Error: {exc}")
                result = False
        output = buf.getvalue()
        self.state.last_output = output

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
        matched = self._filtered(user)
        if not matched:
            print(f"No lines match '{user}'.")
            return
        analyze_user_with_llm(
            user, [e.text for e in matched],
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
        matched = self._filtered(nick)
        if not matched:
            print(f"No lines match '{nick}'.")
            return
        ask_about_user_with_llm(
            nick, question, [e.text for e in matched],
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
            if u_l and not (e.user and e.user.lower() == u_l) and u_l not in (e.raw or "").lower():
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
        print(f"  back/fwd        = {len(st.focus_back)}/{len(st.focus_forward)}")

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
            ("commands", "commands  (or ??)", "Print this reference."),
            ("help", "help [name]  (or ?<name>)", "Built-in help."),
            ("quit", "quit  (exit, Ctrl-D)", "Exit the shell."),
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
        if not anoms:
            print(f"(no anomalies for '{user}' at z>={z})")
            return
        print(f"\nAnomalies for '{user}' (z>={z}):")
        for a in anoms:
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

    def do_quit(self, arg: str) -> bool:
        """quit   Exit the shell."""
        save_shell_config(self.state)
        if self.state.watch_bg:
            self.state.watch_bg.stop()
            self.state.watch_bg = None
        if self.state.web_server:
            self.state.web_server.shutdown()
            self.state.web_server = None
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
    args = p.parse_args(argv)

    try:
        all_entries = list(iter_entries(args.log))
    except FileNotFoundError:
        print(f"File not found: {args.log}", file=sys.stderr)
        return 1

    since = parse_iso_arg(args.since) if args.since else None
    until = parse_iso_arg(args.until) if args.until else None
    if args.since and not since:
        print(f"Could not parse --since {args.since!r}", file=sys.stderr); return 2
    if args.until and not until:
        print(f"Could not parse --until {args.until!r}", file=sys.stderr); return 2

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
            for a in anoms:
                print(f"  {a.metric} z={a.zscore:.2f} value={a.value:.1f} expected={a.expected:.1f}")
            if not anoms:
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
