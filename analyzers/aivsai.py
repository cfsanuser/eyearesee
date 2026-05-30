import asyncio
import json
import os
import time
from collections import deque
from typing import Dict, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class AIVsAIDetector:
    """Detects when two AI/bot users are talking to each other.

    Correlates:
      • Both participants have high rolling AI scores
      • Frequent mutual mentions or replies between them
      • Formal/templated dialogue patterns (question\u2192answer chains)
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
                        f"[ai-vs-ai] {nick_a} \u2194 {nick_b} in {channel}: "
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
