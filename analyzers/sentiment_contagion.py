import json
import os
import time
from collections import deque
from typing import Any, Dict, List, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SentimentContagionMap:
    """Tracks how mood spreads through a channel: who influences whom, cascade patterns.

    Models:
      * Sentiment propagation (positive/negative mood spreading)
      * Influence scoring (who sets the tone)
      * Cascade detection (chain reactions of sentiment)
      * Emotional contagion networks
      * Mood recovery time (how long negative sentiment persists)
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "sentiment_contagion.json")

    def __init__(self):
        self._sentiment_timeline: Dict[str, deque] = {}
        self._influence_matrix: Dict[str, Dict[str, float]] = {}
        self._cascades: List[Dict] = []
        self._channel_mood: Dict[str, deque] = {}
        self._last_save: float = 0.0
        self.load()

    def record(self, nick: str, channel: str, text: str) -> Dict[str, Any]:
        nl = nick.lower()
        cl = channel.lower()
        now = time.time()
        sentiment = self._analyze_sentiment(text)

        timeline = self._sentiment_timeline.setdefault(nl, deque(maxlen=100))
        timeline.append({"ts": now, "sentiment": sentiment, "channel": cl})

        mood = self._channel_mood.setdefault(cl, deque(maxlen=50))
        prev_mood = mood[-1]["sentiment"] if mood else 0.0
        mood.append({"ts": now, "nick": nl, "sentiment": sentiment})

        influence = self._calculate_influence(cl, nl, sentiment, prev_mood)
        if influence > 0.3:
            self._influence_matrix.setdefault(cl, {}).setdefault(nl, 0.0)
            self._influence_matrix[cl][nl] = (self._influence_matrix[cl][nl] * 0.9 + influence * 0.1)

        cascade = self._detect_cascade(cl, nl, sentiment)
        result = {"sentiment": sentiment, "influence": round(influence, 3)}
        if cascade:
            result["cascade"] = cascade
            self._cascades.append(cascade)
            if len(self._cascades) > 50:
                self._cascades.pop(0)

        self._maybe_save()
        return result

    def get_channel_mood(self, channel: str) -> Dict[str, Any]:
        cl = channel.lower()
        mood = self._channel_mood.get(cl, deque())
        if not mood:
            return {"channel": channel, "sentiment": 0.0, "trend": "stable"}
        recent = list(mood)[-20:]
        avg = sum(m["sentiment"] for m in recent) / len(recent)
        first_half = sum(m["sentiment"] for m in recent[:10]) / 10
        second_half = sum(m["sentiment"] for m in recent[10:]) / (len(recent) - 10)
        delta = second_half - first_half
        trend = "improving" if delta > 0.1 else "declining" if delta < -0.1 else "stable"
        return {"channel": channel, "sentiment": round(avg, 3), "trend": trend}

    def get_top_influencers(self, channel: str, limit: int = 5) -> List[Dict]:
        cl = channel.lower()
        matrix = self._influence_matrix.get(cl, {})
        return [{"nick": n, "influence": round(s, 3)} for n, s in
                sorted(matrix.items(), key=lambda x: -x[1])[:limit]]

    def get_cascades(self, limit: int = 5) -> List[Dict]:
        return self._cascades[-limit:]

    @staticmethod
    def _analyze_sentiment(text: str) -> float:
        pos = {"good", "great", "excellent", "love", "best", "amazing", "happy", "awesome"}
        neg = {"bad", "terrible", "worst", "hate", "awful", "sad", "angry", "stupid"}
        words = set(text.lower().split())
        p = len(words & pos)
        n = len(words & neg)
        total = p + n
        if total == 0:
            return 0.0
        return (p - n) / total

    def _calculate_influence(self, channel: str, nick: str, sentiment: float, prev_mood: float) -> float:
        mood = self._channel_mood.get(channel, deque())
        if len(mood) < 3:
            return 0.0
        recent = list(mood)[-10:]
        others = [m["sentiment"] for m in recent if m["nick"] != nick]
        if not others:
            return 0.0
        avg_others = sum(others) / len(others)
        shift = abs(sentiment - prev_mood)
        alignment = 1.0 - abs(sentiment - avg_others)
        return min(1.0, shift * alignment)

    def _detect_cascade(self, channel: str, nick: str, sentiment: float) -> Optional[Dict]:
        mood = self._channel_mood.get(channel, deque())
        if len(mood) < 5:
            return None
        recent = list(mood)[-10:]
        chain = []
        for m in recent:
            if abs(m["sentiment"] - sentiment) < 0.3:
                chain.append(m["nick"])
        if len(set(chain)) >= 3:
            return {"channel": channel, "initiator": nick, "sentiment": sentiment,
                   "participants": list(set(chain)), "length": len(chain), "ts": time.time()}
        return None

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            data = {
                "influence_matrix": self._influence_matrix,
                "cascades": self._cascades[-20:],
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._influence_matrix = data.get("influence_matrix", {})
            self._cascades = data.get("cascades", [])
        except Exception:
            pass
