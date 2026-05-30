import json
import os
import time
from typing import Dict, List, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class StanceTracker:
    """Tracks user positions on topics over time; detects shifts and contradictions.

    Monitors:
      * Topic extraction from messages
      * Sentiment toward specific topics/entities
      * Stance evolution (supports/opposes/neutral)
      * Contradiction detection (current stance vs historical)
      * Cross-topic consistency
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "stances.json")

    _TOPIC_KEYWORDS = {
        "politics": {"government", "election", "policy", "law", "vote", "congress", "president"},
        "technology": {"software", "hardware", "programming", "ai", "machine learning", "code"},
        "climate": {"climate", "carbon", "emission", "warming", "environment", "renewable"},
        "economics": {"economy", "market", "inflation", "tax", "trade", "gdp", "recession"},
        "health": {"health", "medical", "vaccine", "disease", "hospital", "treatment"},
    }

    _SUPPORT_MARKERS = frozenset({"support", "agree", "good", "pro", "for", "favor", "yes", "positive"})
    _OPPOSE_MARKERS = frozenset({"oppose", "against", "bad", "anti", "no", "negative", "wrong", "harmful"})

    def __init__(self):
        self._stances: Dict[str, Dict[str, List[Dict]]] = {}
        self._last_save: float = 0.0
        self.load()

    def record(self, nick: str, text: str) -> List[Dict]:
        nl = nick.lower()
        words = set(text.lower().split())
        sentiment = self._quick_sentiment(text)
        updates = []

        for topic, keywords in self._TOPIC_KEYWORDS.items():
            if words & keywords:
                stance = "support" if words & self._SUPPORT_MARKERS else "oppose" if words & self._OPPOSE_MARKERS else "neutral"
                if sentiment > 0.3 and not (words & self._OPPOSE_MARKERS):
                    stance = "support"
                elif sentiment < -0.3 and not (words & self._SUPPORT_MARKERS):
                    stance = "oppose"

                entry = {"stance": stance, "sentiment": round(sentiment, 3), "ts": time.time(), "text": text[:100]}
                self._stances.setdefault(nl, {}).setdefault(topic, []).append(entry)
                stances = self._stances[nl][topic]
                if len(stances) > 50:
                    stances.pop(0)

                contradiction = self._check_contradiction(nl, topic, stance)
                if contradiction:
                    updates.append({"type": "contradiction", "nick": nick, "topic": topic,
                                   "old": contradiction, "new": stance})
                updates.append({"type": "stance", "nick": nick, "topic": topic, "stance": stance})

        self._maybe_save()
        return updates

    def get_stance(self, nick: str, topic: str) -> Optional[Dict]:
        nl = nick.lower()
        stances = self._stances.get(nl, {}).get(topic, [])
        if not stances:
            return None
        recent = stances[-10:]
        support = sum(1 for s in recent if s["stance"] == "support")
        oppose = sum(1 for s in recent if s["stance"] == "oppose")
        total = len(recent)
        return {
            "nick": nick, "topic": topic,
            "current": "support" if support > oppose else "oppose" if oppose > support else "neutral",
            "support_pct": round(support / total * 100, 1),
            "oppose_pct": round(oppose / total * 100, 1),
            "samples": total,
        }

    def get_all_stances(self, nick: str) -> Dict[str, Dict]:
        nl = nick.lower()
        result = {}
        for topic in self._stances.get(nl, {}):
            s = self.get_stance(nick, topic)
            if s:
                result[topic] = s
        return result

    def _check_contradiction(self, nick: str, topic: str, current: str) -> Optional[str]:
        stances = self._stances.get(nick, {}).get(topic, [])
        if len(stances) < 3:
            return None
        prior = stances[-3:]
        prior_stances = [s["stance"] for s in prior if s["stance"] != "neutral"]
        if not prior_stances:
            return None
        dominant = max(set(prior_stances), key=prior_stances.count)
        if dominant != current and dominant != "neutral" and current != "neutral":
            return dominant
        return None

    @staticmethod
    def _quick_sentiment(text: str) -> float:
        pos = {"good", "great", "excellent", "love", "best", "amazing", "positive"}
        neg = {"bad", "terrible", "worst", "hate", "awful", "negative", "harmful"}
        words = set(text.lower().split())
        p = len(words & pos)
        n = len(words & neg)
        total = p + n
        if total == 0:
            return 0.0
        return (p - n) / total

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            data = {}
            for nick, topics in self._stances.items():
                data[nick] = {t: s[-20:] for t, s in topics.items()}
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                self._stances = json.load(f)
        except Exception:
            pass
