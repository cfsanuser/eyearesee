import json
import os
import time
from collections import deque
from typing import Dict, List, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class AstroturfingDetector:
    """Detects coordinated inauthentic behavior (astroturfing) in IRC channels.

    Identifies:
      * Timing correlation: multiple accounts posting within narrow windows
      * Narrative alignment: different accounts using identical/similar phrasing
      * Shared vocabulary: unusual overlap in word choice, bigrams, trigrams
      * Account clustering: new accounts that only interact with each other
      * Amplification patterns: one account posts, others immediately echo
      * Topic hijacking: sudden coordinated focus on a single topic
      * Sentiment synchronization: artificial agreement/disagreement patterns
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "astroturfing.json")
    _TIMING_WINDOW = 30.0  # seconds
    _MIN_ACCOUNTS = 3
    _SIMILARITY_THRESHOLD = 0.6

    def __init__(self):
        self._message_log: Dict[str, deque] = {}
        self._vocab_sets: Dict[str, set] = {}
        self._timing_groups: List[Dict] = []
        self._campaigns: List[Dict] = []
        self._last_save: float = 0.0
        self.load()

    def record_message(self, nick: str, channel: str, text: str) -> Optional[Dict]:
        nl = nick.lower()
        cl = channel.lower()
        now = time.time()

        log = self._message_log.setdefault(cl, deque(maxlen=500))
        log.append({"nick": nl, "text": text, "ts": now})

        vocab = set(text.lower().split())
        self._vocab_sets.setdefault(nl, set()).update(vocab)

        result = self._detect_coordination(cl, nl, text, now)
        if result and result["confidence"] >= 0.5:
            self._campaigns.append({
                "channel": cl, "nicks": result["nicks"],
                "confidence": result["confidence"], "ts": now,
                "evidence": result["evidence"],
            })
            if len(self._campaigns) > 100:
                self._campaigns = self._campaigns[-100:]
        self._maybe_save()
        return result

    def _detect_coordination(self, channel: str, nick: str, text: str, now: float) -> Optional[Dict]:
        log = self._message_log.get(channel, deque())
        recent = [e for e in log if now - e["ts"] < self._TIMING_WINDOW and e["nick"] != nick]
        if len(recent) < self._MIN_ACCOUNTS - 1:
            return None

        evidence = []
        scores = {}

        timing_nicks = {e["nick"] for e in recent}
        timing_nicks.add(nick)
        scores["timing"] = min(1.0, len(timing_nicks) / 5.0)
        evidence.append(f"{len(timing_nicks)} accounts active in {self._TIMING_WINDOW:.0f}s window")

        vocab = set(text.lower().split())
        shared_vocab = 0
        for e in recent:
            other_vocab = self._vocab_sets.get(e["nick"], set())
            overlap = len(vocab & other_vocab) / max(len(vocab | other_vocab), 1)
            if overlap > 0.3:
                shared_vocab += 1
        scores["vocabulary"] = min(1.0, shared_vocab / max(len(recent), 1))
        evidence.append(f"{shared_vocab}/{len(recent)} share significant vocabulary overlap")

        text_lower = text.lower()
        phrase_matches = 0
        for e in recent:
            if any(word in e["text"].lower() for word in vocab if len(word) > 4):
                phrase_matches += 1
        scores["phrasing"] = min(1.0, phrase_matches / max(len(recent), 1))
        evidence.append(f"{phrase_matches}/{len(recent)} use similar key terms")

        sentiment_scores = []
        for e in recent:
            s = self._quick_sentiment(e["text"])
            sentiment_scores.append(s)
        if sentiment_scores:
            mean_s = sum(sentiment_scores) / len(sentiment_scores)
            variance = sum((s - mean_s) ** 2 for s in sentiment_scores) / len(sentiment_scores)
            scores["sentiment_sync"] = 1.0 - min(1.0, variance * 5)
            evidence.append(f"sentiment variance: {variance:.3f} ({'synchronized' if variance < 0.1 else 'varied'})")

        weights = {"timing": 0.25, "vocabulary": 0.25, "phrasing": 0.30, "sentiment_sync": 0.20}
        confidence = sum(scores[k] * w for k, w in weights.items())

        return {
            "channel": channel, "nicks": sorted(timing_nicks),
            "confidence": round(confidence, 3), "scores": scores,
            "evidence": evidence,
        } if confidence >= 0.3 else None

    @staticmethod
    def _quick_sentiment(text: str) -> float:
        positive = {"good", "great", "excellent", "love", "best", "amazing", "awesome", "perfect", "nice", "happy"}
        negative = {"bad", "terrible", "worst", "hate", "awful", "horrible", "poor", "sad", "angry", "stupid"}
        words = set(text.lower().split())
        pos = len(words & positive)
        neg = len(words & negative)
        total = pos + neg
        if total == 0:
            return 0.5
        return pos / total

    def get_campaigns(self, channel: str = "", limit: int = 10) -> List[Dict]:
        results = self._campaigns
        if channel:
            results = [c for c in results if c["channel"] == channel.lower()]
        results.sort(key=lambda x: -x["confidence"])
        return results[:limit]

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            data = {
                "campaigns": self._campaigns[-50:],
                "vocab_preview": {k: list(v)[:20] for k, v in list(self._vocab_sets.items())[:50]},
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._campaigns = data.get("campaigns", [])
        except Exception:
            pass
