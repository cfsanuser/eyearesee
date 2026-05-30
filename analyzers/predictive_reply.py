import json
import os
import time
from collections import Counter
from typing import Dict, List

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PredictiveReplyEngine:
    """Suggests context-aware replies based on channel history and conversation patterns.

    Uses:
      * N-gram language model built from channel history
      * Response pattern matching (how others replied to similar messages)
      * Topic-aware suggestions
      * Personal style adaptation (learns user's typical response patterns)
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "predictive_replies.json")
    _MAX_NGRAMS = 50000
    _MAX_RESPONSES = 10000

    def __init__(self):
        self._bigrams: Counter = Counter()
        self._trigrams: Counter = Counter()
        self._response_patterns: Dict[str, List[str]] = {}
        self._topic_responses: Dict[str, List[str]] = {}
        self._last_save: float = 0.0
        self.load()

    def train(self, channel: str, nick: str, text: str, reply_to: str = "") -> None:
        words = text.lower().split()
        for i in range(len(words) - 1):
            self._bigrams[(words[i], words[i + 1])] += 1
        for i in range(len(words) - 2):
            self._trigrams[(words[i], words[i + 1], words[i + 2])] += 1

        if reply_to:
            key = reply_to.lower()[:50]
            patterns = self._response_patterns.setdefault(key, [])
            if text not in patterns:
                patterns.append(text)
                if len(patterns) > 20:
                    patterns.pop(0)

        if len(self._bigrams) > self._MAX_NGRAMS:
            self._prune_ngrams()
        self._maybe_save()

    def suggest(self, context: str, channel: str = "", limit: int = 5) -> List[Dict]:
        words = context.lower().split()
        if not words:
            return []

        suggestions = []
        last_word = words[-1]

        for (w1, w2), count in self._bigrams.items():
            if w1 == last_word and count > 2:
                suggestions.append({"text": w2, "score": count, "type": "bigram"})

        if len(words) >= 2:
            for (w1, w2, w3), count in self._trigrams.items():
                if w1 == words[-2] and w2 == last_word and count > 1:
                    suggestions.append({"text": f"{w2} {w3}", "score": count * 1.5, "type": "trigram"})

        ctx_key = context.lower()[:50]
        for key, responses in self._response_patterns.items():
            if any(word in key for word in words[-3:]):
                for resp in responses[:3]:
                    suggestions.append({"text": resp[:80], "score": 10, "type": "pattern"})

        suggestions.sort(key=lambda x: -x["score"])
        seen = set()
        unique = []
        for s in suggestions:
            if s["text"] not in seen:
                seen.add(s["text"])
                unique.append(s)
        return unique[:limit]

    def _prune_ngrams(self) -> None:
        common_bigrams = self._bigrams.most_common(self._MAX_NGRAMS // 2)
        common_trigrams = self._trigrams.most_common(self._MAX_NGRAMS // 3)
        self._bigrams = Counter(dict(common_bigrams))
        self._trigrams = Counter(dict(common_trigrams))

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            data = {
                "bigrams": dict(self._bigrams.most_common(5000)),
                "trigrams": dict(self._trigrams.most_common(5000)),
                "response_patterns": {k: v[:10] for k, v in list(self._response_patterns.items())[:500]},
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._bigrams = Counter(data.get("bigrams", {}))
            self._trigrams = Counter(data.get("trigrams", {}))
            self._response_patterns = data.get("response_patterns", {})
        except Exception:
            pass
