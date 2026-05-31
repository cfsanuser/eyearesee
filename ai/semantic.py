import time
from collections import deque
from typing import List, Dict


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
