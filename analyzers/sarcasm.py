import json
import os
import re
import time
from typing import Dict, List

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class SarcasmDetector:
    """Detects sarcastic messages via sentiment-text mismatch and linguistic markers.

    Signals:
      • Sentiment mismatch — positive words in negative context (or vice versa)
      • Exaggeration markers — "oh great", "fantastic", "just what I needed"
      • Punctuation cues — excessive ellipsis, quotes, exclamation marks
      • Emotion-word inversion — positive adjectives with negative verbs
      • Context contradiction — agrees then immediately contradicts
      • Sarcasm lexicon — known sarcastic phrases and patterns
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "sarcasm.json")
    _SARCASM_THRESHOLD = 0.60

    _SARCASM_PHRASES = {
        "oh great", "oh wonderful", "oh fantastic", "oh brilliant", "oh perfect",
        "just what i needed", "just what i wanted", "just what i always wanted",
        "yeah right", "sure thing", "of course", "naturally", "obviously",
        "thanks a lot", "thanks for nothing", "real helpful", "very helpful",
        "good to know", "good job", "well done", "nice going", "way to go",
        "i'm so impressed", "how original", "how unique", "how creative",
        "big surprise", "no way", "you don't say", "tell me something i don't know",
        "fascinating", "riveting", "groundbreaking", "revolutionary",
        "shocking", "unbelievable", "incredible", "amazing",
    }

    _EXAGGERATION_MARKERS = {"so", "very", "extremely", "incredibly", "absolutely", "totally", "completely", "utterly", "really", "super", "mega", "hyper"}
    _POSITIVE_WORDS = {"great", "wonderful", "fantastic", "amazing", "awesome", "excellent", "perfect", "brilliant", "superb", "outstanding", "love", "best", "good", "nice", "happy", "glad", "thrilled", "delighted", "pleased"}
    _NEGATIVE_WORDS = {"terrible", "awful", "horrible", "disgusting", "worst", "bad", "hate", "stupid", "idiotic", "ridiculous", "absurd", "pathetic", "useless", "worthless", "dreadful", "miserable", "annoying", "frustrating"}

    _PUNCTUATION_PATTERNS = [
        (re.compile(r'\.{3,}'), "ellipsis"),
        (re.compile(r'!{2,}'), "exclamation"),
        (re.compile(r'".*?"'), "quotes"),
        (re.compile(r'\(sarcasm\)|\/s|<sarcasm>', re.IGNORECASE), "explicit"),
    ]

    def __init__(self):
        self._user_messages: Dict[str, List[Dict]] = {}
        self._detected: List[Dict] = []
        self._last_save: float = 0.0
        self.load()

    def analyze(self, nick: str, text: str, sentiment_score: float) -> Dict:
        nl = nick.lower()
        lower = text.lower()
        words = set(lower.split())
        score = 0.0
        signals = []

        # 1. Sarcasm phrase match
        phrase_matches = sum(1 for p in self._SARCASM_PHRASES if p in lower)
        if phrase_matches > 0:
            score += min(phrase_matches * 0.25, 0.5)
            signals.append(f"phrase_match({phrase_matches})")

        # 2. Sentiment mismatch
        has_positive = bool(words & self._POSITIVE_WORDS)
        has_negative = bool(words & self._NEGATIVE_WORDS)
        if has_positive and sentiment_score < -0.3:
            score += 0.3
            signals.append("positive_words_negative_sentiment")
        elif has_negative and sentiment_score > 0.3:
            score += 0.3
            signals.append("negative_words_positive_sentiment")

        # 3. Exaggeration + positive/negative combo
        has_exaggeration = bool(words & self._EXAGGERATION_MARKERS)
        if has_exaggeration and (has_positive or has_negative):
            score += 0.15
            signals.append("exaggeration")

        # 4. Punctuation patterns
        punct_signals = []
        for pattern, name in self._PUNCTUATION_PATTERNS:
            if pattern.search(text):
                punct_signals.append(name)
                if name == "explicit":
                    score += 0.8
                else:
                    score += 0.1
        if punct_signals:
            signals.append(f"punctuation({','.join(punct_signals)})")

        # 5. Context contradiction (check recent messages)
        user_msgs = self._user_messages.get(nl, [])[-5:]
        if len(user_msgs) >= 2:
            recent_sentiments = [m["sentiment"] for m in user_msgs]
            if len(recent_sentiments) >= 2:
                avg_recent = sum(recent_sentiments[:-1]) / len(recent_sentiments[:-1])
                if (avg_recent > 0.3 and sentiment_score < -0.3) or \
                   (avg_recent < -0.3 and sentiment_score > 0.3):
                    score += 0.2
                    signals.append("context_contradiction")

        # 6. Question + statement mismatch
        if "?" in text and has_positive:
            score += 0.1
            signals.append("rhetorical_question")

        score = min(score, 1.0)
        is_sarcastic = score >= self._SARCASM_THRESHOLD

        result = {
            "nick": nick,
            "text": text[:100],
            "score": round(score, 3),
            "is_sarcastic": is_sarcastic,
            "signals": signals,
            "ts": time.time(),
        }

        self._user_messages.setdefault(nl, []).append({
            "text": text,
            "sentiment": sentiment_score,
            "score": score,
            "ts": time.time(),
        })
        if len(self._user_messages.get(nl, [])) > 100:
            self._user_messages[nl] = self._user_messages[nl][-50:]

        if is_sarcastic:
            self._detected.append(result)
            if len(self._detected) > 200:
                self._detected = self._detected[-100:]
            self._maybe_save()

        return result

    def get_user_sarcasm_rate(self, nick: str, limit: int = 50) -> Dict:
        nl = nick.lower()
        msgs = self._user_messages.get(nl, [])[-limit:]
        if not msgs:
            return {"nick": nick, "sarcasm_rate": 0.0, "total_analyzed": 0}
        sarcastic = sum(1 for m in msgs if m["score"] >= self._SARCASM_THRESHOLD)
        return {
            "nick": nick,
            "sarcasm_rate": round(sarcastic / len(msgs), 3),
            "total_analyzed": len(msgs),
            "sarcastic_count": sarcastic,
            "avg_score": round(sum(m["score"] for m in msgs) / len(msgs), 3),
        }

    def get_recent_detections(self, limit: int = 20) -> List[Dict]:
        return self._detected[-limit:]

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            data = {
                "user_messages": {k: v[-20:] for k, v in self._user_messages.items()},
                "detected": self._detected[-50:],
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._user_messages = data.get("user_messages", {})
            self._detected = data.get("detected", [])
        except Exception:
            pass
