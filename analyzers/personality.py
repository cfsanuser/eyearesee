import json
import os
import time
from typing import Any, Dict, List

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PersonalityProfiler:
    """Infers Big Five personality traits from IRC communication patterns.

    Traits measured:
      * Openness: vocabulary diversity, abstract language, topic exploration
      * Conscientiousness: message structure, punctuation accuracy, consistency
      * Extraversion: message frequency, social engagement, exclamation usage
      * Agreeableness: supportive language, conflict avoidance, politeness markers
      * Neuroticism: emotional volatility, negative sentiment, uncertainty markers

    Uses LIWC-inspired linguistic analysis combined with behavioral signals.
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "personality_profiles.json")

    _OPENNESS_MARKERS = frozenset({"imagine", "creative", "explore", "theory", "abstract", "concept", "philosophy", "art", "music", "science"})
    _CONSCIENTIOUSNESS_MARKERS = frozenset({"plan", "organize", "schedule", "deadline", "detail", "precise", "accurate", "method", "system"})
    _EXTRAVERSION_MARKERS = frozenset({"party", "social", "fun", "exciting", "awesome", "love", "great", "everyone", "together"})
    _AGREEABLENESS_MARKERS = frozenset({"thanks", "please", "sorry", "help", "support", "agree", "understand", "appreciate", "kind"})
    _NEUROTICISM_MARKERS = frozenset({"worried", "anxious", "stress", "afraid", "angry", "frustrated", "hate", "terrible", "awful", "can't"})

    def __init__(self):
        self._profiles: Dict[str, Dict] = {}
        self._last_save: float = 0.0
        self.load()

    def update(self, nick: str, text: str) -> Dict[str, float]:
        nl = nick.lower()
        prof = self._profiles.setdefault(nl, {
            "msg_count": 0, "traits": {"openness": 0.5, "conscientiousness": 0.5,
                                       "extraversion": 0.5, "agreeableness": 0.5, "neuroticism": 0.5},
            "word_count": 0, "unique_words": set(), "exclamation_count": 0,
            "question_count": 0, "avg_msg_len": 0.0,
        })
        prof["msg_count"] += 1
        words = text.lower().split()
        prof["word_count"] += len(words)
        prof["unique_words"].update(words)
        prof["exclamation_count"] += text.count("!")
        prof["question_count"] += text.count("?")
        prof["avg_msg_len"] = (prof["avg_msg_len"] * (prof["msg_count"] - 1) + len(text)) / prof["msg_count"]

        word_set = set(words)
        traits = prof["traits"]

        openness = len(word_set & self._OPENNESS_MARKERS) / max(len(words), 1)
        openness += min(0.3, len(prof["unique_words"]) / 500.0)
        traits["openness"] = traits["openness"] * 0.8 + min(1.0, openness) * 0.2

        consc = len(word_set & self._CONSCIENTIOUSNESS_MARKERS) / max(len(words), 1)
        punct_ratio = sum(1 for c in text if c in ".,;:") / max(len(text), 1)
        consc += punct_ratio * 2
        traits["conscientiousness"] = traits["conscientiousness"] * 0.8 + min(1.0, consc) * 0.2

        extra = len(word_set & self._EXTRAVERSION_MARKERS) / max(len(words), 1)
        extra += min(0.3, prof["exclamation_count"] / max(prof["msg_count"], 1) * 0.1)
        traits["extraversion"] = traits["extraversion"] * 0.8 + min(1.0, extra) * 0.2

        agree = len(word_set & self._AGREEABLENESS_MARKERS) / max(len(words), 1)
        traits["agreeableness"] = traits["agreeableness"] * 0.8 + min(1.0, agree * 3) * 0.2

        neuro = len(word_set & self._NEUROTICISM_MARKERS) / max(len(words), 1)
        traits["neuroticism"] = traits["neuroticism"] * 0.8 + min(1.0, neuro * 3) * 0.2

        self._maybe_save()
        return {k: round(v, 3) for k, v in traits.items()}

    def get_profile(self, nick: str) -> Dict[str, Any]:
        nl = nick.lower()
        prof = self._profiles.get(nl)
        if not prof or prof["msg_count"] < 5:
            return {"nick": nick, "samples": prof["msg_count"] if prof else 0, "confidence": "insufficient data"}
        traits = prof["traits"]
        confidence = "high" if prof["msg_count"] >= 50 else "medium" if prof["msg_count"] >= 20 else "low"
        return {
            "nick": nick, "samples": prof["msg_count"], "confidence": confidence,
            "openness": round(traits["openness"] * 100, 1),
            "conscientiousness": round(traits["conscientiousness"] * 100, 1),
            "extraversion": round(traits["extraversion"] * 100, 1),
            "agreeableness": round(traits["agreeableness"] * 100, 1),
            "neuroticism": round(traits["neuroticism"] * 100, 1),
            "vocabulary_size": len(prof["unique_words"]),
            "avg_msg_len": round(prof["avg_msg_len"], 1),
        }

    def get_top_traits(self, trait: str, limit: int = 10) -> List[Dict]:
        results = []
        for nick, prof in self._profiles.items():
            if prof["msg_count"] >= 5:
                results.append({"nick": nick, "score": round(prof["traits"].get(trait, 0.5) * 100, 1),
                               "samples": prof["msg_count"]})
        results.sort(key=lambda x: -x["score"])
        return results[:limit]

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            data = {}
            for nick, prof in self._profiles.items():
                data[nick] = {
                    "msg_count": prof["msg_count"], "traits": prof["traits"],
                    "word_count": prof["word_count"], "exclamation_count": prof["exclamation_count"],
                    "question_count": prof["question_count"], "avg_msg_len": prof["avg_msg_len"],
                    "unique_words": list(prof["unique_words"])[:100],
                }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            for nick, prof in data.items():
                self._profiles[nick] = {
                    "msg_count": prof.get("msg_count", 0),
                    "traits": prof.get("traits", {"openness": 0.5, "conscientiousness": 0.5,
                                                  "extraversion": 0.5, "agreeableness": 0.5, "neuroticism": 0.5}),
                    "word_count": prof.get("word_count", 0),
                    "unique_words": set(prof.get("unique_words", [])),
                    "exclamation_count": prof.get("exclamation_count", 0),
                    "question_count": prof.get("question_count", 0),
                    "avg_msg_len": prof.get("avg_msg_len", 0.0),
                }
        except Exception:
            pass
