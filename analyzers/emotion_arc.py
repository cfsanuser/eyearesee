import json
import os
import time
from collections import Counter
from typing import Dict, List

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class EmotionArc:
    """Tracks emotional journey over time for users.

    Emotions tracked:
      • joy        — happiness, excitement, satisfaction
      • anger      — frustration, rage, annoyance
      • sadness    — disappointment, grief, melancholy
      • fear       — anxiety, worry, concern
      • surprise   — shock, amazement, disbelief
      • disgust    — contempt, revulsion, disapproval
      • neutral    — baseline, factual, unemotional

    Provides:
      • Per-user emotion timeline
      • Emotion transition patterns
      • Dominant emotion per time window
      • Emotional volatility scoring
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "emotion_arc.json")

    _EMOTION_LEXICON = {
        "joy": {"happy", "joy", "excited", "great", "awesome", "love", "wonderful", "amazing", "fantastic", "excellent", "celebrate", "yay", "woohoo", "thrilled", "delighted", "pleased", "glad", "smile", "laugh", "fun", "enjoy", "beautiful", "perfect", "brilliant", "superb", "outstanding", "magnificent", "marvelous", "splendid", "grateful", "thankful", "blessed", "fortunate", "lucky"},
        "anger": {"angry", "mad", "furious", "rage", "hate", "annoyed", "frustrated", "irritated", "pissed", "outraged", "infuriated", "livid", "enraged", "hostile", "aggressive", "violent", "threat", "attack", "destroy", "kill", "stupid", "idiot", "moron", "dumb", "useless", "worthless", "garbage", "trash", "disgusting", "revolting", "sickening"},
        "sadness": {"sad", "depressed", "unhappy", "miserable", "grief", "sorrow", "cry", "tears", "lonely", "alone", "lost", "hopeless", "despair", "heartbroken", "devastated", "crushed", "disappointed", "regret", "sorry", "miss", "missing", "pain", "hurt", "suffering", "tragic", "tragedy", "unfortunate", "pity", "poor"},
        "fear": {"scared", "afraid", "fear", "terrified", "anxious", "worried", "nervous", "panic", "dread", "horror", "frightened", "alarmed", "concerned", "uneasy", "tense", "stress", "paranoid", "phobia", "threatened", "danger", "dangerous", "risk", "unsafe", "insecure", "vulnerable", "helpless"},
        "surprise": {"surprised", "shocked", "amazed", "astonished", "stunned", "wow", "omg", "unbelievable", "incredible", "unexpected", "suddenly", "whoa", "gasp", "jaw-dropping", "mind-blowing", "remarkable", "extraordinary", "phenomenal", "miracle", "miraculous"},
        "disgust": {"disgust", "disgusting", "gross", "nasty", "revolting", "sickening", "repulsive", "contempt", "despise", "loathe", "abhor", "detest", "vile", "foul", "repugnant", "offensive", "obnoxious", "awful", "horrible", "terrible", "dreadful", "atrocious", "abysmal", "appalling"},
    }

    _EMOTION_TRANSITIONS = {
        ("joy", "anger"): "frustrated happiness",
        ("anger", "joy"): "reconciliation",
        ("sadness", "joy"): "recovery",
        ("joy", "sadness"): "disappointment",
        ("fear", "anger"): "defensive aggression",
        ("anger", "sadness"): "defeat",
        ("surprise", "joy"): "delight",
        ("surprise", "fear"): "alarm",
        ("disgust", "anger"): "moral outrage",
    }

    def __init__(self):
        self._user_emotions: Dict[str, List[Dict]] = {}
        self._last_save: float = 0.0
        self.load()

    def analyze(self, nick: str, text: str, ts: float = None) -> Dict:
        if ts is None:
            ts = time.time()
        nl = nick.lower()
        lower = text.lower()
        words = set(lower.split())

        emotion_scores = {}
        for emotion, lexicon in self._EMOTION_LEXICON.items():
            matches = words & lexicon
            emotion_scores[emotion] = len(matches) / max(len(words), 1)

        # Normalize to get dominant emotion
        total = sum(emotion_scores.values())
        if total > 0:
            for e in emotion_scores:
                emotion_scores[e] = emotion_scores[e] / total
        else:
            emotion_scores["neutral"] = 1.0

        dominant = max(emotion_scores, key=emotion_scores.get)
        confidence = emotion_scores[dominant]

        # Track transition
        prev_emotion = None
        user_history = self._user_emotions.get(nl, [])
        if user_history:
            prev_emotion = user_history[-1]["dominant"]

        transition = None
        if prev_emotion and prev_emotion != dominant:
            transition = self._EMOTION_TRANSITIONS.get((prev_emotion, dominant), f"{prev_emotion}\u2192{dominant}")

        result = {
            "nick": nick,
            "text": text[:80],
            "emotions": {k: round(v, 3) for k, v in sorted(emotion_scores.items(), key=lambda x: -x[1])},
            "dominant": dominant,
            "confidence": round(confidence, 3),
            "prev_emotion": prev_emotion,
            "transition": transition,
            "ts": ts,
        }

        self._user_emotions.setdefault(nl, []).append(result)
        if len(self._user_emotions.get(nl, [])) > 200:
            self._user_emotions[nl] = self._user_emotions[nl][-100:]

        self._maybe_save()
        return result

    def get_arc(self, nick: str, window: int = 50) -> Dict:
        nl = nick.lower()
        history = self._user_emotions.get(nl, [])[-window:]
        if not history:
            return {"nick": nick, "arc": [], "summary": {}}

        emotion_counts = Counter(h["dominant"] for h in history)
        total = len(history)

        # Volatility: how often emotions change
        changes = sum(1 for i in range(1, len(history)) if history[i]["dominant"] != history[i-1]["dominant"])
        volatility = changes / max(total - 1, 1)

        # Transitions
        transitions = [h["transition"] for h in history if h.get("transition")]
        transition_counts = Counter(transitions)

        # Time-based summary
        time_buckets = {}
        for h in history:
            hour = time.localtime(h["ts"]).tm_hour
            bucket = hour // 4
            time_buckets.setdefault(bucket, []).append(h["dominant"])

        dominant_by_period = {}
        period_names = {"0": "night (0-4)", "1": "morning (4-8)", "2": "day (8-16)", "3": "evening (16-24)"}
        for bucket, emotions in time_buckets.items():
            dominant_by_period[period_names[str(bucket)]] = Counter(emotions).most_common(1)[0][0]

        return {
            "nick": nick,
            "arc": [{"dominant": h["dominant"], "confidence": h["confidence"], "ts": h["ts"], "transition": h.get("transition")} for h in history],
            "summary": {
                "total_messages": total,
                "emotion_distribution": {k: round(v / total, 3) for k, v in emotion_counts.items()},
                "volatility": round(volatility, 3),
                "top_transitions": dict(transition_counts.most_common(5)),
                "dominant_by_period": dominant_by_period,
                "most_common_emotion": emotion_counts.most_common(1)[0][0] if emotion_counts else "neutral",
            },
        }

    def compare_arcs(self, nick1: str, nick2: str, window: int = 50) -> Dict:
        arc1 = self.get_arc(nick1, window)
        arc2 = self.get_arc(nick2, window)
        if not arc1["arc"] or not arc2["arc"]:
            return {"error": "Not enough data for both users"}

        # Emotional alignment: how often they share the same dominant emotion
        times1 = {h["ts"]: h["dominant"] for h in arc1["arc"]}
        times2 = {h["ts"]: h["dominant"] for h in arc2["arc"]}
        common_times = set(times1.keys()) & set(times2.keys())
        if common_times:
            matches = sum(1 for t in common_times if times1[t] == times2[t])
            alignment = matches / len(common_times)
        else:
            alignment = 0.0

        return {
            "nick1": nick1,
            "nick2": nick2,
            "alignment": round(alignment, 3),
            "nick1_dominant": arc1["summary"]["most_common_emotion"],
            "nick2_dominant": arc2["summary"]["most_common_emotion"],
            "nick1_volatility": arc1["summary"]["volatility"],
            "nick2_volatility": arc2["summary"]["volatility"],
        }

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            data = {
                "user_emotions": {k: [{"dominant": h["dominant"], "confidence": h["confidence"], "ts": h["ts"], "transition": h.get("transition")} for h in v] for k, v in self._user_emotions.items()},
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._user_emotions = data.get("user_emotions", {})
        except Exception:
            pass
