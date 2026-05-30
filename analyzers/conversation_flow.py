import json
import os
import time
from collections import Counter, deque
from typing import Any, Dict, List

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ConversationFlowPredictor:
    """Predicts who will speak next, when, and about what topic.

    Models:
      * Turn-taking patterns (who responds to whom)
      * Temporal rhythms (time between messages per user)
      * Topic transition probabilities
      * Engagement prediction (likelihood of participation)
      * Conversation lifecycle (winding down, heating up)
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "flow_predictions.json")

    def __init__(self):
        self._turn_patterns: Dict[str, Counter] = {}
        self._temporal_profiles: Dict[str, deque] = {}
        self._topic_transitions: Counter = Counter()
        self._channel_activity: Dict[str, deque] = {}
        self._last_save: float = 0.0
        self.load()

    def record(self, nick: str, channel: str, text: str, reply_to: str = "") -> None:
        nl = nick.lower()
        cl = channel.lower()
        now = time.time()

        if reply_to:
            rt = reply_to.lower()
            self._turn_patterns.setdefault(cl, Counter())[f"{rt}->{nl}"] += 1

        tp = self._temporal_profiles.setdefault(nl, deque(maxlen=100))
        if tp:
            gap = now - tp[-1]
            if gap < 300:
                tp.append(gap)
        tp.append(now)

        activity = self._channel_activity.setdefault(cl, deque(maxlen=200))
        activity.append(now)

        words = text.lower().split()
        if words:
            self._topic_transitions[(words[0], words[-1])] += 1

        self._maybe_save()

    def predict_next_speaker(self, channel: str, current_speaker: str = "", limit: int = 5) -> List[Dict]:
        cl = channel.lower()
        patterns = self._turn_patterns.get(cl, Counter())
        candidates = Counter()

        if current_speaker:
            key_prefix = f"{current_speaker.lower()}->"
            for k, v in patterns.items():
                if k.startswith(key_prefix):
                    target = k.split("->")[1]
                    candidates[target] += v

        activity = self._channel_activity.get(cl, deque())
        if activity:
            recent = [a for a in activity if time.time() - a < 300]
            active_nicks = Counter()
            for a in recent:
                for nl, tp in self._temporal_profiles.items():
                    if tp and abs(tp[-1] - a) < 60:
                        active_nicks[nl] += 1
            for nl, score in active_nicks.most_common(10):
                candidates[nl] += score * 0.5

        total = sum(candidates.values()) or 1
        return [{"nick": n, "probability": round(c / total, 3), "score": c}
                for n, c in candidates.most_common(limit)]

    def predict_conversation_state(self, channel: str) -> Dict[str, Any]:
        cl = channel.lower()
        activity = self._channel_activity.get(cl, deque())
        if not activity:
            return {"state": "unknown", "activity_level": 0}

        now = time.time()
        recent_5min = sum(1 for a in activity if now - a < 300)
        recent_30min = sum(1 for a in activity if now - a < 1800)

        if recent_5min == 0:
            state = "dormant"
        elif recent_5min < 5:
            state = "winding_down" if recent_30min > 20 else "quiet"
        elif recent_5min < 20:
            state = "active"
        else:
            state = "heated"

        return {
            "state": state, "msgs_5min": recent_5min, "msgs_30min": recent_30min,
            "activity_level": min(1.0, recent_5min / 30.0),
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
                "turn_patterns": dict(self._turn_patterns.most_common(1000)),
                "topic_transitions": dict(self._topic_transitions.most_common(500)),
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._turn_patterns = {}
            for k, v in data.get("turn_patterns", {}).items():
                ch = k.split("::")[0] if "::" in k else "default"
                self._turn_patterns.setdefault(ch, Counter())[k] = v
            self._topic_transitions = Counter(data.get("topic_transitions", {}))
        except Exception:
            pass
