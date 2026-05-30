import json
import os
import time
from typing import Dict, List, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class RoleInference:
    """Classifies users into social roles based on behavioral and linguistic patterns.

    Roles:
      • moderator     — enforces rules, uses authoritative language, high channel tenure
      • helper        — answers questions, high reply-to-others ratio, positive sentiment
      • expert        — deep technical vocabulary, long messages, cited by others
      • regular       — consistent presence, balanced participation
      • lurker        — low message count, long gaps, mostly observes
      • troll         — negative sentiment, provocative language, high conflict rate
      • newbie        — asks many questions, short messages, recent join date
      • socializer    — high off-topic ratio, greeting/farewell frequency, emoji use
      • debater       — high argument frequency, logical connectors, counter-statements
      • broadcaster   — shares links/resources, high information density, one-to-many pattern
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "role_inference.json")

    _ROLE_WEIGHTS = {
        "moderator":    {"auth_words": 0.20, "tenure": 0.15, "cmd_usage": 0.15, "reply_ratio": 0.10, "msg_freq": 0.10, "sentiment": 0.05, "conflict": -0.15, "link_share": 0.05, "question_ratio": -0.10, "off_topic": -0.05},
        "helper":       {"auth_words": 0.05, "tenure": 0.10, "cmd_usage": 0.05, "reply_ratio": 0.25, "msg_freq": 0.10, "sentiment": 0.20, "conflict": -0.10, "link_share": 0.05, "question_ratio": -0.10, "off_topic": 0.05},
        "expert":       {"auth_words": 0.10, "tenure": 0.15, "cmd_usage": 0.05, "reply_ratio": 0.15, "msg_freq": 0.10, "sentiment": 0.05, "conflict": 0.00, "link_share": 0.15, "question_ratio": -0.15, "off_topic": -0.10},
        "regular":      {"auth_words": 0.00, "tenure": 0.10, "cmd_usage": 0.00, "reply_ratio": 0.10, "msg_freq": 0.20, "sentiment": 0.05, "conflict": 0.00, "link_share": 0.05, "question_ratio": 0.00, "off_topic": 0.10},
        "lurker":       {"auth_words": 0.00, "tenure": 0.05, "cmd_usage": 0.00, "reply_ratio": 0.05, "msg_freq": -0.20, "sentiment": 0.00, "conflict": 0.00, "link_share": 0.00, "question_ratio": 0.00, "off_topic": 0.00},
        "troll":        {"auth_words": 0.00, "tenure": 0.00, "cmd_usage": 0.00, "reply_ratio": 0.10, "msg_freq": 0.10, "sentiment": -0.25, "conflict": 0.30, "link_share": 0.00, "question_ratio": 0.00, "off_topic": 0.15},
        "newbie":       {"auth_words": 0.00, "tenure": -0.15, "cmd_usage": 0.00, "reply_ratio": 0.10, "msg_freq": 0.05, "sentiment": 0.05, "conflict": 0.00, "link_share": 0.00, "question_ratio": 0.25, "off_topic": 0.10},
        "socializer":   {"auth_words": 0.00, "tenure": 0.05, "cmd_usage": 0.00, "reply_ratio": 0.15, "msg_freq": 0.15, "sentiment": 0.15, "conflict": -0.05, "link_share": 0.00, "question_ratio": 0.00, "off_topic": 0.25},
        "debater":      {"auth_words": 0.05, "tenure": 0.05, "cmd_usage": 0.00, "reply_ratio": 0.20, "msg_freq": 0.15, "sentiment": -0.05, "conflict": 0.20, "link_share": 0.05, "question_ratio": 0.10, "off_topic": -0.05},
        "broadcaster":  {"auth_words": 0.05, "tenure": 0.10, "cmd_usage": 0.05, "reply_ratio": 0.05, "msg_freq": 0.15, "sentiment": 0.05, "conflict": 0.00, "link_share": 0.30, "question_ratio": -0.10, "off_topic": 0.00},
    }

    _AUTH_WORDS = {"should", "must", "rule", "policy", "ban", "kick", "warning", "enforce", "moderator", "admin", "please stop", "read the", "topic is", "stay on", "keep it", "respect", "follow the"}
    _LOGICAL_CONNECTORS = {"however", "therefore", "because", "although", "but", "thus", "hence", "consequently", "nevertheless", "moreover", "furthermore", "whereas", "conversely", "arguably", "counterpoint"}
    _QUESTION_MARKERS = {"what", "how", "why", "when", "where", "who", "which", "can you", "could you", "does anyone", "is there", "anyone know", "help with", "how do i", "what is"}
    _GREETINGS = {"hi", "hello", "hey", "good morning", "good evening", "good night", "welcome", "wb", "welcome back", "greetings", "o/", "sup", "yo"}
    _FAREWELLS = {"bye", "goodbye", "see you", "later", "gtg", "brb", "afk", "goodnight", "cya", "farewell", "o7"}

    def __init__(self):
        self._user_data: Dict[str, Dict] = {}
        self._roles: Dict[str, Dict] = {}
        self._last_save: float = 0.0
        self.load()

    def observe(self, nick: str, channel: str, text: str, is_reply: bool, sentiment_score: float, first_seen: float, now: float) -> None:
        nl = nick.lower()
        ch = channel.lower()
        d = self._user_data.setdefault(nl, {
            "msg_count": 0, "reply_count": 0, "question_count": 0,
            "link_count": 0, "auth_word_count": 0, "connector_count": 0,
            "greeting_count": 0, "farewell_count": 0, "off_topic_count": 0,
            "conflict_count": 0, "total_chars": 0, "first_seen": first_seen,
            "last_seen": 0.0, "channels": set(), "sentiment_sum": 0.0,
        })
        d["msg_count"] += 1
        d["reply_count"] += 1 if is_reply else 0
        d["total_chars"] += len(text)
        d["last_seen"] = now
        d["channels"].add(ch)
        d["sentiment_sum"] += sentiment_score

        lower = text.lower()
        words = set(lower.split())
        if any(w in words for w in self._AUTH_WORDS):
            d["auth_word_count"] += 1
        if any(w in words for w in self._LOGICAL_CONNECTORS):
            d["connector_count"] += 1
        if any(lower.startswith(q) for q in self._QUESTION_MARKERS) or "?" in text:
            d["question_count"] += 1
        if any(lower.startswith(g) for g in self._GREETINGS):
            d["greeting_count"] += 1
        if any(lower.startswith(f) for f in self._FAREWELLS):
            d["farewell_count"] += 1
        if "http://" in lower or "https://" in lower:
            d["link_count"] += 1
        if any(w in words for w in {"stupid", "idiot", "moron", "dumb", "wrong", "shut up", "noob", "fake", "lies"}):
            d["conflict_count"] += 1

    def infer_roles(self, channel: str = "") -> Dict[str, List[Dict]]:
        results: Dict[str, List[Dict]] = {}
        for nl, d in self._user_data.items():
            if channel and channel.lower() not in d["channels"]:
                continue
            if d["msg_count"] < 3:
                continue

            tenure_days = (d["last_seen"] - d["first_seen"]) / 86400.0
            msg_freq = d["msg_count"] / max(tenure_days, 0.01)
            reply_ratio = d["reply_count"] / max(d["msg_count"], 1)
            question_ratio = d["question_count"] / max(d["msg_count"], 1)
            link_ratio = d["link_count"] / max(d["msg_count"], 1)
            avg_sentiment = d["sentiment_sum"] / max(d["msg_count"], 1)
            conflict_ratio = d["conflict_count"] / max(d["msg_count"], 1)
            auth_ratio = d["auth_word_count"] / max(d["msg_count"], 1)
            connector_ratio = d["connector_count"] / max(d["msg_count"], 1)
            off_topic_ratio = (d["greeting_count"] + d["farewell_count"]) / max(d["msg_count"], 1)

            features = {
                "auth_words": auth_ratio,
                "tenure": min(tenure_days / 30.0, 1.0),
                "cmd_usage": auth_ratio * 0.5,
                "reply_ratio": reply_ratio,
                "msg_freq": min(msg_freq / 50.0, 1.0),
                "sentiment": avg_sentiment,
                "conflict": conflict_ratio,
                "link_share": link_ratio,
                "question_ratio": question_ratio,
                "off_topic": off_topic_ratio,
            }

            scores = {}
            for role, weights in self._ROLE_WEIGHTS.items():
                score = sum(weights.get(k, 0) * v for k, v in features.items())
                scores[role] = max(0.0, min(1.0, 0.5 + score))

            primary_role = max(scores, key=scores.get)
            ch_key = channel.lower() if channel else "*"
            results.setdefault(ch_key, []).append({
                "nick": nl,
                "primary_role": primary_role,
                "scores": {k: round(v, 3) for k, v in sorted(scores.items(), key=lambda x: -x[1])},
                "msg_count": d["msg_count"],
                "tenure_days": round(tenure_days, 1),
            })

        for ch in results:
            results[ch].sort(key=lambda x: -x["scores"][x["primary_role"]])
        return results

    def get_role(self, nick: str, channel: str = "") -> Optional[Dict]:
        nl = nick.lower()
        d = self._user_data.get(nl)
        if not d or d["msg_count"] < 3:
            return None
        roles = self.infer_roles(channel)
        ch_key = channel.lower() if channel else "*"
        for r in roles.get(ch_key, []):
            if r["nick"] == nl:
                return r
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
                "user_data": {k: {**v, "channels": list(v["channels"])} for k, v in self._user_data.items()},
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            for k, v in data.get("user_data", {}).items():
                v["channels"] = set(v.get("channels", []))
                self._user_data[k] = v
        except Exception:
            pass
