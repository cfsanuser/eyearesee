import json
import os
import re
import time
from typing import Dict, List, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class AchievementBadges:
    """Tracks and awards achievement badges based on user behavior.

    Badge Categories:
      • Participation    — First Post, Regular, Marathon, Night Owl, Early Bird
      • Social           — Welcomer, Connector, Peacemaker, Popular
      • Knowledge        — Expert, Helper, Source Citer, Fact Checker
      • Communication    — Wordsmith, Concise, Multilingual, Storyteller
      • Dedication       — Veteran, Streak Master, Daily Driver, Year Club
      • Special          — Comeback Kid, Channel Hopper, Meme Lord, Emoji Master
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "achievements.json")

    _BADGE_DEFS = {
        "first_post":       {"name": "First Post",       "icon": "🌟", "desc": "Sent your first message", "category": "Participation"},
        "regular":          {"name": "Regular",          "icon": "⭐", "desc": "Sent 100 messages", "category": "Participation"},
        "marathon":         {"name": "Marathon",         "icon": "🏃", "desc": "Sent 1000 messages", "category": "Participation"},
        "night_owl":        {"name": "Night Owl",        "icon": "🦉", "desc": "Active between 2-5 AM", "category": "Participation"},
        "early_bird":       {"name": "Early Bird",       "icon": "🐦", "desc": "Active between 5-8 AM", "category": "Participation"},
        "welcomer":         {"name": "Welcomer",         "icon": "👋", "desc": "Welcomed 10 new users", "category": "Social"},
        "connector":        {"name": "Connector",        "icon": "🔗", "desc": "Active in 5+ channels", "category": "Social"},
        "peacemaker":       {"name": "Peacemaker",       "icon": "☮️", "desc": "Resolved 5 conflicts", "category": "Social"},
        "popular":          {"name": "Popular",          "icon": "💫", "desc": "Replied to by 20+ users", "category": "Social"},
        "expert":           {"name": "Expert",           "icon": "🎓", "desc": "High technical vocabulary score", "category": "Knowledge"},
        "helper":           {"name": "Helper",           "icon": "🤝", "desc": "Answered 50 questions", "category": "Knowledge"},
        "source_citer":     {"name": "Source Citer",     "icon": "📚", "desc": "Cited 25 sources", "category": "Knowledge"},
        "fact_checker":     {"name": "Fact Checker",     "icon": "🔍", "desc": "Corrected 10 misinformation claims", "category": "Knowledge"},
        "wordsmith":        {"name": "Wordsmith",        "icon": "✍️", "desc": "Sent 10,000 words", "category": "Communication"},
        "concise":          {"name": "Concise",          "icon": "📌", "desc": "Sent 50 messages under 10 chars", "category": "Communication"},
        "multilingual":     {"name": "Multilingual",     "icon": "🌐", "desc": "Used 3+ languages", "category": "Communication"},
        "storyteller":      {"name": "Storyteller",      "icon": "📖", "desc": "Sent 20 messages over 500 chars", "category": "Communication"},
        "veteran":          {"name": "Veteran",          "icon": "🏅", "desc": "Active for 30+ days", "category": "Dedication"},
        "streak_master":    {"name": "Streak Master",    "icon": "🔥", "desc": "7-day activity streak", "category": "Dedication"},
        "daily_driver":     {"name": "Daily Driver",     "icon": "📅", "desc": "Active every day for 14 days", "category": "Dedication"},
        "year_club":        {"name": "Year Club",        "icon": "🎂", "desc": "Active for 365 days", "category": "Dedication"},
        "comeback_kid":     {"name": "Comeback Kid",     "icon": "🔄", "desc": "Returned after 30 days absence", "category": "Special"},
        "channel_hopper":   {"name": "Channel Hopper",   "icon": "🦘", "desc": "Active in 10+ channels", "category": "Special"},
        "meme_lord":        {"name": "Meme Lord",        "icon": "😂", "desc": "Used 50 meme phrases", "category": "Special"},
        "emoji_master":     {"name": "Emoji Master",     "icon": "😀", "desc": "Used 100 unique emojis", "category": "Special"},
    }

    def __init__(self):
        self._user_stats: Dict[str, Dict] = {}
        self._awarded: Dict[str, set] = {}
        self._last_save: float = 0.0
        self.load()

    def observe(self, nick: str, channel: str, text: str, ts: float, replied_to_by: List[str] = None) -> None:
        nl = nick.lower()
        d = self._user_stats.setdefault(nl, {
            "msg_count": 0, "word_count": 0, "total_chars": 0,
            "channels": set(), "first_seen": ts, "last_seen": ts,
            "night_msgs": 0, "morning_msgs": 0, "short_msgs": 0,
            "long_msgs": 0, "welcome_count": 0, "conflict_resolved": 0,
            "questions_answered": 0, "sources_cited": 0, "facts_corrected": 0,
            "unique_emojis": set(), "meme_count": 0, "languages": set(),
            "active_days": set(), "reply_targets": set(), "streak_days": 0,
            "last_active_date": "", "absence_days": 0,
        })
        d["msg_count"] += 1
        d["word_count"] += len(text.split())
        d["total_chars"] += len(text)
        d["last_seen"] = ts
        d["channels"].add(channel.lower())

        hour = time.localtime(ts).tm_hour
        if 2 <= hour < 5:
            d["night_msgs"] += 1
        if 5 <= hour < 8:
            d["morning_msgs"] += 1
        if len(text) < 10:
            d["short_msgs"] += 1
        if len(text) > 500:
            d["long_msgs"] += 1

        day_str = time.strftime("%Y-%m-%d", time.localtime(ts))
        d["active_days"].add(day_str)

        if replied_to_by:
            d["reply_targets"].update(n.lower() for n in replied_to_by)

        lower = text.lower()
        emojis = re.findall(r'[\U0001F600-\U0001F64F\U0001F300-\U0001F5FF\U0001F680-\U0001F6FF\U0001F1E0-\U0001F1FF]', text)
        d["unique_emojis"].update(emojis)

        if any(lower.startswith(p) for p in {"welcome", "hi ", "hey ", "greetings", "wb "}):
            d["welcome_count"] += 1
        if any(w in lower for w in {"study", "research", "paper", "source", "according to", "citation"}):
            d["sources_cited"] += 1
        if "?" in text and any(lower.startswith(q) for q in {"because", "actually", "the answer", "it's", "you can", "try"}):
            d["questions_answered"] += 1

    def check_achievements(self, nick: str) -> List[Dict]:
        nl = nick.lower()
        d = self._user_stats.get(nl)
        if not d:
            return []

        awarded = self._awarded.setdefault(nl, set())
        new_badges = []

        checks = {
            "first_post": d["msg_count"] >= 1,
            "regular": d["msg_count"] >= 100,
            "marathon": d["msg_count"] >= 1000,
            "night_owl": d["night_msgs"] >= 10,
            "early_bird": d["morning_msgs"] >= 10,
            "welcomer": d["welcome_count"] >= 10,
            "connector": len(d["channels"]) >= 5,
            "peacemaker": d["conflict_resolved"] >= 5,
            "popular": len(d["reply_targets"]) >= 20,
            "expert": d["word_count"] >= 5000 and len(d["channels"]) >= 2,
            "helper": d["questions_answered"] >= 50,
            "source_citer": d["sources_cited"] >= 25,
            "fact_checker": d["facts_corrected"] >= 10,
            "wordsmith": d["word_count"] >= 10000,
            "concise": d["short_msgs"] >= 50,
            "multilingual": len(d["languages"]) >= 3,
            "storyteller": d["long_msgs"] >= 20,
            "veteran": (d["last_seen"] - d["first_seen"]) >= 86400 * 30,
            "streak_master": d["streak_days"] >= 7,
            "daily_driver": len(d["active_days"]) >= 14,
            "year_club": (d["last_seen"] - d["first_seen"]) >= 86400 * 365,
            "comeback_kid": d["absence_days"] >= 30,
            "channel_hopper": len(d["channels"]) >= 10,
            "meme_lord": d["meme_count"] >= 50,
            "emoji_master": len(d["unique_emojis"]) >= 100,
        }

        for badge_id, earned in checks.items():
            if earned and badge_id not in awarded:
                awarded.add(badge_id)
                new_badges.append({**self._BADGE_DEFS[badge_id], "id": badge_id, "earned_at": time.time()})

        if new_badges:
            self._maybe_save()
        return new_badges

    def get_badges(self, nick: str) -> List[Dict]:
        nl = nick.lower()
        awarded = self._awarded.get(nl, set())
        return [{**self._BADGE_DEFS[bid], "id": bid} for bid in sorted(awarded)]

    def get_leaderboard(self, limit: int = 20) -> List[Dict]:
        results = []
        for nl, awarded in self._awarded.items():
            d = self._user_stats.get(nl, {})
            results.append({
                "nick": nl,
                "badge_count": len(awarded),
                "badges": list(awarded),
                "msg_count": d.get("msg_count", 0),
                "channels": len(d.get("channels", set())),
            })
        results.sort(key=lambda x: -x["badge_count"])
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
                "user_stats": {k: {**v, "channels": list(v["channels"]), "unique_emojis": list(v["unique_emojis"]), "active_days": list(v["active_days"]), "languages": list(v["languages"]), "reply_targets": list(v["reply_targets"])} for k, v in self._user_stats.items()},
                "awarded": {k: list(v) for k, v in self._awarded.items()},
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            for k, v in data.get("user_stats", {}).items():
                v["channels"] = set(v.get("channels", []))
                v["unique_emojis"] = set(v.get("unique_emojis", []))
                v["active_days"] = set(v.get("active_days", []))
                v["languages"] = set(v.get("languages", []))
                v["reply_targets"] = set(v.get("reply_targets", []))
                self._user_stats[k] = v
            for k, v in data.get("awarded", {}).items():
                self._awarded[k] = set(v)
        except Exception:
            pass
