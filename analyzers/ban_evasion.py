import json
import os
import time
from collections import Counter, deque
from typing import Dict, List, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class BanEvasionDetector:
    """Detects banned users returning with new nicks using biometric and linguistic fingerprints.

    Tracks:
      • Vocabulary overlap (Jaccard similarity)
      • N-gram patterns (bigram/trigram similarity)
      • Timing regularity (inter-message gap distribution)
      • Channel affinity (shared channels, join times)
      • Behavioral markers (message length, punctuation habits)
    
    Provides real-time alerts when a new nick strongly matches a banned profile.
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "ban_evasion.json")
    _EVASION_THRESHOLD = 0.65

    def __init__(self):
        self._banned_profiles: Dict[str, Dict] = {}
        self._user_stats: Dict[str, Dict] = {}
        self._detected_matches: List[Dict] = []
        self._last_save: float = 0.0
        self.load()

    def track_user(self, nick: str, channel: str, text: str, timing_gaps: List[float]) -> None:
        nl = nick.lower()
        stats = self._user_stats.setdefault(nl, {
            "channels": set(), "vocab": set(), "bigrams": Counter(),
            "timing_gaps": deque(maxlen=100), "msg_count": 0,
            "total_chars": 0, "punct_count": 0, "first_seen": time.time(),
        })
        stats["channels"].add(channel.lower())
        stats["msg_count"] += 1
        stats["total_chars"] += len(text)
        stats["punct_count"] += sum(1 for c in text if c in ".,;:!?")

        words = text.lower().split()
        stats["vocab"].update(w.strip(".,;:!?\"'()[]") for w in words if len(w) > 2)
        for i in range(len(words) - 1):
            stats["bigrams"][(words[i], words[i + 1])] += 1

        stats["timing_gaps"].extend(timing_gaps)

    def snapshot_banned(self, nick: str, reason: str = "") -> Optional[Dict]:
        nl = nick.lower()
        stats = self._user_stats.get(nl)
        if not stats or stats["msg_count"] < 3:
            return None

        profile = {
            "nick": nl, "reason": reason, "banned_at": time.time(),
            "channels": set(stats["channels"]), "vocab": set(stats["vocab"]),
            "bigrams": dict(stats["bigrams"].most_common(500)),
            "timing_mean": sum(stats["timing_gaps"]) / max(len(stats["timing_gaps"]), 1),
            "timing_std": (sum((g - sum(stats["timing_gaps"])/len(stats["timing_gaps"]))**2 for g in stats["timing_gaps"]) / max(len(stats["timing_gaps"]), 1))**0.5,
            "avg_msg_len": stats["total_chars"] / max(stats["msg_count"], 1),
            "punct_ratio": stats["punct_count"] / max(stats["total_chars"], 1),
            "msg_count": stats["msg_count"],
        }
        self._banned_profiles[nl] = profile
        self._maybe_save()
        return profile

    def check_evasion(self, nick: str) -> Optional[Dict]:
        nl = nick.lower()
        stats = self._user_stats.get(nl)
        if not stats or stats["msg_count"] < 3:
            return None

        best_match = None
        best_score = 0.0

        for b_nick, b_profile in self._banned_profiles.items():
            if b_nick == nl:
                continue

            # 1. Vocabulary Overlap (Jaccard)
            vocab_sim = len(stats["vocab"] & b_profile["vocab"]) / max(len(stats["vocab"] | b_profile["vocab"]), 1)

            # 2. Bigram Overlap
            user_bigrams = Counter(stats["bigrams"])
            banned_bigrams = Counter(b_profile["bigrams"])
            overlap = sum((user_bigrams & banned_bigrams).values())
            total = sum(user_bigrams.values())
            bigram_sim = overlap / max(total, 1)

            # 3. Timing Similarity
            if stats["timing_gaps"] and b_profile["timing_mean"] > 0:
                u_mean = sum(stats["timing_gaps"]) / len(stats["timing_gaps"])
                u_std = (sum((g - u_mean)**2 for g in stats["timing_gaps"]) / len(stats["timing_gaps"]))**0.5
                mean_diff = abs(u_mean - b_profile["timing_mean"]) / max(b_profile["timing_mean"], 1)
                std_diff = abs(u_std - b_profile["timing_std"]) / max(b_profile["timing_std"], 1)
                timing_sim = max(0, 1.0 - (mean_diff + std_diff) / 2)
            else:
                timing_sim = 0.0

            # 4. Channel Affinity
            chan_sim = len(stats["channels"] & b_profile["channels"]) / max(len(stats["channels"] | b_profile["channels"]), 1)

            # 5. Behavioral Similarity
            len_diff = abs(stats["total_chars"]/max(stats["msg_count"],1) - b_profile["avg_msg_len"]) / max(b_profile["avg_msg_len"], 1)
            punct_diff = abs(stats["punct_count"]/max(stats["total_chars"],1) - b_profile["punct_ratio"])
            behavior_sim = max(0, 1.0 - (len_diff + punct_diff) / 2)

            # Weighted Score
            score = (vocab_sim * 0.30 + bigram_sim * 0.25 + timing_sim * 0.20 + chan_sim * 0.15 + behavior_sim * 0.10)

            if score > best_score and score >= self._EVASION_THRESHOLD:
                best_score = score
                best_match = {
                    "suspect": nick, "banned_nick": b_nick,
                    "score": round(score, 3), "reason": b_profile.get("reason", ""),
                    "details": {
                        "vocab": round(vocab_sim, 3), "bigram": round(bigram_sim, 3),
                        "timing": round(timing_sim, 3), "channel": round(chan_sim, 3), "behavior": round(behavior_sim, 3)
                    },
                    "ts": time.time(),
                }

        if best_match:
            self._detected_matches.append(best_match)
            if len(self._detected_matches) > 50:
                self._detected_matches.pop(0)
            return best_match
        return None

    def list_banned(self) -> List[Dict]:
        return [{"nick": k, **v} for k, v in self._banned_profiles.items()]

    def remove_banned(self, nick: str) -> bool:
        nl = nick.lower()
        if nl in self._banned_profiles:
            del self._banned_profiles[nl]
            self._maybe_save()
            return True
        return False

    def get_matches(self, limit: int = 10) -> List[Dict]:
        return self._detected_matches[-limit:]

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            data = {
                "banned_profiles": {k: {**v, "channels": list(v["channels"]), "vocab": list(v["vocab"])} for k, v in self._banned_profiles.items()},
                "matches": self._detected_matches[-20:],
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            for k, v in data.get("banned_profiles", {}).items():
                v["channels"] = set(v.get("channels", []))
                v["vocab"] = set(v.get("vocab", []))
                self._banned_profiles[k] = v
            self._detected_matches = data.get("matches", [])
        except Exception:
            pass
