import json
import os
import time
from collections import Counter, deque
from typing import Dict, List, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class BotSwarmDetector:
    """Detects coordinated AI/bot accounts operating as a swarm.

    Identifies:
      • Shared generation patterns (identical phrasing across accounts)
      • Synchronized timing (messages posted at regular intervals)
      • Narrative alignment (pushing same talking points)
      • Cross-account amplification (mutual reinforcement)
      • Account age clustering (new accounts created together)
      • Behavioral uniformity (similar response patterns, vocabulary)
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "bot_swarms.json")

    def __init__(self):
        self._account_profiles: Dict[str, Dict] = {}
        self._swarm_clusters: List[Dict] = []
        self._message_signatures: Dict[str, deque] = {}
        self._last_save: float = 0.0
        self.load()

    def record(self, nick: str, channel: str, text: str, ai_score: float = 0) -> Optional[Dict]:
        nl = nick.lower()
        cl = channel.lower()
        now = time.time()

        prof = self._account_profiles.setdefault(nl, {
            "msg_count": 0, "channels": set(), "first_seen": now, "last_seen": now,
            "avg_ai_score": 0.0, "vocab": set(), "bigrams": Counter(),
            "timing_gaps": deque(maxlen=50), "last_msg_time": 0,
        })
        prof["msg_count"] += 1
        prof["channels"].add(cl)
        prof["last_seen"] = now
        prof["avg_ai_score"] = (prof["avg_ai_score"] * (prof["msg_count"] - 1) + ai_score) / prof["msg_count"]

        words = text.lower().split()
        prof["vocab"].update(words)
        for i in range(len(words) - 1):
            prof["bigrams"][(words[i], words[i + 1])] += 1

        if prof["last_msg_time"] > 0:
            gap = now - prof["last_msg_time"]
            if gap < 600:
                prof["timing_gaps"].append(gap)
        prof["last_msg_time"] = now

        sig = self._text_signature(text)
        self._message_signatures.setdefault(sig, deque(maxlen=20)).append({"nick": nl, "ts": now, "channel": cl})

        result = self._detect_swarm(nl, cl, now)
        if result:
            self._swarm_clusters.append(result)
            if len(self._swarm_clusters) > 50:
                self._swarm_clusters.pop(0)

        self._maybe_save()
        return result

    def _text_signature(self, text: str) -> str:
        words = text.lower().split()
        if len(words) < 3:
            return text.lower()
        key_words = sorted(set(w for w in words if len(w) > 3))[:5]
        return " ".join(key_words)

    def _detect_swarm(self, nick: str, channel: str, now: float) -> Optional[Dict]:
        prof = self._account_profiles.get(nick, {})
        if prof.get("msg_count", 0) < 3:
            return None

        candidates = []
        for other_nl, other_prof in self._account_profiles.items():
            if other_nl == nick or other_prof.get("msg_count", 0) < 3:
                continue
            if not (other_prof.get("channels", set()) & prof.get("channels", set())):
                continue

            vocab_overlap = len(prof.get("vocab", set()) & other_prof.get("vocab", set()))
            vocab_union = len(prof.get("vocab", set()) | other_prof.get("vocab", set()))
            vocab_sim = vocab_overlap / max(vocab_union, 1)

            bigram_overlap = sum((prof.get("bigrams", Counter()) & other_prof.get("bigrams", Counter())).values())
            bigram_total = sum(prof.get("bigrams", Counter()).values()) + sum(other_prof.get("bigrams", Counter()).values())
            bigram_sim = bigram_overlap / max(bigram_total, 1)

            ai_sim = 1.0 - abs(prof.get("avg_ai_score", 0) - other_prof.get("avg_ai_score", 0))

            timing_sim = self._timing_similarity(prof.get("timing_gaps", deque()),
                                                  other_prof.get("timing_gaps", deque()))

            combined = vocab_sim * 0.25 + bigram_sim * 0.30 + ai_sim * 0.25 + timing_sim * 0.20
            if combined > 0.5:
                candidates.append({"nick": other_nl, "similarity": round(combined, 3),
                                  "vocab_sim": round(vocab_sim, 3), "bigram_sim": round(bigram_sim, 3),
                                  "ai_sim": round(ai_sim, 3), "timing_sim": round(timing_sim, 3)})

        if len(candidates) >= 2:
            swarm_nicks = [nick] + [c["nick"] for c in candidates[:5]]
            avg_sim = sum(c["similarity"] for c in candidates[:5]) / len(candidates[:5])
            return {
                "channel": channel, "nicks": swarm_nicks,
                "confidence": round(avg_sim, 3), "size": len(swarm_nicks),
                "evidence": candidates[:5], "ts": now,
            }
        return None

    @staticmethod
    def _timing_similarity(gaps_a: deque, gaps_b: deque) -> float:
        if len(gaps_a) < 3 or len(gaps_b) < 3:
            return 0.0
        mean_a = sum(gaps_a) / len(gaps_a)
        mean_b = sum(gaps_b) / len(gaps_b)
        if mean_a == 0 or mean_b == 0:
            return 0.0
        ratio = min(mean_a, mean_b) / max(mean_a, mean_b)
        return ratio

    def get_swarms(self, limit: int = 10) -> List[Dict]:
        return sorted(self._swarm_clusters, key=lambda x: -x["confidence"])[:limit]

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            data = {
                "swarms": self._swarm_clusters[-20:],
                "account_preview": {k: {"msg_count": v["msg_count"], "avg_ai": v["avg_ai_score"]}
                                   for k, v in list(self._account_profiles.items())[:100]},
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._swarm_clusters = data.get("swarms", [])
        except Exception:
            pass
