import json
import os
import time
from collections import Counter
from typing import Dict, List, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class DebateAnalyzer:
    """Analyzes conversations between two users to score argument quality.

    Metrics:
      • Logical fallacies (ad hominem, strawman, appeal to authority, etc.)
      • Evidence usage (citations, data references, examples)
      • Response quality (addresses points, stays on topic, constructive)
      • Tone analysis (respectful, aggressive, dismissive)
      • Turn balance (fair exchange vs domination)
      • Resolution indicators (agreement, compromise, concession)
    """

    _FALLACIES = {
        "ad_hominem": {"you're", "you are", "stupid", "idiot", "moron", "ignorant", "delusional", "clueless", "pathetic"},
        "strawman": {"so you're saying", "you think that", "your position is", "you believe", "apparently you"},
        "appeal_to_authority": {"experts agree", "scientists say", "studies show", "research proves", "authorities confirm"},
        "appeal_to_emotion": {"think of", "imagine if", "how would you feel", "it's heartbreaking", "unacceptable"},
        "false_dichotomy": {"either.*or", "only two options", "black and white", "all or nothing", "with us or against"},
        "slippery_slope": {"will lead to", "next thing", "eventually", "soon they'll", "before you know it"},
        "circular_reasoning": {"because it is", "by definition", "obviously", "self-evident", "inherently"},
        "red_herring": {"but what about", "you're ignoring", "let's not forget", "meanwhile", "distracting from"},
        "bandwagon": {"everyone knows", "most people", "majority agrees", "common sense", "widely accepted"},
        "appeal_to_nature": {"natural", "organic", "chemical-free", "pure", "unnatural"},
    }

    _EVIDENCE_MARKERS = {"study", "research", "paper", "data", "statistics", "according to", "source", "citation", "reference", "peer-reviewed", "meta-analysis", "survey", "experiment", "trial", "evidence", "proof", "demonstrates", "shows that", "indicates"}
    _AGREEMENT_MARKERS = {"i agree", "you're right", "good point", "fair enough", "concede", "you make a valid", "i see your point", "that's true", "agreed", "makes sense", "i hadn't considered"}
    _DISMISSIVE_MARKERS = {"whatever", "doesn't matter", "irrelevant", "who cares", "nobody asked", "so what", "big deal", "yeah right", "sure", "ok boomer"}
    _CONSTRUCTIVE_MARKERS = {"let's consider", "perhaps", "maybe we could", "what if", "another perspective", "building on that", "to add to", "i think we could", "compromise", "middle ground"}

    def __init__(self):
        self._exchanges: Dict[str, List[Dict]] = {}
        self._last_save: float = 0.0
        self.load()

    def record_message(self, nick1: str, nick2: str, channel: str, text: str, ts: float) -> None:
        key = self._debate_key(nick1, nick2, channel)
        exchange = self._exchanges.setdefault(key, {"messages": [], "started": ts, "channel": channel})
        exchange["messages"].append({"nick": nick1.lower(), "text": text, "ts": ts})
        if len(exchange["messages"]) > 200:
            exchange["messages"] = exchange["messages"][-100:]

    def analyze(self, nick1: str, nick2: str, channel: str = "") -> Optional[Dict]:
        key = self._debate_key(nick1, nick2, channel)
        alt_key = self._debate_key(nick2, nick1, channel)
        exchange = self._exchanges.get(key) or self._exchanges.get(alt_key)
        if not exchange or len(exchange["messages"]) < 4:
            return None

        msgs = exchange["messages"]
        n1, n2 = nick1.lower(), nick2.lower()
        n1_msgs = [m for m in msgs if m["nick"] == n1]
        n2_msgs = [m for m in msgs if m["nick"] == n2]

        n1_analysis = self._analyze_user(n1_msgs, n2_msgs)
        n2_analysis = self._analyze_user(n2_msgs, n1_msgs)

        turn_balance = self._turn_balance(msgs, n1, n2)
        resolution = self._check_resolution(msgs)

        return {
            "nick1": nick1, "nick2": nick2, "channel": exchange["channel"],
            "msg_count": len(msgs), "duration_min": round((msgs[-1]["ts"] - msgs[0]["ts"]) / 60, 1),
            "nick1_analysis": n1_analysis, "nick2_analysis": n2_analysis,
            "turn_balance": turn_balance,
            "resolution": resolution,
            "overall_quality": round((n1_analysis["quality_score"] + n2_analysis["quality_score"]) / 2, 3),
        }

    def _analyze_user(self, user_msgs: List[Dict], opponent_msgs: List[Dict]) -> Dict:
        if not user_msgs:
            return {"quality_score": 0.0}

        fallacies_found = []
        evidence_count = 0
        constructive_count = 0
        dismissive_count = 0
        agreement_count = 0
        topic_adherence = 0.0
        total = len(user_msgs)

        for m in user_msgs:
            text = m["text"].lower()
            words = set(text.split())

            for fname, fwords in self._FALLACIES.items():
                if any(w in words for w in fwords):
                    fallacies_found.append(fname)

            if any(w in words for w in self._EVIDENCE_MARKERS):
                evidence_count += 1
            if any(m["text"].lower().startswith(c) for c in self._CONSTRUCTIVE_MARKERS):
                constructive_count += 1
            if any(m["text"].lower().startswith(d) for d in self._DISMISSIVE_MARKERS):
                dismissive_count += 1
            if any(m["text"].lower().startswith(a) for a in self._AGREEMENT_MARKERS):
                agreement_count += 1

        fallacy_rate = len(fallacies_found) / max(total, 1)
        evidence_rate = evidence_count / max(total, 1)
        constructive_rate = constructive_count / max(total, 1)
        dismissive_rate = dismissive_count / max(total, 1)

        quality = 0.5
        quality -= fallacy_rate * 0.3
        quality += evidence_rate * 0.25
        quality += constructive_rate * 0.2
        quality -= dismissive_rate * 0.25
        quality += min(agreement_count / max(total, 1) * 0.1, 0.1)
        quality = max(0.0, min(1.0, quality))

        fallacy_counts = Counter(fallacies_found)
        return {
            "quality_score": round(quality, 3),
            "fallacy_rate": round(fallacy_rate, 3),
            "evidence_rate": round(evidence_rate, 3),
            "constructive_rate": round(constructive_rate, 3),
            "dismissive_rate": round(dismissive_rate, 3),
            "agreement_count": agreement_count,
            "fallacies": dict(fallacy_counts.most_common(5)),
            "msg_count": total,
        }

    def _turn_balance(self, msgs: List[Dict], n1: str, n2: str) -> Dict:
        n1_count = sum(1 for m in msgs if m["nick"] == n1)
        n2_count = sum(1 for m in msgs if m["nick"] == n2)
        total = n1_count + n2_count
        return {
            "nick1_msgs": n1_count, "nick2_msgs": n2_count,
            "ratio": round(n1_count / max(n2_count, 1), 2),
            "balance": round(1.0 - abs(n1_count - n2_count) / max(total, 1), 3),
        }

    def _check_resolution(self, msgs: List[Dict]) -> Dict:
        recent = msgs[-10:]
        agreements = sum(1 for m in recent if any(m["text"].lower().startswith(a) for a in self._AGREEMENT_MARKERS))
        return {
            "indicators": agreements,
            "resolved": agreements >= 2,
            "status": "resolved" if agreements >= 2 else "ongoing" if len(msgs) > 4 else "insufficient data",
        }

    def _debate_key(self, nick1: str, nick2: str, channel: str) -> str:
        n1, n2 = sorted([nick1.lower(), nick2.lower()])
        return f"{n1}:{n2}:{channel.lower()}"

    def get_active_debates(self, channel: str = "", limit: int = 10) -> List[Dict]:
        results = []
        for key, exchange in self._exchanges.items():
            if channel and exchange["channel"].lower() != channel.lower():
                continue
            if len(exchange["messages"]) < 4:
                continue
            parts = key.split(":")
            analysis = self.analyze(parts[0], parts[1], exchange["channel"])
            if analysis:
                results.append(analysis)
        results.sort(key=lambda x: -x["msg_count"])
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
                "exchanges": {k: v for k, v in list(self._exchanges.items())[:50]},
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._exchanges = data.get("exchanges", {})
        except Exception:
            pass
