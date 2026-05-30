import json
import os
import time
from typing import Dict, List, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class EchoChamberDetector:
    """Measures opinion homogeneity and cross-pollination in channels.

    Metrics:
      • Sentiment consensus — how aligned are users' sentiments?
      • Vocabulary overlap — do users share the same lexicon?
      • Agreement ratio — how often do users affirm each other?
      • Dissent suppression — are contrary voices ignored or attacked?
      • Cross-channel exposure — do users participate in diverse channels?
      • Information diversity — range of topics discussed
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "echo_chamber.json")
    _AGREEMENT_PHRASES = {"i agree", "you're right", "good point", "exactly", "true", "agreed", "makes sense", "that's right", "absolutely", "definitely", "for sure", "no doubt", "well said", "couldn't agree more"}
    _DISSENT_PHRASES = {"i disagree", "not true", "that's wrong", "incorrect", "nope", "false", "i don't think so", "hardly", "doubt it", "that's not", "you're mistaken"}
    _ATTACK_PHRASES = {"stupid", "idiot", "moron", "shut up", "you're dumb", "ignorant", "delusional", "clueless", "wake up", "brainwashed"}

    def __init__(self):
        self._channel_data: Dict[str, Dict] = {}
        self._user_channel_map: Dict[str, set] = {}
        self._last_save: float = 0.0
        self.load()

    def observe(self, nick: str, channel: str, text: str, sentiment_score: float) -> None:
        ch = channel.lower()
        nl = nick.lower()
        cd = self._channel_data.setdefault(ch, {
            "msg_count": 0, "sentiment_scores": [], "vocab": set(),
            "agreement_count": 0, "dissent_count": 0, "attack_count": 0,
            "topic_set": set(), "user_sentiments": {}, "users": set(),
        })
        cd["msg_count"] += 1
        cd["sentiment_scores"].append(sentiment_score)
        cd["users"].add(nl)
        cd["user_sentiments"].setdefault(nl, []).append(sentiment_score)

        words = set(text.lower().split())
        cd["vocab"].update(w for w in words if len(w) > 3)

        lower = text.lower()
        if any(lower.startswith(p) for p in self._AGREEMENT_PHRASES):
            cd["agreement_count"] += 1
        if any(lower.startswith(p) for p in self._DISSENT_PHRASES):
            cd["dissent_count"] += 1
        if any(p in lower for p in self._ATTACK_PHRASES):
            cd["attack_count"] += 1

        self._user_channel_map.setdefault(nl, set()).add(ch)

    def analyze(self, channel: str) -> Optional[Dict]:
        ch = channel.lower()
        cd = self._channel_data.get(ch)
        if not cd or cd["msg_count"] < 10:
            return None

        sentiment_scores = cd["sentiment_scores"]
        avg_sentiment = sum(sentiment_scores) / len(sentiment_scores)
        sentiment_std = (sum((s - avg_sentiment)**2 for s in sentiment_scores) / len(sentiment_scores))**0.5
        sentiment_consensus = max(0, 1.0 - sentiment_std)

        user_sentiments = {}
        for user, scores in cd["user_sentiments"].items():
            user_sentiments[user] = sum(scores) / len(scores)

        if len(user_sentiments) >= 2:
            vals = list(user_sentiments.values())
            mean_vals = sum(vals) / len(vals)
            user_std = (sum((v - mean_vals)**2 for v in vals) / len(vals))**0.5
            opinion_homogeneity = max(0, 1.0 - user_std)
        else:
            opinion_homogeneity = 1.0

        total_responses = cd["agreement_count"] + cd["dissent_count"] + cd["attack_count"]
        agreement_ratio = cd["agreement_count"] / max(total_responses, 1)
        dissent_ratio = cd["dissent_count"] / max(total_responses, 1)
        attack_ratio = cd["attack_count"] / max(total_responses, 1)

        dissent_suppression = 1.0 if (attack_ratio > 0.3 and dissent_ratio < 0.1) else (attack_ratio * 2)

        cross_channel_scores = []
        for user in cd["users"]:
            user_channels = self._user_channel_map.get(user, set())
            cross_channel_scores.append(len(user_channels))
        avg_cross_channel = sum(cross_channel_scores) / max(len(cross_channel_scores), 1)
        cross_channel_exposure = min(avg_cross_channel / 5.0, 1.0)

        topic_diversity = min(len(cd["topic_set"]) / 10.0, 1.0)

        echo_score = (
            sentiment_consensus * 0.20 +
            opinion_homogeneity * 0.25 +
            agreement_ratio * 0.20 +
            dissent_suppression * 0.15 +
            (1.0 - cross_channel_exposure) * 0.10 +
            (1.0 - topic_diversity) * 0.10
        )

        if echo_score >= 0.7:
            severity = "strong"
        elif echo_score >= 0.5:
            severity = "moderate"
        elif echo_score >= 0.3:
            severity = "mild"
        else:
            severity = "open"

        return {
            "channel": channel,
            "echo_score": round(echo_score, 3),
            "severity": severity,
            "metrics": {
                "sentiment_consensus": round(sentiment_consensus, 3),
                "opinion_homogeneity": round(opinion_homogeneity, 3),
                "agreement_ratio": round(agreement_ratio, 3),
                "dissent_ratio": round(dissent_ratio, 3),
                "attack_ratio": round(attack_ratio, 3),
                "dissent_suppression": round(dissent_suppression, 3),
                "cross_channel_exposure": round(cross_channel_exposure, 3),
                "topic_diversity": round(topic_diversity, 3),
            },
            "user_count": len(cd["users"]),
            "msg_count": cd["msg_count"],
        }

    def analyze_all(self) -> List[Dict]:
        results = []
        for ch in self._channel_data:
            result = self.analyze(ch)
            if result:
                results.append(result)
        results.sort(key=lambda x: -x["echo_score"])
        return results

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            data = {
                "channel_data": {k: {**v, "vocab": list(v["vocab"])[:500], "topic_set": list(v["topic_set"])[:200], "users": list(v["users"])} for k, v in self._channel_data.items()},
                "user_channel_map": {k: list(v) for k, v in self._user_channel_map.items()},
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            for k, v in data.get("channel_data", {}).items():
                v["vocab"] = set(v.get("vocab", []))
                v["topic_set"] = set(v.get("topic_set", []))
                v["users"] = set(v.get("users", []))
                self._channel_data[k] = v
            for k, v in data.get("user_channel_map", {}).items():
                self._user_channel_map[k] = set(v)
        except Exception:
            pass
