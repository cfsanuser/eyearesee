import json
import os
import time
from typing import Dict, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class SentimentAICorrelator:
    """Correlates sentiment scores with AI detection scores per nick and channel.

    Tracks:
      • Per-nick sentiment vs AI score distribution
      • Channel-level correlation (do AI messages cluster in specific sentiment ranges?)
      • Anomaly flags (nicks whose sentiment is unnaturally uniform given high AI scores)

    Provides /saicorr to inspect sentiment-AI correlation patterns.
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "sentiment_ai_corr.json")

    def __init__(self):
        self._nick_data: Dict[str, Dict] = {}
        self._channel_data: Dict[str, Dict] = {}
        self._last_save: float = 0.0
        self.load()

    def record(self, nick: str, channel: str, ai_score: float,
               sentiment: float, intensity: float = 0.0) -> None:
        nl = nick.lower()
        cl = channel.lower()
        entry = {
            "ai": ai_score, "sentiment": sentiment,
            "intensity": intensity, "ts": time.time(),
        }
        nd = self._nick_data.setdefault(nl, {"samples": [], "channel": cl})
        nd["samples"].append(entry)
        if len(nd["samples"]) > 200:
            nd["samples"] = nd["samples"][-200:]
        cd = self._channel_data.setdefault(cl, {"samples": []})
        cd["samples"].append(entry)
        if len(cd["samples"]) > 500:
            cd["samples"] = cd["samples"][-500:]
        self._maybe_save()

    def get_nick_correlation(self, nick: str) -> Dict:
        nl = nick.lower()
        nd = self._nick_data.get(nl, {})
        samples = nd.get("samples", [])
        if len(samples) < 3:
            return {"nick": nick, "samples": len(samples), "correlation": None,
                    "ai_sentiment_avg": None, "anomaly": False}
        ai_scores = [s["ai"] for s in samples]
        sent_scores = [s["sentiment"] for s in samples]
        high_ai = [s for s in samples if s["ai"] >= 60]
        low_ai = [s for s in samples if s["ai"] < 40]
        correlation = self._pearson_r(ai_scores, sent_scores)
        ai_sent_avg = (sum(s["sentiment"] for s in high_ai) / len(high_ai)) if high_ai else None
        human_sent_avg = (sum(s["sentiment"] for s in low_ai) / len(low_ai)) if low_ai else None
        sent_variance = self._variance(sent_scores)
        anomaly = len(high_ai) >= 3 and sent_variance < 0.02
        return {
            "nick": nick, "samples": len(samples),
            "correlation": round(correlation, 3) if correlation is not None else None,
            "ai_sentiment_avg": round(ai_sent_avg, 3) if ai_sent_avg is not None else None,
            "human_sentiment_avg": round(human_sent_avg, 3) if human_sent_avg is not None else None,
            "sentiment_variance": round(sent_variance, 4),
            "high_ai_count": len(high_ai),
            "anomaly": anomaly,
            "anomaly_reason": "uniform sentiment with high AI scores" if anomaly else "",
        }

    def get_channel_correlation(self, channel: str) -> Dict:
        cl = channel.lower()
        cd = self._channel_data.get(cl, {})
        samples = cd.get("samples", [])
        if len(samples) < 5:
            return {"channel": channel, "samples": len(samples), "correlation": None}
        ai_scores = [s["ai"] for s in samples]
        sent_scores = [s["sentiment"] for s in samples]
        high_ai = [s for s in samples if s["ai"] >= 60]
        low_ai = [s for s in samples if s["ai"] < 40]
        correlation = self._pearson_r(ai_scores, sent_scores)
        ai_sent_avg = (sum(s["sentiment"] for s in high_ai) / len(high_ai)) if high_ai else None
        human_sent_avg = (sum(s["sentiment"] for s in low_ai) / len(low_ai)) if low_ai else None
        ai_int_avg = (sum(s["intensity"] for s in high_ai) / len(high_ai)) if high_ai else None
        human_int_avg = (sum(s["intensity"] for s in low_ai) / len(low_ai)) if low_ai else None
        return {
            "channel": channel, "samples": len(samples),
            "correlation": round(correlation, 3) if correlation is not None else None,
            "ai_sentiment_avg": round(ai_sent_avg, 3) if ai_sent_avg is not None else None,
            "human_sentiment_avg": round(human_sent_avg, 3) if human_sent_avg is not None else None,
            "ai_intensity_avg": round(ai_int_avg, 3) if ai_int_avg is not None else None,
            "human_intensity_avg": round(human_int_avg, 3) if human_int_avg is not None else None,
            "high_ai_pct": round(len(high_ai) / len(samples) * 100, 1),
        }

    def get_top_anomalies(self, limit: int = 10) -> list:
        results = []
        for nick, data in self._nick_data.items():
            corr = self.get_nick_correlation(nick)
            if corr["anomaly"]:
                results.append(corr)
        results.sort(key=lambda x: -x.get("high_ai_count", 0))
        return results[:limit]

    @staticmethod
    def _pearson_r(xs: list, ys: list) -> Optional[float]:
        n = len(xs)
        if n < 3:
            return None
        mean_x = sum(xs) / n
        mean_y = sum(ys) / n
        cov = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys))
        var_x = sum((x - mean_x) ** 2 for x in xs)
        var_y = sum((y - mean_y) ** 2 for y in ys)
        denom = (var_x * var_y) ** 0.5
        if denom == 0:
            return None
        return cov / denom

    @staticmethod
    def _variance(xs: list) -> float:
        if not xs:
            return 0.0
        mean = sum(xs) / len(xs)
        return sum((x - mean) ** 2 for x in xs) / len(xs)

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump({"nicks": self._nick_data, "channels": self._channel_data}, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._nick_data = data.get("nicks", {})
            self._channel_data = data.get("channels", {})
        except Exception:
            pass
