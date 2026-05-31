import time
from typing import Dict, Any


class BehavioralAnomalyDetector:
    """Detects sudden changes in a user's behavioral patterns.

    Tracks:
      • Message length distribution
      • Sentiment distribution
      • Timing patterns (messages per minute)
      • Vocabulary richness
      • Punctuation usage

    Flags when a user's recent behavior deviates significantly from their
    historical baseline (z-score > 2.0).
    """

    def __init__(self, window_size: int = 50):
        self.window_size = window_size
        self._user_profiles: Dict[str, Dict] = {}

    def _get_profile(self, nick: str) -> Dict:
        if nick not in self._user_profiles:
            self._user_profiles[nick] = {
                "msg_lengths": [],
                "sentiments": [],
                "gaps": [],
                "vocab_sizes": [],
                "punct_ratios": [],
                "last_ts": None,
                "anomaly_count": 0,
                "last_anomaly_ts": 0,
            }
        return self._user_profiles[nick]

    def update(self, nick: str, msg: str, sentiment_score: float) -> Dict[str, Any]:
        """Update user profile and return anomaly analysis.

        Returns dict with:
          anomaly_score – 0..1 (higher = more anomalous)
          changed_aspects – list of aspects that changed significantly
          explanation – human-readable summary
        """
        prof = self._get_profile(nick)
        now = time.time()

        # Compute current metrics
        msg_len = len(msg)
        words = msg.split()
        vocab_size = len(set(w.lower() for w in words))
        punct_count = sum(1 for c in msg if c in ".,!?;:\"'()[]-")
        punct_ratio = punct_count / max(len(msg), 1)

        # Timing gap
        gap = 0.0
        if prof["last_ts"] is not None:
            gap = now - prof["last_ts"]
        prof["last_ts"] = now

        # Update rolling windows
        prof["msg_lengths"].append(msg_len)
        prof["sentiments"].append(sentiment_score)
        prof["vocab_sizes"].append(vocab_size)
        prof["punct_ratios"].append(punct_ratio)
        if gap > 0:
            prof["gaps"].append(gap)

        # Trim to window size
        for key in ("msg_lengths", "sentiments", "vocab_sizes", "punct_ratios", "gaps"):
            if len(prof[key]) > self.window_size:
                prof[key] = prof[key][-self.window_size:]

        # Need at least 10 samples to detect anomalies
        if len(prof["msg_lengths"]) < 10:
            return {
                "anomaly_score": 0.0,
                "changed_aspects": [],
                "explanation": "Insufficient data for anomaly detection",
            }

        # Compute z-scores for each aspect
        anomalies = []
        _calc_z = lambda lst, val: self._z_score(lst, val)

        len_z = _calc_z(prof["msg_lengths"][:-1], msg_len)
        sent_z = _calc_z(prof["sentiments"][:-1], sentiment_score)
        vocab_z = _calc_z(prof["vocab_sizes"][:-1], vocab_size)
        punct_z = _calc_z(prof["punct_ratios"][:-1], punct_ratio)

        # Gap anomaly (sudden burst or long silence)
        gap_z = 0.0
        if len(prof["gaps"]) >= 5:
            gap_z = _calc_z(prof["gaps"][:-1], gap)

        # Threshold: z-score > 2.0 = significant deviation
        if abs(len_z) > 2.0:
            anomalies.append(f"message length {'dramatically longer' if len_z > 0 else 'much shorter'} than usual")
        if abs(sent_z) > 2.0:
            anomalies.append(f"sentiment {'unusually positive' if sent_z > 0 else 'much more negative'} than usual")
        if abs(vocab_z) > 2.0:
            anomalies.append(f"vocabulary {'much richer' if vocab_z > 0 else 'much simpler'} than usual")
        if abs(punct_z) > 2.0:
            anomalies.append(f"punctuation usage {'much higher' if punct_z > 0 else 'much lower'} than usual")
        if abs(gap_z) > 2.0:
            anomalies.append(f"timing {'sudden burst' if gap_z < 0 else 'long silence'} detected")

        # Composite anomaly score
        max_z = max(abs(len_z), abs(sent_z), abs(vocab_z), abs(punct_z), abs(gap_z))
        anomaly_score = min(1.0, max_z / 4.0)

        # Track anomaly frequency
        if anomaly_score > 0.5:
            prof["anomaly_count"] += 1
            prof["last_anomaly_ts"] = now

        explanation = ""
        if anomalies:
            explanation = f"{nick}: " + "; ".join(anomalies)

        return {
            "anomaly_score": round(anomaly_score, 3),
            "changed_aspects": anomalies,
            "explanation": explanation,
            "z_scores": {
                "length": round(len_z, 2),
                "sentiment": round(sent_z, 2),
                "vocabulary": round(vocab_z, 2),
                "punctuation": round(punct_z, 2),
                "timing": round(gap_z, 2),
            },
        }

    @staticmethod
    def _z_score(data: list, value: float) -> float:
        if len(data) < 2:
            return 0.0
        mean = sum(data) / len(data)
        variance = sum((x - mean) ** 2 for x in data) / len(data)
        std = variance ** 0.5
        if std < 1e-6:
            return 0.0
        return (value - mean) / std
