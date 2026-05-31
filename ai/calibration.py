import json
import os
import time
from typing import Dict, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class AICalibrationManager:
    """Manages AI detection confidence calibration using feedback history.

    Tracks:
      • Per-nick feedback (ai/human labels with associated scores)
      • Per-signal accuracy (how often each heuristic signal correlates with feedback)
      • Adaptive thresholds (auto-tuned from feedback distribution)
      • Calibration curve data (binned accuracy vs. predicted score)

    Provides /aicalibrate to inspect and adjust calibration.
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "ai_calibration.json")

    def __init__(self):
        self._feedback: list = []
        self._signal_stats: Dict[str, Dict] = {}
        self._thresholds: Dict[str, float] = {
            "ai_confirm": 70.0,
            "human_confirm": 30.0,
            "review": 50.0,
        }
        self._score_bins: Dict[str, int] = {}
        self._last_save: float = 0.0
        self.load()

    def record_feedback(self, nick: str, label: str, ai_score: float,
                        signal_scores: Dict = None) -> None:
        entry = {
            "nick": nick,
            "label": label,
            "ai_score": ai_score,
            "signal_scores": signal_scores or {},
            "ts": time.time(),
        }
        self._feedback.append(entry)
        self._update_signal_stats(entry)
        self._update_score_bins(ai_score, label)
        self._auto_adjust_thresholds()
        self._maybe_save()

    def _update_signal_stats(self, entry: dict) -> None:
        label = entry["label"]
        signals = entry.get("signal_scores", {})
        for sig_name, sig_val in signals.items():
            stats = self._signal_stats.setdefault(sig_name, {
                "ai_total": 0.0, "ai_count": 0,
                "human_total": 0.0, "human_count": 0,
            })
            if label == "ai":
                stats["ai_total"] += sig_val
                stats["ai_count"] += 1
            else:
                stats["human_total"] += sig_val
                stats["human_count"] += 1

    def _update_score_bins(self, ai_score: float, label: str) -> None:
        bin_key = f"{int(ai_score / 10) * 10}-{int(ai_score / 10) * 10 + 9}"
        self._score_bins.setdefault(bin_key, 0)
        if label == "ai":
            self._score_bins[bin_key] = self._score_bins.get(bin_key, 0) + 1

    def _auto_adjust_thresholds(self) -> None:
        if len(self._feedback) < 5:
            return
        ai_scores = [e["ai_score"] for e in self._feedback if e["label"] == "ai"]
        human_scores = [e["ai_score"] for e in self._feedback if e["label"] == "human"]
        if not ai_scores or not human_scores:
            return
        ai_avg = sum(ai_scores) / len(ai_scores)
        human_avg = sum(human_scores) / len(human_scores)
        midpoint = (ai_avg + human_avg) / 2.0
        spread = abs(ai_avg - human_avg)
        if spread < 10:
            return
        self._thresholds["review"] = midpoint
        self._thresholds["ai_confirm"] = midpoint + spread * 0.25
        self._thresholds["human_confirm"] = midpoint - spread * 0.25

    def get_signal_reliability(self) -> Dict[str, Dict]:
        results: Dict[str, Dict] = {}
        for sig, stats in self._signal_stats.items():
            ai_avg = stats["ai_total"] / stats["ai_count"] if stats["ai_count"] else 0
            human_avg = stats["human_total"] / stats["human_count"] if stats["human_count"] else 0
            separation = abs(ai_avg - human_avg)
            results[sig] = {
                "ai_avg": round(ai_avg, 3),
                "human_avg": round(human_avg, 3),
                "separation": round(separation, 3),
                "ai_count": stats["ai_count"],
                "human_count": stats["human_count"],
                "reliable": separation > 0.1 and stats["ai_count"] >= 3 and stats["human_count"] >= 3,
            }
        return results

    def get_thresholds(self) -> Dict[str, float]:
        return dict(self._thresholds)

    def get_summary(self) -> Dict:
        ai_count = sum(1 for e in self._feedback if e["label"] == "ai")
        human_count = sum(1 for e in self._feedback if e["label"] == "human")
        return {
            "total_feedback": len(self._feedback),
            "ai_confirmations": ai_count,
            "human_corrections": human_count,
            "thresholds": self.get_thresholds(),
            "signals": len(self._signal_stats),
            "recent": self._feedback[-5:],
        }

    def get_weight_adjustments(self) -> Dict[str, float]:
        reliability = self.get_signal_reliability()
        adj: Dict[str, float] = {}
        for sig, info in reliability.items():
            if info["reliable"]:
                if info["ai_avg"] > info["human_avg"]:
                    adj[sig] = min(0.05, info["separation"] * 0.1)
                else:
                    adj[sig] = -min(0.05, info["separation"] * 0.1)
            else:
                adj[sig] = 0.0
        return adj

    def reset(self) -> None:
        self._feedback.clear()
        self._signal_stats.clear()
        self._score_bins.clear()
        self._thresholds = {
            "ai_confirm": 70.0,
            "human_confirm": 30.0,
            "review": 50.0,
        }
        self._save()

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 60:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump({
                    "feedback": self._feedback[-200:],
                    "signal_stats": self._signal_stats,
                    "thresholds": self._thresholds,
                    "score_bins": self._score_bins,
                }, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._feedback = data.get("feedback", [])
            self._signal_stats = data.get("signal_stats", {})
            self._thresholds = data.get("thresholds", self._thresholds)
            self._score_bins = data.get("score_bins", {})
        except Exception:
            pass
