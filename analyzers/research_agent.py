import json
import os
import re
import time
import urllib.parse
import urllib.request
from collections import deque
from typing import Any, Dict, List, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class AutonomousResearchAgent:
    """AI agent that reads channel conversations, identifies knowledge gaps,
    fetches relevant information, and provides summaries.

    Capabilities:
      • Topic detection and knowledge gap identification
      • Web search and summarization
      • Context-aware information delivery
      • Learning from feedback (useful/not useful)
      • Proactive assistance (detects confusion, offers help)
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "research_agent.json")

    def __init__(self):
        self._channel_context: Dict[str, deque] = {}
        self._knowledge_gaps: List[Dict] = []
        self._research_results: Dict[str, Dict] = {}
        self._feedback_log: deque = deque(maxlen=200)
        self._enabled: bool = False
        self._last_save: float = 0.0
        self.load()

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    def observe(self, nick: str, channel: str, text: str) -> List[Dict]:
        if not self._enabled:
            return []

        cl = channel.lower()
        ctx = self._channel_context.setdefault(cl, deque(maxlen=100))
        ctx.append({"nick": nick, "text": text, "ts": time.time()})

        gaps = self._identify_gaps(cl, text)
        results = []
        for gap in gaps:
            research = self._research(gap)
            if research:
                results.append(research)
                self._knowledge_gaps.append({**gap, **research, "ts": time.time()})
                if len(self._knowledge_gaps) > 100:
                    self._knowledge_gaps.pop(0)

        confusion = self._detect_confusion(cl, text)
        if confusion:
            research = self._research(confusion)
            if research:
                results.append(research)

        self._maybe_save()
        return results

    def _identify_gaps(self, channel: str, text: str) -> List[Dict]:
        gaps = []
        questions = re.findall(r'(?:what|who|where|when|why|how|which|is there|are there|does|do|can|could)\s+[^?]+\?', text, re.IGNORECASE)
        for q in questions:
            gaps.append({"type": "question", "query": q.strip(), "channel": channel})

        entities = re.findall(r'\b([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\b', text)
        for entity in entities:
            if len(entity) > 3 and entity not in {"The", "This", "That", "These", "Those"}:
                gaps.append({"type": "entity", "query": entity, "channel": channel})

        return gaps[:3]

    def _detect_confusion(self, channel: str, text: str) -> Optional[Dict]:
        confusion_markers = {"confused", "don't understand", "dont understand", "what does",
                           "what is", "how does", "how do", "explain", "clarify", "meaning"}
        text_lower = text.lower()
        if any(m in text_lower for m in confusion_markers):
            words = text_lower.split()
            query = " ".join(words[max(0, words.index("what") if "what" in words else 0):])[:100]
            return {"type": "confusion", "query": query, "channel": channel}
        return None

    def _research(self, gap: Dict) -> Optional[Dict]:
        query = gap["query"]
        try:
            url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(query)}"
            req = urllib.request.Request(url, headers={"User-Agent": "eyearesee/1.0"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                summary = data.get("extract", "")
                if summary and len(summary) > 20:
                    return {
                        "query": query, "summary": summary[:300],
                        "url": data.get("content_urls", {}).get("desktop", {}).get("page", ""),
                        "type": gap["type"],
                    }
        except Exception:
            pass
        return None

    def record_feedback(self, query: str, useful: bool) -> None:
        self._feedback_log.append({"query": query, "useful": useful, "ts": time.time()})

    def get_recent_research(self, limit: int = 10) -> List[Dict]:
        return self._knowledge_gaps[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        useful = sum(1 for f in self._feedback_log if f.get("useful"))
        total = len(self._feedback_log)
        return {
            "enabled": self._enabled,
            "gaps_identified": len(self._knowledge_gaps),
            "feedback_useful_pct": round(useful / max(total, 1) * 100, 1),
            "total_feedback": total,
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
                "knowledge_gaps": self._knowledge_gaps[-50:],
                "feedback": list(self._feedback_log)[-100:],
                "enabled": self._enabled,
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._knowledge_gaps = data.get("knowledge_gaps", [])
            for fb in data.get("feedback", []):
                self._feedback_log.append(fb)
            self._enabled = data.get("enabled", False)
        except Exception:
            pass
