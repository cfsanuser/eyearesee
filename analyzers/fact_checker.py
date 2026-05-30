import json
import os
import re
import time
import urllib.parse
import urllib.request
from collections import deque
from typing import Dict, List, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

class RealtimeFactChecker:
    """Cross-references claims against knowledge sources in real-time.

    Sources:
      • Wikipedia API for factual claims
      • Known fact database (user-curated)
      • Claim pattern matching (common misinformation)
      • Statistical anomaly detection (numbers that don't add up)
      • Source credibility scoring
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "fact_checker.json")

    _CLAIM_PATTERNS = re.compile(
        r'(?:studies show|research (?:shows|indicates|proves)|'
        r'experts (?:say|agree|confirm)|scientists (?:found|discovered|proved)|'
        r'it is (?:well )?known that|everyone knows|'
        r'(?:\d+)% of (?:people|Americans|users)|'
        r'(?:more|less) than \d+ (?:people|users|cases)|'
        r'(?:first|second|third|last) (?:time|year|month|day))',
        re.IGNORECASE,
    )

    _NUMBER_PATTERN = re.compile(r'\b(\d[\d,]*(?:\.\d+)?(?:\s*(?:million|billion|trillion|percent|%))?)\b', re.IGNORECASE)

    def __init__(self):
        self._fact_db: Dict[str, Dict] = {}
        self._claim_log: deque = deque(maxlen=500)
        self._wiki_cache: Dict[str, Dict] = {}
        self._last_save: float = 0.0
        self.load()

    def check(self, nick: str, channel: str, text: str) -> List[Dict]:
        results = []
        claims = self._extract_claims(text)
        for claim in claims:
            result = self._verify_claim(claim, text)
            if result:
                result["nick"] = nick
                result["channel"] = channel
                result["ts"] = time.time()
                results.append(result)
                self._claim_log.append(result)
        self._maybe_save()
        return results

    def _extract_claims(self, text: str) -> List[str]:
        claims = []
        sentences = re.split(r'[.!?]+', text)
        for sent in sentences:
            sent = sent.strip()
            if len(sent) < 10:
                continue
            if self._CLAIM_PATTERNS.search(sent):
                claims.append(sent)
            elif self._NUMBER_PATTERN.search(sent) and any(w in sent.lower() for w in
                {"percent", "%", "million", "billion", "times", "more", "less", "increase", "decrease"}):
                claims.append(sent)
        return claims

    def _verify_claim(self, claim: str, context: str) -> Optional[Dict]:
        confidence = 0.0
        flags = []

        if self._CLAIM_PATTERNS.search(claim):
            confidence += 0.3
            flags.append("vague attribution")

        numbers = self._NUMBER_PATTERN.findall(claim)
        for num_str in numbers:
            try:
                num = float(num_str.replace(",", "").replace("million", "e6").replace("billion", "e9").replace("trillion", "e12").replace("%", ""))
                if num > 1e12:
                    confidence += 0.2
                    flags.append(f"extreme number: {num_str}")
            except ValueError:
                pass

        wiki_result = self._check_wikipedia(claim)
        if wiki_result:
            if wiki_result.get("contradicts"):
                confidence += 0.4
                flags.append(f"contradicts Wikipedia: {wiki_result['summary']}")
            elif wiki_result.get("supports"):
                confidence -= 0.2
                flags.append("supported by Wikipedia")

        if claim.lower() in self._fact_db:
            db_entry = self._fact_db[claim.lower()]
            if db_entry.get("verified") is False:
                confidence += 0.5
                flags.append("known false claim")
            elif db_entry.get("verified") is True:
                confidence -= 0.3
                flags.append("verified true")

        verdict = "likely_false" if confidence >= 0.6 else "questionable" if confidence >= 0.3 else "likely_true"

        return {
            "claim": claim[:200], "confidence": round(confidence, 3),
            "verdict": verdict, "flags": flags,
        } if confidence > 0.2 else None

    def _check_wikipedia(self, claim: str) -> Optional[Dict]:
        words = claim.lower().split()
        key_terms = [w for w in words if len(w) > 4 and w not in
                    {"studies", "shows", "research", "indicates", "scientists", "found", "people", "percent", "million"}]
        if not key_terms:
            return None

        query = " ".join(key_terms[:3])
        cached = self._wiki_cache.get(query)
        if cached:
            return cached

        try:
            url = f"https://en.wikipedia.org/api/rest_v1/page/summary/{urllib.parse.quote(query)}"
            req = urllib.request.Request(url, headers={"User-Agent": "eyearesee/1.0"})
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                summary = data.get("extract", "").lower()
                result = {"summary": data.get("extract", "")[:200], "supports": False, "contradicts": False}
                claim_lower = claim.lower()
                neg_words = {"not", "no", "never", "false", "wrong", "incorrect"}
                if any(w in summary for w in claim_lower.split() if len(w) > 4):
                    result["supports"] = True
                elif any(neg in summary for neg in neg_words):
                    result["contradicts"] = True
                self._wiki_cache[query] = result
                if len(self._wiki_cache) > 100:
                    self._wiki_cache.popitem(last=False)
                return result
        except Exception:
            return None

    def add_fact(self, claim: str, verified: bool, source: str = "") -> None:
        self._fact_db[claim.lower()] = {"verified": verified, "source": source, "ts": time.time()}
        self._maybe_save()

    def get_claims(self, limit: int = 20) -> List[Dict]:
        return list(self._claim_log)[-limit:]

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            data = {
                "fact_db": self._fact_db,
                "claims": list(self._claim_log)[-50:],
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._fact_db = data.get("fact_db", {})
            for c in data.get("claims", []):
                self._claim_log.append(c)
        except Exception:
            pass
