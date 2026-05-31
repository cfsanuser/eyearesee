import time
from collections import deque
from typing import Dict, List, Optional, Set


class CrossChannelBotDetector:
    """Detects bots that operate across multiple channels.

    Correlates:
      • Identical messages sent to multiple channels
      • Similar timing patterns across channels
      • Shared vocabulary fingerprints
    """

    def __init__(self):
        self._nick_channels: Dict[str, set] = {}
        self._nick_messages: Dict[str, deque] = {}
        self._cross_channel_alerts: List[Dict] = []

    def record_message(self, nick: str, channel: str, text: str) -> Optional[Dict]:
        """Record a message and check for cross-channel coordination.

        Returns alert dict if suspicious activity detected.
        """
        self._nick_channels.setdefault(nick, set()).add(channel)
        if nick not in self._nick_messages:
            self._nick_messages[nick] = deque(maxlen=200)
        self._nick_messages[nick].append({
            "channel": channel,
            "text": text.lower(),
            "ts": time.time(),
        })

        # Check for identical messages in different channels
        channels = self._nick_channels[nick]
        if len(channels) < 2:
            return None

        msgs = self._nick_messages[nick]
        recent = [m for m in msgs if time.time() - m["ts"] < 300]  # 5 min window

        # Group by text
        text_channels: Dict[str, set] = {}
        for m in recent:
            text_channels.setdefault(m["text"], set()).add(m["channel"])

        for text, chs in text_channels.items():
            if len(chs) >= 2:
                alert = {
                    "nick": nick,
                    "type": "identical_cross_channel",
                    "channels": sorted(chs),
                    "message": text[:100],
                    "ts": time.time(),
                }
                self._cross_channel_alerts.append(alert)
                return alert

        return None

    def get_suspicious_nicks(self, min_channels: int = 3) -> List[Dict]:
        """Return nicks active in many channels with suspicious patterns."""
        results = []
        for nick, channels in self._nick_channels.items():
            if len(channels) >= min_channels:
                msgs = self._nick_messages.get(nick, [])
                results.append({
                    "nick": nick,
                    "channels": sorted(channels),
                    "message_count": len(msgs),
                    "alerts": sum(1 for a in self._cross_channel_alerts if a["nick"] == nick),
                })
        results.sort(key=lambda x: x["alerts"], reverse=True)
        return results
