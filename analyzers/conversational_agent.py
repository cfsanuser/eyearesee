import json
import os
import random
import time
import urllib.parse
import urllib.request
from collections import deque
from typing import Any, Dict, List, Optional

_SCRIPT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_ANTHROPIC_AVAILABLE = False
_ANTHROPIC_API_KEY = ""
_OPENAI_AVAILABLE = False
_OPENAI_API_KEY = ""
_GEMINI_AVAILABLE = False
_GEMINI_API_KEY = ""
_OLLAMA_URL = ""
_LLAMACPP_URL = ""
_AI_MODELS: Dict[str, Dict[str, str]] = {}
_globals_initialized = False

def _init_globals():
    global _ANTHROPIC_AVAILABLE, _ANTHROPIC_API_KEY, _OPENAI_AVAILABLE, _OPENAI_API_KEY
    global _GEMINI_AVAILABLE, _GEMINI_API_KEY, _OLLAMA_URL, _LLAMACPP_URL, _AI_MODELS
    global _globals_initialized
    if _globals_initialized:
        return
    _globals_initialized = True
    try:
        import eyearesee as _eya
        _ANTHROPIC_AVAILABLE = getattr(_eya, 'ANTHROPIC_AVAILABLE', False)
        _ANTHROPIC_API_KEY = getattr(_eya, 'ANTHROPIC_API_KEY', '')
        _OPENAI_AVAILABLE = getattr(_eya, 'OPENAI_AVAILABLE', False)
        _OPENAI_API_KEY = getattr(_eya, 'OPENAI_API_KEY', '')
        _GEMINI_AVAILABLE = getattr(_eya, 'GEMINI_AVAILABLE', False)
        _GEMINI_API_KEY = getattr(_eya, 'GEMINI_API_KEY', '')
        _OLLAMA_URL = getattr(_eya, 'OLLAMA_URL', '')
        _LLAMACPP_URL = getattr(_eya, 'LLAMACPP_URL', '')
        _AI_MODELS = getattr(_eya, 'AI_MODELS', {})
    except Exception:
        pass


class ConversationalAgent:
    """LLM-powered conversational agent that participates naturally in IRC.

    Capabilities:
      • Configurable personalities (helpful, sarcastic, expert, casual, etc.)
      • Long-term memory of conversations per channel
      • Context-aware responses using LLM
      • Responds when addressed by nick or participates proactively
      • Rate limiting to avoid flooding
      • Topic awareness and learning from interactions
      • Can summarize conversations, answer questions, debate topics
    """

    _SAVE_PATH = os.path.join(_SCRIPT_DIR, "conversational_agent.json")

    PERSONALITIES = {
        "helpful": {
            "system": "You are a helpful, friendly IRC participant. Be concise (max 2-3 sentences), use casual language, and avoid sounding like an AI. Don't use phrases like 'as an AI' or 'I'd be happy to'. Just chat naturally.",
            "temperature": 0.7,
        },
        "sarcastic": {
            "system": "You are a witty, slightly sarcastic IRC participant. Use dry humor, be clever but not mean. Keep responses short (1-2 sentences). Sound like a real person who's seen it all.",
            "temperature": 0.8,
        },
        "expert": {
            "system": "You are a knowledgeable expert participating in IRC. Provide accurate, concise information. Cite sources when possible. Keep responses under 3 sentences. Use technical language appropriately.",
            "temperature": 0.5,
        },
        "casual": {
            "system": "You are a casual IRC user chatting with friends. Use informal language, slang, and abbreviations naturally. Keep responses short (1-2 sentences). Be relatable and authentic.",
            "temperature": 0.9,
        },
        "debater": {
            "system": "You enjoy intellectual debate and discussion. Present thoughtful counterarguments, ask probing questions, and engage deeply with ideas. Stay respectful. Keep responses to 2-3 sentences.",
            "temperature": 0.7,
        },
        "mentor": {
            "system": "You are a wise mentor figure. Offer guidance, ask thought-provoking questions, and help others think through problems. Be patient and encouraging. Keep responses concise (2-3 sentences).",
            "temperature": 0.6,
        },
    }

    def __init__(self):
        self._enabled: bool = False
        self._personality: str = "helpful"
        self._nick: str = ""
        self._channel_context: Dict[str, deque] = {}
        self._long_term_memory: Dict[str, List[Dict]] = {}
        self._response_cooldowns: Dict[str, float] = {}
        self._participation_rate: float = 0.1
        self._max_response_len: int = 300
        self._respond_to_mentions: bool = True
        self._proactive_participation: bool = True
        self._last_response_time: float = 0.0
        self._min_response_interval: float = 5.0
        self._conversation_summaries: Dict[str, str] = {}
        self._user_preferences: Dict[str, Dict] = {}
        self._last_save: float = 0.0
        self._llm_model: str = "gemma4"  # default model for /agent
        self.load()

    def configure(self, **kwargs) -> None:
        if "personality" in kwargs and kwargs["personality"] in self.PERSONALITIES:
            self._personality = kwargs["personality"]
        if "nick" in kwargs:
            self._nick = kwargs["nick"]
        if "participation_rate" in kwargs:
            self._participation_rate = max(0.0, min(1.0, float(kwargs["participation_rate"])))
        if "max_response_len" in kwargs:
            self._max_response_len = int(kwargs["max_response_len"])
        if "respond_to_mentions" in kwargs:
            self._respond_to_mentions = bool(kwargs["respond_to_mentions"])
        if "proactive_participation" in kwargs:
            self._proactive_participation = bool(kwargs["proactive_participation"])
        if "min_response_interval" in kwargs:
            self._min_response_interval = float(kwargs["min_response_interval"])
        if "llm_model" in kwargs:
            self._llm_model = kwargs["llm_model"]

    def enable(self) -> None:
        self._enabled = True

    def disable(self) -> None:
        self._enabled = False

    def observe(self, nick: str, channel: str, text: str, is_mention: bool = False) -> Optional[str]:
        if not self._enabled:
            return None

        cl = channel.lower()
        now = time.time()

        ctx = self._channel_context.setdefault(cl, deque(maxlen=50))
        ctx.append({"nick": nick, "text": text, "ts": now})

        self._long_term_memory.setdefault(cl, []).append({
            "nick": nick, "text": text, "ts": now,
        })
        if len(self._long_term_memory[cl]) > 200:
            self._long_term_memory[cl] = self._long_term_memory[cl][-200:]

        if nick.lower() == self._nick.lower():
            return None

        if now - self._last_response_time < self._min_response_interval:
            return None

        should_respond = False
        if is_mention and self._respond_to_mentions:
            should_respond = True
        elif self._proactive_participation:
            should_respond = self._should_participate(cl, nick, text)

        if should_respond:
            response = self._generate_response(cl, nick, text)
            if response:
                self._last_response_time = now
                self._response_cooldowns[cl] = now
                return response
        return None

    def _should_participate(self, channel: str, nick: str, text: str) -> bool:
        ctx = self._channel_context.get(channel, deque())
        if len(ctx) < 2:
            return False

        last_response = self._response_cooldowns.get(channel, 0)
        cooldown = max(5.0, 30.0 * (1.0 - self._participation_rate))
        if time.time() - last_response < cooldown:
            return False

        rate = self._participation_rate

        text_lower = text.lower()
        question_markers = {"?", "what", "how", "why", "who", "when", "where", "does", "is there", "can someone"}
        if any(m in text_lower for m in question_markers):
            return random.random() < min(1.0, rate * 1.5)

        topic_keywords = {"help", "explain", "thoughts", "opinion", "agree", "disagree", "think", "know"}
        if any(k in text_lower for k in topic_keywords):
            return random.random() < min(1.0, rate * 1.2)

        if self._nick and self._nick.lower() in text_lower:
            return random.random() < min(1.0, rate * 1.3)

        return random.random() < rate

    def _generate_response(self, channel: str, nick: str, text: str) -> Optional[str]:
        ctx = self._channel_context.get(channel, deque())
        recent = list(ctx)[-10:]

        context_str = "\n".join(f"{m['nick']}: {m['text']}" for m in recent)

        personality = self.PERSONALITIES.get(self._personality, self.PERSONALITIES["helpful"])
        system_prompt = personality["system"]

        user_prompt = (
            f"Channel: {channel}\n"
            f"Recent conversation:\n{context_str}\n\n"
            f"{nick} just said: {text}\n\n"
            f"Generate a natural response (max {self._max_response_len} chars):"
        )

        try:
            response = self._call_llm(system_prompt, user_prompt, personality["temperature"])
            if response and len(response.strip()) > 0:
                return response.strip()[:self._max_response_len]
        except Exception:
            pass

        return self._fallback_response(nick, text)

    def _fallback_response(self, nick: str, text: str) -> str:
        text_lower = text.lower()
        question_markers = ["?", "what", "how", "why", "who", "when", "where"]
        is_question = any(m in text_lower for m in question_markers)

        fallbacks = {
            "helpful": [
                f"Good question, {nick}! Let me think about that...",
                f"Interesting point, {nick}. I'd say it depends on the context.",
                f"Thanks for sharing that, {nick}! Anyone else have thoughts?",
                f"Hmm, {nick} raises a good point there.",
                f"I see what you mean, {nick}. That's worth considering.",
            ],
            "sarcastic": [
                f"Wow, {nick}, groundbreaking insight there.",
                f"Ah yes, {nick}, because that's definitely how it works.",
                f"Riveting stuff, {nick}. Truly.",
                f"Sure, {nick}. And I'm the Queen of England.",
                f"Bold take, {nick}. Bold but wrong.",
            ],
            "expert": [
                f"Actually, {nick}, the data suggests otherwise.",
                f"From a technical standpoint, {nick}, there are a few factors to consider.",
                f"Research indicates that's not entirely accurate, {nick}.",
                f"The evidence points in a different direction, {nick}.",
                f"Let me clarify that, {nick} \u2014 it's more nuanced than that.",
            ],
            "casual": [
                f"yeah {nick}, i feel you on that",
                f"lol true {nick}",
                f"eh, could go either way {nick}",
                f"fair point {nick}, fair point",
                f"nah {nick}, not really buying that",
            ],
            "debater": [
                f"I'd challenge that assumption, {nick}. What's your evidence?",
                f"Interesting position, {nick}, but have you considered the counterargument?",
                f"I disagree, {nick}. Here's why...",
                f"That's a common misconception, {nick}. Let me explain.",
                f"Let's test that claim, {nick}. Does it hold up under scrutiny?",
            ],
            "mentor": [
                f"Good thinking, {nick}. What led you to that conclusion?",
                f"That's a thoughtful observation, {nick}. Let's explore it further.",
                f"I appreciate your perspective, {nick}. Have you considered...?",
                f"Wise words, {nick}. What do others think?",
                f"Keep exploring that idea, {nick}. You're onto something.",
            ],
        }

        personality_fallbacks = fallbacks.get(self._personality, fallbacks["helpful"])

        if is_question:
            question_fallbacks = [
                f"Good question, {nick}! I'd say it depends.",
                f"Hmm, {nick}, that's a tough one.",
                f"Let me think about that, {nick}...",
                f"Interesting question, {nick}. What do others think?",
            ]
            return random.choice(question_fallbacks)

        return random.choice(personality_fallbacks)

    def _call_llm(self, system_prompt: str, user_prompt: str, temperature: float) -> Optional[str]:
        _init_globals()
        if _ANTHROPIC_AVAILABLE and _ANTHROPIC_API_KEY:
            return self._call_claude(system_prompt, user_prompt, temperature)
        elif _OPENAI_AVAILABLE and _OPENAI_API_KEY:
            return self._call_openai(system_prompt, user_prompt, temperature)
        elif _GEMINI_AVAILABLE and _GEMINI_API_KEY:
            return self._call_gemini(system_prompt, user_prompt, temperature)
        elif _OLLAMA_URL:
            return self._call_ollama(system_prompt, user_prompt, temperature)
        elif _LLAMACPP_URL:
            return self._call_llamacpp(system_prompt, user_prompt, temperature)
        return None

    def _call_claude(self, system_prompt: str, user_prompt: str, temperature: float) -> Optional[str]:
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=_ANTHROPIC_API_KEY)
            response = client.messages.create(
                model="claude-haiku-4-5-20251001",
                max_tokens=200,
                temperature=temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return response.content[0].text
        except Exception:
            return None

    def _call_openai(self, system_prompt: str, user_prompt: str, temperature: float) -> Optional[str]:
        try:
            import openai
            client = openai.OpenAI(api_key=_OPENAI_API_KEY)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                max_tokens=200,
                temperature=temperature,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return response.choices[0].message.content
        except Exception:
            return None

    def _call_gemini(self, system_prompt: str, user_prompt: str, temperature: float) -> Optional[str]:
        try:
            from google import genai
            client = genai.Client(api_key=_GEMINI_API_KEY)
            response = client.models.generate_content(
                model="gemini-2.0-flash",
                contents=f"{system_prompt}\n\n{user_prompt}",
                config={"temperature": temperature, "max_output_tokens": 200},
            )
            return response.text
        except Exception:
            return None

    def _call_ollama(self, system_prompt: str, user_prompt: str, temperature: float) -> Optional[str]:
        try:
            url = f"{_OLLAMA_URL}/api/generate"
            payload = {
                "model": "llama3.2",
                "prompt": f"{system_prompt}\n\n{user_prompt}",
                "stream": False,
                "options": {"temperature": temperature, "num_predict": 200},
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                return data.get("response", "")
        except Exception:
            return None

    def _call_llamacpp(self, system_prompt: str, user_prompt: str, temperature: float) -> Optional[str]:
        try:
            model_spec = _AI_MODELS.get(self._llm_model, _AI_MODELS.get("gemma4"))
            model_id = model_spec.get("id", "gemma-4")
            body = json.dumps({
                "model": model_id,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                "max_tokens": 200,
                "temperature": temperature,
                "stream": False,
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{_LLAMACPP_URL}/v1/chat/completions",
                data=body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            return (data.get("choices", [{}])[0]
                        .get("message", {})
                        .get("content", ""))
        except Exception:
            return None

    def summarize_conversation(self, channel: str, limit: int = 20) -> str:
        ctx = self._channel_context.get(channel.lower(), deque())
        recent = list(ctx)[-limit:]
        if not recent:
            return "No recent conversation."

        context_str = "\n".join(f"{m['nick']}: {m['text']}" for m in recent)
        summary_prompt = (
            f"Summarize this IRC conversation in 2-3 sentences:\n{context_str}\n\nSummary:"
        )
        try:
            return self._call_llm(
                "You are a concise conversation summarizer. Provide brief, accurate summaries.",
                summary_prompt,
                0.3,
            ) or "Unable to generate summary."
        except Exception:
            return "Unable to generate summary."

    def get_status(self) -> Dict[str, Any]:
        _init_globals()
        llm_available = bool(
            (_ANTHROPIC_AVAILABLE and _ANTHROPIC_API_KEY) or
            (_OPENAI_AVAILABLE and _OPENAI_API_KEY) or
            (_GEMINI_AVAILABLE and _GEMINI_API_KEY) or
            _OLLAMA_URL or
            _LLAMACPP_URL
        )
        # Determine which provider is active
        active_provider = "unknown"
        if _ANTHROPIC_AVAILABLE and _ANTHROPIC_API_KEY:
            active_provider = "claude"
        elif _OPENAI_AVAILABLE and _OPENAI_API_KEY:
            active_provider = "openai"
        elif _GEMINI_AVAILABLE and _GEMINI_API_KEY:
            active_provider = "gemini"
        elif _OLLAMA_URL:
            active_provider = "ollama"
        elif _LLAMACPP_URL:
            active_provider = "llamacpp"
        return {
            "enabled": self._enabled,
            "personality": self._personality,
            "nick": self._nick,
            "participation_rate": self._participation_rate,
            "channels_active": len(self._channel_context),
            "total_messages_tracked": sum(len(ctx) for ctx in self._channel_context.values()),
            "llm_available": llm_available,
            "mode": "LLM" if llm_available else "fallback",
            "provider": active_provider,
            "llm_model": self._llm_model,
        }

    def list_personalities(self) -> List[str]:
        return list(self.PERSONALITIES.keys())

    def _maybe_save(self) -> None:
        now = time.time()
        if now - self._last_save < 120:
            return
        self._save()

    def _save(self) -> None:
        self._last_save = time.time()
        try:
            data = {
                "enabled": self._enabled,
                "personality": self._personality,
                "nick": self._nick,
                "participation_rate": self._participation_rate,
                "max_response_len": self._max_response_len,
                "respond_to_mentions": self._respond_to_mentions,
                "proactive_participation": self._proactive_participation,
                "min_response_interval": self._min_response_interval,
                "llm_model": self._llm_model,
                "long_term_memory": {k: v[-50:] for k, v in self._long_term_memory.items()},
                "conversation_summaries": self._conversation_summaries,
            }
            with open(self._SAVE_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f)
        except Exception:
            pass

    def load(self) -> None:
        try:
            with open(self._SAVE_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            self._enabled = data.get("enabled", False)
            self._personality = data.get("personality", "helpful")
            self._nick = data.get("nick", "")
            self._participation_rate = data.get("participation_rate", 0.1)
            self._max_response_len = data.get("max_response_len", 300)
            self._respond_to_mentions = data.get("respond_to_mentions", True)
            self._proactive_participation = data.get("proactive_participation", True)
            self._min_response_interval = data.get("min_response_interval", 5.0)
            self._llm_model = data.get("llm_model", "gemma4")
            self._long_term_memory = data.get("long_term_memory", {})
            self._conversation_summaries = data.get("conversation_summaries", {})
            for ch in self._long_term_memory:
                self._channel_context[ch] = deque(self._long_term_memory[ch][-50:], maxlen=50)
        except Exception:
            pass
