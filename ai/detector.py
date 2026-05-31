"""
EnsembleAIDetector and helper functions extracted from eyearesee.py.

AI-detection ensemble: Binoculars + RoBERTa classifiers + language heuristics
+ Llama-specific pattern detection + watermark detection + embedding drift.
"""

import asyncio
import json
import os
import re
import time
import urllib.error
import urllib.request
from collections import Counter, OrderedDict
from math import log, log2
from typing import Dict, List, Optional, Tuple

# ── Optional AI imports ──────────────────────────────────────────────────────
AI_AVAILABLE = False
try:
    import torch
    from transformers import (AutoTokenizer, AutoModelForSequenceClassification,
                              GPT2LMHeadModel, GPT2TokenizerFast)
    AI_AVAILABLE = True
except Exception:
    pass

_PEFT_AVAILABLE = False
try:
    import peft  # noqa: F401
    _PEFT_AVAILABLE = True
except ImportError:
    pass

# ── Lazy-loaded globals from eyearesee.py ────────────────────────────────────
_GLOBALS = None

def _init():
    global _GLOBALS
    if _GLOBALS is not None:
        return
    import eyearesee as _eya
    _GLOBALS = {
        'ANTHROPIC_API_KEY': getattr(_eya, 'ANTHROPIC_API_KEY', ''),
        'OPENAI_API_KEY': getattr(_eya, 'OPENAI_API_KEY', ''),
        'GEMINI_API_KEY': getattr(_eya, 'GEMINI_API_KEY', ''),
        'DEEPSEEK_API_KEY': getattr(_eya, 'DEEPSEEK_API_KEY', ''),
        'GITHUB_TOKEN': getattr(_eya, 'GITHUB_TOKEN', ''),
        'OLLAMA_URL': getattr(_eya, 'OLLAMA_URL', 'http://127.0.0.1:11434'),
        'LLAMACPP_URL': getattr(_eya, 'LLAMACPP_URL', 'http://127.0.0.1:8033'),
        'AI_MODELS': getattr(_eya, 'AI_MODELS', {}),
        'ANTHROPIC_AVAILABLE': getattr(_eya, 'ANTHROPIC_AVAILABLE', False),
        'OPENAI_AVAILABLE': getattr(_eya, 'OPENAI_AVAILABLE', False),
        'GEMINI_AVAILABLE': getattr(_eya, 'GEMINI_AVAILABLE', False),
        'AI_LOG_PATH': getattr(_eya, 'AI_LOG_PATH', ''),
        'AI_SUSPECT_THRESHOLD': getattr(_eya, 'AI_SUSPECT_THRESHOLD', 70),
        '_SCRIPT_DIR': getattr(_eya, '_SCRIPT_DIR', os.path.dirname(os.path.abspath(__file__))),
        '_IO_EXECUTOR': getattr(_eya, '_IO_EXECUTOR', None),
        '_ML_EXECUTOR': getattr(_eya, '_ML_EXECUTOR', None),
        '_ML_SEM': getattr(_eya, '_ML_SEM', None),
        '_anthropic_mod': getattr(_eya, '_anthropic_mod', None),
        '_openai_mod': getattr(_eya, '_openai_mod', None),
        '_gemini_mod': getattr(_eya, '_gemini_mod', None),
        'OBSERVER_MODEL_ID': getattr(_eya, 'OBSERVER_MODEL_ID', 'distilgpt2'),
        'EMBEDDING_MODEL': getattr(_eya, 'EMBEDDING_MODEL', ''),
    }

# Module-level cached classify clients (reset on error, as in original)
_classify_ac = None
_classify_oc = None

# ── CJK character-range regex patterns ───────────────────────────────────────
_CJK_CN_RE = re.compile(r'[\u4e00-\u9fff]')
_CJK_JP_RE = re.compile(r'[\u3040-\u309f\u30a0-\u30ff]')
_CJK_KR_RE = re.compile(r'[\uac00-\ud7af]')
_LATIN_ACCENT_RE = re.compile(r'[\u00e0\u00e1\u00e2\u00e3\u00e4\u00e5\u00e8\u00e9\u00ea\u00eb\u00ec\u00ed\u00ee\u00ef\u00f2\u00f3\u00f4\u00f5\u00f6\u00f9\u00fa\u00fb\u00fc\u00fd\u00ff\u00f1\u00e7\u00df\u00f0\u00fe\u00e6\u0153]')

# ── Bot-opener regex (patterns AI assistants start messages with) ───────────
_BOT_OPENER_RE = re.compile(
    r"^(?:Sure[!,]?|Absolutely[!,]?|Certainly[!,]?|Of course[!,]?|"
    r"Great[!,]?|Gladly[!,]?|Happy to help[!,]?|I'?d be happy|"
    r"I'?d be glad|Let me|Here'?s |Here are |To answer|"
    r"Of course[,!] I'?d|I can help|I'?ll help|"
    r"I can certainly|Allow me|Thanks for (?:asking|the question)|"
    r"Good (?:question|point)[!,.]?|That'?s (?:a )?(?:great|good|interesting)|"
    r"To (?:address|answer|respond to)|I'?ll (?:break|walk|explain|outline)|"
    r"Step(?:\s+\d+)?[:.]\s*\w)",
    re.IGNORECASE,
)

# Structural patterns Llama/open-source LLMs use that are unusual in IRC
# (numbered lists, bullet points, markdown headers, code fences)
_LLAMA_STRUCT_RE = re.compile(
    r"(?m)^(?:\s*\d+[.)]\s+\S|\s*[-*\u2022]\s+\S|\s*#{1,3}\s+\S|```)",
)

# ── Language heuristic phrase sets ───────────────────────────────────────────

IRC_CASUAL_WORDS = frozenset({
    "lol", "lmao", "lmfao", "rofl", "haha", "hehe", "xd", "xdd",
    "brb", "afk", "omg", "wtf", "gtg", "gg", "rip", "smh", "imo",
    "imho", "tbh", "ngl", "idk", "irl", "fyi", "ty", "thx", "np",
    "nvm", "btw", "iirc", "tfw", "mfw", "welp", "kek", "ez",
    "lmk", "imo", "ikr", "fr", "no cap", "w", "l", "based", "cope",
    "slay", "bro", "dude", "gonna", "wanna", "gotta",
})

# General LLM tell-phrases — applies across GPT-4, Claude, Gemini, Llama, etc.
AI_TELL_PHRASES = frozenset({
    # Hedging / meta-commentary
    "it's worth noting", "it is worth noting",
    "it's important to", "it is important to",
    "it should be noted", "it's crucial to",
    "as previously mentioned", "as noted above",
    "it's important to understand", "it's essential to understand",
    "keep in mind that", "bear in mind that",
    "it's worth mentioning", "worth pointing out",
    # Transitional connectors overused by LLMs
    "to elaborate", "to clarify", "in other words",
    "furthermore", "moreover", "additionally", "consequently",
    "that being said", "having said that", "with that said",
    "on the other hand", "in conclusion", "to that end",
    "at its core", "at the end of the day",
    # Summary / recap language
    "to summarize", "in summary", "to recap", "to put it simply",
    "in a nutshell", "in essence", "to boil it down",
    "overall,", "ultimately,", "in short,",
    # Sycophantic openers
    "certainly!", "absolutely!", "great question", "excellent question",
    "good question", "that's a great", "what a great",
    "of course!", "sure thing", "i'd be happy to", "i'd be glad to",
    "happy to help", "glad to help", "i'm happy to",
    # Closing / helper phrases
    "i hope this helps", "i hope that helps", "hope this helps",
    "feel free to", "please let me know", "let me know if",
    "don't hesitate to", "if you have any questions",
    "if you'd like more", "if you need further",
    # LLM identity tells
    "as an ai", "as an ai assistant", "as an ai language model",
    "as a language model", "i'm just an ai", "i am just an ai",
    "my training data", "my knowledge cutoff", "my training",
    "based on my training", "i don't have real-time",
    "i don't have access to real-time",
    # 2025/2026 stylistic tells
    "delve into", "tapestry", "nuanced perspective",
    "it's fascinating", "it's interesting to note",
    "navigating the", "landscape of", "realm of",
    "leverage", "synergize", "holistic approach",
    # Deliberative / thinking-aloud phrases (Claude 3/4, GPT-4o)
    "let me think through", "here's my thinking",
    "to put it another way", "to be more specific",
    "broadly speaking", "in practical terms",
    "at a high level", "drill down into",
    "the key takeaway", "the main takeaway",
    "worth unpacking", "let me unpack",
    "when it comes to", "in real-world terms",
    # 2026 additions — newer stylistic tics across all frontier models
    "i think it's worth", "one thing to consider",
    "it depends on", "the short answer is",
    "the long answer is", "to answer directly",
    "to give you a direct answer", "what i'd say is",
    "here's the thing:", "the thing is,",
})

# Phrases characteristic of Llama 2 / Llama 3 / Mistral / open-source LLMs
LLAMA_TELL_PHRASES = frozenset({
    # Typical Llama openers
    "sure, here", "sure! here", "sure, i can",
    "of course, here", "of course! i",
    "i'll do my best", "i'll try my best",
    "let me provide", "let me explain", "let me walk you through",
    "let me break this down", "let me break down",
    "let me help you", "let me help with",
    "here's a step-by-step", "here are some steps",
    "here's how you can", "here's how to",
    "here's an overview", "here's a breakdown",
    "here's what you", "here are a few", "here are some",
    # Llama meta-language
    "as requested", "as you asked", "as you mentioned",
    "based on your question", "based on what you've said",
    "to answer your question", "to address your question",
    "your question is", "you asked about",
    # Llama recommendation style
    "my recommendation would be", "my suggestion would be",
    "i would recommend", "i would suggest", "i suggest",
    "i recommend", "one approach would be", "one option is",
    # Llama closing phrases
    "i hope this answers", "i hope this clarifies",
    "i hope this helps you", "please feel free",
    "feel free to ask", "feel free to reach out",
    "let me know if you", "let me know if there",
    "to summarize my response", "in summary,",
    # Llama hedging / safety language
    "i need to point out", "i should point out",
    "i should mention", "i should note",
    "to be clear", "to be precise", "to be transparent",
    "i want to be clear", "i want to clarify",
    "it's important that i clarify", "i must clarify",
    # Llama 2 refusal / alignment patterns
    "i cannot assist with", "i'm not able to assist",
    "i'm unable to", "i'm afraid i can't",
    "that falls outside", "outside my capabilities",
    "i'm designed to", "my purpose is to",
    # Llama 3 / newer patterns
    "my understanding is", "based on my knowledge",
    "as of my last update", "as of my knowledge",
    "as of my training", "my response to this",
    # Additional open-source LLM openers (Qwen, Gemma, Mistral, Phi)
    "i can certainly help", "i can help you with",
    "let me outline", "here's a quick overview",
    "here's a quick summary", "to break it down",
    "step by step:", "step-by-step guide",
    "here's what i'd suggest", "happy to elaborate",
    "glad you asked", "great, let me",
    "to put it simply,", "simply put,",
    # Qwen3 / DeepSeek thinking-mode bleed-through (internal CoT leaking)
    "let me think step by step", "thinking step by step",
    "let me reason through", "let me work through",
    "so first, let me", "ok, so the question",
})

# Vocabulary LLMs reach for that humans rarely use in casual IRC chat
FORMAL_WORDS = frozenset({
    # Classic formal vocabulary
    "utilize", "leverage", "implement", "facilitate",
    "demonstrate", "enumerate", "articulate",
    "commence", "terminate", "endeavor",
    "subsequent", "pertaining", "aforementioned",
    "constitute", "comprises", "optimal",
    "paramount", "imperative", "holistic",
    "synergy", "paradigm", "streamline",
    # 2025 additions — words AI over-applies in casual settings
    "comprehensive", "multifaceted", "intricate",
    "pivotal", "fundamental", "substantial",
    "conceptual", "theoretical", "contextual",
    "methodology", "framework", "perspective",
    "implications", "considerations", "ramifications",
    "sophisticated", "nuanced", "intrinsically",
    "inherently", "essentially", "fundamentally",
    "predominantly", "predominantly", "encompass",
    "elucidate", "expound", "elaborate",
    "ascertain", "discern", "navigate",
    "augment", "mitigate", "alleviate",
})

# ── Multi-language AI detection patterns ──

# CJK (Chinese/Japanese/Korean) LLM tell-phrases and patterns
CJK_AI_TELL_PHRASES = frozenset({
    "\u503c\u5f97\u6ce8\u610f\u7684\u662f", "\u9700\u8981\u6ce8\u610f\u7684\u662f", "\u603b\u7684\u6765\u8bf4", "\u603b\u800c\u8a00\u4e4b",
    "\u9996\u5148", "\u5176\u6b21", "\u6700\u540e", "\u7efc\u4e0a\u6240\u8ff0", "\u7b80\u800c\u8a00\u4e4b",
    "\u6362\u53e5\u8bdd\u8bf4", "\u4e5f\u5c31\u662f\u8bf4", "\u4ece\u67d0\u79cd\u610f\u4e49\u4e0a\u8bf4", "\u4ece\u67d0\u79cd\u7a0b\u5ea6\u4e0a\u8bf4",
    "\u9700\u8981\u6307\u51fa\u7684\u662f", "\u5e94\u5f53\u6ce8\u610f\u7684\u662f", "\u4e0d\u53ef\u5426\u8ba4",
    "\u5728\u6211\u770b\u6765", "\u6211\u8ba4\u4e3a", "\u53ef\u4ee5\u8bf4",
    "\u4e8b\u5b9e\u4e0a", "\u5b9e\u9645\u4e0a", "\u5ba2\u89c2\u5730\u8bf4",
    "\u8fd9\u662f\u4e00\u4e2a\u5f88\u597d\u7684\u95ee\u9898", "\u597d\u95ee\u9898", "\u5f88\u597d\u7684\u95ee\u9898",
    "\u8ba9\u6211\u6765\u89e3\u91ca", "\u8ba9\u6211\u8be6\u7ec6\u8bf4\u660e", "\u6211\u6765\u5e2e\u4f60",
    "\u5e0c\u671b\u80fd\u5e2e\u5230\u4f60", "\u5e0c\u671b\u5bf9\u4f60\u6709\u5e2e\u52a9", "\u5e0c\u671b\u8fd9\u80fd\u5e2e\u52a9",
    "\u4f5c\u4e3a\u4e00\u4e2a\u4eba\u5de5\u667a\u80fd", "\u4f5c\u4e3aAI", "\u6211\u7684\u8bad\u7ec3\u6570\u636e",
    "\u6211\u7684\u77e5\u8bc6\u622a\u6b62", "\u6211\u65e0\u6cd5\u5b9e\u65f6",
})

# Japanese LLM patterns
JP_AI_TELL_PHRASES = frozenset({
    "\u91cd\u8981\u306a\u306e\u306f", "\u6ce8\u610f\u3059\u3079\u304d\u306f", "\u307e\u3068\u3081\u308b\u3068", "\u3064\u307e\u308a",
    "\u8a00\u3044\u63db\u3048\u308b\u3068", "\u7aef\u7684\u306b\u8a00\u3048\u3070", "\u7d50\u8ad6\u3068\u3057\u3066",
    "\u307e\u305a", "\u6b21\u306b", "\u6700\u5f8c\u306b",
    "\u826f\u3044\u8cea\u554f\u3067\u3059\u306d", "\u7d20\u6674\u3089\u3057\u3044\u8cea\u554f", "\u3054\u8cea\u554f\u3042\u308a\u304c\u3068\u3046\u3054\u3056\u3044\u307e\u3059",
    "\u8a73\u3057\u304f\u8aac\u660e\u3057\u307e\u3059", "\u8aac\u660e\u3055\u305b\u3066\u3044\u305f\u3060\u304d\u307e\u3059",
    "\u304a\u5f79\u306b\u7acb\u3066\u3070\u5e78\u3044\u3067\u3059", "\u53c2\u8003\u306b\u306a\u308c\u3070",
    "AI\u3068\u3057\u3066", "\u79c1\u306e\u77e5\u8b58",
})

# Korean LLM patterns
KR_AI_TELL_PHRASES = frozenset({
    "\uc8fc\ubaa9\ud560 \uc810\uc740", "\uc720\uc758\ud574\uc57c \ud560 \uc810\uc740", "\uc694\uc57d\ud558\uc790\uba74", "\uacb0\ub860\uc801\uc73c\ub85c",
    "\ub2e4\uc2dc \ub9d0\ud574", "\uc989", "\uac04\ub2e8\ud788 \ub9d0\ud574",
    "\uba3c\uc800", "\ub2e4\uc74c\uc73c\ub85c", "\ub9c8\uc9c0\ub9c9\uc73c\ub85c",
    "\uc88b\uc740 \uc9c8\ubb38\uc774\ub124\uc694", "\ud6cc\ub96d\ud55c \uc9c8\ubb38\uc785\ub2c8\ub2e4",
    "\uc790\uc138\ud788 \uc124\uba85\ud574 \ub4dc\ub9ac\uaca0\uc2b5\ub2c8\ub2e4", "\ub3c4\uc6c0\uc774 \ub418\uae38 \ubc14\ub78d\ub2c8\ub2e4",
    "AI\ub85c\uc11c", "\uc81c \uc9c0\uc2dd\uc740",
})

# European language LLM tell-phrases (French, German, Spanish, Portuguese, Italian)
EU_AI_TELL_PHRASES = frozenset({
    # French
    "il est important de noter", "il vaut la peine de", "en r\u00e9sum\u00e9",
    "en conclusion", "autrement dit", "en d'autres termes",
    "tout d'abord", "ensuite", "enfin",
    "excellente question", "bonne question",
    "permettez-moi d'expliquer", "laissez-moi expliquer",
    "j'esp\u00e8re que cela aide", "n'h\u00e9sitez pas \u00e0",
    "en tant qu'ia", "en tant qu'intelligence artificielle",
    # German
    "es ist wichtig zu beachten", "es lohnt sich zu",
    "zusammenfassend", "kurz gesagt", "mit anderen Worten",
    "zun\u00e4chst", "desweiteren", "schlie\u00dflich",
    "gute frage", "ausgezeichnete frage",
    "lass mich erkl\u00e4ren", "ich erkl\u00e4re gerne",
    "ich hoffe das hilft", "z\u00f6gern sie nicht",
    "als ki", "als k\u00fcnstliche intelligenz",
    # Spanish
    "es importante tener en cuenta", "vale la pena se\u00f1alar",
    "en resumen", "en conclusi\u00f3n", "en otras palabras",
    "primero", "segundo", "por \u00faltimo",
    "excelente pregunta", "buena pregunta",
    "d\u00e9jame explicarte", "perm\u00edteme explicar",
    "espero que esto ayude", "no dudes en",
    "como ia", "como inteligencia artificial",
    # Portuguese
    "\u00e9 importante notar", "vale a pena notar",
    "em resumo", "em conclus\u00e3o", "em outras palavras",
    "primeiro", "segundo", "por fim",
    "excelente pergunta", "boa pergunta",
    "deixe-me explicar", "espero que isso ajude",
    "como ia", "como intelig\u00eancia artificial",
    # Italian
    "\u00e8 importante notare", "vale la pena notare",
    "in sintesi", "in conclusione", "in altre parole",
    "innanzitutto", "in secondo luogo", "infine",
    "ottima domanda", "buona domanda",
    "lasciami spiegare", "spero che questo aiuti",
    "come ia", "come intelligenza artificiale",
})

# CJK formal vocabulary that AI over-uses in casual settings
CJK_FORMAL_WORDS = frozenset({
    "\u6b64\u5916", "\u7136\u800c", "\u56e0\u6b64", "\u603b\u4e4b", "\u9274\u4e8e",
    "\u6beb\u65e0\u7591\u95ee", "\u81f3\u5173\u91cd\u8981", "\u4e0d\u53ef\u6216\u7f3a", "\u663e\u8457",
    "\u6d89\u53ca", "\u9610\u8ff0", "\u63a2\u8ba8", "\u5206\u6790", "\u8bba\u8bc1",
    "\u7efc\u4e0a\u6240\u8ff0", "\u6362\u8a00\u4e4b", "\u4e0e\u6b64\u540c\u65f6", "\u53e6\u4e00\u65b9\u9762",
})

# European formal vocabulary
EU_FORMAL_WORDS = frozenset({
    "par cons\u00e9quent", "n\u00e9anmoins", "en outre", "cependant",
    "demnach", "dar\u00fcber hinaus", "insbesondere", "beziehungsweise",
    "adicionalmente", "asimismo", "no obstante", "por consiguiente",
    "adicionalmente", "outrossim", "entretanto", "por conseguinte",
    "inoltre", "pertanto", "d'altra parte", "di conseguenza",
})

# Casual CJK words that humans use but AI rarely does in chat
CJK_CASUAL_WORDS = frozenset({
    "\u54c8\u54c8", "\u563f\u563f", "\u989d", "\u55ef", "\u54e6", "\u554a",
    "\u5367\u69fd", "\u725b\u903c", "666", "\u8349", "emmm", "hhh",
    "w", "kwsk", "\u8349", "\u3046p", "\u4e59", "\u304a\u3064",
    "\u314b\u314b", "\u314e\u314e", "\u3137\u3137", "\ud5d0", "\ub300\ubc15", "\uc9d5\uc9d5",
})

# Detect CJK character ranges for language identification
_CJK_RANGE_RE = re.compile(r'[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]')

# =========================
# Helper functions
# =========================

def _detect_text_language(text: str) -> str:
    """Simple language detection: 'zh', 'ja', 'ko', 'eu', or 'en'."""
    if _CJK_CN_RE.search(text) and not _CJK_JP_RE.search(text):
        return "zh"
    if _CJK_JP_RE.search(text):
        return "ja"
    if _CJK_KR_RE.search(text):
        return "ko"
    if _LATIN_ACCENT_RE.search(text):
        return "eu"
    return "en"

# =========================
# Ollama local-model helper
# =========================

def _ollama_blocking_call(model_id: str, prompt: str, max_tokens: int) -> Tuple[str, str]:
    """Synchronous HTTP call to a local Ollama server (run via asyncio executor).

    Uses only stdlib urllib so no extra package is required.
    Requires `ollama serve` running at OLLAMA_URL (default http://localhost:11434).
    Pull models first with e.g.: ollama pull gemma3:4b
    """
    _init()
    _url = _GLOBALS['OLLAMA_URL']
    body = json.dumps({
        "model":   model_id,
        "messages": [{"role": "user", "content": prompt}],
        "stream":  False,
        "options": {"num_predict": max_tokens},
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{_url}/api/chat",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        answer = data.get("message", {}).get("content", "(empty response)")
        eval_c   = data.get("eval_count")
        prompt_c = data.get("prompt_eval_count", 0)
        tokens   = str(eval_c + prompt_c) if isinstance(eval_c, int) else "?"
        return answer, tokens
    except urllib.error.URLError as exc:
        return (
            f"[error] Ollama unreachable at {_url} \u2014 "
            f"start it with: ollama serve  (then: ollama pull {model_id})\n"
            f"Detail: {exc}"
        ), "?"
    except Exception as exc:
        return f"[error] Ollama call failed: {exc}", "?"


def _llamacpp_blocking_call(model_id: str, prompt: str, max_tokens: int) -> Tuple[str, str]:
    """Synchronous HTTP call to a llama.cpp server (run via asyncio executor).

    Uses only stdlib urllib so no extra package is required.
    Requires `llama-server` running at LLAMACPP_URL (default http://127.0.0.1:8033).
    The model field is sent but ignored by llama.cpp \u2014 it serves whichever model was
    loaded at startup.  Uses the OpenAI-compatible /v1/chat/completions endpoint.
    """
    _init()
    _url = _GLOBALS['LLAMACPP_URL']
    body = json.dumps({
        "model":      model_id,
        "messages":   [{"role": "user", "content": prompt}],
        "max_tokens": max_tokens,
        "stream":     False,
    }).encode("utf-8")
    req = urllib.request.Request(
        f"{_url}/v1/chat/completions",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        answer = (data.get("choices", [{}])[0]
                      .get("message", {})
                      .get("content", "(empty response)"))
        usage  = data.get("usage", {})
        total  = usage.get("total_tokens")
        tokens = str(total) if isinstance(total, int) else "?"
        return answer, tokens
    except urllib.error.URLError as exc:
        return (
            f"[error] llama.cpp unreachable at {_url} \u2014 "
            f"start it with: llama-server -m <model.gguf>\n"
            f"Detail: {exc}"
        ), "?"
    except Exception as exc:
        return f"[error] llama.cpp call failed: {exc}", "?"


async def _llm_classify_ai(text: str, model_key: str) -> float:
    """Ask the active /model to classify *text* as AI- or human-written.

    Sends a tightly constrained prompt and expects a single-word reply of
    "AI" or "HUMAN".  Returns 0.0\u20131.0 (1.0 = AI-generated).  Returns 0.0
    on any network or parse error so it degrades gracefully.

    Skipped for messages shorter than 6 words \u2014 too little signal to be
    meaningful and would waste API / local-inference budget.
    """
    if len(text.split()) < 6:
        return 0.0

    prompt = (
        "You are an AI-text detector reviewing IRC chat messages.\n"
        "Classify the message below as written by a human or generated by AI.\n"
        "Consider: informal language, typos, slang, IRC conventions, naturalness.\n"
        "Reply with ONLY one word: AI or HUMAN.\n\n"
        f"Message: {text!r}\n\nClassification:"
    )

    try:
        _init()
        if model_key.startswith("ollama:"):
            provider = "ollama"
            model_id = model_key[len("ollama:"):]
        else:
            spec = _GLOBALS['AI_MODELS'].get(model_key)
            if not spec:
                return 0.0
            provider = spec["provider"]
            model_id = spec["id"]

        global _classify_ac, _classify_oc
        answer = ""
        if provider == "claude":
            if not _GLOBALS['ANTHROPIC_AVAILABLE'] or not _GLOBALS['ANTHROPIC_API_KEY']:
                return 0.0
            if _classify_ac is None:
                _classify_ac = _GLOBALS['_anthropic_mod'].AsyncAnthropic(api_key=_GLOBALS['ANTHROPIC_API_KEY'])
            try:
                msg = await _classify_ac.messages.create(
                    model=model_id, max_tokens=10,
                    messages=[{"role": "user", "content": prompt}],
                )
            except Exception:
                _classify_ac = None
                raise
            answer = msg.content[0].text if msg.content else ""
        elif provider == "openai":
            if not _GLOBALS['OPENAI_AVAILABLE'] or not _GLOBALS['OPENAI_API_KEY']:
                return 0.0
            if _classify_oc is None:
                _classify_oc = _GLOBALS['_openai_mod'].AsyncOpenAI(api_key=_GLOBALS['OPENAI_API_KEY'])
            try:
                resp = await _classify_oc.chat.completions.create(
                    model=model_id, max_tokens=10,
                    messages=[{"role": "user", "content": prompt}],
                )
            except Exception:
                _classify_oc = None
                raise
            answer = resp.choices[0].message.content if resp.choices else ""
        elif provider == "gemini":
            if not _GLOBALS['GEMINI_AVAILABLE'] or not _GLOBALS['GEMINI_API_KEY']:
                return 0.0
            try:
                gclient = _GLOBALS['_gemini_mod'].aio.Client(api_key=_GLOBALS['GEMINI_API_KEY'])
                resp = await gclient.models.generate_content(
                    model=model_id,
                    contents=prompt,
                    config=_GLOBALS['_gemini_mod'].types.GenerateContentConfig(max_output_tokens=10))
                answer = resp.text if resp.text else ""
            except Exception:
                return 0.0
        elif provider == "ollama":
            loop   = asyncio.get_running_loop()
            answer, _ = await loop.run_in_executor(
                _GLOBALS['_IO_EXECUTOR'], _ollama_blocking_call, model_id, prompt, 10)
        elif provider == "llamacpp":
            loop   = asyncio.get_running_loop()
            answer, _ = await loop.run_in_executor(
                _GLOBALS['_IO_EXECUTOR'], _llamacpp_blocking_call, model_id, prompt, 10)
        else:
            return 0.0

        upper = answer.strip().upper()
        if "HUMAN" in upper:
            return 0.0
        if "AI" in upper:
            return 1.0
        return 0.5   # ambiguous / unexpected reply

    except Exception:
        return 0.0


# =========================
# EnsembleAIDetector
# =========================

class EnsembleAIDetector:
    _CACHE_MAX = 512  # LRU-style prediction cache (bots repeat themselves)

    # Primary classifier: trained on ChatGPT/GPT-family output
    _CLS1_MODEL = "Hello-SimpleAI/chatgpt-detector-roberta"
    # Secondary classifier: broader OpenAI GPT-2-era detector; generalises to
    # fluent AI text regardless of model family (Llama, Mistral, etc.).
    # Loaded opportunistically \u2014 falls back gracefully if unavailable.
    _CLS2_MODEL = "openai-community/roberta-base-openai-detector"

    def __init__(self, disabled: bool = False):
        self.enabled = not disabled
        self.active_detect_model: str = "" if disabled else "qwen3"  # default: llama.cpp qwen3 for LLM detection
        self._gpt2_model = None   # GPT-2: Binoculars performer
        self._obs_model  = None   # distilgpt2 or configurable observer
        self._obs_modern = None   # modern observer (TinyLlama etc.), optional
        self._obs_modern_tok = None
        self._gpt2_tok   = None   # shared GPT-2 tokenizer
        self._cls_model  = None   # primary classifier (ChatGPT-focused RoBERTa)
        self._cls_tok    = None
        self._cls2_model = None   # secondary classifier (general LLM detector), optional
        self._cls2_tok   = None
        self._embed_model = None  # sentence embedding model (drift detection), optional
        self._embed_tok   = None
        self._device = "cpu"
        self._pred_cache: OrderedDict = OrderedDict()  # text \u2192 Dict[str,float], LRU
        # \u2500\u2500 LoRA incremental fine-tuning (Area 7) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        self._lora_peft_config = None
        self._lora_model = None
        self._lora_loaded = False

        if disabled:
            return
        if not AI_AVAILABLE:
            raise SystemExit(
                "AI detector requires: pip install transformers torch\n"
                "Core models (gpt2, distilgpt2, RoBERTa) must load successfully."
            )
        self._load_models()

    def _load_models(self) -> None:
        _init()
        self._device = "cuda" if torch.cuda.is_available() else "cpu"

        print("AI detector: loading gpt2 tokenizer...", end=" ", flush=True)
        self._gpt2_tok = GPT2TokenizerFast.from_pretrained("gpt2")
        print("OK")

        print("AI detector: loading gpt2 (Binoculars performer)...", end=" ", flush=True)
        self._gpt2_model = GPT2LMHeadModel.from_pretrained("gpt2").to(self._device)
        self._gpt2_model.eval()
        print("OK")

        # \u2500\u2500 Binoculars observer model (configurable via IRC_OBSERVER_MODEL) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        _obs_id = _GLOBALS['OBSERVER_MODEL_ID']
        if _obs_id == "distilgpt2":
            print("AI detector: loading distilgpt2 (Binoculars observer)...", end=" ", flush=True)
            try:
                self._obs_model = GPT2LMHeadModel.from_pretrained(_obs_id).to(self._device)
                self._obs_model.eval()
                print("OK")
            except Exception as _e:
                print(f"failed ({_e})")
        else:
            # Modern observer \u2014 not GPT-2 family, so it gets its own tokenizer
            print(f"AI detector: loading {_obs_id} (modern Binoculars observer)...", end=" ", flush=True)
            try:
                from transformers import AutoModelForCausalLM as _AutoCausal
                self._obs_modern_tok = AutoTokenizer.from_pretrained(_obs_id)
                if self._obs_modern_tok.pad_token is None:
                    self._obs_modern_tok.pad_token = self._obs_modern_tok.eos_token
                self._obs_modern = _AutoCausal.from_pretrained(
                    _obs_id, torch_dtype="auto", device_map="auto",
                ).to(self._device)
                self._obs_modern.eval()
                print("OK")
            except Exception as _e:
                self._obs_modern = None
                self._obs_modern_tok = None
                print(f"skipped ({_e})")
            # Load distilgpt2 as fallback for the classic Binoculars path
            print("AI detector: loading distilgpt2 (fallback observer)...", end=" ", flush=True)
            try:
                self._obs_model = GPT2LMHeadModel.from_pretrained("distilgpt2").to(self._device)
                self._obs_model.eval()
                print("OK")
            except Exception as _e:
                print(f"failed ({_e})")

        # \u2500\u2500 Sentence embedding model for semantic-drift detection \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        if _GLOBALS['EMBEDDING_MODEL']:
            print(f"AI detector: loading embedding model ({_GLOBALS['EMBEDDING_MODEL']})...", end=" ", flush=True)
            try:
                from sentence_transformers import SentenceTransformer
                self._embed_model = SentenceTransformer(_GLOBALS['EMBEDDING_MODEL'], device=self._device)
                print("OK")
            except ImportError:
                print("skipped (sentence-transformers not installed)")
            except Exception as _e:
                print(f"skipped ({_e})")

        # \u2500\u2500 Classifiers \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        print(f"AI detector: loading primary classifier ({self._CLS1_MODEL})...", end=" ", flush=True)
        try:
            self._cls_tok = AutoTokenizer.from_pretrained(self._CLS1_MODEL)
            self._cls_model = AutoModelForSequenceClassification.from_pretrained(
                self._CLS1_MODEL,
                ignore_mismatched_sizes=True,
            ).to(self._device)
            self._cls_model.eval()
            print("OK")
        except Exception as _e:
            self._cls_tok   = None
            self._cls_model = None
            print(f"skipped ({_e})")

        print(f"AI detector: loading secondary classifier ({self._CLS2_MODEL})...", end=" ", flush=True)
        try:
            self._cls2_tok = AutoTokenizer.from_pretrained(self._CLS2_MODEL)
            self._cls2_model = AutoModelForSequenceClassification.from_pretrained(
                self._CLS2_MODEL,
                ignore_mismatched_sizes=True,
            ).to(self._device)
            self._cls2_model.eval()
            print("OK")
        except Exception as _e:
            self._cls2_tok   = None
            self._cls2_model = None
            print(f"skipped ({_e})")

        obs_name = _GLOBALS['OBSERVER_MODEL_ID'] if self._obs_modern else "distilgpt2"
        loaded = [f"Binoculars(gpt2+{obs_name})", "Llama-heuristics"]
        if self._cls_model:
            loaded.append("RoBERTa(chatgpt)")
        if self._cls2_model:
            loaded.append("RoBERTa(general)")
        if self._embed_model:
            loaded.append(f"Embed({_GLOBALS['EMBEDDING_MODEL']})")
        print(f"AI detector ENABLED: {' + '.join(loaded)}  (device={self._device})")

    # ---- static heuristics ----

    @staticmethod
    def entropy(text: str) -> float:
        if not text: return 0.0
        total = len(text)
        freq: dict = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        inv = 1.0 / total
        return -sum(n * inv * log2(n * inv) for n in freq.values())

    @staticmethod
    def repetition(text: str) -> float:
        if not text: return 0.0
        words = text.lower().split()
        if len(words) < 3: return 0.0
        return 1.0 - (len(set(words)) / len(words))

    @staticmethod
    def _burstiness(text: str) -> float:
        """Measure sentence-length variance (burstiness).

        Human writing exhibits high burstiness \u2014 alternating short and long
        sentences.  LLM output tends toward uniform sentence lengths.
        Returns 0..1, higher = more human-like burstiness.
        """
        if not text:
            return 0.0
        sentences = [s.strip() for s in re.split(r'[.!?]+', text) if s.strip()]
        if len(sentences) < 3:
            return 0.0  # not enough data
        lengths = [len(s.split()) for s in sentences]
        mean_len = sum(lengths) / len(lengths)
        if mean_len < 1:
            return 0.0
        variance = sum((l - mean_len) ** 2 for l in lengths) / len(lengths)
        cv = (variance ** 0.5) / mean_len  # coefficient of variation
        # Human text: CV typically 0.4\u20131.2; AI text: CV 0.1\u20130.4
        return max(0.0, min(1.0, (cv - 0.15) / 0.85))

    @staticmethod
    def _lexical_diversity(text: str) -> float:
        """Measure of Textual Lexical Diversity (MTLD-style approximation).

        Humans use a wider variety of unique words relative to total word count.
        LLMs tend to recycle common vocabulary more frequently.
        Returns 0..1, higher = more diverse (human-like).
        """
        if not text:
            return 0.0
        words = [w.lower().strip(".,!?;:\"'()[]") for w in text.split() if w.strip(".,!?;:\"'()[]")]
        if len(words) < 5:
            return 0.0
        # Type-token ratio over sliding windows (more robust than simple TTR)
        window_size = 10
        ttr_values = []
        for i in range(0, len(words) - window_size + 1, window_size // 2):
            window = words[i:i + window_size]
            if len(window) >= window_size:
                ttr_values.append(len(set(window)) / len(window))
        if not ttr_values:
            return 0.0
        avg_ttr = sum(ttr_values) / len(ttr_values)
        # Human IRC: ~0.7\u20130.95; AI: ~0.5\u20130.75
        return max(0.0, min(1.0, (avg_ttr - 0.45) / 0.55))

    @staticmethod
    def _punctuation_anomaly(text: str) -> float:
        """Detect unusual punctuation patterns common in AI output.

        LLMs overuse certain punctuation (em-dashes, semicolons, colons)
        and underuse others (ellipses, interrobangs, casual punctuation).
        Returns 0..1, higher = more anomalous (AI-like).
        """
        if not text or len(text) < 10:
            return 0.0
        score = 0.0
        words = text.split()
        n_words = len(words)

        # Em-dash density (LLMs love em-dashes for parentheticals)
        emdash_count = text.count('\u2014') + text.count(' -- ')
        if emdash_count > 0 and n_words > 10:
            ratio = emdash_count / (n_words / 20)  # expected ~1 per 20 words
            if ratio > 2.0:
                score += 0.15

        # Semicolon density (rare in casual IRC, common in AI prose)
        semicolon_count = text.count(';')
        if semicolon_count > 1 and n_words < 50:
            score += 0.10 * min(1.0, semicolon_count / 2)

        # Colon density (LLMs use colons to introduce lists/explanations)
        colon_count = text.count(':') - text.count('::')  # exclude IRC smileys
        if colon_count > 1 and n_words < 40:
            score += 0.10 * min(1.0, colon_count / 2)

        # Lack of casual punctuation (humans use ???, !!!, ?!, etc.)
        has_casual_punct = bool(re.search(r'[!?]{2,}|[\?!]{2,}|\.{4,}', text))
        if not has_casual_punct and n_words > 15:
            score += 0.08

        # Overly balanced parentheses (LLMs use them for asides)
        paren_pairs = min(text.count('('), text.count(')'))
        if paren_pairs > 2 and n_words < 60:
            score += 0.07 * min(1.0, paren_pairs / 3)

        return min(1.0, score)

    @staticmethod
    def _function_word_ratio(text: str) -> float:
        """Ratio of function words to content words.

        LLMs tend to have higher function-word density due to verbose
        connective tissue ("it is important to note that...", etc.).
        Returns 0..1, higher = more function-word heavy (AI-like).
        """
        if not text:
            return 0.0
        words = [w.lower().strip(".,!?;:\"'()[]") for w in text.split() if w.strip(".,!?;:\"'()[]")]
        if len(words) < 5:
            return 0.0

        _function_words = frozenset({
            "the", "a", "an", "of", "to", "in", "is", "that", "for", "it",
            "on", "and", "be", "or", "as", "at", "by", "with", "this", "are",
            "was", "were", "been", "has", "have", "had", "do", "does", "did",
            "will", "would", "can", "could", "may", "might", "shall", "should",
            "not", "no", "so", "if", "than", "then", "but", "because", "we",
            "they", "them", "their", "there", "here", "where", "when", "what",
            "which", "who", "whom", "whose", "about", "into", "through",
            "during", "before", "after", "above", "below", "between",
            "under", "again", "further", "once", "also", "just", "even",
            "still", "already", "always", "never", "often", "sometimes",
            "usually", "however", "therefore", "thus", "hence", "moreover",
            "furthermore", "additionally", "consequently", "nevertheless",
        })

        func_count = sum(1 for w in words if w in _function_words)
        ratio = func_count / len(words)
        # Human IRC: ~0.25\u20130.40; AI: ~0.40\u20130.55
        return max(0.0, min(1.0, (ratio - 0.30) / 0.25))

    @staticmethod
    def _sentence_openers_variety(text: str) -> float:
        """Measure variety of sentence/phrase openers.

        Humans vary how they start sentences; LLMs often repeat patterns
        ("The...", "It...", "This...", "Additionally,...").
        Returns 0..1, higher = more varied (human-like).
        """
        if not text:
            return 0.0
        # Split on sentence boundaries and line breaks
        segments = re.split(r'[.!?]+\s*|\n', text)
        segments = [s.strip() for s in segments if len(s.strip()) > 3]
        if len(segments) < 3:
            return 0.0

        # Extract first 2 words of each segment
        openers = []
        for seg in segments:
            words = seg.split()[:2]
            if words:
                openers.append(' '.join(w.lower() for w in words))

        if not openers:
            return 0.0
        unique_ratio = len(set(openers)) / len(openers)
        # Human: ~0.7\u20131.0; AI: ~0.3\u20130.7
        return max(0.0, min(1.0, (unique_ratio - 0.25) / 0.75))

    @staticmethod
    def formality_score(text: str) -> float:
        """0..1 \u2014 calibrated for 2025/2026 LLM output patterns in IRC chat."""
        if not text: return 0.0
        words = text.split()
        if not words: return 0.0
        text_lower = text.lower()
        _strip = ".,!?;:\"'()[]"
        words_lower_stripped = {w.lower().strip(_strip) for w in words}

        # Classic IRC vs formal signals
        casual_hit   = bool(words_lower_stripped & IRC_CASUAL_WORDS)
        ends_cleanly = text.rstrip().endswith((".", "!", "?", "..."))
        starts_cap   = text[0].isupper()
        no_charspam  = not any(len(set(w)) == 1 and len(w) > 2 for w in words)
        no_emoticon  = not any(e in text for e in (":)", ":(", ":D", "xD", "XD", "^_^", ">_<", "o/"))
        long_enough  = len(words) >= 6

        # LLM-specific tells (general across all model families)
        has_emdash     = "\u2014" in text or " -- " in text
        tell_phrase    = any(p in text_lower for p in AI_TELL_PHRASES)
        llama_phrase   = any(p in text_lower for p in LLAMA_TELL_PHRASES)
        formal_vocab   = bool(words_lower_stripped & FORMAL_WORDS)
        no_contraction = not any(c in text_lower for c in
                                 ("n't", "'re", "'ve", "'ll", "'m", "'d"))
        # Bot-opener at the very start of the message
        bot_opener = bool(_BOT_OPENER_RE.match(text))

        return min(1.0,
            0.08 * ends_cleanly
            + 0.04 * starts_cap
            + 0.06 * (not casual_hit)
            + 0.04 * no_charspam
            + 0.03 * no_emoticon
            + 0.05 * long_enough
            + 0.16 * tell_phrase       # strongest general signal
            + 0.14 * llama_phrase      # Llama/open-source LLM signal
            + 0.12 * has_emdash
            + 0.12 * formal_vocab
            + 0.10 * no_contraction
            + 0.14 * bot_opener        # unambiguous AI opener pattern
        )

    @staticmethod
    def llama_pattern_score(text: str) -> float:
        """0..1 \u2014 detects structural and phrasing patterns specific to Llama/
        open-source LLM outputs (Llama 2, Llama 3, Mistral, Vicuna, etc.).

        Focuses on signals that are low-FP in casual IRC:
        \u2022 Markdown structure (numbered lists, bullets, headers) in plain chat
        \u2022 Bot-opener words at the message start
        \u2022 Colon-terminated sentences introducing a list
        \u2022 Unusually long single messages (LLMs over-explain)
        \u2022 Multi-sentence uniform capitalisation (templated output)
        """
        if not text:
            return 0.0
        text_lower = text.lower()
        score = 0.0

        # Llama-specific tell phrases (subset different from general AI_TELL_PHRASES)
        if any(p in text_lower for p in LLAMA_TELL_PHRASES):
            score += 0.30

        # Markdown-style structural elements in what should be plain IRC chat
        struct_hits = len(_LLAMA_STRUCT_RE.findall(text))
        if struct_hits >= 3:
            score += 0.25
        elif struct_hits >= 1:
            score += 0.12

        # Bot-opener (unambiguous start patterns)
        if _BOT_OPENER_RE.match(text):
            score += 0.18

        # Colon at end of a sentence followed by newline or end-of-text (list intro)
        if re.search(r':\s*(?:\n|$)', text):
            score += 0.08

        # Very long single message: Llama over-explains simple questions
        word_count = len(text.split())
        if word_count >= 60:
            score += 0.15
        elif word_count >= 30:
            score += 0.07

        # All sentences start with a capital: templated / AI-generated prose
        sentences = [s.strip() for s in re.split(r'[.!?]', text) if len(s.strip()) > 4]
        if len(sentences) >= 3 and all(s[0].isupper() for s in sentences):
            score += 0.08

        # Repeated numbered / enumerated structure (common Llama answer format)
        if re.search(r'\b(?:first|second|third|finally|lastly)[,:]', text_lower):
            score += 0.08

        return min(1.0, score)

    @staticmethod
    def _multilang_formality_score(text: str) -> float:
        """0..1 \u2014 language-specific formality scoring for CJK and European text."""
        if not text:
            return 0.0
        lang = _detect_text_language(text)
        score = 0.0

        if lang == "zh":
            text_lower = text.lower()
            if any(p in text for p in CJK_AI_TELL_PHRASES):
                score += 0.30
            if any(p in text for p in CJK_FORMAL_WORDS):
                score += 0.15
            if not any(p in text for p in CJK_CASUAL_WORDS):
                score += 0.10
            if re.search(r'[\u3002\uff1b\uff1a]', text) and not re.search(r'[\uff01\uff1f]', text):
                score += 0.08
            if len(text) > 80:
                score += 0.10
            if re.search(r'[\u4e00\u4e8c\u4e09\u56db\u4e94\u516d\u4e03\u516b\u4e5d\u5341]\u3001', text):
                score += 0.12
            if any(p in text for p in ("\u9996\u5148", "\u5176\u6b21", "\u6700\u540e", "\u7b2c\u4e00", "\u7b2c\u4e8c", "\u7b2c\u4e09")):
                score += 0.10
            return min(1.0, score)

        elif lang == "ja":
            if any(p in text for p in JP_AI_TELL_PHRASES):
                score += 0.30
            if re.search(r'\u3002$', text) and not re.search(r'[\uff01\uff1fww]', text):
                score += 0.10
            if re.search(r'[\u2460\u2461\u2462\u2463\u2464]', text):
                score += 0.12
            if len(text) > 80:
                score += 0.08
            if not re.search(r'ww|\uff57\uff57|\u7b11', text):
                score += 0.05
            return min(1.0, score)

        elif lang == "ko":
            if any(p in text for p in KR_AI_TELL_PHRASES):
                score += 0.30
            if not any(p in text for p in CJK_CASUAL_WORDS):
                score += 0.10
            if re.search(r'[.\uff1b:]', text) and not re.search(r'[\u314b\u314e\u3160\u315c]', text):
                score += 0.08
            if len(text) > 80:
                score += 0.08
            return min(1.0, score)

        elif lang == "eu":
            text_lower = text.lower()
            if any(p in text_lower for p in EU_AI_TELL_PHRASES):
                score += 0.30
            if any(p in text_lower for p in EU_FORMAL_WORDS):
                score += 0.15
            if any(p in text for p in ("\u2014", "\u2013")):
                score += 0.10
            words = text.split()
            if len(words) >= 6:
                score += 0.05
            return min(1.0, score)

        return 0.0

    def _heuristic_score(self, text: str) -> float:
        """Combined heuristic score incorporating general formality,
        Llama-specific patterns, burstiness, lexical diversity, and
        punctuation anomalies."""
        form  = self.formality_score(text)
        llama = self.llama_pattern_score(text)
        rep   = self.repetition(text)
        ent   = self.entropy(text)
        length = min(1.0, len(text) / 300.0)
        ent_penalty = max(0.0, (ent - 4.0) / 2.0)

        # New signals
        burst   = 1.0 - self._burstiness(text)          # low burstiness \u2192 AI-like
        lex_div = 1.0 - self._lexical_diversity(text)   # low diversity \u2192 AI-like
        punct   = self._punctuation_anomaly(text)       # high anomaly \u2192 AI-like
        func_w  = self._function_word_ratio(text)       # high ratio \u2192 AI-like
        opener  = 1.0 - self._sentence_openers_variety(text)  # low variety \u2192 AI-like
        ml_form = self._multilang_formality_score(text) # CJK/EU language-specific signals

        lang = _detect_text_language(text)
        is_cjk_eu = lang not in ("en",)
        en_weight = 0.0 if is_cjk_eu else 0.28
        ml_weight = 0.30 if is_cjk_eu else 0.05
        llama_w = 0.10 if is_cjk_eu else 0.25

        return max(0.0, min(1.0,
            en_weight * form
            + llama_w * llama
            + ml_weight * ml_form
            + 0.10 * rep
            + 0.05 * length
            - 0.10 * ent_penalty
            + 0.08 * burst
            + 0.08 * lex_div
            + 0.06 * punct
            + 0.06 * func_w
            + 0.04 * opener
        ))

    # ---- ML signals ----

    def _binoculars_score(self, text: str) -> float:
        """Binoculars (Hans et al., 2024): CE_observer / CE_performer.

        Low ratio \u2192 both models find the text fluent \u2192 likely AI-generated.
        When `self._obs_modern` is set, both the performer (gpt2) and the
        modern observer run on their own tokenizers independently and we take
        whichever yields a stronger signal.  Falls back to classic (gpt2,
        distilgpt2) if the modern model is unavailable.
        Returns 0..1, higher = more AI-like.
        """
        if self._gpt2_tok is None or self._gpt2_model is None:
            return 0.0
        if len(text.split()) < 5:
            return 0.0

        performer_ready = self._gpt2_model is not None
        classic_ready   = performer_ready and self._obs_model is not None
        modern_ready    = performer_ready and self._obs_modern is not None and self._obs_modern_tok is not None

        if not classic_ready and not modern_ready:
            return 0.0

        best_ratio = None

        # Classic path (gpt2 performer + distilgpt2 observer)
        if classic_ready:
            try:
                enc = self._gpt2_tok(text, return_tensors="pt", truncation=True, max_length=128)
                enc = {k: v.to(self._device) for k, v in enc.items()}
                if enc["input_ids"].shape[1] >= 3:
                    with torch.inference_mode():
                        ce_perf = self._gpt2_model(**enc, labels=enc["input_ids"]).loss.item()
                        ce_obs  = self._obs_model(**enc, labels=enc["input_ids"]).loss.item()
                    if ce_perf >= 1e-6:
                        best_ratio = ce_obs / ce_perf
            except Exception:
                pass

        # Modern path (gpt2 performer + modern observer on its own tokenizer).
        # A strong fluency disagreement between the two architectures is a
        # cheaper signal than perplexity itself.
        if modern_ready:
            try:
                enc_m = self._obs_modern_tok(
                    text, return_tensors="pt", truncation=True, max_length=128,
                    padding=True,
                )
                enc_m = {k: v.to(self._device) for k, v in enc_m.items()}
                if enc_m["input_ids"].shape[1] >= 3:
                    with torch.inference_mode():
                        ce_modern = self._obs_modern(**enc_m, labels=enc_m["input_ids"]).loss.item()
                    if ce_modern >= 1e-6:
                        # Re-run performer through the same encoding to compare
                        # on the modern model's tokenization.
                        enc_p = self._gpt2_tok(
                            text, return_tensors="pt", truncation=True, max_length=128)
                        enc_p = {k: v.to(self._device) for k, v in enc_p.items()}
                        with torch.inference_mode():
                            ce_perf2 = self._gpt2_model(**enc_p, labels=enc_p["input_ids"]).loss.item()
                        if ce_perf2 >= 1e-6:
                            r = ce_modern / ce_perf2
                            if best_ratio is None or r < best_ratio:
                                best_ratio = r
            except Exception:
                pass

        if best_ratio is None:
            return 0.0

        # Calibration is model-pair specific.  distilgpt2 threshold:
        #   human ~1.3\u20132.5,  AI ~0.7\u20131.2  \u2192  score = (1.9 - r) / 1.3
        # A modern observer (e.g. TinyLlama) has lower perplexity overall,
        # so the ratio for AI text is typically *higher* (~1.0\u20131.6) because
        # both the performer and the modern model find it reasonably fluent.
        if self._obs_modern is not None and best_ratio is not None:
            return max(0.0, min(1.0, (2.2 - best_ratio) / 1.4))
        return max(0.0, min(1.0, (1.9 - best_ratio) / 1.3))

    def _classifier_score(self, text: str) -> float:
        """Average AI-probability across all loaded classifiers.

        Primary (cls1): Hello-SimpleAI/chatgpt-detector-roberta \u2014 strong on
          ChatGPT / GPT-4 / Claude family output.  If a LoRA adapter is loaded
          (Area 7), the LoRA-adapted cls1 is used instead.
        Secondary (cls2): openai-community/roberta-base-openai-detector \u2014 trained
          on GPT-2 outputs; generalises to Llama / Mistral / open-source LLMs
          because it captures broad fluency features rather than ChatGPT style.
        If cls2 failed to load only cls1 is used.
        """
        scores: List[float] = []
        if len(text.split()) < 5:
            return 0.0
        _cls_model = self._cls_model
        if getattr(self, "_lora_loaded", False) and self._lora_model is not None:
            _cls_model = self._lora_model
        if _cls_model is not None:
            try:
                enc = self._cls_tok(text, return_tensors="pt", truncation=True, max_length=128)
                enc = {k: v.to(self._device) for k, v in enc.items()}
                with torch.inference_mode():
                    logits = _cls_model(**enc).logits
                scores.append(torch.softmax(logits, dim=-1)[0][1].item())
            except Exception:
                pass
        if self._cls2_model is not None:
            try:
                enc2 = self._cls2_tok(text, return_tensors="pt", truncation=True, max_length=128)
                enc2 = {k: v.to(self._device) for k, v in enc2.items()}
                with torch.inference_mode():
                    logits2 = self._cls2_model(**enc2).logits
                # openai-community/roberta-base-openai-detector: LABEL_0=Real, LABEL_1=Fake
                scores.append(torch.softmax(logits2, dim=-1)[0][1].item())
            except Exception:
                pass
        return sum(scores) / len(scores) if scores else 0.0

    # ---- adversarial character-level detection ----

    @staticmethod
    def _char_ngram_entropy(text: str, n: int = 3) -> float:
        """Normalised entropy over character n-grams.  Low entropy suggests
        repetitive/patterned text; near-zero is suspicious for natural language
        but common in adversarial padding (e.g. "s p r e a d  o u t")."""
        if not text or len(text) < n:
            return 1.0
        ngrams: Counter = Counter()
        for i in range(len(text) - n + 1):
            ngrams[text[i:i + n]] += 1
        total = sum(ngrams.values())
        inv   = 1.0 / total
        ent   = -sum(c * inv * log2(c * inv) for c in ngrams.values())
        max_ent = log2(len(ngrams)) if ngrams else 1.0
        return ent / max_ent if max_ent > 0 else 0.0

    @staticmethod
    def _spacing_anomaly(text: str) -> float:
        """Score (0..1) for unusual spacing patterns common in adversarial
        evasion: multi-space gaps, letter-spacing (every-other char space),
        excessive whitespace."""
        if not text:
            return 0.0
        score = 0.0
        # Multi-space runs (>2 spaces)
        multi = re.findall(r'  +', text)
        if multi:
            score += min(0.4, 0.1 * len(multi))
        # Letter-spacing detection: "s p r e a d" pattern
        spaced = re.findall(r'\b(?:\w ){3,}\w\b', text)
        if spaced:
            score += min(0.5, 0.15 * len(spaced))
        # Whitespace ratio anomaly
        if len(text) > 10:
            ws_ratio = text.count(" ") / len(text)
            if ws_ratio > 0.5:
                score += min(0.3, (ws_ratio - 0.5) * 2.0)
        return min(1.0, score)

    @staticmethod
    def _adversarial_score(text: str) -> float:
        """Combined adversarial-evasion score (0..1).  Low char-ngram entropy
        combined with spacing anomalies is a strong indicator of adversarial
        padding designed to bypass classifiers."""
        if not text or len(text) < 8:
            return 0.0
        tri_ent = EnsembleAIDetector._char_ngram_entropy(text, n=3)
        quad_ent = EnsembleAIDetector._char_ngram_entropy(text, n=4)
        spacing = EnsembleAIDetector._spacing_anomaly(text)
        entropy_penalty = max(0.0, 0.5 - (tri_ent + quad_ent) * 0.5) * 0.6
        return min(1.0, entropy_penalty + 0.4 * spacing)

    # ---- embedding-based semantic drift ----

    def _embed_text(self, text: str):
        """Return a sentence embedding vector, or None on failure."""
        if self._embed_model is None:
            return None
        try:
            return self._embed_model.encode(text, convert_to_numpy=True)
        except Exception:
            return None

    @staticmethod
    def _cosine_sim(a, b) -> float:
        """Cosine similarity between two 1-D vectors."""
        import numpy as _np
        a_n = _np.linalg.norm(a)
        b_n = _np.linalg.norm(b)
        if a_n < 1e-8 or b_n < 1e-8:
            return 0.0
        return float(_np.dot(a, b) / (a_n * b_n))

    def _embedding_variance_score(self, text: str, recent_embeds: list) -> float:
        """Return 0..1 based on how much *text*'s embedding deviates from
        the user's recent embedding history.  Low variance (tight cluster)
        suggests machine-generated text.  Returns 0 if not enough data or
        embedding model unavailable."""
        if self._embed_model is None or not recent_embeds:
            return 0.0
        emb = self._embed_text(text)
        if emb is None:
            return 0.0
        sims = [self._cosine_sim(emb, e) for e in recent_embeds if e is not None]
        if len(sims) < 3:
            return 0.0
        avg_sim = sum(sims) / len(sims)
        # Humans typically have avg_sim ~0.6\u20130.8 (diverse topics);
        # bots cluster at ~0.85\u20131.0 (uniform style/topic).
        # Scale: 1.0 at avg_sim=1.0, 0.0 at avg_sim <= 0.60
        return max(0.0, min(1.0, (avg_sim - 0.60) / 0.40))

    # ---- main entry point ----

    def predict_detailed(self, text: str,
                         recent_embeds: Optional[list] = None) -> Dict[str, float]:
        """Return ensemble probability plus per-signal breakdown.

        Keys:
          prob  \u2013 final ensemble score (0\u20131)
          heu   \u2013 combined heuristic (formality + Llama patterns + repetition
                  + burstiness + lexical diversity + punctuation + function words)
          llama \u2013 raw Llama-specific pattern sub-score (0\u20131)
          bino  \u2013 Binoculars perplexity ratio score (0\u20131)
          cls   \u2013 average classifier score across all loaded models (0\u20131)
          adv   \u2013 adversarial-evasion score (char n-gram entropy + spacing) (0\u20131)
          embed \u2013 embedding-variance score (0\u20131); needs recent_embeds
          styl  \u2013 stylometric score (burstiness + lexical diversity + punctuation)
          wm    \u2013 watermark detection score (0\u20131)

        All values 0\u20131; higher = more likely AI-generated.
        Results are LRU-cached (up to _CACHE_MAX entries).
        """
        _zero: Dict[str, float] = {
            "prob": 0.0, "heu": 0.0, "llama": 0.0,
            "bino": 0.0, "cls": 0.0, "adv": 0.0, "embed": 0.0,
            "styl": 0.0, "watermark": 0.0}
        if not self.enabled:
            return _zero
        text = text.strip()
        if not text:
            return _zero

        cached = self._pred_cache.get(text)
        if cached is not None:
            try:
                self._pred_cache.move_to_end(text)
            except KeyError:
                pass  # evicted by a concurrent thread between get() and move_to_end()
            return cached  # type: ignore[return-value]

        # Reasoning-model CoT leakage: <think>...</think> tags from Qwen3 / DeepSeek-R1
        # bleeding into chat are unambiguous AI evidence \u2014 skip all other scoring.
        if re.search(r'</?think\b', text, re.IGNORECASE):
            _certain: Dict[str, float] = {
                "prob": 1.0, "heu": 1.0, "llama": 1.0,
                "bino": 1.0, "cls": 1.0, "adv": 1.0, "embed": 0.0,
                "styl": 1.0, "watermark": 1.0}
            if len(self._pred_cache) >= self._CACHE_MAX:
                self._pred_cache.popitem(last=False)
            self._pred_cache[text] = _certain
            return _certain

        llama = self.llama_pattern_score(text)
        heu   = self._heuristic_score(text)
        bino  = self._binoculars_score(text)
        cls   = self._classifier_score(text)
        adv   = self._adversarial_score(text)
        embed = self._embedding_variance_score(text, recent_embeds or [])
        wm    = self.watermark_score(text)

        # Stylometric composite: burstiness + lexical diversity + punctuation
        # These capture structural writing patterns independent of vocabulary
        burst   = 1.0 - self._burstiness(text)
        lex_div = 1.0 - self._lexical_diversity(text)
        punct   = self._punctuation_anomaly(text)
        func_w  = self._function_word_ratio(text)
        opener  = 1.0 - self._sentence_openers_variety(text)
        styl    = max(0.0, min(1.0,
            0.30 * burst
            + 0.25 * lex_div
            + 0.20 * punct
            + 0.15 * func_w
            + 0.10 * opener
        ))

        # Adaptive ensemble: ML models are unreliable on short IRC messages
        # (< 8 words) \u2014 weight heuristics much higher there.  For long text
        # (>= 30 words) Binoculars and the classifiers become more trustworthy.
        n_words = len(text.split())
        if n_words < 8:
            prob = max(0.0, min(1.0, 0.10 * bino + 0.10 * cls + 0.65 * heu + 0.15 * styl))
        elif n_words < 30:
            prob = max(0.0, min(1.0, 0.30 * bino + 0.30 * cls + 0.25 * heu + 0.15 * styl))
        else:
            prob = max(0.0, min(1.0, 0.32 * bino + 0.32 * cls + 0.20 * heu + 0.16 * styl))

        # High-confidence override: unambiguous Llama structural output in short
        # IRC messages should score high even when ML signals are uncertain.
        if llama >= 0.60 and prob < 0.55:
            prob = min(1.0, prob * 0.5 + llama * 0.5)

        # Stylometric override: strong structural anomalies push score up
        if styl >= 0.55 and prob < 0.50:
            prob = min(1.0, prob + 0.4 * styl * (1.0 - prob))

        # Adversarial-evasion override: strong spacing/entropy anomalies push
        # the score upward regardless of the main ensemble.
        if adv >= 0.40:
            prob = min(1.0, prob + 0.6 * adv * (1.0 - prob))

        # Embedding-variance boost: add up to +0.08 when the text is unusually
        # consistent with the user's own recent style.
        if embed > 0.0:
            prob = min(1.0, prob + 0.08 * embed)

        # Watermark-detection boost: add up to +0.12 when watermark patterns found
        if wm > 0.0:
            prob = min(1.0, prob + 0.12 * wm)

        result: Dict[str, float] = {
            "prob": prob, "heu": heu, "llama": llama, "bino": bino,
            "cls": cls, "adv": adv, "embed": embed, "styl": styl, "watermark": wm}

        if len(self._pred_cache) >= self._CACHE_MAX:
            self._pred_cache.popitem(last=False)   # O(1) FIFO eviction
        self._pred_cache[text] = result
        return result

    def predict_prob(self, text: str) -> float:
        """Convenience wrapper \u2014 returns only the ensemble probability (0\u20131)."""
        return self.predict_detailed(text)["prob"]

    # ---- watermark detection (Area 5) ----

    def watermark_score(self, text: str) -> float:
        """Detect common LLM watermark patterns.  Returns 0..1.

        Checks:
          \u2022 Duplicate-token watermark (repeated function words / high-frequency
            tokens at suspiciously regular intervals)
          \u2022 Green-red list bias (unusual token-frequency distribution)
          \u2022 Structural watermarks (uniform sentence length, low positional entropy)
        """
        if not text or len(text) < 10:
            return 0.0
        score = 0.0
        words = text.lower().split()
        n_words = len(words)
        if n_words < 5:
            return 0.0

        # \u2500\u2500 Duplicate-token watermark \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        # Some watermarking schemes bias toward repeating high-frequency tokens.
        # Detect by counting function-word repeats at 3\u20137 token intervals.
        _func_words = frozenset({
            "the", "a", "an", "of", "to", "in", "is", "that", "for", "it",
            "on", "and", "be", "or", "as", "at", "by", "with", "this", "are",
            "was", "were", "been", "has", "have", "had", "do", "does", "did",
            "will", "would", "can", "could", "may", "might", "shall", "should",
            "not", "no", "so", "if", "than", "then", "but", "because", "we",
        })
        func_positions = [i for i, w in enumerate(words) if w in _func_words]
        if len(func_positions) >= 6:
            gaps = [func_positions[i+1] - func_positions[i]
                    for i in range(len(func_positions)-1)]
            if gaps:
                mean_gap = sum(gaps) / len(gaps)
                low_var = sum((g - mean_gap) ** 2 for g in gaps) / len(gaps)
                cv = (low_var ** 0.5) / max(mean_gap, 1)
                # Suspiciously regular function-word spacing \u2192 watermark
                if cv < 0.30 and mean_gap <= 7:
                    score += 0.25

        # \u2500\u2500 Green-red token bias \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        # Watermarked text tends to have an unusually uniform token-frequency
        # rank distribution (too many "medium-rare" tokens, too few rare ones).
        if n_words >= 10:
            wf: Counter = Counter()
            for w in words:
                wf[w] += 1
            freqs = sorted(wf.values(), reverse=True)
            if len(freqs) >= 5:
                top3 = sum(freqs[:3])
                rare = sum(freqs[3:])
                total_f = sum(freqs)
                top3_ratio = top3 / total_f if total_f else 0
                # Human text: top-3 words account for ~15\u201335% of tokens.
                # Watermarked: more uniform \u2192 top-3 ratio < 15% or > 45%.
                if top3_ratio < 0.15:
                    score += 0.15
                elif top3_ratio > 0.45:
                    score += 0.10

        # \u2500\u2500 Sentence-length uniformity \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
        # Watermarked prose often has very uniform sentence lengths.
        sentences = re.split(r'[.!?]+', text)
        sent_lens = [len(s.split()) for s in sentences if len(s.split()) >= 2]
        if len(sent_lens) >= 4:
            m_sl = sum(sent_lens) / len(sent_lens)
            v_sl = sum((sl - m_sl) ** 2 for sl in sent_lens) / len(sent_lens)
            cv_sl = (v_sl ** 0.5) / max(m_sl, 1)
            if cv_sl < 0.25:
                score += 0.20

        return min(1.0, score)

    # ---- LoRA incremental fine-tuning (Area 7) ----

    def _init_lora(self) -> bool:
        """Attempt to prepare a LoRA adapter on cls1.  Returns True if ready."""
        if self._cls_model is None:
            return False
        try:
            from peft import LoraConfig, get_peft_model, TaskType
            if getattr(self, "_lora_peft_config", None) is None:
                self._lora_peft_config = LoraConfig(
                    task_type=TaskType.SEQ_CLS,
                    r=8,
                    lora_alpha=16,
                    lora_dropout=0.05,
                    target_modules=["query", "value"],
                )
                self._lora_model = get_peft_model(self._cls_model, self._lora_peft_config)
                self._lora_model.to(self._device)
            return True
        except ImportError:
            return False

    def _train_lora_adapter(self, positive_texts: List[str], negative_texts: List[str],
                             output_path: str, epochs: int = 3) -> str:
        """Fine-tune the LoRA adapter on positive vs negative examples.

        Runs synchronously (call from a thread executor).  Returns the adapter
        path on success, or an error message on failure.
        """
        if not _PEFT_AVAILABLE or self._cls_tok is None:
            return "PEFT not available"
        if not self._init_lora():
            return "failed to init LoRA"
        # Limit PyTorch to 1 thread so BLAS doesn't starve the event loop
        _old_torch_threads = torch.get_num_threads()
        torch.set_num_threads(1)
        from torch.utils.data import DataLoader, TensorDataset
        texts = positive_texts + negative_texts
        labels = [1] * len(positive_texts) + [0] * len(negative_texts)
        if len(texts) < 4:
            return "need at least 4 examples (2 pos + 2 neg)"
        enc = self._cls_tok(texts, truncation=True, padding=True, max_length=128, return_tensors="pt")
        dataset = TensorDataset(enc["input_ids"], enc["attention_mask"], torch.tensor(labels))
        loader = DataLoader(dataset, batch_size=4, shuffle=True)
        opt = torch.optim.AdamW(self._lora_model.parameters(), lr=3e-5)
        self._lora_model.train()
        for epoch in range(epochs):
            for batch_ids, batch_mask, batch_labels in loader:
                batch_ids = batch_ids.to(self._device)
                batch_mask = batch_mask.to(self._device)
                batch_labels = batch_labels.to(self._device).float()
                out = self._lora_model(input_ids=batch_ids, attention_mask=batch_mask,
                                       labels=batch_labels.long())
                loss = out.loss
                opt.zero_grad()
                loss.backward()
                opt.step()
        self._lora_model.eval()
        try:
            os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
            self._lora_model.save_pretrained(output_path)
        except Exception as e:
            return f"save failed: {e}"
        finally:
            torch.set_num_threads(_old_torch_threads)
        self._lora_loaded = True
        return output_path
