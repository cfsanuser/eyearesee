"""AI Module — AI detection engine, sentiment analysis, and model providers.

Each submodule contains a single class or related function group that was
extracted from the main eyearesee.py client.

Imports are lazy — modules that fail to load (missing optional dependencies)
don't prevent the remaining AI features from working.
"""

import os

# ── Core AI detector ────────────────────────────────────────────────────────
try:
    from .detector import EnsembleAIDetector, _detect_text_language
except ImportError:
    EnsembleAIDetector = None
    _detect_text_language = None

# ── Analytics ───────────────────────────────────────────────────────────────
try:
    from .sentiment import SentimentAnalyzer
except ImportError:
    SentimentAnalyzer = None

try:
    from .anomaly import BehavioralAnomalyDetector
except ImportError:
    BehavioralAnomalyDetector = None

try:
    from .topics import TopicDetector
except ImportError:
    TopicDetector = None

try:
    from .semantic import SemanticSimilarityDetector
except ImportError:
    SemanticSimilarityDetector = None

try:
    from .crosschannel import CrossChannelBotDetector
except ImportError:
    CrossChannelBotDetector = None

try:
    from .calibration import AICalibrationManager
except ImportError:
    AICalibrationManager = None

# ── Model providers ─────────────────────────────────────────────────────────
try:
    from .providers import (
        call_claude, call_openai, call_deepseek, call_copilot,
        call_gemini, call_ollama, call_llamacpp,
        _ollama_blocking_call, _llamacpp_blocking_call,
    )
except ImportError:
    call_claude = call_openai = call_deepseek = call_copilot = None
    call_gemini = call_ollama = call_llamacpp = None
    _ollama_blocking_call = _llamacpp_blocking_call = None
