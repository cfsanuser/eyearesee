"""Analyzers Plugin Package — modular IRC analytics subsystem.

Each `.py` file in this directory contains a single analyzer class that is
auto-discovered and loaded as a plugin.  The classes themselves can also be
imported directly for use in ScoringEngine and other core modules.

Usage:
    from analyzers import PersonalityProfiler, StanceTracker, ...
    from analyzers import load_all  # plugin auto-loader
"""

import importlib.util as _importlib_util
import logging
import os
import pathlib
import sys
from typing import Callable, Dict, Any, Optional

_log = logging.getLogger(__name__)

# ── Class exports ───────────────────────────────────────────────────────────
# Import each analyzer class so they are accessible as analyzers.ClassName.
# Each import is wrapped in try/except so missing optional analyzer files
# don't prevent the rest from loading.

try:
    from .astroturfing import AstroturfingDetector
except ImportError:
    AstroturfingDetector = None

try:
    from .personality import PersonalityProfiler
except ImportError:
    PersonalityProfiler = None

try:
    from .predictive_reply import PredictiveReplyEngine
except ImportError:
    PredictiveReplyEngine = None

try:
    from .stance_tracker import StanceTracker
except ImportError:
    StanceTracker = None

try:
    from .conversation_flow import ConversationFlowPredictor
except ImportError:
    ConversationFlowPredictor = None

try:
    from .sentiment_contagion import SentimentContagionMap
except ImportError:
    SentimentContagionMap = None

try:
    from .bot_swarm import BotSwarmDetector
except ImportError:
    BotSwarmDetector = None

try:
    from .role_inference import RoleInference
except ImportError:
    RoleInference = None

try:
    from .debate_analyzer import DebateAnalyzer
except ImportError:
    DebateAnalyzer = None

try:
    from .echo_chamber import EchoChamberDetector
except ImportError:
    EchoChamberDetector = None

try:
    from .achievements import AchievementBadges
except ImportError:
    AchievementBadges = None

try:
    from .sarcasm import SarcasmDetector
except ImportError:
    SarcasmDetector = None

try:
    from .emotion_arc import EmotionArc
except ImportError:
    EmotionArc = None

try:
    from .ban_evasion import BanEvasionDetector
except ImportError:
    BanEvasionDetector = None

try:
    from .fact_checker import RealtimeFactChecker
except ImportError:
    RealtimeFactChecker = None

try:
    from .research_agent import AutonomousResearchAgent
except ImportError:
    AutonomousResearchAgent = None

try:
    from .conversational_agent import ConversationalAgent
except ImportError:
    ConversationalAgent = None

try:
    from .aivsai import AIVsAIDetector
except ImportError:
    AIVsAIDetector = None

try:
    from .sentiment_ai_corr import SentimentAICorrelator
except ImportError:
    SentimentAICorrelator = None


ANALYZER_DIR = os.path.dirname(os.path.abspath(__file__))

_loaded_modules: Dict[str, Any] = {}
_registry: Dict[str, Dict[str, Any]] = {}


def discover() -> Dict[str, str]:
    """Scan the analyzers directory and return {name: path} for all .py files.

    Files starting with `_` or `.` are skipped.
    """
    found: Dict[str, str] = {}
    try:
        for entry in pathlib.Path(ANALYZER_DIR).iterdir():
            if not entry.is_file():
                continue
            if entry.name.startswith(("_", ".")):
                continue
            if not entry.suffix == ".py":
                continue
            name = entry.stem
            found[name] = str(entry)
    except OSError:
        pass
    return found


def load(name: str, tui: Any = None, PluginAPI: Optional[type] = None) -> Optional[Any]:
    """Load a single analyzer plugin by name."""
    global _loaded_modules, _registry

    path = os.path.join(ANALYZER_DIR, name + ".py")
    if not os.path.isfile(path):
        return None

    if name in _loaded_modules:
        return _loaded_modules[name]

    spec = _importlib_util.spec_from_file_location(
        f"analyzers.{name}", path
    )
    if spec is None or spec.loader is None:
        _log.warning("Could not create spec for %s", name)
        return None

    mod = _importlib_util.module_from_spec(spec)
    try:
        spec.loader.exec_module(mod)
    except Exception as exc:
        _log.warning("Failed to load analyzer %s: %s", name, exc)
        return None

    setup_fn = getattr(mod, "setup", None)
    if not callable(setup_fn):
        return None

    if PluginAPI is None:
        try:
            import eyearesee as _eya
            PluginAPI = getattr(_eya, "PluginAPI", None)
        except Exception:
            pass
        if PluginAPI is None:
            return None

    api = PluginAPI(f"analyzer:{name}", tui)
    if hasattr(mod, "__plugin_name__"):
        api.set_metadata(
            version=getattr(mod, "__plugin_version__", ""),
            author=getattr(mod, "__plugin_author__", ""),
            description=getattr(mod, "__plugin_desc__", ""),
        )

    try:
        setup_fn(api)
    except Exception as exc:
        _log.warning("Analyzer %s setup() failed: %s", name, exc)
        return None

    _loaded_modules[name] = api
    _registry[name] = {
        "name": getattr(mod, "__plugin_name__", name),
        "version": getattr(mod, "__plugin_version__", ""),
        "author": getattr(mod, "__plugin_author__", ""),
        "description": getattr(mod, "__plugin_desc__", ""),
        "path": path,
    }
    return api


def load_all(tui: Any = None, PluginAPI: Optional[type] = None) -> Dict[str, Any]:
    """Discover and load all analyzer plugins. Returns {name: api} dict."""
    loaded: Dict[str, Any] = {}
    for name in discover():
        api = load(name, tui, PluginAPI)
        if api is not None:
            loaded[name] = api
    return loaded


def unload(name: str) -> bool:
    """Unload an analyzer plugin by name."""
    global _loaded_modules, _registry
    api = _loaded_modules.pop(name, None)
    _registry.pop(name, None)
    if api is not None and hasattr(api, "_teardown_fn"):
        try:
            api._teardown_fn(api)
        except Exception:
            pass
    return api is not None


def get_registry() -> Dict[str, Dict[str, Any]]:
    return dict(_registry)


def get_commands(tui: Any = None) -> Dict[str, tuple]:
    cmds: Dict[str, tuple] = {}
    for name, api in _loaded_modules.items():
        for cmd_name, handler in api._commands.items():
            cmds[cmd_name] = (api, handler)
    return cmds
