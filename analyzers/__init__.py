"""Analyzers Plugin Package — auto-discovered analytics modules.

Place any `.py` file in this directory to have it auto-loaded as an analyzer
plugin.  Each module must export a top-level `setup(api)` function (sync or async)
receiving a `PluginAPI` instance.

Optional module-level metadata:
    __plugin_name__    = "My Analyzer"
    __plugin_version__ = "1.0"
    __plugin_author__  = "Author"
    __plugin_desc__    = "Description"

Analyzers can register slash commands, event hooks, keybindings, and
background tasks.  See the PluginAPI class for the full interface.

Built-in analyzers (shipped alongside the package):
    echo_chamber.py       — EchoChamberDetector slash commands
    astroturfing.py       — AstroturfingDetector slash commands
    debate_quality.py     — DebateAnalyzer slash commands
    sentiment_influence.py— Sentiment contagion & influence commands
    role_classifier.py    — RoleInference slash commands
    user_dossier.py       — Unified social dossier reporting
    threat_score.py       — Cross-analyzer threat assessment
    activity_heatmap.py   — Visual activity heatmap in stats panel
"""

import importlib
import importlib.util as _importlib_util
import logging
import os
import pathlib
import sys
from typing import Callable, Dict, Any, Optional

_log = logging.getLogger(__name__)

_loaded_modules: Dict[str, Any] = {}
_registry: Dict[str, Dict[str, Any]] = {}

ANALYZER_DIR = os.path.dirname(os.path.abspath(__file__))


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
    """Load a single analyzer plugin by name.

    Args:
        name: The analyzer name (stem of the .py file in this directory).
        tui: The TUI instance (or None for headless usage).
        PluginAPI: The PluginAPI class (avoids circular import).
    Returns the PluginAPI instance on success, or None.
    """
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
        _log.warning("Analyzer %s has no setup(api) function", name)
        return None

    if PluginAPI is None:
        import eyearesee as _eya
        PluginAPI = getattr(_eya, "PluginAPI", None)
        if PluginAPI is None:
            _log.warning("PluginAPI class not found in eyearesee module")
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
    """Return the registry of loaded analyzer metadata."""
    return dict(_registry)


def get_commands(tui: Any = None) -> Dict[str, tuple]:
    """Return {command_name: (api, handler)} for all loaded analyzers."""
    cmds: Dict[str, tuple] = {}
    for name, api in _loaded_modules.items():
        for cmd_name, handler in api._commands.items():
            cmds[cmd_name] = (api, handler)
    return cmds
