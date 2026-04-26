( Note: python eyearesee.py --no-ai --no-install will run without installing dependencies or using offline AI )

Analysis: eyearesee.py
What it is
eyearesee.py (the name puns on "I-R-C") is a single-file, terminal-based IRC client written in Python 3 — about 5,480 lines in one module. Despite being one file, it bundles together what would normally be three or four separate projects:

A full-featured IRC client with a curses TUI
An AI-text detection engine that scores every message for likelihood of being LLM-generated
LLM integration for asking questions and summarizing chat (Claude, OpenAI, Ollama, llama.cpp)
A small plugin system with hot-reload

It's clearly a personal/hobby project of considerable scope — the comments are conversational, packages auto-install on first run, and the whole thing is designed to launch from a single python eyearesee.py invocation.
High-level architecture
The module is organized into roughly ten classes plus a layer of free functions. The major ones, by size:
ClassLinesRoleTUI~2,700Curses interface, input handling, slash-command dispatch, renderingIRCClient~900Async IRC protocol: connection, parsing, sending, NickServ, CTCP, flood controlEnsembleAIDetector~350The AI-detection ensemble (transformers + heuristics)PluginAPI / PluginManager~150Public API surface + lifecycle for user pluginsScoringEngine, BotFingerprint, UserState, ChatWindow, ServerContextsmallerPer-user/per-channel state and scoring glue
Concurrency is built on asyncio — one task drives the IRC connection (read loop, write queue with rate-limiting for flood protection), another drives the TUI render/input loop, and they communicate through an asyncio.Queue. curses.wrapper runs asyncio.run(main_curses(...)), which is a slightly unusual but workable pattern.
Multi-server support is in there: TUI.servers is a dict of ServerContext objects, and the active server's state is aliased onto self.* during event dispatch.
The IRC client side
The IRC half is reasonably complete, not just a toy:

TLS by default (port 6697), with the option to fall back to plain.
CAP negotiation, NickServ identification (password from IRC_NICKSERV_PASSWORD env var), CTCP responses with rate-limiting, ISUPPORT parsing.
Outbound flood control — every send goes through an asyncio.Queue (max 512) drained by a writer task that paces messages so the server doesn't disconnect for excess flood.
Numeric replies are categorized into frozensets (_WHOIS_REPLIES, _WHO_REPLIES, _SERVER_INFO, _ERROR_REPLIES, _SILENT_NUMERICS) for fast routing.
Per-window chat logs in chat_logs/, with safe-filename sanitization that also collapses .. to prevent directory traversal.
Input history persists across runs in irc_input_history.txt.
CJK auto-translation: messages with ≥2 CJK characters are routed through Google Translate's free translate_a/single endpoint, gated by an asyncio.Semaphore(3) and an LRU cache (256 entries) so common phrases never re-hit the network.

The slash-command surface is broad — channel ops (/op, /ban, /mode), services (/ns, /cs), users (/whois, /ignore, /away), windows/themes, plugins, and 5 built-in color themes. The terminal-rendering code is careful: there are dedicated wide-character helpers (_char_width, _str_visual_width, _truncate_to_width, _irc_visual_pos) so CJK columns don't break alignment, and IRC formatting codes (\x02 bold, \x03 color, \x1D italic, etc.) are parsed into curses attributes with a 512-entry parse cache to avoid re-parsing on every redraw.
The AI-detection engine
This is the most interesting part and what gives the file its character. EnsembleAIDetector blends several signals to produce a 0–100 "AI score" for each message:

Binoculars (Hans et al., 2024) — runs the text through GPT-2 as a "performer" and DistilGPT-2 as an "observer" and uses the cross-entropy ratio as a perplexity-based AI signal. This is a real published technique.
A primary classifier: Hello-SimpleAI/chatgpt-detector-roberta — a HuggingFace RoBERTa fine-tuned on ChatGPT outputs.
A secondary classifier (optional, opportunistic): openai-community/roberta-base-openai-detector — broader GPT-2-era detector for non-OpenAI families.
Hand-tuned heuristics: a formality_score that adds weighted signals for em-dashes, "AI tell phrases", Llama-specific phrasing, lack of contractions, capitalized openings, no emoticons, plus a llama_pattern_score that catches markdown lists/bullets/numbered structure showing up incongruously in IRC.
Optional LLM-as-judge: for the active model (/model), it can call out to Claude/OpenAI/Ollama/llama.cpp asking "is this AI text?" — combined as 60% local ensemble + 40% LLM signal.
BotFingerprint: once a user is confirmed via /bot <nick>, the engine builds a vocabulary/bigram/trigram fingerprint of their messages, then nudges the score upward for other users whose text overlaps significantly. This is a learn-from-positives feedback loop.

Predictions are LRU-cached (512 entries) since chat repeats. There's also the ScoringEngine/UserState machinery to track rolling AI scores per user, idle times, message-length statistics, etc., and a /topai command to rank everyone in a channel.
Detection events are logged to ai_scores.log as JSONL (one JSON object per line, with ts, dt, session UUID, monotonic seq, nick, target, individual sub-scores, and the message). Logging can be toggled live with /logtoggle or via the IRC_AI_LOG env var. There's a _load_all_nick_ai_history() helper that replays the log on startup so the running nick scores survive across sessions.
LLM integration
The AI_MODELS registry is a single dict of short names → provider/model-id/label, covering:

Anthropic Claude (opus, sonnet, haiku)
OpenAI (gpt4o, gpt4, gpt35)
Ollama local server (gemma, llama3)
llama.cpp local server (gemma4, qwen3)

/askai and /summarize route through this registry. Default is qwen3 (local llama.cpp) — meaning the author's intended hot path is fully offline. There are blocking helpers _ollama_blocking_call and _llamacpp_blocking_call that talk to the local servers' OpenAI-compatible endpoints; cloud providers use their official SDKs if installed.
One thing to flag, since the file's model registry will be visible to a user reading this: the Claude model IDs hard-coded there (claude-opus-4-6, claude-sonnet-4-6, claude-haiku-4-5-20251001) don't match Anthropic's current model strings exactly — claude-opus-4-6 and claude-sonnet-4-6 should be claude-opus-4-6 style hyphenation… actually, the canonical strings are claude-opus-4-6, claude-sonnet-4-6, and claude-haiku-4-5-20251001 for the current generation; whether 4-6 will resolve depends on Anthropic's aliasing. Worth verifying against the API before relying on /askai opus working out of the box.
The plugin system
Small but real. A plugin is a Python file that defines setup(api) (and optionally teardown(api)). The PluginAPI object hands out a @api.command("name") decorator to register slash commands and helpers like api.status(...) to print to the status window. /loadplugin, /unloadplugin, and /reloadplugin all work, with the reload using importlib to hot-swap. Both sync and async command handlers are supported.
Notable engineering choices
A few things stand out as quietly thoughtful:

Auto-install of optional deps (_ensure_deps) — on first run, missing packages are pip-installed and the process re-execs itself so module-level imports re-resolve. Good UX for a script you want to "just work."
Windows-curses handling with a manual sys.path widening pass before falling back to pip install windows-curses.
Persistent file handles for the AI log, chat logs, and input history, with an atexit flush — avoids open/close syscall thrash but makes crash-recovery slightly riskier (mitigated by line-buffered mode where it matters).
All data files live next to the script (_SCRIPT_DIR), so launching from C:\Windows\system32 doesn't strand logs in unexpected places.
Filename safety: _chat_log_path strips control chars and collapses .. runs to defeat directory traversal — this isn't paranoid, since channel/window names come from the network.

Concerns and rough edges
Honest assessment:

The TUI class is enormous (~2,700 lines). It's doing rendering, input, every slash command, multi-server bookkeeping, and dashboard generation. It's the obvious refactor target — pulling slash commands into a registry like the plugin system already uses would shed thousands of lines.
Single-file packaging at 5,500 lines makes the codebase harder to navigate than it needs to be. Splitting EnsembleAIDetector and the IRC protocol layer into their own modules would help future-you a lot.
Auto-pip-install on launch is convenient but surprising; some users won't expect a chat client to mutate their site-packages. A --no-install flag or --no-ai is
set it will stay disabled.
The Google Translate endpoint used (translate.googleapis.com/translate_a/single?client=gtx) is undocumented and unofficial — it works today but Google has rate-limited or broken it before. Worth having a graceful fallback path.
Heuristics in formality_score have hand-tuned weights without an obvious calibration corpus. The comment says "calibrated for 2025/2026 LLM output patterns" which is honest, but the false-positive rate on heavily formal human writers (academics, non-native English speakers writing carefully) is probably non-trivial. The fingerprint feedback loop could amplify this.
Plenty of broad except Exception: pass in the I/O paths. Pragmatic for a TUI app where you don't want a logging hiccup to crash the chat, but it does swallow real bugs.

Summary
eyearesee.py is an ambitious, single-file IRC client that grafts a serious AI-text-detection pipeline (Binoculars + RoBERTa classifiers + heuristics + optional LLM judging) onto a competent terminal IRC implementation, then adds LLM chat integration and a plugin system on top. The IRC layer is genuinely solid — async, TLS, flood-controlled, CJK-aware, multi-server. The AI-detection ensemble is the most novel piece and shows real familiarity with the literature. The main weakness is structural: at 5,500 lines, the TUI class in particular is screaming to be broken up. As a working tool it's impressive; as a codebase to maintain long-term it would benefit from a modularization pass.
