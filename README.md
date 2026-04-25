( For windows users don't forget to install Python: https://www.python.org/downloads/ and don't forget to run pip install windows-curses )

eyearesee — Terminal IRC Client with Built-in AI Detection
eyearesee.py is a single-file, ~5,200-line Python IRC client that runs in the terminal (curses TUI) and bolts a fairly serious AI-text-detection pipeline onto a real, working IRC stack. The headline idea: while you're chatting, every message on the channel is scored in the background for how likely it is to have been written by an LLM, and suspect users get flagged in the userlist with a rolling score.
It runs on Linux, macOS, and Windows (auto-installs windows-curses if needed), connects over SSL by default (irc.libera.chat:6697), and prompts you for server / nick / channel / NickServ password on first launch.
Core architecture
A handful of cooperating classes do the work, all driven by asyncio:

IRCClient — async TCP/SSL socket, full IRC line parser, handles JOIN/PART/QUIT/PRIVMSG/NOTICE/MODE/CAP, NickServ identify, CTCP, server numerics, and reconnection.
TUI — curses-based interface with multiple windows (status, channels, DMs), userlist sidebar, scrollable buffer, input line with history, theme support, and a dashboard.
EnsembleAIDetector — the ML side; loads several models and combines their scores.
ScoringEngine / UserState / BotFingerprint — per-nick rolling state, score history, typing fingerprints for confirmed bots.
PluginManager / PluginAPI — runtime-loadable Python plugins.
ServerContext — lets you connect to multiple IRC networks in parallel from one TUI.

Feature highlights
1. Real IRC client, not a toy
It's a complete client: SSL connections, multi-server support (/server), channel join/part, DMs (/msg, /query), /me actions, NickServ/ChanServ, modes and ops (/op, /voice, /ban, /kick, /invite, /mode), /whois, /who, /whowas, /away//back, /ignore, CTCP, /topic, /names. Channel-join error numerics (471/473/474/475/477/489) are routed back to the relevant window so you actually see why a join failed.
2. AI-text detection ensemble
This is the unusual part. For every message, it computes an AI-likelihood score (0–100) by combining four signals:

Binoculars — runs the text through GPT-2 (the "performer") and DistilGPT-2 (the "observer") and looks at the cross-entropy ratio. AI-generated text tends to have an unusually low ratio because it's "too predictable."
RoBERTa classifiers — Hello-SimpleAI/chatgpt-detector-roberta (primary) and openai-community/roberta-base-openai-detector (secondary, broader).
Heuristics — entropy, repetition, formality, em-dash usage, contractions, length, capitalization patterns.
LLM "tell" phrase lists — large frozensets of giveaway phrases ("delve into," "tapestry," "it's worth noting," "as an AI," "I hope this helps," etc.) plus a separate Llama/open-source-LLM pattern detector that catches things like markdown structure in plain chat, numbered lists, and bot-opener words.

Models load on startup with progress messages, run on GPU if available (torch.cuda), and predictions are LRU-cached (512 entries) since bots repeat themselves.
Optional: /model can route messages through Claude, GPT, Ollama, or llama.cpp for an additional "is this AI?" verdict from an actual LLM.
3. Per-user scoring and flagging

Each nick gets a rolling AI score over the last 200 messages. Users above the threshold (70 by default) appear with their score next to their nick in the userlist and get colored as "suspect."
/ai <nick> — full profile: current score, idle time, sparkline of recent scores, verdict.
/topai — ranked list of every scored user in the current channel.
/bot <nick> / /unbot <nick> — manually mark a nick as a confirmed bot and build a typing fingerprint from their messages.
/aitoggle — turn detection on/off.

4. JSONL detection log
Every scored message is appended to ai_scores.log as one JSON object per line, with timestamp, session UUID, sequence number, nick, target, the four sub-scores (heuristic / Binoculars / classifier / Llama), the ensemble score, the rolling average, and the message text (capped at 512 bytes). Session-start markers and toggle events are recorded too, so gaps in seq are auditable. The log can be replayed to compute per-nick history and a "historical suspects" leaderboard across sessions. /logtoggle controls it; IRC_AI_LOG=0 disables at startup.
5. AI assistants for you
Quite separate from the detection side, you can ask AI models things directly:

/askai [model] <question> — answer rendered in the dashboard.
/summarize [n] [model] — summarizes the last n messages in the current window.
/model — pick between Claude (Opus/Sonnet/Haiku), GPT (4o, 4 Turbo, 3.5), Ollama (Gemma 3, Llama 3.2), or llama.cpp (Gemma 4, Qwen 3). Local backends require no API key.
/api — view or set ANTHROPIC_API_KEY, OPENAI_API_KEY, OLLAMA_URL in the environment.

6. CJK auto-translation
A Unicode-block-based detector identifies Chinese/Japanese/Korean text (supports CJK Extensions A–G, Hangul Jamo, Kanbun, Bopomofo, Katakana phonetic extensions, the lot). When triggered, an async translation pipeline fetches an English version inline. /autotranslate toggles it; on by default.
7. TUI quality of life

Multiple windows, switched with Ctrl+N or /win <n>, closed with /close / /wc.
Tab for nick completion, PgUp/PgDn for scroll.
Persistent input history (last 500 commands, irc_input_history.txt) survives restarts; chat logs per window go to chat_logs/<window>.log and are reloaded on rejoin.
Five color themes (Classic, Hacker, Ocean, Sunset, Neon) via /theme.
Wide-character-aware rendering — CJK and fullwidth characters take their proper 2 columns, IRC formatting codes (bold, italic, underline, reverse, color) are parsed and stripped or rendered correctly, and the parse cache (512 entries) avoids reparsing the same line on every redraw.

8. Plugin system
/loadplugin <path>, /unloadplugin, /reloadplugin (hot-swap), /plugins. A plugin is a Python file exposing setup(api); PluginAPI lets it register slash commands and hook into events.
9. Production touches

Auto-installs missing dependencies (anthropic, openai, transformers, torch) on first run via pip and restarts itself.
Reconfigures stdout/stderr to UTF-8 on Windows so the box-drawing intro prints correctly.
Persistent file handles for the AI log, input history, and chat logs (8 KB buffering for chat, line-buffered for crash safety on the AI log), with an atexit flush.
Filename sanitization that blocks directory traversal in window names.
IRC nick/channel input is sanitized to RFC 1459 character classes.
Clean shutdown: cancels async tasks, sends QUIT, drains the writer with timeouts so it doesn't hang on a dead socket.

In one sentence
It's a fully usable terminal IRC client that quietly runs a four-signal ML pipeline on every line of chat, scores users for AI-likelihood, logs everything as JSONL, and also lets you talk to Claude / GPT / local LLMs from the same interface — with multi-server, multi-window, plugins, themes, CJK translation, and persistent history along the way.
