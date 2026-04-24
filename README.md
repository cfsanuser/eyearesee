 eyearesee.py — Advanced Feature Overview
                                                                                                                          ~4,800 lines · single-file Python · asyncio + curses
                                                                                                                          ---
  Architecture

  The client is built entirely on asyncio with no threading. Four concurrent coroutines run in the event loop at all
  times: an IRC reader, a flood-controlled write queue flusher, an AI scoring pipeline, and the TUI render loop. Curses
  is driven synchronously from within the async loop via a narrow dirty-flag system so screen redraws only happen when
  state actually changes.

  ---
  Core Classes

  ┌────────────────────┬─────────────────────────────────────────────────────┐
  │       Class        │                        Role                         │
  ├────────────────────┼─────────────────────────────────────────────────────┤
  │ EnsembleAIDetector │ Multi-signal AI text classifier                     │
  ├────────────────────┼─────────────────────────────────────────────────────┤
  │ ScoringEngine      │ Owns the detector; coordinates per-nick scoring     │
  ├────────────────────┼─────────────────────────────────────────────────────┤
  │ UserState          │ Per-nick rolling stats via O(1) incremental sums    │
  ├────────────────────┼─────────────────────────────────────────────────────┤
  │ ChatWindow         │ Named message pane backed by a deque(maxlen=500)    │
  ├────────────────────┼─────────────────────────────────────────────────────┤
  │ IRCClient          │ Full IRC protocol layer (one instance per server)   │
  ├────────────────────┼─────────────────────────────────────────────────────┤
  │ ServerContext      │ Bundles an IRCClient with its per-server window set │
  ├────────────────────┼─────────────────────────────────────────────────────┤
  │ TUI                │ curses renderer, input handling, all slash commands │
  └────────────────────┴─────────────────────────────────────────────────────┘

  ---
  IRC Protocol Layer

  - IRCv3: CAP negotiation (server-time, message-tags, sasl, multi-prefix, away-notify, account-notify, extended-join)
  - SASL PLAIN authentication over TLS
  - NickServ IDENTIFY fallback when SASL is unavailable
  - Flood control: outbound messages go through asyncio.Queue(maxsize=512); the writer coroutine rate-limits them to
  avoid server disconnection
  - Keepalive: sends PING every 90 s; treats missing PONG within 45 s as a dead connection and reconnects
  - Nick collision recovery: on 433 (nick in use), appends _, registers _desired_nick, and retries reclaim in background
  - Multi-server: /server [-ssl] <host> [port] opens a parallel IRCClient connection; each gets its own window set and
  is independently managed
  - TCP tuning: TCP_NODELAY, SO_KEEPALIVE, TCP_KEEPIDLE/INTVL/CNT set on the raw socket
  - CTCP: handles PING, VERSION, TIME; rate-limited replies (max 3 per nick per 10 s)
  - WHOIS/WHO/WHOWAS: parsed and formatted into *status* window
  - Channel modes: /op, /deop, /voice, /devoice, /hop, /dehop, /ban, /unban, /kick, /invite, /mode, /topic

  ---
  AI Detection Engine (EnsembleAIDetector)

  A 4-signal ensemble that runs in a background async task per message and never blocks the UI:

  1. Binoculars (perplexity ratio) — GPT-2 as "performer", DistilGPT-2 as "observer". Measures how much more predictable
   text is under the larger model — the key signal that distinguishes fluent LLM output from human writing.
  2. RoBERTa classifier 1 (Hello-SimpleAI/chatgpt-detector-roberta) — fine-tuned on ChatGPT/GPT-family output; strong on
   cloud model text.
  3. RoBERTa classifier 2 (openai-community/roberta-base-openai-detector) — broader open-source detector; generalises to
   Llama/Mistral/Vicuna families. Loaded opportunistically — degrades gracefully if unavailable.
  4. Heuristics — two static scorers:
    - formality_score: weights 12 features including em-dash usage, AI tell-phrases (curated list), Llama-specific
  phrases, formal vocabulary set, absence of contractions, bot-opener regex patterns, emoticon/charspam absence.
    - llama_pattern_score: structural patterns specific to open-source LLMs (numbered lists, citation styles, hedging
  language).

  Blending: when a model is selected via /model, _llm_classify_ai() also queries the selected LLM
  (Claude/GPT/Ollama/llama.cpp) to classify each message as "AI" or "HUMAN". This LLM vote is blended in at 40%, local
  ensemble at 60%.

  LRU cache (_pred_cache, 512 entries): identical messages (common in bots) skip re-inference.

  Per-nick tracking (UserState): rolling window of the last 200 AI scores per nick. rolling_ai_likelihood() returns O(1)
   via an incremental running sum. Also tracks message timestamps and lengths with the same incremental-sum pattern for
  messages_per_minute() and avg_msg_length().

  ---
  AI Integration (LLM Commands)

  Multi-provider dispatch — all via stdlib urllib, no SDK required for local providers:

  ┌──────────┬────────────────────────────┬────────────────────────────────────────────────────┐
  │ Provider │            Auth            │                       Models                       │
  ├──────────┼────────────────────────────┼────────────────────────────────────────────────────┤
  │ claude   │ ANTHROPIC_API_KEY (or SDK) │ Opus 4, Sonnet 4, Haiku 4                          │
  ├──────────┼────────────────────────────┼────────────────────────────────────────────────────┤
  │ openai   │ OPENAI_API_KEY (or SDK)    │ GPT-4o, GPT-4 Turbo, GPT-3.5                       │
  ├──────────┼────────────────────────────┼────────────────────────────────────────────────────┤
  │ ollama   │ None (local)               │ Gemma 3 4B, Llama 3.2, any ollama:<name>           │
  ├──────────┼────────────────────────────┼────────────────────────────────────────────────────┤
  │ llamacpp │ None (local)               │ Gemma 4 via OpenAI-compatible /v1/chat/completions │
  └──────────┴────────────────────────────┴────────────────────────────────────────────────────┘

  Commands:
  - /askai [model] <question> — arbitrary question to any model; answer rendered in dashboard, held 60 s
  - /summarize [n] [model] — structured analysis of last n messages (default 50): per-user contributions, inter-user
  interactions, main topics, open threads; rendered in dashboard, held 60 s
  - /model [key] — switch active model for both chat and LLM detection blending; lists all models with current selection
   marked
  - /api [VAR value] — display or set ANTHROPIC_API_KEY, OPENAI_API_KEY, OLLAMA_URL, LLAMACPP_URL at runtime without
  restarting

  ---
  AI Detection Commands

  - /ai <nick> — full profile in dashboard: rolling AI%, message count, avg length, messages/min, last-seen, sparkline
  of recent scores (last 10), suspect verdict
  - /topai — channel-scoped ranked table of all users with AI% > 0, sorted by score descending; includes sparkline and
  stats columns; held 60 s
  - /aitoggle — enable/disable the background scoring pipeline entirely
  - /logtoggle — toggle JSONL logging of scores to ai_scores.log (on by default; env IRC_AI_LOG=0 disables at startup)

  ---
  Dashboard (*dashboard* window)

  Two modes, managed by _dashboard_mode:

  - "suspects" — auto-refreshes every 5 s; shows all users above AI_SUSPECT_THRESHOLD (70%) with ranked stats
  - "profile" — set by /ai, /topai, /summarize, /askai; suppresses auto-refresh for 60 s; one-shot
  _dashboard_profile_locked flag prevents the same-tick edge-detection reset from clearing it immediately

  ---
  TUI & Input

  - Three panes: tab bar + chat window (left), userlist (right), input box (bottom)
  - 5 colour themes: Classic, Hacker, Ocean, Sunset, Neon — switchable live with /theme
  - Soft-wrapping: _wrap_window() wraps IRC-formatted lines to terminal width; result cached until width changes or new
  lines arrive; _wrap_dirty flag ensures lazy re-evaluation only for the visible window
  - IRC formatting: bold (Ctrl+B), italic (Ctrl+]), underline (Ctrl+_), colour codes, reset (Ctrl+O) — both rendering
  incoming and composing outbound
  - Nick completion: Tab cycles through channel members matching the current prefix
  - Input history: persistent across sessions via irc_input_history.txt; ↑/↓ to navigate
  - Scroll: PgUp/PgDn with pinned-to-bottom auto-scroll on new messages
  - Keyboard shortcuts: Ctrl+A/E (line start/end), Ctrl+K (kill to EOL), Ctrl+W (delete word), Ctrl+N (next window)
  - Window management: /win <n>, /close (/wc), /clear; unread markers in tab bar
  - Ignore list: /ignore//unignore suppresses messages and scoring for a nick

  ---
  Persistence

  ┌───────────┬──────────────────────────────┬─────────────────────────────────────────────────────────────────────┐
  │   Store   │            Format            │                                Notes                                │
  ├───────────┼──────────────────────────────┼─────────────────────────────────────────────────────────────────────┤
  │ Chat logs │ chat_logs/<window>.log —     │ Appended line-buffered; loaded backwards from EOF in 8 KB chunks so │
  │           │ plain text                   │  large files are never fully read (only last 500 lines)             │
  ├───────────┼──────────────────────────────┼─────────────────────────────────────────────────────────────────────┤
  │ Input     │ irc_input_history.txt        │ Line-buffered; capped at 500 entries; trimmed on load               │
  │ history   │                              │                                                                     │
  ├───────────┼──────────────────────────────┼─────────────────────────────────────────────────────────────────────┤
  │ AI score  │ ai_scores.log — JSONL        │ Per-message score records; time.time() timestamps; toggleable at    │
  │ log       │                              │ runtime                                                             │
  └───────────┴──────────────────────────────┴─────────────────────────────────────────────────────────────────────┘

  ---
  Translation

  - /autotranslate toggles automatic CJK (Chinese/Japanese/Korean) → English translation; on by default
  - Runs as a fire-and-forget async task per message; result appended as an indented line in the source window
  - _TRANSLATION_CACHE (LRU) prevents re-translating identical text

  ---
  Robustness & Portability

  - Windows support: auto-detects missing _curses, widens sys.path across user-site and sibling Python installs, falls
  back to windows_curses and auto-installs it if needed
  - Optional dependencies: anthropic and openai SDKs are optional; client runs without them using stdlib urllib for
  local providers. HuggingFace transformers+torch required only for local AI detection.
  - Dependency checker: startup scans for wanted packages and shows a formatted install-hint table for anything missing
  - SSL: shared ssl.SSLContext with TLSv1.2 minimum, reused across all connections (parsing the CA bundle once is
  expensive)
  - Log path safety: _UNSAFE_FILENAME_RE strips shell-unsafe characters from window names before constructing log paths;
   dot-sequences collapsed to prevent directory traversal
























































































