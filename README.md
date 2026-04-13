 eyearesee.py is a ~3,100-line Python IRC client with a curses TUI. Here's a summary
  of its architecture:

  Core components:
  - IRCClient — async IRC connection with SSL/TLS, IRCv3 caps (SASL, away-notify, server-time, etc.), CTCP,               exponential-backoff reconnect
  - TUI — curses-based UI with multiple chat windows, userlist panel, 5 color themes, CJK-aware text wrapping             - EnsembleAIDetector — three-signal AI text detector: Binoculars (GPT-2/distilGPT-2 perplexity ratio) + RoBERTa
  classifier + heuristics (formality, AI tell-phrases, em-dashes)
  - ScoringEngine — wraps the detector for per-message and per-user rolling scores
  - ChatWindow / UserState — window buffers and per-nick state with O(1) incremental stats

  Key features:
  - /askai [opus|sonnet|haiku] <question> — queries Claude API, displays in *dashboard*
  - Auto-translate CJK messages via Google Translate free endpoint (LRU-cached, semaphore-limited)
  - Persistent JSONL AI score log + per-channel chat logs, with session/gap tracking
  - /ai <nick> — full AI profiling dashboard with per-session breakdown and sparklines
  - Tab nick completion, input history, Emacs-style editing keys (Ctrl+A/E/K/U/W/B/F)
  - Auto-installs missing pip packages on first run
