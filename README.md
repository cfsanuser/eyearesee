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
 ---
  /commands Reference

  Messaging

  ┌─────────────────────────┬────────────────────────────────────────────────────────────────┐
  │         Command         │                          What it does                          │
  ├─────────────────────────┼────────────────────────────────────────────────────────────────┤
  │ /msg <nick> <text>      │ Send a private message; opens and switches to the DM window    │
  ├─────────────────────────┼────────────────────────────────────────────────────────────────┤
  │ /query <nick> [message] │ Open a DM window with nick; optionally send a first message    │
  ├─────────────────────────┼────────────────────────────────────────────────────────────────┤
  │ /notice <nick> <text>   │ Send a notice (appears as -nick- in their client, not in chat) │
  ├─────────────────────────┼────────────────────────────────────────────────────────────────┤
  │ /me <text>              │ Send an action line (* nick waves)                             │
  └─────────────────────────┴────────────────────────────────────────────────────────────────┘

  Channels

  ┌──────────────────────────────┬─────────────────────────────────────────────────────────────┐
  │           Command            │                        What it does                         │
  ├──────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ /join <channel>              │ Join a channel (prefix # is added automatically if omitted) │
  ├──────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ /part [channel] [msg]        │ Leave a channel with an optional part message               │
  ├──────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ /topic <channel> [text]      │ View or set the channel topic                               │
  ├──────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ /names [channel]             │ List users currently in the channel                         │
  ├──────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ /kick <chan> <nick> [reason] │ Kick a user from the channel                                │
  ├──────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ /invite <nick> [channel]     │ Invite a user to a channel                                  │
  ├──────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ /mode <target> [modes]       │ Get or set channel/user modes                               │
  └──────────────────────────────┴─────────────────────────────────────────────────────────────┘

  Operator

  ┌──────────────────┬──────────────────────────────────────────────────┐
  │     Command      │                   What it does                   │
  ├──────────────────┼──────────────────────────────────────────────────┤
  │ /op <nick>       │ Grant operator status (+o)                       │
  ├──────────────────┼──────────────────────────────────────────────────┤
  │ /deop <nick>     │ Remove operator status (-o)                      │
  ├──────────────────┼──────────────────────────────────────────────────┤
  │ /voice <nick>    │ Grant voice (+v)                                 │
  ├──────────────────┼──────────────────────────────────────────────────┤
  │ /devoice <nick>  │ Remove voice (-v)                                │
  ├──────────────────┼──────────────────────────────────────────────────┤
  │ /hop <nick>      │ Grant half-op (+h)                               │
  ├──────────────────┼──────────────────────────────────────────────────┤
  │ /dehop <nick>    │ Remove half-op (-h)                              │
  ├──────────────────┼──────────────────────────────────────────────────┤
  │ /ban <nick|mask> │ Ban; bare nick expands to nick!*@* automatically │
  ├──────────────────┼──────────────────────────────────────────────────┤
  │ /unban <mask>    │ Remove a ban mask                                │
  └──────────────────┴──────────────────────────────────────────────────┘

  Users & Status

  ┌──────────────────┬───────────────────────────────────────┐
  │     Command      │             What it does              │
  ├──────────────────┼───────────────────────────────────────┤
  │ /nick <newnick>  │ Change your nickname                  │
  ├──────────────────┼───────────────────────────────────────┤
  │ /whois <nick>    │ Look up information on a user         │
  ├──────────────────┼───────────────────────────────────────┤
  │ /whowas <nick>   │ Info on a recently disconnected user  │
  ├──────────────────┼───────────────────────────────────────┤
  │ /who <target>    │ List users matching a pattern         │
  ├──────────────────┼───────────────────────────────────────┤
  │ /ignore <nick>   │ Suppress all messages from nick       │
  ├──────────────────┼───────────────────────────────────────┤
  │ /unignore <nick> │ Stop ignoring nick                    │
  ├──────────────────┼───────────────────────────────────────┤
  │ /away [message]  │ Set away status with optional message │
  ├──────────────────┼───────────────────────────────────────┤
  │ /back            │ Remove away status                    │
  └──────────────────┴───────────────────────────────────────┘

  Services & CTCP

  ┌───────────────────────────┬───────────────────────────────────────────────────┐
  │          Command          │                   What it does                    │
  ├───────────────────────────┼───────────────────────────────────────────────────┤
  │ /ns <command>             │ Send command to NickServ (e.g. /ns identify pass) │
  ├───────────────────────────┼───────────────────────────────────────────────────┤
  │ /cs <command>             │ Send command to ChanServ                          │
  ├───────────────────────────┼───────────────────────────────────────────────────┤
  │ /ctcp <nick> <cmd> [args] │ Send a CTCP request (PING, VERSION, TIME, etc.)   │
  └───────────────────────────┴───────────────────────────────────────────────────┘

  AI Detection

  ┌────────────┬───────────────────────────────────────────────────────────────────────────────────────────────┐
  │  Command   │                                         What it does                                          │
  ├────────────┼───────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /ai <nick> │ Full AI-detection profile: rolling score, peak/low, per-session breakdown, sparkline, verdict │
  ├────────────┼───────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /aitoggle  │ Enable or disable AI scoring entirely                                                         │
  └────────────┴───────────────────────────────────────────────────────────────────────────────────────────────┘

  Claude Integration

  ┌───────────────────────────────────────┬─────────────────────────────────────────────────────────────┐
  │                Command                │                        What it does                         │
  ├───────────────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ /askai [opus|sonnet|haiku] <question> │ Ask Claude a question; answer shown in the dashboard window │
  ├───────────────────────────────────────┼─────────────────────────────────────────────────────────────┤
  │ /model <opus|sonnet|haiku>            │ Set the default Claude model used by /askai                 │
  └───────────────────────────────────────┴─────────────────────────────────────────────────────────────┘

  Translation

  ┌────────────────┬──────────────────────────────────────────────────────────────────────────────────────────────────────────┐
  │    Command     │                                               What it does                                               │
  ├────────────────┼──────────────────────────────────────────────────────────────────────────────────────────────────────────┤
  │ /autotranslate │ Toggle auto CJK→English translation (on by default); translated lines appear indented below the original │
  └────────────────┴──────────────────────────────────────────────────────────────────────────────────────────────────────────┘

  Connection

  ┌──────────────────────────────┬────────────────────────────────────────────────────────────────────┐
  │           Command            │                            What it does                            │
  ├──────────────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ /server <host> [port] [nick] │ Connect to a different IRC server over SSL (port defaults to 6697) │
  ├──────────────────────────────┼────────────────────────────────────────────────────────────────────┤
  │ /reconnect                   │ Drop and re-establish the current connection                       │
  └──────────────────────────────┴────────────────────────────────────────────────────────────────────┘

  Interface

  ┌─────────────────┬─────────────────────────────────────────────────────────────────────┐
  │     Command     │                            What it does                             │
  ├─────────────────┼─────────────────────────────────────────────────────────────────────┤
  │ /theme <1-5>    │ Switch colour theme: 1 Classic, 2 Hacker, 3 Ocean, 4 Sunset, 5 Neon │
  ├─────────────────┼─────────────────────────────────────────────────────────────────────┤
  │ /win <n>        │ Switch to window number n (also shown in the tab bar)               │
  ├─────────────────┼─────────────────────────────────────────────────────────────────────┤
  │ /clear          │ Clear messages in the current window                                │
  ├─────────────────┼─────────────────────────────────────────────────────────────────────┤
  │ /close (or /wc) │ Close the current chat window and return to the previous one        │
  └─────────────────┴─────────────────────────────────────────────────────────────────────┘

  General

  ┌─────────────────┬──────────────────────────────────────┐
  │     Command     │             What it does             │
  ├─────────────────┼──────────────────────────────────────┤
  │ /quit [message] │ Send quit message to server and exit │
  ├─────────────────┼──────────────────────────────────────┤
  │ /help           │ Brief one-line command reference     │
  ├─────────────────┼──────────────────────────────────────┤
  │ /commands       │ Full command list (this output)      │
  └─────────────────┴──────────────────────────────────────┘

  ---
  Keyboard shortcuts: Ctrl+N next window · Tab nick completion · ↑/↓ scroll history · PgUp/PgDn scroll chat · Ctrl+A/E line start/end · Ctrl+K kill to end · Ctrl+U clear line · Ctrl+W delete word · Ctrl+B/]/_
  bold/italic/underline · Ctrl+O reset formatting
