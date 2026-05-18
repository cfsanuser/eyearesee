# eyearesee: IRCv3 Client with AI Detection & Analysis Suite

eyearesee is a sophisticated terminal-based IRC suite featuring an integrated seven-signal AI text detection ensemble. It combines a robust IRCv3-compliant client with advanced linguistic analysis tools to identify and audit automated messages in real-time.

## Table of Contents
- [Quick Start](#quick-start)
- [Architecture and AI Composition](#architecture-and-ai-composition)
- [Core IRC Features](#core-irc-features)
- [AI Detection System](#ai-detection-system)
- [Bouncer & Connectivity](#bouncer--connectivity)
- [Social & Behavioral Analysis](#social--behavioral-analysis)
- [Collaboration & Media](#collaboration--media)
- [Analysis & Monitoring (analyzelog.py)](#analysis--monitoring-analyzelogpy)
- [Comprehensive Command Reference](#comprehensive-command-reference)
- [Keyboard and Mouse Interactions](#keyboard-and-mouse-interactions)
- [Dependencies](#dependencies)
- [Summary](#summary)

---

## Quick Start

To run the core client without installing dependencies or enabling AI detection:

```bash
python eyearesee.py --no-ai --no-install
```
*Note: All AI features will be disabled. Use `--require-virtualenv` if running within a virtual environment.*

---

## Architecture and AI Composition

Approximately 29% of the codebase (2,254 of 7,710 lines) is dedicated to AI and Large Language Model (LLM) functionality.

### Breakdown of AI Components:
- **9.6% AI Detection Ensemble:** Heuristics, Binoculars, RoBERTa classifiers, and LLM-based classification.
- **6.0% AI Integration:** Core logic for `/askai`, `/summarize`, `/model`, and `/api` provider clients.
- **5.8% AI Interface:** Slash commands and dashboard views (suspects view, AI profiles, `/topai`, `/bot`).
- **4.4% AI Logging & History:** JSONL audit trails and per-nick history management.
- **2.2% AI Linguistic Data:** Detection word lists including casual/formal words and common LLM phrases.
- **1.2% Bot Fingerprinting:** The `BotFingerprint` class for identifying recurring patterns.
- **1.0% HTTP Clients:** Support for Ollama and llama.cpp.
- **0.7% AI Configuration:** Model registry, API key management, and thread pools.
- **0.5% AI Initialization:** Dependency management and startup logic.

The remaining **71%** comprises the core IRC protocol stack (IRCv3), curses TUI, plugin system, CJK translation, and general infrastructure.

---

## Core IRC Features

- **Multi-Server Support:** SSL/TLS support and extensive SASL mechanisms (PLAIN, SCRAM-SHA-256, EXTERNAL, ECDSA-NIST256P-CHALLENGE).
- **IRCv3 Compliance:** Labeled-response, message-tags (server-time, msgid), chathistory replay, multiline, monitor, WHOX, and draft extensions (react, redact, reply, mention).
- **TUI Interface & Themes:** A curses-based split-pane layout with 5 built-in color themes (Classic, Hacker, Ocean, Sunset, Neon). Toggle via `/theme`.
- **Session Persistence:** Automatic loading of historical chat logs and per-nick AI scores at startup. Persistent input history and JSON configuration.
- **Advanced Utilities:** Auto-translation via Google Translate, link previews, inline help, plugin system, vim-style command chaining (`/chain`), and behavioural analysis.

---

## AI Detection System (EnsembleAIDetector)

The detector computes eight distinct signals for every incoming message to determine the likelihood of AI generation.

| Signal | Method | Description |
| :--- | :--- | :--- |
| **Binoculars** | `_binoculars_score()` | Perplexity ratio between a performer model (GPT-2) and an observer model. |
| **Classifiers** | `_classifier_score()` | RoBERTa-based ChatGPT and OpenAI detectors, with optional LoRA adaptation. |
| **Heuristics** | `_heuristic_score()` | Analysis of formality, capitalization, punctuation, and IRC slang. |
| **Llama Patterns** | `llama_pattern_score()` | Detection of specific Markdown structures, bot openers, and enumeration styles. |
| **Adversarial** | `_adversarial_score()` | Detection of low char-ngram entropy and spacing anomalies used for evasion. |
| **Embedding Drift**| `_embedding_variance_score()` | Sentence-BERT embedding variance against a user's recent history. |
| **Watermark** | `watermark_score()` | Analysis of token spacing regularity and "green-red" list bias. |
| **Timing** | `timing_anomaly_score()` | Log-normal modeling of inter-message intervals to detect automation. |

---

## Bouncer & Connectivity

eyearesee provides advanced features for maintaining persistent connections and ensuring privacy.

- **Built-in Bouncer (BNC):** Detach the TUI while keeping the IRC session alive. Incoming messages are buffered to disk (`bouncer_buffer.jsonl`) and automatically replayed when you reattach. Use `/bouncer detach` and `/bouncer attach`.
- **ZNC Support:** Dedicated `/znc` command for seamless interaction with remote ZNC bouncers (e.g., `/znc play *chan 100`).
- **SOCKS5 / Tor Proxy:** Native support for connecting via a SOCKS5 proxy (configured via `IRC_TOR_PROXY_HOST` and `IRC_TOR_PROXY_PORT` environment variables) for enhanced anonymity.
- **SASL Support:** Robust implementation of modern SASL mechanisms including `ECDSA-NIST256P-CHALLENGE` for secure authentication.

---

## Social & Behavioral Analysis

Beyond simple AI detection, eyearesee tracks deep behavioral patterns to map social structures and identify sophisticated automation.

- **Linguistic Fingerprinting:** Use `/fingerprint` to analyze a user's unique N-gram distribution (words, bigrams, trigrams). Compare users to identify sockpuppets or recurring bot templates.
- **Social Clustering:** `/cluster <nick>` analyzes a user's social circle by combining adjacency tracking (who they talk *after*), targeting (who they mention), and inverse-targeting (who mentions them).
- **Activity Heatmaps:** Track per-nick and per-channel activity levels over time.
- **Adjacency Tracking:** Real-time tracking of message flow to identify users who consistently respond to specific targets.

---

## Collaboration & Media

- **Jitsi Integration:** Instantly create and share a secure Jitsi Meet room using `/jitsi`. The link is sent to your current PM recipient and opened in your default browser.
- **Common Interests:** `/together <nick1> <nick2>` identifies shared channels and common interests between two users based on their activity logs.
- **DCC File Transfer:** Full support for Direct Client-to-Client transfers including `SEND`, `ACCEPT`, `RESUME`, and a high-performance "Turbo" mode (`TSEND`).
- **Media Previews:** Automatic metadata fetching and link previews for URLs shared in chat.

---

## Analysis & Monitoring (analyzelog.py)

The companion `analyzelog.py` utility provides professional-grade log auditing and real-time monitoring.

### CLI Batch Analysis
- **Filtering:** `--since`, `--until`, `--flagged`, `--similar` (find related nicks), `--bursts`, `--diff`.
- **Reporting:** `--summarize`, `--export`, `--json`.
- **Modes:** `--dashboard` (real-time TUI), `--watch` (live tailing), `--web` (start API), `--webportal` (start UI).

### Interactive Console Commands
- **Dashboard:** `dashboard` (curses TUI), `watch` (live alerts), `cron` (scheduled checks).
- **Web Services:** `web` (JSON API on :8088), `webportal` (Hacker UI on :80), `webhook` (Slack/Discord).
- **Extensions:** `plugin` (load/reload analysis plugins), `script` (batch process script files).
- **Output:** `export` (save analysis results).

---

## Comprehensive Command Reference

### Messaging
- `/msg` (`/m`), `/query`, `/notice`, `/me` (`/action`), `/reply`, `/react`, `/ml` (`/multiline`), `/redact`, `/tagmsg`, `/x0` (image upload), `/chain` (vim-style chaining)

### Channels
- `/join`, `/part`, `/topic`, `/names`, `/kick`, `/invite`, `/mode`, `/autojoin`, `/list`, `/links`

### Social & Behavioral Analysis
- `/cluster`, `/fingerprint`, `/together`, `/adjacent`, `/targets`, `/seen`, `/tell`, `/idle`, `/vibe`

### AI Detection
- `/ai`, `/topai`, `/bot`, `/unbot`, `/aitoggle`, `/logtoggle`, `/scan_watermark` (`/watermark`), `/learn_tell` (`/ltell`), `/forget_tell` (`/ftell`)

### AI Integration (Claude, OpenAI, Ollama)
- `/askai`, `/summarize` (`/summarise`, `/summerize`), `/model`, `/explain`, `/api`

### Collaboration & Media
- `/jitsi`, `/linkpreview`, `/autotranslate`, `/dcc` (send/tsend/accept/resume/trust/untrust/trusted/status), `/dccchat`

### Connectivity & Bouncer
- `/bouncer` (`/bnc`) (on|off|status|detach|attach|replay|clear), `/detach`, `/attach`, `/znc`, `/tor`, `/pgp`, `/ctcpmode`

### Users & Status
- `/nick`, `/whois`, `/whowas`, `/who`, `/ignore`, `/unignore`, `/away`, `/back`, `/monitor`, `/whox`

### Operator
- `/op`, `/deop`, `/voice`, `/devoice`, `/hop`, `/dehop`, `/ban`, `/ban -l`, `/unban`

### Windows & Navigation
- `/win` (`/window`), `/close` (`/wc`), `/clear`, `/alias`, `/lf`, `/theme`, `/userlist`

### Connection & Services
- `/server`, `/reconnect`, `/replay`, `/register`, `/pem`, `/ns` (`/nickserv`), `/cs` (`/chanserv`), `/ctcp`

### Plugins & System
- `/loadplugin`, `/unloadplugin`, `/reloadplugin`, `/plugins`, `/script`, `/redraw`, `/quit` (`/exit`), `/help`, `/commands`, `/mute`

---

## Keyboard and Mouse Interactions

### Keyboard Shortcuts
- **Navigation:** `Ctrl+N` (Next window), `Tab` / `Shift+Tab` (Completion / Navigation), `PgUp` / `PgDn` (Scrolling)
- **Editing:** `Ctrl+A` (Home), `Ctrl+E` (End), `Ctrl+K` (Clear after cursor), `Ctrl+W` (Delete word)
- **Formatting:** `Ctrl+B` (Bold), `Ctrl+]` (Italic), `Ctrl+_` (Underline), `Ctrl+O` (Reset formatting)

### Mouse Support
- **Scrolling:** Support for **Mouse Wheel** scrolling and a physical **Visual Scrollbar** on the right edge of the chat window.
- **URLs:** Click to open in default browser.
- **Nicks:** Click in userlist or chat to initiate a `/query`.
- **Header:** Click to switch between active channels/windows.

---

## Dependencies

Required dependencies are automatically installed via pip on startup unless `--no-install` is specified.

- **windows-curses:** Required for the terminal interface on Windows.
- **transformers / torch:** Powers the AI detection ensemble.
- **anthropic / openai:** Required for LLM-based features like `/askai` and `/summarize`.
- **cryptography:** (Optional) Required for SASL ECDSA-NIST256P-CHALLENGE support.
- **matplotlib / pandas:** (Optional) Used by `analyzelog.py` for advanced visualization and analysis.

---

## Summary

eyearesee is an ambitious IRC suite that bridges the gap between traditional communication and modern AI analysis. It provides a polished, feature-rich IRCv3 experience alongside powerful tools for auditing and interacting with AI-generated content in real-time.

