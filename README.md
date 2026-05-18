# eyearesee: IRCv3 Client with AI Detection

eyearesee is a sophisticated, single-file terminal-based IRC client featuring an integrated seven-signal AI text detection ensemble. It combines a robust IRCv3-compliant stack with advanced linguistic analysis to identify automated messages in real-time.

## Table of Contents
- [Quick Start](#quick-start)
- [Architecture and AI Composition](#architecture-and-ai-composition)
- [Core IRC Features](#core-irc-features)
- [AI Detection System](#ai-detection-system)
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
- **Protocol Handling:** Full CTCP support (VERSION, PING, TIME, CLIENTINFO, ACTION).
- **TUI Interface:** A curses-based split-pane layout featuring a main chat window, user list, input line, and a scrollable dashboard for AI profiles and information visualization.
- **Persistence:** Local logging of chat and AI scores (JSONL), input history, and JSON-based configuration with autojoin support.
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

## Comprehensive Command Reference

### Messaging
- `/msg`, `/query`, `/jitsi`, `/chain`, `/idle`, `/together`, `/adjacent`, `/targets`, `/notice`, `/me`, `/reply`, `/react`, `/ml` (multiline), `/redact`, `/tagmsg`, `/x0` (image upload)

### Channels
- `/join`, `/part`, `/topic`, `/names`, `/kick`, `/invite`, `/mode`, `/autojoin`

### Operator
- `/op`, `/deop`, `/voice`, `/devoice`, `/hop`, `/dehop`, `/ban`, `/ban -l`, `/unban`

### Users & Status
- `/nick`, `/whois`, `/whowas`, `/who`, `/ignore`, `/unignore`, `/away`, `/back`, `/seen`, `/tell`, `/monitor`, `/whox`, `/cluster`

### AI Detection
- `/ai`, `/topai`, `/bot`, `/unbot`, `/aitoggle`, `/logtoggle`, `/learn_tell`, `/forget_tell`, `/scan_watermark`, `/fingerprint`

### AI Integration (Claude, OpenAI, Ollama)
- `/askai`, `/summarize`, `/model`, `/vibe`, `/explain`, `/api`

### Translation & Utilities
- `/autotranslate`, `/linkpreview`, `/dcc` (send/trust/untrust/trusted/status)

### Windows & Navigation
- `/win`, `/close` (`/wc`), `/clear`, `/alias`, `/links`, `/list`, `/lf`, `/theme`, `/userlist`, `/znc`

### Connection & Services
- `/server`, `/reconnect`, `/replay`, `/register`, `/pem`, `/ns`, `/cs`, `/ctcp`

### Plugins & System
- `/loadplugin`, `/unloadplugin`, `/reloadplugin`, `/plugins`, `/redraw`, `/quit`, `/help`, `/commands`, `/mute`

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

---

## Summary

eyearesee is an ambitious single-file project that bridges the gap between traditional IRC communication and modern AI analysis. It provides a polished, feature-rich IRCv3 experience alongside powerful tools for auditing and interacting with AI-generated content in real-time.
