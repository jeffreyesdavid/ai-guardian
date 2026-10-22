# ai-guardian 🛡️

**Find the AI agents on your machine, and see what they can touch.**

AI agents now read your files, run commands, browse for you, and plug into your email, calendar, and bank through **MCP servers**. Big companies are buying enterprise tools to keep track of their "shadow AI." Everyone else (freelancers, students, small businesses, solo devs) has nothing.

ai-guardian is a free, open-source, local scanner that gives you the same visibility.

> Part of my Guardian security series, alongside [php-guardian](https://github.com/jeffreyesdavid/php-guardian), [Wi-Fi Guardian](https://github.com/jeffreyesdavid/wifi-guardian), and [VPN Guardian](https://github.com/jeffreyesdavid/vpn-guardian).

## What it does

**1. Discover: what AI is on this machine?**
- 🖥️ AI apps: Claude, ChatGPT, Cursor, Windsurf, Ollama, LM Studio, and more
- ⌨️ Command-line agents: Claude Code, Codex, Gemini CLI, Aider, Goose, and more
- ⚙️ AI processes running right now, grouped by app
- 🔌 **MCP servers**, the plugins that give agents access to your files and accounts
- 🧩 AI browser extensions in Chrome, Brave, Edge, and Arc
- 📡 Local AI servers (Ollama, LM Studio, llama.cpp) listening on your network

**2. Map: what can each one touch?**

| Risk | Severity |
|---|---|
| API keys or tokens saved in plain text in agent configs | 🟥 HIGH |
| MCP server with access to your whole drive, home folder, or `~/.ssh` | 🟥 HIGH |
| Agent set to skip permission prompts, or allowed to run any shell command | 🟥 HIGH |
| MCP server connecting over unencrypted `http://` | 🟥 HIGH |
| Local AI server open to everyone on your Wi-Fi | 🟥 HIGH |
| MCP server that auto-installs the latest unpinned code on every launch | 🟨 MEDIUM |
| MCP server built to run shell commands | 🟨 MEDIUM |
| Passwords pasted into MCP server settings | 🟨 MEDIUM |
| AI API keys in your shell profile (`.zshrc`, `.bashrc`) | 🟨 MEDIUM |
| AI browser extension that can read every website | 🟨 MEDIUM |

Every finding explains **why** it matters in plain English and **how** to fix it.

## Privacy first

- 🔒 **Read-only.** It reads config files and process lists. It never changes anything.
- 🙈 **Secrets are masked.** A key shows up as `sk-ant…****Xy`, never in full.
- 🏠 **Nothing leaves your computer.** No cloud, no telemetry, no account.
- 📦 **No installs.** Python 3 standard library only.

## Quick start

```bash
git clone https://github.com/jeffreyesdavid/ai-guardian.git
cd ai-guardian
python3 ai_guardian.py
```

Works on macOS and Linux.

## Real result from my own Mac

```
ai-guardian 1.0.0 - what AI is on this machine, and what can it touch?

  AI apps (3)
    • Claude                       Anthropic Claude desktop
    • LM Studio                    LM Studio local AI models
    • Ollama                       Ollama local AI models

  Command-line agents (3)
    • claude                       Claude Code agent
    • ollama                       Ollama local models
    • lms                          LM Studio CLI

  Running now (6)
    • Claude                       running now (26 processes)
    • LM Studio                    running now (4 processes)
    ...

  Local AI servers (2)
    • Ollama                       local AI server listening - port 11434
    • LM Studio                    local AI server listening - port 1234

  Risks (1)

  MEDIUM AI extension can read every website: Claude
         Why: It has permission to see and change content on all sites, including
              your email, bank, and work tools.
         Fix: Set Site access to 'On click' in Chrome's extension settings.

  Summary: 16 AI agent(s) found · 0 high, 1 medium risk(s)
```

16 AI agents on one personal laptop. Most people would guess two or three.

## Options

| Command | What it does |
|---|---|
| `python3 ai_guardian.py` | Full scan |
| `python3 ai_guardian.py --json` | Machine-readable output for SIEMs and scripts |
| `python3 ai_guardian.py --no-live` | Skip running-process and network checks |
| `python3 ai_guardian.py --fail-on medium` | Exit 1 on medium or higher (default: high) |

**Exit codes:** `0` = no risks at your chosen level, `1` = risks found. You can drop it into a cron job or CI pipeline.

## Tests

```bash
python3 tests/test_ai_guardian.py
```

23 tests build a fake home folder full of risky AI setups and check that each one is caught, that a safe setup stays quiet, and that **no secret is ever printed in full**. The fake keys are assembled at runtime, so no secret-looking strings live in this repo.

## Roadmap

- [x] **v1: Discover + Map.** Find AI agents and flag risky setups.
- [ ] **v2: Watch.** Live phone alerts (via ntfy) when an AI process reads SSH keys, browser passwords, or crypto wallets, launches a shell, or talks to a new server.
- [ ] **v3: Explain.** A local AI (Ollama) explains each alert in plain English, the same approach as VPN Guardian.
- [ ] **v4: Red vs. blue lab.** One local agent tries prompt injection on another, and the attacks that work become detection rules.

## Why I built this

At Fal.Con 2026, CrowdStrike launched Falcon Guardian, an enterprise product that discovers a company's AI agents, maps what they can access, and stops threats where they run. The idea is right. But the people installing AI agents fastest (freelancers, small shops, students) will never buy enterprise security. ai-guardian brings the same **discover → map → watch** model to them, for free.

## Disclaimer

Defensive tool for checking machines **you own or are authorized to check**. Provided as-is, with no guarantees. Not affiliated with CrowdStrike or any AI vendor.

## License

MIT © 2026 Jeffrey David
