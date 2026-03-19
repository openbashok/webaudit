# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WebAudit is an autonomous frontend security analysis agent powered by Claude CLI. It receives a target URL, downloads the complete site with `wget`, performs static analysis of JavaScript/HTML/CSS, and generates a comprehensive security diagnostic with custom pentesting tools.

## Architecture

- **`webaudit.py`** — CLI orchestrator. Loads config, reads system prompt from `AGENT_PROMPT.md`, launches Claude CLI (`claude -p`) with streaming output, normalizes JSON output, generates Markdown report, Burp plugins, and AGENT.md briefing.
- **`AGENT_PROMPT.md`** — System prompt for the audit agent. Defines the 12-step methodology: Inventory → Deep Read → Grep Patterns → Library CVEs → Category Analysis → Verification → PoC Suite → Sniffer → Crypto Analysis → Burp Crypto Plugin → Burp Auth Plugin → Report JSON.
- **`install.sh`** — Installer: clones repo, creates venv, installs deps, creates symlink and config.

### Key functions in webaudit.py

- `run_claude_streaming()` — Executes `claude -p` with `--output-format stream-json --verbose`, parses events, shows real-time progress.
- `step_audit()` — Main audit step. Sends AUDIT_PROMPT, extracts JSON report, normalizes field names (en/es aliases), validates all outputs (PoCs, sniffer, crypto, burp plugins), saves files.
- `_generate_markdown_report()` — Builds the full Markdown report from JSON data. Handles type coercion, HTML escaping, local-path-to-URL conversion.
- `_generate_agent_md()` — Builds AGENT.md operational briefing from report data for follow-up agents/tools.
- `_to_str()` — Coerces any value to markdown-safe string with `<`/`>` escaping (for prose).
- `_to_raw_str()` — Coerces any value to string WITHOUT escaping (for code blocks).
- `_md_escape()` — Escapes `<`/`>` in text while preserving backtick code spans.
- `_local_path_to_url()` — Converts `site/www.example.com/path` to `https://www.example.com/path`.

### Configuration

API key and defaults are read from (priority order):
1. Environment variable `ANTHROPIC_API_KEY`
2. `~/.config/webaudit/config.yaml`
3. `/etc/webaudit/config.yaml`

## Running

```bash
pip3 install -r requirements.txt

# Basic
python3 webaudit.py https://target.example.com

# With options
python3 webaudit.py scan https://target.example.com -m claude-opus-4-6 -b 15.0 -t 80 -l es

# Health check
python3 webaudit.py check
```

## Output

The agent produces `webaudit_report.json` with structured findings. Key JSON fields:

- **`hallazgos[]`** — Findings array, each with `console_instrumentation` (JS PoC)
- **`console_instrumentation`** (root) — Complete PoC suite with floating panel UI
- **`application_sniffer`** — Custom JS sniffer with persistence and nav protection
- **`crypto_analysis`** — Crypto scheme documentation (null if no crypto found)
- **`burp_extension`** — Burp crypto traffic viewer plugin (null if no crypto)
- **`burp_auth_analyzer`** — Burp auth bypass tester plugin (always generated)

Post-processing generates:
- `webaudit_report.md` — Markdown report with appendices A-F
- `webaudit_burp_auth.py` — Standalone Burp plugin file
- `webaudit_burp_crypto.py` — Standalone Burp plugin file (if crypto detected)
- `AGENT.md` — Operational briefing for follow-up agents

## Key Design Decisions

- **Static analysis only** — no backend interaction, no active exploitation.
- PoCs must be console-injectable JavaScript that demonstrates issues without causing real damage.
- CVEs should only be reported if the vulnerable function is actually used in the target's code.
- Severity ratings must be conservative and honest (CVSS v3.1).
- The agent prompt language is **Spanish**; report output language is configurable (en/es).
- JSON normalization layer handles agent output variations (field name aliases, nested wrappers, type mismatches).
- Markdown prose escapes `<`/`>` to prevent HTML interpretation; code blocks are left raw.
