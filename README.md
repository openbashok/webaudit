# WebAudit

Autonomous frontend security analysis agent powered by Claude. WebAudit downloads a target website, performs deep static analysis of its JavaScript/HTML source code, and generates a comprehensive security diagnostic with actionable tooling for pentesters.

**This is not a generic vulnerability scanner.** WebAudit reads every line of application JavaScript, understands data flows, identifies real vulnerabilities in context, and generates custom exploitation tools tailored to each target.

## How It Works

```
webaudit https://target.example.com
```

WebAudit runs a 3-step pipeline:

1. **Download** — `wget` mirrors the complete site (HTML, JS, CSS, images)
2. **Reconnaissance** — Claude analyzes the downloaded structure and generates a code map (`/init`)
3. **Deep Audit** — Claude reads every JS file line by line, searches for vulnerability patterns, and generates the full report with all tooling

The entire audit runs autonomously. No interaction required.

## What It Produces

Each audit generates a project directory with:

| File | Description |
|------|-------------|
| `webaudit_report.json` | Structured findings with evidence, PoCs, and all generated tooling |
| `webaudit_report.md` | Professional Markdown report ready for client delivery |
| `AGENT.md` | Operational briefing for follow-up agents or complementary tools |
| `webaudit_burp_auth.py` | Burp Suite plugin for authorization bypass testing (always generated) |
| `webaudit_burp_recon.py` | Burp Suite plugin for active reconnaissance of discovered endpoints (always generated) |
| `webaudit_burp_crypto.py` | Burp Suite plugin for decrypted traffic viewing (when crypto is detected) |
| `site/` | Downloaded source code |
| `CLAUDE.md` | Code map from reconnaissance phase |

## Analysis Methodology

The agent follows a 13-step methodology defined in [`AGENT_PROMPT.md`](AGENT_PROMPT.md):

### Source Code Analysis (Steps 1-6)

1. **Inventory** — Glob all JS/HTML files, classify each as APPLICATION or LIBRARY
2. **Deep Read** — Read every application JS file completely with line-by-line analysis
3. **Pattern Search** — Grep for 13+ vulnerability patterns: hardcoded keys, innerHTML, eval, localStorage, fetch, postMessage, exposed globals, sensitive comments, hardcoded URLs, and more
4. **Library Analysis** — Identify library versions, search CVEs via WebSearch, verify if vulnerable functions are actually used in the application code
5. **Category Analysis** — Evaluate findings across 8 security categories: Cryptography, Authentication/Session, Access Control, Injection (XSS), Data Exposure, Dependencies, CSRF, and Others
6. **Verification** — Re-read code context for each finding before confirming. No false positives.

### Tooling Generation (Steps 7-11)

7. **Proof of Concept Suite** — JavaScript PoCs for each finding, plus a complete injectable suite with a floating panel to execute PoCs selectively from the browser console

8. **Application Sniffer** — Custom JavaScript sniffer tailored to the target application. Monitors in real-time:
   - Global variables found in the code (via Object.defineProperty/Proxy)
   - localStorage/sessionStorage operations (monkeypatched setItem/getItem)
   - Cookie changes
   - fetch/XHR calls with URL, headers, body, response
   - Form submissions with all field values
   - postMessage events
   - DOM mutations on sensitive elements (passwords, hidden inputs, tokens)

   The sniffer includes:
   - **Persistence** — Log saved to localStorage, survives page navigation, restored on re-injection
   - **Navigation protection** — `beforeunload` confirmation + link click interception with export dialog
   - Floating draggable panel with pause/resume, export JSON, clear, minimize

9. **Cryptographic Analysis** — When client-side encryption is detected (CryptoJS, Web Crypto API, forge, custom schemes):
   - Full scheme documentation: algorithm, mode, key source, IV/nonce, padding
   - Step-by-step encryption flow
   - Weakness assessment and impact analysis
   - Console-injectable JS to hook encrypt/decrypt functions in real-time, showing plaintext, ciphertext, keys, and IVs

10. **Burp Suite — Decrypted Traffic Viewer** (only when crypto is detected) — Complete Jython plugin that:
    - Replicates the target's exact encryption scheme (algorithm, key derivation, padding)
    - Creates a custom Burp tab with decrypted traffic table
    - Shows original request/response headers with decrypted body (JSON pretty-printed)
    - Captures traffic in real-time via `IHttpListener`
    - Syncs incrementally from proxy history
    - Filters only relevant endpoints
    - Dark theme UI

11. **Burp Suite — Authorization Analyzer** (always generated) — Complete Jython plugin pre-loaded with:
    - All API endpoints found in the code, classified as: `public`, `authenticated`, `privileged`, `hidden`
    - The target's authentication pattern (bearer token, cookie, custom header)
    - Test engine that replays each endpoint with: original auth, no auth, modified auth
    - Results table showing: **ENFORCED** (green), **BYPASS!** (red), **IDOR!** (red)
    - Context menu integration: right-click any proxy request → "Send to AuthZ Tester"

12. **Burp Suite — Active Recon** (always generated) — Complete Jython plugin that:
    - Loads all endpoints and URLs discovered during static analysis into an EndpointDB
    - Classifies endpoints as: `public`, `authenticated`, `privileged`, `hidden`
    - Probes endpoints through Burp's proxy with configurable auth tokens
    - Color-coded response analysis (200=green, 301/302=yellow, 401/403=orange, 404=grey, 500=red)
    - Real-time traffic classification via `IHttpListener`
    - Context menu: right-click any proxy request → "Send to Active Recon"
    - CSV export of results

### Report (Step 13)

13. **Structured Report** — JSON + Markdown with:
    - Executive summary
    - Findings with CVSS v3.1 scores, CWE IDs, evidence (file, line, code, context)
    - Reproduction steps
    - Remediation recommendations
    - Library inventory with CVE cross-reference
    - All appendices (PoC suite, sniffer, Burp plugins, analyzed files)

### Agent Briefing (post-processing)

After the audit completes, WebAudit generates an `AGENT.md` file — an operational briefing that consolidates all intelligence gathered during static analysis into a format optimized for follow-up work:

- **Target profile** — URL, domain, tech stack, analysis scope
- **File inventory** — Application code vs libraries, with descriptions
- **Library CVEs** — Versions and known vulnerabilities with in-use status
- **API endpoints** — All endpoints extracted from source code
- **Authentication pattern** — How the app handles auth (tokens, cookies, headers, storage keys)
- **Crypto schemes** — Full documentation of any client-side encryption (algorithm, key, IV, flow, weaknesses)
- **Findings summary** — All vulnerabilities with severity, CVSS, CWE
- **Finding details** — Description, impact, location, remediation for each
- **Analysis coverage** — What was completed (static) and what remains (dynamic testing)
- **Available tooling** — Map of all generated tools and their purpose

This file enables any agent, tool, or pentester to pick up where WebAudit left off — with 80% of reconnaissance already done.

## Installation

### One-liner (recommended)

```bash
# System-wide (/opt/webaudit)
sudo bash -c "$(curl -sL https://raw.githubusercontent.com/openbashok/webaudit/main/install.sh)"

# User-only (~/.local/share/webaudit)
bash -c "$(curl -sL https://raw.githubusercontent.com/openbashok/webaudit/main/install.sh)"
```

### Manual

```bash
git clone https://github.com/openbashok/webaudit.git
cd webaudit
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### Requirements

- Python 3.8+
- `git`, `wget`
- [Claude CLI](https://claude.ai/code) (`claude` command available in PATH)
- Anthropic API key

### Configuration

Edit the config file created by the installer:

```yaml
# /etc/webaudit/config.yaml (system) or ~/.config/webaudit/config.yaml (user)
anthropic_api_key: "sk-ant-..."
default_model: "claude-sonnet-4-6"
default_budget_usd: 5.0
default_max_turns: 50
default_lang: "en"
# work_dir: "/tmp/webaudit"
```

Or set `ANTHROPIC_API_KEY` as an environment variable.

## Usage

```bash
# Basic scan
webaudit https://example.com

# With options
webaudit scan https://example.com -m claude-opus-4-6 -b 15.0 -t 80 -l es

# Health check
webaudit check
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-m, --model` | Claude model | `claude-sonnet-4-6` |
| `-b, --budget` | Max spend in USD | `5.0` |
| `-t, --max-turns` | Max agent turns | `50` |
| `-l, --lang` | Report language (`en`, `es`) | `en` |
| `-o, --output-dir` | Output directory | Auto-generated |
| `-w, --work-dir` | Base work directory | `~/webaudit` |
| `-d, --debug` | Debug mode with real-time output | Off |

## Output Structure

```
~/webaudit/example.com_2024-01-15_143022/
├── site/                          # Downloaded source code
│   └── www.example.com/
│       ├── index.html
│       ├── js/
│       │   ├── app.js
│       │   ├── login.js
│       │   └── jquery.min.js
│       └── ...
├── CLAUDE.md                      # Code map (auto-generated)
├── AGENT.md                       # Operational briefing for follow-up agents
├── webaudit_report.json           # Structured report (findings, crypto, stats)
├── webaudit_report.md             # Client-ready Markdown report
├── webaudit_suite.js              # PoC suite (floating panel with all PoCs)
├── webaudit_sniffer.js            # Custom application sniffer
├── webaudit_burp_auth.py          # Burp auth bypass tester
├── webaudit_burp_recon.py         # Burp active recon of discovered endpoints
└── webaudit_burp_crypto.py        # Burp traffic decryptor (if crypto found)
```

## Report Appendices

The Markdown report includes up to 7 appendices:

| Appendix | Content | Generated |
|----------|---------|-----------|
| A | Library Inventory — name, version, CVEs, in-use status | Always |
| B | Instrumentation Suite — floating panel with all PoCs | Always |
| C | Burp Decrypted Traffic Viewer — complete plugin code | If crypto detected |
| D | Burp Authorization Analyzer — complete plugin code | Always |
| E | Burp Active Recon — endpoint discovery and probing plugin | Always |
| F | Application Sniffer — real-time monitoring panel | Always |
| G | Analyzed Files — inventory of all files reviewed | Always |

## Markdown Report Features

- **Local path to URL conversion** — File paths like `site/www.example.com/js/app.js` are automatically converted to live URLs in the report
- **HTML-safe prose** — `<` and `>` characters in explanation text are escaped to prevent Markdown rendering issues, while code blocks remain untouched
- **Resilient output handling** — Handles agent JSON variations: field name aliases (en/es), nested wrappers, lists-as-strings, dicts-as-values, CVE objects, CVSS objects

## Security Model

- **Static analysis only** — no backend interaction, no active exploitation
- PoCs demonstrate vulnerabilities without causing damage
- Burp plugins perform safe replay testing (no destructive payloads)
- Conservative severity ratings with honest CVSS v3.1 scoring
- Findings verified in context before reporting (no false positives from pattern matching)

## License

MIT

## Contributing

Issues and pull requests welcome at [github.com/openbashok/webaudit](https://github.com/openbashok/webaudit).
