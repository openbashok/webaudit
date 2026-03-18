# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WebAudit is an autonomous frontend security analysis agent built on the **Claude Agent SDK** (Python). It receives a target URL, downloads the complete site with `wget`, performs static analysis of JavaScript/HTML/CSS, and generates a professional security diagnostic report in Markdown.

## Architecture

- **`webaudit.py`** — Orquestador CLI. Carga config, lee el system prompt de `AGENT_PROMPT.md`, lanza el agente via `claude_agent_sdk.query()`, y guarda el informe JSON.
- **`AGENT_PROMPT.md`** — System prompt + documentacion del operador. Define el workflow de 5 fases: Download → Reconnaissance → Security Analysis → PoC Generation → Report.
- **`install.sh`** — Instalador: clona el repo, instala dependencias, crea symlink y config.

### Configuracion

La API key y defaults se leen de (en orden de prioridad):
1. Variable de entorno `ANTHROPIC_API_KEY`
2. `~/.config/webaudit/config.yaml`
3. `/etc/webaudit/config.yaml`

## Running the Agent

```bash
# Instalar dependencias
pip3 install -r requirements.txt

# Uso basico
python3 webaudit.py https://target.example.com

# Con modelo, budget y max turns custom
python3 webaudit.py https://target.example.com claude-opus-4-6 15.0 80
```

## Output Format

La salida del agente es un archivo JSON (`webaudit_report.json`) con los hallazgos estructurados. Campos clave:

- **`hallazgos[].console_instrumentation`** — PoC JavaScript individual por hallazgo, inyectable en la consola del navegador.
- **`console_instrumentation`** (raiz) — Suite JS completa que genera un panel/interfaz grafica en el navegador para explotar y demostrar múltiples fallas de forma interactiva. Es el campo más importante de la salida.
- **`informe_markdown`** — Informe completo en Markdown para lectura humana.

## Key Design Decisions

- **Static analysis only** — no backend interaction, no active exploitation.
- PoCs must be console-injectable JavaScript that demonstrates issues without causing real damage.
- CVEs should only be reported if the vulnerable function is actually used in the target's code (no false positives from unused library features).
- Severity ratings must be conservative and honest (CVSS v3.1).
- The project language is **Spanish** (prompts, report output, variable names/descriptions).
