#!/usr/bin/env python3
"""
WebAudit — Agente autonomo de analisis de seguridad frontend.

Flujo de 3 pasos (todo via claude CLI real, sin SDK):
  Paso 1 (wget):   Descarga completa del sitio — codigo Python puro.
  Paso 2 (init):   claude -p "/init" en la carpeta descargada.
  Paso 3 (audit):  claude -p con el AGENT_PROMPT.md como system prompt.
"""

import sys
import os
import json
import re
import shutil
import argparse
import subprocess
import time
import threading
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

import yaml

# --- Prompt para el audit (paso 3) -------------------------------------------

AUDIT_PROMPT = """\
Source code audit for site: {url}

The site is already downloaded in ./site/ and CLAUDE.md has the code context.

LANGUAGE: Write ALL report content (JSON fields and markdown) in {lang_name}.
Field names in the JSON stay in English, but all values (descriptions, titles,
recommendations, executive summary, etc.) MUST be written in {lang_name}.

INSTRUCTIONS — follow the system prompt steps in order:

1. Read CLAUDE.md to understand the structure.
2. Use Glob to list all .js and .html in ./site/
3. Classify each JS as APPLICATION or LIBRARY.
4. Read EACH application JS file completely with Read — line by line.
5. Use Grep to search for vulnerability patterns (hardcoded keys, innerHTML, eval, localStorage, fetch, postMessage, etc.)
6. For libraries with detected versions, search CVEs with WebSearch and verify if affected functions are used.
7. Verify each potential finding — re-read the context before confirming.
8. For EACH finding, generate a functional JavaScript PoC in the "console_instrumentation" field.
9. Generate the complete suite in the root "console_instrumentation" field.
10. Generate the "application_sniffer" field: a CUSTOM JavaScript sniffer tailored to THIS app.
    Based on the variables, APIs, storage keys, and functions you found in the code, create
    a self-contained IIFE that when pasted in the browser console shows a floating panel
    monitoring in real-time: global variables, localStorage/sessionStorage, cookies, fetch/XHR,
    form submissions, postMessage. Only hook what THIS app actually uses — not generic.
11. If the app encrypts/decrypts requests or data (CryptoJS, Web Crypto API, forge, custom XOR, etc.),
    generate "crypto_analysis" with: detected schemes, algorithm, key source, IV, full flow,
    weaknesses, impact, and console_instrumentation JS to hook encrypt/decrypt in real-time.
    If no crypto found, set "crypto_analysis" to null.
12. If crypto_analysis.detected is true, generate "burp_extension": a complete Python/Jython
    Burp Suite plugin (.py file) that decrypts the app's traffic in real-time inside Burp.
    The plugin must replicate the exact crypto scheme found, create a custom tab with a
    decrypted traffic viewer (table + request/response panels), and capture traffic via
    IHttpListener. If no crypto, set "burp_extension" to null.
13. ALWAYS generate "burp_auth_analyzer": a Burp plugin for authorization bypass testing.
    Pre-load it with the API endpoints found in the code (classified as public/authenticated/
    privileged/hidden) and the auth pattern (bearer token, cookie, custom header, etc.).
    The plugin tests each endpoint with no auth and modified auth, showing which enforce
    server-side authorization and which can be bypassed.
14. Save webaudit_report.json with Write.

CRITICAL: This is STATIC SOURCE CODE ANALYSIS, not a network pentest.
Your job is to READ JavaScript code and find vulnerabilities IN THE CODE.
Do not check HTTP headers or run network tests. Read files, search patterns, analyze data flows.

MANDATORY — CONSOLE_INSTRUMENTATION:
Every finding MUST have a "console_instrumentation" field with functional JavaScript
code that can be copied and pasted into the browser console to demonstrate the
vulnerability. Do not leave this field empty or omit it. The PoC must:
- Be self-contained (copy-paste into DevTools > Console)
- Show visible evidence (console.log, alert, or modified UI)
- Have comments explaining what it does and what it demonstrates
- Minimum example: (function(){{ console.log('[PoC] Token found:', localStorage.getItem('token')); }})();

Also, the "console_instrumentation" field at the JSON ROOT must contain a
COMPLETE SUITE: a single JS block that when pasted in the console creates a
floating panel on the page with buttons to execute each PoC individually.
"""

# --- Configuracion -----------------------------------------------------------

CONFIG_PATHS = [
    Path("/etc/webaudit/config.yaml"),
    Path.home() / ".config" / "webaudit" / "config.yaml",
]

DEFAULTS = {
    "anthropic_api_key": "",
    "default_model": "claude-sonnet-4-6",
    "default_budget_usd": 5.0,
    "default_max_turns": 50,
    "work_dir": str(Path.home() / "webaudit"),
    "default_lang": "en",
}

LANG_NAMES = {
    "en": "English",
    "es": "Spanish (Español)",
}


def load_config() -> dict:
    config = dict(DEFAULTS)
    config["_config_file"] = None
    for path in CONFIG_PATHS:
        if path.is_file():
            with open(path) as f:
                file_config = yaml.safe_load(f) or {}
            config.update({k: v for k, v in file_config.items() if v is not None})
            config["_config_file"] = str(path)
            break
    if os.environ.get("ANTHROPIC_API_KEY"):
        config["anthropic_api_key"] = os.environ["ANTHROPIC_API_KEY"]
    return config


def dbg(msg: str, debug: bool):
    if debug:
        print(f"[debug] {msg}", file=sys.stderr)


def run_claude_streaming(claude_cmd: list, cwd: str, label: str, debug: bool,
                         timeout: int = 600) -> tuple[int, str]:
    """
    Ejecuta un comando claude -p con --output-format stream-json
    y muestra actividad en tiempo real.
    Retorna (returncode, output_text).
    """
    # Usar stream-json para tener visibilidad (requiere --verbose con -p)
    cmd = claude_cmd + ["--output-format", "stream-json", "--verbose"]

    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    output_text_parts = []
    last_activity = time.time()
    tool_count = 0
    start_time = time.time()

    # Thread para mostrar heartbeat si no hay actividad
    stop_heartbeat = threading.Event()

    def heartbeat():
        while not stop_heartbeat.is_set():
            elapsed = int(time.time() - start_time)
            mins, secs = divmod(elapsed, 60)
            if time.time() - last_activity > 10:
                print(f"\r[{label}] Trabajando... {mins:02d}:{secs:02d} | herramientas usadas: {tool_count}   ", end="", flush=True)
            stop_heartbeat.wait(5)

    hb_thread = threading.Thread(target=heartbeat, daemon=True)
    hb_thread.start()

    try:
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            last_activity = time.time()

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                if debug:
                    dbg(f"[stream] raw: {line[:200]}", debug)
                continue

            etype = event.get("type", "")

            # Eventos tipo "assistant" contienen content blocks con texto y tool_use
            if etype == "assistant" and "message" in event:
                msg = event["message"]
                for block in msg.get("content", []):
                    btype = block.get("type", "")
                    if btype == "text":
                        text = block.get("text", "")
                        if text:
                            output_text_parts.append(text)
                            if debug:
                                # Mostrar lo que dice el agente (truncado)
                                preview = text.replace("\n", " ")[:120]
                                dbg(f"[texto] {preview}", debug)
                    elif btype == "tool_use":
                        tool_name = block.get("name", "?")
                        tool_count += 1
                        elapsed = int(time.time() - start_time)
                        mins, secs = divmod(elapsed, 60)
                        print(f"\r[{label}] {mins:02d}:{secs:02d} | Tool #{tool_count}: {tool_name}                    ", flush=True)
                        if debug:
                            tool_input = json.dumps(block.get("input", {}), ensure_ascii=False)[:200]
                            dbg(f"  {tool_name}({tool_input})", debug)

            # Eventos tipo "user" contienen tool_result
            elif etype == "user" and "message" in event:
                if debug:
                    msg = event["message"]
                    for block in msg.get("content", []):
                        if block.get("type") == "tool_result":
                            content = str(block.get("content", ""))[:150]
                            dbg(f"  -> {content}", debug)

            elif etype == "result":
                # Mensaje final
                result_text = event.get("result", "")
                if result_text:
                    output_text_parts.append(result_text)
                cost = event.get("cost_usd", 0)
                duration = event.get("duration_ms", 0)
                if cost or duration:
                    print(f"\r[{label}] Completado | Costo: ${cost:.4f} | Duracion: {duration/1000:.1f}s                    ")

            elif debug and etype not in ("system",):
                dbg(f"[stream] {etype}: {json.dumps(event, ensure_ascii=False)[:200]}", debug)

        proc.wait(timeout=timeout)

    except subprocess.TimeoutExpired:
        proc.kill()
        print(f"\n[{label}] TIMEOUT ({timeout}s)")
    finally:
        stop_heartbeat.set()
        hb_thread.join(timeout=2)

    # Leer stderr para diagnosticar errores
    stderr_output = ""
    try:
        stderr_output = proc.stderr.read() if proc.stderr else ""
    except Exception:
        pass

    if proc.returncode != 0 and stderr_output:
        print(f"[{label}] ERROR stderr: {stderr_output.strip()[:500]}")
    elif debug and stderr_output:
        dbg(f"stderr: {stderr_output.strip()[:300]}", debug)

    elapsed = int(time.time() - start_time)
    mins, secs = divmod(elapsed, 60)
    print(f"\r[{label}] Finalizado en {mins:02d}:{secs:02d} | {tool_count} herramientas usadas                    ")

    return proc.returncode or 0, "".join(output_text_parts)


# --- Directorio de proyecto ---------------------------------------------------

def resolve_project_dir(base_work_dir: str, url: str, output_dir: str | None, debug: bool) -> Path:
    if output_dir:
        project_dir = Path(output_dir)
    else:
        domain = urlparse(url if "://" in url else f"https://{url}").hostname or "unknown"
        domain = domain.replace("www.", "")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        project_dir = Path(base_work_dir) / f"{domain}_{ts}"
    project_dir.mkdir(parents=True, exist_ok=True)
    dbg(f"Directorio del proyecto: {project_dir}", debug)
    return project_dir


# --- PASO 1: wget — descarga del sitio ---------------------------------------

def step_wget(url: str, project_dir: Path, debug: bool) -> bool:
    """Descarga el sitio completo con wget. Codigo puro, sin IA."""
    print("=" * 60)
    print("[PASO 1/3] Descarga del sitio con wget")
    print("=" * 60)

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    site_dir = project_dir / "site"
    site_dir.mkdir(exist_ok=True)

    wget_cmd = [
        "wget",
        "--mirror",
        "--convert-links",
        "--adjust-extension",
        "--no-parent",
        "--wait=1",
        "--random-wait",
        "-e", "robots=off",
        "--no-check-certificate",
        # Solo descargar HTML, JS y JSON — rechazar imagenes, CSS, fuentes, video, etc.
        "--reject", "*.png,*.jpg,*.jpeg,*.gif,*.svg,*.ico,*.webp,*.bmp,*.tiff,"
                    "*.css,*.woff,*.woff2,*.ttf,*.eot,*.otf,"
                    "*.mp4,*.mp3,*.avi,*.mov,*.wmv,*.flv,*.webm,*.ogg,"
                    "*.pdf,*.zip,*.tar,*.gz,*.rar,*.7z,"
                    "*.map",
        "--accept", "*.html,*.htm,*.js,*.json,*.xml,*.mjs,*.cjs,*.jsx,*.ts,*.tsx",
        "-U", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        "-P", str(site_dir),
        url,
    ]

    dbg(f"Comando: {' '.join(wget_cmd)}", debug)
    print(f"[wget] Descargando {url} ...")
    print(f"[wget] Destino: {site_dir}")

    try:
        result = subprocess.run(
            wget_cmd,
            cwd=str(project_dir),
            timeout=300,
            capture_output=not debug,
        )
        if result.returncode not in (0, 8):
            print(f"[wget] WARN: wget termino con codigo {result.returncode}")
            if not debug and result.stderr:
                print(f"[wget] stderr: {result.stderr.decode('utf-8', errors='replace')[-500:]}")
    except FileNotFoundError:
        print("[wget] ERROR: wget no encontrado. Instala con: apt install wget")
        return False
    except subprocess.TimeoutExpired:
        print("[wget] WARN: wget timeout (5 min). Descarga parcial.")

    downloaded = list(site_dir.rglob("*"))
    files = [f for f in downloaded if f.is_file()]
    js_files = [f for f in files if f.suffix == ".js"]
    html_files = [f for f in files if f.suffix in (".html", ".htm")]

    print(f"[wget] Descargados: {len(files)} archivos ({len(js_files)} JS, {len(html_files)} HTML)")

    if not files:
        print("[wget] ERROR: No se descargo ningun archivo.")
        return False

    if debug:
        for f in sorted(files)[:50]:
            rel = f.relative_to(site_dir)
            size = f.stat().st_size
            dbg(f"  {rel} ({size:,} bytes)", debug)
        if len(files) > 50:
            dbg(f"  ... y {len(files) - 50} archivos mas", debug)

    return True


# --- PASO 2: claude /init ----------------------------------------------------

def step_init(project_dir: Path, debug: bool) -> bool:
    """Ejecuta 'claude -p /init' real en la carpeta del proyecto."""
    print()
    print("=" * 60)
    print("[PASO 2/3] Reconocimiento con Claude Code (/init)")
    print("=" * 60)

    claude_bin = shutil.which("claude")
    if not claude_bin:
        print("[init] ERROR: 'claude' CLI no encontrado.")
        print("[init] Instala Claude Code: https://claude.ai/code")
        return False

    claude_cmd = [
        claude_bin,
        "-p", "/init",
        "--dangerously-skip-permissions",
    ]

    print(f"[init] Ejecutando Claude Code /init en {project_dir} ...")
    returncode, _ = run_claude_streaming(claude_cmd, str(project_dir), "init", debug, timeout=300)

    if returncode != 0:
        print(f"[init] WARN: claude termino con codigo {returncode}")

    claude_md = project_dir / "CLAUDE.md"
    if claude_md.is_file():
        size = claude_md.stat().st_size
        print(f"[init] OK: CLAUDE.md generado ({size:,} bytes)")
        return True
    else:
        print("[init] WARN: No se genero CLAUDE.md.")
        return False


# --- PASO 3: claude -p audit (CLI real, no SDK) -------------------------------

def step_audit(url: str, model: str, budget: float, max_turns: int,
               project_dir: Path, debug: bool, lang: str = "en") -> bool:
    """Ejecuta el analisis de seguridad usando claude CLI real (no SDK)."""
    print()
    print("=" * 60)
    print("[STEP 3/3] Security analysis with Claude Code")
    print(f"[audit] Model: {model} | Budget: ${budget:.2f}")
    print("=" * 60)

    claude_bin = shutil.which("claude")
    if not claude_bin:
        print("[audit] ERROR: 'claude' CLI no encontrado.")
        return False

    # Construir system prompt desde AGENT_PROMPT.md
    agent_prompt_path = Path(__file__).parent / "AGENT_PROMPT.md"
    if not agent_prompt_path.is_file():
        print(f"[audit] ERROR: No se encontro {agent_prompt_path}")
        return False

    system_prompt = agent_prompt_path.read_text(encoding="utf-8")
    dbg(f"System prompt: {len(system_prompt)} chars desde {agent_prompt_path}", debug)

    # Armar el prompt del usuario
    lang_name = LANG_NAMES.get(lang, "English")
    user_prompt = AUDIT_PROMPT.format(url=url, lang_name=lang_name)

    # Comando claude con system prompt, modelo, budget
    claude_cmd = [
        claude_bin,
        "-p", user_prompt,
        "--system-prompt", system_prompt,
        "--model", model,
        "--max-budget-usd", str(budget),
        "--dangerously-skip-permissions",
    ]

    dbg(f"Comando: claude -p '...' --model {model} --max-budget-usd {budget}", debug)
    print(f"[audit] Ejecutando analisis de seguridad ...")

    returncode, output = run_claude_streaming(claude_cmd, str(project_dir), "audit", debug, timeout=600)

    if returncode != 0:
        print(f"[audit] WARN: claude termino con codigo {returncode}")

    # Verificar si se genero el report JSON (el agente deberia haberlo escrito con Write)
    report_path = project_dir / "webaudit_report.json"
    report_data = None

    if report_path.is_file():
        print(f"[audit] OK: Informe JSON generado ({report_path.stat().st_size:,} bytes)")
        try:
            report_data = json.loads(report_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            print(f"[audit] WARN: webaudit_report.json no es JSON valido")
    elif output:
        # Si no lo escribio con Write, intentar extraer JSON del output
        try:
            json_start = output.find("{")
            json_end = output.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                candidate = output[json_start:json_end]
                report_data = json.loads(candidate)
                report_path.write_text(candidate, encoding="utf-8")
                print(f"[audit] OK: Informe JSON extraido del output ({len(candidate):,} bytes)")
        except json.JSONDecodeError:
            pass

        if not report_data:
            txt_path = project_dir / "webaudit_report.txt"
            txt_path.write_text(output, encoding="utf-8")
            print(f"[audit] Resultado guardado como texto: {txt_path}")

    # --- Normalizar estructura del JSON (el agente puede usar variantes) ---
    if report_data:
        # Si el agente wrappeo en report_metadata / report, aplanar
        if "report_metadata" in report_data and "url" not in report_data:
            meta = report_data.pop("report_metadata")
            if isinstance(meta, dict):
                for k, v in meta.items():
                    if k not in report_data:
                        report_data[k] = v
        if "report" in report_data and isinstance(report_data["report"], dict) and "url" not in report_data:
            inner = report_data.pop("report")
            for k, v in inner.items():
                if k not in report_data:
                    report_data[k] = v

        # Normalizar nombres de campos en/es (el agente puede usar ingles)
        _ALIASES = {
            "findings": "hallazgos",
            "libraries": "librerias",
            "analyzed_files": "archivos_analizados",
            "executive_summary": "resumen_ejecutivo",
            "statistics": "estadisticas",
            "date": "fecha",
            "scope": "alcance",
            "type": "tipo",
            "target": "url",
            "title": "titulo_reporte",
        }
        for en_key, es_key in _ALIASES.items():
            if en_key in report_data and es_key not in report_data:
                report_data[es_key] = report_data[en_key]

    # --- Validar y reportar PoCs ---
    if report_data:
        hallazgos = report_data.get("hallazgos", [])
        total = len(hallazgos)
        con_poc = sum(1 for h in hallazgos if h.get("console_instrumentation"))
        sin_poc = total - con_poc
        suite = report_data.get("console_instrumentation", "")

        print(f"[audit] Hallazgos: {total} total, {con_poc} con PoC, {sin_poc} sin PoC")
        if suite:
            print(f"[audit] Suite de instrumentacion: {len(suite):,} chars")
        else:
            print(f"[audit] WARN: No se genero suite de instrumentacion (campo console_instrumentation raiz)")

        if sin_poc > 0:
            print(f"[audit] WARN: {sin_poc} hallazgos sin console_instrumentation:")
            for h in hallazgos:
                if not h.get("console_instrumentation"):
                    print(f"         - #{h.get('id', '?')}: {h.get('titulo', '?')}")

        sniffer = report_data.get("application_sniffer", "")
        if sniffer:
            print(f"[audit] Application sniffer: {len(sniffer):,} chars")
        else:
            print(f"[audit] WARN: No se genero application_sniffer")

        crypto = report_data.get("crypto_analysis")
        if crypto and isinstance(crypto, dict) and crypto.get("detected"):
            n_schemes = len(crypto.get("schemes", []))
            print(f"[audit] Crypto analysis: {n_schemes} scheme(s) detected")
        elif crypto is None:
            print(f"[audit] Crypto analysis: no client-side encryption detected")
        else:
            print(f"[audit] Crypto analysis: present but no schemes detected")

        burp_ext = report_data.get("burp_extension", "")
        if burp_ext:
            print(f"[audit] Burp crypto extension: {len(burp_ext):,} chars")
            burp_path = project_dir / "webaudit_burp_crypto.py"
            burp_path.write_text(burp_ext, encoding="utf-8")
            print(f"[audit] OK: Burp crypto extension saved to {burp_path}")
        elif crypto and isinstance(crypto, dict) and crypto.get("detected"):
            print(f"[audit] WARN: Crypto detected but no burp_extension generated")
        else:
            print(f"[audit] Burp crypto extension: not generated (no crypto detected)")

        burp_auth = report_data.get("burp_auth_analyzer", "")
        if burp_auth:
            print(f"[audit] Burp auth analyzer: {len(burp_auth):,} chars")
            burp_auth_path = project_dir / "webaudit_burp_auth.py"
            burp_auth_path.write_text(burp_auth, encoding="utf-8")
            print(f"[audit] OK: Burp auth analyzer saved to {burp_auth_path}")
        else:
            print(f"[audit] WARN: No burp_auth_analyzer generated")

    # --- Generar reporte Markdown (siempre desde JSON, no del agente) ---
    if report_data:
        md_path = project_dir / "webaudit_report.md"
        md_content = _generate_markdown_report(report_data, lang)
        md_path.write_text(md_content, encoding="utf-8")
        print(f"[audit] OK: Markdown report generated ({md_path.stat().st_size:,} bytes)")

    return True


# --- Labels por idioma para el Markdown generado ---

MD_LABELS = {
    "en": {
        "title": "Frontend Security Diagnostic",
        "target": "Target",
        "date": "Date",
        "type": "Type",
        "scope": "Scope",
        "stats": "Statistics",
        "metric": "Metric",
        "value": "Value",
        "executive_summary": "Executive Summary",
        "findings_table": "Findings Classification",
        "finding": "Finding",
        "severity": "Severity",
        "description": "Description",
        "impact": "Impact",
        "evidence": "Evidence",
        "file": "File",
        "line": "line",
        "context": "Context",
        "reproduction_steps": "Reproduction Steps",
        "poc": "Proof of Concept (PoC)",
        "poc_instructions": "Copy and paste in the browser console:",
        "recommendations": "Recommendations",
        "appendix_libs": "Appendix A: Library Inventory",
        "lib_name": "Library",
        "version": "Version",
        "cves": "CVEs",
        "in_use": "In Use",
        "note": "Note",
        "yes": "Yes",
        "no": "No",
        "appendix_suite": "Appendix B: Instrumentation Suite",
        "suite_instructions": "Complete PoC suite — copy and paste in the browser console:",
        "appendix_crypto": "Cryptographic Analysis",
        "crypto_summary": "Summary",
        "crypto_scheme": "Encryption Scheme",
        "crypto_algorithm": "Algorithm",
        "crypto_key_source": "Key Source",
        "crypto_iv": "IV / Nonce",
        "crypto_what": "What is Encrypted",
        "crypto_flow": "Encryption Flow",
        "crypto_weaknesses": "Weaknesses",
        "crypto_impact": "Impact",
        "crypto_instrumentation": "Crypto Instrumentation",
        "crypto_instrumentation_instructions": "Copy and paste in the browser console to intercept encryption/decryption in real-time:",
        "crypto_files": "Files",
        "crypto_not_detected": "No client-side request encryption/decryption was detected in the application code.",
        "appendix_burp": "Appendix C: Burp Suite — Decrypted Traffic Viewer",
        "burp_instructions": "Save the code below as a .py file and load it in Burp Suite > Extensions > Add (requires Jython). The plugin creates a custom tab that shows decrypted traffic in real-time.",
        "appendix_burp_auth": "Appendix D: Burp Suite — Authorization Analyzer",
        "burp_auth_instructions": "Save the code below as a .py file and load it in Burp Suite > Extensions > Add (requires Jython). The plugin creates a custom tab pre-loaded with the target's endpoints to test authorization bypass. Click 'Run All Tests' to check which endpoints enforce server-side auth.",
        "appendix_sniffer": "Appendix E: Application Sniffer",
        "sniffer_instructions": "Custom application sniffer — copy and paste in the browser console to monitor the application's behavior in real-time (variables, storage, network calls, forms, cookies):",
        "appendix_files": "Appendix F: Analyzed Files",
        "file_col": "File",
        "type_col": "Type",
        "lines_col": "Lines",
        "desc_col": "Description",
        "generated_by": "Generated by",
    },
    "es": {
        "title": "Diagnostico de Seguridad Frontend",
        "target": "Objetivo",
        "date": "Fecha",
        "type": "Tipo",
        "scope": "Alcance",
        "stats": "Estadisticas",
        "metric": "Metrica",
        "value": "Valor",
        "executive_summary": "Resumen Ejecutivo",
        "findings_table": "Clasificacion de Hallazgos",
        "finding": "Hallazgo",
        "severity": "Severidad",
        "description": "Descripcion",
        "impact": "Impacto",
        "evidence": "Evidencia",
        "file": "Archivo",
        "line": "linea",
        "context": "Contexto",
        "reproduction_steps": "Pasos de Reproduccion",
        "poc": "Prueba de Concepto (PoC)",
        "poc_instructions": "Copiar y pegar en la consola del navegador:",
        "recommendations": "Recomendaciones",
        "appendix_libs": "Apendice A: Inventario de Librerias",
        "lib_name": "Libreria",
        "version": "Version",
        "cves": "CVEs",
        "in_use": "En uso",
        "note": "Nota",
        "yes": "Si",
        "no": "No",
        "appendix_suite": "Apendice B: Suite de Instrumentacion",
        "suite_instructions": "Suite completa de PoCs — copiar y pegar en la consola del navegador:",
        "appendix_crypto": "Analisis Criptografico",
        "crypto_summary": "Resumen",
        "crypto_scheme": "Esquema de Cifrado",
        "crypto_algorithm": "Algoritmo",
        "crypto_key_source": "Origen de la Clave",
        "crypto_iv": "IV / Nonce",
        "crypto_what": "Que se Cifra",
        "crypto_flow": "Flujo de Cifrado",
        "crypto_weaknesses": "Debilidades",
        "crypto_impact": "Impacto",
        "crypto_instrumentation": "Instrumentacion Crypto",
        "crypto_instrumentation_instructions": "Copiar y pegar en la consola del navegador para interceptar cifrado/descifrado en tiempo real:",
        "crypto_files": "Archivos",
        "crypto_not_detected": "No se detecto cifrado/descifrado de requests del lado del cliente en el codigo de la aplicacion.",
        "appendix_burp": "Apendice C: Burp Suite — Visor de Trafico Descifrado",
        "burp_instructions": "Guardar el codigo de abajo como archivo .py y cargarlo en Burp Suite > Extensions > Add (requiere Jython). El plugin crea una pestania custom que muestra el trafico descifrado en tiempo real.",
        "appendix_burp_auth": "Apendice D: Burp Suite — Analizador de Autorizacion",
        "burp_auth_instructions": "Guardar el codigo de abajo como archivo .py y cargarlo en Burp Suite > Extensions > Add (requiere Jython). El plugin crea una pestania pre-cargada con los endpoints del target para testear bypass de autorizacion. Click en 'Run All Tests' para verificar cuales endpoints aplican auth del lado del servidor.",
        "appendix_sniffer": "Apendice E: Sniffer Aplicativo",
        "sniffer_instructions": "Sniffer personalizado de la aplicacion — copiar y pegar en la consola del navegador para monitorear en tiempo real el comportamiento de la aplicacion (variables, storage, llamadas de red, formularios, cookies):",
        "appendix_files": "Apendice F: Archivos Analizados",
        "file_col": "Archivo",
        "type_col": "Tipo",
        "lines_col": "Lineas",
        "desc_col": "Descripcion",
        "generated_by": "Generado por",
    },
}


def _local_path_to_url(path: str, target_url: str) -> str:
    """Convert local file path like site/www.example.com/page/index.html to https://www.example.com/page/."""
    parsed = urlparse(target_url)
    scheme = parsed.scheme or "https"

    # Strip site/ prefix
    p = path
    if p.startswith("site/"):
        p = p[5:]
    elif p.startswith("./site/"):
        p = p[7:]

    # The first path component should be the domain; strip it
    parts = p.split("/", 1)
    if len(parts) < 2:
        return f"{scheme}://{p}"
    domain_part = parts[0]
    rest = parts[1]

    # Strip trailing index.html / index.htm
    rest = re.sub(r'index\.html?$', '', rest)

    # Ensure trailing slash for directories
    if rest and not rest.endswith("/") and "." not in rest.split("/")[-1]:
        rest += "/"

    return f"{scheme}://{domain_part}/{rest}"


def _to_str(val) -> str:
    """Coerce any value to a markdown-safe string. Lists become bullet points, dicts become JSON."""
    if val is None:
        return ""
    if isinstance(val, str):
        return val
    if isinstance(val, list):
        return "\n".join(f"- {_to_str(item)}" for item in val)
    if isinstance(val, dict):
        # Try to render key-value pairs
        parts = []
        for k, v in val.items():
            parts.append(f"**{k}:** {_to_str(v)}")
        return "\n".join(parts)
    return str(val)


def _generate_markdown_report(data: dict, lang: str = "en") -> str:
    """Genera un informe Markdown completo desde los datos JSON del reporte."""
    L = MD_LABELS.get(lang, MD_LABELS["en"])
    lines = []
    url = data.get("url", data.get("target", "?"))
    domain = urlparse(url).hostname or url

    lines.append(f"# {L['title']} — {domain}")
    lines.append("")
    lines.append(f"**{L['target']}:** {url}")
    lines.append(f"**{L['date']}:** {data.get('fecha', '?')}")
    lines.append(f"**{L['type']}:** {data.get('tipo', '?')}")
    lines.append(f"**{L['scope']}:** {data.get('alcance', '?')}")
    lines.append("")

    # Estadisticas
    stats = data.get("estadisticas", {})
    if stats:
        lines.append(f"## {L['stats']}")
        lines.append("")
        lines.append(f"| {L['metric']} | {L['value']} |")
        lines.append(f"|---------|-------|")
        for k, v in stats.items():
            label = k.replace("_", " ").capitalize()
            lines.append(f"| {label} | {v} |")
        lines.append("")

    # Resumen ejecutivo
    resumen = data.get("resumen_ejecutivo", "")
    if resumen:
        lines.append(f"## {L['executive_summary']}")
        lines.append("")
        lines.append(_to_str(resumen))
        lines.append("")

    # Tabla de hallazgos
    hallazgos = data.get("hallazgos", [])
    if hallazgos:
        lines.append(f"## {L['findings_table']}")
        lines.append("")
        lines.append(f"| # | {L['finding']} | {L['severity']} | CVSS | CWE |")
        lines.append("|---|----------|-----------|------|-----|")
        for h in hallazgos:
            titulo = h.get("titulo", h.get("title", "?"))
            sev = h.get("severidad", h.get("severity", "?"))
            cvss_val = h.get('cvss_v3_1', '?')
            if isinstance(cvss_val, dict):
                cvss_val = cvss_val.get('score', cvss_val.get('base_score', '?'))
            lines.append(f"| {h.get('id', '?')} | {titulo} | **{sev}** | {cvss_val} | {h.get('cwe', '?')} |")
        lines.append("")

        # Detalle de cada hallazgo
        for h in hallazgos:
            titulo = h.get("titulo", h.get("title", "?"))
            sev = h.get("severidad", h.get("severity", "?"))
            lines.append(f"---")
            lines.append("")
            lines.append(f"## {L['finding']} {h.get('id', '?')}: {titulo}")
            lines.append("")
            lines.append(f"**{L['severity']}:** {sev}")
            cvss_val = h.get('cvss_v3_1', '?')
            if isinstance(cvss_val, dict):
                cvss_val = cvss_val.get('score', cvss_val.get('base_score', str(cvss_val)))
            lines.append(f"**CVSS v3.1:** {cvss_val}")
            lines.append(f"**CWE:** {h.get('cwe', '?')}")
            lines.append("")

            desc = h.get("descripcion", h.get("description", ""))
            if desc:
                lines.append(f"### {L['description']}")
                lines.append("")
                lines.append(_to_str(desc))
                lines.append("")

            impacto = h.get("impacto", h.get("impact", ""))
            if impacto:
                lines.append(f"### {L['impact']}")
                lines.append("")
                lines.append(_to_str(impacto))
                lines.append("")

            evidencia = h.get("evidencia", h.get("evidence", {}))
            if evidencia:
                lines.append(f"### {L['evidence']}")
                lines.append("")
                if isinstance(evidencia, dict):
                    archivo_raw = str(evidencia.get("archivo", evidencia.get("file", "?")))
                    archivo = _local_path_to_url(archivo_raw, url) if archivo_raw.startswith(("site/", "./site/")) else archivo_raw
                    linea = evidencia.get("linea", evidencia.get("line", "?"))
                    codigo = _to_str(evidencia.get("codigo", evidencia.get("code", "")))
                    contexto = _to_str(evidencia.get("contexto", evidencia.get("context", "")))
                    lines.append(f"**{L['file']}:** `{archivo}` ({L['line']} {linea})")
                    lines.append("")
                    if codigo:
                        lines.append("```javascript")
                        lines.append(codigo)
                        lines.append("```")
                        lines.append("")
                    if contexto:
                        lines.append(f"**{L['context']}:** {contexto}")
                        lines.append("")
                elif isinstance(evidencia, list):
                    for ev in evidencia:
                        lines.append(_to_str(ev))
                        lines.append("")
                else:
                    lines.append(str(evidencia))
                    lines.append("")

            pasos = h.get("pasos_reproduccion", h.get("reproduction_steps", ""))
            if pasos:
                lines.append(f"### {L['reproduction_steps']}")
                lines.append("")
                lines.append(_to_str(pasos))
                lines.append("")

            if h.get("console_instrumentation"):
                lines.append(f"### {L['poc']}")
                lines.append("")
                lines.append(L['poc_instructions'])
                lines.append("")
                lines.append("```javascript")
                lines.append(_to_str(h["console_instrumentation"]))
                lines.append("```")
                lines.append("")

            recom = h.get("recomendaciones", h.get("recommendations", ""))
            if recom:
                lines.append(f"### {L['recommendations']}")
                lines.append("")
                lines.append(_to_str(recom))
                lines.append("")

    # Analisis criptografico
    crypto = data.get("crypto_analysis")
    if crypto and isinstance(crypto, dict) and crypto.get("detected"):
        lines.append("---")
        lines.append("")
        lines.append(f"## {L['appendix_crypto']}")
        lines.append("")

        crypto_summary = crypto.get("summary", "")
        if crypto_summary:
            lines.append(f"### {L['crypto_summary']}")
            lines.append("")
            lines.append(crypto_summary)
            lines.append("")

        schemes = crypto.get("schemes", [])
        for i, scheme in enumerate(schemes, 1):
            name = scheme.get("name", f"Scheme {i}")
            lines.append(f"### {L['crypto_scheme']} {i}: {name}")
            lines.append("")

            if scheme.get("files"):
                files_list = scheme["files"]
                converted = []
                for f in files_list:
                    if f.startswith(("site/", "./site/")):
                        converted.append(f"`{_local_path_to_url(f, url)}`")
                    else:
                        converted.append(f"`{f}`")
                lines.append(f"**{L['crypto_files']}:** {', '.join(converted)}")
                lines.append("")

            for field, label_key in [
                ("algorithm", "crypto_algorithm"),
                ("key_source", "crypto_key_source"),
                ("iv", "crypto_iv"),
                ("what_is_encrypted", "crypto_what"),
            ]:
                val = scheme.get(field, "")
                if val:
                    lines.append(f"**{L[label_key]}:** {_to_str(val)}")
                    lines.append("")

            flow = scheme.get("flow", "")
            if flow:
                lines.append(f"**{L['crypto_flow']}:**")
                lines.append("")
                lines.append(_to_str(flow))
                lines.append("")

            weaknesses = scheme.get("weaknesses", [])
            if weaknesses:
                lines.append(f"**{L['crypto_weaknesses']}:**")
                lines.append("")
                for w in weaknesses:
                    lines.append(f"- {_to_str(w)}")
                lines.append("")

            impact = scheme.get("impact", "")
            if impact:
                lines.append(f"**{L['crypto_impact']}:** {_to_str(impact)}")
                lines.append("")

            ci = scheme.get("console_instrumentation", "")
            if ci:
                lines.append(f"### {L['crypto_instrumentation']}")
                lines.append("")
                lines.append(L['crypto_instrumentation_instructions'])
                lines.append("")
                lines.append("```javascript")
                lines.append(ci)
                lines.append("```")
                lines.append("")

    # Librerias
    librerias = data.get("librerias", data.get("libraries", []))
    if librerias:
        lines.append("---")
        lines.append("")
        lines.append(f"## {L['appendix_libs']}")
        lines.append("")
        lines.append(f"| {L['lib_name']} | {L['version']} | {L['cves']} | {L['in_use']} | {L['note']} |")
        lines.append("|----------|---------|------|--------|------|")
        for lib in librerias:
            cves_list = lib.get("cves", [])
            cves = ", ".join(str(c) if not isinstance(c, dict) else c.get("id", c.get("cve", str(c))) for c in cves_list) if cves_list else "—"
            en_uso = L["yes"] if lib.get("funciones_afectadas_en_uso", lib.get("affected_functions_in_use")) else L["no"]
            nota = lib.get("nota", lib.get("note", ""))
            nombre = lib.get("nombre", lib.get("name", "?"))
            lines.append(f"| {nombre} | {lib.get('version', '?')} | {cves} | {en_uso} | {nota} |")
        lines.append("")

    # Suite de instrumentacion
    suite = data.get("console_instrumentation", "")
    if suite:
        lines.append("---")
        lines.append("")
        lines.append(f"## {L['appendix_suite']}")
        lines.append("")
        lines.append(L['suite_instructions'])
        lines.append("")
        lines.append("```javascript")
        lines.append(suite)
        lines.append("```")
        lines.append("")

    # Burp Suite Extension
    burp_ext = data.get("burp_extension", "")
    if burp_ext:
        lines.append("---")
        lines.append("")
        lines.append(f"## {L['appendix_burp']}")
        lines.append("")
        lines.append(L['burp_instructions'])
        lines.append("")
        lines.append("```python")
        lines.append(burp_ext)
        lines.append("```")
        lines.append("")

    # Burp Auth Analyzer
    burp_auth = data.get("burp_auth_analyzer", "")
    if burp_auth:
        lines.append("---")
        lines.append("")
        lines.append(f"## {L['appendix_burp_auth']}")
        lines.append("")
        lines.append(L['burp_auth_instructions'])
        lines.append("")
        lines.append("```python")
        lines.append(burp_auth)
        lines.append("```")
        lines.append("")

    # Application Sniffer
    sniffer = data.get("application_sniffer", "")
    if sniffer:
        lines.append("---")
        lines.append("")
        lines.append(f"## {L['appendix_sniffer']}")
        lines.append("")
        lines.append(L['sniffer_instructions'])
        lines.append("")
        lines.append("```javascript")
        lines.append(sniffer)
        lines.append("```")
        lines.append("")

    # Archivos analizados
    archivos = data.get("archivos_analizados", data.get("analyzed_files", []))
    if archivos:
        lines.append("---")
        lines.append("")
        lines.append(f"## {L['appendix_files']}")
        lines.append("")
        lines.append(f"| {L['file_col']} | {L['type_col']} | {L['lines_col']} | {L['desc_col']} |")
        lines.append("|---------|------|--------|-------------|")
        for a in archivos:
            archivo_raw = a.get("archivo", a.get("file", "?"))
            archivo = _local_path_to_url(archivo_raw, url) if archivo_raw.startswith(("site/", "./site/")) else archivo_raw
            tipo = a.get("tipo", a.get("type", "?"))
            lineas = a.get("lineas", a.get("lines", "?"))
            desc = a.get("descripcion", a.get("description", ""))
            lines.append(f"| `{archivo}` | {tipo} | {lineas} | {desc} |")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(f"*{L['generated_by']} [WebAudit](https://github.com/openbashok/webaudit)*")
    lines.append("")

    return "\n".join(lines)


# --- Health check -------------------------------------------------------------

def run_check(config: dict, debug: bool) -> bool:
    ok = True

    print("[check] Archivo de configuracion ...")
    if config["_config_file"]:
        print(f"  OK: {config['_config_file']}")
    else:
        print(f"  WARN: No se encontro config en: {', '.join(str(p) for p in CONFIG_PATHS)}")

    print("[check] API key de Anthropic ...")
    api_key = config.get("anthropic_api_key", "")
    if api_key and api_key != 'sk-ant-PONE-TU-CLAVE-ACA':
        masked = api_key[:10] + "..." + api_key[-4:]
        print(f"  OK: {masked}")
    else:
        print("  FAIL: No configurada o es placeholder.")
        ok = False

    print("[check] Conexion a la API de Anthropic ...")
    if api_key and api_key != 'sk-ant-PONE-TU-CLAVE-ACA':
        try:
            import anthropic
            client = anthropic.Anthropic(api_key=api_key)
            resp = client.messages.create(
                model="claude-haiku-4-5",
                max_tokens=10,
                messages=[{"role": "user", "content": "ping"}],
            )
            print(f"  OK: API respondio (tokens: {resp.usage.output_tokens})")
        except ImportError:
            print("  SKIP: anthropic SDK no instalado (solo necesario para check)")
        except Exception as e:
            print(f"  FAIL: {e}")
            ok = False
    else:
        print("  SKIP: No hay API key.")
        ok = False

    print("[check] Claude Code CLI ...")
    claude_bin = shutil.which("claude")
    if claude_bin:
        try:
            result = subprocess.run([claude_bin, "--version"], capture_output=True, text=True)
            print(f"  OK: {claude_bin} ({result.stdout.strip()})")
        except Exception:
            print(f"  OK: {claude_bin}")
    else:
        print("  FAIL: 'claude' no encontrado. Es necesario para /init y audit.")
        ok = False

    base_dir = Path(__file__).parent
    for fname, label, required in [
        ("CLAUDE.md", "Contexto del proyecto", False),
        ("AGENT_PROMPT.md", "Instrucciones del agente", True),
    ]:
        fpath = base_dir / fname
        print(f"[check] {label} ({fname}) ...")
        if fpath.is_file():
            print(f"  OK: {fpath} ({fpath.stat().st_size:,} bytes)")
        elif required:
            print(f"  FAIL: No encontrado")
            ok = False
        else:
            print(f"  WARN: No encontrado (opcional)")

    print("[check] wget ...")
    if shutil.which("wget"):
        print(f"  OK: {shutil.which('wget')}")
    else:
        print("  FAIL: wget no encontrado. Instala con: apt install wget")
        ok = False

    print("[check] Directorio de trabajo ...")
    work_dir = Path(config["work_dir"])
    try:
        work_dir.mkdir(parents=True, exist_ok=True)
        test_file = work_dir / ".webaudit_test"
        test_file.write_text("ok")
        test_file.unlink()
        print(f"  OK: {work_dir} (escribible)")
    except Exception as e:
        print(f"  FAIL: {work_dir} -> {e}")
        ok = False

    print()
    if ok:
        print("[check] Todo OK. Listo para auditar.")
    else:
        print("[check] Hay problemas. Revisa los FAIL de arriba.")
    return ok


# --- Flujo principal ----------------------------------------------------------

def run_audit(url: str, model: str, budget: float, max_turns: int,
              project_dir: Path, debug: bool, lang: str = "en"):
    """Flujo completo: wget → claude /init → claude audit."""

    lang_name = LANG_NAMES.get(lang, "English")
    print(f"[webaudit] URL: {url}")
    print(f"[webaudit] Model: {model}")
    print(f"[webaudit] Budget: ${budget:.2f}")
    print(f"[webaudit] Language: {lang_name}")
    print(f"[webaudit] Project: {project_dir}")
    print()

    # --- PASO 1: wget ---
    if not step_wget(url, project_dir, debug):
        print("\n[webaudit] ERROR: Download failed. Aborting.")
        sys.exit(1)

    # --- PASO 2: claude /init ---
    step_init(project_dir, debug)

    # --- PASO 3: claude audit ---
    step_audit(url, model, budget, max_turns, project_dir, debug, lang)

    # --- Resumen ---
    print("\n" + "=" * 60)
    print("[webaudit] Analisis completo.")

    # Mostrar reportes generados
    report_json = project_dir / "webaudit_report.json"
    report_md = project_dir / "webaudit_report.md"

    if report_json.is_file():
        print(f"\n[webaudit] Reportes:")
        print(f"  JSON: {report_json} ({report_json.stat().st_size:,} bytes)")
    if report_md.is_file():
        print(f"  Markdown: {report_md} ({report_md.stat().st_size:,} bytes)")

    print(f"\n[webaudit] Todos los archivos en {project_dir}:")
    for f in sorted(project_dir.rglob("*")):
        if f.is_file() and ".git" not in f.parts:
            size = f.stat().st_size
            rel = f.relative_to(project_dir)
            print(f"  {rel} ({size:,} bytes)")


# --- CLI ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webaudit",
        description="Agente autonomo de analisis de seguridad frontend.",
    )
    sub = parser.add_subparsers(dest="command")

    scan = sub.add_parser("scan", help="Ejecutar auditoria de seguridad")
    scan.add_argument("url", help="URL del sitio a analizar")
    scan.add_argument("-m", "--model", help="Modelo de Claude")
    scan.add_argument("-b", "--budget", type=float, help="Limite de gasto en USD")
    scan.add_argument("-t", "--max-turns", type=int, help="Maximo de turnos del agente")
    scan.add_argument("-o", "--output-dir", help="Directorio de salida (default: auto)")
    scan.add_argument("-w", "--work-dir", help="Directorio base de trabajo (default: ~/webaudit)")
    scan.add_argument("-l", "--lang", choices=["en", "es"], help="Report language: en (default), es")
    scan.add_argument("-d", "--debug", action="store_true", help="Debug mode: real-time output")

    check = sub.add_parser("check", help="System health check")
    check.add_argument("-d", "--debug", action="store_true", help="Modo debug")

    return parser


def main():
    parser = build_parser()

    # Compatibilidad: "webaudit <url>" → "webaudit scan <url>"
    if len(sys.argv) > 1 and sys.argv[1] not in ("scan", "check", "-h", "--help"):
        first_arg = sys.argv[1]
        if "." in first_arg or "/" in first_arg:
            sys.argv.insert(1, "scan")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(0)

    config = load_config()
    debug = getattr(args, "debug", False)
    dbg(f"Config: {config['_config_file'] or 'defaults'}", debug)

    if args.command == "check":
        sys.exit(0 if run_check(config, debug) else 1)

    # --- scan ---
    api_key = config.get("anthropic_api_key", "")
    if not api_key or api_key == "sk-ant-PONE-TU-CLAVE-ACA":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("Error: No se encontro ANTHROPIC_API_KEY.", file=sys.stderr)
            sys.exit(1)
    if api_key and not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = api_key

    url = args.url
    model = args.model or config["default_model"]
    budget = args.budget if args.budget is not None else config["default_budget_usd"]
    max_turns = args.max_turns if args.max_turns is not None else config["default_max_turns"]
    work_dir = args.work_dir or config["work_dir"]
    lang = args.lang or config.get("default_lang", "en")
    project_dir = resolve_project_dir(work_dir, url, args.output_dir, debug)

    run_audit(url, model, budget, max_turns, project_dir, debug, lang)


if __name__ == "__main__":
    main()
