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
Auditoria de codigo fuente del sitio: {url}

El sitio ya fue descargado en ./site/ y CLAUDE.md tiene el contexto del codigo.

INSTRUCCIONES — segui los pasos del system prompt en orden:

1. Lee CLAUDE.md para entender la estructura.
2. Usa Glob para listar todos los .js y .html en ./site/
3. Clasifica cada JS como PROPIO o LIBRERIA.
4. Lee CADA archivo JS propio completo con Read — linea por linea.
5. Usa Grep para buscar patrones de vulnerabilidad (claves hardcodeadas, innerHTML, eval, localStorage, fetch, postMessage, etc.)
6. Para librerias con version, busca CVEs con WebSearch y verifica si las funciones afectadas se usan.
7. Verifica cada hallazgo potencial — vuelve a leer el contexto antes de confirmar.
8. Genera PoCs JavaScript inyectables para hallazgos Alta/Critica.
9. Genera la suite completa (panel inyectable con todos los PoCs).
10. Guarda webaudit_report.json con Write.

CRITICO: Esto es analisis ESTATICO DE CODIGO FUENTE, no un pentest de red.
Tu trabajo es LEER el codigo JavaScript y encontrar vulnerabilidades EN EL CODIGO.
No revises headers HTTP ni hagas pruebas de red. Lee archivos, busca patrones, analiza flujos de datos.
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
               project_dir: Path, debug: bool) -> bool:
    """Ejecuta el analisis de seguridad usando claude CLI real (no SDK)."""
    print()
    print("=" * 60)
    print("[PASO 3/3] Analisis de seguridad con Claude Code")
    print(f"[audit] Modelo: {model} | Budget: ${budget:.2f}")
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
    user_prompt = AUDIT_PROMPT.format(url=url)

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

    # --- Generar reporte Markdown ---
    if report_data:
        md_path = project_dir / "webaudit_report.md"

        # Si el agente incluyó informe_markdown, usarlo como base
        md_content = report_data.get("informe_markdown", "")

        if not md_content:
            # Generar Markdown desde los datos JSON
            md_content = _generate_markdown_report(report_data)

        md_path.write_text(md_content, encoding="utf-8")
        print(f"[audit] OK: Informe Markdown generado ({md_path.stat().st_size:,} bytes)")

    return True


def _generate_markdown_report(data: dict) -> str:
    """Genera un informe Markdown completo desde los datos JSON del reporte."""
    lines = []
    url = data.get("url", "?")
    domain = urlparse(url).hostname or url

    lines.append(f"# Diagnostico de Seguridad Frontend — {domain}")
    lines.append("")
    lines.append(f"**Objetivo:** {url}")
    lines.append(f"**Fecha:** {data.get('fecha', '?')}")
    lines.append(f"**Tipo:** {data.get('tipo', 'Analisis estatico de codigo frontend')}")
    lines.append(f"**Alcance:** {data.get('alcance', 'Codigo descargado del sitio')}")
    lines.append("")

    # Estadisticas
    stats = data.get("estadisticas", {})
    if stats:
        lines.append("## Estadisticas")
        lines.append("")
        lines.append(f"| Metrica | Valor |")
        lines.append(f"|---------|-------|")
        for k, v in stats.items():
            label = k.replace("_", " ").capitalize()
            lines.append(f"| {label} | {v} |")
        lines.append("")

    # Resumen ejecutivo
    resumen = data.get("resumen_ejecutivo", "")
    if resumen:
        lines.append("## Resumen Ejecutivo")
        lines.append("")
        lines.append(resumen)
        lines.append("")

    # Tabla de hallazgos
    hallazgos = data.get("hallazgos", [])
    if hallazgos:
        lines.append("## Clasificacion de Hallazgos")
        lines.append("")
        lines.append("| # | Hallazgo | Severidad | CVSS | CWE |")
        lines.append("|---|----------|-----------|------|-----|")
        for h in hallazgos:
            lines.append(f"| {h.get('id', '?')} | {h.get('titulo', '?')} | **{h.get('severidad', '?')}** | {h.get('cvss_v3_1', '?')} | {h.get('cwe', '?')} |")
        lines.append("")

        # Detalle de cada hallazgo
        for h in hallazgos:
            lines.append(f"---")
            lines.append("")
            lines.append(f"## Hallazgo {h.get('id', '?')}: {h.get('titulo', '?')}")
            lines.append("")
            lines.append(f"**Severidad:** {h.get('severidad', '?')}")
            lines.append(f"**CVSS v3.1:** {h.get('cvss_v3_1', '?')}")
            lines.append(f"**CWE:** {h.get('cwe', '?')}")
            lines.append("")

            if h.get("descripcion"):
                lines.append("### Descripcion")
                lines.append("")
                lines.append(h["descripcion"])
                lines.append("")

            if h.get("impacto"):
                lines.append("### Impacto")
                lines.append("")
                lines.append(h["impacto"])
                lines.append("")

            evidencia = h.get("evidencia", {})
            if evidencia:
                lines.append("### Evidencia")
                lines.append("")
                if isinstance(evidencia, dict):
                    archivo = evidencia.get("archivo", "?")
                    linea = evidencia.get("linea", "?")
                    codigo = evidencia.get("codigo", "")
                    contexto = evidencia.get("contexto", "")
                    lines.append(f"**Archivo:** `{archivo}` (linea {linea})")
                    lines.append("")
                    if codigo:
                        lines.append("```javascript")
                        lines.append(codigo)
                        lines.append("```")
                        lines.append("")
                    if contexto:
                        lines.append(f"**Contexto:** {contexto}")
                        lines.append("")
                else:
                    lines.append(str(evidencia))
                    lines.append("")

            if h.get("pasos_reproduccion"):
                lines.append("### Pasos de Reproduccion")
                lines.append("")
                lines.append(h["pasos_reproduccion"])
                lines.append("")

            if h.get("console_instrumentation"):
                lines.append("### Prueba de Concepto (PoC)")
                lines.append("")
                lines.append("Copiar y pegar en la consola del navegador:")
                lines.append("")
                lines.append("```javascript")
                lines.append(h["console_instrumentation"])
                lines.append("```")
                lines.append("")

            if h.get("recomendaciones"):
                lines.append("### Recomendaciones")
                lines.append("")
                lines.append(h["recomendaciones"])
                lines.append("")

    # Librerias
    librerias = data.get("librerias", [])
    if librerias:
        lines.append("---")
        lines.append("")
        lines.append("## Apendice A: Inventario de Librerias")
        lines.append("")
        lines.append("| Libreria | Version | CVEs | En uso | Nota |")
        lines.append("|----------|---------|------|--------|------|")
        for lib in librerias:
            cves = ", ".join(lib.get("cves", [])) or "—"
            en_uso = "Si" if lib.get("funciones_afectadas_en_uso") else "No"
            nota = lib.get("nota", "")
            lines.append(f"| {lib.get('nombre', '?')} | {lib.get('version', '?')} | {cves} | {en_uso} | {nota} |")
        lines.append("")

    # Suite de instrumentacion
    suite = data.get("console_instrumentation", "")
    if suite:
        lines.append("---")
        lines.append("")
        lines.append("## Apendice B: Suite de Instrumentacion")
        lines.append("")
        lines.append("Suite completa de PoCs — copiar y pegar en la consola del navegador:")
        lines.append("")
        lines.append("```javascript")
        lines.append(suite)
        lines.append("```")
        lines.append("")

    # Archivos analizados
    archivos = data.get("archivos_analizados", [])
    if archivos:
        lines.append("---")
        lines.append("")
        lines.append("## Apendice C: Archivos Analizados")
        lines.append("")
        lines.append("| Archivo | Tipo | Lineas | Descripcion |")
        lines.append("|---------|------|--------|-------------|")
        for a in archivos:
            lines.append(f"| `{a.get('archivo', '?')}` | {a.get('tipo', '?')} | {a.get('lineas', '?')} | {a.get('descripcion', '')} |")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append("*Generado por [WebAudit](https://github.com/openbashok/webaudit) — Analisis estatico de codigo fuente frontend.*")
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
              project_dir: Path, debug: bool):
    """Flujo completo: wget → claude /init → claude audit."""

    print(f"[webaudit] URL: {url}")
    print(f"[webaudit] Modelo: {model}")
    print(f"[webaudit] Budget: ${budget:.2f}")
    print(f"[webaudit] Proyecto: {project_dir}")
    print()

    # --- PASO 1: wget ---
    if not step_wget(url, project_dir, debug):
        print("\n[webaudit] ERROR: Descarga fallida. Abortando.")
        sys.exit(1)

    # --- PASO 2: claude /init ---
    step_init(project_dir, debug)

    # --- PASO 3: claude audit ---
    step_audit(url, model, budget, max_turns, project_dir, debug)

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
    scan.add_argument("-d", "--debug", action="store_true", help="Modo debug: output en tiempo real")

    check = sub.add_parser("check", help="Verificar salud del sistema")
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
    project_dir = resolve_project_dir(work_dir, url, args.output_dir, debug)

    run_audit(url, model, budget, max_turns, project_dir, debug)


if __name__ == "__main__":
    main()
