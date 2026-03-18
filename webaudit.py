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
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

import yaml

# --- Prompt para el audit (paso 3) -------------------------------------------

AUDIT_PROMPT = """\
Realiza el analisis de seguridad completo del sitio: {url}

El sitio ya fue descargado y esta en el subdirectorio ./site/
Ya se ejecuto /init y el archivo CLAUDE.md en este directorio tiene el contexto
completo del codigo descargado.

Ejecuta las Fases 3, 4 y 5 del system prompt:

FASE 3 — ANALISIS DE SEGURIDAD:
Analiza todo el codigo JavaScript buscando vulnerabilidades en todas las categorias
(cifrado, autenticacion, control de acceso, inyeccion, exposicion de datos,
dependencias, CSRF, etc.). Para cada hallazgo, documenta archivo, linea, codigo
vulnerable, y por que es un problema. Busca CVEs para las librerias con version
detectada — pero solo reportalos si la funcion vulnerable se usa en el codigo.

FASE 4 — PRUEBAS DE CONCEPTO:
Para cada hallazgo de severidad Alta o Critica, genera codigo JavaScript inyectable
desde la consola del navegador. Ademas genera una suite completa que agrupe todos
los PoCs en un panel interactivo inyectable.

FASE 5 — INFORME:
Genera el archivo webaudit_report.json con la estructura JSON definida en el
system prompt. Los campos console_instrumentation (por hallazgo y en la raiz)
son los mas importantes — deben ser JS funcional copiar-y-pegar en consola.

IMPORTANTE:
- Lee CLAUDE.md primero para entender el sitio.
- Despues lee los archivos JS/HTML reales para encontrar vulnerabilidades.
- No reportes falsos positivos. Verifica que cada vulnerabilidad sea real.
- Guarda webaudit_report.json en este directorio.
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
        "--page-requisites",
        "--no-parent",
        "--wait=1",
        "--random-wait",
        "-e", "robots=off",
        "--no-check-certificate",
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

    dbg(f"Claude CLI: {claude_bin}", debug)

    claude_cmd = [
        claude_bin,
        "-p", "/init",
        "--dangerously-skip-permissions",
    ]

    dbg(f"Comando: {' '.join(claude_cmd)}", debug)
    print(f"[init] Ejecutando Claude Code /init en {project_dir} ...")

    try:
        if debug:
            # En debug, mostrar output en tiempo real
            proc = subprocess.Popen(
                claude_cmd,
                cwd=str(project_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            for line in proc.stdout:
                print(f"  [claude] {line}", end="")
            proc.wait(timeout=300)
            returncode = proc.returncode
        else:
            result = subprocess.run(
                claude_cmd,
                cwd=str(project_dir),
                timeout=300,
                capture_output=True,
                text=True,
            )
            returncode = result.returncode
            if returncode != 0 and result.stderr:
                print(f"[init] stderr: {result.stderr[-500:]}")

        if returncode != 0:
            print(f"[init] WARN: claude termino con codigo {returncode}")

    except FileNotFoundError:
        print("[init] ERROR: No se pudo ejecutar claude CLI.")
        return False
    except subprocess.TimeoutExpired:
        print("[init] WARN: claude /init timeout (5 min).")

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

    # Comando claude con system prompt, modelo, budget, y output JSON
    claude_cmd = [
        claude_bin,
        "-p", user_prompt,
        "--system-prompt", system_prompt,
        "--model", model,
        "--max-budget-usd", str(budget),
        "--dangerously-skip-permissions",
        "--output-format", "text",
    ]

    dbg(f"Comando: claude -p '...' --model {model} --max-budget-usd {budget}", debug)
    print(f"[audit] Ejecutando analisis de seguridad ...")

    try:
        if debug:
            # En debug, streaming del output en tiempo real
            proc = subprocess.Popen(
                claude_cmd,
                cwd=str(project_dir),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            output_lines = []
            for line in proc.stdout:
                output_lines.append(line)
                print(f"  [claude] {line}", end="")
            proc.wait(timeout=600)
            returncode = proc.returncode
            output = "".join(output_lines)
        else:
            result = subprocess.run(
                claude_cmd,
                cwd=str(project_dir),
                timeout=600,  # 10 minutos
                capture_output=True,
                text=True,
            )
            returncode = result.returncode
            output = result.stdout
            if result.stderr:
                dbg(f"stderr: {result.stderr[-300:]}", debug)

        if returncode != 0:
            print(f"[audit] WARN: claude termino con codigo {returncode}")

    except FileNotFoundError:
        print("[audit] ERROR: No se pudo ejecutar claude CLI.")
        return False
    except subprocess.TimeoutExpired:
        print("[audit] WARN: claude timeout (10 min).")
        return False

    # Verificar si se genero el report JSON (el agente deberia haberlo escrito con Write)
    report_path = project_dir / "webaudit_report.json"
    if report_path.is_file():
        print(f"[audit] OK: Informe generado ({report_path.stat().st_size:,} bytes)")
        return True

    # Si no lo escribio con Write, intentar extraer JSON del output
    if output:
        try:
            # Buscar JSON en el output
            json_start = output.find("{")
            json_end = output.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                candidate = output[json_start:json_end]
                json.loads(candidate)  # validar
                report_path.write_text(candidate, encoding="utf-8")
                print(f"[audit] OK: Informe extraido del output ({len(candidate):,} bytes)")
                return True
        except json.JSONDecodeError:
            pass

        # Guardar como texto
        txt_path = project_dir / "webaudit_report.txt"
        txt_path.write_text(output, encoding="utf-8")
        print(f"[audit] Resultado guardado como texto: {txt_path}")

    return True


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
    print(f"\n[webaudit] Archivos en {project_dir}:")
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
