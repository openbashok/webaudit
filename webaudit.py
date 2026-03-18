#!/usr/bin/env python3
"""
WebAudit — Agente autonomo de analisis de seguridad frontend.

Descarga un sitio web, analiza estaticamente su codigo JS/HTML/CSS,
y genera un informe JSON con hallazgos y codigo de instrumentacion
inyectable en la consola del navegador.
"""

import sys
import os
import json
import shutil
import argparse
import anyio
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

import yaml

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
    "work_dir": "/tmp/webaudit",
}


def load_config() -> dict:
    """Carga configuracion desde archivo YAML. Variables de entorno tienen prioridad."""
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
    """Imprime mensaje solo si debug esta activo."""
    if debug:
        print(f"[debug] {msg}", file=sys.stderr)


# --- Prompt del sistema -------------------------------------------------------

def load_system_prompt(debug: bool = False) -> str:
    """
    Construye el system prompt completo.
    Combina CLAUDE.md (contexto del proyecto) + AGENT_PROMPT.md (instrucciones del agente).
    Esto equivale a lo que Claude Code hace con /init — le da al agente el contexto
    completo del proyecto antes de ejecutar.
    """
    base_dir = Path(__file__).parent
    parts = []

    # CLAUDE.md — contexto del proyecto (equivalente a /init)
    claude_md = base_dir / "CLAUDE.md"
    if claude_md.is_file():
        dbg(f"Cargando contexto del proyecto: {claude_md}", debug)
        parts.append(f"# Contexto del proyecto\n\n{claude_md.read_text(encoding='utf-8')}")

    # AGENT_PROMPT.md — instrucciones del agente
    prompt_path = base_dir / "AGENT_PROMPT.md"
    if not prompt_path.is_file():
        print(f"Error: no se encontro {prompt_path}", file=sys.stderr)
        sys.exit(1)
    dbg(f"Cargando instrucciones del agente: {prompt_path}", debug)
    parts.append(prompt_path.read_text(encoding="utf-8"))

    return "\n\n---\n\n".join(parts)


# --- Directorio de proyecto ---------------------------------------------------

def resolve_project_dir(base_work_dir: str, url: str, output_dir: str | None, debug: bool) -> Path:
    """
    Resuelve el directorio del proyecto para esta auditoria.
    Si se pasa --output-dir, lo usa directamente.
    Si no, crea uno automatico basado en dominio + timestamp.
    """
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


# --- Health check -------------------------------------------------------------

def run_check(config: dict, debug: bool) -> bool:
    """Verifica que todo este en orden para ejecutar una auditoria."""
    ok = True

    # 1. Config file
    print("[check] Archivo de configuracion ...")
    if config["_config_file"]:
        print(f"  OK: {config['_config_file']}")
    else:
        print(f"  WARN: No se encontro archivo de config en: {', '.join(str(p) for p in CONFIG_PATHS)}")

    # 2. API key
    print("[check] API key de Anthropic ...")
    api_key = config.get("anthropic_api_key", "")
    if api_key and api_key != 'sk-ant-PONE-TU-CLAVE-ACA':
        masked = api_key[:10] + "..." + api_key[-4:]
        print(f"  OK: {masked}")
    else:
        print("  FAIL: No configurada o es el placeholder por defecto.")
        ok = False

    # 3. API connectivity
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
            print(f"  OK: API respondio (modelo: claude-haiku-4-5, tokens: {resp.usage.output_tokens})")
        except ImportError:
            print("  SKIP: anthropic SDK no instalado (no es critico, el Agent SDK lo maneja)")
        except Exception as e:
            print(f"  FAIL: {e}")
            ok = False
    else:
        print("  SKIP: No hay API key para probar.")
        ok = False

    # 4. Claude Agent SDK
    print("[check] Claude Agent SDK ...")
    try:
        from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage
        import claude_agent_sdk
        version = getattr(claude_agent_sdk, "__version__", "unknown")
        print(f"  OK: claude-agent-sdk {version}")
    except ImportError as e:
        print(f"  FAIL: {e}")
        ok = False

    # 5. System prompt files
    base_dir = Path(__file__).parent
    for fname, label in [("CLAUDE.md", "Contexto del proyecto"), ("AGENT_PROMPT.md", "Instrucciones del agente")]:
        fpath = base_dir / fname
        print(f"[check] {label} ({fname}) ...")
        if fpath.is_file():
            size = fpath.stat().st_size
            print(f"  OK: {fpath} ({size} bytes)")
        elif fname == "AGENT_PROMPT.md":
            print(f"  FAIL: No encontrado en {fpath}")
            ok = False
        else:
            print(f"  WARN: No encontrado (opcional)")

    # 6. wget
    print("[check] wget (para descarga de sitios) ...")
    if shutil.which("wget"):
        print(f"  OK: {shutil.which('wget')}")
    else:
        print("  WARN: wget no encontrado. El agente intentara alternativas.")

    # 7. Work dir
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

    # Resultado
    print()
    if ok:
        print("[check] Todo OK. Listo para auditar.")
    else:
        print("[check] Hay problemas. Revisa los FAIL de arriba.")

    return ok


# --- Ejecucion del agente ----------------------------------------------------

async def run_audit(url: str, model: str, budget: float, max_turns: int,
                    project_dir: Path, debug: bool):
    """Ejecuta el agente de auditoria contra la URL indicada."""
    from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage, SystemMessage, AssistantMessage

    system_prompt = load_system_prompt(debug)
    dbg(f"System prompt total: {len(system_prompt)} chars", debug)

    print(f"[webaudit] URL objetivo: {url}")
    print(f"[webaudit] Modelo: {model}")
    print(f"[webaudit] Budget: ${budget:.2f} | Max turns: {max_turns}")
    print(f"[webaudit] Proyecto: {project_dir}")
    print("-" * 60)

    async for message in query(
        prompt=f"Analiza el sitio: {url}",
        options=ClaudeAgentOptions(
            system_prompt=system_prompt,
            model=model,
            max_turns=max_turns,
            max_budget_usd=budget,
            allowed_tools=["Read", "Write", "Edit", "Glob", "Grep", "Bash", "WebSearch", "WebFetch"],
            permission_mode="acceptEdits",
            cwd=str(project_dir),
        ),
    ):
        # --- Modo debug: mostrar todo lo que pasa ---
        if debug:
            msg_type = type(message).__name__
            if isinstance(message, ResultMessage):
                dbg(f"ResultMessage (len={len(message.result or '')})", debug)
            elif isinstance(message, AssistantMessage):
                for block in message.content:
                    if hasattr(block, "text") and block.text:
                        dbg(f"AssistantMessage/text: {block.text[:200]}...", debug)
                    elif hasattr(block, "name"):
                        tool_input = ""
                        if hasattr(block, "input"):
                            tool_input = json.dumps(block.input, ensure_ascii=False)[:150]
                        dbg(f"ToolUse: {block.name}({tool_input})", debug)
            elif isinstance(message, SystemMessage):
                subtype = getattr(message, "subtype", "")
                dbg(f"SystemMessage subtype={subtype}", debug)
            else:
                dbg(f"{msg_type}: {str(message)[:200]}", debug)

        # --- Resultado final ---
        if isinstance(message, ResultMessage):
            print("\n" + "=" * 60)
            print("[webaudit] Analisis completo.")
            result_text = message.result

            report_path = project_dir / "webaudit_report.json"
            try:
                if report_path.is_file():
                    print(f"[webaudit] Informe guardado en: {report_path}")
                else:
                    json.loads(result_text)
                    report_path.write_text(result_text, encoding="utf-8")
                    print(f"[webaudit] Informe guardado en: {report_path}")
            except (json.JSONDecodeError, TypeError):
                txt_path = project_dir / "webaudit_report.txt"
                txt_path.write_text(result_text or "", encoding="utf-8")
                print(f"[webaudit] Resultado guardado en: {txt_path}")

            return result_text

    return None


# --- CLI ----------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="webaudit",
        description="Agente autonomo de analisis de seguridad frontend.",
    )
    sub = parser.add_subparsers(dest="command")

    # --- webaudit scan <url> ---
    scan = sub.add_parser("scan", help="Ejecutar auditoria de seguridad")
    scan.add_argument("url", help="URL del sitio a analizar")
    scan.add_argument("-m", "--model", help="Modelo de Claude")
    scan.add_argument("-b", "--budget", type=float, help="Limite de gasto en USD")
    scan.add_argument("-t", "--max-turns", type=int, help="Maximo de turnos del agente")
    scan.add_argument("-o", "--output-dir", help="Directorio de salida (default: auto)")
    scan.add_argument("-d", "--debug", action="store_true", help="Modo debug: muestra todo lo que hace el agente")

    # --- webaudit check ---
    check = sub.add_parser("check", help="Verificar salud del sistema")
    check.add_argument("-d", "--debug", action="store_true", help="Modo debug")

    return parser


def main():
    parser = build_parser()

    # Compatibilidad: si el primer arg parece URL, tratar como "scan <url>"
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

    dbg(f"Config cargada de: {config['_config_file'] or 'defaults'}", debug)

    # --- check ---
    if args.command == "check":
        success = run_check(config, debug)
        sys.exit(0 if success else 1)

    # --- scan ---
    api_key = config.get("anthropic_api_key", "")
    if not api_key or api_key == "sk-ant-PONE-TU-CLAVE-ACA":
        if not os.environ.get("ANTHROPIC_API_KEY"):
            print("Error: No se encontro ANTHROPIC_API_KEY.", file=sys.stderr)
            print("Configurala en ~/.config/webaudit/config.yaml o /etc/webaudit/config.yaml", file=sys.stderr)
            sys.exit(1)

    if api_key and not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = api_key

    url = args.url
    model = args.model or config["default_model"]
    budget = args.budget if args.budget is not None else config["default_budget_usd"]
    max_turns = args.max_turns if args.max_turns is not None else config["default_max_turns"]

    project_dir = resolve_project_dir(config["work_dir"], url, args.output_dir, debug)

    anyio.run(run_audit, url, model, budget, max_turns, project_dir, debug)


if __name__ == "__main__":
    main()
