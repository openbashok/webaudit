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
import anyio
from pathlib import Path

import yaml
from claude_agent_sdk import query, ClaudeAgentOptions, ResultMessage

# --- Configuracion -----------------------------------------------------------

CONFIG_PATHS = [
    Path("/etc/webaudit/config.yaml"),
    Path.home() / ".config" / "webaudit" / "config.yaml",
]


def load_config() -> dict:
    """Carga configuracion desde archivo YAML. Variables de entorno tienen prioridad."""
    config = {
        "anthropic_api_key": "",
        "default_model": "claude-sonnet-4-6",
        "default_budget_usd": 5.0,
        "default_max_turns": 50,
        "work_dir": "/tmp/webaudit",
    }
    for path in CONFIG_PATHS:
        if path.is_file():
            with open(path) as f:
                file_config = yaml.safe_load(f) or {}
            config.update({k: v for k, v in file_config.items() if v is not None})
            break

    # Variables de entorno sobreescriben el archivo
    if os.environ.get("ANTHROPIC_API_KEY"):
        config["anthropic_api_key"] = os.environ["ANTHROPIC_API_KEY"]

    return config


# --- Prompt del sistema -------------------------------------------------------

def load_system_prompt() -> str:
    """Lee AGENT_PROMPT.md desde el mismo directorio que este script."""
    prompt_path = Path(__file__).parent / "AGENT_PROMPT.md"
    if not prompt_path.is_file():
        print(f"Error: no se encontro {prompt_path}", file=sys.stderr)
        sys.exit(1)
    return prompt_path.read_text(encoding="utf-8")


# --- Ejecucion del agente ----------------------------------------------------

async def run_audit(url: str, model: str, budget: float, max_turns: int, work_dir: str):
    """Ejecuta el agente de auditoria contra la URL indicada."""
    system_prompt = load_system_prompt()

    # Crear directorio de trabajo
    os.makedirs(work_dir, exist_ok=True)

    print(f"[webaudit] URL objetivo: {url}")
    print(f"[webaudit] Modelo: {model}")
    print(f"[webaudit] Budget: ${budget:.2f} | Max turns: {max_turns}")
    print(f"[webaudit] Directorio de trabajo: {work_dir}")
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
            cwd=work_dir,
        ),
    ):
        if isinstance(message, ResultMessage):
            print("\n" + "=" * 60)
            print("[webaudit] Analisis completo.")
            result_text = message.result

            # Intentar extraer JSON del resultado
            report_path = Path(work_dir) / "webaudit_report.json"
            try:
                # El agente deberia haber guardado el JSON con Write,
                # pero si lo devolvio como texto intentamos parsearlo
                if report_path.is_file():
                    print(f"[webaudit] Informe guardado en: {report_path}")
                else:
                    # Intentar extraer JSON del texto de resultado
                    json.loads(result_text)
                    report_path.write_text(result_text, encoding="utf-8")
                    print(f"[webaudit] Informe guardado en: {report_path}")
            except (json.JSONDecodeError, TypeError):
                # No es JSON puro, guardar como texto
                txt_path = Path(work_dir) / "webaudit_report.txt"
                txt_path.write_text(result_text or "", encoding="utf-8")
                print(f"[webaudit] Resultado guardado en: {txt_path}")

            return result_text

    return None


# --- CLI ----------------------------------------------------------------------

def main():
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print("Uso: webaudit.py <url> [modelo] [budget_usd] [max_turns]")
        print()
        print("  url         URL del sitio a analizar")
        print("  modelo      Modelo de Claude (default: config o claude-sonnet-4-6)")
        print("  budget_usd  Limite de gasto en USD (default: config o 5.0)")
        print("  max_turns   Maximo de turnos del agente (default: config o 50)")
        print()
        print("Configuracion: ~/.config/webaudit/config.yaml o /etc/webaudit/config.yaml")
        print("Variable de entorno: ANTHROPIC_API_KEY")
        sys.exit(0)

    config = load_config()

    if not config["anthropic_api_key"] and not os.environ.get("ANTHROPIC_API_KEY"):
        print("Error: No se encontro ANTHROPIC_API_KEY.", file=sys.stderr)
        print("Configurala en ~/.config/webaudit/config.yaml o como variable de entorno.", file=sys.stderr)
        sys.exit(1)

    # Si la clave viene del config, setearla como variable de entorno
    # para que el Agent SDK la encuentre
    if config["anthropic_api_key"] and not os.environ.get("ANTHROPIC_API_KEY"):
        os.environ["ANTHROPIC_API_KEY"] = config["anthropic_api_key"]

    url = sys.argv[1]
    model = sys.argv[2] if len(sys.argv) > 2 else config["default_model"]
    budget = float(sys.argv[3]) if len(sys.argv) > 3 else config["default_budget_usd"]
    max_turns = int(sys.argv[4]) if len(sys.argv) > 4 else config["default_max_turns"]
    work_dir = config["work_dir"]

    anyio.run(run_audit, url, model, budget, max_turns, work_dir)


if __name__ == "__main__":
    main()
