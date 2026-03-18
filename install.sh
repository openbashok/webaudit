#!/usr/bin/env bash
#
# install.sh — Instalador de WebAudit
#
# Uso:
#   curl -sL <raw-url-de-install.sh> | bash
#   o bien: ./install.sh
#
set -euo pipefail

REPO="openbashok/webaudit"
INSTALL_DIR="${WEBAUDIT_INSTALL_DIR:-/usr/local/share/webaudit}"
BIN_LINK="/usr/local/bin/webaudit"
CONFIG_DIR="${HOME}/.config/webaudit"

echo "=== WebAudit Installer ==="

# --- Dependencias del sistema -------------------------------------------------
command -v python3 >/dev/null 2>&1 || { echo "Error: python3 no encontrado."; exit 1; }
command -v git     >/dev/null 2>&1 || { echo "Error: git no encontrado."; exit 1; }
command -v pip3    >/dev/null 2>&1 || { echo "Error: pip3 no encontrado."; exit 1; }
command -v wget    >/dev/null 2>&1 || echo "Aviso: wget no encontrado. El agente lo necesita para descargar sitios."

# --- Clonar o actualizar repositorio -----------------------------------------
if [ -d "$INSTALL_DIR" ]; then
    echo "Actualizando instalacion existente en $INSTALL_DIR ..."
    git -C "$INSTALL_DIR" pull --ff-only
else
    echo "Clonando repositorio en $INSTALL_DIR ..."
    sudo mkdir -p "$(dirname "$INSTALL_DIR")"
    sudo git clone "https://github.com/${REPO}.git" "$INSTALL_DIR"
    sudo chown -R "$(whoami)" "$INSTALL_DIR"
fi

# --- Instalar dependencias Python --------------------------------------------
echo "Instalando dependencias Python ..."
pip3 install --upgrade -r "${INSTALL_DIR}/requirements.txt"

# --- Crear symlink al binario -------------------------------------------------
echo "Creando enlace simbolico: $BIN_LINK -> ${INSTALL_DIR}/webaudit.py"
sudo ln -sf "${INSTALL_DIR}/webaudit.py" "$BIN_LINK"
sudo chmod +x "${INSTALL_DIR}/webaudit.py"

# --- Crear archivo de configuracion si no existe ------------------------------
mkdir -p "$CONFIG_DIR"
if [ ! -f "${CONFIG_DIR}/config.yaml" ]; then
    cat > "${CONFIG_DIR}/config.yaml" <<'YAML'
# WebAudit - Configuracion
# Tambien se puede usar la variable de entorno ANTHROPIC_API_KEY

anthropic_api_key: "sk-ant-PONE-TU-CLAVE-ACA"
default_model: "claude-sonnet-4-6"
default_budget_usd: 5.0
default_max_turns: 50
work_dir: "/tmp/webaudit"
YAML
    echo "Archivo de configuracion creado en ${CONFIG_DIR}/config.yaml"
    echo ">>> Edita ese archivo y pone tu API key de Anthropic. <<<"
else
    echo "Configuracion existente en ${CONFIG_DIR}/config.yaml (no se modifico)."
fi

echo ""
echo "=== Instalacion completa ==="
echo "Uso:  webaudit https://sitio-objetivo.com"
echo "      webaudit https://sitio-objetivo.com claude-opus-4-6 15.0"
