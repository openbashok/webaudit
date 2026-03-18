#!/usr/bin/env bash
#
# install.sh — Instalador de WebAudit
#
# Uso:
#   sudo bash -c "$(curl -sL https://raw.githubusercontent.com/openbashok/webaudit/main/install.sh)"
#   o bien: sudo ./install.sh
#
# Con sudo: /opt/webaudit para todos los usuarios.
# Sin sudo: ~/.local/share/webaudit solo para el usuario actual.
#
# Crea un virtualenv interno para las dependencias Python (compatible PEP 668).
#
set -euo pipefail

REPO="openbashok/webaudit"

# --- Detectar si tenemos root ------------------------------------------------
if [ "$(id -u)" -eq 0 ]; then
    MODE="system"
    INSTALL_DIR="${WEBAUDIT_INSTALL_DIR:-/opt/webaudit}"
    BIN_LINK="/usr/local/bin/webaudit"
    CONFIG_DIR="/etc/webaudit"
else
    MODE="user"
    INSTALL_DIR="${WEBAUDIT_INSTALL_DIR:-${HOME}/.local/share/webaudit}"
    BIN_LINK="${HOME}/.local/bin/webaudit"
    CONFIG_DIR="${HOME}/.config/webaudit"
fi

VENV_DIR="${INSTALL_DIR}/.venv"

echo "=== WebAudit Installer ==="
echo "Modo: ${MODE} (instalando en ${INSTALL_DIR})"

# --- Dependencias del sistema -------------------------------------------------
command -v python3 >/dev/null 2>&1 || { echo "Error: python3 no encontrado."; exit 1; }
command -v git     >/dev/null 2>&1 || { echo "Error: git no encontrado."; exit 1; }
command -v wget    >/dev/null 2>&1 || echo "Aviso: wget no encontrado. El agente lo necesita para descargar sitios."

# Verificar que python3-venv este disponible
python3 -m venv --help >/dev/null 2>&1 || {
    echo "Error: python3-venv no disponible."
    echo "Instala con: apt install python3-venv"
    exit 1
}

# --- Clonar o actualizar repositorio -----------------------------------------
if [ -d "$INSTALL_DIR" ]; then
    echo "Actualizando instalacion existente en $INSTALL_DIR ..."
    git -C "$INSTALL_DIR" pull --ff-only
else
    echo "Clonando repositorio en $INSTALL_DIR ..."
    mkdir -p "$(dirname "$INSTALL_DIR")"
    git clone "https://github.com/${REPO}.git" "$INSTALL_DIR"
fi

# --- Crear/actualizar virtualenv ---------------------------------------------
if [ ! -d "$VENV_DIR" ]; then
    echo "Creando virtualenv en $VENV_DIR ..."
    python3 -m venv "$VENV_DIR"
fi

echo "Instalando dependencias Python en virtualenv ..."
"${VENV_DIR}/bin/pip" install --upgrade pip -q
"${VENV_DIR}/bin/pip" install --upgrade -r "${INSTALL_DIR}/requirements.txt"

# --- Crear wrapper script que usa el venv ------------------------------------
WRAPPER="${INSTALL_DIR}/webaudit"
cat > "$WRAPPER" <<SCRIPT
#!/usr/bin/env bash
exec "${VENV_DIR}/bin/python3" "${INSTALL_DIR}/webaudit.py" "\$@"
SCRIPT
chmod +x "$WRAPPER"

# --- Crear symlink al wrapper -------------------------------------------------
mkdir -p "$(dirname "$BIN_LINK")"
ln -sf "$WRAPPER" "$BIN_LINK"
echo "Enlace: $BIN_LINK -> $WRAPPER"

# --- Verificar PATH (solo modo usuario) --------------------------------------
if [ "$MODE" = "user" ]; then
    BIN_DIR="$(dirname "$BIN_LINK")"
    if ! echo "$PATH" | tr ':' '\n' | grep -qx "$BIN_DIR"; then
        echo ""
        echo "IMPORTANTE: $BIN_DIR no esta en tu PATH."
        echo "Agrega esto a tu ~/.bashrc o ~/.zshrc:"
        echo ""
        echo "  export PATH=\"\$HOME/.local/bin:\$PATH\""
        echo ""
    fi
fi

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
# work_dir: por defecto usa ~/webaudit (del usuario que ejecuta)
# work_dir: "/tmp/webaudit"
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
