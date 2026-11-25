#!/usr/bin/env bash
# Arranca la UI en el bastión (127.0.0.1:8765). Ctrl-C la detiene.
AQUI="$(cd "$(dirname "$0")" && pwd)"
[ -f "${DEMO_ENV:-/opt/demo-vault/env.sh}" ] && source "${DEMO_ENV:-/opt/demo-vault/env.sh}" >/dev/null
unset VAULT_TOKEN
sudo -n true 2>/dev/null || { echo "Se necesita sudo sin clave para leer el audit log"; exit 1; }
pkill -f "$AQUI/servidor.py" 2>/dev/null; sleep 0.3
exec python3 "$AQUI/servidor.py" "$@"
