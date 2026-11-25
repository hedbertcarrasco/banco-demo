#!/usr/bin/env bash
# Crea (o actualiza) en watsonx Orchestrate el tool OpenAPI y el agente de la demo.
# Correr en el bastión DESPUÉS de ui/tunel.sh (usa la URL pública que deja en ~/.idp-demo/tunel.url).
# Pide la API key de IBM Cloud por teclado (no se guarda en archivos de la demo).
set -euo pipefail
AQUI="$(cd "$(dirname "$0")" && pwd)"
O=~/orchestrate-adk/bin/orchestrate
D="${IDP_DIR:-$HOME/.idp-demo}"
WXO_URL="${WXO_URL:-https://api.<region>.watson-orchestrate.cloud.ibm.com/instances/<instancia>}"
TUNEL="$(cat "$D/tunel.url")"
[ -n "${WXO_API_KEY:-}" ] || [ ! -f "$D/wxo.key" ] || WXO_API_KEY="$(cat "$D/wxo.key")"
[ -n "${WXO_API_KEY:-}" ] || { read -r -s -p "API key de IBM Cloud (watsonx Orchestrate): " WXO_API_KEY; echo; }

$O env add -n demo-agentic -u "$WXO_URL" -t ibm_iam >/dev/null 2>&1 || true
$O env activate demo-agentic --api-key "$WXO_API_KEY"

echo "== Conexión con la API key del tool"
$O connections add -a vault_banca >/dev/null 2>&1 || true
for e in draft live; do
  $O connections configure -a vault_banca --env $e --type team --kind api_key --url "$TUNEL"
  $O connections set-credentials -a vault_banca --env $e --api-key "$(cat "$D/tool.key")"
done

echo "== Tool OpenAPI ($TUNEL)"
curl -sf "http://127.0.0.1:8765/tool/openapi.json" -H "X-Forwarded-Proto: https" -H "Host: ${TUNEL#https://}" > /tmp/openapi-vault-banca.json
$O tools import -k openapi -f /tmp/openapi-vault-banca.json -a vault_banca

echo "== Agente"
$O agents import -f "$AQUI/agente.yaml"
$O agents deploy -n asistente_banca_vault || true
echo "Listo. Abre https://au-syd.watson-orchestrate.cloud.ibm.com/chat y elige «Asistente Banca (Vault Agentic IAM)»."
