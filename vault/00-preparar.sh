#!/usr/bin/env bash
# Prepara la demo de Agentic IAM en el namespace demo/agentes.
# Requiere: licencia con el módulo agentic-iam, Vault Enterprise 2.2+, un token con
# permisos de administración sobre el namespace "demo" (VAULT_TOKEN), y openssl + python3.
# Se puede correr varias veces: lo que ya existe se sobrescribe con los mismos valores.
set -euo pipefail

AQUI="$(cd "$(dirname "$0")" && pwd)"
: "${VAULT_ADDR:?Falta VAULT_ADDR (o el archivo de entorno de tu ambiente)}"
: "${VAULT_TOKEN:?Falta VAULT_TOKEN de administración}"
export IDP_ISSUER="${IDP_ISSUER:-https://idp-demo.lab.local}"
export IDP_AUDIENCE="${IDP_AUDIENCE:-https://127.0.0.1:8200/v1}"
NS_PADRE="demo"
NS="demo/agentes"

echo "== Licencia"
curl -s ${VAULT_CACERT:+--cacert "$VAULT_CACERT"} "$VAULT_ADDR/v1/sys/license/features" \
  | python3 -c 'import sys,json; f=json.load(sys.stdin)["features"]; print("Agentic IAM presente" if "Agentic IAM" in f else sys.exit("La licencia no trae Agentic IAM"))'

echo "== Namespace $NS"
VAULT_NAMESPACE="$NS_PADRE" vault namespace create agentes >/dev/null 2>&1 || true
export VAULT_NAMESPACE="$NS"

echo "== Motor KV y secretos de ejemplo"
vault secrets enable -path=banca kv-v2 >/dev/null 2>&1 || true
vault kv put -mount=banca canales/api-cuentas api_key="demo-cuentas-$(openssl rand -hex 6)" proveedor="core-canales" >/dev/null
vault kv put -mount=banca canales/api-transferencias api_key="demo-transf-$(openssl rand -hex 6)" limite_diario_usd="5000" >/dev/null
vault kv put -mount=banca core/db-admin usuario="dba_core" password="demo-$(openssl rand -hex 8)" >/dev/null

echo "== Políticas"
vault policy write ana-ejecutiva - <<'EOF'
# Lo que Ana puede hacer por sí misma
path "banca/data/*"     { capabilities = ["create", "read", "update", "delete", "list"] }
path "banca/metadata/*" { capabilities = ["read", "list"] }
EOF
vault policy write techo-asistente-banca - <<'EOF'
# Lo máximo que puede hacer el asistente, actúe en nombre de quien actúe
path "banca/data/canales/*" { capabilities = ["read"] }
EOF

echo "== Llave del emisor de tokens de prueba"
PUB_PEM="$(python3 "$AQUI/../app/idp-simulado.py" iniciar)"

echo "== Perfil OAuth resource server (llave estática)"
python3 - "$PUB_PEM" > /tmp/perfil-idp-demo.json <<'EOF'
import json, os, sys
print(json.dumps({
  "issuer_id": os.environ["IDP_ISSUER"],
  "use_jwks": False,
  "public_keys": [{"key_id": "idp-demo-1", "pem": sys.argv[1]}],
  "audiences": [os.environ["IDP_AUDIENCE"]],
  "supported_algorithms": ["RS256"],
  "jwt_type": "access_token",
  "user_claim": "sub",
  "actor_claim": "act.sub",
  "authorization_details_claim": "authorization_details",
  "clock_skew_leeway": 30,
}))
EOF
vault write sys/config/oauth-resource-server/idp-demo @/tmp/perfil-idp-demo.json >/dev/null
rm -f /tmp/perfil-idp-demo.json

echo "== Entidades y alias"
vault write identity/entity name=ana policies=ana-ejecutiva >/dev/null
vault write identity/entity name=asistente-banca >/dev/null
ANA_ID="$(vault read -field=id identity/entity/name/ana)"
AGENTE_ID="$(vault read -field=id identity/entity/name/asistente-banca)"
for par in "ana:$ANA_ID" "asistente-banca:$AGENTE_ID"; do
  nombre="${par%%:*}"; id="${par#*:}"
  vault write identity/entity-alias name="$nombre" canonical_id="$id" \
    issuer="$IDP_ISSUER" external_id="$nombre" >/dev/null 2>&1 \
    || echo "   (alias de $nombre ya existía)"
done

echo "== Usuario userpass para Ana (para mostrar su acceso sin agente)"
vault auth enable userpass >/dev/null 2>&1 || true
PASS_FILE="${IDP_DIR:-$HOME/.idp-demo}/ana.pass"
[ -f "$PASS_FILE" ] || { openssl rand -base64 18 > "$PASS_FILE"; chmod 600 "$PASS_FILE"; }
vault write auth/userpass/users/ana password="$(cat "$PASS_FILE")" >/dev/null
UP_ACC="$(vault auth list -format=json | python3 -c 'import sys,json; print(json.load(sys.stdin)["userpass/"]["accessor"])')"
vault write identity/entity-alias name=ana canonical_id="$ANA_ID" mount_accessor="$UP_ACC" >/dev/null 2>&1 || true

echo "== Registro del agente"
vault write agent-registry/register display_name=asistente-banca entity_id="$AGENTE_ID" \
  description="Asistente bancario que actúa en nombre de ejecutivos" \
  ceiling_policies=techo-asistente-banca >/dev/null 2>&1 || echo "   (el agente ya estaba registrado)"
vault read agent-registry/registration/display-name/asistente-banca

echo
echo "Listo. Siguiente paso: bash $AQUI/01-demo.sh"
