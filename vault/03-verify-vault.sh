#!/usr/bin/env bash
# Hace que Vault (namespace demo/agentes) confíe en los tokens de IBM Verify.
# Requiere ~/.idp-demo/verify.json con tenant, ana_id y agente_id (IDs de usuario de Verify)
# y un token de administración en VAULT_TOKEN o en ~/.idp-demo/admin.token.
# No toca el perfil idp-demo (IdP simulado), que queda de respaldo.
set -euo pipefail
D="${IDP_DIR:-$HOME/.idp-demo}"
[ -f "${DEMO_ENV:-/opt/demo-vault/env.sh}" ] && source "${DEMO_ENV:-/opt/demo-vault/env.sh}" >/dev/null
export VAULT_NAMESPACE="demo/agentes"
[ -n "${VAULT_TOKEN:-}" ] || export VAULT_TOKEN="$(cat "$D/admin.token")"
TENANT=$(jq -r .tenant "$D/verify.json")
ANA_ID=$(jq -r .ana_id "$D/verify.json")
AGENTE_ID=$(jq -r .agente_id "$D/verify.json")
ISSUER="$TENANT/oauth2"

echo "== Perfil OAuth resource server 'verify' ($ISSUER)"
jq -n --arg iss "$ISSUER" --arg jwks "$TENANT/oauth2/jwks" '{
  issuer_id: $iss, use_jwks: true, jwks_uri: $jwks,
  user_claim: "sub", actor_claim: "actor-token.sub",
  authorization_details_claim: "authorization_details",
  supported_algorithms: ["RS256"], jwt_type: "access_token", clock_skew_leeway: 30
}' | vault write sys/config/oauth-resource-server/verify - >/dev/null
vault read sys/config/oauth-resource-server/verify

echo "== Alias de Verify para ana y asistente-banca"
for par in "ana:$ANA_ID" "asistente-banca:$AGENTE_ID"; do
  nombre="${par%%:*}"; ext="${par#*:}"
  id="$(vault read -field=id identity/entity/name/$nombre)"
  vault write identity/entity-alias name="verify-$nombre" canonical_id="$id" \
    issuer="$ISSUER" external_id="$ext" >/dev/null 2>&1 \
    && echo "   alias verify-$nombre -> $ext" \
    || echo "   (alias de $nombre con $ext ya existía o falló; revisar)"
done
echo "Listo."
