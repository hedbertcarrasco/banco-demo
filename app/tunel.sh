#!/usr/bin/env bash
# Túnel rápido de Cloudflare hacia la UI de la demo. Desde internet solo responde /tool/*
# (protegido con la API key de ~/.idp-demo/tool.key). No toca el servicio cloudflared del sistema.
# Deja la URL pública en ~/.idp-demo/tunel.url y la imprime.
D="${IDP_DIR:-$HOME/.idp-demo}"; PUERTO=${PUERTO:-8765}
[ -f "$D/tool.key" ] || { openssl rand -hex 24 > "$D/tool.key"; chmod 600 "$D/tool.key"; }
pkill -f "cloudflared tunnel --no-autoupdate --url http://127.0.0.1:$PUERTO" 2>/dev/null; sleep 0.5
rm -f "$D/tunel.url"
setsid nohup cloudflared tunnel --no-autoupdate --url "http://127.0.0.1:$PUERTO" </dev/null > /tmp/tunel-demo.log 2>&1 &
for i in $(seq 1 30); do
  U=$(grep -o 'https://[a-z0-9-]*\.trycloudflare\.com' /tmp/tunel-demo.log | head -1)
  [ -n "$U" ] && { echo "$U" > "$D/tunel.url"; echo "$U"; exit 0; }
  sleep 1
done
echo "No salió la URL del túnel; ver /tmp/tunel-demo.log"; exit 1
