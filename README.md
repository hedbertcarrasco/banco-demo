# Banco Demo

Portal de banca en línea para demos de HashiCorp Vault e IBM Verify. La misma aplicación se usa en tres escenarios:

- **Agentic IAM:** el cliente entra con IBM Verify (passkey) y conversa con un asistente (agente de watsonx Orchestrate). Cada acción del asistente usa un token de IBM Verify por tarea (token exchange RFC 8693 con RAR), y Vault Enterprise autoriza con política de la persona ∩ techo del agente ∩ RAR.
- **Gestión de certificados (CLM):** el portal se publica detrás de un F5 BIG-IP, con certificados emitidos por Vault y renovados por Vault Agent.
- **Autoservicio con HCP Terraform:** el mismo portal es la aplicación que crea el módulo no-code.

## Estructura

| Carpeta | Contenido |
|---|---|
| `app/` | Backend (`servidor.py`, solo biblioteca estándar de Python 3.9+), portal del cliente (`portal.html`), vista del presentador (`presentador.html`) e IdP de prueba (`idp-simulado.py`) |
| `proxy/` | `portal-proxy.py`: proxy HTTP liviano para correr el portal detrás de un balanceador (por ejemplo, un EC2 en el pool del F5) |
| `vault/` | Preparación de Vault: namespace, políticas, Agent registry y perfiles OAuth (IdP simulado e IBM Verify) |
| `orchestrate/` | Agente y tools para watsonx Orchestrate |

## Rutas

| Ruta | Para qué |
|---|---|
| `/portal` | Portal del cliente: login, cuentas, movimientos y asistente |
| `/presentador` | Vista técnica: token de Verify, decisión de Vault y audit log en vivo (solo local) |
| `/login`, `/callback`, `/logout` | Login OIDC con IBM Verify (PKCE) |
| `/api/asistente` | Chat del portal hacia el agente de Orchestrate |
| `/tool/*` | Tools que llama Orchestrate (header `X-API-Key`) |
| `/salud` | Health check (en el proxy) |

## Arranque

```bash
# backend (host con acceso a Vault)
python3 app/servidor.py --puerto 8765

# proxy detrás del balanceador (HTTP :8080; el balanceador termina TLS)
PORTAL_PROXY_ENV=/etc/portal-proxy.env python3 proxy/portal-proxy.py
```

`/etc/portal-proxy.env`: `BACKEND_URL=<URL del backend>`, `PORTAL_KEY=<clave compartida>`, `PUERTO=8080`.

## Configuración y secretos

Ningún secreto va en este repositorio. El backend los lee de `~/.idp-demo/` (permisos 600):

| Archivo | Contenido |
|---|---|
| `verify.json` | `tenant`, `app_id`, `app_secret`, `sts_id`, `sts_secret`, `ana_id`, `agente_id`, `activo` |
| `tool.key` | API key de las tools de Orchestrate |
| `portal.key` | Clave compartida con el proxy del portal |
| `wxo.key` | API key de IBM Cloud para watsonx Orchestrate |

Variables de entorno: `VAULT_ADDR`, `VAULT_CACERT`, `VAULT_AUDIT_LOG`, `IDP_DIR`, `VERIFY_REDIRECT`, `WXO_URL`, `WXO_AGENT_ID`, `MODO_IDP=simulado` (usa el IdP de prueba en vez de IBM Verify).

## IBM Verify

- Aplicación OIDC con access token JWT, PKCE y client credentials. Redirect URI: `https://<host del portal>/callback`.
- Tipo de authorization details `vault:path_access`.
- STS client con token exchange (subject y actor: access token), access token JWT de 300 s y mapeo de introspección `actor-token` = `{"sub":requestContext["actor_token"].sub}`.
- Guía de referencia: developer.hashicorp.com/vault/ai/iam/providers/verify
