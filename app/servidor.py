#!/usr/bin/env python3
"""UI web de la demo de Vault Agentic IAM (asistente bancario).

Corre en el bastión, solo en 127.0.0.1. Cada mensaje del chat:
  1. pide al IdP simulado un token (sub=ana, act.sub=asistente-banca, RAR de la tarea),
  2. llama a la API HTTP de Vault con ese token en el namespace demo/agentes,
  3. muestra la decisión de Vault y la entrada del audit log que generó (por jti).

No usa tokens de administración. Solo biblioteca estándar de Python.

Uso:  python3 servidor.py [--puerto 8765]
"""
import argparse
import base64
import json
import os
import queue
import re
import ssl
import subprocess
import sys
import threading
import time
import unicodedata
import hashlib
import secrets
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

AQUI = os.path.dirname(os.path.abspath(__file__))
RAIZ = os.path.dirname(AQUI)
IDP = os.path.join(AQUI, "idp-simulado.py")
VAULT_ADDR = os.environ.get("VAULT_ADDR", "https://127.0.0.1:8200")
VAULT_CACERT = os.environ.get("VAULT_CACERT", "/etc/vault/ca.pem")
NS = "demo/agentes"
AUDIT = os.environ.get("VAULT_AUDIT_LOG", "/var/log/vault/audit.log")
ANA_PASS = os.path.join(os.environ.get("IDP_DIR", os.path.expanduser("~/.idp-demo")), "ana.pass")

CTX = ssl.create_default_context(cafile=VAULT_CACERT if os.path.exists(VAULT_CACERT) else None)

# Lo configurado por 00-preparar.sh (para la tarjeta del registro y la evaluación ilustrativa).
REGISTRO = {
    "display_name": "asistente-banca",
    "descripcion": "Asistente bancario que actúa en nombre de ejecutivos",
    "ceiling_policies": ["techo-asistente-banca"],
    "techo": 'path "banca/data/canales/*" { capabilities = ["read"] }',
    "persona": "ana",
    "politica_persona": 'path "banca/data/*" { capabilities = ["create","read","update","delete","list"] }',
}
_reg_file = os.path.join(AQUI, "registro.json")
if os.path.exists(_reg_file):
    try:
        REGISTRO.update(json.load(open(_reg_file)))
    except Exception:
        pass

ESTADO = {"ultimo_token": None, "ultimo_rar": None, "ultimo_exp": 0}


# ---------------------------------------------------------------- utilidades
def unb64(t):
    return base64.urlsafe_b64decode(t + "=" * (-len(t) % 4))


def emitir_simulado(ruta, cap, ttl=300):
    t = subprocess.run([sys.executable, IDP, "emitir", "--sub", "ana", "--actor", "asistente-banca",
                        "--ruta", ruta, "--cap", cap, "--ttl", str(ttl)],
                       capture_output=True, text=True, check=True).stdout.strip()
    h, c, _ = t.split(".")
    return t, json.loads(unb64(h)), json.loads(unb64(c))


def vault(metodo, ruta, token=None, cuerpo=None, ns=True):
    url = f"{VAULT_ADDR}/v1/{ruta}"
    data = json.dumps(cuerpo).encode() if cuerpo is not None else None
    req = urllib.request.Request(url, data=data, method=metodo)
    if ns:
        req.add_header("X-Vault-Namespace", NS)
    if token:
        req.add_header("X-Vault-Token", token)
    if data:
        req.add_header("Content-Type", "application/json")
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, context=CTX, timeout=10) as r:
            status, body = r.status, r.read()
    except urllib.error.HTTPError as e:
        status, body = e.code, e.read()
    ms = int((time.time() - t0) * 1000)
    try:
        j = json.loads(body) if body else {}
    except ValueError:
        j = {"raw": body.decode(errors="replace")}
    return status, j, ms


def enmascarar(v):
    v = str(v)
    return v[:6] + "•" * 8 if len(v) > 6 else "•" * 8


def gates_locales(ruta, cap, rar_ruta, rar_cap):
    """Evaluación ilustrativa de las 3 compuertas; el veredicto real es el de Vault."""
    ana = ruta.startswith("banca/data/")
    techo = ruta.startswith("banca/data/canales/") and cap == "read"
    rar = (ruta == rar_ruta) and (cap in rar_cap)
    return {"persona": ana, "techo": techo, "rar": rar}


def compuertas(status, errores, ruta, cap, rar_ruta, rar_cap):
    g = gates_locales(ruta, cap, rar_ruta, rar_cap)
    texto = " ".join(errores)
    out = {
        "persona": {"ok": g["persona"], "nota": "política ana-ejecutiva"},
        "techo": {"ok": g["techo"], "nota": "techo-asistente-banca"},
        "rar": {"ok": g["rar"], "nota": "authorization_details del token"},
    }
    if status < 300:
        for k in out:
            out[k]["ok"] = True
            out[k]["vault"] = True
    elif "CEILING_POLICY_DENIED" in texto:
        out["techo"]["ok"] = False
        out["techo"]["vault"] = True
    elif "RAR_NO_MATCH" in texto:
        out["rar"]["ok"] = False
        out["rar"]["vault"] = True
    else:
        out["persona"]["ok"] = False
        out["persona"]["vault"] = True
    return out


def codigo_error(errores):
    m = re.search(r"\b([A-Z]+(?:_[A-Z]+)+):", " ".join(errores))
    if m:
        return m.group(1)
    return "PERMISSION_DENIED" if errores else ""


# ---------------------------------------------------------------- IBM Verify (modo real)
# ~/.idp-demo/verify.json: {"tenant": "https://x.verify.ibm.com", "app_id", "app_secret", "sts_id", "sts_secret",
#                           "agente_usuario", "agente_password", "ana_usuario", "ana_password" (respaldo ROPC)}
VERIFY_CFG = os.path.join(os.environ.get("IDP_DIR", os.path.expanduser("~/.idp-demo")), "verify.json")
VERIFY = {"ana": None, "ana_refresh": None, "ana_exp": 0, "agente": None, "agente_exp": 0, "pkce": {}, "revocada": False}
try:
    VERIFY["ana_refresh"] = open(os.path.join(os.path.dirname(VERIFY_CFG), "ana.refresh")).read().strip() or None
except OSError:
    pass
REDIRECT = os.environ.get("VERIFY_REDIRECT", "http://localhost:8765/callback")


def verify_cfg():
    try:
        return json.load(open(VERIFY_CFG))
    except (OSError, ValueError):
        return None


def modo():
    if os.environ.get("MODO_IDP") == "simulado":
        return "simulado"
    cfg = verify_cfg()
    return "verify" if cfg and cfg.get("activo") else "simulado"


def verify_token(datos, auth=None):
    cfg = verify_cfg()
    req = urllib.request.Request(cfg["tenant"] + "/oauth2/token", data=urllib.parse.urlencode(datos).encode(), method="POST")
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("Accept", "application/json")
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{auth[0]}:{auth[1]}".encode()).decode())
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            j = json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Verify {e.code}: {e.read().decode(errors='replace')[:300]}")
    j["_ms"] = int((time.time() - t0) * 1000)
    return j


def claims_de(tok):
    p = tok.split(".")
    return json.loads(unb64(p[0])), json.loads(unb64(p[1]))


def token_agente():
    if VERIFY["agente"] and VERIFY["agente_exp"] > time.time() + 30:
        return VERIFY["agente"]
    cfg = verify_cfg()
    # El agente se autentica con su propia identidad de máquina (client credentials de la app del asistente)
    j = verify_token({"grant_type": "client_credentials", "scope": "openid"}, (cfg["app_id"], cfg["app_secret"]))
    VERIFY["agente"] = j["access_token"]
    VERIFY["agente_exp"] = claims_de(j["access_token"])[1].get("exp", time.time() + 600)
    return VERIFY["agente"]


def verify_revocar():
    """Revoca en IBM Verify el refresh token y el access token de la persona (RFC 7009)."""
    cfg = verify_cfg()
    res = []
    for tok, hint in ((VERIFY["ana_refresh"], "refresh_token"), (VERIFY["ana"], "access_token")):
        if not tok:
            continue
        req = urllib.request.Request(cfg["tenant"] + "/oauth2/revoke", method="POST",
                                     data=urllib.parse.urlencode({"token": tok, "token_type_hint": hint}).encode())
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{cfg['app_id']}:{cfg['app_secret']}".encode()).decode())
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                res.append((hint, r.status))
        except urllib.error.HTTPError as e:
            res.append((hint, e.code))
    VERIFY.update(ana_refresh=None, revocada=True, agente=None, agente_exp=0)
    ESTADO.update(ultimo_token=None, ultimo_rar=None, ultimo_exp=0)
    try:
        os.remove(os.path.join(os.path.dirname(VERIFY_CFG), "ana.refresh"))
    except OSError:
        pass
    return res


def token_ana():
    cfg = verify_cfg()
    if VERIFY["revocada"] and VERIFY["ana"]:
        return VERIFY["ana"]  # se intenta igual: Verify debe rechazar el exchange
    if VERIFY["ana"] and VERIFY["ana_exp"] > time.time() + 30:
        return VERIFY["ana"]
    if VERIFY["ana_refresh"]:
        try:
            j = verify_token({"grant_type": "refresh_token", "refresh_token": VERIFY["ana_refresh"]},
                             (cfg["app_id"], cfg["app_secret"]))
            guardar_ana(j)
            return VERIFY["ana"]
        except RuntimeError:
            pass
    if cfg.get("ana_password"):  # respaldo sin navegador
        j = verify_token({"grant_type": "password", "username": cfg["ana_usuario"], "password": cfg["ana_password"],
                          "scope": "openid profile email"}, (cfg["app_id"], cfg["app_secret"]))
        guardar_ana(j)
        return VERIFY["ana"]
    raise RuntimeError("Ana no ha iniciado sesión en IBM Verify (botón «Iniciar sesión con IBM Verify»)")


def guardar_ana(j):
    VERIFY["revocada"] = False
    VERIFY["ana"] = j["access_token"]
    VERIFY["ana_refresh"] = j.get("refresh_token") or VERIFY["ana_refresh"]
    try:  # para que un reinicio del servidor no obligue a volver a iniciar sesión
        f = os.path.join(os.path.dirname(VERIFY_CFG), "ana.refresh")
        with open(os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as fh:
            fh.write(VERIFY["ana_refresh"] or "")
    except OSError:
        pass
    VERIFY["ana_exp"] = claims_de(j["access_token"])[1].get("exp", time.time() + 600)


def emitir_verify(ruta, cap, ttl=None):
    cfg = verify_cfg()
    rar = [{"type": "vault:path_access", "path": ruta, "capabilities": [cap]}]
    j = verify_token({
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "subject_token": token_ana(), "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "actor_token": token_agente(), "actor_token_type": "urn:ietf:params:oauth:token-type:access_token",
        "client_id": cfg["sts_id"], "client_secret": cfg["sts_secret"],
        "authorization_details": json.dumps(rar),
    })
    t = j["access_token"]
    h, c = claims_de(t)
    c.setdefault("_exchange_ms", j["_ms"])
    if actor_de(c) == cfg.get("agente_id"):
        c["_actor_nombre"] = "asistente-banca"
    return t, h, c


def emitir(ruta, cap, ttl=300):
    return emitir_verify(ruta, cap) if modo() == "verify" else emitir_simulado(ruta, cap, ttl)


def rar_de(c):
    ad = c.get("authorization_details") or []
    return ad[0] if ad else {"path": "", "capabilities": []}


def actor_de(c):
    return (c.get("act") or {}).get("sub") or (c.get("actor-token") or {}).get("sub")


# ---------------------------------------------------------------- intenciones
def normal(s):
    s = unicodedata.normalize("NFD", s.lower())
    return "".join(c for c in s if unicodedata.category(c) != "Mn")


def intencion(texto):
    t = normal(texto)
    if re.search(r"sin (el )?agente|ana directo|como ana|ana sola|login de ana", t):
        return "ana"
    if re.search(r"mismo token|ese token|token anterior|reus|reutiliz|aprovech", t):
        return "reuso"
    if re.search(r"\bcore\b|dba|base de datos|contrasen|password|clave del", t):
        return "core"
    if re.search(r"\btransfier|\btransferir|\btransferi\b|envia(le)? \$|pagale|deposita", t):
        return "transferir"
    if re.search(r"rota|rotar|cambia|actualiza|modifica|reemplaza|escrib|nueva api key|nueva key", t):
        return "escribir"
    if re.search(r"transfer|limite", t):
        return "transferencias"
    if re.search(r"cuenta|proveedor|api key|api de", t):
        return "cuentas"
    return "ayuda"


def accion_agente(intent, texto, ruta_cap=None):
    """Ejecuta la tarea como lo haría el agente y devuelve los pasos para la UI."""
    pasos = []
    if intent == "ayuda":
        return {
            "respuesta": "Soy el asistente de banca. Puedo consultar las APIs de canales en Vault por ti. "
                         "Prueba: «¿Qué proveedor usa la API de cuentas?» o «¿Cuál es el límite diario de transferencias?»",
            "pasos": [], "veredicto": None,
        }

    if intent == "ana":
        try:
            pw = open(ANA_PASS).read().strip()
        except OSError:
            return {"respuesta": "No encuentro la clave de Ana en el bastión (~/.idp-demo/ana.pass).", "pasos": []}
        st, j, ms = vault("POST", "auth/userpass/login/ana", cuerpo={"password": pw})
        tok = (j.get("auth") or {}).get("client_token")
        pasos.append({"tipo": "login", "metodo": "POST", "ruta": "auth/userpass/login/ana", "status": st, "ms": ms,
                      "politicas": (j.get("auth") or {}).get("policies", []), "ttl": (j.get("auth") or {}).get("lease_duration")})
        ruta, cap = "banca/data/core/db-admin", "read"
        st, j, ms = vault("GET", ruta, tok)
        datos = ((j.get("data") or {}).get("data") or {})
        pasos.append({"tipo": "vault", "metodo": "GET", "ruta": ruta, "op": cap, "status": st, "ms": ms,
                      "errores": j.get("errors", []), "codigo": codigo_error(j.get("errors", [])),
                      "datos": {"usuario": datos.get("usuario"), "password": enmascarar(datos.get("password", ""))} if datos else None,
                      "compuertas": {"persona": {"ok": st < 300, "vault": True, "nota": "política ana-ejecutiva"},
                                     "techo": {"ok": None, "nota": "no aplica: no hay agente"},
                                     "rar": {"ok": None, "nota": "no aplica: token de userpass"}}})
        resp = (f"Ana, iniciando sesión ella misma (sin agente), sí puede leer la credencial del core: usuario «{datos.get('usuario')}»."
                " El límite era del agente, no de la persona.") if st < 300 else f"Vault respondió {st}."
        return {"respuesta": resp, "pasos": pasos, "veredicto": st < 300, "actor": "ana"}

    if intent == "reuso":
        if (ESTADO["ultimo_token"] and ESTADO["ultimo_exp"] > time.time() + 5 and ESTADO["ultimo_rar"]
                and ESTADO["ultimo_rar"]["path"].endswith("api-transferencias")):
            tok, rar = ESTADO["ultimo_token"], ESTADO["ultimo_rar"]
            h, c = json.loads(unb64(tok.split(".")[0])), json.loads(unb64(tok.split(".")[1]))
            if modo() == "verify" and actor_de(c) == (verify_cfg() or {}).get("agente_id"):
                c["_actor_nombre"] = "asistente-banca"
            reusado = True
        else:
            tok, h, c = emitir("banca/data/canales/api-transferencias", "read")
            rar = rar_de(c)
            reusado = False
        pasos.append({"tipo": "idp", "emisor": modo(), "header": h, "claims": c, "reusado": reusado})
        ruta, cap = "banca/data/canales/api-cuentas", "read"
    else:
        ruta, cap = {
            "cuentas": ("banca/data/canales/api-cuentas", "read"),
            "transferencias": ("banca/data/canales/api-transferencias", "read"),
            "escribir": ("banca/data/canales/api-cuentas", "update"),
            "core": ("banca/data/core/db-admin", "read"),
            "transferir": ("banca/data/canales/api-transferencias", "update"),
        }.get(intent) or ruta_cap
        tok, h, c = emitir(ruta, cap)
        rar = rar_de(c)
        pasos.append({"tipo": "idp", "emisor": modo(), "header": h, "claims": c, "reusado": False})
        ESTADO.update(ultimo_token=tok, ultimo_rar=rar, ultimo_exp=c["exp"])

    if cap == "update":
        st, j, ms = vault("POST", ruta, tok, {"data": {"api_key": "rotada-por-el-agente", "proveedor": "core-canales"}})
        metodo = "POST"
    else:
        st, j, ms = vault("GET", ruta, tok)
        metodo = "GET"
    errores = j.get("errors", [])
    datos = ((j.get("data") or {}).get("data") or {}) if st < 300 else None
    vis = None
    if datos:
        vis = {k: (enmascarar(v) if k in ("api_key", "password") else v) for k, v in datos.items()}
    pasos.append({"tipo": "vault", "metodo": metodo, "ruta": ruta, "op": cap, "status": st, "ms": ms,
                  "errores": errores, "codigo": codigo_error(errores), "datos": vis, "jti": c.get("jti"),
                  "compuertas": compuertas(st, errores, ruta, cap, rar["path"], rar["capabilities"])})

    ok = st < 300
    if intent == "cuentas":
        resp = (f"La API de cuentas la provee «{datos.get('proveedor')}». Tengo su API key (te muestro solo el inicio: {vis.get('api_key')})."
                if ok else "Vault no me dejó leer la API de cuentas.")
    elif intent == "transferencias":
        resp = (f"El límite diario de la API de transferencias es US$ {datos.get('limite_diario_usd')}." if ok
                else "Vault no me dejó leer la API de transferencias.")
    elif intent == "escribir":
        resp = ("Rotada." if ok else
                "No puedo rotar esa API key. Tú podrías hacerlo, pero mi techo en el registro de agentes es de solo lectura, "
                "así que Vault rechazó la escritura (CEILING_POLICY_DENIED).")
    elif intent == "core":
        resp = ("Aquí está." if ok else
                "Intenté leer la credencial del DBA del core y Vault la negó: está fuera de mi techo, aunque tú sí tengas acceso. "
                "Ni un prompt ingenioso cambia eso, porque la regla vive en Vault y no en mis instrucciones.")
    elif intent == "transferir":
        resp = ("Transferencia enviada." if ok else
                "No puedo ejecutar transferencias por ti: mi permiso es solo de consulta y Vault rechazó la operación "
                "(CEILING_POLICY_DENIED). Puedes hacerla tú desde Transferencias.")
    elif intent == "generico":
        resp = (f"Listo: {json.dumps(vis, ensure_ascii=False)}" if ok else f"Vault negó la operación ({codigo_error(errores)}).")
    else:  # reuso
        resp = ("Leí la API de cuentas con el token de transferencias." if ok else
                "Intenté reusar el token que me dieron para transferencias y Vault lo rechazó (RAR_NO_MATCH): "
                "ese token solo autoriza la ruta de transferencias. Cada tarea necesita su propio token.")
    return {"respuesta": resp, "pasos": pasos, "veredicto": ok, "actor": "asistente-banca"}


# ---------------------------------------------------------------- audit log en vivo
SUSCRIPTORES = []
SUS_LOCK = threading.Lock()


def difundir(obj):
    with SUS_LOCK:
        for q in list(SUSCRIPTORES):
            q.put(obj)


def resumir(e):
    req, auth = e.get("request") or {}, e.get("auth") or {}
    md = auth.get("metadata") or {}
    pr = auth.get("policy_results") or {}
    return {
        "kind": "audit",
        "time": e.get("time"),
        "op": req.get("operation"),
        "path": req.get("path"),
        "ns": (req.get("namespace") or {}).get("path"),
        "remote": req.get("remote_address"),
        "error": e.get("error") or "",
        "allowed": pr.get("allowed"),
        "granting": [g.get("name") for g in pr.get("granting_policies", []) if g.get("name")],
        "policies": auth.get("policies", []),
        "actor": md.get("actor_entity_name"),
        "jti": md.get("jwt_unique_id"),
        "rar": auth.get("authorization_details") or md.get("jwt_authorization_details"),
        "display_name": auth.get("display_name"),
        "persona": md.get("username") or ("ana" if "ana-ejecutiva" in (auth.get("policies") or []) else None),
        "username": md.get("username"),
        "status": ((e.get("response") or {}).get("data") or {}).get("http_status_code"),
    }


def seguir_audit():
    while True:
        try:
            p = subprocess.Popen(["sudo", "-n", "tail", "-n", "0", "-F", AUDIT],
                                 stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
            for linea in p.stdout:
                if '"demo/agentes/"' not in linea or '"type":"response"' not in linea:
                    continue
                try:
                    r = resumir(json.loads(linea))
                except ValueError:
                    continue
                if r["ns"] != "demo/agentes/" or (r["path"] or "").startswith("sys/internal/ui"):
                    continue
                with SUS_LOCK:
                    for q in list(SUSCRIPTORES):
                        q.put(r)
        except Exception as ex:  # reintenta si tail muere
            print("audit:", ex, file=sys.stderr)
        time.sleep(2)


# ---------------------------------------------------------------- HTTP
class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        b = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    PORTAL_RUTAS = ("/", "/portal", "/api/yo", "/api/asistente", "/login", "/callback", "/logout", "/favicon.ico")

    def _portal_ok(self):
        k = portal_key()
        return bool(k) and self.headers.get("X-Portal-Key") == k

    def _desde_internet(self):
        # Lo que llega por el túnel de Cloudflare trae Cf-Connecting-Ip: solo /tool/* (Orchestrate)
        # y, si viene del proxy del portal (X-Portal-Key), las rutas del portal.
        if not self.headers.get("Cf-Connecting-Ip"):
            return False
        ruta = urllib.parse.urlparse(self.path).path
        if ruta.startswith("/tool/"):
            return False
        return not (ruta in self.PORTAL_RUTAS and self._portal_ok())

    def _redirect_uri(self):
        host = self.headers.get("X-Forwarded-Host")
        if host and self._portal_ok():
            return f"{self.headers.get('X-Forwarded-Proto', 'https')}://{host}/callback"
        return REDIRECT

    def _ir(self, destino):
        self.send_response(302)
        self.send_header("Location", destino)
        self.end_headers()

    def _html(self, nombre):
        b = open(os.path.join(AQUI, nombre), "rb").read()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        if self._desde_internet():
            return self.send_error(404)
        ruta = urllib.parse.urlparse(self.path).path
        qs = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if ruta in ("/", "/index.html", "/presentador"):
            if ruta == "/" and self._portal_ok():
                return self._ir("/portal")
            self._html("presentador.html")
        elif ruta == "/portal":
            self._html("portal.html")
        elif ruta == "/api/yo":
            sesion = modo() == "verify" and not VERIFY["revocada"] and bool(VERIFY["ana_refresh"] or VERIFY["ana"])
            nombre = saludo = None
            if sesion:
                try:
                    c = claims_de(token_ana())[1]
                    nombre = c.get("preferred_username") or c.get("name") or "Ana"
                    cfgp = verify_cfg() or {}
                    nombre = cfgp.get("persona_nombre") or nombre
                    saludo = cfgp.get("persona_saludo") or (c.get("given_name") or c.get("name") or nombre.split("@")[0]).split(" ")[0].capitalize()
                except Exception:
                    sesion = False
            self._json({"sesion": sesion, "nombre": nombre, "saludo": saludo})
        elif self.path == "/api/registro":
            st, j, _ = vault("GET", "sys/health", ns=False)
            cfg = verify_cfg() or {}
            if modo() == "verify" and not VERIFY["revocada"] and VERIFY["ana_refresh"] and not VERIFY["ana"]:
                try:
                    token_ana()
                except Exception:
                    pass
            self._json({"modo": modo(), "verify": {"tenant": cfg.get("tenant"), "revocada": VERIFY["revocada"], "ana_sesion": (not VERIFY["revocada"]) and (bool(VERIFY["ana_refresh"]) or (bool(VERIFY["ana"]) and VERIFY["ana_exp"] > time.time())),
                                                   "ana_usuario": (claims_de(VERIFY["ana"])[1].get("preferred_username") if VERIFY["ana"] else None)},
                        "registro": REGISTRO, "vault": {"version": j.get("version"), "addr": VAULT_ADDR, "ns": NS,
                                                         "sealed": j.get("sealed")}})
        elif ruta == "/login":
            cfg = verify_cfg()
            if not cfg:
                return self.send_error(404)
            ver = secrets.token_urlsafe(48)
            st = secrets.token_urlsafe(16)
            ru = self._redirect_uri()
            VERIFY["pkce"] = {st: (ver, ru, (qs.get("volver") or ["/"])[0])}
            q = urllib.parse.urlencode({"client_id": cfg["app_id"], "response_type": "code", "redirect_uri": ru,
                                        "scope": "openid profile email", "state": st, "code_challenge_method": "S256",
                                        "code_challenge": base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()})
            self.send_response(302)
            self.send_header("Location", cfg["tenant"] + "/oauth2/authorize?" + q)
            self.end_headers()
        elif ruta == "/callback":
            cfg = verify_cfg()
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            st, code = (q.get("state") or [""])[0], (q.get("code") or [""])[0]
            pk = VERIFY["pkce"].pop(st, None)
            ver, ru, volver = pk if pk else (None, REDIRECT, "/")
            try:
                if not (ver and code):
                    raise RuntimeError(f"callback sin code/state válido: {q.get('error_description') or q.get('error')}")
                j = verify_token({"grant_type": "authorization_code", "code": code, "redirect_uri": ru,
                                  "code_verifier": ver}, (cfg["app_id"], cfg["app_secret"]))
                guardar_ana(j)
                self._ir(volver if volver.startswith("/") else "/")
            except Exception as ex:
                b = f"<pre>Error en el login con Verify: {ex}</pre><a href='/'>volver</a>".encode()
                self.send_response(500)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(b)
        elif self.path == "/api/quien":  # IDs para los alias de Vault (sin tokens)
            out = {}
            try:
                if VERIFY["ana"]:
                    c = claims_de(VERIFY["ana"])[1]
                    out["ana"] = {k: c.get(k) for k in ("sub", "uid", "preferred_username", "userName", "name", "email", "iss", "aud")}
                c = claims_de(token_agente())[1]
                out["agente"] = {k: c.get(k) for k in ("sub", "client_id", "iss", "aud", "grant_type")}
            except Exception as ex:
                out["error"] = str(ex)
            self._json(out)
        elif ruta == "/logout":
            VERIFY.update(ana=None, ana_refresh=None, ana_exp=0)
            try:
                os.remove(os.path.join(os.path.dirname(VERIFY_CFG), "ana.refresh"))
            except OSError:
                pass
            self._ir((qs.get("volver") or ["/"])[0])
        elif self.path == "/tool/openapi.json":
            proto = self.headers.get("X-Forwarded-Proto", "http")
            self._json(openapi(f"{proto}://{self.headers.get('Host')}"))
        elif self.path == "/api/eventos":
            q = queue.Queue()
            with SUS_LOCK:
                SUSCRIPTORES.append(q)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            try:
                self.wfile.write(b": hola\n\n")
                self.wfile.flush()
                while True:
                    try:
                        r = q.get(timeout=15)
                        self.wfile.write(f"data: {json.dumps(r, ensure_ascii=False)}\n\n".encode())
                    except queue.Empty:
                        self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                with SUS_LOCK:
                    SUSCRIPTORES.remove(q)
        else:
            self.send_error(404)

    def do_POST(self):
        if self._desde_internet():
            return self.send_error(404)
        if self.path.startswith("/tool/"):
            k = tool_key()
            if not k or self.headers.get("X-API-Key") != k:
                return self._json({"error": "API key inválida"}, 401)
            n = int(self.headers.get("Content-Length", 0))
            try:
                cuerpo = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                return self._json({"error": "JSON inválido"}, 400)
            op = {"/tool/leer_secreto": "leer", "/tool/rotar_secreto": "rotar", "/tool/transferir": "transferir"}.get(self.path)
            if not op:
                return self.send_error(404)
            try:
                code, r = ejecutar_tool(op, cuerpo)
            except Exception as ex:
                code, r = 500, {"error": str(ex)}
            return self._json(r, code)
        if self.path == "/api/asistente":
            n = int(self.headers.get("Content-Length", 0))
            msgs = (json.loads(self.rfile.read(n) or b"{}").get("messages") or [])[-8:]
            return self._json(asistente(msgs))
        if self.path == "/api/revocar":
            if modo() != "verify":
                return self._json({"error": "solo en modo Verify"}, 400)
            res = verify_revocar()
            difundir({"kind": "revocada", "resultado": res})
            return self._json({"ok": True, "resultado": res})
        if self.path != "/api/chat":
            return self.send_error(404)
        n = int(self.headers.get("Content-Length", 0))
        texto = (json.loads(self.rfile.read(n) or b"{}").get("texto") or "").strip()
        intent = intencion(texto)
        r = ejecutar_con_verify(intent, texto)
        r["intencion"] = intent
        self._json(r)


def ejecutar_con_verify(intent, texto, ruta_cap=None):
    try:
        return accion_agente(intent, texto, ruta_cap)
    except RuntimeError as ex:
        if modo() == "verify" and str(ex).startswith("Verify"):
            return {"respuesta": "IBM Verify rechazó emitir el token: la sesión fue revocada. El agente ya no puede actuar en nombre de la persona.",
                    "pasos": [{"tipo": "idp_error", "error": str(ex)[:300]}], "veredicto": False, "actor": "asistente-banca"}
        return {"respuesta": f"Error: {ex}", "pasos": [], "veredicto": None}
    except Exception as ex:
        return {"respuesta": f"Error: {ex}", "pasos": [], "veredicto": None}


# ---------------------------------------------------------------- Asistente del portal (agente de watsonx Orchestrate)
WXO = {"token": None, "exp": 0}
WXO_URL = os.environ.get("WXO_URL", "")
WXO_AGENT = os.environ.get("WXO_AGENT_ID", "")
DIR_IDP = os.environ.get("IDP_DIR", os.path.expanduser("~/.idp-demo"))


def portal_key():
    try:
        return open(os.path.join(DIR_IDP, "portal.key")).read().strip()
    except OSError:
        return None


def wxo_token():
    if WXO["token"] and WXO["exp"] > time.time() + 60:
        return WXO["token"]
    k = open(os.path.join(DIR_IDP, "wxo.key")).read().strip()
    req = urllib.request.Request("https://iam.cloud.ibm.com/identity/token", method="POST",
                                 data=urllib.parse.urlencode({"grant_type": "urn:ibm:params:oauth:grant-type:apikey", "apikey": k}).encode())
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=20) as r:
        j = json.loads(r.read())
    WXO.update(token=j["access_token"], exp=j.get("expiration", time.time() + 3000))
    return WXO["token"]


def asistente(msgs):
    msgs = [{"role": m.get("role", "user"), "content": str(m.get("content", ""))[:2000]} for m in msgs if m.get("content")]
    if not msgs:
        return {"respuesta": ""}
    try:
        req = urllib.request.Request(f"{WXO_URL}/v1/orchestrate/{WXO_AGENT}/chat/completions", method="POST",
                                     data=json.dumps({"messages": msgs, "stream": False}).encode())
        req.add_header("Authorization", "Bearer " + wxo_token())
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=90) as r:
            j = json.loads(r.read())
        return {"respuesta": j["choices"][0]["message"]["content"], "origen": "orchestrate"}
    except Exception as ex:  # respaldo: el agente local
        print("orchestrate:", ex, file=sys.stderr)
        texto = msgs[-1]["content"]
        r = ejecutar_con_verify(intencion(texto), texto)
        r.update(kind="flujo", origen="asistente local", intencion=intencion(texto), pedido=texto)
        difundir(r)
        return {"respuesta": r["respuesta"], "origen": "local"}


# ---------------------------------------------------------------- API de tool (watsonx Orchestrate)
TOOL_KEY_FILE = os.path.join(os.environ.get("IDP_DIR", os.path.expanduser("~/.idp-demo")), "tool.key")
RECURSOS = {
    "api-cuentas": "banca/data/canales/api-cuentas",
    "api-transferencias": "banca/data/canales/api-transferencias",
    "core-db-admin": "banca/data/core/db-admin",
}


def tool_key():
    try:
        return open(TOOL_KEY_FILE).read().strip()
    except OSError:
        return None


DATOS_BANCO = {
    "api-cuentas": {"cuenta_corriente": {"numero": "00-123-45678-9", "saldo_clp": 4582300},
                    "cuenta_vista": {"numero": "00-987-65432-1", "saldo_clp": 312940},
                    "tarjeta_credito": {"numero": "•••• 4821", "cupo_disponible_clp": 1250000, "facturado_clp": 186420}},
    "api-transferencias": {"limite_diario_clp": 5000000, "usado_hoy_clp": 150000},
}


def ejecutar_tool(op, cuerpo):
    if op == "transferir":
        cuerpo = dict(cuerpo, recurso="api-transferencias")
    recurso = cuerpo.get("recurso", "")
    if recurso not in RECURSOS:
        return 400, {"error": f"recurso debe ser uno de {list(RECURSOS)}"}
    ruta = RECURSOS[recurso]
    pedido = cuerpo.get("pedido_del_usuario") or ""
    if op == "leer" and cuerpo.get("reusar_token_anterior"):
        intent = "reuso" if recurso == "api-cuentas" else "generico"
        cap = "read"
    elif op == "leer":
        intent = {"api-cuentas": "cuentas", "api-transferencias": "transferencias", "core-db-admin": "core"}[recurso]
        cap = "read"
    elif op == "transferir":
        intent, cap = "transferir", "update"
    else:
        intent = "escribir" if recurso == "api-cuentas" else "generico"
        cap = "update"
    r = ejecutar_con_verify(intent, pedido, (ruta, cap))
    r.update(kind="flujo", origen="watsonx Orchestrate", intencion=f"tool {op}_secreto({recurso})", pedido=pedido)
    difundir(r)
    v = next((p for p in r["pasos"] if p["tipo"] == "vault"), {})
    return 200, {
        "permitido": bool(r.get("veredicto")),
        "http_status_vault": v.get("status"),
        "codigo_vault": v.get("codigo") or None,
        "datos": v.get("datos"),
        "datos_banco": (DATOS_BANCO.get(recurso) if r.get("veredicto") and op == "leer" else None),
        "explicacion": r["respuesta"],
        "error_idp": next((p["error"] for p in r["pasos"] if p["tipo"] == "idp_error"), None),
        "token": next(({"emisor": p.get("emisor"), "sub": p["claims"].get("sub"), "actor": actor_de(p["claims"]),
                        "rar": p["claims"].get("authorization_details")} for p in r["pasos"] if p["tipo"] == "idp"), None),
    }


def openapi(base):
    prop = {"recurso": {"type": "string", "enum": list(RECURSOS),
                        "description": "api-cuentas y api-transferencias son APIs de canales; core-db-admin es la credencial del DBA del core bancario"},
            "pedido_del_usuario": {"type": "string", "description": "Lo que pidió el usuario, literal"}}
    resp = {"200": {"description": "Resultado de Vault", "content": {"application/json": {"schema": {"type": "object", "properties": {
        "permitido": {"type": "boolean"}, "http_status_vault": {"type": "integer"}, "codigo_vault": {"type": "string"},
        "datos": {"type": "object"}, "explicacion": {"type": "string"}, "token": {"type": "object"}}}}}}}
    def op(oid, summary, desc, extra=None):
        p = dict(prop, **(extra or {}))
        return {"post": {"operationId": oid, "summary": summary, "description": desc,
                         "requestBody": {"required": True, "content": {"application/json": {"schema": {
                             "type": "object", "required": ["recurso"], "properties": p}}}},
                         "responses": resp, "security": [{"apiKey": []}]}}
    return {
        "openapi": "3.0.3",
        "info": {"title": "Vault Banca (Agentic IAM)", "version": "1.0.0",
                 "description": "Secretos de banca en HashiCorp Vault. Cada llamada usa un token del IdP emitido para Ana con el agente como actor y un RAR de la tarea."},
        "servers": [{"url": base}],
        "components": {"securitySchemes": {"apiKey": {"type": "apiKey", "in": "header", "name": "X-API-Key"}}},
        "paths": {
            "/tool/leer_secreto": op("leer_secreto", "Leer un secreto de banca en Vault",
                                     "Lee un secreto (API de cuentas, API de transferencias o credencial del core) en nombre de Ana.",
                                     {"reusar_token_anterior": {"type": "boolean", "description": "true solo si el usuario pide explícitamente reutilizar el token de la tarea anterior"}}),
            "/tool/rotar_secreto": op("rotar_secreto", "Rotar o cambiar un secreto de banca en Vault",
                                      "Escribe un valor nuevo para la API key del recurso indicado, en nombre de Ana."),
            "/tool/transferir": {"post": {"operationId": "transferir", "summary": "Ejecutar una transferencia",
                "description": "Ejecuta una transferencia de dinero en nombre del cliente usando la API de transferencias del banco.",
                "requestBody": {"required": True, "content": {"application/json": {"schema": {"type": "object", "required": ["monto", "destinatario"],
                    "properties": {"monto": {"type": "number", "description": "Monto en pesos chilenos"},
                                   "destinatario": {"type": "string", "description": "Nombre del destinatario"},
                                   "pedido_del_usuario": {"type": "string", "description": "Lo que pidió el usuario, literal"}}}}}},
                "responses": resp, "security": [{"apiKey": []}]}},
        },
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--puerto", type=int, default=8765)
    a = ap.parse_args()
    threading.Thread(target=seguir_audit, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", a.puerto), H)
    srv.daemon_threads = True
    print(f"UI lista en http://127.0.0.1:{a.puerto}  (desde el Mac: túnel ssh -L {a.puerto}:127.0.0.1:{a.puerto})")
    srv.serve_forever()


if __name__ == "__main__":
    main()
