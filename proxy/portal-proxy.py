#!/usr/bin/env python3
"""Proxy del portal Banco Demo (corre en el EC2 detrás del F5, HTTP :8080).

Reenvía las rutas del portal al backend de la demo (en el bastión) por el túnel de Cloudflare,
agregando X-Portal-Key y X-Forwarded-Host para que el login con IBM Verify vuelva a este host.
Config en /etc/portal-proxy.env: BACKEND_URL=https://...trycloudflare.com y PORTAL_KEY=...
Solo biblioteca estándar de Python 3.
"""
import os
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CFG = {}
for line in open(os.environ.get("PORTAL_PROXY_ENV", "/etc/portal-proxy.env")):
    if "=" in line and not line.startswith("#"):
        k, v = line.strip().split("=", 1)
        CFG[k] = v
BACKEND = CFG["BACKEND_URL"].rstrip("/")
KEY = CFG["PORTAL_KEY"]
PERMITIDAS = ("/", "/portal", "/api/yo", "/api/asistente", "/login", "/callback", "/logout", "/favicon.ico", "/salud")


class SinRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


OPENER = urllib.request.build_opener(SinRedirect)


class H(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *a):
        print(self.address_string(), fmt % a, flush=True)

    def _proxy(self, metodo):
        ruta = self.path.split("?", 1)[0]
        if ruta == "/salud":
            b = b"ok"
            self.send_response(200)
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        if ruta not in PERMITIDAS:
            self.send_error(404)
            return
        n = int(self.headers.get("Content-Length") or 0)
        cuerpo = self.rfile.read(n) if n else None
        req = urllib.request.Request(BACKEND + self.path, data=cuerpo, method=metodo)
        for h in ("Content-Type", "Accept", "Accept-Language", "User-Agent"):
            if self.headers.get(h):
                req.add_header(h, self.headers[h])
        req.add_header("X-Portal-Key", KEY)
        req.add_header("X-Forwarded-Host", self.headers.get("Host", ""))
        req.add_header("X-Forwarded-Proto", "https")
        try:
            r = OPENER.open(req, timeout=120)
            st, hdrs, b = r.status, r.headers, r.read()
        except urllib.error.HTTPError as e:
            st, hdrs, b = e.code, e.headers, e.read()
        except Exception as e:
            st, hdrs, b = 502, {}, f"Backend no disponible: {e}".encode()
        self.send_response(st)
        for h in ("Content-Type", "Location", "Cache-Control"):
            if hdrs and hdrs.get(h):
                self.send_header(h, hdrs.get(h))
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self._proxy("GET")

    def do_POST(self):
        self._proxy("POST")


if __name__ == "__main__":
    srv = ThreadingHTTPServer(("0.0.0.0", int(CFG.get("PUERTO", "8080"))), H)
    srv.daemon_threads = True
    print("portal-proxy escuchando", flush=True)
    srv.serve_forever()
