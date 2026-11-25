#!/usr/bin/env python3
"""Emisor de tokens de prueba para la demo de Agentic IAM.

Hace el papel que en producción cumple el IdP (IBM Verify, Entra ID, Okta, Auth0):
emite access tokens JWT (RFC 9068, typ at+jwt) con el claim act (RFC 8693, el agente
que actúa en nombre de la persona) y authorization_details (RFC 9396, RAR).

Solo usa la biblioteca estándar de Python y el comando openssl.

Uso:
  idp-simulado.py iniciar                      # crea la llave y muestra la pública (PEM)
  idp-simulado.py emitir --sub ana --actor asistente-banca \
      --ruta banca/data/canales/api-cuentas --cap read
  idp-simulado.py ver <token>                  # muestra header y claims
"""
import argparse
import base64
import json
import os
import subprocess
import sys
import time
import uuid

DIR = os.environ.get("IDP_DIR", os.path.expanduser("~/.idp-demo"))
KEY = os.path.join(DIR, "idp-key.pem")
PUB = os.path.join(DIR, "idp-pub.pem")
ISS = os.environ.get("IDP_ISSUER", "https://idp-demo.lab.local")
AUD = os.environ.get("IDP_AUDIENCE", "https://127.0.0.1:8200/v1")
KID = os.environ.get("IDP_KID", "idp-demo-1")


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def iniciar(_args):
    os.makedirs(DIR, mode=0o700, exist_ok=True)
    if not os.path.exists(KEY):
        subprocess.run(["openssl", "genpkey", "-algorithm", "RSA",
                        "-pkeyopt", "rsa_keygen_bits:2048", "-out", KEY],
                       check=True, capture_output=True)
        os.chmod(KEY, 0o600)
        subprocess.run(["openssl", "pkey", "-in", KEY, "-pubout", "-out", PUB],
                       check=True, capture_output=True)
    sys.stdout.write(open(PUB).read())


def emitir(args):
    if not os.path.exists(KEY):
        sys.exit("Falta la llave: ejecuta primero 'idp-simulado.py iniciar'")
    now = int(time.time())
    claims = {
        "iss": ISS,
        "aud": AUD,
        "sub": args.sub,
        "client_id": "app-banca",
        "iat": now,
        "nbf": now,
        "exp": now + args.ttl,
        "jti": str(uuid.uuid4()),
    }
    if args.actor:
        claims["act"] = {"sub": args.actor}
    if args.ruta:
        claims["authorization_details"] = [{
            "type": "vault:path_access",
            "path": args.ruta,
            "capabilities": args.cap,
        }]
    header = {"alg": "RS256", "typ": "at+jwt", "kid": KID}
    signing_input = ".".join([
        b64(json.dumps(header, separators=(",", ":")).encode()),
        b64(json.dumps(claims, separators=(",", ":")).encode()),
    ])
    sig = subprocess.run(["openssl", "dgst", "-sha256", "-sign", KEY],
                         input=signing_input.encode(), capture_output=True,
                         check=True).stdout
    print(signing_input + "." + b64(sig))


def ver(args):
    parts = args.token.split(".")
    print(json.dumps(json.loads(unb64(parts[0])), indent=2, ensure_ascii=False))
    print(json.dumps(json.loads(unb64(parts[1])), indent=2, ensure_ascii=False))


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("iniciar").set_defaults(fn=iniciar)
    e = sub.add_parser("emitir")
    e.add_argument("--sub", required=True, help="persona (claim sub)")
    e.add_argument("--actor", help="agente que actúa en su nombre (claim act.sub)")
    e.add_argument("--ruta", help="ruta de Vault autorizada en el RAR")
    e.add_argument("--cap", nargs="+", default=["read"], help="capacidades del RAR")
    e.add_argument("--ttl", type=int, default=300, help="segundos de vida (300)")
    e.set_defaults(fn=emitir)
    v = sub.add_parser("ver")
    v.add_argument("token")
    v.set_defaults(fn=ver)
    args = p.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
