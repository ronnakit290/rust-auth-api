"""Independent verification of an SSO access token.

Uses only the public JWKS document plus the `cryptography` package, i.e. exactly
what an external system (Node, Java, Go, …) would do: no shared secret, no
knowledge of this codebase.
"""

import base64
import hashlib
import json
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import os

BASE = os.environ.get("BASE_URL", "http://127.0.0.1:8080")
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL", "admin@example.com")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "")


def post_json(path, payload, token=None):
    request = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    if token:
        request.add_header("authorization", f"Bearer {token}")
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def post_form(path, pairs):
    request = urllib.request.Request(
        BASE + path,
        data=urllib.parse.urlencode(pairs).encode(),
        headers={"content-type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def get_json(path):
    with urllib.request.urlopen(BASE + path) as response:
        return json.load(response)


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def b64url_uint(value: str) -> int:
    return int.from_bytes(b64url_decode(value), "big")


if not ADMIN_PASSWORD:
    raise SystemExit("set ADMIN_PASSWORD (and optionally BASE_URL / ADMIN_EMAIL)")

admin = post_json("/api/v1/auth/login", {"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD})
admin_token = admin["data"]["tokens"]["access_token"]

name = f"Verified Service {int(time.time())}"
client = post_json(
    "/api/v1/admin/clients",
    {"name": name, "client_type": "confidential", "allowed_scopes": ["users:read"]},
    token=admin_token,
)["data"]
client_id = client["client"]["client_id"]
client_secret = client["client_secret"]

tokens = post_form(
    "/oauth/token",
    [
        ("grant_type", "client_credentials"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("scope", "users:read"),
    ],
)
access = tokens["access_token"]

header_b64, payload_b64, signature_b64 = access.split(".")
header = json.loads(b64url_decode(header_b64))
claims = json.loads(b64url_decode(payload_b64))

jwks = get_json("/.well-known/jwks.json")
key = next(k for k in jwks["keys"] if k["kid"] == header["kid"])
public_key = rsa.RSAPublicNumbers(b64url_uint(key["e"]), b64url_uint(key["n"])).public_key()

signing_input = f"{header_b64}.{payload_b64}".encode()
public_key.verify(
    b64url_decode(signature_b64),
    signing_input,
    padding.PKCS1v15(),
    hashes.SHA256(),
)

now = datetime.now(timezone.utc).timestamp()
assert header["alg"] == "RS256", header
assert header["typ"] == "JWT", header
assert claims["iss"] == BASE.rstrip("/"), claims
assert claims["aud"] == client_id, claims
assert claims["exp"] > now, claims
assert claims["sub"] == f"client:{client_id}", claims
assert claims["scope"] == "users:read", claims

pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo,
).decode()

print("Signature verified with the published JWKS only ✓")
print("  alg/typ :", header["alg"], "/", header["typ"], "kid", header["kid"])
print("  iss     :", claims["iss"])
print("  aud/sub :", claims["aud"], "/", claims["sub"])
print("  scope   :", claims["scope"])
print("  expires :", datetime.fromtimestamp(claims["exp"], timezone.utc).isoformat())
print("  public key fingerprint:", hashlib.sha256(pem.encode()).hexdigest()[:32])
