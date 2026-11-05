#!/usr/bin/env python3
"""Live auth -> regional LB verification of a real ES256 JWT and API-key oracle.

Requires an EXISTING nonproduction key; read-only, never creates/revokes keys.
FIDUCIA_E2E_AUTH_URL=http://127.0.0.1:18097 FIDUCIA_E2E_LB_URL=http://127.0.0.1:18088 \
FIDUCIA_E2E_API_KEY=... FIDUCIA_E2E_INTROSPECT_SECRET=... \
python3 tests/live_auth_lb_boundary_e2e.py
"""
import base64
import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def origin(name):
    url = os.environ[name].strip().rstrip("/")
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname or parts.path not in ("", "/"):
        raise ValueError("%s must be an origin" % name)
    return url


def call(base, path, method="GET", body=None, headers=None):
    data = json.dumps(body).encode() if body is not None else None
    h = {"accept": "application/json", **(headers or {})}
    if data is not None:
        h["content-type"] = "application/json"
    request = urllib.request.Request(base + path, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(request, timeout=8) as res:
            raw = res.read(65536)
            return res.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as err:
        raw = err.read(65536)
        try:
            return err.code, json.loads(raw) if raw else None
        except ValueError:
            return err.code, None


def jwt_part(value):
    return json.loads(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))


def denied(status, payload):
    assert status in (401, 403), (status, payload)
    # Never return credentials or backend state in a customer-facing error.
    assert "private-key" not in json.dumps(payload or {}).lower()


def main():
    auth, lb = origin("FIDUCIA_E2E_AUTH_URL"), origin("FIDUCIA_E2E_LB_URL")
    key = os.environ["FIDUCIA_E2E_API_KEY"]
    secret = os.environ["FIDUCIA_E2E_INTROSPECT_SECRET"]
    assert key.startswith("fdc_") and len(key) > 20 and secret
    code, health = call(auth, "/healthz")
    assert code == 200 and health["status"] == "ok"
    code, jwks = call(auth, "/.well-known/jwks.json")
    keys = jwks.get("keys", []) if code == 200 and isinstance(jwks, dict) else []
    assert keys, "production auth must publish a nonempty JWKS"
    by_kid = {k["kid"]: k for k in keys}
    assert len(by_kid) == len(keys), "duplicate published signing key IDs"
    assert all(k["kty"] == "EC" and k["alg"] == "ES256" and k["crv"] == "P-256"
               and k.get("x") and k.get("y") for k in keys), keys

    # A customer presenting even a REAL API key must not use the server-side
    # introspection oracle without the secret authenticated server-to-server hop.
    code, payload = call(auth, "/v1/introspect", "POST", {"api_key": key})
    denied(code, payload)
    code, payload = call(auth, "/v1/introspect", "POST", {"api_key": key},
                         {"x-server-auth": "wrong-internal-secret"})
    denied(code, payload)
    code, introspected = call(auth, "/v1/introspect", "POST", {"api_key": key},
                              {"x-server-auth": secret})
    assert code == 200 and introspected.get("valid") is True, (code, introspected)
    org = introspected["org_id"]
    assert isinstance(org, str) and org
    code, bad = call(auth, "/v1/introspect", "POST",
                     {"api_key": "fdc_live_" + uuid.uuid4().hex + ".invalid"},
                     {"x-server-auth": secret})
    assert code == 200 and bad.get("valid") is False, (code, bad)

    # Exchange is PUBLIC but proof-of-key-possession required. The LB must
    # validate the real auth signature against the same published trust root.
    code, minted = call(auth, "/v1/token", "POST", {"api_key": key})
    assert code == 200 and minted["token_type"] == "Bearer"
    token = minted["token"]
    parts = token.split(".")
    assert len(parts) == 3 and all(parts), "signed compact JWT required"
    header, claims = jwt_part(parts[0]), jwt_part(parts[1])
    assert header["alg"] == "ES256" and header["kid"] in by_kid, header
    assert claims.get("org_id") == org and claims["exp"] > time.time(), claims
    path = "/v1/locks?key=" + urllib.parse.quote("e2e/auth/" + uuid.uuid4().hex, safe="")
    code, _ = call(lb, path, headers={"authorization": "Bearer " + token})
    assert code == 200, "LB rejected authentic JWT"
    code, payload = call(lb, path, headers={
        "authorization": "Bearer " + parts[0] + "." + parts[1] + ".tampered"})
    denied(code, payload)
    code, payload = call(lb, path, headers={
        "authorization": "Bearer fdc_live_" + uuid.uuid4().hex + ".bad"})
    denied(code, payload)
    print("PASS: auth-to-LB ES256 chain valid; oracle and bad signatures denied")


if __name__ == "__main__":
    main()
