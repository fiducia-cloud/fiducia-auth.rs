# Revocation API examples

The examples use placeholders. Never commit or paste live secrets or raw JWTs into issue trackers, logs, or shell history.

## Revoke one token ID

```sh
curl --fail-with-body \
  -H 'content-type: application/json' \
  -H 'x-revocation-admin-auth: <writer-secret>' \
  -H 'x-fiducia-actor: operator-id' \
  -H 'idempotency-key: incident-20260731-token-01' \
  --data '{
    "kind": "token_id",
    "claims": {
      "sub": "subject-id",
      "org_id": "tenant-id",
      "scopes": ["locks:write"],
      "iss": "fiducia-auth",
      "aud": "fiducia-api",
      "iat": 100,
      "exp": 700,
      "jti": "token-id"
    },
    "reason": "credential exposure investigation"
  }' \
  http://127.0.0.1:8098/v1/revocations/revoke
```

## Quarantine one subject within one tenant

```sh
curl --fail-with-body \
  -H 'content-type: application/json' \
  -H 'x-revocation-admin-auth: <writer-secret>' \
  -H 'x-fiducia-actor: operator-id' \
  -H 'idempotency-key: incident-20260731-subject-01' \
  --data '{
    "kind": "subject",
    "tenant_id": "tenant-id",
    "subject": "subject-id",
    "expires_at": 800,
    "reason": "temporary subject quarantine"
  }' \
  http://127.0.0.1:8098/v1/revocations/revoke
```

## Lift a revocation

```sh
curl --fail-with-body \
  -H 'content-type: application/json' \
  -H 'x-revocation-admin-auth: <writer-secret>' \
  -H 'x-fiducia-actor: operator-id' \
  -H 'idempotency-key: incident-20260731-lift-01' \
  --data '{
    "selector": {
      "kind": "token_id",
      "tenant_id": "tenant-id",
      "jti": "token-id"
    },
    "reason": "false positive confirmed"
  }' \
  http://127.0.0.1:8098/v1/revocations/lift
```

## Authoritative check

```sh
curl --fail-with-body \
  -H 'content-type: application/json' \
  -H 'x-revocation-reader-auth: <reader-secret>' \
  --data '{
    "claims": {
      "sub": "subject-id",
      "org_id": "tenant-id",
      "scopes": ["locks:write"],
      "iss": "fiducia-auth",
      "aud": "fiducia-api",
      "iat": 100,
      "exp": 700,
      "jti": "token-id"
    }
  }' \
  http://127.0.0.1:8098/v1/revocations/check
```

The check endpoint is for control-plane validation and bounded cache refresh, not a remote read on every application request.
