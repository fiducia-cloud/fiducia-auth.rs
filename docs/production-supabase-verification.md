# Production Supabase session verification

Linear: DEN-251

`fiducia-auth` prefers offline verification of Supabase access tokens against the configured issuer, audience, and cached asymmetric JWKS. The production container now starts through `fiducia-auth-production-entrypoint`, which resolves the verification mode before the HTTP server starts and then replaces itself with the main auth process.

## Environment contract

| Environment | `FIDUCIA_DEPLOYMENT_MODE` | Remote `/auth/v1/user` fallback |
| --- | --- | --- |
| Production | `production` or unset | Always forbidden. An explicit `SUPABASE_AUTH_ALLOW_REMOTE_USERINFO=true` aborts startup. |
| Staging migration | `staging` | Off by default. May be enabled explicitly only when `SUPABASE_PUBLISHABLE_KEY` is present. |
| Development | `development` | Off by default. May be enabled explicitly only when `SUPABASE_PUBLISHABLE_KEY` is present. |
| Test | `test` | Off by default. May be enabled explicitly only when `SUPABASE_PUBLISHABLE_KEY` is present. |

Accepted boolean values are `true/false`, `1/0`, `yes/no`, and `on/off`. Unknown deployment modes and malformed booleans fail startup rather than selecting a permissive default.

## Production example

```text
FIDUCIA_DEPLOYMENT_MODE=production
SUPABASE_AUTH_ALLOW_REMOTE_USERINFO=false
SUPABASE_AUTH_ISSUER=https://<project>.supabase.co/auth/v1
SUPABASE_AUTH_JWKS_URL=https://<project>.supabase.co/auth/v1/.well-known/jwks.json
SUPABASE_AUTH_AUDIENCE=authenticated
```

Every production Supabase project must use an asymmetric signing key exposed through JWKS. A shared-secret token or unknown/unsupported signing algorithm is rejected; the production container does not make a network userinfo call as a compatibility fallback.

## Temporary staging migration

```text
FIDUCIA_DEPLOYMENT_MODE=staging
SUPABASE_AUTH_ALLOW_REMOTE_USERINFO=true
SUPABASE_PUBLISHABLE_KEY=<secret-manager reference>
```

This mode is for a bounded migration window only. Record an owner and removal date, migrate the project to asymmetric signing, then remove both the opt-in and publishable key. Never copy the key into source control, Linear, logs, or command history.

## Rollout and rollback

1. Verify the target Supabase project publishes the expected asymmetric JWKS and audience.
2. Deploy to staging with remote userinfo disabled first.
3. Exercise valid, expired, wrong-audience, wrong-issuer, unknown-`kid`, and unsupported-algorithm tokens.
4. Deploy the production image with `FIDUCIA_DEPLOYMENT_MODE=production`.
5. Roll back to the prior image only if necessary; do not restore production remote-userinfo fallback. Fix the issuer, audience, JWKS endpoint, or signing-key migration instead.

The wrapper deliberately does not log tokens, keys, or claims. It reports only the rejected configuration class.

## Remaining DEN-251 work

This guard protects the shipped production image immediately. The parent issue remains open for the deeper library/configuration update, content-free unknown-`kid` and JWKS-refresh metrics, alert thresholds, and deployment-manifest/CI drift checks across all Fiducia environments.
