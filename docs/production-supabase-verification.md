# Production Supabase session verification

Linear: DEN-251

`fiducia-auth` verifies Supabase access tokens offline against the configured issuer, audience, and cached asymmetric JWKS. The production container starts through `fiducia-auth-production-entrypoint`, and both that wrapper and the core HTTP server compile the same policy module: `src/supabase_policy.rs`.

This shared policy is intentional. The wrapper rejects unsafe configuration before replacing itself with the server process, while the server independently validates the same rules before serving traffic. A packaging or entrypoint mistake therefore cannot silently restore a permissive core-verifier default.

## Environment contract

| Environment | `FIDUCIA_DEPLOYMENT_MODE` | Remote `/auth/v1/user` compatibility |
| --- | --- | --- |
| Production | `production`, `prod`, or unset | Always forbidden. An explicit `SUPABASE_AUTH_ALLOW_REMOTE_USERINFO=true` aborts startup. |
| Staging migration | `staging` or `stage` | Off by default. May be enabled explicitly only when `SUPABASE_PUBLISHABLE_KEY` is present. |
| Development | `development` or `dev` | Off by default. May be enabled explicitly only when `SUPABASE_PUBLISHABLE_KEY` is present. |
| Test | `test` | Off by default. May be enabled explicitly only when `SUPABASE_PUBLISHABLE_KEY` is present. |

Accepted boolean values are `true/false`, `1/0`, `yes/no`, and `on/off`, without case sensitivity. Unknown deployment modes and malformed booleans fail startup instead of selecting a permissive default.

### Production example

```text
FIDUCIA_DEPLOYMENT_MODE=production
SUPABASE_AUTH_ALLOW_REMOTE_USERINFO=false
SUPABASE_AUTH_ISSUER=https://<project>.supabase.co/auth/v1
SUPABASE_AUTH_JWKS_URL=https://<project>.supabase.co/auth/v1/.well-known/jwks.json
SUPABASE_AUTH_AUDIENCE=authenticated
```

Every production Supabase project must use an asymmetric signing key exposed through JWKS. Shared-secret tokens, symmetric JWKS keys, unsupported algorithms, wrong issuers, and wrong audiences are rejected. The production verifier does not call `/auth/v1/user` as a compatibility fallback.

### Temporary non-production migration

```text
FIDUCIA_DEPLOYMENT_MODE=staging
SUPABASE_AUTH_ALLOW_REMOTE_USERINFO=true
SUPABASE_PUBLISHABLE_KEY=<secret-manager reference>
```

Use this only for a bounded migration window. Record an owner and removal date, migrate the project to asymmetric signing, then remove both the opt-in and publishable key. Never copy the key into source control, Linear, logs, metrics, traces, or command history.

## Unknown-key and compatibility observability

The verifier emits counters with bounded, content-free attributes. OpenTelemetry exporters may normalize punctuation in metric names, but the source instruments are:

| Instrument | Attribute | Allowed values |
| --- | --- | --- |
| `fiducia.auth.supabase.unknown_kid` | `stage` | `observed`, `refresh_blocked` |
| `fiducia.auth.supabase.forced_jwks_refresh` | `outcome` | `attempted`, `succeeded`, `failed`, `missing_after_refresh` |
| `fiducia.auth.supabase.remote_userinfo` | `outcome` | `attempted`, `accepted`, `claim_rejected`, `rejected`, `transport_error`, `invalid_response`, `upstream_status` |

The requested `kid`, bearer token, JWT claims, subject, email, organization, publishable key, upstream response body, and provider error body are never metric attributes. Unknown-key rejection text is deliberately generic: it does not echo the attacker-controlled `kid`.

An unknown `kid` may force at most one refresh after the anti-amplification cooldown. A young cache records `refresh_blocked` and rejects immediately rather than allowing random key identifiers to create unbounded JWKS traffic.

### Initial alert policy

Use these as conservative starting rules and tune the non-security volume thresholds after measuring normal traffic:

1. **Production remote-userinfo attempt:** page immediately when `remote_userinfo{outcome="attempted"}` is nonzero in a five-minute window. This indicates a stale binary, bad routing, or a broken deployment-mode invariant.
2. **Refresh transport failure:** page the auth on-call when `forced_jwks_refresh{outcome="failed"}` reaches three events in five minutes. Correlate with JWKS endpoint reachability and normal token-verification failures.
3. **Key still absent after refresh:** warn at five `missing_after_refresh` events in ten minutes; page security/auth at twenty-five in ten minutes or when the condition persists for thirty minutes.
4. **Blocked refresh surge:** warn when `unknown_kid{stage="refresh_blocked"}` exceeds the established environment baseline by an order of magnitude. This can indicate random-`kid` probing or a legitimate rotation occurring inside the cooldown.
5. **Migration path use:** outside a documented non-production migration window, any `remote_userinfo` outcome is an operational defect even when the call succeeds.

Alert payloads must contain only the deployment, service, region, and bounded labels above. Do not attach sampled authorization headers, tokens, raw `kid` values, claims, or upstream bodies.

## Rollout and rollback

1. Verify the target Supabase project publishes the expected asymmetric JWKS and audience.
2. Deploy to staging with remote userinfo disabled first.
3. Exercise valid, expired, wrong-audience, wrong-issuer, unknown-`kid`, symmetric-key, and unsupported-algorithm tokens.
4. Confirm unknown-key tests increment only bounded metric labels and do not add outbound refreshes inside the cooldown.
5. Confirm the production configuration rejects `SUPABASE_AUTH_ALLOW_REMOTE_USERINFO=true` before binding traffic.
6. Deploy the production image with `FIDUCIA_DEPLOYMENT_MODE=production` and the compatibility flag false or unset.
7. Confirm no production egress reaches `/auth/v1/user`, then enable the alerts above.

Roll back to the prior known-good asymmetric-verification image only when necessary. Do not restore production remote-userinfo fallback. Correct the issuer, audience, JWKS endpoint, network path, or signing-key migration instead.

## Acceptance evidence

The verifier contract is covered by deterministic tests for the deployment-mode matrix, malformed configuration, missing publishable keys, symmetric-key rejection, unknown-key cooldown behavior, bounded metric vocabulary, and content-free unknown-key errors. CI runs formatting, clippy with warnings denied, all-target tests, the CLI flag contract, action validation, and dependency audit.
