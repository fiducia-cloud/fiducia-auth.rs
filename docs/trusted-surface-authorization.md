# Trusted surface authorization context

Linear: DEN-253

`GET /v1/me` continues to return the verified dashboard user, organization membership, trusted raw roles, and assurance level. It now also serializes a versioned `authorization` object derived entirely inside `fiducia-auth` after Supabase signature, issuer, audience, and claim verification.

## Version 1 vocabulary

Surface audiences:

- `fiducia-admin`
- `fiducia-customer`

Trusted roles:

- `admin`
- `operator`
- `customer`

Capabilities:

- `admin:read`
- `admin:operate`
- `admin:write`
- `customer:self-service`

Unknown role strings are never copied into the authorization object. Browser headers and Supabase `user_metadata` are not inputs.

## Audience derivation

- `admin` or `operator` grants only `fiducia-admin` by default.
- `customer` grants `fiducia-customer`.
- both surfaces require an explicit trusted role combination such as `operator` + `customer`.
- an empty trusted role list remains a temporary legacy customer session during migration.
- a non-empty list containing only unknown roles receives no surface audience and fails closed.

This avoids silently treating every `aud=authenticated` Supabase session as interchangeable across customer and operator entry points. Receiving applications must check the versioned surface audience and their required normalized role or capability; organization membership alone never grants operator power.

## Rollout order

1. Deploy this additive auth response first. Older consumers ignore the extra object.
2. Deploy admin consumers that require `authorization.version=1`, `fiducia-admin`, and a normalized `admin` or `operator` role.
3. Deploy customer consumers that require `authorization.version=1` and `fiducia-customer`.
4. Assign explicit `customer` where an operator genuinely needs both surfaces.
5. Remove the empty-role customer compatibility rule after the migration inventory reaches zero.

Do not let a reverse proxy or browser supply replacement authorization fields. The complete `/v1/me` response must come directly from the configured `fiducia-auth` service over the authenticated internal deployment path.
