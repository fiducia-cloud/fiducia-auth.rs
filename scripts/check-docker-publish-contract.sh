#!/usr/bin/env bash
set -euo pipefail

workflow='.github/workflows/docker.yml'
documentation='docs/revocation-container.md'
renderer='scripts/render-oci-release-ledger-entry.sh'

require_literal() {
  local file="$1"
  local literal="$2"
  if ! grep -Fq -- "$literal" "$file"; then
    printf 'missing required publication contract in %s: %s\n' "$file" "$literal" >&2
    exit 1
  fi
}

for required in \
  'issues: write # Required only to append validated image digests to issue 38.' \
  '- id: build' \
  'DIGEST: ${{ steps.build.outputs.digest }}' \
  'RELEASE_LEDGER_ISSUE: "38"' \
  'bash scripts/render-oci-release-ledger-entry.sh' \
  'gh issue comment "$RELEASE_LEDGER_ISSUE"' \
  'org.opencontainers.image.source=https://github.com/${{ github.repository }}' \
  'org.opencontainers.image.revision=${{ github.sha }}'
do
  require_literal "$workflow" "$required"
done

for required in \
  'OCI release digest ledger' \
  'fiducia-auth.rs/issues/38' \
  'image@sha256' \
  'workflow-scoped `GITHUB_TOKEN`'
do
  require_literal "$documentation" "$required"
done

for required in \
  '[[ ! "$source_sha" =~ ^[0-9a-f]{40}$ ]]' \
  '[[ ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]' \
  "expected_image='ghcr.io/fiducia-cloud/fiducia-auth'" \
  "expected_image='ghcr.io/fiducia-cloud/fiducia-revocation-admin'" \
  'immutable_ref="${image}@${digest}"' \
  "printf '<!-- fiducia-oci-release:%s:%s -->\\n'" \
  '"digest":"%s"' \
  '"ref":"%s"'
do
  require_literal "$renderer" "$required"
done

if grep -Eiq '(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|CR_PAT|PERSONAL_ACCESS_TOKEN|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)' "$workflow" "$renderer"; then
  printf 'OCI publication path contains a long-lived credential marker\n' >&2
  exit 1
fi

if grep -Eq 'issues:[[:space:]]*write' .github/workflows/ci.yml; then
  printf 'PR CI must not receive issue-write permission\n' >&2
  exit 1
fi

sample_sha='0123456789abcdef0123456789abcdef01234567'
sample_digest='sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef'
sample_image='ghcr.io/fiducia-cloud/fiducia-revocation-admin'
sample_ref="${sample_image}@${sample_digest}"
output="$(bash "$renderer" \
  'fiducia-cloud/fiducia-auth.rs' \
  "$sample_sha" \
  'revocation-admin' \
  "$sample_image" \
  "$sample_digest")"

for exact in \
  "<!-- fiducia-oci-release:${sample_sha}:revocation-admin -->" \
  '```json' \
  "{\"repository\":\"fiducia-cloud/fiducia-auth.rs\",\"source_sha\":\"${sample_sha}\",\"target\":\"revocation-admin\",\"image\":\"${sample_image}\",\"digest\":\"${sample_digest}\",\"ref\":\"${sample_ref}\"}" \
  '```'
do
  if ! grep -Fxq -- "$exact" <<<"$output"; then
    printf 'renderer output missing exact line: %s\n' "$exact" >&2
    exit 1
  fi
done

expect_failure() {
  if bash "$renderer" "$@" >/dev/null 2>&1; then
    printf 'renderer unexpectedly accepted invalid metadata\n' >&2
    exit 1
  fi
}

expect_failure \
  'fiducia-cloud/fiducia-auth.rs' \
  'not-a-commit' \
  'revocation-admin' \
  "$sample_image" \
  "$sample_digest"
expect_failure \
  'fiducia-cloud/fiducia-auth.rs' \
  "$sample_sha" \
  'revocation-admin' \
  "$sample_image" \
  'sha256:ABCDEF'
expect_failure \
  'fiducia-cloud/fiducia-auth.rs' \
  "$sample_sha" \
  'revocation-admin' \
  'ghcr.io/fiducia-cloud/fiducia-auth' \
  "$sample_digest"
expect_failure \
  'fiducia-cloud/fiducia-auth.rs' \
  "$sample_sha" \
  'unexpected-target' \
  "$sample_image" \
  "$sample_digest"
expect_failure \
  'fiducia-cloud/fiducia-auth.rs;echo-pwned' \
  "$sample_sha" \
  'revocation-admin' \
  "$sample_image" \
  "$sample_digest"

printf 'OCI digest publication contract passed\n'
