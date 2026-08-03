#!/usr/bin/env bash
set -euo pipefail

workflow='.github/workflows/docker.yml'
documentation='docs/revocation-container.md'

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
  '[[ ! "$DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]]' \
  '[[ ! "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]]' \
  'immutable_ref="${IMAGE}@${DIGEST}"' \
  '<!-- fiducia-oci-release:${SOURCE_SHA}:${TARGET} -->' \
  '"digest":"${DIGEST}"' \
  '"ref":"${immutable_ref}"' \
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

if grep -Eiq '(ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|CR_PAT|PERSONAL_ACCESS_TOKEN|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)' "$workflow"; then
  printf 'docker publication workflow contains a long-lived credential marker\n' >&2
  exit 1
fi

if grep -Eq 'issues:[[:space:]]*write' .github/workflows/ci.yml; then
  printf 'PR CI must not receive issue-write permission\n' >&2
  exit 1
fi

printf 'OCI digest publication contract passed\n'
