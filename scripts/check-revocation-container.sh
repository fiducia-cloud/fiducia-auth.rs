#!/usr/bin/env bash
set -euo pipefail

image="${1:?usage: check-revocation-container.sh IMAGE}"

expected_user='65532:65532'
expected_entrypoint='["/usr/local/bin/fiducia-revocation-admin"]'

actual_user="$(docker image inspect --format '{{.Config.User}}' "$image")"
actual_entrypoint="$(docker image inspect --format '{{json .Config.Entrypoint}}' "$image")"
image_env="$(docker image inspect --format '{{json .Config.Env}}' "$image")"

if [[ "$actual_user" != "$expected_user" ]]; then
  printf 'expected image user %s, found %s\n' "$expected_user" "$actual_user" >&2
  exit 1
fi
if [[ "$actual_entrypoint" != "$expected_entrypoint" ]]; then
  printf 'expected entrypoint %s, found %s\n' "$expected_entrypoint" "$actual_entrypoint" >&2
  exit 1
fi
if grep -Eiq '(REVOCATION_(ADMIN|READER)_SECRET|FIDUCIA_INTERNAL_SECRET|ghp_|fdc_(live|test)_)' <<<"$image_env"; then
  printf 'image config contains a secret name/value marker: %s\n' "$image_env" >&2
  exit 1
fi

output_file="$(mktemp)"
trap 'rm -f "$output_file"' EXIT
set +e
docker run --rm "$image" >"$output_file" 2>&1
status=$?
set -e

if [[ $status -eq 0 ]]; then
  printf 'revocation-admin unexpectedly started without required credentials\n' >&2
  cat "$output_file" >&2
  exit 1
fi
if ! grep -Fq 'FIDUCIA_REVOCATION_ADMIN_SECRET must be configured' "$output_file"; then
  printf 'missing-credential smoke returned an unexpected error\n' >&2
  cat "$output_file" >&2
  exit 1
fi
if grep -Eiq '(ghp_[A-Za-z0-9]+|fdc_(live|test)_[A-Za-z0-9_.-]+|BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY)' "$output_file"; then
  printf 'container smoke output leaked a credential-shaped value\n' >&2
  cat "$output_file" >&2
  exit 1
fi

printf 'revocation-admin image contract passed for %s\n' "$image"
