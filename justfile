# fiducia-auth.rs — task runner. Run `just` to see everything.
#
# Environment secrets live in env/enc/*.env.enc, encrypted with sops + age and
# committed to this repo. See env/README.md for the workflow.

# Exported assignments are always evaluated by Just, even if lazy evaluation is
# enabled later. Empty ignored directories do not survive Git, so prepare the
# owner-only plaintext boundary before parsing or running any recipe.
export FIDUCIA_ENV_DEC := ```
  set -eu
  root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
  if [ -L "$root/env" ] || [ -L "$root/env/dec" ]; then
    echo "refusing to prepare symlinked env/dec" >&2
    exit 1
  fi
  umask 077
  mkdir -p "$root/env/dec"
  chmod 700 "$root/env/dec"
  printf '%s' "$root/env/dec"
```

import '.just/env.just'

# Show available recipes.
default:
    @just --list
