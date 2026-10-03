# fiducia-auth.rs — task runner. Run `just` to see everything.
#
# Environment secrets live in env/enc/*.env.enc, encrypted with sops + age and
# committed to this repo. See env/README.md for the workflow.

# Exported assignments are always evaluated by Just, even if lazy evaluation is
# enabled later. Empty ignored directories do not survive Git, so prepare the
# owner-only plaintext boundary before parsing or running any recipe.
export FIDUCIA_ENV_DEC := ```
  set -eu
  command -v ores-sops >/dev/null 2>&1 || { echo "ores-sops is required to create env/dec" >&2; exit 1; }
  ores-sops ensure-dec >/dev/null
  root="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
  printf '%s' "$root/env/dec"
```

import '.just/env.just'

# Show available recipes.
default:
    @just --list
