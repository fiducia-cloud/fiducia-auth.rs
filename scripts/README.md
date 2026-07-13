# scripts

Helper scripts for working with the crate.

- `with-flags2env.sh` — bridges CLI flags to the `FIDUCIA_*` / `SUPABASE_*`
  environment variables the `fiducia-auth` binary reads. It runs the pinned
  `flags2env` parser against the `.cli-flags.toml` schema, exports the resulting
  env map, then execs the given command (e.g. `cargo run`).
