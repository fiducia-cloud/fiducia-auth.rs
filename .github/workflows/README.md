# workflows

GitHub Actions pipelines for fiducia-auth:

- `ci.yml` — build, test, and lint (rustfmt/clippy) on push and pull request.
  The sibling `fiducia-interfaces` checkout is pinned to the same immutable
  commit as the Dockerfile, and dependency-resolving Cargo commands require the
  committed lockfile. Formatting, Clippy, tests, and the pinned cargo-audit are
  mandatory gates; none is allowed to continue on failure.
- `docker.yml` — build and push the service container image on push to `main`.
  The Dockerfile fetches its interfaces dependency by full SHA, checks it out
  detached, and verifies the resulting `HEAD` before compiling with `--locked`;
  the publish workflow passes the same SHA explicitly.
- `deploy-test.yml` — fail-closed TEST rollout: it requires `KUBE_CONFIG_TEST`,
  an existing deployment, and a successful rollout.
