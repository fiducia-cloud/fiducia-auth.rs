# workflows

GitHub Actions pipelines for fiducia-auth:

- `ci.yml` — build, test, and lint (rustfmt/clippy) on push and pull request.
  The sibling `fiducia-interfaces` checkout is pinned to the same immutable
  commit as the Dockerfile, and dependency-resolving Cargo commands require the
  committed lockfile. Formatting, Clippy, tests, and the pinned cargo-audit are
  mandatory gates; none is allowed to continue on failure.
- `docker.yml` — build and push the service container image on push to `main`,
  using only its immutable commit-SHA tag plus provenance and an SBOM.
  The Dockerfile fetches its interfaces dependency by full SHA, checks it out
  detached, and verifies the resulting `HEAD` before compiling with `--locked`;
  the publish workflow passes the same SHA explicitly.

This repository contains no environment credentials or rollout workflow;
deployment is owned by `fiducia-monorepo`.

## Security baseline

Every executable workflow uses explicit least-privilege permissions, immutable
third-party action or container references, non-persisted checkout credentials,
concurrency control, and a job timeout. The main CI workflow validates this
directory with the digest-pinned actionlint container. Environment mutation is
forbidden unless this README documents a repository-specific platform exception.
