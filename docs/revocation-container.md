# Immutable revocation-admin container

`fiducia-revocation-admin` is a separate least-privilege control-plane process. It must not run from the customer auth image entrypoint, clone source, compile code, or install packages at Pod startup.

## Build targets

The repository Dockerfile has two explicit runtime targets built from the same pinned Rust builder, generated-interface commit, source tree, and `Cargo.lock`:

```sh
docker build \
  --target auth \
  --build-arg INTERFACES_SHA=bd718cd72d72aa330534f3688f8fb1ce90c19d10 \
  -t fiducia-auth:local .

docker build \
  --target revocation-admin \
  --build-arg INTERFACES_SHA=bd718cd72d72aa330534f3688f8fb1ce90c19d10 \
  -t fiducia-revocation-admin:local .
```

The default final target remains `auth`, preserving the existing `docker build .` contract.

The revocation target contains only the stripped `fiducia-revocation-admin` binary and the digest-pinned distroless C runtime. It runs as `65532:65532`, exposes port 8098, and has this exact entrypoint:

```text
/usr/local/bin/fiducia-revocation-admin
```

It contains no Git client, compiler, source checkout, package manager, or shell. Runtime credentials are injected by the deployment platform and are never image build arguments, labels, or environment defaults.

## Fail-closed smoke

Run the committed contract check after building the target:

```sh
bash scripts/check-revocation-container.sh fiducia-revocation-admin:local
```

The smoke verifies the non-root identity and exact entrypoint, rejects credential markers in the image configuration, and proves the process exits nonzero when the required writer credential is absent. The check asserts only the expected configuration error name; it never supplies or prints a credential value.

A healthy HTTP smoke requires a real or controlled Fiducia KV endpoint plus distinct writer and reader credentials. That belongs to deployment integration and is not simulated by weakening startup requirements in image CI.

## Publication

On `main`, `.github/workflows/docker.yml` publishes two independent commit-SHA tags:

```text
ghcr.io/fiducia-cloud/fiducia-auth:<commit-sha>
ghcr.io/fiducia-cloud/fiducia-revocation-admin:<commit-sha>
```

Both use BuildKit SBOM generation and maximum provenance. Each image carries OCI source, revision, and title labels. GitOps must resolve the revocation image to the registry digest produced by the reviewed commit and pin that digest in the workload manifest. A mutable tag alone is not a deployment identity.

The publisher validates the `docker/build-push-action` digest as exactly `sha256:` plus 64 lowercase hexadecimal characters, then appends a machine-readable record to the [OCI release digest ledger](https://github.com/fiducia-cloud/fiducia-auth.rs/issues/38):

```json
{"repository":"fiducia-cloud/fiducia-auth.rs","source_sha":"<40-hex-commit>","target":"revocation-admin","image":"ghcr.io/fiducia-cloud/fiducia-revocation-admin","digest":"sha256:<64-hex-digest>","ref":"ghcr.io/fiducia-cloud/fiducia-revocation-admin@sha256:<64-hex-digest>"}
```

GitOps automation must select the record whose `source_sha` and `target` match the reviewed release and copy the exact `ref` value. Workflow retries may append an identical record; identical `(source_sha, target, digest)` tuples are equivalent.

The ledger write uses only the workflow-scoped `GITHUB_TOKEN`. The publishing job receives `packages: write` and `issues: write`; ordinary PR CI remains `contents: read` only. No personal access token, registry password, runtime credential, token claim, tenant identifier, or subject is written to the ledger.

Validate this contract locally with:

```sh
bash scripts/check-docker-publish-contract.sh
```

## GitOps follow-up

The pending deployment must replace its Rust builder image and startup-time Git/cargo script with the published revocation `image@sha256` reference. After that replacement, remove public HTTP(S) bootstrap egress from the revocation authority NetworkPolicy. The load balancer receives only the reader credential; writer access remains restricted to a separately reviewed operator or break-glass path.

This repository change creates the immutable artifact and release-metadata contract. It does not by itself prove registry publication, Argo CD rollout, live authority health, credential rotation, two-verifier propagation, or production fault behavior.
Both use BuildKit SBOM generation and maximum provenance. GitOps must resolve the revocation image to the registry digest produced by the reviewed commit and pin that digest in the workload manifest. A mutable tag alone is not a deployment identity.

## GitOps follow-up

The pending deployment must replace its Rust builder image and startup-time Git/cargo script with the published revocation image digest. After that replacement, remove public HTTP(S) bootstrap egress from the revocation authority NetworkPolicy. The load balancer receives only the reader credential; writer access remains restricted to a separately reviewed operator or break-glass path.

This repository change creates the immutable artifact contract. It does not by itself prove registry publication, Argo CD rollout, live authority health, credential rotation, two-verifier propagation, or production fault behavior.
