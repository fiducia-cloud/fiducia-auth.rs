# syntax=docker/dockerfile:1
# Multi-stage build for the customer auth server and the separately deployed
# least-privilege revocation authority. The final default target remains `auth`
# so existing `docker build .` callers preserve their current image contract.
FROM rust:1.98.0-slim-bookworm@sha256:1469a27c125cb5a3aebfa4f4e4665d935b02fb72cc093b2c974b3d740e43f157 AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates
WORKDIR /build
# Immutable cross-repository input. Bump this SHA together with the CI checkout.
ARG INTERFACES_SHA=bd718cd72d72aa330534f3688f8fb1ce90c19d10
RUN git init fiducia-interfaces \
    && git -C fiducia-interfaces remote add origin \
       https://github.com/fiducia-cloud/fiducia-interfaces.git \
    && git -C fiducia-interfaces fetch --depth 1 origin "$INTERFACES_SHA" \
    && git -C fiducia-interfaces checkout --detach FETCH_HEAD \
    && test "$(git -C fiducia-interfaces rev-parse HEAD)" = "$INTERFACES_SHA"
COPY . fiducia-auth.rs
WORKDIR /build/fiducia-auth.rs
RUN cargo build --locked --release \
       --bin fiducia-auth \
       --bin fiducia-auth-production-entrypoint \
       --bin fiducia-revocation-admin \
    && strip target/release/fiducia-auth \
       target/release/fiducia-auth-production-entrypoint \
       target/release/fiducia-revocation-admin

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f AS runtime
USER 65532:65532

# Explicit target for the private revocation control plane. It contains no Git,
# compiler, package manager, source tree, or shell and starts only the reviewed
# binary. Kubernetes supplies its distinct reader/writer credentials at runtime.
FROM runtime AS revocation-admin
COPY --from=build --chown=65532:65532 /build/fiducia-auth.rs/target/release/fiducia-revocation-admin /usr/local/bin/fiducia-revocation-admin
EXPOSE 8098
# --- sops: this final stage has no shell (distroless/scratch), so runtime
# decryption cannot run inside the container. Inject secrets HOST-SIDE at
# `docker run` instead — never at build, never as --build-arg:
#     just env-docker-run prod <image>        # decrypts env/enc/prod.env.enc
#                                             # and passes --env-file, no plaintext on disk
# or render a platform secret from the same ciphertext. See env/README.md.
ENTRYPOINT ["/usr/local/bin/fiducia-revocation-admin"]

# Keep this stage last: it is the backward-compatible default image target.
FROM runtime AS auth
COPY --from=build --chown=65532:65532 /build/fiducia-auth.rs/target/release/fiducia-auth /usr/local/bin/fiducia-auth
COPY --from=build --chown=65532:65532 /build/fiducia-auth.rs/target/release/fiducia-auth-production-entrypoint /usr/local/bin/fiducia-auth-production-entrypoint
EXPOSE 8097
# --- sops: this final stage has no shell (distroless/scratch), so runtime
# decryption cannot run inside the container. Inject secrets HOST-SIDE at
# `docker run` instead — never at build, never as --build-arg:
#     just env-docker-run prod <image>        # decrypts env/enc/prod.env.enc
#                                             # and passes --env-file, no plaintext on disk
# or render a platform secret from the same ciphertext. See env/README.md.
ENTRYPOINT ["/usr/local/bin/fiducia-auth-production-entrypoint"]
