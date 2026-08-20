# syntax=docker/dockerfile:1
# Multi-stage build for the customer auth server and the separately deployed
# least-privilege revocation authority. The final default target remains `auth`
# so existing `docker build .` callers preserve their current image contract.
FROM rust:1.97.1-slim-bookworm@sha256:2775a09d208ff0d7c1f50490c45b62db929e87ba1dcbc3f2132ac71a704bcdd3 AS build
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

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e AS runtime
USER 65532:65532

# Explicit target for the private revocation control plane. It contains no Git,
# compiler, package manager, source tree, or shell and starts only the reviewed
# binary. Kubernetes supplies its distinct reader/writer credentials at runtime.
FROM runtime AS revocation-admin
COPY --from=build --chown=65532:65532 /build/fiducia-auth.rs/target/release/fiducia-revocation-admin /usr/local/bin/fiducia-revocation-admin
EXPOSE 8098
ENTRYPOINT ["/usr/local/bin/fiducia-revocation-admin"]

# Keep this stage last: it is the backward-compatible default image target.
FROM runtime AS auth
COPY --from=build --chown=65532:65532 /build/fiducia-auth.rs/target/release/fiducia-auth /usr/local/bin/fiducia-auth
COPY --from=build --chown=65532:65532 /build/fiducia-auth.rs/target/release/fiducia-auth-production-entrypoint /usr/local/bin/fiducia-auth-production-entrypoint
EXPOSE 8097
ENTRYPOINT ["/usr/local/bin/fiducia-auth-production-entrypoint"]
