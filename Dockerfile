# syntax=docker/dockerfile:1
# Multi-stage build for fiducia-auth.
FROM rust:1.97.1-slim-bookworm@sha256:99e09cb2284e2ddbb73a995deee3e91783fd04d177602ccf6eab326d778ee777 AS build
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
    && strip target/release/fiducia-auth \
       target/release/fiducia-auth-production-entrypoint

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:fccdbb0a547c14e23fcf4ce8ad62ca5d43b4faae8d22cd292f490fef9946c96e
COPY --from=build --chown=65532:65532 /build/fiducia-auth.rs/target/release/fiducia-auth /usr/local/bin/fiducia-auth
COPY --from=build --chown=65532:65532 /build/fiducia-auth.rs/target/release/fiducia-auth-production-entrypoint /usr/local/bin/fiducia-auth-production-entrypoint
EXPOSE 8097
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/fiducia-auth-production-entrypoint"]
