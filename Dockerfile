# syntax=docker/dockerfile:1
# Multi-stage build for fiducia-auth.
FROM rust:1-slim-bookworm AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates
WORKDIR /build
ARG INTERFACES_REF=main
RUN git clone --depth 1 --branch "$INTERFACES_REF" \
    https://github.com/fiducia-cloud/fiducia-interfaces.git fiducia-interfaces
COPY . fiducia-auth.rs
WORKDIR /build/fiducia-auth.rs
RUN cargo build --release && strip target/release/fiducia-auth

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build --chown=65532:65532 /build/fiducia-auth.rs/target/release/fiducia-auth /usr/local/bin/fiducia-auth
EXPOSE 8097
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/fiducia-auth"]
