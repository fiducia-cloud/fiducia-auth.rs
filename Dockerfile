# syntax=docker/dockerfile:1
# Multi-stage build for fiducia-auth (no shared-crate dependency).
FROM rust:1-slim-bookworm AS build
WORKDIR /build/fiducia-auth.rs
COPY . .
RUN cargo build --release && strip target/release/fiducia-auth

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && useradd --uid 10001 --user-group --home-dir /nonexistent --shell /usr/sbin/nologin fiducia
COPY --from=build --chown=10001:10001 /build/fiducia-auth.rs/target/release/fiducia-auth /usr/local/bin/fiducia-auth
EXPOSE 8097
USER 10001:10001
ENTRYPOINT ["/usr/local/bin/fiducia-auth"]
