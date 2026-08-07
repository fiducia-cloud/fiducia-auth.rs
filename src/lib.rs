//! Reusable Fiducia authentication contracts.
//!
//! The primary `fiducia-auth` binary keeps its existing routing surface. This
//! library exposes the durable storage, token identity, revocation authority,
//! and fail-closed verifier-cache modules used by least-privilege consumers.

pub mod cache;
pub mod gate;
pub mod model;
pub mod revocation;
pub mod revocation_cache;
pub mod store;
pub mod token;
