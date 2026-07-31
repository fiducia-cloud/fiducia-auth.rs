//! Reusable Fiducia authentication contracts.
//!
//! The primary `fiducia-auth` binary keeps its existing routing surface. This
//! library exposes the durable storage, token identity, and revocation modules
//! needed by the least-privilege revocation administration binary.

pub mod model;
pub mod revocation;
pub mod store;
pub mod token;
