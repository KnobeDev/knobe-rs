//! KNOBE Protocol v1 in Rust: a verifier that reproduces `lens.py` (the
//! reference) verdict-for-verdict, and a sealer that reproduces
//! `knobe-core.js` `createKnobe` byte-for-byte.
//!
//! A match proves integrity, not truth. A `valid` proves conformance, not
//! truth. Inspect before trusting.

pub mod canon;
pub mod json;
pub mod pyfmt;
pub mod seal;
pub mod verify;

mod b64;
mod conformance;
mod pyprintable;

pub use json::Value;
pub use seal::{CreateOptions, Created, SealError, create_knobe, seal};
pub use verify::{Report, verify_bytes, verify_path};

/// Spec versions this implementation can honestly verify.
pub const SUPPORTED_SPEC_VERSIONS: &[&str] = &["1.0"];
