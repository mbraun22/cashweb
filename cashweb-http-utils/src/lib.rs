#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]

//! `cashweb-http-utils` is a crate providing utils for CashWeb HTTP servers.

pub mod error;
pub mod protobuf;
pub mod validation;

pub mod proto {
    //! Protobuf structs for SignedPayload.
    include!(concat!(env!("OUT_DIR"), "/cashweb.http.rs"));
}
