#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]

//! `cashweb-payload` is a library for verifying [`payload::SignedPayload`], and converting it to
//! and from Protobuf.

pub mod error;
pub mod payload;
pub mod verify;

pub mod proto {
    //! Protobuf structs for SignedPayload.
    include!(concat!(env!("OUT_DIR"), "/cashweb.payload.rs"));
}
