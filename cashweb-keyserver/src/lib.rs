#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]

//! `cashweb-keyserver` is a library for hosting a CashWeb keyserver.
//! It allows storing and retrieving metadata by addresses (scripts).

pub mod store;

pub mod proto {
    //! Protobuf structs for data stored by the keyserver.
    include!(concat!(env!("OUT_DIR"), "/cashweb.database.rs"));
}
