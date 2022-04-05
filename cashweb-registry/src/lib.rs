#![warn(
    missing_debug_implementations,
    missing_docs,
    rust_2018_idioms,
    unreachable_pub
)]

//! `cashweb-registry` is a library for the Registry part of a CashWeb server.
//! It allows storing and retrieving metadata by addresses (scripts).

pub mod store;
