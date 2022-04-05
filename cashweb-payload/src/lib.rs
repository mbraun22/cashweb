pub mod proto {
    //! Protobuf structs for data stored by the registry.
    include!(concat!(env!("OUT_DIR"), "/cashweb.payload.rs"));
}
