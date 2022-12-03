use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(
        &["proto/registry.proto", "proto/broadcast.proto"],
        &["proto/", "../cashweb-payload/proto/"],
    )?;
    Ok(())
}
