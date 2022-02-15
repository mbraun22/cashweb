use std::io::Result;

fn main() -> Result<()> {
    prost_build::compile_protos(&["proto/database.proto"], &["proto/"])?;
    Ok(())
}
