fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/route.proto");
    tonic_prost_build::configure().compile_protos(&["proto/route.proto"], &["proto"])?;
    Ok(())
}
