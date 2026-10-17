fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/decision.proto");
    prost_build::Config::new().compile_protos(&["proto/decision.proto"], &["proto"])?;
    Ok(())
}
