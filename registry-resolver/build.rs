fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/registry.proto");

    let out_dir = std::path::PathBuf::from("./target/proto");

    // create the target directory if it does not exist.
    std::fs::create_dir_all(&out_dir)?;

    tonic_build::configure()
        .out_dir(out_dir.clone())
        .file_descriptor_set_path(out_dir.join("registry_descriptor.bin"))
        .build_server(true)
        .compile(&["./proto/registry.proto"], &["./proto"])?;

    Ok(())
}
