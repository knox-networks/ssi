use bigerror::{BuildError, Report, ReportAs, Reportable};
use std::{env, path::PathBuf};

fn main() -> Result<(), Report<BuildError>> {
    let out_dir = env::var("OUT_DIR").unwrap();

    let proto_dir = PathBuf::from(&out_dir).join("protos");

    let std::process::Output {
        status,
        stderr,
        stdout,
        ..
    } = std::process::Command::new("protofetch")
        .env("RUST_LOG", "TRACE")
        .arg("--output-proto-directory")
        .arg(&proto_dir)
        .arg("fetch")
        .output()
        .report_as()?;

    println!(
        "protofetch stdout: {}",
        String::from_utf8_lossy(&stdout).into_owned()
    );
    println!(
        "protofetch stderr: {}",
        String::from_utf8_lossy(&stderr).into_owned()
    );

    if !status.success() {
        return Err(BuildError::attach(
            String::from_utf8_lossy(&stderr).into_owned(),
        ));
    }

    // The following protobuf binding setup is adapted from what is documented at
    // https://docs.rs/pbjson-build/latest/pbjson_build/  - note that `tonic_build`
    // accepts many of the same arguments as `prost_build` does in the documented example.

    let gen_out_dir = {
        let mut p = PathBuf::from(&out_dir);
        p.push("gen");
        p
    };
    std::fs::create_dir_all(&gen_out_dir).report_as()?;

    let descriptor_path = PathBuf::from(&out_dir).join("proto_descriptor.bin");

    let registry_proto = proto_dir.join("registry-mgmt/registry_api/v1/registry.proto");
    println!("registry proto: {}", registry_proto.display());

    tonic_build::configure()
        .out_dir(&gen_out_dir)
        .compile_well_known_types(true)
        .extern_path(".google.protobuf", "::pbjson_types")
        .file_descriptor_set_path(descriptor_path)
        .compile(&[registry_proto], &[proto_dir])
        .report_as()?;

    Ok(())
}
