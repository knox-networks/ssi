use bigerror::{BuildError, Report, ReportAs};
use std::{env, path::PathBuf};

fn main() -> Result<(), Report<BuildError>> {
    let out_dir = env::var("OUT_DIR").report_as()?;

    let out_dir = PathBuf::from(out_dir);
    let gen_dir = &out_dir.join("gen/pb");
    std::fs::create_dir_all(gen_dir).report_as()?;

    let descriptor_path = PathBuf::from(&out_dir).join("registry_resolver.bin");

    // The following protobuf binding setup is adapted from what is documented at
    // https://docs.rs/pbjson-build/latest/pbjson_build/  - note that `tonic_build`
    // accepts many of the same arguments as `prost_build` does in the documented example.
    tonic_build::configure()
        .out_dir(gen_dir)
        .compile_well_known_types(true)
        .extern_path(".google.protobuf", "::pbjson_types")
        .file_descriptor_set_path(descriptor_path)
        .compile(
            &["protos/registry-mgmt/registry_api/v1/registry.proto"],
            &["protos"],
        )
        .report_as()?;

    Ok(())
}
