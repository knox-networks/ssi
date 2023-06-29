fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(feature = "ci_ffi_build"))]
    {
        let out_dir = format!(
            "{}/{}",
            std::env::var("OUT_DIR").unwrap(),
            std::env::var("CARGO_PKG_NAME").unwrap(),
        );

        println!("cargo:warning={out_dir}");

        let package_path = "buf.build/knox-networks/registry-mgmt";
        let commit = "d65b89f5f58c4e2ca3d64401cf81b220";
        let std::process::Output { status, stderr, .. } = std::process::Command::new("buf")
            .arg("generate")
            .arg(format!("{package_path}:{commit}"))
            .arg("--output")
            .arg(out_dir)
            .output()?;
        if !status.success() {
            return Err(String::from_utf8_lossy(&stderr).into());
        }
        Ok(())
    }

    #[cfg(feature = "ci_ffi_build")]
    {
        Ok(())
    }
}
