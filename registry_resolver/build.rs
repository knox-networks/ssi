fn main() -> Result<(), Box<dyn std::error::Error>> {
    let package_path = "buf.build/knox-networks/registry-mgmt";
    let commit = "addbc87cc6424f7ab40534825fa0cb70";
    let std::process::Output { status, stderr, .. } = std::process::Command::new("buf")
        .arg("generate")
        .arg(format!("{package_path}:{commit}"))
        .arg("--output")
        .arg(std::env::var("OUT_DIR").unwrap())
        .output()?;
    if !status.success() {
        return Err(String::from_utf8_lossy(&stderr).into());
    }
    Ok(())
}
