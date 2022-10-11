fn main() -> Result<(), Box<dyn std::error::Error>> {
    let package_path = "buf.build/knox-networks/registry-mgmt";
    let std::process::Output { status, stderr, .. } = std::process::Command::new("buf")
        .arg("generate")
        .arg(package_path)
        .output()?;

    if !status.success() {
        return Err(String::from_utf8_lossy(&stderr).into());
    }

    Ok(())
}
