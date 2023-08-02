fn main() -> Result<(), Box<dyn std::error::Error>> {
    let package_path = "buf.build/knox-networks/registry-mgmt";
    let commit = "e36fc74230bb4af7b49588108dc2531a";
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
