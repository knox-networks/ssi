fn main() -> Result<(), Box<dyn std::error::Error>> {
    let package_path = "buf.build/knox-networks/registry-mgmt";
    let commit = "f7ff6f57030c418e886459a18b35645e";
    let std::process::Output { status, stderr, .. } = std::process::Command::new("/usr/local/bin/buf")
        .arg("generate")
        .arg(format!("{package_path}:{commit}"))
        .output()?;

    if !status.success() {
        return Err(String::from_utf8_lossy(&stderr).into());
    }

    Ok(())
}
