use std::path::PathBuf;

use protofetch::{cache::ProtofetchGitCache, model::protofetch::LockFile};
// #[cfg(not(feature = "protofetch"))]
// fn main() -> Result<(), Box<dyn std::error::Error>> {
//     let package_path = "buf.build/knox-networks/registry-mgmt";
//     let commit = "f7ff6f57030c418e886459a18b35645e";
//     let std::process::Output { status, stderr, .. } = std::process::Command::new("buf")
//         .arg("generate")
//         .arg(format!("{package_path}:{commit}"))
//         .output()?;

//     if !status.success() {
//         return Err(String::from_utf8_lossy(&stderr).into());
//     }

//     Ok(())
// }
// #[cfg(feature = "protofetch")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let fetch_cache = ProtofetchGitCache::new(PathBuf::from("~/.protofetch/cache"), None)?;
    protofetch::cli::command_handlers::do_fetch(
        false,
        &fetch_cache,
        &PathBuf::from("protofetch.toml"),
        &PathBuf::from("protofetch.lock"),
        &PathBuf::from("dependencies"),
        &PathBuf::from("./proto"),
    )?;
    let out_dir = std::path::PathBuf::from("./src/gen");
    std::fs::create_dir_all(&out_dir)?;

    tonic_build::configure().out_dir(&out_dir).compile(
        &["registry-mgmt/protos/registry_api/v1/registry.proto"],
        &["./proto"],
    )?;

    Ok(())
}
