use anyhow::{Context, anyhow};
use aya_build::{Package, Toolchain, build_ebpf};
use cargo_metadata::MetadataCommand;

fn main() -> anyhow::Result<()> {
    let metadata = MetadataCommand::new()
        .no_deps()
        .exec()
        .context("Cargo-Workspace-Metadaten konnten nicht gelesen werden")?;

    let ebpf_package = metadata
        .packages
        .iter()
        .find(|package| package.name == "detector-ebpf")
        .ok_or_else(|| anyhow!("Workspace-Paket detector-ebpf wurde nicht gefunden"))?;

    let ebpf_root = ebpf_package
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("Ungültiger manifest_path für detector-ebpf"))?
        .to_string();

    let package = Package {
        name: "detector-ebpf",
        root_dir: ebpf_root.as_str(),
        no_default_features: true,
        features: &[],
    };

    std::env::set_var("CARGO_PROFILE_RELEASE_PANIC", "abort");
    build_ebpf([package], Toolchain::Nightly)
        .context("eBPF-Build mit aya-build ist fehlgeschlagen")?;

    println!("cargo:rerun-if-changed=../detector-ebpf/src");
    println!("cargo:rerun-if-changed=../detector-common/src");
    println!("cargo:rerun-if-changed=../detector-ebpf/Cargo.toml");
    Ok(())
}
