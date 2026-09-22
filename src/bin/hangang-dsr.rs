//! Standalone, explicitly scoped IPVS direct-routing companion.
use anyhow::{Context, Result, ensure};
use clap::Parser;
use hangang::dsr::{self, Config, MAX_CONFIG_BYTES};
use std::{io::Read, path::PathBuf};

#[derive(Parser, Debug)]
#[command(
    name = "hangang-dsr",
    version,
    about = "Validate and reconcile owned Linux IPVS DSR services"
)]
struct Args {
    /// Strict JSON file containing only the explicitly owned VIP services.
    #[arg(long)]
    config: PathBuf,
    /// Apply the configured services. Requires Linux IPVS and ipvsadm.
    #[arg(long, conflicts_with_all = ["cleanup", "check"])]
    apply: bool,
    /// Remove only configured VIP/port services.
    #[arg(long, conflicts_with_all = ["apply", "check"])]
    cleanup: bool,
    /// Validate JSON and print the bounded reconciliation plan.
    #[arg(long, conflicts_with_all = ["apply", "cleanup"])]
    check: bool,
}

fn read_config(path: &std::path::Path) -> Result<Config> {
    ensure!(path.is_absolute(), "--config requires an absolute path");
    let metadata = std::fs::symlink_metadata(path).context("inspect config")?;
    ensure!(metadata.is_file(), "config must be a regular file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode() & 0o077 == 0,
            "config must not be accessible by group or other users"
        );
    }
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let mut file = options.open(path).context("open config")?;
    let opened = file.metadata()?;
    ensure!(
        opened.is_file(),
        "config is not a regular file after opening"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            opened.permissions().mode() & 0o077 == 0,
            "opened config must not be accessible by group or other users"
        );
    }
    let mut bytes = Vec::with_capacity(4096);
    file.by_ref()
        .take((MAX_CONFIG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= MAX_CONFIG_BYTES,
        "config exceeds {} bytes",
        MAX_CONFIG_BYTES
    );
    let config = serde_json::from_slice::<Config>(&bytes).context("parse strict DSR JSON")?;
    config.validate()?;
    Ok(config)
}

fn main() -> Result<()> {
    let args = Args::parse();
    ensure!(
        args.apply || args.cleanup || args.check,
        "select exactly one of --check, --apply, or --cleanup"
    );
    let config = read_config(&args.config)?;
    if args.check {
        println!("{}", serde_json::to_string_pretty(&config.plan())?);
    } else if args.apply {
        dsr::apply(&config).context("apply scoped IPVS DSR configuration")?;
    } else {
        dsr::cleanup(&config).context("cleanup scoped IPVS DSR configuration")?;
    }
    Ok(())
}
