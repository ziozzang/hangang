//! Stable-PID process owner. Listening sockets pass through this supervisor;
//! accepted streams remain in the draining generation.
use crate::restart::{
    ControlChannel, ControlMessage as Control, ProtocolMessage, ReceivedDescriptor, control_channel,
};
use anyhow::{Context, Result, bail, ensure};
use std::{ffi::OsString, os::fd::AsFd, path::PathBuf, time::Duration};
use tokio::process::{Child, Command};

pub struct UpdateOptions {
    pub manifest_url: Option<String>,
    pub github: bool,
    pub public_key: String,
    pub additional_ca: Option<PathBuf>,
    pub interval: Duration,
    pub status_path: PathBuf,
}
#[derive(serde::Serialize, serde::Deserialize)]
pub struct UpdateStatus {
    pub enabled: bool,
    pub phase: String,
    pub current_version: String,
    pub last_check_unix: u64,
    pub detail: Option<String>,
    /// Automatic rollbacks since this status file was created: an update was
    /// activated on disk, the new generation failed to take over, and the
    /// previous executable was restored.
    #[serde(default)]
    pub rollbacks_total: u64,
    /// Fixed-vocabulary reason for the most recent rollback (no URLs or
    /// paths; details stay in protected logs).
    #[serde(default)]
    pub last_rollback_reason: Option<String>,
    /// Unix time of the most recent rollback; 0 when none happened.
    #[serde(default)]
    pub last_rollback_unix: u64,
}

/// Every phase the updater reports, in `hangang_update_phase` order.
pub const UPDATE_PHASES: [&str; 6] = [
    "idle",
    "checking",
    "active",
    "up_to_date",
    "rejected",
    "rolled_back",
];

/// Reason recorded when the candidate generation fails to take over.
pub const ROLLBACK_REASON_HANDOFF: &str =
    "candidate generation failed to take over; previous executable restored";

/// Marks an update error after which the previous executable was restored.
#[derive(Debug)]
pub struct RolledBack;
impl std::fmt::Display for RolledBack {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("update rolled back")
    }
}

impl UpdateStatus {
    pub fn initial(enabled: bool) -> Self {
        Self {
            enabled,
            phase: "idle".into(),
            current_version: env!("CARGO_PKG_VERSION").into(),
            last_check_unix: 0,
            detail: None,
            rollbacks_total: 0,
            last_rollback_reason: None,
            last_rollback_unix: 0,
        }
    }

    /// Record an automatic rollback.
    pub fn record_rollback(&mut self, reason: &str, now_unix: u64) {
        self.phase = "rolled_back".into();
        self.detail = Some(reason.into());
        self.rollbacks_total = self.rollbacks_total.saturating_add(1);
        self.last_rollback_reason = Some(reason.into());
        self.last_rollback_unix = now_unix;
    }

    /// Prometheus lines: `hangang_update_rollbacks_total`, the last rollback
    /// time and `hangang_update_phase{phase=...}` (1 for the current phase).
    pub fn render_metrics(&self, out: &mut String) {
        use std::fmt::Write;
        let _ = write!(
            out,
            "# HELP hangang_update_rollbacks_total Automatic update rollbacks.\n# TYPE hangang_update_rollbacks_total counter\nhangang_update_rollbacks_total {}\n# HELP hangang_update_last_rollback_unix Unix time of the last automatic rollback (0 = none).\n# TYPE hangang_update_last_rollback_unix gauge\nhangang_update_last_rollback_unix {}\n# HELP hangang_update_phase Current updater phase (1 for the active phase).\n# TYPE hangang_update_phase gauge\n",
            self.rollbacks_total, self.last_rollback_unix
        );
        for phase in UPDATE_PHASES {
            let _ = writeln!(
                out,
                "hangang_update_phase{{phase=\"{phase}\"}} {}",
                u8::from(self.phase == phase)
            );
        }
    }
}

/// Read a supervisor status file written by `persist_status`.
pub fn load_status(path: &std::path::Path) -> Result<UpdateStatus> {
    use std::io::Read;
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(65537)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 65536, "update status too large");
    Ok(crate::input_json::from_slice(&bytes)?)
}
fn persist_status(path: &std::path::Path, status: &UpdateStatus) -> Result<()> {
    use std::io::Write;
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(&serde_json::to_vec(status)?)?;
    file.as_file().sync_all()?;
    file.persist(path)?;
    Ok(())
}

const PHASE_TIMEOUT: Duration = Duration::from_secs(15);
struct Generation {
    child: Child,
    channel: ControlChannel,
}
impl Generation {
    fn spawn(executable: &PathBuf, arguments: &[OsString]) -> Result<Self> {
        let (parent, child_channel) = control_channel()?;
        let fd = child_channel.as_raw_fd();
        let mut command = Command::new(executable);
        command
            .args(arguments)
            .arg("--serve-child")
            .env("HANGANG_CONTROL_FD", fd.to_string())
            .kill_on_drop(true);
        // Only this dedicated control descriptor crosses exec. Rust listeners,
        // files and received SCM_RIGHTS descriptors remain CLOEXEC.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                #[cfg(target_os = "linux")]
                if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGTERM) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().context("spawn gateway generation")?;
        drop(child_channel);
        Ok(Self {
            child,
            channel: parent,
        })
    }
    async fn expect(&self, expected: Control) -> Result<()> {
        let channel = self.channel.try_clone()?;
        let message =
            tokio::task::spawn_blocking(move || channel.recv_timeout(PHASE_TIMEOUT)).await??;
        ensure!(
            matches!(message,ProtocolMessage::Control(actual) if actual==expected),
            "unexpected lifecycle handshake"
        );
        Ok(())
    }
    /// Retire a generation whose successor is serving: close its accept
    /// loops at once and let in-flight streams drain. Readiness is not
    /// withdrawn, so probes on connections it still owns keep answering for
    /// the (healthy) endpoint.
    async fn stop(&mut self, grace: Duration) {
        let _ = self.channel.send_control(Control::Drain);
        if tokio::time::timeout(grace + Duration::from_secs(2), self.child.wait())
            .await
            .is_err()
        {
            let _ = self.child.kill().await;
        }
    }

    /// Endpoint shutdown: withdraw readiness first while the generation keeps
    /// accepting for `lame_duck` (so a load balancer observes 503 and stops
    /// routing), then drain. The kill deadline covers both phases.
    async fn shutdown(&mut self, grace: Duration, lame_duck: Duration) {
        // Always withdraw explicitly, so the generation can tell an endpoint
        // shutdown from a retirement behind a successor even with no window.
        let _ = self.channel.send_control(Control::Withdraw);
        if !lame_duck.is_zero() {
            tokio::time::sleep(lame_duck).await;
        }
        self.stop(grace).await;
    }
}

pub async fn run(
    executable: PathBuf,
    arguments: Vec<OsString>,
    grace: Duration,
    lame_duck: Duration,
    update: Option<UpdateOptions>,
) -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
    let mut restart = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut update_status = UpdateStatus::initial(update.is_some());
    if let Some(options) = &update {
        persist_status(&options.status_path, &update_status)?;
    }
    let mut active = Generation::spawn(&executable, &arguments)?;
    active.channel.send_control(Control::Commit)?;
    if let Err(error) = active.expect(Control::Ready).await {
        active.stop(Duration::ZERO).await;
        return Err(error);
    }
    let mut draining: Vec<Generation> = Vec::new();
    let mut version = semver::Version::parse(env!("CARGO_PKG_VERSION"))?;
    let mut next_update = tokio::time::Instant::now();
    let mut terminal_error = None;
    let mut interrupted = false;

    loop {
        let channel = active.channel.try_clone()?;
        // Never cancel a blocking channel read: a detached reader could steal
        // the next export descriptor after SIGHUP and corrupt the handshake.
        let received =
            tokio::task::spawn_blocking(move || channel.recv_timeout(Duration::from_millis(100)))
                .await?;
        let pending = match received {
            Ok(ProtocolMessage::Control(control)) => Some(control),
            Ok(_) => {
                tracing::warn!("unsolicited lifecycle descriptor");
                Some(Control::Ready)
            }
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Some(Control::Ready),
            Err(error) => {
                tracing::error!(%error,"gateway control channel failed");
                terminal_error = Some(anyhow::anyhow!("gateway control channel failed: {error}"));
                None
            }
        };
        let event = tokio::select! {
            biased;
            _=terminate.recv()=>None,
            _=interrupt.recv()=>None,
            _=restart.recv()=>Some(Control::RestartRequested),
            value=std::future::ready(pending)=>value,
        };
        let Some(mut event) = event else { break };
        if update.is_some() && tokio::time::Instant::now() >= next_update {
            event = Control::UpdateRequested;
        }

        if let Some(status) = active.child.try_wait()? {
            bail!("gateway generation exited: {status}");
        }
        let mut index = 0;
        while index < draining.len() {
            if draining[index].child.try_wait()?.is_some() {
                draining.swap_remove(index);
            } else {
                index += 1;
            }
        }
        if event == Control::UpdateRequested
            && draining.len() < 2
            && let Some(options) = &update
        {
            next_update = tokio::time::Instant::now() + options.interval;
            update_status.phase = "checking".into();
            update_status.detail = None;
            update_status.last_check_unix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            if let Err(error) = persist_status(&options.status_path, &update_status) {
                tracing::warn!(%error,"could not persist updater status");
            }
            // Fetching, verifying and preflighting a candidate can take up
            // to the transport timeout against a stalled release origin.
            // Termination must stay observable there: dropping the staging
            // future removes its partial file and kills its preflight child.
            // Activation below is not cancellable; it completes or rolls back
            // before the supervisor drains.
            let staged = tokio::select! {
                biased;
                _=terminate.recv()=>None,
                _=interrupt.recv()=>None,
                result=stage_candidate(&executable, &arguments, options, &version)=>Some(result),
            };
            let Some(staged) = staged else {
                tracing::info!("termination requested; abandoning update staging");
                interrupted = true;
                break;
            };
            let outcome = match staged {
                Ok(candidate) => {
                    activate_and_replace(&mut active, &executable, &arguments, candidate).await
                }
                Err(error) => Err(error),
            };
            match outcome {
                Ok((next, new_version)) => {
                    let _ = active.channel.send_control(Control::Drain);
                    draining.push(std::mem::replace(&mut active, next));
                    version = new_version;
                    update_status.current_version = version.to_string();
                    update_status.phase = "active".into();
                }
                Err(error) if error.downcast_ref::<crate::update::UpToDate>().is_some() => {
                    update_status.phase = "up_to_date".into();
                }
                Err(error) if error.downcast_ref::<RolledBack>().is_some() => {
                    let _ = active.channel.send_control(Control::Resume);
                    tracing::warn!(%error,"signed update rolled back; keeping active generation");
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |elapsed| elapsed.as_secs());
                    update_status.record_rollback(ROLLBACK_REASON_HANDOFF, now);
                }
                Err(error) => {
                    let _ = active.channel.send_control(Control::Resume);
                    tracing::warn!(%error,"signed update rejected; keeping active generation");
                    update_status.phase = "rejected".into();
                    // Detailed errors can contain release URLs; keep them in protected logs.
                    update_status.detail=Some("Release verification, preflight, or activation failed; active generation retained".into());
                }
            }
            if let Err(error) = persist_status(&options.status_path, &update_status) {
                tracing::warn!(%error,"could not persist updater status");
            }
        }
        if event == Control::RestartRequested {
            if draining.len() >= 2 {
                tracing::warn!("restart deferred while previous generations drain");
                continue;
            }
            match replace(&mut active, &executable, &arguments).await {
                Ok(next) => {
                    let _ = active.channel.send_control(Control::Drain);
                    draining.push(std::mem::replace(&mut active, next));
                    tracing::info!("gateway generation replaced; previous connections draining");
                }
                Err(error) => {
                    tracing::warn!(%error,"replacement rejected; retaining active generation");
                    let _ = active.channel.send_control(Control::Resume);
                }
            }
        }
    }
    if interrupted && let Some(options) = &update {
        update_status.phase = "idle".into();
        update_status.detail = None;
        if let Err(error) = persist_status(&options.status_path, &update_status) {
            tracing::warn!(%error,"could not persist updater status");
        }
    }
    // Endpoint shutdown: only the serving generation needs the lame-duck
    // phase; generations already retiring just finish draining.
    let retire = futures_util::future::join_all(
        draining
            .into_iter()
            .map(|mut generation| async move { generation.stop(grace).await }),
    );
    tokio::join!(active.shutdown(grace, lame_duck), retire);
    match terminal_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn replace(
    active: &mut Generation,
    executable: &PathBuf,
    arguments: &[OsString],
) -> Result<Generation> {
    active.channel.send_control(Control::FreezeExport)?;
    let channel = active.channel.try_clone()?;
    let descriptors: Vec<ReceivedDescriptor> =
        tokio::task::spawn_blocking(move || channel.receive_export(PHASE_TIMEOUT)).await??;
    let mut candidate = Generation::spawn(executable, arguments)?;
    let result = async {
        candidate.channel.send_control(Control::FreezeExport)?;
        for descriptor in &descriptors {
            candidate
                .channel
                .send_descriptor(descriptor.role, descriptor.fd.as_fd())?;
        }
        candidate.channel.send_control(Control::ExportDone)?;
        candidate.expect(Control::Prepared).await?;
        candidate.channel.send_control(Control::Commit)?;
        candidate.expect(Control::Ready).await?;
        Ok::<_, anyhow::Error>(())
    }
    .await;
    if let Err(error) = result {
        candidate.stop(Duration::ZERO).await;
        return Err(error);
    }
    Ok(candidate)
}

/// A verified, preflighted candidate that has not touched the installed
/// binary yet. Dropping it removes the staged file and releases the installer
/// lock, so the staging phase is safe to abandon at any await point.
struct StagedCandidate {
    _lock: std::fs::File,
    staged: crate::update::StagedUpdate,
    version: semver::Version,
}

/// Cancellable phase: fetch, verify and preflight a signed release.
async fn stage_candidate(
    executable: &std::path::Path,
    arguments: &[OsString],
    options: &UpdateOptions,
    current: &semver::Version,
) -> Result<StagedCandidate> {
    use crate::update::{TrustKey, UpdateManager};
    // Serialize installers that intentionally share one executable path.
    let lock_path = executable.with_extension("update.lock");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    lock.try_lock()
        .context("another updater owns this executable")?;
    let root = if let Some(path) = &options.additional_ca {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(path)?
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 1024 * 1024, "update CA file too large");
        Some(reqwest::Certificate::from_pem(&bytes)?)
    } else {
        None
    };
    let updater = if options.github {
        UpdateManager::new_github(
            TrustKey::from_base64(&options.public_key)?,
            current.clone(),
            env!("HANGANG_TARGET"),
        )?
    } else {
        UpdateManager::new_with_ca(
            TrustKey::from_base64(&options.public_key)?,
            current.clone(),
            env!("HANGANG_TARGET"),
            root,
        )?
    };
    let destination = executable.parent().context("executable parent")?;
    let staged = if options.github {
        updater.stage_github(destination).await?
    } else {
        updater
            .stage(
                options
                    .manifest_url
                    .as_deref()
                    .context("missing update manifest URL")?,
                destination,
            )
            .await?
    };
    let version = staged.version().clone();
    let reported = bounded_preflight(staged.path(), &[OsString::from("--version")]).await?;
    ensure!(
        reported.trim() == format!("hangang {version}"),
        "candidate version differs from signed manifest"
    );
    let mut check_arguments = arguments.to_vec();
    check_arguments.push(OsString::from("--check"));
    bounded_preflight(staged.path(), &check_arguments)
        .await
        .context("candidate configuration preflight")?;
    Ok(StagedCandidate {
        _lock: lock,
        staged,
        version,
    })
}

/// Non-cancellable phase: activate the candidate on disk and replace the
/// serving generation, restoring the previous binary if replacement fails.
async fn activate_and_replace(
    active: &mut Generation,
    executable: &PathBuf,
    arguments: &[OsString],
    candidate: StagedCandidate,
) -> Result<(Generation, semver::Version)> {
    use crate::update::UpdateManager;
    let StagedCandidate {
        _lock,
        staged,
        version,
    } = candidate;
    let activated = UpdateManager::activate(staged, executable)?;
    match replace(active, executable, arguments).await {
        Ok(next) => {
            if let Err(error) = activated.discard_rollback() {
                tracing::warn!(%error,"update active but rollback cleanup failed");
            }
            Ok((next, version))
        }
        Err(error) => {
            UpdateManager::rollback(activated).context("restore failed update")?;
            Err(error.context(RolledBack))
        }
    }
}

async fn bounded_preflight(executable: &std::path::Path, arguments: &[OsString]) -> Result<String> {
    use tokio::io::AsyncReadExt;
    let mut child = Command::new(executable)
        .args(arguments)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let stdout = child.stdout.take().context("candidate stdout")?;
    let output = tokio::time::timeout(PHASE_TIMEOUT, async {
        let mut bytes = Vec::new();
        stdout.take(64 * 1024 + 1).read_to_end(&mut bytes).await?;
        ensure!(bytes.len() <= 64 * 1024, "candidate output too large");
        ensure!(child.wait().await?.success(), "candidate preflight failed");
        Ok::<_, anyhow::Error>(String::from_utf8(bytes)?)
    })
    .await
    .context("candidate preflight timeout")??;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rollback_is_recorded_and_exported() {
        let mut status = UpdateStatus::initial(true);
        status.record_rollback(ROLLBACK_REASON_HANDOFF, 1_700_000_000);
        status.record_rollback(ROLLBACK_REASON_HANDOFF, 1_700_000_060);
        assert_eq!(status.phase, "rolled_back");
        assert_eq!(status.rollbacks_total, 2);
        assert_eq!(status.last_rollback_unix, 1_700_000_060);
        assert_eq!(
            status.last_rollback_reason.as_deref(),
            Some(ROLLBACK_REASON_HANDOFF)
        );

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("update-status.json");
        persist_status(&path, &status).unwrap();
        let loaded = load_status(&path).unwrap();
        assert_eq!(loaded.rollbacks_total, 2);

        let mut out = String::new();
        loaded.render_metrics(&mut out);
        assert!(out.contains("hangang_update_rollbacks_total 2\n"));
        assert!(out.contains("hangang_update_last_rollback_unix 1700000060\n"));
        assert!(out.contains("hangang_update_phase{phase=\"rolled_back\"} 1\n"));
        assert!(out.contains("hangang_update_phase{phase=\"idle\"} 0\n"));
    }

    #[test]
    fn status_written_by_an_older_release_still_loads() {
        let old = br#"{"enabled":true,"phase":"active","current_version":"0.1.0","last_check_unix":5,"detail":null}"#;
        let status: UpdateStatus = serde_json::from_slice(old).unwrap();
        assert_eq!(status.rollbacks_total, 0);
        assert_eq!(status.last_rollback_reason, None);
        assert_eq!(status.last_rollback_unix, 0);
    }

    #[test]
    fn status_file_rejects_deep_unknown_fields_and_oversized_input() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("update-status.json");
        let status = UpdateStatus::initial(true);
        let mut document = serde_json::to_string(&status).unwrap();
        document.pop();
        document.push_str(&format!(
            ",\"unknown\":{}0{}}}",
            "[".repeat(129),
            "]".repeat(129)
        ));
        // A typed decoder otherwise skips unknown fields without a depth check.
        assert!(serde_json::from_str::<UpdateStatus>(&document).is_ok());
        std::fs::write(&path, document).unwrap();
        assert!(
            load_status(&path)
                .err()
                .unwrap()
                .to_string()
                .contains("nesting")
        );

        std::fs::write(&path, vec![b' '; 65537]).unwrap();
        assert!(
            load_status(&path)
                .err()
                .unwrap()
                .to_string()
                .contains("too large")
        );

        persist_status(&path, &status).unwrap();
        assert_eq!(load_status(&path).unwrap().phase, status.phase);
    }
}
