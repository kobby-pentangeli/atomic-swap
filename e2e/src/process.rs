//! Managed child processes and the small primitives the chain nodes share.
//!
//! Every external service (`bitcoind`, `anvil`, `solana-test-validator`) is run
//! as a child process owned by a [`Process`] guard that kills it on drop, so a
//! panicking test never leaks a daemon. Scratch state lives under a [`Scratch`]
//! temporary directory that is removed on drop for the same reason.

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};

/// A child process that is terminated when the guard is dropped.
pub struct Process {
    name: &'static str,
    child: Child,
}

impl Process {
    /// Spawn `program` with `args`, discarding its output.
    ///
    /// The chains are noisy and their health is polled out of band, so their
    /// stdio is sent to the null device rather than captured.
    pub fn spawn(name: &'static str, program: &str, args: &[&str]) -> Result<Self> {
        let child = Command::new(program)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("Failed to spawn {name} (`{program}`); is it installed?"))?;
        Ok(Self { name, child })
    }

    /// Returns an error if the process has already exited, naming the service.
    pub fn assert_running(&mut self) -> Result<()> {
        match self.child.try_wait() {
            Ok(Some(status)) => bail!("{} exited early with {status}", self.name),
            Ok(None) => Ok(()),
            Err(e) => Err(e).with_context(|| format!("Failed to poll {}", self.name)),
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A unique temporary directory removed when the guard is dropped.
pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    /// Create a fresh scratch directory tagged with `label`.
    pub fn new(label: &str) -> Result<Self> {
        // A monotonic counter plus the wall clock keeps the name unique across
        // nodes created in the same process and across repeated local runs.
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("atomic-swap-e2e-{label}-{nanos}-{seq}"));
        fs::create_dir_all(&path)
            .with_context(|| format!("Failed to create scratch dir {}", path.display()))?;
        Ok(Self { path })
    }

    /// The scratch directory path.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

/// Reserve a free localhost TCP port by binding to port 0 and releasing it.
///
/// The brief gap between release and the daemon re-binding is a race, but the
/// nodes serialize through the harness lock, so in practice each port is claimed
/// by exactly one service.
pub fn free_port() -> Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").context("Failed to reserve a free port")?;
    Ok(listener
        .local_addr()
        .context("Failed to read reserved port")?
        .port())
}

/// Poll `ready` every 250ms until it returns `true` or `timeout` elapses.
///
/// `service` keeps the process-liveness check honest: if the daemon dies while
/// we wait, the error names it instead of timing out opaquely.
pub fn wait_until(
    what: &str,
    timeout: Duration,
    service: &mut Process,
    mut ready: impl FnMut() -> bool,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        service.assert_running()?;
        if ready() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            bail!("Timed out after {:?} waiting for {what}", timeout);
        }
        sleep(Duration::from_millis(250));
    }
}

/// Run `program` to completion, returning its stdout on success.
///
/// Used for the one-shot tooling calls (`bitcoin-cli`, `cast`, `solana`,
/// `forge`) where we need the output rather than a long-lived process.
pub fn run(program: &str, args: &[&str]) -> Result<String> {
    run_impl(program, args, None)
}

/// Like [`run`], but with `program` invoked from the working directory `dir`.
pub fn run_in(dir: &Path, program: &str, args: &[&str]) -> Result<String> {
    run_impl(program, args, Some(dir))
}

fn run_impl(program: &str, args: &[&str], dir: Option<&Path>) -> Result<String> {
    let mut command = Command::new(program);
    command.args(args).stdin(Stdio::null());
    if let Some(dir) = dir {
        command.current_dir(dir);
    }
    let output = command
        .output()
        .with_context(|| format!("Failed to run `{program}`; is it installed?"))?;
    if !output.status.success() {
        bail!(
            "`{program} {}` failed ({}): {}",
            args.join(" "),
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)
        .context("Command produced non-UTF-8 output")?
        .trim()
        .to_string())
}
