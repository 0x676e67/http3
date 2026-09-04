//! Child Client/Server lifecycle, timeout, and result-collection boundaries.

use std::{
    io::{BufRead, BufReader},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use http3_bench::{
    case::{Case, Http3Library, SERVER_ADDR, SERVER_WORKERS, workspace_root},
    result::ClientResult,
};
use wait_timeout::ChildExt;

const SERVER_READY_TIMEOUT: Duration = Duration::from_secs(15);
const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP3_CLIENT_EXE: &str = env!("CARGO_BIN_EXE_http3-bench-http3-client");
const H3_CLIENT_EXE: &str = env!("CARGO_BIN_EXE_http3-bench-h3-client");
const NGHTTP3_CLIENT_EXE: &str = env!("CARGO_BIN_EXE_http3-bench-nghttp3-client");
const SERVER_EXE: &str = env!("CARGO_BIN_EXE_http3-bench-server");

struct ChildCleanupGuard {
    child: Option<Child>,
}

impl ChildCleanupGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn child_mut(&mut self) -> Result<&mut Child> {
        self.child
            .as_mut()
            .context("benchmark child process was already consumed")
    }

    fn kill(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
        }
    }

    fn wait_with_output(mut self) -> std::io::Result<std::process::Output> {
        let child = self
            .child
            .take()
            .ok_or_else(|| std::io::Error::other("benchmark child process was already consumed"))?;
        child.wait_with_output()
    }

    fn into_child(mut self) -> Result<Child> {
        self.child
            .take()
            .context("benchmark child process was already consumed")
    }
}

impl Drop for ChildCleanupGuard {
    fn drop(&mut self) {
        if let Some(child) = &mut self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

pub(crate) struct ClientRunner {
    executable: PathBuf,
    library: Http3Library,
}

impl ClientRunner {
    pub(crate) fn rust(library: Http3Library) -> Result<Self> {
        let executable = PathBuf::from(match library {
            Http3Library::Http3 => HTTP3_CLIENT_EXE,
            Http3Library::H3 => H3_CLIENT_EXE,
            Http3Library::Nghttp3 => bail!("nghttp3 cannot use the Rust child runner"),
        });
        Self::new(executable, library)
    }

    pub(crate) fn nghttp3() -> Result<Self> {
        Self::new(PathBuf::from(NGHTTP3_CLIENT_EXE), Http3Library::Nghttp3)
    }

    fn new(executable: PathBuf, library: Http3Library) -> Result<Self> {
        if !executable.is_file() {
            bail!(
                "{} benchmark client does not exist: {}",
                library,
                executable.display()
            );
        }
        Ok(Self {
            executable,
            library,
        })
    }

    pub(crate) fn run_iterations(&self, iterations: u64, case: Case) -> Result<Duration> {
        let mut measured = Duration::ZERO;
        for _ in 0..iterations {
            let sample = self.run_once(case)?;
            measured = measured
                .checked_add(sample)
                .context("aggregate measured duration overflowed")?;
        }
        Ok(measured)
    }

    fn run_once(&self, case: Case) -> Result<Duration> {
        let mut command = Command::new(&self.executable);
        command
            .arg(case.topology.connections.to_string())
            .arg(case.topology.sockets.to_string())
            .arg(case.requests_per_connection.to_string())
            .arg(case.workload.body_bytes.to_string())
            .arg(case.in_flight_per_connection.to_string())
            .current_dir(workspace_root())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = ChildCleanupGuard::new(
            command
                .spawn()
                .with_context(|| format!("could not run {} client", self.library))?,
        );
        if child
            .child_mut()?
            .wait_timeout(client_timeout(case))
            .context("could not wait for benchmark client")?
            .is_none()
        {
            child.kill();
            let output = child
                .wait_with_output()
                .context("could not collect timed-out benchmark client")?;
            bail!(
                "{} client exceeded its {:?} batch timeout; stderr: {}",
                self.library,
                client_timeout(case),
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let output = child
            .wait_with_output()
            .context("could not collect benchmark client output")?;

        if !output.status.success() {
            bail!(
                "{} client exited with {}; stderr: {}",
                self.library,
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }

        let result = ClientResult::parse(&output.stdout).with_context(|| {
            format!(
                "{} client stderr: {}",
                self.library,
                String::from_utf8_lossy(&output.stderr).trim()
            )
        })?;
        result.validate(self.library, case)
    }
}

pub(crate) struct ServerGuard {
    child: Child,
    stdin: Option<ChildStdin>,
}

impl ServerGuard {
    pub(crate) fn start(body_bytes: usize) -> Result<Self> {
        let executable = PathBuf::from(SERVER_EXE);
        if !executable.is_file() {
            bail!(
                "Cargo did not build the benchmark server at {}",
                executable.display()
            );
        }
        let mut child = ChildCleanupGuard::new(
            Command::new(executable)
                .arg(body_bytes.to_string())
                .current_dir(workspace_root())
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::inherit())
                .spawn()
                .context("could not start benchmark server")?,
        );
        let stdin = child
            .child_mut()?
            .stdin
            .take()
            .context("benchmark server stdin was not captured")?;

        let stdout = child
            .child_mut()?
            .stdout
            .take()
            .context("benchmark server stdout was not captured")?;
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let mut line = String::new();
            let result = BufReader::new(stdout).read_line(&mut line).map(|_| line);
            let _ = ready_tx.send(result);
        });

        let ready = match ready_rx.recv_timeout(SERVER_READY_TIMEOUT) {
            Ok(result) => result.context("could not read benchmark server readiness")?,
            Err(error) => {
                return Err(error)
                    .context("benchmark server did not become ready within 15 seconds");
            }
        };
        let expected = format!(
            "http3-bench-server-v1 address={SERVER_ADDR} body_bytes={body_bytes} \
             transport=quinn-default workers={SERVER_WORKERS}"
        );
        if ready.trim() != expected {
            let status = child
                .child_mut()?
                .try_wait()
                .context("could not inspect benchmark server")?;
            bail!(
                "benchmark server returned unexpected readiness {ready:?}; expected {expected:?}; \
                 status={status:?}"
            );
        }

        Ok(Self {
            child: child.into_child()?,
            stdin: Some(stdin),
        })
    }

    pub(crate) fn finish(&mut self) -> Result<()> {
        self.stdin.take();
        let Some(status) = self
            .child
            .wait_timeout(SERVER_SHUTDOWN_TIMEOUT)
            .context("could not wait for benchmark server shutdown")?
        else {
            let _ = self.child.kill();
            let _ = self.child.wait();
            bail!(
                "benchmark server did not stop within {:?}",
                SERVER_SHUTDOWN_TIMEOUT
            );
        };
        if !status.success() {
            bail!("benchmark server exited with {status}");
        }
        Ok(())
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        self.stdin.take();
        let exited = self
            .child
            .wait_timeout(SERVER_SHUTDOWN_TIMEOUT)
            .ok()
            .flatten()
            .is_some();
        if !exited {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
    }
}

fn client_timeout(case: Case) -> Duration {
    if case.workload.body_bytes >= 100 * 1024 * 1024 {
        Duration::from_secs(10 * 60)
    } else {
        Duration::from_secs(2 * 60)
    }
}
