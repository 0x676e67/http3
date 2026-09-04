//! Child Client/Server lifecycle, timeout, and result-collection boundaries.

use std::{
    ffi::OsStr,
    io::{BufRead, BufReader},
    path::Path,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    thread,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use bench::{
    case::{
        Case, Http3Library, MAX_BODY_BYTES, SERVER_ADDR, SERVER_MAX_BIDI_STREAMS, SERVER_WORKERS,
        workspace_root,
    },
    result::ClientResult,
};
use wait_timeout::ChildExt;

const SERVER_READY_TIMEOUT: Duration = Duration::from_secs(15);
const SERVER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const CHILD_MARKER: &str = "--http3-bench-child";

#[derive(Clone, Copy, Debug)]
pub(crate) enum ChildRole {
    Client(Http3Library),
    Server,
}

impl ChildRole {
    pub(crate) fn parse(value: &OsStr) -> Result<Self> {
        match value.to_str() {
            Some("http3") => Ok(Self::Client(Http3Library::Http3)),
            Some("h3") => Ok(Self::Client(Http3Library::H3)),
            Some("nghttp3") => Ok(Self::Client(Http3Library::Nghttp3)),
            Some("server") => Ok(Self::Server),
            _ => bail!("unsupported internal benchmark role {value:?}"),
        }
    }

    fn argument(self) -> &'static str {
        match self {
            Self::Client(library) => library.name(),
            Self::Server => "server",
        }
    }

    fn command(self, executable: &Path) -> Command {
        let mut command = Command::new(executable);
        command.arg(CHILD_MARKER).arg(self.argument());
        command
    }
}

struct ChildCleanupGuard {
    child: Option<Child>,
}

impl ChildCleanupGuard {
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

pub(crate) struct ClientRunner<'a> {
    pub executable: &'a Path,
    pub library: Http3Library,
}

impl ClientRunner<'_> {
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
        let mut command = ChildRole::Client(self.library).command(self.executable);
        command
            .arg(case.requests.to_string())
            .arg(case.body_bytes.to_string())
            .arg(case.in_flight.to_string())
            .current_dir(workspace_root())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = ChildCleanupGuard {
            child: Some(
                command
                    .spawn()
                    .with_context(|| format!("could not run {} client", self.library))?,
            ),
        };
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
    pub(crate) fn start(executable: &Path, body_bytes: usize) -> Result<Self> {
        let mut child = ChildCleanupGuard {
            child: Some(
                ChildRole::Server
                    .command(executable)
                    .arg(body_bytes.to_string())
                    .current_dir(workspace_root())
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::inherit())
                    .spawn()
                    .context("could not start benchmark server")?,
            ),
        };
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
            "http3-bench-server-v2 address={SERVER_ADDR} body_bytes={body_bytes} \
             max_concurrent_bidi_streams={SERVER_MAX_BIDI_STREAMS} transport=quinn \
             workers={SERVER_WORKERS}"
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
    if case.body_bytes >= MAX_BODY_BYTES {
        Duration::from_secs(10 * 60)
    } else {
        Duration::from_secs(2 * 60)
    }
}
