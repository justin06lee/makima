//! Talking to makimad.
//!
//! Two channels, deliberately unequal.
//!
//! Reading goes over the daemon's read-only Unix socket — the one it chowns to
//! the person who started makima. Nothing sent down it can change anything,
//! which is what makes it safe for a window rendering HTML to hold open.
//!
//! Writing does not go over a socket at all. Every action this app offers runs
//! the `makima` CLI behind a graphical authentication prompt, so changing an
//! exit node crosses exactly the same permission boundary as typing sudo —
//! made visible instead of implicit. A web view cannot reconfigure a VPN by
//! accident, because the web view was never able to.

use std::path::{Path, PathBuf};
use std::time::Duration;

use http_body_util::{BodyExt, Empty};
use hyper::body::Bytes;
use hyper::Request;
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use tokio::net::UnixStream;

/// Where the daemon keeps its sockets, matching `localapi.GUISocketPath`.
const CONFIG_DIR: &str = "/etc/makima";
const GUI_SOCKET: &str = "makimad-gui.sock";

/// How long a status read may take.
///
/// Short. Every call here is a local read from a process on this machine; one
/// that takes seconds has hung, and a menu bar that freezes is worse than one
/// that says it cannot see the daemon.
const READ_TIMEOUT: Duration = Duration::from_secs(3);

/// Where to look for the daemon.
///
/// MAKIMA_GUI_SOCKET overrides it. That exists for development — the app can
/// be pointed at a socket in /tmp without needing root to place one in
/// /etc/makima — and it is read from the process environment, which a web view
/// cannot reach.
fn socket_path() -> PathBuf {
    if let Ok(p) = std::env::var("MAKIMA_GUI_SOCKET") {
        if !p.is_empty() {
            return PathBuf::from(p);
        }
    }
    let real = PathBuf::from(CONFIG_DIR).join(GUI_SOCKET);
    // A debug build with no real daemon falls back to the devserver's socket,
    // so the app can be launched from Finder or a script — anything that
    // cannot set an environment variable — while it is being worked on. A
    // release build never looks in /tmp for a socket to trust.
    if cfg!(debug_assertions) && !real.exists() {
        let dev = PathBuf::from("/tmp/makima-dev.sock");
        if dev.exists() {
            return dev;
        }
    }
    real
}

/// What the app knows about the daemon at any moment.
///
/// `running` is separate from the rest because "makimad is not up" is the most
/// common state a desktop app will find, and it is not an error — it is the
/// thing the connect button exists to fix.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Snapshot {
    pub running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<serde_json::Value>,
}

/// GET a path from the daemon's read-only socket.
async fn get(path: &str) -> Result<serde_json::Value, String> {
    let sock = socket_path();

    let stream = tokio::time::timeout(READ_TIMEOUT, UnixStream::connect(&sock))
        .await
        .map_err(|_| format!("{} did not answer", sock.display()))?
        .map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => "no makimad is running".to_string(),
            std::io::ErrorKind::PermissionDenied => format!(
                "{} is not readable by this account — makimad gives it to whoever ran 'makima up'",
                sock.display()
            ),
            _ => e.to_string(),
        })?;

    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|e| e.to_string())?;

    // The connection future drives the socket and finishes when the response
    // is done. Dropping it would stall the request.
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // The host is ignored for a Unix socket, but HTTP/1.1 insists on one.
    let req = Request::builder()
        .uri(path)
        .header(hyper::header::HOST, "makimad")
        .body(Empty::<Bytes>::new())
        .map_err(|e| e.to_string())?;

    let resp = tokio::time::timeout(READ_TIMEOUT, sender.send_request(req))
        .await
        .map_err(|_| "the daemon stopped answering".to_string())?
        .map_err(|e| e.to_string())?;

    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .map_err(|e| e.to_string())?
        .to_bytes();

    if !status.is_success() {
        return Err(format!("daemon returned {status}"));
    }
    serde_json::from_slice(&body).map_err(|e| e.to_string())
}

/// Read the daemon's whole view of itself.
pub async fn snapshot() -> Snapshot {
    match get("/api/status").await {
        Ok(v) => Snapshot { running: true, error: None, status: Some(v) },
        Err(e) => Snapshot { running: false, error: Some(e), status: None },
    }
}

/// Run the doctor's checks.
pub async fn diagnose() -> Result<serde_json::Value, String> {
    get("/api/doctor").await
}

/// Probe one peer and report the path to it.
pub async fn ping(peer: &str) -> Result<serde_json::Value, String> {
    // The peer name is a value the user picked from a list this process
    // fetched, but it still ends up in a URL, so it is encoded rather than
    // interpolated.
    let encoded: String = peer
        .bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect();
    get(&format!("/api/ping?peer={encoded}")).await
}

/// What is true about this machine before the daemon says anything.
///
/// The window has to choose a first screen — set up, connect, or the mesh —
/// and it has to do so when nothing is running, which is exactly when the
/// socket cannot tell it. These are the facts on disk that decide it.
#[derive(Debug, Clone, Serialize)]
pub struct Environment {
    /// The CLI this app will run, if it found one.
    pub cli: Option<String>,
    /// This machine is on a mesh already: its identity is written down.
    pub member: bool,
    /// The coordination plane runs here, so this is the machine that mints
    /// invites.
    pub holds_mesh: bool,
    /// `makima` is on PATH for a terminal, not only inside this bundle.
    pub linked: bool,
    pub platform: &'static str,
    pub app_version: &'static str,
}

pub fn environment() -> Environment {
    // A developer pointing the app at a pretend mesh has no /etc/makima and
    // still wants to see the connected screen, or the off screen, on demand.
    let dev_member = std::env::var("MAKIMA_DEV_MEMBER").map(|v| !v.is_empty()).unwrap_or(false);
    let member = dev_member || Path::new(CONFIG_DIR).join("node.json").exists();
    Environment {
        cli: crate::privileged::makima_binary().map(|p| p.to_string_lossy().to_string()),
        member,
        holds_mesh: Path::new("/var/lib/makima/control.sock").exists(),
        linked: crate::privileged::cli_on_path(),
        platform: std::env::consts::OS,
        app_version: env!("CARGO_PKG_VERSION"),
    }
}
