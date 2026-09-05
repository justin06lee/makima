//! Running the `makima` CLI as root, with the person's consent.
//!
//! This is the only way anything in this app changes anything. There is no
//! privileged socket, no helper daemon holding root on standby, and no way for
//! the web view to reach a mutating endpoint — because none is open to it.
//!
//! What there is instead is the platform's own authentication dialog. On macOS
//! that is Authorization Services via osascript; on Linux it is polkit through
//! pkexec. Both put a prompt in front of the user that names what is about to
//! happen, and both are the same boundary they would cross by typing sudo. The
//! point is not that this is more secure than sudo — it is exactly as secure,
//! and visible.
//!
//! The command is never assembled from a string. Every action is a fixed verb
//! with arguments this process chose, quoted by `shell_quote` before it can
//! reach a shell, so a peer named `; rm -rf /` is a peer with a strange name
//! and nothing more.

use std::process::Stdio;
use tokio::process::Command;

/// What the app is allowed to ask for.
///
/// An enum rather than a command string, so the set of privileged operations
/// is a list somebody can read in one screen and the web view can only name
/// one of them — never compose a new one.
#[derive(Debug, Clone, serde::Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Action {
    /// Bring the tunnel up, making a mesh if there is not one yet.
    Up,
    /// Stop, and put this machine's network configuration back.
    Down,
    /// Publish a local port on the mesh.
    Allow { port: u16 },
    /// Stop publishing one.
    Deny { port: u16 },
    /// Route this machine's traffic through a peer, or stop doing so.
    ExitNode { name: String },
    /// Print an invite for the next machine.
    Invite,
    /// Publish a pairing address and listen for one machine.
    Pair,
}

impl Action {
    /// The argv this action runs. Never a string, never concatenated.
    fn argv(&self) -> Vec<String> {
        let s = |v: &str| v.to_string();
        match self {
            Action::Up => vec![s("up")],
            Action::Down => vec![s("down")],
            Action::Allow { port } => vec![s("allow"), port.to_string()],
            Action::Deny { port } => vec![s("deny"), port.to_string()],
            // An empty name is how "stop using an exit node" is spelled, and
            // `set -exit-node ""` is what the CLI expects for it.
            Action::ExitNode { name } => vec![s("set"), s("-exit-node"), name.clone()],
            Action::Invite => vec![s("invite")],
            Action::Pair => vec![s("pair")],
        }
    }

    /// One line for the authentication prompt, so the dialog says what it is
    /// for rather than "an application wants to make changes".
    fn reason(&self) -> String {
        match self {
            Action::Up => "makima needs to bring up the tunnel".into(),
            Action::Down => "makima needs to take the tunnel down".into(),
            Action::Allow { port } => format!("makima needs to publish port {port} on your mesh"),
            Action::Deny { port } => format!("makima needs to stop publishing port {port}"),
            Action::ExitNode { name } if name.is_empty() => {
                "makima needs to stop using an exit node".into()
            }
            Action::ExitNode { name } => {
                format!("makima needs to route this machine's traffic through {name}")
            }
            Action::Invite => "makima needs to mint an invite".into(),
            Action::Pair => "makima needs to publish a pairing address".into(),
        }
    }
}

/// What a privileged run produced.
#[derive(Debug, serde::Serialize)]
pub struct Outcome {
    pub ok: bool,
    pub output: String,
}

/// Where the CLI is.
///
/// Looked up rather than assumed: Homebrew, the install script and a `make
/// install` put it in different places, and a hardcoded path would work on
/// exactly one of them.
fn makima_binary() -> String {
    for candidate in [
        "/usr/local/bin/makima",
        "/opt/homebrew/bin/makima",
        "/usr/bin/makima",
    ] {
        if std::path::Path::new(candidate).exists() {
            return candidate.to_string();
        }
    }
    "makima".to_string()
}

/// Quote one argument for a POSIX shell.
///
/// Single quotes make everything literal except a single quote itself, which
/// is closed, escaped and reopened. This is the whole reason a peer name can
/// be passed to osascript without thinking about what is in it.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// Run an action, asking the user to authenticate first.
pub async fn run(action: Action) -> Result<Outcome, String> {
    let bin = makima_binary();
    let argv = action.argv();
    let reason = action.reason();

    let output = if cfg!(target_os = "macos") {
        // `with administrator privileges` is Authorization Services: the
        // system draws the prompt, and this process never sees the password.
        let mut command = shell_quote(&bin);
        for a in &argv {
            command.push(' ');
            command.push_str(&shell_quote(a));
        }
        // The reason is displayed to the user, so it is quoted too — it is
        // built here, but quoting it costs nothing and means it can never
        // become part of the script.
        let script = format!(
            "do shell script {} with prompt {} with administrator privileges",
            shell_quote(&command),
            shell_quote(&reason),
        );
        Command::new("osascript")
            .arg("-e")
            .arg(script)
            .stdin(Stdio::null())
            .output()
            .await
    } else {
        // pkexec takes argv directly, so nothing is ever parsed as a shell
        // command on Linux at all.
        Command::new("pkexec")
            .arg(&bin)
            .args(&argv)
            .stdin(Stdio::null())
            .output()
            .await
    };

    let output = output.map_err(|e| match e.kind() {
        std::io::ErrorKind::NotFound if !cfg!(target_os = "macos") => {
            "pkexec is not installed — makima needs polkit to ask for permission".to_string()
        }
        _ => e.to_string(),
    })?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        return Ok(Outcome { ok: true, output: stdout });
    }

    // A cancelled prompt is not a failure worth shouting about: the user said
    // no, and the app should say so rather than showing them an error.
    let cancelled = stderr.contains("User canceled")
        || stderr.contains("User cancelled")
        || stderr.contains("-128")
        || stderr.contains("Request dismissed")
        || stderr.contains("Not authorized");

    if cancelled {
        return Ok(Outcome { ok: false, output: "cancelled".into() });
    }

    let detail = if stderr.is_empty() { stdout } else { stderr };
    Ok(Outcome {
        ok: false,
        output: if detail.is_empty() { "it did not say why".into() } else { detail },
    })
}
