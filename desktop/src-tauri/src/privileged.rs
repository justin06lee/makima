//! Running the `makima` CLI, with the person's consent where it needs root.
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

use std::path::PathBuf;
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
    /// Join somebody else's mesh with a pasted invite.
    Join { invite: String },
    /// Stop, and put this machine's network configuration back.
    Down,
    /// Publish a local port on the mesh.
    Allow { port: u16 },
    /// Stop publishing one.
    Deny { port: u16 },
    /// Route this machine's traffic through a peer, or stop doing so.
    ExitNode { name: String },
    /// Mint an invite for the next machine.
    Invite,
    /// Publish a pairing address and listen for one machine.
    Pair,
    /// Put the `makima` command on PATH.
    LinkCli,
}

impl Action {
    /// The argv this action runs. Never a string, never concatenated.
    fn argv(&self) -> Vec<String> {
        let s = |v: &str| v.to_string();
        match self {
            Action::Up => vec![s("up")],
            Action::Join { invite } => vec![s("join"), invite.clone()],
            Action::Down => vec![s("down")],
            Action::Allow { port } => vec![s("allow"), port.to_string()],
            Action::Deny { port } => vec![s("deny"), port.to_string()],
            // An empty name is how "stop using an exit node" is spelled, and
            // `set -exit-node ""` is what the CLI expects for it.
            Action::ExitNode { name } => vec![s("set"), s("-exit-node"), name.clone()],
            Action::Invite => vec![s("invite"), s("-q")],
            Action::Pair => vec![s("pair")],
            Action::LinkCli => vec![s("link-cli"), s("-q")],
        }
    }

    /// One line for the authentication prompt, so the dialog says what it is
    /// for rather than "an application wants to make changes".
    fn reason(&self) -> String {
        match self {
            Action::Up => "makima needs to bring up the tunnel".into(),
            Action::Join { .. } => "makima needs to join the network and bring up the tunnel".into(),
            Action::Down => "makima needs to take the tunnel down".into(),
            Action::Allow { port } => format!("makima needs to publish port {port} on your network"),
            Action::Deny { port } => format!("makima needs to stop publishing port {port}"),
            Action::ExitNode { name } if name.is_empty() => {
                "makima needs to stop using an exit node".into()
            }
            Action::ExitNode { name } => {
                format!("makima needs to route this machine's traffic through {name}")
            }
            Action::Invite => "makima needs to create an invite".into(),
            Action::Pair => "makima needs to publish a pairing address".into(),
            Action::LinkCli => "makima needs to put its command in /usr/local/bin".into(),
        }
    }

    /// Refuse anything malformed before a password is asked for.
    ///
    /// Being prompted for root and then told the invite was mistyped is the
    /// wrong order to find that out in. The CLI checks again; this is the
    /// cheap check that happens first.
    fn validate(&self) -> Result<(), String> {
        match self {
            Action::Join { invite } => {
                let body = invite
                    .strip_prefix("mk1_")
                    .ok_or("that is not an invite — it should start with mk1_")?;
                if body.is_empty() || body.len() > 4096 {
                    return Err("that invite is not the right length".into());
                }
                if !body
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    return Err("that invite has characters in it that an invite never has — check the paste".into());
                }
                Ok(())
            }
            Action::ExitNode { name } => {
                if name.len() > 253 || name.chars().any(|c| c.is_control()) {
                    return Err("that is not a device name".into());
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

/// What a run produced.
#[derive(Debug, serde::Serialize)]
pub struct Outcome {
    pub ok: bool,
    pub output: String,
}

/// Where the CLI is.
///
/// Inside this app's own bundle first: Tauri places the four sidecar binaries
/// beside the app's executable, and the makima in there is the one built and
/// shipped with this window. Then the places an install puts it, because a
/// machine with a `make install`ed makima and no bundle is the other common
/// case. A hardcoded path would work on exactly one of them.
pub fn makima_binary() -> Option<PathBuf> {
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("makima");
            if p.is_file() {
                return Some(p);
            }
        }
    }
    for candidate in [
        "/usr/local/bin/makima",
        "/opt/homebrew/bin/makima",
        "/usr/bin/makima",
    ] {
        let p = PathBuf::from(candidate);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Whether the CLI in the bundle is the same one a terminal would find.
pub fn cli_on_path() -> bool {
    std::path::Path::new("/usr/local/bin/makima").exists()
}

/// Quote one argument for a POSIX shell.
///
/// Single quotes make everything literal except a single quote itself, which
/// is closed, escaped and reopened. This is the whole reason a peer name can
/// be passed to osascript without thinking about what is in it.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', r"'\''"))
}

/// The person this app is running for, by name.
///
/// Told to the daemon as MAKIMA_OWNER, because the shell behind the admin
/// prompt sets none of the variables sudo would, and the daemon needs to know
/// whose socket to open and whose Downloads to put files in.
fn owner() -> Option<String> {
    std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty() && u != "root" && u.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.'))
}

/// Run an action, asking the user to authenticate first.
pub async fn run(action: Action) -> Result<Outcome, String> {
    action.validate()?;

    let bin = makima_binary()
        .ok_or("the makima command is missing — this app should have it inside; reinstall it")?;
    let bin = bin.to_string_lossy().to_string();
    let argv = action.argv();
    let reason = action.reason();

    let output = if cfg!(target_os = "macos") {
        // `with administrator privileges` is Authorization Services: the
        // system draws the prompt, and this process never sees the password.
        let mut command = String::new();
        if let Some(who) = owner() {
            command.push_str("MAKIMA_OWNER=");
            command.push_str(&shell_quote(&who));
            command.push(' ');
        }
        command.push_str(&shell_quote(&bin));
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
        // command on Linux at all. It also scrubs the environment and sets
        // PKEXEC_UID, which is how the daemon learns who we are.
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

    Ok(Outcome {
        ok: false,
        output: tidy(&stdout, &stderr),
    })
}

/// Run the CLI as this user, with no prompt.
///
/// For the things the CLI can do without root — sending a file, mostly. The
/// daemon answers a plain user over its read-only socket, and the copy itself
/// goes straight to the peer.
pub async fn run_unprivileged(args: &[String]) -> Result<Outcome, String> {
    let bin = makima_binary()
        .ok_or("the makima command is missing — this app should have it inside; reinstall it")?;

    let output = Command::new(&bin)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .await
        .map_err(|e| e.to_string())?;

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        return Ok(Outcome { ok: true, output: stdout });
    }
    Ok(Outcome {
        ok: false,
        output: tidy(&stdout, &stderr),
    })
}

/// The one line worth showing from a failed run.
///
/// The CLI's errors already start with "makima: " and osascript wraps them in
/// its own line-number noise; neither belongs in a window.
fn tidy(stdout: &str, stderr: &str) -> String {
    let detail = if stderr.is_empty() { stdout } else { stderr };
    let line = detail
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim();
    let line = line.strip_prefix("makima: ").unwrap_or(line);
    // "123:456: execution error: makima: ..." is what osascript makes of it.
    let line = match line.find("execution error: ") {
        Some(i) => &line[i + "execution error: ".len()..],
        None => line,
    };
    let line = line.strip_prefix("makima: ").unwrap_or(line);
    let line = line.trim_end_matches(|c: char| c == '(' || c.is_ascii_digit() || c == ')' || c == ' ');
    if line.is_empty() {
        "it did not say why".into()
    } else {
        line.to_string()
    }
}
