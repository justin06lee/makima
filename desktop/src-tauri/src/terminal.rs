//! Opening a shell on another device, in the person's own terminal.
//!
//! An ssh:// link would do it on paper. It goes to whatever the system says
//! handles ssh — Terminal, on a Mac — and runs plain `ssh NAME`, which asks the
//! system resolver for the name and logs in as this account's name. This runs
//! `makima ssh NAME` instead, which asks the daemon for the address, finds
//! makima's own SSH server where that is what answers, and logs in as the
//! account the person's keys open — in the terminal they picked.

use std::path::PathBuf;
use std::process::Stdio;

use tokio::process::Command;

use crate::privileged::{applescript_quote, makima_binary, shell_quote};

/// A terminal found on this device.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Terminal {
    pub id: &'static str,
    pub name: &'static str,
    /// The one the system comes with.
    pub builtin: bool,
}

/// How a terminal is found, and told to run a command.
struct Known {
    id: &'static str,
    name: &'static str,
    builtin: bool,
    /// macOS: the app bundle.
    app: &'static str,
    /// Linux: the command on PATH.
    bin: &'static str,
    /// What goes in front of the command it should run.
    run: &'static [&'static str],
}

/// Most wanted first. Somebody who installed a terminal did it for a reason,
/// so the ones the system came with come last.
const KNOWN: &[Known] = &[
    Known { id: "ghostty", name: "Ghostty", builtin: false, app: "Ghostty.app", bin: "ghostty", run: &["-e"] },
    Known { id: "alacritty", name: "Alacritty", builtin: false, app: "Alacritty.app", bin: "alacritty", run: &["-e"] },
    Known { id: "kitty", name: "kitty", builtin: false, app: "kitty.app", bin: "kitty", run: &[] },
    Known { id: "wezterm", name: "WezTerm", builtin: false, app: "WezTerm.app", bin: "wezterm", run: &["start", "--"] },
    Known { id: "iterm", name: "iTerm", builtin: false, app: "iTerm.app", bin: "", run: &[] },
    Known { id: "foot", name: "foot", builtin: false, app: "", bin: "foot", run: &[] },
    Known { id: "terminal", name: "Terminal", builtin: true, app: "Terminal.app", bin: "", run: &[] },
    Known { id: "gnome-terminal", name: "GNOME Terminal", builtin: true, app: "", bin: "gnome-terminal", run: &["--"] },
    Known { id: "konsole", name: "Konsole", builtin: true, app: "", bin: "konsole", run: &["-e"] },
    Known { id: "xfce4-terminal", name: "Xfce Terminal", builtin: true, app: "", bin: "xfce4-terminal", run: &["-x"] },
    Known { id: "xterm", name: "XTerm", builtin: true, app: "", bin: "xterm", run: &["-e"] },
];

/// Run `makima ssh`, and keep the window open when it ends in an error: a
/// terminal that closes the moment it opens has said nothing at all.
const HOLD: &str = r#""$0" ssh "$1"; s=$?; if [ "$s" -ne 0 ]; then printf '\n[makima ssh ended with status %s. Press return to close.]' "$s"; read -r _; fi"#;

fn home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

/// Where a terminal is on this device, if it is.
fn locate(k: &Known) -> Option<PathBuf> {
    if cfg!(target_os = "macos") {
        if k.app.is_empty() {
            return None;
        }
        let mut dirs = vec![
            PathBuf::from("/Applications"),
            PathBuf::from("/Applications/Utilities"),
            PathBuf::from("/System/Applications/Utilities"),
        ];
        dirs.extend(home().map(|h| h.join("Applications")));
        dirs.into_iter().map(|d| d.join(k.app)).find(|p| p.is_dir())
    } else {
        if k.bin.is_empty() {
            return None;
        }
        // An app started from a desktop menu may have a thin PATH, so the
        // usual places are looked in as well.
        let mut dirs: Vec<PathBuf> = std::env::var_os("PATH").map(|p| std::env::split_paths(&p).collect()).unwrap_or_default();
        dirs.extend(["/usr/bin", "/usr/local/bin", "/snap/bin"].map(PathBuf::from));
        dirs.extend(home().map(|h| h.join(".local/bin")));
        dirs.into_iter().map(|d| d.join(k.bin)).find(|p| p.is_file())
    }
}

/// The terminals on this device, most wanted first.
pub fn installed() -> Vec<Terminal> {
    KNOWN
        .iter()
        .filter(|k| locate(k).is_some())
        .map(|k| Terminal { id: k.id, name: k.name, builtin: k.builtin })
        .collect()
}

/// A device name as the daemon gives them. It becomes an argument, never part
/// of a script, but a leading dash would still be read as a flag.
fn device_name(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 253
        && !p.starts_with('-')
        && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_')
}

/// Open a new window of the terminal running `makima ssh PEER`.
pub async fn open_ssh(id: &str, peer: &str) -> Result<(), String> {
    if !device_name(peer) {
        return Err("that is not a device name".into());
    }
    let k = KNOWN.iter().find(|k| k.id == id).ok_or("that is not a terminal makima knows")?;
    let path = locate(k).ok_or_else(|| format!("{} is not installed", k.name))?;
    let makima = makima_binary()
        .ok_or("the makima command is missing — this app should have it inside; reinstall it")?;
    let argv: Vec<String> = vec![
        "/bin/sh".into(),
        "-c".into(),
        HOLD.into(),
        makima.to_string_lossy().into_owned(),
        peer.into(),
    ];

    let mut cmd = match id {
        // These two take a command line through AppleScript, typed into the
        // person's own shell, so it is quoted for that shell first.
        "terminal" | "iterm" => {
            let line = argv.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ");
            let script = if id == "terminal" {
                format!("tell application \"Terminal\"\nactivate\ndo script {}\nend tell", applescript_quote(&line))
            } else {
                format!(
                    "tell application \"iTerm\"\nactivate\nset w to (create window with default profile)\ntell current session of w to write text {}\nend tell",
                    applescript_quote(&line)
                )
            };
            let mut c = Command::new("osascript");
            c.arg("-e").arg(script);
            c
        }
        _ if cfg!(target_os = "macos") => {
            let mut c = Command::new("open");
            c.arg("-na").arg(&path).arg("--args").args(k.run).args(&argv);
            c
        }
        _ => {
            let mut c = Command::new(&path);
            c.args(k.run).args(&argv);
            c
        }
    };
    cmd.stdin(Stdio::null()).stdout(Stdio::null());

    if cfg!(target_os = "macos") {
        // open and osascript return as soon as the window is asked for, so
        // waiting for them costs nothing and catches a refusal.
        let out = cmd.stderr(Stdio::piped()).output().await.map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!("{} did not open: {}", k.name, String::from_utf8_lossy(&out.stderr).trim()));
        }
    } else {
        cmd.stderr(Stdio::null())
            .spawn()
            .map_err(|e| format!("{} did not open: {e}", k.name))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_names_are_checked() {
        assert!(device_name("justin06lee"));
        assert!(device_name("huiyuns-macbook-air-2.makima"));
        assert!(!device_name(""));
        assert!(!device_name("-oProxyCommand=x"));
        assert!(!device_name("a b"));
        assert!(!device_name("x;rm"));
    }

    #[test]
    fn ids_are_unique() {
        let mut ids: Vec<_> = KNOWN.iter().map(|k| k.id).collect();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), KNOWN.len());
    }
}
