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
    /// Offer this machine as an exit node for the others, or stop offering.
    AdvertiseExit { on: bool },
    /// Mint an invite for the next machine.
    Invite,
    /// Publish a pairing address and listen for one machine.
    Pair,
    /// Put the `makima` command on PATH.
    LinkCli,
    /// Moving from Tailscale: start the network here, or find it running
    /// here, and mint an invite for every machine coming along.
    MigrateHost {
        advertise: String,
        name: String,
        #[serde(default)]
        invites: u8,
    },
    /// Moving from Tailscale: join the network, leaving Tailscale running —
    /// it is still how this machine reaches the others.
    MigrateJoin { invite: String, name: String },
    /// Moving from Tailscale: this machine's own switch, last of all. Stops
    /// Tailscale, proves makima works, then removes Tailscale — or puts it
    /// back exactly if makima does not come up.
    MigrateCutover {
        name: String,
        controller: String,
        #[serde(default)]
        server_self: bool,
        #[serde(default)]
        remove: bool,
    },
    /// Moving from Tailscale: the verdict on this machine's held switch —
    /// remove Tailscale, keep it running alongside, or call it off.
    MigrateCommit {
        #[serde(default)]
        verdict: String,
    },
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
            Action::AdvertiseExit { on } => {
                vec![s("set"), s("-advertise-exit-node"), s(if *on { "true" } else { "false" })]
            }
            Action::Invite => vec![s("invite"), s("-json")],
            Action::Pair => vec![s("pair")],
            Action::LinkCli => vec![s("link-cli"), s("-q")],
            Action::MigrateHost { advertise, name, invites } => vec![
                s("migrate"),
                s("host"),
                s("-json"),
                s("-advertise"),
                advertise.clone(),
                s("-name"),
                name.clone(),
                s("-invites"),
                invites.to_string(),
            ],
            Action::MigrateJoin { invite, name } => {
                vec![s("migrate"), s("join"), s("-name"), name.clone(), invite.clone()]
            }
            Action::MigrateCutover { name, controller, server_self, remove } => {
                let mut v = vec![s("migrate"), s("cutover"), s("-detach"), s("-name"), name.clone(), s("-controller"), controller.clone()];
                if *server_self {
                    v.push(s("-server-self"));
                }
                v.push(format!("-remove={remove}"));
                v
            }
            Action::MigrateCommit { verdict } => match verdict.as_str() {
                "keep" => vec![s("migrate"), s("commit"), s("-keep")],
                "abort" => vec![s("migrate"), s("commit"), s("-abort")],
                _ => vec![s("migrate"), s("commit")],
            },
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
            Action::AdvertiseExit { on: true } => "makima needs to offer this machine as an exit node".into(),
            Action::AdvertiseExit { on: false } => "makima needs to stop offering this machine as an exit node".into(),
            Action::Invite => "makima needs to create an invite".into(),
            Action::Pair => "makima needs to publish a pairing address".into(),
            Action::LinkCli => "makima needs to put its command in /usr/local/bin".into(),
            Action::MigrateHost { .. } => "makima needs to start your network on this device, to move your devices from Tailscale".into(),
            Action::MigrateJoin { .. } => "makima needs to join this device to your new network".into(),
            Action::MigrateCutover { remove: true, .. } => "makima needs to switch this device from Tailscale to makima, and uninstall Tailscale".into(),
            Action::MigrateCutover { .. } => "makima needs to switch this device from Tailscale to makima".into(),
            Action::MigrateCommit { verdict } if verdict == "abort" => "makima needs to put Tailscale back on this device".into(),
            Action::MigrateCommit { verdict } if verdict == "keep" => "makima needs to finish the move, keeping Tailscale on this device".into(),
            Action::MigrateCommit { .. } => "makima needs to finish the move: every device is confirmed on makima".into(),
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
                // Two shapes: the pasted mk1_ string, or the fifteen words —
                // possibly with a typed address in front of ten of them.
                if let Some(body) = invite.strip_prefix("mk1_") {
                    if body.is_empty() || body.len() > 4096 {
                        return Err("that invite is not the right length".into());
                    }
                    if !body
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                    {
                        return Err("that invite has characters in it that an invite never has — check the paste".into());
                    }
                    return Ok(());
                }
                let words: Vec<&str> = invite.split_whitespace().collect();
                if words.len() < 11 || words.len() > 40 || invite.len() > 512 {
                    return Err("that is not an invite — paste the mk1_ string, or type all fifteen words".into());
                }
                if !words.iter().all(|w| {
                    w.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || b == b'.' || b == b':' || b == b'/' || b == b'-' || b == b'[' || b == b']'
                    })
                }) {
                    return Err("those words have characters in them that an invite never has".into());
                }
                Ok(())
            }
            Action::ExitNode { name } => {
                if name.len() > 253 || name.chars().any(|c| c.is_control()) {
                    return Err("that is not a device name".into());
                }
                Ok(())
            }
            Action::MigrateHost { advertise, name, .. } => {
                machine_name(name)?;
                let ok = !advertise.is_empty()
                    && advertise.len() <= 253
                    && advertise.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:/[]_".contains(&b));
                if !ok {
                    return Err("that is not an address other devices can reach".into());
                }
                Ok(())
            }
            Action::MigrateJoin { invite, name } => {
                machine_name(name)?;
                Action::Join { invite: invite.clone() }.validate()
            }
            Action::MigrateCutover { name, controller, .. } => {
                machine_name(name)?;
                machine_name(controller)
            }
            Action::MigrateCommit { verdict } => match verdict.as_str() {
                "" | "commit" | "keep" | "abort" => Ok(()),
                _ => Err("that is not a verdict".into()),
            },
            _ => Ok(()),
        }
    }
}

/// A name as the migration gives machines: lowercase letters, digits and
/// hyphens, as `migrate.ValidName` in Go checks too.
fn machine_name(n: &str) -> Result<(), String> {
    let ok = !n.is_empty()
        && n.len() <= 63
        && !n.starts_with('-')
        && !n.ends_with('-')
        && n.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if ok {
        Ok(())
    } else {
        Err(format!("{n:?} is not a device name makima can use"))
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

/// Quote a string as an AppleScript literal.
///
/// AppleScript strings are double-quoted, with backslash and double quote the
/// only characters that need escaping. The shell command inside is already
/// single-quoted for the shell; this is the second, outer layer, and getting
/// it wrong is a syntax error before anything runs — which is exactly what
/// the app's Connect button used to show.
fn applescript_quote(s: &str) -> String {
    format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\""))
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

/// Where root keeps its own copy of the app's binaries.
///
/// Remembering the person's yes means letting sudo run makima without a
/// password, and that is only as safe as the file sudo runs. The copies inside
/// the app bundle belong to whoever dragged the app into /Applications, so a
/// rule pointing at them would hand root to anything that can write there.
/// These copies are root's, in a directory Apple creates root-owned for
/// exactly this kind of helper, so the only way to change them is to be root
/// already.
const TRUSTED_DIR: &str = "/Library/PrivilegedHelperTools/makima";

/// The binaries the app carries, all copied together: the CLI finds makimad
/// beside itself, so a lone copy of makima would start a daemon from nowhere.
const SIDECARS: [&str; 4] = ["makima", "makimad", "makima-server", "makima-relay"];

/// The sudoers drop-in that remembers the person's yes.
///
/// One per account, named without dots because sudo skips any file in
/// sudoers.d with a dot in its name.
fn sudoers_path(who: &str) -> String {
    format!("/etc/sudoers.d/makima_{}", who.replace(|c: char| !c.is_ascii_alphanumeric(), "_"))
}

/// The commands the rule allows, and nothing else.
///
/// Each is one of the app's own buttons, spelled the way `Action::argv` spells
/// it, so the rule grants what the person already said yes to — not the whole
/// CLI. A verb with no arguments is listed bare, which sudo reads as "exactly
/// these arguments". Anything not here falls back to the password prompt.
fn sudo_commands() -> Vec<String> {
    let bin = format!("{TRUSTED_DIR}/makima");
    [
        "up",
        "down",
        "join *",
        "allow *",
        "deny *",
        "set -exit-node *",
        "set -advertise-exit-node true",
        "set -advertise-exit-node false",
        "invite -json",
        "pair",
        "link-cli -q",
    ]
    .iter()
    .map(|args| format!("{bin} {args}"))
    .collect()
}

/// The sudoers rule itself, one line per element.
fn sudoers_lines(who: &str) -> Vec<String> {
    let alias = format!(
        "MAKIMA_{}",
        who.to_ascii_uppercase().replace(|c: char| !c.is_ascii_alphanumeric(), "_")
    );
    vec![
        "# Written by the makima app so its buttons stop asking for a password.".into(),
        "# Delete this file to make it ask every time again.".into(),
        format!("Cmnd_Alias {alias} = {}", sudo_commands().join(", ")),
        format!("{who} ALL=(root) NOPASSWD: {alias}"),
    ]
}

/// Whether root's copy is the same build as the one in the bundle.
///
/// Size and modification time, which `install -p` carries over. After an app
/// update they differ, the next action goes through the prompt once more, and
/// that prompt refreshes the copy — so the trusted binaries never lag the app.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn trusted_copy_current(src_dir: &std::path::Path, who: &str) -> bool {
    if !std::path::Path::new(&sudoers_path(who)).exists() {
        return false;
    }
    let stamp = |p: &std::path::Path| {
        let m = std::fs::metadata(p).ok()?;
        let t = m.modified().ok()?.duration_since(std::time::UNIX_EPOCH).ok()?;
        Some((m.len(), t.as_secs()))
    };
    SIDECARS.iter().all(|name| match stamp(&src_dir.join(name)) {
        None => true,
        Some(s) => stamp(&std::path::Path::new(TRUSTED_DIR).join(name)) == Some(s),
    })
}

/// The shell that installs root's copy and the rule, run inside the one
/// password prompt the person already sees.
///
/// Everything in it is best-effort and silent: if any step fails, the action
/// they clicked still runs, and they are simply asked again next time. The
/// rule is checked with visudo before it goes anywhere near sudoers.d — a
/// malformed file there breaks sudo for the whole machine.
fn trust_script(src_dir: &std::path::Path, who: &str) -> String {
    let mut s = format!(
        "{{ t=$(/usr/bin/mktemp /tmp/makima-sudoers.XXXXXX) && /bin/mkdir -p {d} && /usr/sbin/chown root:wheel {d} && /bin/chmod 755 {d}",
        d = shell_quote(TRUSTED_DIR),
    );
    for name in SIDECARS {
        let src = src_dir.join(name);
        if src.is_file() {
            s.push_str(&format!(
                " && /usr/bin/install -p -o root -g wheel -m 0755 {} {}",
                shell_quote(&src.to_string_lossy()),
                shell_quote(&format!("{TRUSTED_DIR}/{name}")),
            ));
        }
    }
    s.push_str(" && /usr/bin/printf '%s\\n'");
    for line in sudoers_lines(who) {
        s.push(' ');
        s.push_str(&shell_quote(&line));
    }
    s.push_str(&format!(
        " > \"$t\" && /usr/sbin/visudo -cqf \"$t\" && /usr/bin/install -o root -g wheel -m 0440 \"$t\" {}; /bin/rm -f \"$t\"; }} >/dev/null 2>&1; ",
        shell_quote(&sudoers_path(who)),
    ));
    s
}

/// Run an action through the remembered rule, if there is one.
///
/// None means "ask instead": no rule yet, a stale copy, or sudo saying no —
/// every sudo refusal starts with "sudo:", and makima's own errors never do.
#[cfg(target_os = "macos")]
async fn run_remembered(src_dir: &std::path::Path, who: &str, argv: &[String]) -> Option<std::process::Output> {
    if !trusted_copy_current(src_dir, who) {
        return None;
    }
    let out = Command::new("/usr/bin/sudo")
        .arg("-n")
        .arg(format!("{TRUSTED_DIR}/makima"))
        .args(argv)
        .stdin(Stdio::null())
        .output()
        .await
        .ok()?;
    if !out.status.success() && String::from_utf8_lossy(&out.stderr).trim_start().starts_with("sudo:") {
        return None;
    }
    Some(out)
}

/// Run an action, asking the user to authenticate first — once.
///
/// On macOS the first prompt also installs a narrow sudo rule for the app's
/// own buttons, so later clicks run without one. See `sudo_commands`.
pub async fn run(action: Action) -> Result<Outcome, String> {
    action.validate()?;

    let bin = makima_binary()
        .ok_or("the makima command is missing — this app should have it inside; reinstall it")?;
    // /usr/local/bin/makima is a symlink into the bundle once linked; the
    // bundle is where the rest of the binaries are.
    let src_dir = std::fs::canonicalize(&bin)
        .ok()
        .and_then(|p| p.parent().map(|d| d.to_path_buf()))
        .filter(|d| d != std::path::Path::new(TRUSTED_DIR));
    let bin = bin.to_string_lossy().to_string();
    let argv = action.argv();
    let reason = action.reason();

    #[cfg(target_os = "macos")]
    if let (Some(dir), Some(who)) = (&src_dir, owner()) {
        if let Some(out) = run_remembered(dir, &who, &argv).await {
            return Ok(finish(out));
        }
    }

    let output = if cfg!(target_os = "macos") {
        // `with administrator privileges` is Authorization Services: the
        // system draws the prompt, and this process never sees the password.
        let mut command = String::new();
        if let (Some(dir), Some(who)) = (&src_dir, owner()) {
            command.push_str(&trust_script(dir, &who));
        }
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
            applescript_quote(&command),
            applescript_quote(&reason),
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

    Ok(finish(output))
}

/// What a privileged run amounts to, whichever way it was run.
fn finish(output: std::process::Output) -> Outcome {
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();

    if output.status.success() {
        return Outcome { ok: true, output: stdout };
    }

    // A cancelled prompt is not a failure worth shouting about: the user said
    // no, and the app should say so rather than showing them an error.
    let cancelled = stderr.contains("User canceled")
        || stderr.contains("User cancelled")
        || stderr.contains("-128")
        || stderr.contains("Request dismissed")
        || stderr.contains("Not authorized");

    if cancelled {
        return Outcome { ok: false, output: "cancelled".into() };
    }

    Outcome {
        ok: false,
        output: tidy(&stdout, &stderr),
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_quote_makes_everything_literal() {
        assert_eq!(shell_quote("a b"), "'a b'");
        assert_eq!(shell_quote("it's"), r"'it'\''s'");
        assert_eq!(shell_quote(r#"x"y"#), r#"'x"y'"#);
    }

    #[test]
    fn applescript_quote_escapes_only_what_applescript_needs() {
        assert_eq!(applescript_quote("plain"), r#""plain""#);
        assert_eq!(applescript_quote(r#"say "hi""#), r#""say \"hi\"""#);
        assert_eq!(applescript_quote(r"back\slash"), r#""back\\slash""#);
        // A shell-quoted argument with a single quote survives both layers.
        assert_eq!(applescript_quote(&shell_quote("it's")), r#""'it'\\''s'""#);
    }

    #[test]
    fn join_accepts_both_shapes() {
        assert!(Action::Join { invite: "mk1_abcDEF123-_".into() }.validate().is_ok());
        let words = "abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve";
        assert!(Action::Join { invite: words.into() }.validate().is_ok());
        let hosted = "makima.example.dev abandon ability able about above absent absorb abstract absurd abuse";
        assert!(Action::Join { invite: hosted.into() }.validate().is_ok());
        assert!(Action::Join { invite: "just three words".into() }.validate().is_err());
        assert!(Action::Join { invite: "mk1_has spaces".into() }.validate().is_err());
    }

    #[test]
    fn migrate_actions_spell_what_go_expects() {
        // Pinned on the Go side too, in internal/migrate: TestActionArgs.
        let host = Action::MigrateHost { advertise: "192.168.1.20".into(), name: "tenet".into(), invites: 2 };
        assert_eq!(host.argv().join(" "), "migrate host -json -advertise 192.168.1.20 -name tenet -invites 2");
        let join = Action::MigrateJoin { invite: "mk1_abcDEF123-_".into(), name: "mac".into() };
        assert_eq!(join.argv().join(" "), "migrate join -name mac mk1_abcDEF123-_");
        let cut = Action::MigrateCutover { name: "mac".into(), controller: "tenet".into(), server_self: false, remove: true };
        assert_eq!(cut.argv().join(" "), "migrate cutover -detach -name mac -controller tenet -remove=true");
        let own = Action::MigrateCutover { name: "mac".into(), controller: "mac".into(), server_self: true, remove: false };
        assert_eq!(own.argv().join(" "), "migrate cutover -detach -name mac -controller mac -server-self -remove=false");
        let commit: Action = serde_json::from_str(r#"{"kind":"migrate-commit","verdict":"commit","server_self":false,"remove":false}"#).unwrap();
        assert_eq!(commit.argv().join(" "), "migrate commit");
        let keep: Action = serde_json::from_str(r#"{"kind":"migrate-commit","verdict":"keep","server_self":false,"remove":false}"#).unwrap();
        assert_eq!(keep.argv().join(" "), "migrate commit -keep");
        assert!(Action::MigrateCommit { verdict: "rm -rf".into() }.validate().is_err());

        // The JSON the Go side sends deserializes to exactly these.
        let parsed: Action = serde_json::from_str(r#"{"kind":"migrate-cutover","name":"mac","controller":"tenet","server_self":false,"remove":true}"#).unwrap();
        assert_eq!(parsed.argv(), cut.argv());
        let parsed: Action = serde_json::from_str(r#"{"kind":"migrate-host","advertise":"192.168.1.20","name":"tenet","invites":2,"server_self":false,"remove":false}"#).unwrap();
        assert_eq!(parsed.argv(), host.argv());

        assert!(host.validate().is_ok() && join.validate().is_ok() && cut.validate().is_ok());
        assert!(Action::MigrateHost { advertise: "a; rm -rf /".into(), name: "x".into(), invites: 1 }.validate().is_err());
        assert!(Action::MigrateCutover { name: "Bad Name".into(), controller: "x".into(), server_self: false, remove: true }.validate().is_err());
        assert!(Action::MigrateJoin { invite: "nope".into(), name: "mac".into() }.validate().is_err());
    }

    #[test]
    fn sudoers_rule_is_valid_and_narrow() {
        let lines = sudoers_lines("huiyun.lee");
        assert_eq!(sudoers_path("huiyun.lee"), "/etc/sudoers.d/makima_huiyun_lee");
        assert!(lines[2].starts_with("Cmnd_Alias MAKIMA_HUIYUN_LEE = /Library/PrivilegedHelperTools/makima/makima up, "));
        assert_eq!(lines[3], "huiyun.lee ALL=(root) NOPASSWD: MAKIMA_HUIYUN_LEE");
        // Every verb the app can ask for is covered by the rule.
        for a in [
            Action::Up,
            Action::Down,
            Action::Invite,
            Action::Pair,
            Action::LinkCli,
            Action::AdvertiseExit { on: true },
            Action::AdvertiseExit { on: false },
        ] {
            let spelled = format!("{TRUSTED_DIR}/makima {}", a.argv().join(" "));
            assert!(sudo_commands().contains(&spelled), "{spelled} is not in the rule");
        }
        // And nothing that is not a button — sshd, say — is.
        assert!(!lines[2].contains("sshd"));
    }
}
