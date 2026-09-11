//! Moving from Tailscale.
//!
//! The work is `makima migrate`, run as this person — it reaches the other
//! machines with their own ssh, over Tailscale. This file only carries its
//! lines to the window and back.
//!
//! One kind of line is not for the window: `elevate`, which is the CLI asking
//! for a step on this machine that needs root. That goes through
//! `privileged::run`, the same prompt as every other button in the app, and
//! only the three migration actions are accepted — whatever the process says,
//! it cannot use this channel to ask for anything else.

use std::process::Stdio;
use std::sync::Arc;

use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::Mutex;

use crate::privileged::{self, Action};

/// The migration running now, if one is.
#[derive(Default)]
pub struct State {
    child: std::sync::Mutex<Option<Running>>,
}

struct Running {
    child: Arc<Mutex<Child>>,
    /// A run cannot be stopped from the window once it has begun: it may be
    /// halfway through switching a machine, and the machine finishes on its
    /// own regardless. A scan can.
    stoppable: bool,
}

/// Is Tailscale here, and on? Cheap: asks the local Tailscale only.
pub async fn detect() -> Value {
    match privileged::run_unprivileged(&["migrate".into(), "detect".into(), "-json".into()]).await {
        Ok(o) if o.ok => serde_json::from_str(&o.output).unwrap_or(json!({ "installed": false })),
        _ => json!({ "installed": false }),
    }
}

/// Start a scan, or a run with the person's choice, streaming its events to
/// the window as `migrate`.
pub async fn start(app: AppHandle, run: bool, choice: Option<Value>) -> Result<(), String> {
    let bin = privileged::makima_binary()
        .ok_or("the makima command is missing — this app should have it inside; reinstall it")?;

    let state = app.state::<State>();
    {
        let guard = state.child.lock().unwrap();
        if guard.is_some() {
            return Err("a move from Tailscale is already under way".into());
        }
    }

    let args: Vec<&str> = if run { vec!["migrate", "run", "-app"] } else { vec!["migrate", "scan", "-json"] };
    let mut child = Command::new(&bin)
        .args(&args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| e.to_string())?;

    let stdin = Arc::new(Mutex::new(child.stdin.take().ok_or("no stdin")?));
    let stdout = child.stdout.take().ok_or("no stdout")?;
    let stderr = child.stderr.take();

    if let Some(choice) = choice {
        // The choice — passwords for other machines' sudo included — goes
        // down the pipe, never onto a command line.
        let mut line = serde_json::to_vec(&choice).map_err(|e| e.to_string())?;
        line.push(b'\n');
        stdin.lock().await.write_all(&line).await.map_err(|e| e.to_string())?;
    }

    let child = Arc::new(Mutex::new(child));
    *state.child.lock().unwrap() = Some(Running { child: child.clone(), stoppable: !run });

    // stderr is kept for the one case it matters: the process dying without
    // saying anything on stdout.
    let tail = Arc::new(std::sync::Mutex::new(String::new()));
    if let Some(err) = stderr {
        let tail = tail.clone();
        tauri::async_runtime::spawn(async move {
            let mut lines = BufReader::new(err).lines();
            while let Ok(Some(l)) = lines.next_line().await {
                let mut t = tail.lock().unwrap();
                t.push_str(&l);
                t.push('\n');
                if t.len() > 4000 {
                    let cut = t.len() - 4000;
                    t.drain(..cut);
                }
            }
        });
    }

    let handle = app.clone();
    tauri::async_runtime::spawn(async move {
        let mut lines = BufReader::new(stdout).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let Ok(event) = serde_json::from_str::<Value>(&line) else { continue };
            if event.get("type").and_then(Value::as_str) == Some("elevate") {
                let app = handle.clone();
                let stdin = stdin.clone();
                tauri::async_runtime::spawn(async move { answer(app, stdin, event).await });
                continue;
            }
            let _ = handle.emit("migrate", event);
        }
        let code = child.lock().await.wait().await.ok().and_then(|s| s.code());
        let stderr = tail.lock().unwrap().trim().to_string();
        let _ = handle.emit("migrate", json!({ "type": "exit", "code": code, "detail": stderr }));
        {
            let state = handle.state::<State>();
            *state.child.lock().unwrap() = None;
        }
        crate::tray::refresh(&handle).await;
    });
    Ok(())
}

/// Carry out one root step the CLI asked for, and tell it how that went.
async fn answer(app: AppHandle, stdin: Arc<Mutex<ChildStdin>>, event: Value) {
    let id = event.get("id").and_then(Value::as_i64).unwrap_or(0);
    let reply = match serde_json::from_value::<Action>(event.get("action").cloned().unwrap_or(Value::Null)) {
        Ok(action @ (Action::MigrateHost { .. } | Action::MigrateJoin { .. } | Action::MigrateCutover { .. })) => {
            let _ = app.emit("migrate", json!({ "type": "prompt" }));
            match privileged::run(action).await {
                Ok(o) => json!({ "id": id, "ok": o.ok, "output": o.output }),
                Err(e) => json!({ "id": id, "ok": false, "output": e }),
            }
        }
        _ => json!({ "id": id, "ok": false, "output": "the app only runs migration steps for a migration" }),
    };
    let mut line = serde_json::to_vec(&reply).unwrap_or_default();
    line.push(b'\n');
    let _ = stdin.lock().await.write_all(&line).await;
}

/// Stop a scan. A run is left to finish.
pub async fn stop(app: AppHandle) -> Result<(), String> {
    let state = app.state::<State>();
    let running = {
        let guard = state.child.lock().unwrap();
        guard.as_ref().map(|r| (r.child.clone(), r.stoppable))
    };
    match running {
        Some((child, true)) => {
            let _ = child.lock().await.start_kill();
            Ok(())
        }
        Some((_, false)) => Err("the move is under way and finishes on its own".into()),
        None => Ok(()),
    }
}
