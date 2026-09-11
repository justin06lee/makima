//! makima's desktop app.
//!
//! A menu bar item and a window over the daemon's local API. It exists
//! because everything makima does was reachable only from a terminal, and
//! "which of my machines can I see right now" is a question people ask twenty
//! times a day and should not have to type a command to answer.
//!
//! The whole app is a reader with a small set of named actions. See
//! `daemon.rs` for why reading and writing take deliberately different paths,
//! and `tray.rs` for the menu bar, which is most of the interface.

mod daemon;
mod migrate;
mod privileged;
mod tray;

use tauri::{AppHandle, Manager};

/// How often the tray refreshes.
///
/// The window polls on its own while it is open; this is only for the menu
/// bar, which is visible all the time and must not be a busy loop. Five
/// seconds is fast enough that a device going away is noticed before it is
/// asked about.
const TRAY_REFRESH: std::time::Duration = std::time::Duration::from_secs(5);

#[tauri::command]
async fn status() -> daemon::Snapshot {
    daemon::snapshot().await
}

#[tauri::command]
fn environment() -> daemon::Environment {
    daemon::environment()
}

#[tauri::command]
async fn doctor() -> Result<serde_json::Value, String> {
    daemon::diagnose().await
}

#[tauri::command]
async fn ping(peer: String) -> Result<serde_json::Value, String> {
    daemon::ping(&peer).await
}

#[tauri::command]
async fn act(app: AppHandle, action: privileged::Action) -> Result<privileged::Outcome, String> {
    let out = privileged::run(action).await;
    // The menu bar should agree with the window as soon as the window knows.
    app.state::<tray::State>().shown.lock().unwrap().clear();
    tray::refresh(&app).await;
    out
}

/// Send one file to a device, as this user, with no prompt.
#[tauri::command]
async fn send_file(peer: String, path: String) -> Result<privileged::Outcome, String> {
    if peer.is_empty() || peer.contains(':') || peer.chars().any(|c| c.is_control()) {
        return Err("that is not a device name".into());
    }
    if !std::path::Path::new(&path).is_file() {
        return Err("only files can be sent, one at a time".into());
    }
    privileged::run_unprivileged(&["cp".into(), "-q".into(), path, format!("{peer}:")]).await
}

/// Is Tailscale on this machine, and connected?
#[tauri::command]
async fn migrate_detect() -> serde_json::Value {
    migrate::detect().await
}

/// Look at every machine on the tailnet. Changes nothing.
#[tauri::command]
async fn migrate_scan(app: AppHandle) -> Result<(), String> {
    migrate::start(app, false, None).await
}

/// Move the chosen machines. The choice is the plan a scan produced, with
/// the person's decisions on it.
#[tauri::command]
async fn migrate_run(app: AppHandle, choice: serde_json::Value) -> Result<(), String> {
    migrate::start(app, true, Some(choice)).await
}

#[tauri::command]
async fn migrate_stop(app: AppHandle) -> Result<(), String> {
    migrate::stop(app).await
}

/// Show the window and bring it to the front.
///
/// Both halves matter: a window that is merely visible but behind the browser
/// looks like the app did nothing. On macOS the app also steps into the Dock
/// while its window is open, and back out when it closes — a menu bar app
/// with a permanent Dock icon is two apps, and one with none cannot be
/// ⌘-tabbed to while its window is up.
pub fn reveal(app: &AppHandle) {
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Regular);
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn conceal(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.hide();
    }
    #[cfg(target_os = "macos")]
    let _ = app.set_activation_policy(tauri::ActivationPolicy::Accessory);
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        // A second launch means "show me the window", not a second tray icon.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| reveal(app)))
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--hidden"]),
        ))
        .manage(tray::State::default())
        .manage(migrate::State::default())
        .invoke_handler(tauri::generate_handler![
            status,
            environment,
            doctor,
            ping,
            act,
            send_file,
            migrate_detect,
            migrate_scan,
            migrate_run,
            migrate_stop
        ])
        .setup(|app| {
            let handle = app.handle().clone();
            tray::install(&handle)?;

            // Launched at login, the app belongs in the menu bar and nowhere
            // else. Opened by hand, the window is what was asked for.
            let hidden = std::env::args().any(|a| a == "--hidden");
            if hidden {
                conceal(&handle);
            } else {
                reveal(&handle);
            }

            tauri::async_runtime::spawn(async move {
                loop {
                    tray::refresh(&handle).await;
                    tokio::time::sleep(TRAY_REFRESH).await;
                }
            });

            Ok(())
        })
        .on_window_event(|window, event| {
            // Closing the window hides it rather than quitting. A tray app
            // that exits when its window closes is a tray app nobody can find
            // again, and every platform's convention here is the same.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                conceal(window.app_handle());
            }
        })
        .run(tauri::generate_context!())
        .expect("makima desktop failed to start");
}
