//! makima's desktop app.
//!
//! A window and a tray icon over the daemon's local API. It exists because
//! everything makima does was reachable only from a terminal, and "which of my
//! machines can I see right now" is a question people ask twenty times a day
//! and should not have to type a command to answer.
//!
//! The whole app is a reader with a small set of named actions. See
//! `daemon.rs` for why reading and writing take deliberately different paths.

mod daemon;
mod privileged;

use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager};

/// How often the tray refreshes its own title.
///
/// The window polls on its own while it is open; this is only for the icon,
/// which is visible all the time and must not be a busy loop. Five seconds is
/// fast enough that a peer going away is noticed before it is asked about.
const TRAY_REFRESH: std::time::Duration = std::time::Duration::from_secs(5);

#[tauri::command]
async fn status() -> daemon::Snapshot {
    daemon::snapshot().await
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
async fn act(action: privileged::Action) -> Result<privileged::Outcome, String> {
    privileged::run(action).await
}

/// Show the window and bring it to the front.
///
/// Both halves matter: a window that is merely visible but behind the browser
/// looks like the app did nothing.
fn reveal(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .invoke_handler(tauri::generate_handler![status, doctor, ping, act])
        .setup(|app| {
            let handle = app.handle().clone();

            let open = MenuItem::with_id(app, "open", "Open makima", true, None::<&str>)?;
            let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&open, &quit])?;

            let tray = TrayIconBuilder::with_id("makima")
                .icon(app.default_window_icon().unwrap().clone())
                // A template image on macOS, so the glyph follows the menu bar
                // through light and dark rather than being a pale square in
                // one of them.
                .icon_as_template(true)
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(|app, event| match event.id.as_ref() {
                    "open" => reveal(app),
                    "quit" => app.exit(0),
                    _ => {}
                })
                .on_tray_icon_event(|tray, event| {
                    // Left click opens the window; the menu is on right click.
                    // That is the convention on both platforms, and the menu
                    // is for quitting rather than for doing the work.
                    if let TrayIconEvent::Click {
                        button: MouseButton::Left,
                        button_state: MouseButtonState::Up,
                        ..
                    } = event
                    {
                        reveal(tray.app_handle());
                    }
                })
                .build(app)?;

            // The tray title is the only part of the app visible when the
            // window is closed, so it carries the one fact worth glancing at:
            // how many machines are reachable, or that nothing is running.
            tauri::async_runtime::spawn(async move {
                loop {
                    let snap = daemon::snapshot().await;
                    let title = tray_title(&snap);
                    let _ = tray.set_tooltip(Some(&title));
                    #[cfg(target_os = "macos")]
                    let _ = tray.set_title(Some(&title));
                    let _ = &handle;
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
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("makima desktop failed to start");
}

/// One short line for the tray.
fn tray_title(snap: &daemon::Snapshot) -> String {
    let Some(status) = &snap.status else {
        return "makima — off".to_string();
    };
    let peers = status
        .get("peers")
        .and_then(|p| p.as_array())
        .map(|p| p.len())
        .unwrap_or(0);

    match peers {
        0 => "makima — no peers".to_string(),
        1 => "makima — 1 machine".to_string(),
        n => format!("makima — {n} machines"),
    }
}
