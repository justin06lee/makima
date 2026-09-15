//! The menu bar.
//!
//! The one part of the app that is always on screen, so it carries the whole
//! answer to "what can I reach right now": this device's address, every other
//! device and whether it is up, which exit node is in use, and a way to turn
//! the tunnel on and off. All of it is a native menu — the platform's own,
//! not a window pretending to be one — because that is what a menu bar item
//! is for and what every other one on the bar does.
//!
//! The menu is rebuilt whenever what it shows changes, and only then. A menu
//! replaced under an open cursor is unpleasant, and replacing it every few
//! seconds for the same content would be that for no reason.

use std::sync::Mutex;

use tauri::image::Image;
use tauri::menu::{CheckMenuItem, IconMenuItem, Menu, MenuItem, PredefinedMenuItem, Submenu};
use tauri::tray::TrayIcon;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_clipboard_manager::ClipboardExt;

use crate::daemon::{self, Snapshot};
use crate::privileged;

/// Everything the tray's event handler needs that arrives after it is built.
#[derive(Default)]
pub struct State {
    /// The latest snapshot, so a click on a device can copy its address
    /// without another round trip.
    pub snapshot: Mutex<Snapshot>,
    /// What the current menu shows, so it is only rebuilt on change.
    pub shown: Mutex<String>,
}

/// One device, as the menu needs it.
struct Device {
    name: String,
    address: String,
    online: bool,
    exit: bool,
}

/// What the snapshot says, flattened for the menu.
struct View {
    running: bool,
    name: String,
    address: String,
    devices: Vec<Device>,
    exit_node: String,
}

fn view(snap: &Snapshot) -> View {
    let Some(st) = &snap.status else {
        return View {
            running: false,
            name: String::new(),
            address: String::new(),
            devices: vec![],
            exit_node: String::new(),
        };
    };
    let s = |v: Option<&serde_json::Value>| v.and_then(|x| x.as_str()).unwrap_or("").to_string();
    let devices = st
        .get("peers")
        .and_then(|p| p.as_array())
        .map(|peers| {
            peers
                .iter()
                .map(|p| Device {
                    name: s(p.get("name")),
                    address: s(p.get("address")),
                    online: p.get("online").and_then(|v| v.as_bool()).unwrap_or(false),
                    exit: p.get("exit_node").and_then(|v| v.as_bool()).unwrap_or(false),
                })
                .collect()
        })
        .unwrap_or_default();
    View {
        running: true,
        name: s(st.get("node").and_then(|n| n.get("name"))),
        address: s(st.get("node").and_then(|n| n.get("address"))),
        devices,
        exit_node: s(st.get("exit_node")),
    }
}

/// A short fingerprint of what the menu would show.
fn signature(v: &View, member: bool) -> String {
    let mut s = format!("{}|{}|{}|{}|{}", v.running, member, v.name, v.address, v.exit_node);
    for d in &v.devices {
        s.push_str(&format!("|{}:{}:{}:{}", d.name, d.address, d.online, d.exit));
    }
    s
}

/// Refresh the icon, tooltip and menu from a fresh snapshot.
pub async fn refresh(app: &AppHandle) {
    let snap = daemon::snapshot().await;
    let env = daemon::environment();
    let v = view(&snap);
    let state = app.state::<State>();
    *state.snapshot.lock().unwrap() = snap;

    let Some(tray) = app.tray_by_id("makima") else { return };

    let sig = signature(&v, env.member);
    {
        let mut shown = state.shown.lock().unwrap();
        if *shown == sig {
            return;
        }
        *shown = sig;
    }

    let _ = tray.set_icon(Some(icon(v.running)));
    let _ = tray.set_icon_as_template(true);
    let _ = tray.set_tooltip(Some(tooltip(&v)));
    if let Ok(menu) = build(app, &v, env.member) {
        let _ = tray.set_menu(Some(menu));
    }
}

fn tooltip(v: &View) -> String {
    if !v.running {
        return "makima — off".into();
    }
    let online = v.devices.iter().filter(|d| d.online).count();
    match v.devices.len() {
        0 => format!("makima — {}, no other devices", v.name),
        n => format!("makima — {online} of {n} devices online"),
    }
}

/// The whole menu, from the view.
fn build(app: &AppHandle, v: &View, member: bool) -> tauri::Result<Menu<tauri::Wry>> {
    // A plain item rather than the predefined one, which draws an icon of its
    // own on macOS and throws the column alignment of everything above it.
    let quit = MenuItem::with_id(app, "quit", "Quit makima", true, Some("CmdOrCtrl+Q"))?;
    let open = MenuItem::with_id(app, "open", "Open makima", true, None::<&str>)?;

    if !v.running {
        let head = MenuItem::with_id(app, "head", "makima is off", false, None::<&str>)?;
        let connect = if member {
            MenuItem::with_id(app, "toggle", "Connect", true, None::<&str>)?
        } else {
            MenuItem::with_id(app, "setup", "Set up makima…", true, None::<&str>)?
        };
        return Menu::with_items(
            app,
            &[
                &head,
                &PredefinedMenuItem::separator(app)?,
                &connect,
                &open,
                &PredefinedMenuItem::separator(app)?,
                &quit,
            ],
        );
    }

    let head = MenuItem::with_id(app, "head", "Connected", false, None::<&str>)?;
    let this = MenuItem::with_id(
        app,
        "self",
        format!("This device: {} ({})", v.name, v.address),
        true,
        None::<&str>,
    )?;

    // Devices: one row each, a dot for whether it is reachable, click to
    // copy the address. Exactly what somebody about to type ssh wants.
    let devices = if v.devices.is_empty() {
        let none = MenuItem::with_id(app, "no-devices", "No other devices yet", false, None::<&str>)?;
        Submenu::with_items(app, "Devices", true, &[&none])?
    } else {
        let sub = Submenu::with_id(app, "devices", "Devices", true)?;
        for d in &v.devices {
            let item = IconMenuItem::with_id(
                app,
                format!("peer:{}", d.name),
                format!("{}    {}", d.name, d.address),
                true,
                Some(dot(d.online)),
                None::<&str>,
            )?;
            sub.append(&item)?;
        }
        sub
    };

    // Exit nodes: a radio group drawn with check items, "None" first.
    let exits = Submenu::with_id(app, "exit", "Exit node", true)?;
    let none = CheckMenuItem::with_id(app, "exit:", "None", true, v.exit_node.is_empty(), None::<&str>)?;
    exits.append(&none)?;
    let offering: Vec<&Device> = v.devices.iter().filter(|d| d.exit).collect();
    if !offering.is_empty() {
        exits.append(&PredefinedMenuItem::separator(app)?)?;
        for d in offering {
            let item = CheckMenuItem::with_id(
                app,
                format!("exit:{}", d.name),
                &d.name,
                d.online || v.exit_node == d.name,
                v.exit_node == d.name,
                None::<&str>,
            )?;
            exits.append(&item)?;
        }
    } else {
        let hint = MenuItem::with_id(app, "no-exits", "No device offers to be one", false, None::<&str>)?;
        exits.append(&PredefinedMenuItem::separator(app)?)?;
        exits.append(&hint)?;
    }

    let add = MenuItem::with_id(app, "add", "Add a device…", true, None::<&str>)?;
    let disconnect = MenuItem::with_id(app, "toggle", "Disconnect", true, None::<&str>)?;

    Menu::with_items(
        app,
        &[
            &head,
            &this,
            &PredefinedMenuItem::separator(app)?,
            &devices,
            &exits,
            &PredefinedMenuItem::separator(app)?,
            &add,
            &open,
            &PredefinedMenuItem::separator(app)?,
            &disconnect,
            &quit,
        ],
    )
}

/// What a click on a menu item does.
pub fn on_menu(app: &AppHandle, id: &str) {
    match id {
        "quit" => app.exit(0),
        "open" => crate::reveal(app),
        "setup" => crate::reveal(app),
        "add" => {
            crate::reveal(app);
            let _ = app.emit("navigate", "add-device");
        }
        "self" => {
            let state = app.state::<State>();
            let v = view(&state.snapshot.lock().unwrap());
            copy(app, &v.address);
        }
        "toggle" => {
            let state = app.state::<State>();
            let running = state.snapshot.lock().unwrap().running;
            let action = if running { privileged::Action::Down } else { privileged::Action::Up };
            act(app.clone(), action);
        }
        _ => {
            if let Some(name) = id.strip_prefix("peer:") {
                let state = app.state::<State>();
                let v = view(&state.snapshot.lock().unwrap());
                if let Some(d) = v.devices.iter().find(|d| d.name == name) {
                    copy(app, &d.address);
                }
            } else if let Some(name) = id.strip_prefix("exit:") {
                act(app.clone(), privileged::Action::ExitNode { name: name.to_string() });
            }
        }
    }
}

/// Run a privileged action from the tray and refresh when it is done.
///
/// Failures are shown in the window, which is opened for the purpose: a
/// menu has nowhere to put an error, and swallowing one is worse.
fn act(app: AppHandle, action: privileged::Action) {
    tauri::async_runtime::spawn(async move {
        match privileged::run(action).await {
            Ok(out) if out.ok || out.output == "cancelled" => {}
            Ok(out) => {
                crate::reveal(&app);
                let _ = app.emit("notice", out.output);
            }
            Err(e) => {
                crate::reveal(&app);
                let _ = app.emit("notice", e);
            }
        }
        // Force a rebuild: the signature is cleared so the next refresh
        // redraws even if the daemon has not caught up yet.
        app.state::<State>().shown.lock().unwrap().clear();
        refresh(&app).await;
    });
}

fn copy(app: &AppHandle, text: &str) {
    if !text.is_empty() {
        let _ = app.clipboard().write_text(text.to_string());
    }
}

/// The menu bar glyph, dimmed when nothing is running.
///
/// A template image: one colour and an alpha channel. macOS recolours it for
/// the bar, so the "off" state is the same shape at a third of the opacity —
/// what every other menu bar item does to say it is idle.
pub fn icon(on: bool) -> Image<'static> {
    let base = Image::from_bytes(include_bytes!("../icons/tray.png")).expect("tray icon is a PNG");
    let (w, h) = (base.width(), base.height());
    let mut rgba = base.rgba().to_vec();
    if !on {
        for px in rgba.chunks_mut(4) {
            px[3] = (px[3] as u16 * 38 / 100) as u8;
        }
    }
    Image::new_owned(rgba, w, h)
}

/// A small filled circle: green for a device that is reachable, grey for one
/// that is not. Drawn rather than shipped, because it is nine lines.
fn dot(online: bool) -> Image<'static> {
    const SIZE: u32 = 14;
    let (r, g, b) = if online { (52u8, 199u8, 89u8) } else { (174u8, 174u8, 178u8) };
    let mut rgba = vec![0u8; (SIZE * SIZE * 4) as usize];
    let centre = SIZE as f32 / 2.0;
    let radius = 4.0f32;
    for y in 0..SIZE {
        for x in 0..SIZE {
            let dx = x as f32 + 0.5 - centre;
            let dy = y as f32 + 0.5 - centre;
            let d = (dx * dx + dy * dy).sqrt();
            let a = (radius - d + 0.5).clamp(0.0, 1.0);
            let i = ((y * SIZE + x) * 4) as usize;
            rgba[i] = r;
            rgba[i + 1] = g;
            rgba[i + 2] = b;
            rgba[i + 3] = (a * 255.0) as u8;
        }
    }
    Image::new_owned(rgba, SIZE, SIZE)
}

/// Build the tray for the first time.
pub fn install(app: &AppHandle) -> tauri::Result<TrayIcon> {
    use tauri::tray::TrayIconBuilder;

    let menu = Menu::with_items(
        app,
        &[
            &MenuItem::with_id(app, "head", "Looking for makima…", false, None::<&str>)?,
            &PredefinedMenuItem::separator(app)?,
            &MenuItem::with_id(app, "open", "Open makima", true, None::<&str>)?,
            &MenuItem::with_id(app, "quit", "Quit makima", true, Some("CmdOrCtrl+Q"))?,
        ],
    )?;

    TrayIconBuilder::with_id("makima")
        .icon(icon(false))
        .icon_as_template(true)
        .tooltip("makima")
        .menu(&menu)
        // The menu is the whole interface here, so it is what a click gets.
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| on_menu(app, event.id.as_ref()))
        .build(app)
}
