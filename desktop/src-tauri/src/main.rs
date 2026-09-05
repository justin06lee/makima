// Prevents a console window appearing alongside the app on Windows release
// builds. Harmless everywhere else.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    makima_desktop_lib::run()
}
