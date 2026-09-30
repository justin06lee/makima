// Prevents a console window appearing alongside the app on Windows release
// builds. Harmless everywhere else.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    // WebKitGTK's DMA-BUF renderer is known to leave the window blank on
    // NVIDIA's drivers, Jetsons included: it opens, and stays empty. Drawing
    // through shared memory instead costs a window this small nothing
    // measurable. Set before GTK starts, and only when the person has not
    // said otherwise.
    #[cfg(target_os = "linux")]
    if std::env::var_os("WEBKIT_DISABLE_DMABUF_RENDERER").is_none() {
        std::env::set_var("WEBKIT_DISABLE_DMABUF_RENDERER", "1");
    }
    makima_desktop_lib::run()
}
