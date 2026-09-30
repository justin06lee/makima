import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { execFile } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

/// The browser preview's stand-in for the app's terminals and terminal_icon
/// commands: which terminals are really on this Mac, looked for where
/// terminal.rs looks, and their icons drawn by the same script
/// (src-tauri/src/app_icon.js). Dev only, Mac only; anywhere else the list
/// is empty and the page shows what it shows with no terminal.
function terminalIcons(): Plugin {
  // Most wanted first, as in terminal.rs's KNOWN.
  const apps: Record<string, { name: string; app: string; builtin: boolean }> = {
    ghostty: { name: "Ghostty", app: "Ghostty.app", builtin: false },
    alacritty: { name: "Alacritty", app: "Alacritty.app", builtin: false },
    kitty: { name: "kitty", app: "kitty.app", builtin: false },
    wezterm: { name: "WezTerm", app: "WezTerm.app", builtin: false },
    iterm: { name: "iTerm", app: "iTerm.app", builtin: false },
    terminal: { name: "Terminal", app: "Terminal.app", builtin: true },
  };
  const dirs = ["/Applications", "/Applications/Utilities", "/System/Applications/Utilities", join(homedir(), "Applications")];
  const script = join(__dirname, "src-tauri/src/app_icon.js");
  const locate = (id: string) => apps[id] && dirs.map((d) => join(d, apps[id].app)).find((p) => existsSync(p));
  return {
    name: "makima-terminal-icons",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use("/dev/terminals", (_req, res) => {
        const found = process.platform === "darwin" ? Object.keys(apps).filter((id) => locate(id)) : [];
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify(found.map((id) => ({ id, name: apps[id].name, builtin: apps[id].builtin }))));
      });
      server.middlewares.use("/dev/terminal-icon/", (req, res) => {
        const id = decodeURIComponent((req.url ?? "").replace(/^\//, "").split("?")[0]);
        const app = locate(id);
        if (process.platform !== "darwin" || !app) {
          res.statusCode = 404;
          res.end();
          return;
        }
        const out = join(tmpdir(), `makima-dev-icon-${id}.png`);
        execFile("osascript", ["-l", "JavaScript", script, app, out], (err) => {
          if (err || !existsSync(out)) {
            res.statusCode = 404;
            res.end();
            return;
          }
          res.setHeader("Content-Type", "image/png");
          res.end(readFileSync(out));
          rmSync(out, { force: true });
        });
      });
    },
  };
}

// Tauri serves the built assets from disk, so everything is relative and there
// is no server to talk to but the one in Rust.
export default defineConfig({
  plugins: [react(), tailwindcss(), terminalIcons()],
  clearScreen: false,
  server: {
    port: 5183,
    strictPort: true,
    // In a plain browser the app reads the devserver over TCP instead of the
    // socket; see api.ts. Same handler, same types.
    proxy: { "/api": "http://127.0.0.1:8099" },
  },
  build: { outDir: "dist", emptyOutDir: true, target: "safari15" },
});
