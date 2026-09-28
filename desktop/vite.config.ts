import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { execFile } from "node:child_process";
import { existsSync, readFileSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";

/// The browser preview's stand-in for the app's terminal_icon command: the
/// same script (src-tauri/src/app_icon.js) run against the same app bundles,
/// so the onboarding can be looked at with real icons. Dev only, Mac only;
/// anything else answers 404 and the page draws a plain icon.
function terminalIcons(): Plugin {
  const apps: Record<string, string> = {
    ghostty: "Ghostty.app",
    alacritty: "Alacritty.app",
    kitty: "kitty.app",
    wezterm: "WezTerm.app",
    iterm: "iTerm.app",
    terminal: "Terminal.app",
  };
  const dirs = ["/Applications", "/Applications/Utilities", "/System/Applications/Utilities", join(homedir(), "Applications")];
  const script = join(__dirname, "src-tauri/src/app_icon.js");
  return {
    name: "makima-terminal-icons",
    apply: "serve",
    configureServer(server) {
      server.middlewares.use("/dev/terminal-icon/", (req, res) => {
        const id = decodeURIComponent((req.url ?? "").replace(/^\//, "").split("?")[0]);
        const app = apps[id] && dirs.map((d) => join(d, apps[id])).find((p) => existsSync(p));
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
