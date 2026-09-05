import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// Tauri serves the built assets from disk, so everything is relative and there
// is no server to talk to but the one in Rust.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  clearScreen: false,
  server: { port: 5183, strictPort: true },
  build: { outDir: "dist", emptyOutDir: true, target: "safari15" },
});
