import { defineConfig } from "vite";

export default defineConfig({
  // The dev server port is fixed because `tauri.conf.json` pins `devUrl` to it.
  clearScreen: false,
  server: {
    host: "127.0.0.1",
    port: 1420,
    strictPort: true,
  },
});
