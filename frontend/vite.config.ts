import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const isDocker = process.env.CHOKIDAR_USEPOLLING === "true";

const publicHost = process.env.VITE_PUBLIC_HOST || "localhost";

export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    strictPort: true,
    // Allow LAN / future domain hostnames (Vite 5.1+)
    allowedHosts: true,
    watch: isDocker
      ? {
          usePolling: true,
          interval: 1000,
        }
      : undefined,
    hmr: {
      // Must match the host the browser uses (LAN IP / domain), not only localhost
      host: publicHost,
      port: 5173,
      clientPort: 5173,
    },
    proxy: {
      "/api": {
        target: process.env.VITE_API_PROXY || "http://api:8000",
        changeOrigin: true,
        // Same-origin WS default (resolveWsBaseUrl) upgrades through Vite.
        ws: true,
      },
    },
  },
});
