import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The Flask backend serves the built app from its own origin in production, so
// assets are referenced relatively. In dev, /api is proxied to Flask on :8000.
export default defineConfig({
  plugins: [react()],
  base: "./",
  build: {
    outDir: "dist",
  },
  server: {
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
