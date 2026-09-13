import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The Flask backend serves the built app from its own origin at the root, so
// assets are referenced from an absolute base ("/"). A relative base ("./")
// breaks nested client-side routes, whose assets would resolve against the route
// path. In dev, /api is proxied to Flask on :8000.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: "dist",
  },
  server: {
    proxy: {
      "/api": "http://localhost:8000",
    },
  },
});
