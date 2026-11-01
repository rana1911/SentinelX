import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
// base "./" so the built app works under any path. The dev proxy forwards
// /api to the Go audit server (sentinelx-server) on :8080.
export default defineConfig({
    plugins: [react()],
    base: "./",
    server: {
        proxy: {
            "/api": {
                target: "http://localhost:8080",
                changeOrigin: true,
            },
        },
    },
});
