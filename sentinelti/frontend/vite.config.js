import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const localApiTarget =
  process.env.SENTINELTI_RENDER_API_URL || "http://127.0.0.1:8000";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      "/api": {
        target: localApiTarget,
        changeOrigin: true,
        rewrite: (path) => path.replace(/^\/api/, ""),
        configure: (proxy) => {
          proxy.on("proxyReq", (proxyRequest) => {
            const apiKey = process.env.SENTINELTI_API_KEY;
            if (apiKey) {
              proxyRequest.setHeader("X-API-KEY", apiKey);
            }
          });
        },
      },
    },
  },
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.js",
    globals: true,
  },
});