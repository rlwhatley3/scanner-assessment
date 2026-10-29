import react from "@vitejs/plugin-react";
import { defineConfig, searchForWorkspaceRoot } from "vite";

const appBasePath =
  process.env.VITE_APP_BASE_PATH ||
  process.env.VITE_CODER_APP_BASE_PATH ||
  process.env.VITE_CODE_SERVER_BASE_PATH ||
  "/";
const apiPort = process.env.API_PORT || "3001";

export default defineConfig({
  base: appBasePath,
  plugins: [react()],
  build: {
    chunkSizeWarningLimit: 2000,
  },
  server: {
    host: process.env.HOST || "127.0.0.1",
    port: Number(process.env.UI_PORT || "5173"),
    strictPort: true,
    // The playground's sample inputs are imported from the repo's tests/ folder.
    fs: { allow: [searchForWorkspaceRoot(process.cwd()), "../tests"] },
    proxy: {
      "/api": `http://127.0.0.1:${apiPort}`,
      "/swagger-ui": `http://127.0.0.1:${apiPort}`,
    },
  },
});
