import react from "@vitejs/plugin-react";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig } from "vite";

const root = fileURLToPath(new URL(".", import.meta.url));

export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "harness-dist",
    emptyOutDir: true,
    sourcemap: false,
    rollupOptions: {
      input: resolve(root, "harness/filters-focus.html"),
    },
  },
});
