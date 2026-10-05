import react from "@vitejs/plugin-react";
import { defineConfig } from "vitest/config";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    // Local-time rendering is asserted with Date getters; pin the zone so runs are deterministic.
    env: { TZ: "UTC" },
    // Bound the CPU/memory cost of independent browser environments.
    maxWorkers: 1,
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    setupFiles: ["./src/test/setup.ts"],
  },
});
