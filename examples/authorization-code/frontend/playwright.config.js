import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  workers: 1,
  timeout: 30_000,
  reporter: "list",
  use: {
    baseURL: "http://localhost:5173",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [
    {
      name: "chrome",
      use: { ...devices["Desktop Chrome"], channel: "chrome" },
    },
  ],
  webServer: [
    {
      command:
        "java -Dquarkus.http.port=18080 -Dquarkus.authorization-server.issuer=http://localhost:18080 -jar ../build/quarkus-app/quarkus-run.jar",
      url: "http://localhost:18080/.well-known/openid-configuration",
      timeout: 60_000,
      reuseExistingServer: false,
    },
    {
      command: "npm run dev",
      url: "http://localhost:5173",
      env: { VITE_AUTHORITY: "http://localhost:18080" },
      reuseExistingServer: false,
    },
  ],
});
