import { defineConfig } from "@playwright/test";

const apiPort = Number(process.env.E2E_API_PORT ?? 8000);
const webPort = Number(process.env.E2E_WEB_PORT ?? 4173);
const apiBase = `http://127.0.0.1:${apiPort}`;

export default defineConfig({
  testDir: "./e2e",
  timeout: 60_000,
  expect: { timeout: 15_000 },
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: process.env.CI ? [["github"], ["list"]] : [["list"]],
  use: {
    baseURL: `http://127.0.0.1:${webPort}`,
    headless: true,
    trace: "retain-on-failure",
  },
  webServer: [
    {
      command: "bash ../scripts/run_e2e_api.sh",
      cwd: __dirname,
      port: apiPort,
      reuseExistingServer: !process.env.CI,
      timeout: 120_000,
      env: {
        ...process.env,
        AUTH_ENABLED: "true",
        LOCAL_AUTH_ENABLED: "true",
        SKIP_MIGRATIONS: "1",
        PROFILES_AUTO_SEED: "false",
        NOTIFICATIONS_ENABLED: "false",
        OBJECT_RBAC_ENABLED: "false",
        SECRET_KEY: process.env.SECRET_KEY ?? "ci-test-secret-key-32chars-minimum",
        POSTGRES_HOST: process.env.POSTGRES_HOST ?? "127.0.0.1",
        POSTGRES_PORT: process.env.POSTGRES_PORT ?? "5432",
        POSTGRES_DB: process.env.POSTGRES_DB ?? "secaudit",
        POSTGRES_USER: process.env.POSTGRES_USER ?? "secaudit",
        POSTGRES_PASSWORD: process.env.POSTGRES_PASSWORD ?? "secaudit_dev",
        REDIS_URL: process.env.REDIS_URL ?? "redis://127.0.0.1:6379/0",
        CELERY_BROKER_URL: process.env.CELERY_BROKER_URL ?? "redis://127.0.0.1:6379/0",
        CELERY_RESULT_BACKEND: process.env.CELERY_RESULT_BACKEND ?? "redis://127.0.0.1:6379/1",
      },
    },
    {
      command: "bash ../scripts/run_e2e_web.sh",
      cwd: __dirname,
      port: webPort,
      reuseExistingServer: !process.env.CI,
      timeout: 180_000,
      env: {
        ...process.env,
        E2E_WEB_PORT: String(webPort),
        VITE_AUTH_ENABLED: "true",
        VITE_LOCAL_AUTH_ENABLED: "true",
        VITE_API_URL: apiBase,
      },
    },
  ],
});
