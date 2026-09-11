export const E2E_ADMIN = {
  username: process.env.E2E_ADMIN_USERNAME ?? "e2e-admin",
  password: process.env.E2E_ADMIN_PASSWORD ?? "e2e-admin-password-32chars-min",
} as const;

export const E2E_DATA = {
  profileName: "E2E Test Profile",
  hostName: "e2e-host",
  jobName: "E2E Compliance Job",
} as const;

export const LOCALE_STORAGE_KEY = "secaudit_locale";
