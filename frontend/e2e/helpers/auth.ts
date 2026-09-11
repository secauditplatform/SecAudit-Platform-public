import { expect, type Page } from "@playwright/test";
import { E2E_ADMIN, LOCALE_STORAGE_KEY } from "../constants";

export async function forceEnglishLocale(page: Page) {
  await page.addInitScript((key) => {
    localStorage.setItem(key, "en");
  }, LOCALE_STORAGE_KEY);
}

export async function loginLocal(page: Page) {
  await forceEnglishLocale(page);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "SecAudit" })).toBeVisible();

  await page.getByRole("button", { name: /local sign-in|локальный вход/i }).click();
  await page.locator("#local-username").fill(E2E_ADMIN.username);
  await page.locator("#local-password").fill(E2E_ADMIN.password);
  await page.getByRole("button", { name: /sign in|войти/i }).click();

  await expect(page.locator(".pf-sidebar, .pf-dashboard-hero, nav.pf-sidebar")).toBeVisible({
    timeout: 15_000,
  });
}

export async function logout(page: Page) {
  const logoutButton = page.getByRole("button", { name: /log out|выйти/i });
  if (await logoutButton.isVisible()) {
    await logoutButton.click();
    await expect(page.getByRole("heading", { name: "SecAudit" })).toBeVisible();
  }
}
