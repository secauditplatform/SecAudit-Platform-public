import { expect, test } from "@playwright/test";
import { E2E_ADMIN } from "./constants";
import { forceEnglishLocale, loginLocal, logout } from "./helpers/auth";

test.describe("Authentication", () => {
  test("redirects unauthenticated users to login", async ({ page }) => {
    await forceEnglishLocale(page);
    await page.goto("/");
    await expect(page.getByText(/sign in to continue|требуется вход/i)).toBeVisible();
    await expect(page.getByRole("button", { name: /local sign-in|локальный вход/i })).toBeVisible();
  });

  test("local login succeeds and shows shell", async ({ page }) => {
    await loginLocal(page);
    await expect(page.getByRole("link", { name: "Dashboard" })).toBeVisible();
    await expect(page.locator(".pf-masthead__user")).toContainText(E2E_ADMIN.username);
  });

  test("logout returns to login screen", async ({ page }) => {
    await loginLocal(page);
    await logout(page);
    await expect(page.getByRole("button", { name: /local sign-in|локальный вход/i })).toBeVisible();
  });
});
