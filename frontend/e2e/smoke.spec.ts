import { expect, test } from "./fixtures/authenticated.fixture";

test("app shell loads for authenticated users", async ({ page }) => {
  await expect(page.locator("#root")).toBeVisible();
  await expect(page.locator(".pf-sidebar")).toBeVisible();
  await expect(page.getByRole("link", { name: "Dashboard" })).toBeVisible();
});
