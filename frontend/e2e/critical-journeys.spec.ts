import { expect, test } from "./fixtures/authenticated.fixture";
import { E2E_DATA } from "./constants";

test.describe("Critical journeys", () => {
  test("dashboard shows platform stats after login", async ({ page }) => {
    await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
    await expect(page.locator(".pf-stat-tiles, .pf-dashboard-hero")).toBeVisible();
  });

  test("profiles page lists seeded profile", async ({ page }) => {
    await page.getByRole("link", { name: "Catalog" }).click();
    await expect(page).toHaveURL(/\/profiles/);
    await expect(page.getByText(E2E_DATA.profileName)).toBeVisible({ timeout: 15_000 });
  });

  test("hosts page lists seeded host", async ({ page }) => {
    await page.getByRole("link", { name: "Inventory" }).click();
    await expect(page).toHaveURL(/\/hosts/);
    await expect(page.getByText(E2E_DATA.hostName)).toBeVisible({ timeout: 15_000 });
  });

  test("operations page lists seeded job and completed run", async ({ page }) => {
    await page.getByRole("link", { name: "Operations" }).click();
    await expect(page).toHaveURL(/\/jobs/);
    await expect(page.getByText(E2E_DATA.jobName)).toBeVisible({ timeout: 15_000 });

    await page.getByRole("row", { name: new RegExp(E2E_DATA.jobName) }).click();
    await expect(page.getByText("completed").first()).toBeVisible({ timeout: 15_000 });
  });

  test("report page opens for seeded completed run", async ({ page }) => {
    await page.goto("/jobs");
    await page.getByRole("row", { name: new RegExp(E2E_DATA.jobName) }).click();
    await page.getByRole("link", { name: /#\d+/ }).first().click();
    await expect(page).toHaveURL(/\/reports\?run=\d+/);
    await expect(page.getByText(/e2e\.check\.(pass|fail)/i).first()).toBeVisible({
      timeout: 15_000,
    });
  });
});
