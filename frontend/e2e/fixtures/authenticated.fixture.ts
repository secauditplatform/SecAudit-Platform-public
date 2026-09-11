import { test as base } from "@playwright/test";
import { loginLocal } from "../helpers/auth";

export const test = base.extend({
  page: async ({ page }, use) => {
    await loginLocal(page);
    await use(page);
  },
});

export { expect } from "@playwright/test";
