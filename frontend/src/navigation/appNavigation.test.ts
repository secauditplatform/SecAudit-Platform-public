import { describe, expect, it } from "vitest";
import {
  filterNavGroups,
  isNavItemActive,
  isOperationsPath,
  NAV_GROUPS,
} from "../navigation/appNavigation";

describe("filterNavGroups", () => {
  it("hides operator-only items without operate permission", () => {
    const groups = filterNavGroups(NAV_GROUPS, false, false, false, false);
    const ids = groups.flatMap((g) => g.items.map((i) => i.id));
    expect(ids).not.toContain("console");
    expect(ids).not.toContain("auditFlow");
    expect(ids).not.toContain("credentials");
    expect(ids).not.toContain("auditLogs");
    expect(ids).toContain("jobs");
    expect(ids).toContain("reports");
  });

  it("hides audit logs for operator without audit access", () => {
    const groups = filterNavGroups(NAV_GROUPS, false, false, true, false);
    const ids = groups.flatMap((g) => g.items.map((i) => i.id));
    expect(ids).toContain("console");
    expect(ids).not.toContain("auditLogs");
  });

  it("shows audit logs for roles with audit access", () => {
    const groups = filterNavGroups(NAV_GROUPS, false, true, true, true);
    const ids = groups.flatMap((g) => g.items.map((i) => i.id));
    expect(ids).toContain("auditLogs");
  });

  it("shows only overview and reports for auditor portal", () => {
    const groups = filterNavGroups(NAV_GROUPS, true, false, false, false);
    const ids = groups.flatMap((g) => g.items.map((i) => i.id));
    expect(ids).toContain("dashboard");
    expect(ids).toContain("overview");
    expect(ids).toContain("trends");
    expect(ids).toContain("reports");
    expect(ids).not.toContain("waivers");
    expect(ids).not.toContain("auditLogs");
    expect(ids).not.toContain("console");
  });
});

describe("isOperationsPath", () => {
  it("matches compliance and remediation routes for all platforms", () => {
    expect(isOperationsPath("/jobs")).toBe(true);
    expect(isOperationsPath("/remediation")).toBe(true);
    expect(isOperationsPath("/network/jobs")).toBe(true);
    expect(isOperationsPath("/network/remediation")).toBe(true);
  });

  it("ignores unrelated routes", () => {
    expect(isOperationsPath("/playbooks")).toBe(false);
    expect(isOperationsPath("/network")).toBe(false);
  });
});

describe("isNavItemActive", () => {
  const jobsItem = { id: "jobs" as const, to: "/jobs" };

  it("highlights Operations on network routes", () => {
    expect(isNavItemActive(jobsItem, "/network/jobs")).toBe(true);
    expect(isNavItemActive(jobsItem, "/network/remediation")).toBe(true);
  });

  it("highlights Operations on linux and windows routes", () => {
    expect(isNavItemActive(jobsItem, "/jobs")).toBe(true);
    expect(isNavItemActive(jobsItem, "/remediation")).toBe(true);
  });

  it("keeps default matching for other nav items", () => {
    expect(isNavItemActive({ id: "profiles", to: "/profiles" }, "/profiles")).toBe(true);
    expect(isNavItemActive({ id: "profiles", to: "/profiles" }, "/playbooks")).toBe(false);
    expect(isNavItemActive({ id: "dashboard", to: "/", end: true }, "/")).toBe(true);
    expect(isNavItemActive({ id: "dashboard", to: "/", end: true }, "/overview")).toBe(false);
  });
});
