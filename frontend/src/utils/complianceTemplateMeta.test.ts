import { describe, expect, it } from "vitest";
import { complianceDisplayName, complianceTemplateCategory } from "./complianceTemplateMeta";

describe("complianceDisplayName", () => {
  it("strips trailing Compliance from the profile title", () => {
    expect(complianceDisplayName("AKS Optimized Azure Linux 2 — Compliance")).toBe(
      "AKS Optimized Azure Linux 2"
    );
    expect(complianceDisplayName("AlmaLinux 10 - Compliance")).toBe("AlmaLinux 10");
    expect(complianceDisplayName("unused", "PostgreSQL 15")).toBe("PostgreSQL 15");
  });
});

describe("complianceTemplateCategory", () => {
  it("classifies common CRE profiles", () => {
    expect(complianceTemplateCategory("Ubuntu 24.04 LTS — Compliance")).toBe("os");
    expect(complianceTemplateCategory("PostgreSQL CRE")).toBe("databases");
    expect(complianceTemplateCategory("Apache HTTP 2.4")).toBe("web");
    expect(complianceTemplateCategory("Kubernetes CRE")).toBe("containers");
    expect(complianceTemplateCategory("Bind9")).toBe("dns");
    expect(complianceTemplateCategory("Cisco IOS 15")).toBe("network");
    expect(complianceTemplateCategory("PCI DSS")).toBe("standards");
  });
});
