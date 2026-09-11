import { describe, expect, it } from "vitest";
import { buildAuditFlowReportHref, findCheckResultHostId } from "./reportDeepLink";

describe("findCheckResultHostId", () => {
  const rows = [{ host_id: 42, host_name: "af-3-192.0.2.248" }];
  const labels = new Map<number, string>([[42, "af-3-192.0.2.248"]]);

  it("prefers explicit host_id", () => {
    expect(findCheckResultHostId(rows, labels, { hostId: "42", host: "10.0.0.1" })).toBe(42);
  });

  it("matches audit-flow host name suffix by ip", () => {
    expect(findCheckResultHostId(rows, labels, { host: "192.0.2.248" })).toBe(42);
  });
});

describe("buildAuditFlowReportHref", () => {
  it("uses host_id when inventory host is known", () => {
    expect(
      buildAuditFlowReportHref({
        job_run_id: 9,
        ip_address: "192.0.2.248",
        ephemeral_host_id: 42,
      })
    ).toBe("/reports?run=9&focus=checks&host_id=42");
  });

  it("falls back to host ip", () => {
    expect(
      buildAuditFlowReportHref({
        job_run_id: 9,
        ip_address: "192.0.2.248",
      })
    ).toBe("/reports?run=9&focus=checks&host=192.0.2.248");
  });
});
