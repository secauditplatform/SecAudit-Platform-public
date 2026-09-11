import { describe, expect, it } from "vitest";
import { applyAuditFlowHostPatch, hostReviewReason } from "./auditFlowHostState";
import type { AuditFlowHost, AuditFlowRun } from "../api/client";

function host(overrides: Partial<AuditFlowHost>): AuditFlowHost {
  return {
    id: 1,
    ip_address: "192.0.2.248",
    open_ports: [],
    confidence: 0,
    alternatives: [],
    selected: true,
    ...overrides,
  };
}

function runWith(hosts: AuditFlowHost[]): AuditFlowRun {
  return {
    id: 1,
    status: "ready",
    targets: ["192.168.1.0/24"],
    hosts_found: hosts.length,
    created_at: "2026-01-01T00:00:00Z",
    hosts,
  };
}

describe("hostReviewReason", () => {
  it("requires credential after profile is selected", () => {
    expect(
      hostReviewReason(
        host({
          skip_reason: "no_matching_profile",
          profile_id: 10,
          profile_name: "Ubuntu 22.04",
          credential_id: null,
        })
      )
    ).toBe("missing_credential");
  });

  it("is ready when profile and credential are set", () => {
    expect(
      hostReviewReason(
        host({
          profile_id: 10,
          credential_id: 5,
          skip_reason: null,
        })
      )
    ).toBeNull();
  });
});

describe("applyAuditFlowHostPatch", () => {
  it("clears retryable skip reasons when profile is assigned", () => {
    const updated = applyAuditFlowHostPatch(runWith([host({ skip_reason: "no_matching_profile" })]), {
      id: 1,
      profile_id: 10,
      profile_name: "Ubuntu 22.04",
    });
    expect(updated.hosts[0]?.skip_reason).toBeNull();
    expect(updated.hosts[0]?.profile_id).toBe(10);
  });
});
