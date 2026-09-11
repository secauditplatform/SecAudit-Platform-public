import { describe, expect, it } from "vitest";
import { parsePlaybookComplianceChecks } from "./parsePlaybookComplianceChecks";

describe("parsePlaybookComplianceChecks", () => {
  it("parses checks array from compliance summary JSON", () => {
    const summary = {
      target: "host-1",
      total: "3",
      passed: "1",
      failed: "2",
      format: "STATUS|rule_id|summary|detail",
      checks: [
        "FAIL|RULE0001|Ensure cramfs is disabled.|kernel module is available",
        "PASS|RULE0006|Ensure squashfs is disabled.|kernel module is not available",
        "FAIL|RULE0009|Ensure /tmp is a separate partition.|/tmp is not a mount point",
      ],
    };
    const output = `Playbook completed (connection: host-1=ssh)\nOK [host-1] Ubuntu CRE compliance summary: ${JSON.stringify(summary)}`;

    const checks = parsePlaybookComplianceChecks(output);
    expect(checks).toHaveLength(3);
    expect(checks[0]).toMatchObject({
      rule: "RULE0001",
      status: "fail",
      summary: "Ensure cramfs is disabled.",
    });
    expect(checks[1].status).toBe("pass");
    expect(checks[2].rule).toBe("RULE0009");
  });

  it("recovers check rows from truncated output via regex", () => {
    const output =
      'OK [h] summary: {"checks":["FAIL|RULE0001|Summary one.|detail one","PASS|RULE0002|Summary two.|detail two","FAIL|RULE00';

    const checks = parsePlaybookComplianceChecks(output);
    expect(checks.map((c) => c.rule)).toEqual(["RULE0001", "RULE0002"]);
    expect(checks[0].status).toBe("fail");
    expect(checks[1].status).toBe("pass");
  });

  it("parses a large checks dump without hanging", () => {
    const checks = Array.from({ length: 300 }, (_, i) => {
      const id = String(i + 1).padStart(4, "0");
      const status = i % 2 === 0 ? "FAIL" : "PASS";
      return `${status}|RULE${id}|Summary for rule ${id}.|detail ${id}`;
    });
    const summary = {
      target: "host-1",
      total: String(checks.length),
      passed: "150",
      failed: "150",
      format: "STATUS|rule_id|summary|detail",
      checks,
    };
    const output = `Playbook completed\nOK [host-1] CRE compliance summary: ${JSON.stringify(summary)}`;

    const started = Date.now();
    const parsed = parsePlaybookComplianceChecks(output);
    const elapsed = Date.now() - started;

    expect(parsed).toHaveLength(300);
    expect(elapsed).toBeLessThan(2000);
  });
});
