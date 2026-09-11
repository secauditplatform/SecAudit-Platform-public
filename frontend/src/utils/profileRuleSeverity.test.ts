import { describe, expect, it } from "vitest";
import { summarizeProfileRuleSeverities } from "./profileRuleSeverity";

describe("summarizeProfileRuleSeverities", () => {
  it("groups rules into high, medium, low, and other buckets", () => {
    const stats = summarizeProfileRuleSeverities([
      { requirement_id: "1", tech_name: "r1", num: "1", criticality: "HIGH" },
      { requirement_id: "2", tech_name: "r2", num: "2", criticality: "critical" },
      { requirement_id: "3", tech_name: "r3", num: "3", criticality: "medium" },
      { requirement_id: "4", tech_name: "r4", num: "4", criticality: "low" },
      { requirement_id: "5", tech_name: "r5", num: "5", criticality: null },
    ]);

    expect(stats).toEqual({
      total: 5,
      high: 2,
      medium: 1,
      low: 1,
      other: 1,
    });
  });
});
