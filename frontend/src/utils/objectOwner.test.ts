import { describe, expect, it } from "vitest";
import { formatOwnerSub } from "./objectOwner";

describe("formatOwnerSub", () => {
  it("strips local: prefix", () => {
    expect(formatOwnerSub("local:alice")).toBe("alice");
  });

  it("returns empty string for missing owner", () => {
    expect(formatOwnerSub(null)).toBe("");
  });
});
