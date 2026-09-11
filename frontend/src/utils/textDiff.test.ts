import { describe, expect, it } from "vitest";
import { buildUnifiedDiff, lineDiffStats } from "./textDiff";

describe("textDiff", () => {
  it("counts added and removed lines", () => {
    const stats = lineDiffStats("a\nb\nc\n", "a\nx\nc\ny\n");
    expect(stats.removed).toBe(1);
    expect(stats.added).toBe(2);
  });

  it("builds unified diff with context", () => {
    const lines = buildUnifiedDiff("one\ntwo\nthree\n", "one\nTWO\nthree\n", { context: 1 });
    expect(lines.some((line) => line.kind === "del" && line.text === "two")).toBe(true);
    expect(lines.some((line) => line.kind === "add" && line.text === "TWO")).toBe(true);
  });
});
