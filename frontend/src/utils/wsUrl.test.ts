import { describe, expect, it } from "vitest";
import { resolveWsBaseUrl } from "./wsUrl";

describe("resolveWsBaseUrl", () => {
  it("upgrades ws:// override to wss:// on https pages", () => {
    expect(resolveWsBaseUrl("ws://localhost:8000", { protocol: "https:", host: "app.example" })).toBe(
      "wss://localhost:8000"
    );
  });

  it("keeps ws:// override on http pages", () => {
    expect(resolveWsBaseUrl("ws://localhost:8000", { protocol: "http:", host: "localhost:5173" })).toBe(
      "ws://localhost:8000"
    );
  });

  it("strips trailing slash from override", () => {
    expect(resolveWsBaseUrl("wss://api.example/", { protocol: "https:", host: "app.example" })).toBe(
      "wss://api.example"
    );
  });

  it("resolves protocol-relative override from page scheme", () => {
    expect(resolveWsBaseUrl("//api.example:8000", { protocol: "https:", host: "app.example" })).toBe(
      "wss://api.example:8000"
    );
    expect(resolveWsBaseUrl("//api.example:8000", { protocol: "http:", host: "localhost:5173" })).toBe(
      "ws://api.example:8000"
    );
  });

  it("ignores blank override and uses page origin", () => {
    expect(resolveWsBaseUrl("  ", { protocol: "http:", host: "localhost:5173" })).toBe(
      "ws://localhost:5173"
    );
  });

  it("defaults to wss on https pages when override is null", () => {
    expect(resolveWsBaseUrl(null, { protocol: "https:", host: "secaudit.example" })).toBe(
      "wss://secaudit.example"
    );
  });

  it("defaults to ws on http pages when override is null", () => {
    expect(resolveWsBaseUrl(null, { protocol: "http:", host: "localhost:5173" })).toBe(
      "ws://localhost:5173"
    );
  });

  it("preserves non-default ports on the current origin", () => {
    expect(resolveWsBaseUrl(null, { protocol: "https:", host: "app.example:8443" })).toBe(
      "wss://app.example:8443"
    );
  });
});
