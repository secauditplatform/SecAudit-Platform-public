import { beforeEach, describe, expect, it, vi } from "vitest";

const setAuthToken = vi.hoisted(() => vi.fn());
const clear = vi.hoisted(() => vi.fn());

vi.mock("../api/client", () => ({ setAuthToken }));
vi.mock("../queryClient", () => ({ queryClient: { clear } }));

import { clearAuthArtifacts, shouldClearQueryCacheOnIdentityChange } from "./clearAuthArtifacts";

describe("shouldClearQueryCacheOnIdentityChange", () => {
  it("does not clear on first mount", () => {
    expect(shouldClearQueryCacheOnIdentityChange(undefined, "alice")).toBe(false);
    expect(shouldClearQueryCacheOnIdentityChange(undefined, null)).toBe(false);
  });

  it("clears on logout", () => {
    expect(shouldClearQueryCacheOnIdentityChange("alice", null)).toBe(true);
  });

  it("clears on user switch", () => {
    expect(shouldClearQueryCacheOnIdentityChange("alice", "bob")).toBe(true);
  });

  it("does not clear when identity is unchanged (token refresh)", () => {
    expect(shouldClearQueryCacheOnIdentityChange("alice", "alice")).toBe(false);
    expect(shouldClearQueryCacheOnIdentityChange(null, null)).toBe(false);
  });

  it("clears on login after logged-out identity", () => {
    expect(shouldClearQueryCacheOnIdentityChange(null, "alice")).toBe(true);
  });
});

describe("clearAuthArtifacts", () => {
  beforeEach(() => {
    setAuthToken.mockClear();
    clear.mockClear();
  });

  it("nulls the bearer token and clears React Query cache", () => {
    clearAuthArtifacts();
    expect(setAuthToken).toHaveBeenCalledWith(null);
    expect(clear).toHaveBeenCalledTimes(1);
  });
});
