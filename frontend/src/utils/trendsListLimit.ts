import { useCallback, useState } from "react";

export const TRENDS_LIST_LIMIT_OPTIONS = [6, 10, 15, 20] as const;
export type TrendsListLimit = (typeof TRENDS_LIST_LIMIT_OPTIONS)[number];

export type TrendsListLimitScope = "recentRuns" | "byProfile" | "byHost";

const SCOPE_STORAGE_KEYS: Record<TrendsListLimitScope, string> = {
  recentRuns: "secaudit.timelineRecentRunsLimit",
  byProfile: "secaudit.trendsByProfileLimit",
  byHost: "secaudit.trendsByHostLimit",
};

/** @deprecated legacy shared key — only used as fallback for recent runs */
const LEGACY_SHARED_LIMIT_KEY = "secaudit.trendsListLimit";

export function readTrendsListLimit(scope: TrendsListLimitScope): TrendsListLimit {
  try {
    const keys =
      scope === "recentRuns"
        ? [SCOPE_STORAGE_KEYS.recentRuns, LEGACY_SHARED_LIMIT_KEY]
        : [SCOPE_STORAGE_KEYS[scope]];

    for (const key of keys) {
      const raw = localStorage.getItem(key);
      const value = Number(raw);
      if (TRENDS_LIST_LIMIT_OPTIONS.includes(value as TrendsListLimit)) {
        return value as TrendsListLimit;
      }
    }
  } catch {
    /* ignore */
  }
  return 6;
}

export function persistTrendsListLimit(scope: TrendsListLimitScope, value: TrendsListLimit): void {
  try {
    localStorage.setItem(SCOPE_STORAGE_KEYS[scope], String(value));
  } catch {
    /* ignore */
  }
}

export function useTrendsListLimit(scope: TrendsListLimitScope) {
  const [limit, setLimit] = useState<TrendsListLimit>(() => readTrendsListLimit(scope));

  const setLimitAndPersist = useCallback(
    (next: TrendsListLimit) => {
      setLimit(next);
      persistTrendsListLimit(scope, next);
    },
    [scope]
  );

  return [limit, setLimitAndPersist] as const;
}
