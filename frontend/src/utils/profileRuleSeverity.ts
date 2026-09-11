import type { ProfileRule } from "../api/client";

export type ProfileSeverityBucket = "high" | "medium" | "low" | "other";

export interface ProfileRuleSeverityStats {
  total: number;
  high: number;
  medium: number;
  low: number;
  other: number;
}

function normalizeSeverityBucket(value: string | null | undefined): ProfileSeverityBucket {
  const normalized = (value || "").trim().toLowerCase();
  if (["critical", "high", "критический", "высокий"].includes(normalized)) return "high";
  if (["medium", "moderate", "средний"].includes(normalized)) return "medium";
  if (["low", "info", "низкий"].includes(normalized)) return "low";
  return "other";
}

export function resolveProfileRuleSeverity(
  rule: Pick<ProfileRule, "criticality"> | null | undefined
): string | null {
  const value = rule?.criticality?.trim();
  return value || null;
}

export function getProfileRuleSeverityBucket(
  rule: Pick<ProfileRule, "criticality"> | null | undefined
): ProfileSeverityBucket | null {
  const severity = resolveProfileRuleSeverity(rule);
  if (!severity) return null;
  return normalizeSeverityBucket(severity);
}

export function summarizeProfileRuleSeverities(rules: ProfileRule[]): ProfileRuleSeverityStats {
  const stats: ProfileRuleSeverityStats = {
    total: rules.length,
    high: 0,
    medium: 0,
    low: 0,
    other: 0,
  };

  for (const rule of rules) {
    const bucket = normalizeSeverityBucket(rule.criticality);
    stats[bucket] += 1;
  }

  return stats;
}

export function formatProfileRuleSeverityLabel(value: string): string {
  return value.trim().toUpperCase();
}
