export type StatusBadgeVariant = "success" | "danger" | "warning" | "info" | "neutral";

export const RUN_STATUS_KEYS = ["completed", "running", "pending", "failed", "cancelled"] as const;

export function runStatusLabel(t: (key: string) => string, status: string): string {
  const key = `runStatus.${status}` as const;
  const translated = t(key);
  return translated === key ? status : translated;
}

/** Job / remediation / playbook run statuses */
export function runStatusVariant(status: string): StatusBadgeVariant {
  if (status === "completed") return "success";
  if (status === "failed" || status === "cancelled") return "danger";
  if (status === "running") return "info";
  if (status === "pending") return "warning";
  return "neutral";
}

/** Drift comparison change categories */
export function driftChangeVariant(change: string): StatusBadgeVariant {
  if (change === "improved") return "success";
  if (change === "regressed") return "danger";
  if (change === "new") return "info";
  if (change === "removed") return "warning";
  return "neutral";
}

/** Check results and combined run/check statuses (Reports) */
export function checkStatusVariant(status: string): StatusBadgeVariant {
  if (status === "pass" || status === "completed") return "success";
  if (status === "fail" || status === "error" || status === "failed" || status === "cancelled") return "danger";
  if (status === "skip" || status === "pending") return "warning";
  if (status === "running") return "info";
  return "neutral";
}

/** Check result severity labels */
export function severityVariant(severity: string): StatusBadgeVariant {
  const value = severity.trim().toLowerCase();
  if (value === "critical" || value === "high" || value === "критический" || value === "высокий") {
    return "danger";
  }
  if (value === "medium" || value === "moderate" || value === "средний") {
    return "warning";
  }
  if (value === "low" || value === "info" || value === "низкий") {
    return "info";
  }
  return "neutral";
}
