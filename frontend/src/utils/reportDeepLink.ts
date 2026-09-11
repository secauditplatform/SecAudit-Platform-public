export type ReportCheckRow = {
  host_id: number;
  host_name?: string | null;
};

export function parseRunId(value: string | null): number | null {
  if (!value) return null;
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

export function findCheckResultHostId(
  checkResults: ReportCheckRow[],
  hostLabelById: Map<number, string>,
  target: { hostId?: string | null; host?: string | null }
): number | null {
  const hostId = (target.hostId || "").trim();
  if (hostId && /^\d+$/.test(hostId)) {
    const numericId = Number(hostId);
    if (checkResults.some((row) => row.host_id === numericId)) {
      return numericId;
    }
  }

  const needle = (target.host || "").trim().toLowerCase();
  if (!needle) return null;

  const match = checkResults.find((row) => {
    const name = (row.host_name || "").trim().toLowerCase();
    const label = (hostLabelById.get(row.host_id) || "").trim().toLowerCase();
    return (
      String(row.host_id) === needle ||
      name === needle ||
      name.includes(needle) ||
      label === needle ||
      label.includes(needle)
    );
  });
  return match?.host_id ?? null;
}

export function buildAuditFlowReportHref(host: {
  job_run_id?: number | null;
  ip_address: string;
  ephemeral_host_id?: number | null;
}): string | null {
  if (!host.job_run_id) return null;
  const params = new URLSearchParams({
    run: String(host.job_run_id),
    focus: "checks",
  });
  if (host.ephemeral_host_id) {
    params.set("host_id", String(host.ephemeral_host_id));
  } else {
    params.set("host", host.ip_address);
  }
  return `/reports?${params.toString()}`;
}
