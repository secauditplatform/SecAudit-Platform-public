import type { Job, JobTemplate } from "../api/client";

type HostCredentials = {
  credential_id?: number | null;
  credential_ids?: number[];
};

type AuditTarget = {
  host_id: number;
  os_type: string | null;
};

function platformOf(osType: string | null): "linux" | "windows" | "network" {
  const normalized = (osType ?? "linux").toLowerCase();
  if (normalized === "network") return "network";
  if (normalized === "windows") return "windows";
  return "linux";
}

function executionMatches(osType: string | null, execution: string | null | undefined): boolean {
  const platform = platformOf(osType);
  if (platform === "network") return execution === "python";
  if (platform === "windows") return execution === "winrm" || execution === "ansible";
  return execution === "ssh" || execution === "ansible";
}

export function hostHasCredential(host: HostCredentials): boolean {
  if (host.credential_id != null) return true;
  return (host.credential_ids?.length ?? 0) > 0;
}

/** Active job that already targets this host and can be started as-is. */
export function readyAuditJob(
  jobs: Job[],
  node: AuditTarget,
  profileId: string,
  host: HostCredentials,
): Job | null {
  if (!hostHasCredential(host)) return null;
  const matches = jobs.filter((job) => {
    if (!job.is_active) return false;
    if (!job.profile_id && !job.playbook_id) return false;
    if (!executionMatches(node.os_type, job.execution_type)) return false;
    if (!job.host_ids.includes(node.host_id)) return false;
    if (profileId && String(job.profile_id ?? "") !== profileId) return false;
    return true;
  });
  matches.sort((a, b) => b.id - a.id);
  return matches[0] ?? null;
}

/** Active template that already targets this host and can be started as-is. */
export function readyAuditTemplate(
  templates: JobTemplate[],
  node: AuditTarget,
  profileId: string,
  host: HostCredentials,
): JobTemplate | null {
  if (!hostHasCredential(host)) return null;
  const matches = templates.filter((template) => {
    if (!template.is_active) return false;
    if (!template.profile_id && !template.playbook_id) return false;
    if (!executionMatches(node.os_type, template.execution_type)) return false;
    if (!template.host_ids.includes(node.host_id)) return false;
    if (profileId && String(template.profile_id ?? "") !== profileId) return false;
    return true;
  });
  matches.sort((a, b) => (a.updated_at < b.updated_at ? 1 : a.updated_at > b.updated_at ? -1 : b.id - a.id));
  return matches[0] ?? null;
}

/** A one-host job already created from this template, so a repeat click does not add another. */
export function reusableAuditJob(jobs: Job[], template: JobTemplate, hostId: number): Job | null {
  return (
    jobs.find(
      (job) =>
        job.is_active &&
        !job.is_scheduled &&
        (job.profile_id ?? null) === (template.profile_id ?? null) &&
        (job.playbook_id ?? null) === (template.playbook_id ?? null) &&
        (job.execution_type ?? null) === (template.execution_type ?? null) &&
        job.host_ids.length === 1 &&
        job.host_ids[0] === hostId,
    ) ?? null
  );
}

/** Existing Operations task that already includes this host. Profile filter wins when it matches. */
export function existingAuditJob(jobs: Job[], hostId: number, profileId: string): Job | null {
  const withHost = jobs.filter((job) => job.host_ids.includes(hostId));
  const scoped = profileId ? withHost.filter((job) => String(job.profile_id ?? "") === profileId) : withHost;
  const pool = scoped.length > 0 ? scoped : withHost;
  const active = pool.filter((job) => job.is_active);
  const ranked = (active.length > 0 ? active : pool).slice().sort((a, b) => b.id - a.id);
  return ranked[0] ?? null;
}
