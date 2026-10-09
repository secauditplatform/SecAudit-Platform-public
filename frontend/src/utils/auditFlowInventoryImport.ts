export type ImportableInventoryHost = {
  hostname: string;
  name?: string;
  ssh_host_key_fingerprint?: string | null;
};

export type MergeInventoryTargetsResult = {
  targets: string[];
  added: number;
  skippedDuplicate: number;
  skippedFingerprint: number;
  truncated: boolean;
};

const MAX_TARGETS = 16;

function normalizeAddress(value: string): string {
  return value.trim().toLowerCase();
}

function normalizeFingerprint(value: string | null | undefined): string | null {
  const raw = (value || "").trim();
  if (!raw) return null;
  const upper = raw.toUpperCase().startsWith("SHA256:")
    ? `SHA256:${raw.split(":").slice(1).join(":")}`
    : `SHA256:${raw}`;
  return upper.replace(/=+$/, "");
}

function hostTarget(host: ImportableInventoryHost): string | null {
  const hostname = (host.hostname || "").trim();
  if (hostname) return hostname;
  const name = (host.name || "").trim();
  return name || null;
}

function expandTargetKeys(targets: string[]): Set<string> {
  const keys = new Set<string>();
  for (const item of targets) {
    for (const part of item.split(/[\s,;\r\n]+/)) {
      const key = normalizeAddress(part);
      if (key) keys.add(key);
    }
  }
  return keys;
}

/** Merge inventory hosts into AuditFlow targets with address + SSH fingerprint dedup. */
export function mergeInventoryHostsIntoTargets(
  currentTargets: string[],
  hosts: ImportableInventoryHost[],
  maxTargets = MAX_TARGETS
): MergeInventoryTargetsResult {
  const next = currentTargets
    .flatMap((item) => item.split(/[\s,;\r\n]+/))
    .map((item) => item.trim())
    .filter(Boolean);
  const seenAddresses = expandTargetKeys(next);
  const seenFingerprints = new Set<string>();

  let added = 0;
  let skippedDuplicate = 0;
  let skippedFingerprint = 0;
  let truncated = false;

  for (const host of hosts) {
    if (next.length >= maxTargets) {
      truncated = true;
      break;
    }
    const target = hostTarget(host);
    if (!target) continue;
    const addressKey = normalizeAddress(target);
    if (seenAddresses.has(addressKey)) {
      skippedDuplicate += 1;
      continue;
    }
    const fingerprint = normalizeFingerprint(host.ssh_host_key_fingerprint);
    if (fingerprint && seenFingerprints.has(fingerprint)) {
      skippedFingerprint += 1;
      continue;
    }
    next.push(target);
    seenAddresses.add(addressKey);
    if (fingerprint) seenFingerprints.add(fingerprint);
    added += 1;
  }

  return {
    targets: next.length > 0 ? next : [""],
    added,
    skippedDuplicate,
    skippedFingerprint,
    truncated,
  };
}
