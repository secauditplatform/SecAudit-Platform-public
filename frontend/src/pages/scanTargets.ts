export type ScanTargetKind = "cidr" | "ip" | "range" | "hostname" | "ipv6prefix" | "invalid" | null;

/** Tight IPv6 prefixes allowed for discovery (/120 ≈ 256 hosts … /128). */
export const MIN_IPV6_PREFIX_LEN = 120;

export function scanTargetTokens(values: string[]): string[] {
  return values
    .flatMap((item) => item.split(/[\s,;\r\n]+/))
    .map((item) => item.trim())
    .filter(Boolean);
}

export function findIpv6Prefix(values: string[]): string | null {
  return scanTargetTokens(values).find((token) => detectTargetType(token) === "ipv6prefix") ?? null;
}

function isIpv6Address(value: string): boolean {
  if (!value.includes(":") || value.includes("/") || value.includes("%") || /\s/.test(value)) {
    return false;
  }
  try {
    const hostname = new URL(`http://[${value}]/`).hostname.replace(/^\[|\]$/g, "");
    return hostname.toLowerCase() === value.toLowerCase();
  } catch {
    return false;
  }
}

export function isAllowedIpv6Prefix(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed.includes(":") || !trimmed.includes("/")) return false;
  const slash = trimmed.lastIndexOf("/");
  const prefixText = trimmed.slice(slash + 1);
  if (!/^\d+$/.test(prefixText)) return false;
  const prefix = Number(prefixText);
  return prefix >= MIN_IPV6_PREFIX_LEN && prefix <= 128;
}

export function detectTargetType(raw: string): ScanTargetKind {
  const v = raw.trim();
  if (!v) return null;
  if (v.includes(":") && v.includes("/")) {
    return isAllowedIpv6Prefix(v) ? "cidr" : "ipv6prefix";
  }
  if (isIpv6Address(v)) return "ip";
  if (v.includes("/")) {
    const parts = v.split("/");
    if (parts.length === 2 && /^\d+$/.test(parts[1])) {
      const prefix = parseInt(parts[1], 10);
      if (prefix >= 0 && prefix <= 32) return "cidr";
    }
    return "invalid";
  }
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) {
    const octets = v.split(".").map(Number);
    if (octets.every((o) => o >= 0 && o <= 255)) return "ip";
    return "invalid";
  }
  if (/^[\d.-]+$/.test(v) && v.includes("-")) {
    return "range";
  }
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(v)) {
    return "hostname";
  }
  return "invalid";
}
