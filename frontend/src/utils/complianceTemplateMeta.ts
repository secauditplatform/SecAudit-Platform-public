export type ComplianceTemplateCategory =
  | "os"
  | "databases"
  | "web"
  | "containers"
  | "dns"
  | "network"
  | "standards"
  | "other";

export const COMPLIANCE_CATEGORY_ORDER: ComplianceTemplateCategory[] = [
  "os",
  "databases",
  "web",
  "containers",
  "dns",
  "network",
  "standards",
  "other",
];

const RULES: { category: ComplianceTemplateCategory; pattern: RegExp }[] = [
  { category: "network", pattern: /\b(cisco|eltex|juniper|mikrotik|routeros|xiaomi|miwifi|ios)\b/i },
  { category: "databases", pattern: /\b(postgres|postgresql|mysql|mariadb|mongodb|cassandra)\b/i },
  { category: "web", pattern: /\b(apache|httpd|tomcat|nginx|haproxy|angie)\b/i },
  { category: "containers", pattern: /\b(docker|kubernetes|k8s)\b/i },
  { category: "dns", pattern: /\b(bind\d*|named)\b/i },
  { category: "standards", pattern: /\b(pci|dss|fstek|fstec)\b/i },
  {
    category: "os",
    pattern:
      /\b(windows|ubuntu|debian|rhel|centos|alma|almalinux|astra|alt\b|oracle linux|azure linux|talos|redos|opensuse|alteros|atlant|aks)\b/i,
  },
];

export function complianceDisplayName(name: string, profileName?: string | null): string {
  const source = (profileName || name || "").trim();
  const cleaned = source
    .replace(/\s*[—–-]\s*Compliance\s*$/i, "")
    .replace(/\s+Compliance\s*$/i, "")
    .trim();
  return cleaned || name;
}

export function complianceTemplateCategory(
  name: string,
  profileName?: string | null
): ComplianceTemplateCategory {
  const haystack = `${profileName ?? ""} ${name}`;
  for (const rule of RULES) {
    if (rule.pattern.test(haystack)) return rule.category;
  }
  return "other";
}
