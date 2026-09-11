export type NavRouteId =
  | "dashboard"
  | "profiles"
  | "playbooks"
  | "console"
  | "hosts"
  | "credentials"
  | "users"
  | "jobs"
  | "remediation"
  | "trends"
  | "reports"
  | "waivers"
  | "auditLogs"
  | "overview"
  | "auditFlow";

export type NavGroupId = "overview" | "audit" | "infrastructure" | "reports";

export type NavItemConfig = {
  id: NavRouteId;
  to: string;
  labelKey: string;
  end?: boolean;
  adminOnly?: boolean;
  requiresOperate?: boolean;
  /** Aligns with API: admin / operator */
  requiresAuditAccess?: boolean;
};

const OPERATIONS_PATH_PREFIXES = [
  "/jobs",
  "/remediation",
  "/network/jobs",
  "/network/remediation",
] as const;

function matchesPathPrefix(pathname: string, prefix: string): boolean {
  return pathname === prefix || pathname.startsWith(`${prefix}/`);
}

export function isOperationsPath(pathname: string): boolean {
  return OPERATIONS_PATH_PREFIXES.some((prefix) => matchesPathPrefix(pathname, prefix));
}

export function isNavItemActive(
  item: Pick<NavItemConfig, "id" | "to" | "end">,
  pathname: string
): boolean {
  if (item.id === "jobs") {
    return isOperationsPath(pathname);
  }
  if (item.end) {
    return pathname === item.to;
  }
  return matchesPathPrefix(pathname, item.to);
}

export type NavGroupConfig = {
  id: NavGroupId;
  labelKey: string;
  items: NavItemConfig[];
};

export const NAV_GROUPS: NavGroupConfig[] = [
  {
    id: "overview",
    labelKey: "nav.groups.overview",
    items: [
      { id: "dashboard", to: "/", labelKey: "nav.dashboard", end: true },
      { id: "overview", to: "/overview", labelKey: "nav.platformOverview" },
    ],
  },
  {
    id: "audit",
    labelKey: "nav.groups.audit",
    items: [
      { id: "profiles", to: "/profiles", labelKey: "nav.profiles" },
      { id: "playbooks", to: "/playbooks", labelKey: "nav.playbooks", requiresOperate: true },
      { id: "auditFlow", to: "/audit-flow", labelKey: "nav.auditFlow", requiresOperate: true },
      { id: "console", to: "/console", labelKey: "nav.console", requiresOperate: true },
      { id: "jobs", to: "/jobs", labelKey: "nav.operations" },
      { id: "waivers", to: "/waivers", labelKey: "nav.waivers" },
    ],
  },
  {
    id: "infrastructure",
    labelKey: "nav.groups.infrastructure",
    items: [
      { id: "hosts", to: "/hosts", labelKey: "nav.hosts" },
      { id: "credentials", to: "/credentials", labelKey: "nav.credentials", requiresOperate: true },
      { id: "users", to: "/users", labelKey: "nav.users", adminOnly: true },
    ],
  },
  {
    id: "reports",
    labelKey: "nav.groups.reports",
    items: [
      { id: "trends", to: "/trends", labelKey: "nav.trends" },
      { id: "reports", to: "/reports", labelKey: "nav.reports" },
      {
        id: "auditLogs",
        to: "/audit-logs",
        labelKey: "nav.auditLogs",
        requiresAuditAccess: true,
      },
    ],
  },
];

export const AUDITOR_NAV_GROUPS: NavGroupConfig[] = [
  {
    id: "overview",
    labelKey: "nav.groups.overview",
    items: [
      { id: "dashboard", to: "/", labelKey: "nav.dashboard", end: true },
      { id: "overview", to: "/overview", labelKey: "nav.platformOverview" },
    ],
  },
  {
    id: "reports",
    labelKey: "nav.groups.reports",
    items: [
      { id: "trends", to: "/trends", labelKey: "nav.trends" },
      { id: "reports", to: "/reports", labelKey: "nav.reports" },
    ],
  },
];

export type BreadcrumbConfig = {
  groupKey?: string;
  pageKey: string;
};

export const ROUTE_BREADCRUMBS: Record<string, BreadcrumbConfig> = {
  "/": { pageKey: "nav.dashboard" },
  "/overview": { groupKey: "nav.groups.overview", pageKey: "platformOverview.title" },
  "/profiles": { groupKey: "nav.groups.audit", pageKey: "nav.profiles" },
  "/playbooks": { groupKey: "nav.groups.audit", pageKey: "nav.playbooks" },
  "/audit-flow": { groupKey: "nav.groups.audit", pageKey: "nav.auditFlow" },
  "/console": { groupKey: "nav.groups.audit", pageKey: "nav.console" },
  "/jobs": { groupKey: "nav.groups.audit", pageKey: "operations.title" },
  "/remediation": { groupKey: "nav.groups.audit", pageKey: "operations.title" },
  "/network/jobs": { groupKey: "nav.groups.audit", pageKey: "operations.title" },
  "/network/remediation": { groupKey: "nav.groups.audit", pageKey: "operations.title" },
  "/waivers": { groupKey: "nav.groups.audit", pageKey: "nav.waivers" },
  "/hosts": { groupKey: "nav.groups.infrastructure", pageKey: "nav.hosts" },
  "/credentials": { groupKey: "nav.groups.infrastructure", pageKey: "nav.credentials" },
  "/users": { groupKey: "nav.groups.infrastructure", pageKey: "nav.users" },
  "/trends": { groupKey: "nav.groups.reports", pageKey: "nav.trends" },
  "/reports": { groupKey: "nav.groups.reports", pageKey: "nav.reports" },
  "/audit-logs": { groupKey: "nav.groups.reports", pageKey: "nav.auditLogs" },
};

export function filterNavGroups(
  groups: NavGroupConfig[],
  isAuditorPortal: boolean,
  isAdmin = false,
  canOperate = true,
  canViewAuditLogs = true
): NavGroupConfig[] {
  const base = isAuditorPortal ? AUDITOR_NAV_GROUPS : groups;
  return base
    .map((group) => ({
      ...group,
      items: group.items.filter((item) => {
        if (item.adminOnly && !isAdmin) return false;
        if (item.requiresOperate && !canOperate) return false;
        if (item.requiresAuditAccess && !canViewAuditLogs) return false;
        return true;
      }),
    }))
    .filter((group) => group.items.length > 0);
}
