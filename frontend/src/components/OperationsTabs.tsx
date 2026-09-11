import { Link, useLocation, useSearchParams } from "react-router-dom";
import { useAuth } from "../auth/AuthProvider";
import { useTranslation } from "../i18n/I18nProvider";
import {
  IconJobs,
  IconLinux,
  IconNetwork,
  IconRemediation,
  IconWindows,
} from "./ui/Icons";

export type OperationsTask = "compliance" | "remediation";
export type OperationsPlatform = "linux" | "windows" | "network";
export type OperationsScope = "standard" | "network";

/** @deprecated Prefer OperationsTask + OperationsPlatform */
export type OperationsTab =
  | "compliance"
  | "remediation"
  | "network-compliance"
  | "network-remediation";

const PLATFORMS: OperationsPlatform[] = ["linux", "windows", "network"];

const PLATFORM_LABEL: Record<OperationsPlatform, string> = {
  linux: "playbooks.scopeLinux",
  windows: "playbooks.scopeWindows",
  network: "playbooks.scopeNetwork",
};

const PLATFORM_ICON: Record<OperationsPlatform, typeof IconLinux> = {
  linux: IconLinux,
  windows: IconWindows,
  network: IconNetwork,
};

const TASK_ICON: Record<OperationsTask, typeof IconJobs> = {
  compliance: IconJobs,
  remediation: IconRemediation,
};

const TASK_LABEL: Record<OperationsTask, string> = {
  compliance: "operations.tabCompliance",
  remediation: "operations.tabRemediation",
};

const TASK_DESCRIPTION: Record<OperationsTask, Record<OperationsPlatform, string>> = {
  compliance: {
    linux: "jobs.description",
    windows: "jobs.description",
    network: "network.jobsDescription",
  },
  remediation: {
    linux: "remediation.description",
    windows: "remediation.description",
    network: "network.remediationDescription",
  },
};

export function operationsScopeForPlatform(platform: OperationsPlatform): OperationsScope {
  return platform === "network" ? "network" : "standard";
}

export function parseOperationsPlatform(
  value: string | null | undefined,
  fallback: OperationsPlatform = "linux"
): OperationsPlatform {
  if (value === "linux" || value === "windows" || value === "network") return value;
  return fallback;
}

export function operationsPath(platform: OperationsPlatform, task: OperationsTask): string {
  if (platform === "network") {
    return task === "compliance" ? "/network/jobs" : "/network/remediation";
  }
  const base = task === "compliance" ? "/jobs" : "/remediation";
  return `${base}?platform=${platform}`;
}

export function platformFromOperationsTab(tab: OperationsTab): OperationsPlatform {
  if (tab === "network-compliance" || tab === "network-remediation") return "network";
  return "linux";
}

export function taskFromOperationsTab(tab: OperationsTab): OperationsTask {
  if (tab === "remediation" || tab === "network-remediation") return "remediation";
  return "compliance";
}

export function hostMatchesOperationsPlatform(
  osType: string | undefined,
  platform: OperationsPlatform
): boolean {
  const normalized = (osType ?? "linux").toLowerCase();
  if (platform === "network") return normalized === "network";
  if (platform === "windows") return normalized === "windows";
  return normalized !== "network" && normalized !== "windows";
}

export function profileMatchesOperationsPlatform(
  categoryName: string | undefined | null,
  platform: OperationsPlatform
): boolean {
  const category = (categoryName || "").toLowerCase();
  if (platform === "network") return category.includes("network");
  if (platform === "windows") return category.includes("windows");
  // Linux + Services for OS-level / service checks on Linux hosts
  return !category.includes("windows") && !category.includes("network");
}

export function jobMatchesOperationsPlatform(
  job: {
    execution_type?: string | null;
    profile_id?: number | null;
    host_ids?: number[];
  },
  platform: OperationsPlatform,
  context: {
    profileCategoryById: Map<number, string | undefined>;
    hostOsById: Map<number, string | undefined>;
  }
): boolean {
  const exec = (job.execution_type || "").toLowerCase();
  if (platform === "windows") {
    if (exec === "winrm") return true;
    if (exec === "ssh" || exec === "ansible") return false;
  }
  if (platform === "linux") {
    if (exec === "winrm") return false;
  }
  if (platform === "network") {
    if (exec === "python" || exec === "ansible") return true;
  }

  if (job.profile_id != null) {
    const category = context.profileCategoryById.get(job.profile_id);
    if (category) return profileMatchesOperationsPlatform(category, platform);
  }

  const hostIds = job.host_ids ?? [];
  if (hostIds.length > 0) {
    const matched = hostIds.filter((id) =>
      hostMatchesOperationsPlatform(context.hostOsById.get(id), platform)
    );
    if (matched.length === 0) return false;
    if (matched.length === hostIds.length) return true;
    // Mixed hosts: keep if majority matches selected platform
    return matched.length >= hostIds.length / 2;
  }

  // No signal — show on linux by default, hide from windows/network lists
  return platform === "linux";
}

type OperationsPageHeaderProps = {
  task: OperationsTask;
  platform: OperationsPlatform;
};

export function OperationsPageHeader({ task, platform }: OperationsPageHeaderProps) {
  const { t } = useTranslation();
  const { canAccessRemediation } = useAuth();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  const preserveSearch = (targetPath: string) => {
    const [pathname, query = ""] = targetPath.split("?");
    const next = new URLSearchParams(query);
    // Keep non-platform params (e.g. edit=) when switching tabs on same area
    for (const key of ["edit", "run"]) {
      const value = searchParams.get(key);
      if (value && !next.has(key) && pathname === location.pathname) {
        next.set(key, value);
      }
    }
    const qs = next.toString();
    return qs ? `${pathname}?${qs}` : pathname;
  };

  const tasks: OperationsTask[] = canAccessRemediation ? ["compliance", "remediation"] : ["compliance"];

  return (
    <div className="pf-operations-header">
      <header className="pf-page-header">
        <div className="pf-page-header__main">
          <h1 className="pf-page-header__title">{t("operations.title")}</h1>
          <p className="pf-page-header__description">{t(TASK_DESCRIPTION[task][platform])}</p>
        </div>
      </header>

      <nav className="pf-operations-platform-tabs" aria-label={t("operations.platformTabsAria")}>
        <div className="pf-segmented pf-segmented--platform" role="tablist">
          {PLATFORMS.map((item) => {
            const Icon = PLATFORM_ICON[item];
            const isActive = platform === item;
            return (
              <Link
                key={item}
                to={preserveSearch(operationsPath(item, task))}
                role="tab"
                aria-selected={isActive}
                data-platform={item}
                className={`pf-segmented__option${isActive ? " is-active" : ""}`}
              >
                <span className="pf-segmented__icon" aria-hidden>
                  <Icon />
                </span>
                <span className="pf-segmented__label">{t(PLATFORM_LABEL[item])}</span>
              </Link>
            );
          })}
        </div>
      </nav>

      <nav className="pf-operations-tabs" aria-label={t("operations.tabsAria")}>
        <div className="pf-segmented pf-segmented--scope" role="tablist">
          {tasks.map((item) => {
            const Icon = TASK_ICON[item];
            const isActive = task === item;
            return (
              <Link
                key={item}
                to={preserveSearch(operationsPath(platform, item))}
                role="tab"
                aria-selected={isActive}
                data-scope={item}
                className={`pf-segmented__option${isActive ? " is-active" : ""}`}
              >
                <span className="pf-segmented__icon" aria-hidden>
                  <Icon />
                </span>
                <span className="pf-segmented__label">{t(TASK_LABEL[item])}</span>
              </Link>
            );
          })}
        </div>
      </nav>
    </div>
  );
}

/** Back-compat wrapper used by older call sites. */
export function OperationsTabs({ activeTab }: { activeTab: OperationsTab }) {
  return (
    <OperationsPageHeader
      task={taskFromOperationsTab(activeTab)}
      platform={platformFromOperationsTab(activeTab)}
    />
  );
}
