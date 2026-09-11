import { useEffect, useMemo, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { AuditorRouteGuard } from "../auth/AuditorRouteGuard";
import { useAuth } from "../auth/AuthProvider";
import { Breadcrumbs } from "./Breadcrumbs";
import { GlobalSearch } from "./GlobalSearch";
import { ScrollToTop, scrollAppToTop } from "./ScrollToTop";
import { SettingsPanel } from "./SettingsPanel";
import { APP_VERSION } from "../constants/version";
import { useTranslation } from "../i18n/I18nProvider";
import {
  filterNavGroups,
  isNavItemActive,
  NAV_GROUPS,
  type NavRouteId,
} from "../navigation/appNavigation";
import {
  IconAudit,
  IconAuditFlow,
  IconBars,
  IconConsole,
  IconCredentials,
  IconDashboard,
  IconHosts,
  IconJobs,
  IconPlatformOverview,
  IconPlaybook,
  IconRemediation,
  IconReports,
  IconTrends,
  IconTemplates,
  IconUsers,
  IconWaivers,
} from "./ui/Icons";

const SIDEBAR_STORAGE_KEY = "secaudit-sidebar-collapsed";

const NAV_ICONS: Record<NavRouteId, typeof IconDashboard> = {
  dashboard: IconDashboard,
  profiles: IconTemplates,
  playbooks: IconPlaybook,
  auditFlow: IconAuditFlow,
  console: IconConsole,
  hosts: IconHosts,
  credentials: IconCredentials,
  users: IconUsers,
  jobs: IconJobs,
  remediation: IconRemediation,
  trends: IconTrends,
  reports: IconReports,
  waivers: IconWaivers,
  auditLogs: IconAudit,
  overview: IconPlatformOverview,
};

function readSidebarCollapsed(): boolean {
  try {
    return localStorage.getItem(SIDEBAR_STORAGE_KEY) === "true";
  } catch {
    return false;
  }
}

export function Layout() {
  const { username, logout, primaryRole, isAuditorPortal, isAdmin, canOperate, canViewAuditLogs } = useAuth();
  const { t } = useTranslation();
  const { pathname } = useLocation();
  const [sidebarCollapsed, setSidebarCollapsed] = useState(readSidebarCollapsed);
  const [mobileNavOpen, setMobileNavOpen] = useState(false);

  const navGroups = useMemo(
    () => filterNavGroups(NAV_GROUPS, isAuditorPortal, isAdmin, canOperate, canViewAuditLogs),
    [isAuditorPortal, isAdmin, canOperate, canViewAuditLogs]
  );

  useEffect(() => {
    const mq = window.matchMedia("(max-width: 768px)");
    const onChange = () => {
      if (mq.matches) {
        setSidebarCollapsed(true);
        setMobileNavOpen(false);
      }
    };
    onChange();
    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, []);

  useEffect(() => {
    try {
      localStorage.setItem(SIDEBAR_STORAGE_KEY, String(sidebarCollapsed));
    } catch {
      /* ignore storage errors */
    }
  }, [sidebarCollapsed]);

  return (
    <div
      className={`pf-app${sidebarCollapsed ? " pf-app--sidebar-collapsed" : ""}${mobileNavOpen ? " pf-app--mobile-nav-open" : ""}${isAuditorPortal ? " pf-app--auditor-portal" : ""}`}
    >
      <ScrollToTop />
      <header className="pf-masthead">
        <div className="pf-masthead__brand">
          <button
            type="button"
            className="pf-masthead__toggle"
            onClick={() => {
              if (window.matchMedia("(max-width: 768px)").matches) {
                setMobileNavOpen((prev) => !prev);
              } else {
                setSidebarCollapsed((prev) => !prev);
              }
            }}
            aria-expanded={!sidebarCollapsed || mobileNavOpen}
            aria-controls="app-sidebar"
            aria-label={sidebarCollapsed ? t("nav.expandSidebar") : t("nav.collapseSidebar")}
          >
            <IconBars />
          </button>
          <span className="pf-masthead__title">SecAudit</span>
          {primaryRole && import.meta.env.VITE_AUTH_ENABLED === "true" ? (
            <span className="pf-masthead__role-badge">{t(`roleBadges.${primaryRole}`)}</span>
          ) : null}
        </div>
        <div className="pf-masthead__spacer" />
        {!isAuditorPortal ? <GlobalSearch /> : null}
        <div className="pf-masthead__user">
          <SettingsPanel />
          <span className="pf-masthead__meta">
            {username}
            {import.meta.env.VITE_AUTH_ENABLED === "true" && (
              <>
                {" · "}
                <button type="button" onClick={logout} className="pf-masthead__logout">
                  {t("common.logout")}
                </button>
              </>
            )}
          </span>
        </div>
      </header>

      <div className="pf-body">
        {mobileNavOpen ? (
          <button
            type="button"
            className="pf-sidebar-backdrop"
            aria-label={t("nav.collapseSidebar")}
            onClick={() => setMobileNavOpen(false)}
          />
        ) : null}
        <aside
          id="app-sidebar"
          className={`pf-sidebar${sidebarCollapsed && !mobileNavOpen ? " pf-sidebar--collapsed secaudit-sidebar-collapsed" : ""}${mobileNavOpen ? " pf-sidebar--mobile-open" : ""}`}
        >
          <nav className="pf-sidebar__nav" aria-label={t("nav.mainAria")}>
            {navGroups.map((group) => (
              <section key={group.id} className="pf-nav-group" aria-label={t(group.labelKey)}>
                <h2 className="pf-nav-group__label">{t(group.labelKey)}</h2>
                <div className="pf-nav-group__items">
                  {group.items.map(({ id, to, labelKey, end }) => {
                    const Icon = NAV_ICONS[id];
                    const label = t(labelKey);
                    return (
                      <NavLink
                        key={to}
                        to={to}
                        end={end}
                        className={() =>
                          `pf-nav-item${isNavItemActive({ id, to, end }, pathname) ? " active" : ""}`
                        }
                        title={sidebarCollapsed ? label : undefined}
                        onClick={() => {
                          scrollAppToTop();
                          setMobileNavOpen(false);
                        }}
                      >
                        <Icon />
                        <span className="pf-nav-item__label">{label}</span>
                      </NavLink>
                    );
                  })}
                </div>
              </section>
            ))}
          </nav>
          <div className="pf-sidebar__footer">v{APP_VERSION}</div>
        </aside>

        <main className="pf-main">
          <div className="pf-main__inner">
            <Breadcrumbs />
            <AuditorRouteGuard>
              <Outlet />
            </AuditorRouteGuard>
          </div>
        </main>
      </div>
    </div>
  );
}
