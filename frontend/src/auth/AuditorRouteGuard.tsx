import { type ReactNode } from "react";
import { Navigate, useLocation } from "react-router-dom";
import { useAuth } from "./AuthProvider";

const AUDITOR_ALLOWED_EXACT = new Set(["/"]);
const AUDITOR_ALLOWED_PREFIXES = ["/overview", "/trends", "/reports"];

const OPERATOR_ONLY_PATHS = new Set(["/console", "/credentials", "/audit-flow", "/playbooks"]);

const REMEDIATION_PATHS = ["/remediation", "/network/remediation"];

const ADMIN_ONLY_PATHS = new Set(["/users"]);

const AUDIT_ACCESS_PATHS = new Set(["/audit-logs"]);

function matchesPathPrefix(pathname: string, prefix: string): boolean {
  return pathname === prefix || pathname.startsWith(`${prefix}/`);
}

function isAuditorAllowedPath(pathname: string): boolean {
  if (AUDITOR_ALLOWED_EXACT.has(pathname)) return true;
  return AUDITOR_ALLOWED_PREFIXES.some((prefix) => matchesPathPrefix(pathname, prefix));
}

function isRemediationPath(pathname: string): boolean {
  return REMEDIATION_PATHS.some((prefix) => matchesPathPrefix(pathname, prefix));
}

export function AuditorRouteGuard({ children }: { children: ReactNode }) {
  const { isAuditorPortal, canOperate, isAdmin, canViewAuditLogs, canAccessRemediation } = useAuth();
  const { pathname } = useLocation();

  if (isAuditorPortal && !isAuditorAllowedPath(pathname)) {
    return <Navigate to="/" replace />;
  }

  if (!canOperate && OPERATOR_ONLY_PATHS.has(pathname)) {
    return <Navigate to="/" replace />;
  }

  if (!canAccessRemediation && isRemediationPath(pathname)) {
    return <Navigate to="/jobs" replace />;
  }

  if (!isAdmin && ADMIN_ONLY_PATHS.has(pathname)) {
    return <Navigate to="/" replace />;
  }

  if (!canViewAuditLogs && AUDIT_ACCESS_PATHS.has(pathname)) {
    return <Navigate to="/" replace />;
  }

  return children;
}
