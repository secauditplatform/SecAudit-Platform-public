import Keycloak from "keycloak-js";
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, setAuthRefreshHandler, setAuthToken } from "../api/client";
import { clearAuthArtifacts } from "./clearAuthArtifacts";
import { LoginLoading, LoginPage } from "./LoginPage";
import { MfaRequiredError } from "./mfaErrors";

// Fail-closed: auth is on unless explicitly disabled with VITE_AUTH_ENABLED=false.
const authEnabled = import.meta.env.VITE_AUTH_ENABLED !== "false";
const localAuthEnabled = import.meta.env.VITE_LOCAL_AUTH_ENABLED === "true";
const demoMode = import.meta.env.VITE_DEMO_MODE === "true";
const ssoEnabled = import.meta.env.VITE_SSO_ENABLED !== "false";
const showSsoButton = import.meta.env.VITE_SHOW_SSO_BUTTON !== "false";
const authIdleTimeoutSeconds = (() => {
  const raw = Number(import.meta.env.VITE_AUTH_IDLE_TIMEOUT_SECONDS ?? "14400");
  return Number.isFinite(raw) && raw > 0 ? raw : 0;
})();
/** Platform (non-demo) UI idle logout: 4h by default. */
const platformIdleEnabled = authEnabled && !demoMode && authIdleTimeoutSeconds > 0;
const demoOperatorUsernames = (import.meta.env.VITE_DEMO_OPERATOR_USERNAMES || "")
  .split(",")
  .map((value) => value.trim().toLowerCase())
  .filter(Boolean);
const LOCAL_TOKEN_KEY = "secaudit_local_token";
const LOCAL_REFRESH_TOKEN_KEY = "secaudit_local_refresh_token";
const LOCAL_USER_KEY = "secaudit_local_user";
const LOCAL_LAST_ACTIVITY_KEY = "secaudit_last_activity";
const ADMIN_ROLE = "admin";
const OPERATOR_ROLE = "operator";
const AUDITOR_ROLE = "auditor";
const LEGACY_OPERATOR_ROLES = ["engineer", "viewer"];

export type PrimaryRole = "admin" | "operator" | "auditor";

type AuthMode = "keycloak" | "local" | "none";

type AuthContextValue = {
  ready: boolean;
  authenticated: boolean;
  username: string;
  token: string | null;
  roles: string[];
  primaryRole: PrimaryRole | null;
  isAdmin: boolean;
  /** Browse/operate UI (nav + forms). True for admin/operator even on the demo stand. */
  canOperate: boolean;
  /** Start compliance jobs, nmap/AuditFlow scans, remediation, playbook runs. False in demo. */
  canExecute: boolean;
  canAccessRemediation: boolean;
  canViewScripts: boolean;
  canManageUsers: boolean;
  canViewReports: boolean;
  canSeeObjectOwners: boolean;
  canViewAuditLogs: boolean;
  isAuditorPortal: boolean;
  isDemoMode: boolean;
  authMode: AuthMode;
  loginKeycloak: () => void;
  loginLocal: (username: string, password: string) => Promise<void>;
  verifyMfa: (mfaToken: string, code: string) => Promise<void>;
  loginDemo: () => Promise<void>;
  logout: () => void;
};

const AuthContext = createContext<AuthContextValue>({
  ready: false,
  authenticated: false,
  username: "",
  token: null,
  roles: [],
  primaryRole: null,
  isAdmin: false,
  canOperate: false,
  canExecute: false,
  canAccessRemediation: false,
  canViewScripts: false,
  canManageUsers: false,
  canViewReports: false,
  canSeeObjectOwners: false,
  canViewAuditLogs: false,
  isAuditorPortal: false,
  isDemoMode: false,
  authMode: "none",
  loginKeycloak: () => {},
  loginLocal: async () => {},
  verifyMfa: async () => {},
  loginDemo: async () => {},
  logout: () => {},
});

function normalizeRoles(roles: string[]): string[] {
  const normalized: string[] = [];
  for (const role of roles) {
    if (LEGACY_OPERATOR_ROLES.includes(role)) {
      if (!normalized.includes(OPERATOR_ROLE)) normalized.push(OPERATOR_ROLE);
      continue;
    }
    if (!normalized.includes(role)) normalized.push(role);
  }
  return normalized;
}

function resolvePrimaryRole(roles: string[]): PrimaryRole | null {
  if (roles.includes(ADMIN_ROLE)) return "admin";
  if (roles.includes(OPERATOR_ROLE)) return "operator";
  if (roles.includes(AUDITOR_ROLE)) return "auditor";
  return null;
}

function parseRolesFromToken(token: string): string[] {
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    return normalizeRoles(payload.realm_access?.roles ?? []);
  } catch {
    return [];
  }
}

function readStoredLocalAuth(): { token: string; refreshToken: string | null; username: string } | null {
  const token = sessionStorage.getItem(LOCAL_TOKEN_KEY);
  const refreshToken = sessionStorage.getItem(LOCAL_REFRESH_TOKEN_KEY);
  const username = sessionStorage.getItem(LOCAL_USER_KEY);
  if (!token || !username) return null;
  return { token, refreshToken, username };
}

function readLastActivity(): number {
  const raw = sessionStorage.getItem(LOCAL_LAST_ACTIVITY_KEY);
  const parsed = raw ? Number(raw) : NaN;
  return Number.isFinite(parsed) ? parsed : Date.now();
}

function writeLastActivity(ts = Date.now()) {
  sessionStorage.setItem(LOCAL_LAST_ACTIVITY_KEY, String(ts));
  return ts;
}

function isPlatformIdle(now = Date.now()): boolean {
  if (!platformIdleEnabled) return false;
  return now - readLastActivity() >= authIdleTimeoutSeconds * 1000;
}

function accessTokenExpiresSoon(token: string, thresholdSeconds = 300): boolean {
  try {
    const payload = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
    const exp = Number(payload.exp);
    if (!exp) return true;
    return exp - Math.floor(Date.now() / 1000) <= thresholdSeconds;
  } catch {
    return true;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [ready, setReady] = useState(!authEnabled);
  const [authenticated, setAuthenticated] = useState(!authEnabled);
  const [username, setUsername] = useState(authEnabled ? "" : "anonymous");
  const [token, setToken] = useState<string | null>(null);
  const [roles, setRoles] = useState<string[]>(authEnabled ? [] : [ADMIN_ROLE]);
  const [authMode, setAuthMode] = useState<AuthMode>(authEnabled ? "none" : "none");

  const keycloak = useMemo(() => {
    if (!authEnabled || !ssoEnabled) return null;
    return new Keycloak({
      url: import.meta.env.VITE_KEYCLOAK_URL || "http://localhost:8080",
      realm: import.meta.env.VITE_KEYCLOAK_REALM || "secaudit",
      clientId: import.meta.env.VITE_KEYCLOAK_CLIENT_ID || "secaudit-frontend",
    });
  }, []);

  const applyLocalAuth = useCallback((
    accessToken: string,
    localUsername: string,
    refreshToken?: string | null,
    options?: { touchActivity?: boolean },
  ) => {
    sessionStorage.setItem(LOCAL_TOKEN_KEY, accessToken);
    sessionStorage.setItem(LOCAL_USER_KEY, localUsername);
    if (refreshToken) {
      sessionStorage.setItem(LOCAL_REFRESH_TOKEN_KEY, refreshToken);
    }
    if (options?.touchActivity) {
      writeLastActivity();
    } else if (!sessionStorage.getItem(LOCAL_LAST_ACTIVITY_KEY)) {
      writeLastActivity();
    }
    setAuthToken(accessToken);
    setToken(accessToken);
    setRoles(parseRolesFromToken(accessToken));
    setUsername(localUsername);
    setAuthenticated(true);
    setAuthMode("local");
  }, []);

  const clearLocalAuth = useCallback(() => {
    sessionStorage.removeItem(LOCAL_TOKEN_KEY);
    sessionStorage.removeItem(LOCAL_REFRESH_TOKEN_KEY);
    sessionStorage.removeItem(LOCAL_USER_KEY);
    sessionStorage.removeItem(LOCAL_LAST_ACTIVITY_KEY);
  }, []);

  const refreshLocalAuth = useCallback(async () => {
    if (isPlatformIdle()) {
      clearLocalAuth();
      clearAuthArtifacts();
      setAuthenticated(false);
      setToken(null);
      setRoles([]);
      setUsername("");
      setAuthMode("none");
      return false;
    }
    const refreshToken = sessionStorage.getItem(LOCAL_REFRESH_TOKEN_KEY);
    if (!refreshToken) return false;
    try {
      const result = await api.refreshLocalToken(refreshToken);
      const username = sessionStorage.getItem(LOCAL_USER_KEY) || "user";
      applyLocalAuth(result.access_token, username, result.refresh_token);
      return true;
    } catch {
      clearLocalAuth();
      clearAuthArtifacts();
      setAuthenticated(false);
      setToken(null);
      setRoles([]);
      setUsername("");
      setAuthMode("none");
      return false;
    }
  }, [applyLocalAuth, clearLocalAuth]);

  const syncKeycloakAuth = useCallback((kc: Keycloak, options?: { touchActivity?: boolean }) => {
    if (!kc.token) return;
    if (options?.touchActivity) {
      writeLastActivity();
    } else if (!sessionStorage.getItem(LOCAL_LAST_ACTIVITY_KEY)) {
      writeLastActivity();
    }
    setAuthToken(kc.token);
    setAuthenticated(true);
    setUsername(kc.tokenParsed?.preferred_username || "user");
    setToken(kc.token);
    setRoles(normalizeRoles((kc.tokenParsed?.realm_access?.roles as string[] | undefined) ?? []));
    setAuthMode("keycloak");
  }, []);

  const clearKeycloakAuth = useCallback(() => {
    clearAuthArtifacts();
    sessionStorage.removeItem(LOCAL_LAST_ACTIVITY_KEY);
    setAuthenticated(false);
    setToken(null);
    setRoles([]);
    setUsername("");
    setAuthMode("none");
  }, []);

  const refreshKeycloakToken = useCallback(async (minValidity = 70) => {
    if (!keycloak?.token) return false;
    if (isPlatformIdle()) {
      clearKeycloakAuth();
      keycloak.logout({ redirectUri: window.location.origin });
      return false;
    }
    try {
      await keycloak.updateToken(minValidity);
      syncKeycloakAuth(keycloak);
      return true;
    } catch {
      clearKeycloakAuth();
      return false;
    }
  }, [keycloak, syncKeycloakAuth, clearKeycloakAuth]);

  const initStartedRef = useRef(false);
  const logoutRef = useRef<() => void>(() => {});

  useEffect(() => {
    if (!authEnabled) return;
    if (initStartedRef.current) return;
    initStartedRef.current = true;

    const stored = readStoredLocalAuth();
    if (stored) {
      if (isPlatformIdle()) {
        sessionStorage.removeItem(LOCAL_TOKEN_KEY);
        sessionStorage.removeItem(LOCAL_REFRESH_TOKEN_KEY);
        sessionStorage.removeItem(LOCAL_USER_KEY);
        sessionStorage.removeItem(LOCAL_LAST_ACTIVITY_KEY);
        setReady(true);
        return;
      }
      applyLocalAuth(stored.token, stored.username, stored.refreshToken);
      setReady(true);
      return;
    }

    if (!keycloak) {
      setReady(true);
      return;
    }

    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      window.clearTimeout(fallbackTimer);
      setReady(true);
    };
    const fallbackTimer = window.setTimeout(finish, 8000);

    keycloak.onTokenExpired = () => {
      void refreshKeycloakToken();
    };

    keycloak
      .init({
        onLoad: "check-sso",
        pkceMethod: "S256",
        checkLoginIframe: false,
        silentCheckSsoRedirectUri: `${window.location.origin}/silent-check-sso.html`,
      })
      .then(async (auth) => {
        if (auth) {
          await refreshKeycloakToken();
        }
        finish();
      })
      .catch(() => finish());
  }, [keycloak, applyLocalAuth, refreshKeycloakToken]);

  useEffect(() => {
    if (!keycloak || authMode !== "keycloak" || !authenticated) return;

    const intervalId = window.setInterval(() => {
      void refreshKeycloakToken();
    }, 30_000);

    return () => window.clearInterval(intervalId);
  }, [keycloak, authMode, authenticated, refreshKeycloakToken]);

  useEffect(() => {
    if (authMode !== "local" || !authenticated || !token) return;

    const intervalId = window.setInterval(() => {
      if (accessTokenExpiresSoon(token)) {
        void refreshLocalAuth();
      }
    }, 30_000);

    return () => window.clearInterval(intervalId);
  }, [authMode, authenticated, token, refreshLocalAuth]);

  useEffect(() => {
    setAuthRefreshHandler(async () => {
      if (authMode === "keycloak") return refreshKeycloakToken(-1);
      if (authMode === "local") return refreshLocalAuth();
      return false;
    });
    return () => setAuthRefreshHandler(null);
  }, [authMode, refreshKeycloakToken, refreshLocalAuth]);

  const loginKeycloak = () => keycloak?.login();

  const loginLocal = async (localUsername: string, password: string) => {
    const result = await api.localLogin(localUsername, password);
    if (result.mfa_required && result.mfa_token) {
      throw new MfaRequiredError(result.mfa_token, result.username);
    }
    if (!result.access_token || !result.refresh_token) {
      throw new Error("Sign-in failed");
    }
    applyLocalAuth(result.access_token, result.username, result.refresh_token, { touchActivity: true });
  };

  const verifyMfa = async (mfaToken: string, code: string) => {
    const result = await api.verifyMfa(mfaToken, code);
    if (!result.access_token || !result.refresh_token) {
      throw new Error("MFA verification failed");
    }
    applyLocalAuth(result.access_token, result.username, result.refresh_token, { touchActivity: true });
  };

  const loginDemo = async () => {
    const result = await api.demoLogin();
    applyLocalAuth(result.access_token, result.username, result.refresh_token, { touchActivity: true });
  };

  const logout = () => {
    if (authMode === "local" && token) {
      void api.logout().catch(() => undefined);
    }
    clearLocalAuth();
    clearAuthArtifacts();
    setAuthenticated(false);
    setToken(null);
    setRoles([]);
    setUsername("");
    setAuthMode("none");
    if (authMode === "keycloak" && keycloak) {
      keycloak.logout({ redirectUri: window.location.origin });
    }
  };
  logoutRef.current = logout;

  useEffect(() => {
    if (!platformIdleEnabled || !authenticated) return;

    writeLastActivity(readLastActivity());
    let lastMoveMark = 0;
    const markActivity = () => {
      writeLastActivity();
    };
    const onMouseMove = () => {
      const now = Date.now();
      if (now - lastMoveMark < 15_000) return;
      lastMoveMark = now;
      markActivity();
    };
    const events: Array<[keyof WindowEventMap, EventListener]> = [
      ["mousedown", markActivity],
      ["keydown", markActivity],
      ["touchstart", markActivity],
      ["scroll", markActivity],
      ["mousemove", onMouseMove],
    ];
    for (const [name, handler] of events) {
      window.addEventListener(name, handler, { passive: true });
    }
    const intervalId = window.setInterval(() => {
      if (isPlatformIdle()) {
        logoutRef.current();
      }
    }, 30_000);
    return () => {
      for (const [name, handler] of events) {
        window.removeEventListener(name, handler);
      }
      window.clearInterval(intervalId);
    };
  }, [authenticated]);

  const primaryRole = !authEnabled ? "admin" : resolvePrimaryRole(roles);
  const isAdmin = !authEnabled || roles.includes(ADMIN_ROLE);
  const canOperate = !authEnabled || roles.includes(ADMIN_ROLE) || roles.includes(OPERATOR_ROLE);
  const isDemoOperator =
    demoMode && demoOperatorUsernames.includes((username || "").trim().toLowerCase());
  const guestDemoMode = demoMode && !isDemoOperator;
  const canExecute = (!demoMode || isDemoOperator) && canOperate;
  const canAccessRemediation = !authEnabled || roles.includes(ADMIN_ROLE);
  const canViewScripts = !authEnabled || roles.includes(ADMIN_ROLE);
  const canManageUsers = !authEnabled || roles.includes(ADMIN_ROLE);
  const canViewReports =
    !authEnabled ||
    roles.includes(ADMIN_ROLE) ||
    roles.includes(OPERATOR_ROLE) ||
    roles.includes(AUDITOR_ROLE);
  const canSeeObjectOwners = !authEnabled || roles.includes(ADMIN_ROLE) || roles.includes(OPERATOR_ROLE);
  const canViewAuditLogs = !authEnabled || roles.includes(ADMIN_ROLE) || roles.includes(OPERATOR_ROLE);
  const isAuditorPortal = authEnabled && primaryRole === "auditor";

  const value: AuthContextValue = {
    ready,
    authenticated,
    username,
    token,
    roles,
    primaryRole,
    isAdmin,
    canOperate,
    canExecute,
    canAccessRemediation,
    canViewScripts,
    canManageUsers,
    canViewReports,
    canSeeObjectOwners,
    canViewAuditLogs,
    isAuditorPortal,
    isDemoMode: guestDemoMode,
    authMode,
    loginKeycloak,
    loginLocal,
    verifyMfa,
    loginDemo,
    logout,
  };

  if (!ready) {
    return <LoginLoading />;
  }

  if (authEnabled && !authenticated) {
    return (
      <LoginPage
        showKeycloak={showSsoButton && (Boolean(keycloak) || !ssoEnabled)}
        keycloakDisabled={!ssoEnabled || !keycloak}
        showLocal={localAuthEnabled}
        localDisabled={demoMode}
        demoStand={demoMode}
        onKeycloakLogin={loginKeycloak}
        onLocalLogin={loginLocal}
        onMfaVerify={verifyMfa}
        onDemoLogin={demoMode ? loginDemo : undefined}
      />
    );
  }

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return useContext(AuthContext);
}
