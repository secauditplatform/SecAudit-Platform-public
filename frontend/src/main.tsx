import { QueryClientProvider, useQueryClient } from "@tanstack/react-query";
import { StrictMode, useEffect, useRef } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter, Route, Routes } from "react-router-dom";
import { setAuthToken } from "./api/client";
import { shouldClearQueryCacheOnIdentityChange } from "./auth/clearAuthArtifacts";
import { AuthProvider, useAuth } from "./auth/AuthProvider";
import { Layout } from "./components/Layout";
import { ConfirmProvider } from "./components/ui/ConfirmDialog";
import { ToastProvider } from "./components/ui/Toast";
import { I18nProvider } from "./i18n/I18nProvider";
import { queryClient } from "./queryClient";
import { ThemeProvider } from "./theme/ThemeProvider";
import { CredentialsPage } from "./pages/CredentialsPage";
import { ConsolePage } from "./pages/ConsolePage";
import { DashboardPage } from "./pages/DashboardPage";
import { PlatformOverviewPage } from "./pages/PlatformOverviewPage";
import { HostsPage } from "./pages/HostsPage";
import { JobsPage } from "./pages/JobsPage";
import { NetworkJobsPage } from "./pages/NetworkJobsPage";
import { NetworkRemediationPage } from "./pages/NetworkRemediationPage";
import { RemediationPage } from "./pages/RemediationPage";
import { PlaybooksPage } from "./pages/PlaybooksPage";
import { ReportsPage } from "./pages/ReportsPage";
import { ProfilesPage } from "./pages/ProfilesPage";
import { WaiversPage } from "./pages/WaiversPage";
import { TrendsPage } from "./pages/TrendsPage";
import { AuditLogsPage } from "./pages/AuditLogsPage";
import { AuditFlowPage } from "./pages/AuditFlowPage";
import { UsersPage } from "./pages/UsersPage";
import "./index.css";

function TokenSync({ children }: { children: React.ReactNode }) {
  const { token, username, authenticated } = useAuth();
  const client = useQueryClient();
  const prevIdentity = useRef<string | null | undefined>(undefined);

  // Stable across JWT refresh; null when logged out.
  const identity = token && authenticated ? username : null;

  // Set synchronously so child useQuery hooks include Bearer on first mount,
  // and so a null token never leaves a stale module-level bearer.
  setAuthToken(token);

  useEffect(() => {
    if (shouldClearQueryCacheOnIdentityChange(prevIdentity.current, identity)) {
      client.clear();
    }
    prevIdentity.current = identity;
  }, [identity, client]);

  return <>{children}</>;
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <I18nProvider>
      <ThemeProvider>
        <QueryClientProvider client={queryClient}>
        <AuthProvider>
          <ToastProvider>
            <ConfirmProvider>
              <TokenSync>
                <BrowserRouter>
                  <Routes>
                    <Route element={<Layout />}>
                      <Route index element={<DashboardPage />} />
                      <Route path="overview" element={<PlatformOverviewPage />} />
                      <Route path="profiles" element={<ProfilesPage />} />
                      <Route path="playbooks" element={<PlaybooksPage />} />
                      <Route path="audit-flow" element={<AuditFlowPage />} />
                      <Route path="console" element={<ConsolePage />} />
                      <Route path="hosts" element={<HostsPage />} />
                      <Route path="credentials" element={<CredentialsPage />} />
                      <Route path="users" element={<UsersPage />} />
                      <Route path="jobs" element={<JobsPage />} />
                      <Route path="network/jobs" element={<NetworkJobsPage />} />
                      <Route path="remediation" element={<RemediationPage />} />
                      <Route path="network/remediation" element={<NetworkRemediationPage />} />
                      <Route path="reports" element={<ReportsPage />} />
                      <Route path="waivers" element={<WaiversPage />} />
                      <Route path="trends" element={<TrendsPage />} />
                      <Route path="audit-logs" element={<AuditLogsPage />} />
                    </Route>
                  </Routes>
                </BrowserRouter>
              </TokenSync>
            </ConfirmProvider>
          </ToastProvider>
        </AuthProvider>
      </QueryClientProvider>
      </ThemeProvider>
    </I18nProvider>
  </StrictMode>
);
