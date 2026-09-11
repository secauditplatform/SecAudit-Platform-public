import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type Host, type InventoryScan } from "../api/client";
import { HostCredentialPopover } from "../components/HostCredentialPopover";
import { OpsListExpandFooter } from "../components/OpsListExpandFooter";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { EmptyState } from "../components/ui/EmptyState";
import { QueryErrorState } from "../components/ui/QueryErrorState";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { SortableTh } from "../components/ui/SortableTh";
import { Spinner } from "../components/ui/Spinner";
import { useConfirm } from "../components/ui/ConfirmDialog";
import { useToast } from "../components/ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";
import { useAuth } from "../auth/AuthProvider";
import { ObjectOwnerCell } from "../components/ObjectOwnerCell";
import { useTableSort } from "../hooks/useTableSort";
import { sliceOpsList } from "../utils/opsListLimit";

function formatNmapFlagsDisplay(raw: string | null | undefined, fallback: string): string {
  if (!raw) return fallback;
  try {
    const data = JSON.parse(raw) as { mode?: string; flags?: string[]; discovery?: string[]; port_scan?: string[] };
    if (data.mode === "custom") {
      return data.flags?.join(" ") || fallback;
    }
    const discovery = data.discovery?.join(" ") ?? "-sn";
    const portScan = data.port_scan?.join(" ") ?? "-Pn -sT -F -T4 --max-retries 1 --host-timeout 30s --open";
    return `${discovery}; ${portScan}`;
  } catch {
    return raw;
  }
}

function parseHostEditId(value: string | null): number | null {
  if (!value) return null;
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function formatHostDeleteError(message: string, t: (key: string) => string): string {
  const normalized = message.toLowerCase();
  if (normalized.includes("active run")) return t("hosts.deleteBlockedActiveRun");
  if (normalized.includes("not found")) return t("hosts.deleteNotFound");
  if (normalized.includes("related data") || normalized.includes("server error")) {
    return t("hosts.deleteFailed");
  }
  return message;
}

function scanStatusVariant(status: string): "success" | "danger" | "warning" | "info" | "neutral" {
  switch (status) {
    case "completed":
      return "success";
    case "failed":
      return "danger";
    case "running":
      return "info";
    case "pending":
      return "warning";
    case "cancelled":
      return "danger";
    default:
      return "neutral";
  }
}

function ScanTaskRow({
  scan,
  expanded,
  onToggle,
  onStop,
  onDelete,
  hostNameById,
  onEditHost,
  stopPending,
  deletePending,
}: {
  scan: InventoryScan;
  expanded: boolean;
  onToggle: () => void;
  onStop: () => void;
  onDelete: () => void;
  hostNameById: Map<number, string>;
  onEditHost?: (hostId: number) => void;
  stopPending: boolean;
  deletePending: boolean;
}) {
  const { t, dateLocale } = useTranslation();
  const queryClient = useQueryClient();
  const detail = useQuery({
    queryKey: ["inventory-scan", scan.id],
    queryFn: () => api.getInventoryScan(scan.id),
    enabled: expanded,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "pending" || status === "running" ? 3000 : false;
    },
  });

  useEffect(() => {
    if ((detail.data?.hosts_created ?? 0) > 0) {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
    }
  }, [detail.data?.hosts_created, queryClient]);

  const live = detail.data ?? scan;
  const isLive = live.status === "pending" || live.status === "running";
  const activeCount = detail.data?.results.filter((r) => r.is_active).length;
  const results = detail.data?.results ?? [];
  const linkedCount = results.filter((r) => r.host_id != null).length;
  const skippedExisting = Math.max(0, linkedCount - (live.hosts_created ?? 0));

  useEffect(() => {
    if (!isLive || !detail.data) return;
    queryClient.setQueryData(["inventory-scans"], (prev: InventoryScan[] | undefined) => {
      if (!prev) return prev;
      return prev.map((item) =>
        item.id === detail.data!.id
          ? {
              ...item,
              status: detail.data!.status,
              hosts_found: detail.data!.hosts_found,
              hosts_created: detail.data!.hosts_created,
              error_message: detail.data!.error_message,
            }
          : item
      );
    });
  }, [
    isLive,
    detail.data?.id,
    detail.data?.status,
    detail.data?.hosts_found,
    detail.data?.hosts_created,
    detail.data?.error_message,
    detail.data,
    queryClient,
  ]);

  return (
    <div className={`pf-scan-task${expanded ? " pf-scan-task--expanded" : ""}`}>
      <div className="pf-scan-task__header">
        <button type="button" className="pf-scan-task__toggle" onClick={onToggle} aria-expanded={expanded}>
          <span className="pf-scan-task__chevron" aria-hidden />
          <div className="pf-scan-task__main">
            <span className="pf-scan-task__target">
              #{scan.id} · {scan.target}
            </span>
            <div className="pf-scan-task__meta">
              <Badge variant={scanStatusVariant(live.status)} literal>
                {live.status}
              </Badge>
              <span>
                {t("hosts.scanFound")}: <strong>{live.hosts_found}</strong>
              </span>
              {detail.data && (live.status === "completed" || isLive) && (
                <span>
                  {t("hosts.scanActive")}: <strong>{activeCount ?? 0}</strong>
                </span>
              )}
              <span>
                {t("hosts.scanCreated")}: <strong>{live.hosts_created}</strong>
              </span>
              {skippedExisting > 0 ? (
                <span>
                  {t("hosts.scanSkippedExisting")}: <strong>{skippedExisting}</strong>
                </span>
              ) : null}
              <span className="pf-scan-task__flags" title={formatNmapFlagsDisplay(scan.nmap_flags, t("hosts.scanNmapFlagsDefault"))}>
                {t("hosts.scanNmapFlagsUsed")}:{" "}
                <code>{formatNmapFlagsDisplay(scan.nmap_flags, t("hosts.scanNmapFlagsDefault"))}</code>
              </span>
              <span>{new Date(scan.created_at).toLocaleString(dateLocale)}</span>
            </div>
          </div>
        </button>
        <div className="pf-scan-task__actions pf-table__actions">
          {(live.status === "pending" || live.status === "running") && (
            <Button variant="secondary" className="pf-btn--sm" onClick={onStop} disabled={stopPending}>
              {t("common.stop")}
            </Button>
          )}
          <Button variant="danger-secondary" className="pf-btn--sm" onClick={onDelete} disabled={deletePending}>
            {t("common.delete")}
          </Button>
        </div>
      </div>
      {expanded && (
        <div className="pf-scan-task__body">
          <p className="pf-scan-task__flags-detail">
            <span className="pf-table__muted">{t("hosts.scanNmapFlagsUsed")}: </span>
            <code>{formatNmapFlagsDisplay(detail.data?.nmap_flags ?? scan.nmap_flags, t("hosts.scanNmapFlagsDefault"))}</code>
          </p>
          {isLive && (
            <p className="pf-table__muted">
              {results.length === 0 ? t("hosts.scanInProgressDiscovery") : t("hosts.scanInProgressPorts")}
            </p>
          )}
          {detail.isLoading ? (
            <Spinner />
          ) : detail.data?.error_message ? (
            <div className="pf-alert pf-alert--error">{detail.data.error_message}</div>
          ) : results.length === 0 ? (
            <p className="pf-table__muted">{isLive ? t("hosts.scanWaitingResults") : t("hosts.scanEmpty")}</p>
          ) : (
            <div className="pf-table-wrap">
              <table className="pf-table pf-table--compact">
                <thead>
                  <tr>
                    <th>{t("hosts.scanIp")}</th>
                    <th>{t("hosts.scanHostname")}</th>
                    <th>{t("hosts.scanPorts")}</th>
                    <th>{t("hosts.scanHostLink")}</th>
                    <th>{t("common.status")}</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((row) => {
                    const portsPending = isLive && row.ports_scanned === false;
                    return (
                      <tr key={row.id}>
                        <td className="pf-table__mono">{row.ip_address}</td>
                        <td>{row.resolved_hostname || t("common.dash")}</td>
                        <td className="pf-table__mono">
                          {row.open_ports.length > 0
                            ? row.open_ports.join(", ")
                            : portsPending
                              ? t("hosts.scanPortsPending")
                              : t("hosts.scanNoPorts")}
                        </td>
                        <td>
                          {row.host_id ? (
                            onEditHost ? (
                              <Button
                                variant="link"
                                className="pf-btn--sm"
                                onClick={() => onEditHost(row.host_id!)}
                              >
                                {hostNameById.get(row.host_id) ??
                                  row.resolved_hostname ??
                                  `#${row.host_id}`}
                              </Button>
                            ) : (
                              hostNameById.get(row.host_id) ??
                              row.resolved_hostname ??
                              `#${row.host_id}`
                            )
                          ) : (
                            t("common.dash")
                          )}
                        </td>
                        <td>
                          <Badge variant={row.is_active ? "success" : "neutral"}>
                            {row.is_active
                              ? t("hosts.scanActive")
                              : portsPending
                                ? t("hosts.scanPortsPending")
                                : t("hosts.scanNoPorts")}
                          </Badge>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function hostHasCredential(host: Host): boolean {
  return (host.linked_credentials?.length ?? 0) > 0 || host.credential_id != null;
}

const HOSTS_FETCH_LIMIT = 200;
const SCAN_STATUS_OPTIONS = ["all", "pending", "running", "completed", "failed", "cancelled"] as const;
type ScanStatusFilter = (typeof SCAN_STATUS_OPTIONS)[number];
type HostStatusFilter = "all" | "active" | "inactive";
type HostCredentialFilter = "all" | "with" | "without";

export function HostsPage() {
  const { t } = useTranslation();
  const { canSeeObjectOwners, canOperate, canExecute } = useAuth();
  const { confirm } = useConfirm();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const emptyHostForm = () => ({
    name: "",
    hostname: "",
    port: "22",
    os_type: "linux",
    credential_id: "" as number | "",
    is_active: true,
  });
  const [form, setForm] = useState(emptyHostForm);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [scanTarget, setScanTarget] = useState("127.0.0.1");
  const [scanNmapFlags, setScanNmapFlags] = useState("");
  const [expandedScanId, setExpandedScanId] = useState<number | null>(null);
  const [scanHistoryCollapsed, setScanHistoryCollapsed] = useState(false);
  const [scanListExpanded, setScanListExpanded] = useState(false);
  const [scanSearch, setScanSearch] = useState("");
  const [scanStatusFilter, setScanStatusFilter] = useState<ScanStatusFilter>("all");
  const [hostSearch, setHostSearch] = useState("");
  const [hostOsFilter, setHostOsFilter] = useState("all");
  const [hostStatusFilter, setHostStatusFilter] = useState<HostStatusFilter>("all");
  const [hostCredentialFilter, setHostCredentialFilter] = useState<HostCredentialFilter>("all");
  const [hostListExpanded, setHostListExpanded] = useState(false);
  const hostFormPanelRef = useRef<HTMLDivElement | null>(null);
  const urlEditHostId = parseHostEditId(searchParams.get("edit"));

  const hosts = useQuery({
    queryKey: ["hosts", HOSTS_FETCH_LIMIT],
    queryFn: () => api.hosts({ offset: 0, limit: HOSTS_FETCH_LIMIT }),
  });
  const credentials = useQuery({ queryKey: ["credentials"], queryFn: api.credentials });
  const scans = useQuery({
    queryKey: ["inventory-scans"],
    queryFn: api.inventoryScans,
    refetchInterval: (query) => {
      const hasActive = query.state.data?.some((s) => s.status === "pending" || s.status === "running");
      return hasActive ? 3000 : false;
    },
  });

  const parsedPort = Number(form.port);
  const portValid = Number.isInteger(parsedPort) && parsedPort >= 1 && parsedPort <= 65535;

  const hostNameById = useMemo(
    () => new Map(hosts.data?.items?.map((h) => [h.id, h.name])),
    [hosts.data]
  );
  const hostById = useMemo(
    () => new Map(hosts.data?.items?.map((h) => [h.id, h])),
    [hosts.data]
  );

  const scrollToHostForm = useCallback(() => {
    requestAnimationFrame(() => {
      hostFormPanelRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      document.getElementById("host-name")?.focus();
    });
  }, []);

  const startEdit = useCallback(
    (host: Host, options?: { updateUrl?: boolean }) => {
      setEditingId(host.id);
      setForm({
        name: host.name,
        hostname: host.hostname,
        port: String(host.port ?? 22),
        os_type: host.os_type ?? "linux",
        credential_id: host.credential_id ?? "",
        is_active: host.is_active,
      });
      if (options?.updateUrl !== false) {
        setSearchParams({ edit: String(host.id) }, { replace: true });
      }
      scrollToHostForm();
    },
    [scrollToHostForm, setSearchParams]
  );

  const startEditById = useCallback(
    async (hostId: number, options?: { updateUrl?: boolean }) => {
      const cached = hostById.get(hostId);
      if (cached) {
        startEdit(cached, options);
        return;
      }
      try {
        const host = await api.getHost(hostId);
        startEdit(host, options);
      } catch (err) {
        toast.error(err instanceof Error ? err.message : t("toast.genericError"));
      }
    },
    [hostById, startEdit, t, toast]
  );

  useEffect(() => {
    if (urlEditHostId == null || editingId === urlEditHostId) return;
    void startEditById(urlEditHostId, { updateUrl: false });
  }, [urlEditHostId, editingId, startEditById]);

  const createMutation = useMutation({
    mutationFn: api.createHost,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      setForm(emptyHostForm());
      toast.success(t("toast.hostCreated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<Omit<Host, "id">> }) =>
      api.updateHost(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      setEditingId(null);
      setForm(emptyHostForm());
      if (searchParams.has("edit")) {
        setSearchParams({}, { replace: true });
      }
      toast.success(t("toast.hostUpdated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteHost,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      toast.success(t("toast.hostDeleted"));
    },
    onError: (err) =>
      toast.error(
        err instanceof Error ? formatHostDeleteError(err.message, t) : t("toast.genericError")
      ),
  });

  const scanFingerprintMutation = useMutation({
    mutationFn: api.scanHostSshFingerprint,
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      toast.success(t("hosts.sshFingerprintSaved", { fingerprint: result.fingerprint }));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const scanMutation = useMutation({
    mutationFn: api.startInventoryScan,
    onSuccess: (scan) => {
      queryClient.invalidateQueries({ queryKey: ["inventory-scans"] });
      setExpandedScanId(scan.id);
      setScanHistoryCollapsed(false);
    },
  });

  const stopScanMutation = useMutation({
    mutationFn: api.stopInventoryScan,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["inventory-scans"] }),
  });

  const deleteScanMutation = useMutation({
    mutationFn: api.deleteInventoryScan,
    onSuccess: (_data, scanId) => {
      queryClient.invalidateQueries({ queryKey: ["inventory-scans"] });
      if (expandedScanId === scanId) {
        setExpandedScanId(null);
      }
    },
  });

  const handleDelete = (id: number) => {
    deleteMutation.mutate(id);
  };

  const cancelEdit = () => {
    setEditingId(null);
    setForm(emptyHostForm());
    if (searchParams.has("edit")) {
      setSearchParams({}, { replace: true });
    }
  };

  const isEditing = editingId !== null;

  const hostRows = hosts.data?.items ?? [];
  const hostsTotal = hosts.data?.total ?? 0;

  const filteredScans = useMemo(() => {
    if (!scans.data) return [];
    const query = scanSearch.trim().toLowerCase();
    return scans.data.filter((scan) => {
      if (scanStatusFilter !== "all" && scan.status !== scanStatusFilter) return false;
      if (!query) return true;
      return (
        scan.target.toLowerCase().includes(query) ||
        String(scan.id).includes(query) ||
        formatNmapFlagsDisplay(scan.nmap_flags, "").toLowerCase().includes(query)
      );
    });
  }, [scans.data, scanSearch, scanStatusFilter]);

  const visibleScans = useMemo(
    () => sliceOpsList(filteredScans, scanListExpanded),
    [filteredScans, scanListExpanded]
  );

  const hasActiveScanFilters = scanSearch.trim() !== "" || scanStatusFilter !== "all";

  const filteredHostRows = useMemo(() => {
    const query = hostSearch.trim().toLowerCase();
    return hostRows.filter((host) => {
      if (hostOsFilter !== "all" && (host.os_type ?? "linux") !== hostOsFilter) return false;
      if (hostStatusFilter === "active" && !host.is_active) return false;
      if (hostStatusFilter === "inactive" && host.is_active) return false;
      if (hostCredentialFilter === "with" && !hostHasCredential(host)) return false;
      if (hostCredentialFilter === "without" && hostHasCredential(host)) return false;
      if (!query) return true;
      return (
        host.name.toLowerCase().includes(query) ||
        host.hostname.toLowerCase().includes(query) ||
        String(host.port).includes(query)
      );
    });
  }, [hostRows, hostSearch, hostOsFilter, hostStatusFilter, hostCredentialFilter]);

  const hasActiveHostFilters =
    hostSearch.trim() !== "" ||
    hostOsFilter !== "all" ||
    hostStatusFilter !== "all" ||
    hostCredentialFilter !== "all";

  type HostSortKey = "name" | "hostname" | "port" | "os_type" | "is_active";
  const hostAccessor = useCallback((host: Host, key: HostSortKey) => {
    if (key === "is_active") return host.is_active;
    return host[key];
  }, []);
  const { sortedRows: sortedHosts, sort: hostSort, toggleSort: toggleHostSort } = useTableSort<
    Host,
    HostSortKey
  >(filteredHostRows, { key: "name", direction: "asc" }, hostAccessor);

  const visibleHosts = useMemo(
    () => sliceOpsList(sortedHosts, hostListExpanded),
    [sortedHosts, hostListExpanded]
  );

  const clearScanFilters = () => {
    setScanSearch("");
    setScanStatusFilter("all");
    setScanListExpanded(false);
  };

  const clearHostFilters = () => {
    setHostSearch("");
    setHostOsFilter("all");
    setHostStatusFilter("all");
    setHostCredentialFilter("all");
    setHostListExpanded(false);
  };

  const handleStopScan = async (id: number, target: string) => {
    const ok = await confirm({
      title: t("common.stop"),
      message: t("hosts.scanStopConfirm", { target }),
      variant: "warning",
    });
    if (ok) stopScanMutation.mutate(id);
  };

  const handleDeleteScan = (id: number) => {
    deleteScanMutation.mutate(id);
  };

  return (
    <>
      <PageHeader title={t("hosts.title")} description={t("hosts.description")} />

      {canOperate ? (
        <>
          <Panel title={t("hosts.inventoryTitle")}>
        <div className="pf-form pf-form--wide">
          <div className="pf-form__row">
            <div className="pf-form__group">
              <label htmlFor="scan-target">{t("hosts.scanTarget")}</label>
              <input
                id="scan-target"
                className="pf-input"
                value={scanTarget}
                onChange={(e) => setScanTarget(e.target.value)}
                placeholder="192.168.1.0/24"
              />
              <p className="pf-form__hint">{t("hosts.scanTargetHint")}</p>
            </div>
            <div className="pf-form__group">
              <label htmlFor="scan-nmap-flags">{t("hosts.scanNmapFlags")}</label>
              <input
                id="scan-nmap-flags"
                className="pf-input"
                value={scanNmapFlags}
                onChange={(e) => setScanNmapFlags(e.target.value)}
                placeholder="-sT -p 22,80,443"
              />
              <p className="pf-form__hint">{t("hosts.scanNmapFlagsHint")}</p>
            </div>
          </div>
          <div className="pf-form__actions">
            <Button
              onClick={() =>
                scanMutation.mutate({
                  target: scanTarget.trim(),
                  ...(scanNmapFlags.trim() ? { nmap_flags: scanNmapFlags.trim() } : {}),
                })
              }
              disabled={!canExecute || !scanTarget.trim() || scanMutation.isPending}
              title={!canExecute ? t("common.demoActionDisabled") : undefined}
            >
              {t("hosts.scanStart")}
            </Button>
          </div>
          {scanMutation.isError && (
            <div className="pf-alert pf-alert--error">
              {(scanMutation.error as Error).message}
            </div>
          )}
        </div>
      </Panel>

      <Panel
        title={t("hosts.scanHistory")}
        noPadding
        collapsed={scanHistoryCollapsed}
        onCollapsedChange={setScanHistoryCollapsed}
      >
        {scans.isLoading ? (
          <Spinner />
        ) : scans.data?.length === 0 ? (
          <EmptyState title={t("hosts.scanEmpty")} description={t("hosts.scanEmptyDesc")} />
        ) : (
          <>
            <div className="pf-filters">
              <div className="pf-filters__grid pf-filters__grid--scans">
                <div className="pf-filters__group">
                  <label htmlFor="scan-filter-search">{t("hosts.scanListSearchLabel")}</label>
                  <input
                    id="scan-filter-search"
                    className="pf-input"
                    value={scanSearch}
                    onChange={(e) => setScanSearch(e.target.value)}
                    placeholder={t("hosts.scanListSearch")}
                  />
                </div>
                <div className="pf-filters__group">
                  <label htmlFor="scan-filter-status">{t("hosts.scanListStatusFilter")}</label>
                  <select
                    id="scan-filter-status"
                    className="pf-select"
                    value={scanStatusFilter}
                    onChange={(e) => setScanStatusFilter(e.target.value as ScanStatusFilter)}
                  >
                    {SCAN_STATUS_OPTIONS.map((status) => (
                      <option key={status} value={status}>
                        {status === "all" ? t("hosts.scanListStatusAll") : status}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="pf-filters__footer">
                <p className="pf-filters__summary">
                  {hasActiveScanFilters
                    ? t("profiles.filterResultsActive", {
                        count: filteredScans.length,
                        total: scans.data.length,
                      })
                    : t("profiles.filterShown", {
                        count: filteredScans.length,
                        total: scans.data.length,
                      })}
                </p>
                {hasActiveScanFilters ? (
                  <Button variant="secondary" className="pf-btn--sm" type="button" onClick={clearScanFilters}>
                    {t("profiles.clearFilters")}
                  </Button>
                ) : null}
              </div>
            </div>
            {filteredScans.length === 0 ? (
              <EmptyState title={t("jobs.noFilterResults")} description={t("jobs.noFilterResultsDesc")} />
            ) : (
              <>
                <div className="pf-scan-list">
                  {visibleScans.map((scan) => (
                    <ScanTaskRow
                      key={scan.id}
                      scan={scan}
                      expanded={expandedScanId === scan.id}
                      onToggle={() => setExpandedScanId(expandedScanId === scan.id ? null : scan.id)}
                      onStop={() => handleStopScan(scan.id, scan.target)}
                      onDelete={() => handleDeleteScan(scan.id)}
                      hostNameById={hostNameById}
                      onEditHost={canOperate ? startEditById : undefined}
                      stopPending={stopScanMutation.isPending}
                      deletePending={deleteScanMutation.isPending}
                    />
                  ))}
                </div>
                <OpsListExpandFooter
                  shown={visibleScans.length}
                  total={filteredScans.length}
                  expanded={scanListExpanded}
                  onToggle={() => setScanListExpanded((value) => !value)}
                />
              </>
            )}
          </>
        )}
      </Panel>

      <div ref={hostFormPanelRef}>
      <Panel title={isEditing ? t("hosts.editTitle", { name: form.name }) : t("hosts.addHost")}>
        <div className="pf-form pf-form--wide">
          <div className="pf-form__row pf-form__row--host-primary">
            <div className="pf-form__group">
              <label htmlFor="host-name">{t("hosts.name")}</label>
              <input
                id="host-name"
                className="pf-input"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="prod-db-01"
              />
            </div>
            <div className="pf-form__group">
              <label htmlFor="host-hostname">{t("hosts.hostname")}</label>
              <input
                id="host-hostname"
                className="pf-input"
                value={form.hostname}
                onChange={(e) => setForm({ ...form, hostname: e.target.value })}
                placeholder="10.0.0.15"
              />
            </div>
            <div className="pf-form__group">
              <label htmlFor="host-port">{t("hosts.port")}</label>
              <input
                id="host-port"
                className="pf-input"
                type="number"
                min={1}
                max={65535}
                value={form.port}
                onChange={(e) => setForm({ ...form, port: e.target.value })}
              />
            </div>
          </div>
          <div className="pf-form__row pf-form__row--host-secondary">
            <div className="pf-form__group">
              <label htmlFor="host-os">{t("hosts.osType")}</label>
              <select
                id="host-os"
                className="pf-select"
                value={form.os_type}
                onChange={(e) => setForm({ ...form, os_type: e.target.value })}
              >
                <option value="linux">{t("hosts.osLinux")}</option>
                <option value="windows">{t("hosts.osWindows")}</option>
                <option value="network">{t("hosts.osNetwork")}</option>
              </select>
            </div>
            <div className="pf-form__group pf-form__group--host-credential">
              <label htmlFor="host-cred">{t("hosts.credential")}</label>
              <select
                id="host-cred"
                className="pf-select"
                value={form.credential_id}
                onChange={(e) =>
                  setForm({ ...form, credential_id: e.target.value ? Number(e.target.value) : "" })
                }
              >
                <option value="">{t("hosts.notSelected")}</option>
                {credentials.data?.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                    {c.username ? ` (${c.username})` : ""} · {c.credential_type}
                  </option>
                ))}
              </select>
              <p className="pf-form__hint">{t("hosts.credentialFormHint")}</p>
            </div>
          </div>
          <div className="pf-form__actions">
            {isEditing ? (
              <label className="pf-form__checkbox-label" htmlFor="host-active">
                <input
                  id="host-active"
                  type="checkbox"
                  className="pf-checkbox-control"
                  checked={form.is_active}
                  onChange={(e) => setForm({ ...form, is_active: e.target.checked })}
                />
                {t("hosts.isActive")}
              </label>
            ) : null}
            <div className="pf-form__actions-buttons">
            {isEditing ? (
              <>
                <Button
                  onClick={() =>
                    updateMutation.mutate({
                      id: editingId,
                      data: {
                        name: form.name,
                        hostname: form.hostname,
                        port: parsedPort,
                        os_type: form.os_type,
                        credential_id: form.credential_id === "" ? null : form.credential_id,
                        is_active: form.is_active,
                      },
                    })
                  }
                  disabled={!form.name || !form.hostname || !portValid || updateMutation.isPending}
                >
                  {t("hosts.saveChanges")}
                </Button>
                <Button variant="secondary" onClick={cancelEdit}>
                  {t("common.cancel")}
                </Button>
              </>
            ) : (
              <Button
                onClick={() =>
                  createMutation.mutate({
                    name: form.name,
                    hostname: form.hostname,
                    port: parsedPort,
                    os_type: form.os_type,
                    credential_id: form.credential_id === "" ? undefined : form.credential_id,
                    is_active: true,
                  })
                }
                disabled={!form.name || !form.hostname || !portValid || createMutation.isPending}
              >
                {t("hosts.addButton")}
              </Button>
            )}
            </div>
          </div>
          {(createMutation.isError || updateMutation.isError) && (
            <div className="pf-alert pf-alert--error">
              {((createMutation.error || updateMutation.error) as Error).message}
            </div>
          )}
        </div>
      </Panel>
      </div>
        </>
      ) : null}

      <Panel title={t("hosts.list")} noPadding>
        {hosts.isLoading ? (
          <Spinner />
        ) : hosts.isError ? (
          <QueryErrorState
            title={t("common.listLoadError")}
            message={hosts.error instanceof Error ? hosts.error.message : undefined}
            onRetry={() => hosts.refetch()}
          />
        ) : hostsTotal === 0 ? (
          <EmptyState title={t("hosts.empty")} description={t("hosts.emptyDesc")} />
        ) : (
          <>
            <div className="pf-filters">
              <div className="pf-filters__grid pf-filters__grid--hosts">
                <div className="pf-filters__group">
                  <label htmlFor="hosts-filter-search">{t("hosts.listSearchLabel")}</label>
                  <input
                    id="hosts-filter-search"
                    className="pf-input"
                    value={hostSearch}
                    onChange={(e) => setHostSearch(e.target.value)}
                    placeholder={t("hosts.listSearch")}
                  />
                </div>
                <div className="pf-filters__group">
                  <label htmlFor="hosts-filter-os">{t("hosts.listOsFilter")}</label>
                  <select
                    id="hosts-filter-os"
                    className="pf-select"
                    value={hostOsFilter}
                    onChange={(e) => setHostOsFilter(e.target.value)}
                  >
                    <option value="all">{t("hosts.listOsAll")}</option>
                    <option value="linux">{t("hosts.osLinux")}</option>
                    <option value="windows">{t("hosts.osWindows")}</option>
                    <option value="network">{t("hosts.osNetwork")}</option>
                  </select>
                </div>
                <div className="pf-filters__group">
                  <label htmlFor="hosts-filter-status">{t("hosts.listStatusFilter")}</label>
                  <select
                    id="hosts-filter-status"
                    className="pf-select"
                    value={hostStatusFilter}
                    onChange={(e) => setHostStatusFilter(e.target.value as HostStatusFilter)}
                  >
                    <option value="all">{t("hosts.listStatusAll")}</option>
                    <option value="active">{t("hosts.listStatusActive")}</option>
                    <option value="inactive">{t("hosts.listStatusInactive")}</option>
                  </select>
                </div>
                <div className="pf-filters__group">
                  <label htmlFor="hosts-filter-credential">{t("hosts.listCredentialFilter")}</label>
                  <select
                    id="hosts-filter-credential"
                    className="pf-select"
                    value={hostCredentialFilter}
                    onChange={(e) => setHostCredentialFilter(e.target.value as HostCredentialFilter)}
                  >
                    <option value="all">{t("hosts.listCredentialAll")}</option>
                    <option value="with">{t("hosts.listCredentialWith")}</option>
                    <option value="without">{t("hosts.listCredentialWithout")}</option>
                  </select>
                </div>
              </div>
              <div className="pf-filters__footer">
                <p className="pf-filters__summary">
                  {hasActiveHostFilters
                    ? t("profiles.filterResultsActive", {
                        count: filteredHostRows.length,
                        total: hostRows.length,
                      })
                    : t("profiles.filterShown", {
                        count: filteredHostRows.length,
                        total: hostRows.length,
                      })}
                  {hostsTotal > hostRows.length
                    ? ` · ${t("hosts.listLoadedCap", { loaded: hostRows.length, total: hostsTotal })}`
                    : null}
                </p>
                {hasActiveHostFilters ? (
                  <Button variant="secondary" className="pf-btn--sm" type="button" onClick={clearHostFilters}>
                    {t("profiles.clearFilters")}
                  </Button>
                ) : null}
              </div>
            </div>
            {filteredHostRows.length === 0 ? (
              <EmptyState title={t("jobs.noFilterResults")} description={t("jobs.noFilterResultsDesc")} />
            ) : (
              <>
            <div className="pf-table-wrap pf-hosts-table-wrap">
              <table className="pf-table pf-hosts-table">
                <thead>
                  <tr>
                    <SortableTh<HostSortKey>
                      label={t("hosts.name")}
                      sortKey="name"
                      activeKey={hostSort.key}
                      direction={hostSort.direction}
                      onSort={toggleHostSort}
                    />
                    <SortableTh<HostSortKey>
                      label={t("hosts.hostname")}
                      sortKey="hostname"
                      activeKey={hostSort.key}
                      direction={hostSort.direction}
                      onSort={toggleHostSort}
                    />
                    <SortableTh<HostSortKey>
                      label={t("hosts.port")}
                      sortKey="port"
                      activeKey={hostSort.key}
                      direction={hostSort.direction}
                      onSort={toggleHostSort}
                    />
                    <SortableTh<HostSortKey>
                      label={t("hosts.os")}
                      sortKey="os_type"
                      activeKey={hostSort.key}
                      direction={hostSort.direction}
                      onSort={toggleHostSort}
                    />
                    <th className="pf-hosts-table__credential">{t("hosts.credential")}</th>
                    <th>{t("hosts.sshFingerprint")}</th>
                    <SortableTh<HostSortKey>
                      label={t("common.status")}
                      sortKey="is_active"
                      activeKey={hostSort.key}
                      direction={hostSort.direction}
                      onSort={toggleHostSort}
                    />
                    {canSeeObjectOwners ? <th className="pf-hosts-table__owner">{t("objectRbac.owner")}</th> : null}
                    {canOperate ? <th className="pf-table__col-actions">{t("common.actions")}</th> : null}
                  </tr>
                </thead>
                <tbody>
                  {visibleHosts.map((host) => (
                    <tr
                      key={host.id}
                      className={editingId === host.id ? "pf-table__row--selected" : undefined}
                    >
                      <td>{host.name}</td>
                      <td className="pf-table__mono">{host.hostname}</td>
                      <td>{host.port}</td>
                      <td>
                        <Badge variant="info" literal>
                          {host.os_type ?? t("common.dash")}
                        </Badge>
                      </td>
                      <td className="pf-hosts-table__credential">
                        <HostCredentialPopover
                          host={host}
                          credentials={credentials.data ?? []}
                        />
                      </td>
                      <td className="pf-table__mono pf-host-fingerprint">
                        {host.ssh_host_key_fingerprint ? (
                          <span title={host.ssh_host_key_fingerprint}>
                            {host.ssh_host_key_fingerprint.slice(0, 20)}…
                          </span>
                        ) : (
                          t("common.dash")
                        )}
                      </td>
                      <td>
                        <Badge variant={host.is_active ? "success" : "danger"}>
                          {host.is_active ? t("common.active") : t("common.inactive")}
                        </Badge>
                      </td>
                      {canSeeObjectOwners ? (
                        <td className="pf-hosts-table__owner">
                          <ObjectOwnerCell ownerSub={host.owner_sub} />
                        </td>
                      ) : null}
                      {canOperate ? (
                      <td className="pf-table__col-actions">
                        <div className="pf-table__actions pf-host-row-actions">
                          <Button
                            variant="secondary"
                            className="pf-btn--sm"
                            onClick={() => scanFingerprintMutation.mutate(host.id)}
                            disabled={
                              scanFingerprintMutation.isPending ||
                              (host.os_type ?? "linux").toLowerCase() !== "linux"
                            }
                            title={
                              (host.os_type ?? "linux").toLowerCase() === "linux"
                                ? t("hosts.scanSshFingerprint")
                                : t("hosts.scanSshFingerprintLinuxOnly")
                            }
                          >
                            {t("hosts.scanSshFingerprint")}
                          </Button>
                          <Button
                            variant="secondary"
                            className="pf-btn--sm"
                            onClick={() => startEdit(host)}
                          >
                            {t("common.edit")}
                          </Button>
                          <Button
                            variant="danger-secondary"
                            className="pf-btn--sm"
                            onClick={() => handleDelete(host.id)}
                            disabled={deleteMutation.isPending}
                          >
                            {t("common.delete")}
                          </Button>
                        </div>
                      </td>
                      ) : null}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <OpsListExpandFooter
              shown={visibleHosts.length}
              total={filteredHostRows.length}
              expanded={hostListExpanded}
              onToggle={() => setHostListExpanded((value) => !value)}
            />
              </>
            )}
          </>
        )}
      </Panel>
    </>
  );
}
