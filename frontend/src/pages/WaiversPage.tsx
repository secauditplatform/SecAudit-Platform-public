import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, type ComplianceWaiver, type WaiverStatus } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { useConfirm } from "../components/ui/ConfirmDialog";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { Spinner } from "../components/ui/Spinner";
import { useToast } from "../components/ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";

const STATUS_OPTIONS: Array<WaiverStatus | "all"> = [
  "all",
  "pending",
  "approved",
  "rejected",
  "expired",
  "revoked",
];

type ExpiryFilter = "all" | "no_expiry" | "with_expiry" | "expired";

function statusVariant(status: WaiverStatus): "success" | "warning" | "danger" | "info" | "neutral" {
  switch (status) {
    case "approved":
      return "success";
    case "pending":
      return "warning";
    case "rejected":
    case "revoked":
    case "expired":
      return "danger";
    default:
      return "neutral";
  }
}

function isWaiverExpired(row: ComplianceWaiver): boolean {
  if (!row.expires_at) return false;
  return new Date(row.expires_at).getTime() < Date.now();
}

export function WaiversPage() {
  const { t, dateLocale } = useTranslation();
  const toast = useToast();
  const queryClient = useQueryClient();
  const { confirm } = useConfirm();
  const { isAdmin, canOperate, roles } = useAuth();
  const canApprove = isAdmin || roles.includes("operator");
  const canDelete = canOperate;
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<WaiverStatus | "all">("all");
  const [profileFilter, setProfileFilter] = useState("all");
  const [hostFilter, setHostFilter] = useState("all");
  const [expiryFilter, setExpiryFilter] = useState<ExpiryFilter>("all");
  const [rejectReasonById, setRejectReasonById] = useState<Record<number, string>>({});
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [bulkChangeTicket, setBulkChangeTicket] = useState("");
  const [bulkRejectReason, setBulkRejectReason] = useState("");

  const apiProfileId = profileFilter === "all" ? undefined : Number(profileFilter);
  const apiHostId =
    hostFilter === "all" || hostFilter === "global" || hostFilter === ""
      ? undefined
      : Number(hostFilter);

  const waivers = useQuery({
    queryKey: ["waivers", statusFilter, apiProfileId, apiHostId],
    queryFn: () =>
      api.waivers({
        status: statusFilter === "all" ? undefined : statusFilter,
        profile_id: apiProfileId,
        host_id: apiHostId,
      }),
  });

  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api.profiles() });
  const hosts = useQuery({ queryKey: ["hosts", "waivers-filter"], queryFn: () => api.hosts({ limit: 200 }) });

  const profileLabel = useMemo(() => {
    const map = new Map<number, string>();
    profiles.data?.forEach((profile) => map.set(profile.id, profile.profile_name));
    return map;
  }, [profiles.data]);

  const hostLabel = useMemo(() => {
    const map = new Map<number, string>();
    hosts.data?.items?.forEach((host) => map.set(host.id, host.name || host.hostname));
    return map;
  }, [hosts.data]);

  const hostOptions = useMemo(() => {
    const ids = new Set<number>();
    for (const row of waivers.data ?? []) {
      if (row.host_id != null) ids.add(row.host_id);
    }
    return [...ids]
      .sort((left, right) =>
        (hostLabel.get(left) ?? String(left)).localeCompare(hostLabel.get(right) ?? String(right))
      )
      .map((id) => ({ id, label: hostLabel.get(id) ?? `#${id}` }));
  }, [waivers.data, hostLabel]);

  const filteredRows = useMemo(() => {
    const query = search.trim().toLowerCase();
    return (waivers.data ?? []).filter((row) => {
      if (hostFilter === "global" && row.host_id != null) return false;
      if (expiryFilter === "no_expiry" && row.expires_at) return false;
      if (expiryFilter === "with_expiry" && !row.expires_at) return false;
      if (expiryFilter === "expired" && !isWaiverExpired(row)) return false;
      if (!query) return true;
      const profileName = profileLabel.get(row.profile_id) ?? "";
      const hostName = row.host_id != null ? hostLabel.get(row.host_id) ?? String(row.host_id) : "";
      const haystack = [
        row.rule_tech_name,
        row.reason,
        row.change_ticket ?? "",
        row.requested_by,
        row.approved_by ?? "",
        row.rejected_by ?? "",
        profileName,
        hostName,
        row.host_id != null ? String(row.host_id) : "",
      ]
        .join(" ")
        .toLowerCase();
      return haystack.includes(query);
    });
  }, [waivers.data, search, hostFilter, expiryFilter, profileLabel, hostLabel]);

  const pendingSelectable = useMemo(
    () => filteredRows.filter((row) => row.status === "pending" && row.is_active),
    [filteredRows]
  );

  const selectedPendingIds = useMemo(
    () => pendingSelectable.filter((row) => selectedIds.has(row.id)).map((row) => row.id),
    [pendingSelectable, selectedIds]
  );

  const allPendingSelected =
    pendingSelectable.length > 0 && pendingSelectable.every((row) => selectedIds.has(row.id));

  const hasActiveFilters =
    search.trim() !== "" ||
    statusFilter !== "all" ||
    profileFilter !== "all" ||
    hostFilter !== "all" ||
    expiryFilter !== "all";

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ["waivers"] });

  const clearSelection = () => setSelectedIds(new Set());

  const toggleRow = (id: number) => {
    setSelectedIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const toggleSelectAllPending = () => {
    if (allPendingSelected) {
      setSelectedIds((prev) => {
        const next = new Set(prev);
        for (const row of pendingSelectable) next.delete(row.id);
        return next;
      });
      return;
    }
    setSelectedIds((prev) => {
      const next = new Set(prev);
      for (const row of pendingSelectable) next.add(row.id);
      return next;
    });
  };

  const approveMutation = useMutation({
    mutationFn: ({ id, changeTicket }: { id: number; changeTicket?: string }) =>
      api.approveWaiver(id, changeTicket),
    onSuccess: () => {
      toast.success(t("waivers.approved"));
      invalidate();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const rejectMutation = useMutation({
    mutationFn: ({ id, reason }: { id: number; reason?: string }) => api.rejectWaiver(id, reason),
    onSuccess: () => {
      toast.success(t("waivers.rejected"));
      invalidate();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const revokeMutation = useMutation({
    mutationFn: api.revokeWaiver,
    onSuccess: () => {
      toast.success(t("waivers.revoked"));
      invalidate();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteWaiver,
    onSuccess: () => {
      toast.success(t("waivers.deleted"));
      invalidate();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const bulkApproveMutation = useMutation({
    mutationFn: ({ ids, changeTicket }: { ids: number[]; changeTicket?: string }) =>
      api.bulkApproveWaivers(ids, changeTicket),
    onSuccess: (result) => {
      const failed = result.failed.length;
      if (failed === 0) {
        toast.success(t("waivers.bulkApproved", { count: result.succeeded.length }));
      } else {
        toast.success(
          t("waivers.bulkApprovedPartial", {
            ok: result.succeeded.length,
            failed,
          })
        );
      }
      clearSelection();
      setBulkChangeTicket("");
      invalidate();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const bulkRejectMutation = useMutation({
    mutationFn: ({ ids, reason }: { ids: number[]; reason?: string }) =>
      api.bulkRejectWaivers(ids, reason),
    onSuccess: (result) => {
      const failed = result.failed.length;
      if (failed === 0) {
        toast.success(t("waivers.bulkRejected", { count: result.succeeded.length }));
      } else {
        toast.success(
          t("waivers.bulkRejectedPartial", {
            ok: result.succeeded.length,
            failed,
          })
        );
      }
      clearSelection();
      setBulkRejectReason("");
      invalidate();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const bulkPending =
    approveMutation.isPending ||
    rejectMutation.isPending ||
    bulkApproveMutation.isPending ||
    bulkRejectMutation.isPending;

  const clearFilters = () => {
    setSearch("");
    setStatusFilter("all");
    setProfileFilter("all");
    setHostFilter("all");
    setExpiryFilter("all");
  };

  const handleDelete = async (row: ComplianceWaiver) => {
    const ok = await confirm({
      title: t("waivers.deleteTitle"),
      message: t("waivers.deleteConfirm", { rule: row.rule_tech_name }),
      variant: "danger",
      confirmLabel: t("common.delete"),
    });
    if (!ok) return;
    deleteMutation.mutate(row.id);
  };

  const handleBulkApprove = async () => {
    if (selectedPendingIds.length === 0) return;
    const ticket = bulkChangeTicket.trim();
    const ok = await confirm({
      title: t("waivers.bulkApproveTitle"),
      message: ticket
        ? t("waivers.bulkApproveConfirmTicket", {
            count: selectedPendingIds.length,
            ticket,
          })
        : t("waivers.bulkApproveConfirm", { count: selectedPendingIds.length }),
      confirmLabel: t("waivers.bulkApprove"),
    });
    if (!ok) return;
    bulkApproveMutation.mutate({
      ids: selectedPendingIds,
      changeTicket: ticket || undefined,
    });
  };

  const handleBulkReject = async () => {
    if (selectedPendingIds.length === 0) return;
    const ok = await confirm({
      title: t("waivers.bulkRejectTitle"),
      message: t("waivers.bulkRejectConfirm", { count: selectedPendingIds.length }),
      variant: "danger",
      confirmLabel: t("waivers.bulkReject"),
    });
    if (!ok) return;
    bulkRejectMutation.mutate({
      ids: selectedPendingIds,
      reason: bulkRejectReason.trim() || undefined,
    });
  };

  const totalRows = waivers.data?.length ?? 0;

  return (
    <>
      <PageHeader title={t("waivers.title")} description={t("waivers.description")} />

      <Panel title={t("waivers.list")} noPadding>
        <div className="pf-filters">
          <div className="pf-filters__grid pf-filters__grid--waivers">
            <div className="pf-filters__group">
              <label htmlFor="waivers-filter-search">{t("waivers.listSearchLabel")}</label>
              <input
                id="waivers-filter-search"
                className="pf-input"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder={t("waivers.listSearch")}
              />
            </div>
            <div className="pf-filters__group">
              <label htmlFor="waivers-filter-profile">{t("waivers.profile")}</label>
              <select
                id="waivers-filter-profile"
                className="pf-select"
                value={profileFilter}
                onChange={(e) => setProfileFilter(e.target.value)}
              >
                <option value="all">{t("reports.allProfiles")}</option>
                {(profiles.data ?? []).map((profile) => (
                  <option key={profile.id} value={String(profile.id)}>
                    {profile.profile_name}
                  </option>
                ))}
              </select>
            </div>
            <div className="pf-filters__group">
              <label htmlFor="waivers-filter-host">{t("waivers.listHostFilter")}</label>
              <select
                id="waivers-filter-host"
                className="pf-select"
                value={hostFilter}
                onChange={(e) => setHostFilter(e.target.value)}
              >
                <option value="all">{t("waivers.listHostAll")}</option>
                <option value="global">{t("waivers.listHostGlobal")}</option>
                {hostOptions.map((host) => (
                  <option key={host.id} value={String(host.id)}>
                    {host.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="pf-filters__group">
              <label htmlFor="waivers-filter-status">{t("common.status")}</label>
              <select
                id="waivers-filter-status"
                className="pf-select"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value as WaiverStatus | "all")}
              >
                {STATUS_OPTIONS.map((status) => (
                  <option key={status} value={status}>
                    {status === "all" ? t("waivers.allStatuses") : t(`waivers.status.${status}`)}
                  </option>
                ))}
              </select>
            </div>
            <div className="pf-filters__group">
              <label htmlFor="waivers-filter-expiry">{t("waivers.listExpiryFilter")}</label>
              <select
                id="waivers-filter-expiry"
                className="pf-select"
                value={expiryFilter}
                onChange={(e) => setExpiryFilter(e.target.value as ExpiryFilter)}
              >
                <option value="all">{t("waivers.listExpiryAll")}</option>
                <option value="no_expiry">{t("waivers.noExpiry")}</option>
                <option value="with_expiry">{t("waivers.listExpirySet")}</option>
                <option value="expired">{t("waivers.listExpiryExpired")}</option>
              </select>
            </div>
          </div>
          <div className="pf-filters__footer">
            <p className="pf-filters__summary">
              {hasActiveFilters
                ? t("profiles.filterResultsActive", {
                    count: filteredRows.length,
                    total: totalRows,
                  })
                : t("profiles.filterShown", {
                    count: filteredRows.length,
                    total: totalRows,
                  })}
            </p>
            {hasActiveFilters ? (
              <Button variant="secondary" className="pf-btn--sm" type="button" onClick={clearFilters}>
                {t("profiles.clearFilters")}
              </Button>
            ) : null}
          </div>
        </div>

        {canApprove && pendingSelectable.length > 0 ? (
          <div className="pf-waivers-bulk">
            <div className="pf-waivers-bulk__start">
              <Button
                variant="secondary"
                className="pf-btn--sm"
                type="button"
                disabled={bulkPending}
                onClick={toggleSelectAllPending}
              >
                {allPendingSelected ? t("waivers.clearSelection") : t("waivers.selectAllPending")}
              </Button>
              <span className="pf-waivers-bulk__meta">
                {t("waivers.selectedPending", { count: selectedPendingIds.length })}
              </span>
            </div>
            <div className="pf-waivers-bulk__fields">
              <input
                className="pf-input"
                value={bulkChangeTicket}
                onChange={(e) => setBulkChangeTicket(e.target.value)}
                placeholder={t("waivers.changeTicketPlaceholder")}
                aria-label={t("waivers.changeTicket")}
                disabled={bulkPending || selectedPendingIds.length === 0}
              />
              <input
                className="pf-input"
                value={bulkRejectReason}
                onChange={(e) => setBulkRejectReason(e.target.value)}
                placeholder={t("waivers.rejectReason")}
                aria-label={t("waivers.rejectReason")}
                disabled={bulkPending || selectedPendingIds.length === 0}
              />
            </div>
            <div className="pf-waivers-bulk__actions">
              <Button
                variant="secondary"
                className="pf-btn--sm"
                type="button"
                disabled={bulkPending || selectedPendingIds.length === 0}
                onClick={() => void handleBulkApprove()}
              >
                {t("waivers.bulkApprove")}
              </Button>
              <Button
                variant="danger-secondary"
                className="pf-btn--sm"
                type="button"
                disabled={bulkPending || selectedPendingIds.length === 0}
                onClick={() => void handleBulkReject()}
              >
                {t("waivers.bulkReject")}
              </Button>
            </div>
          </div>
        ) : null}

        {waivers.isLoading ? (
          <Spinner />
        ) : totalRows === 0 ? (
          <EmptyState title={t("waivers.empty")} description={t("waivers.emptyDesc")} />
        ) : filteredRows.length === 0 ? (
          <EmptyState title={t("jobs.noFilterResults")} description={t("jobs.noFilterResultsDesc")} />
        ) : (
          <div className="pf-table-wrap">
            <table className="pf-table">
              <thead>
                <tr>
                  {canApprove ? (
                    <th className="pf-table__check" scope="col" aria-label={t("waivers.selectColumn")} />
                  ) : null}
                  <th>{t("waivers.rule")}</th>
                  <th>{t("waivers.profile")}</th>
                  <th>{t("reports.hostId")}</th>
                  <th>{t("common.status")}</th>
                  <th>{t("waivers.requestedBy")}</th>
                  <th>{t("waivers.changeTicket")}</th>
                  <th>{t("waivers.expires")}</th>
                  <th>{t("waivers.reason")}</th>
                  <th className="pf-table__col-actions">{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {filteredRows.map((row: ComplianceWaiver) => {
                  const isPending = row.status === "pending" && row.is_active;
                  return (
                    <tr key={row.id}>
                      {canApprove ? (
                        <td className="pf-table__check">
                          {isPending ? (
                            <input
                              type="checkbox"
                              className="pf-checkbox-control"
                              checked={selectedIds.has(row.id)}
                              disabled={bulkPending}
                              onChange={() => toggleRow(row.id)}
                              aria-label={t("waivers.selectRow", { rule: row.rule_tech_name })}
                            />
                          ) : null}
                        </td>
                      ) : null}
                      <td className="pf-table__mono">{row.rule_tech_name}</td>
                      <td>{profileLabel.get(row.profile_id) ?? `#${row.profile_id}`}</td>
                      <td className="pf-table__mono">
                        {row.host_id != null
                          ? hostLabel.get(row.host_id) ?? row.host_id
                          : t("waivers.allHosts")}
                      </td>
                      <td>
                        <Badge variant={statusVariant(row.status)}>
                          {t(`waivers.status.${row.status}`)}
                        </Badge>
                      </td>
                      <td>{row.requested_by}</td>
                      <td className="pf-table__mono">{row.change_ticket || t("common.dash")}</td>
                      <td>
                        {row.expires_at
                          ? new Date(row.expires_at).toLocaleString(dateLocale)
                          : t("waivers.noExpiry")}
                      </td>
                      <td>{row.reason}</td>
                      <td className="pf-table__col-actions">
                        <div className="pf-table__actions pf-table__actions--allow-wrap">
                          {canApprove && isPending && (
                            <>
                              <Button
                                variant="secondary"
                                className="pf-btn--sm"
                                onClick={() =>
                                  approveMutation.mutate({
                                    id: row.id,
                                    changeTicket: bulkChangeTicket.trim() || undefined,
                                  })
                                }
                                disabled={bulkPending}
                              >
                                {t("waivers.approve")}
                              </Button>
                              <input
                                className="pf-input"
                                style={{ width: "8rem" }}
                                placeholder={t("waivers.rejectReason")}
                                value={rejectReasonById[row.id] ?? ""}
                                onChange={(e) =>
                                  setRejectReasonById((prev) => ({
                                    ...prev,
                                    [row.id]: e.target.value,
                                  }))
                                }
                              />
                              <Button
                                variant="danger-secondary"
                                className="pf-btn--sm"
                                onClick={() =>
                                  rejectMutation.mutate({
                                    id: row.id,
                                    reason: rejectReasonById[row.id]?.trim() || undefined,
                                  })
                                }
                                disabled={bulkPending}
                              >
                                {t("waivers.reject")}
                              </Button>
                            </>
                          )}
                          {canApprove && row.status === "approved" && row.is_active && (
                            <Button
                              variant="danger-secondary"
                              className="pf-btn--sm"
                              onClick={() => revokeMutation.mutate(row.id)}
                              disabled={revokeMutation.isPending}
                            >
                              {t("waivers.revoke")}
                            </Button>
                          )}
                          {canDelete ? (
                            <Button
                              variant="danger-secondary"
                              className="pf-btn--sm"
                              onClick={() => void handleDelete(row)}
                              disabled={deleteMutation.isPending}
                            >
                              {t("common.delete")}
                            </Button>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>
    </>
  );
}
