import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type DiffRow, type DriftChange, type CheckResult, type JobRun } from "../api/client";
import { ScheduledReportsPanel } from "../components/ScheduledReportsPanel";
import { ReportsRunsPanel } from "../components/ReportsRunsPanel";
import { RemediationWorkflowPanel } from "../components/RemediationWorkflowPanel";
import { CheckDistributionInsight, ComplianceSummaryInsight } from "../components/InsightSummary";
import {
  findProfileRule,
  hasProfileRuleMetadata,
  ProfileRuleMetadata,
} from "../components/ProfileRuleDetail";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { EmptyState } from "../components/ui/EmptyState";
import { IconCheck } from "../components/ui/Icons";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { SortableTh } from "../components/ui/SortableTh";
import { Spinner } from "../components/ui/Spinner";
import { useToast } from "../components/ui/Toast";
import { useAuth } from "../auth/AuthProvider";
import { useTranslation } from "../i18n/I18nProvider";
import { useConfirm } from "../components/ui/ConfirmDialog";
import { useTableSort } from "../hooks/useTableSort";

import { checkStatusVariant, driftChangeVariant, severityVariant } from "../utils/statusVariant";
import { findCheckResultHostId, parseRunId } from "../utils/reportDeepLink";

function defaultBaselineRunId(
  jobRuns: JobRun[],
  currentRunId: number,
  jobBaselineRunId: number | null | undefined
): number | null {
  const completed = jobRuns
    .filter((run) => run.status === "completed" && run.id !== currentRunId)
    .sort((a, b) => (b.finished_at ?? "").localeCompare(a.finished_at ?? ""));

  if (jobBaselineRunId != null && jobBaselineRunId !== currentRunId) {
    return jobBaselineRunId;
  }
  return completed[0]?.id ?? null;
}

const DRIFT_CHANGE_KEYS: DriftChange[] = ["improved", "regressed", "unchanged", "new", "removed"];

type CheckSortKey = "host" | "rule" | "severity" | "status" | "message";

function runStatusLabel(t: (key: string) => string, status: string): string {
  const key = `runStatus.${status}` as const;
  const translated = t(key);
  return translated === key ? status : translated;
}

function formatRunDuration(startedAt?: string, finishedAt?: string): string | null {
  if (!startedAt || !finishedAt) return null;
  const ms = new Date(finishedAt).getTime() - new Date(startedAt).getTime();
  if (!Number.isFinite(ms) || ms < 0) return null;
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return rest > 0 ? `${minutes}m ${rest}s` : `${minutes}m`;
}

export function ReportsPage() {
  const { t, locale, dateLocale } = useTranslation();
  const { canOperate, canAccessRemediation } = useAuth();
  const canManageScheduledReports = canOperate;
  const { prompt } = useConfirm();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const reportPanelRef = useRef<HTMLDivElement>(null);
  const checkDetailsRef = useRef<HTMLDivElement>(null);
  const [checkHostFilter, setCheckHostFilter] = useState("all");
  const [checkRuleFilter, setCheckRuleFilter] = useState("");
  const [checkStatusFilter, setCheckStatusFilter] = useState("all");
  const [checkSeverityFilter, setCheckSeverityFilter] = useState("all");
  const [checkMessageFilter, setCheckMessageFilter] = useState("");
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState<"html" | "pdf" | "csv" | null>(null);
  const [expandedCheckId, setExpandedCheckId] = useState<number | null>(null);
  const [compareBaselineRunId, setCompareBaselineRunId] = useState<number | null>(null);
  const [driftChangeFilter, setDriftChangeFilter] = useState("all");
  const [driftHostFilter, setDriftHostFilter] = useState("all");
  const [driftRuleFilter, setDriftRuleFilter] = useState("");
  const [multiCompareIds, setMultiCompareIds] = useState<number[]>([]);
  const [multiCompareActive, setMultiCompareActive] = useState(false);
  const [multiCompareSeverityFilter, setMultiCompareSeverityFilter] = useState("all");
  const [multiCompareRuleFilter, setMultiCompareRuleFilter] = useState("");

  const urlRunId = parseRunId(searchParams.get("run"));
  const urlHost = (searchParams.get("host") || "").trim();
  const urlHostId = (searchParams.get("host_id") || "").trim();
  const urlFocusChecks = searchParams.get("focus") === "checks";
  const [selectedRunId, setSelectedRunId] = useState<number | null>(urlRunId);

  const runs = useQuery({
    queryKey: ["job-runs", "reports-detail", 200],
    queryFn: () => api.jobRuns({ offset: 0, limit: 200 }),
    refetchInterval: 15000,
  });
  const jobs = useQuery({ queryKey: ["jobs"], queryFn: () => api.jobs() });
  const hosts = useQuery({
    queryKey: ["hosts", "reports-labels"],
    queryFn: () => api.hosts({ offset: 0, limit: 500 }),
  });

  const jobNameById = useMemo(() => {
    const map = new Map<number, string>();
    jobs.data?.forEach((j) => map.set(j.id, j.name));
    return map;
  }, [jobs.data]);

  const runsTotal = runs.data?.total ?? runs.data?.items?.length ?? 0;

  useEffect(() => {
    if (urlRunId != null) {
      setSelectedRunId(urlRunId);
    }
  }, [urlRunId]);

  const activeRunId = selectedRunId;

  const selectRun = (runId: number) => {
    setSelectedRunId(runId);
    setSearchParams({ run: String(runId) }, { replace: true });
    requestAnimationFrame(() => {
      reportPanelRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };

  const summary = useQuery({
    queryKey: ["summary", activeRunId],
    queryFn: () => api.runSummary(activeRunId!),
    enabled: activeRunId !== null,
  });

  const detail = useQuery({
    queryKey: ["run-detail", activeRunId],
    queryFn: () => api.getJobRun(activeRunId!),
    enabled: activeRunId !== null,
  });

  const hostLabelById = useMemo(() => {
    const map = new Map<number, string>();
    hosts.data?.items?.forEach((host) => {
      const label = (host.name || host.hostname || "").trim();
      if (label) map.set(host.id, label);
    });
    detail.data?.check_results?.forEach((row) => {
      const label = row.host_name?.trim();
      if (label) map.set(row.host_id, label);
    });
    return map;
  }, [hosts.data, detail.data]);

  const hostLabel = (hostId: number) => hostLabelById.get(hostId) ?? `#${hostId}`;

  const deleteRunMutation = useMutation({
    mutationFn: api.deleteJobRun,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["job-runs"] });
      setSelectedRunId(null);
      setSearchParams({}, { replace: true });
      toast.success(t("toast.jobRunDeleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const handleDeleteRun = (run: JobRun) => {
    if (run.status === "pending" || run.status === "running") {
      toast.error(t("reports.stopFirst"));
      return;
    }
    deleteRunMutation.mutate(run.id);
  };

  const handleDownload = async (format: "html" | "pdf" | "csv") => {
    if (activeRunId == null) return;
    setDownloadError(null);
    setDownloading(format);
    try {
      if (format === "html") {
        await api.downloadReportHtml(activeRunId, locale);
      } else if (format === "pdf") {
        await api.downloadReportPdf(activeRunId, locale);
      } else {
        await api.downloadReportCsv(activeRunId, {
          status: checkStatusFilter !== "all" ? checkStatusFilter : undefined,
          severity: checkSeverityFilter !== "all" ? checkSeverityFilter : undefined,
          host_id: checkHostFilter !== "all" ? checkHostFilter : undefined,
          rule: checkRuleFilter.trim() || undefined,
        });
      }
    } catch (err) {
      setDownloadError(err instanceof Error ? err.message : t("reports.downloadError"));
    } finally {
      setDownloading(null);
    }
  };

  const selectedRun =
    runs.data?.items?.find((run) => run.id === activeRunId) ??
    (detail.data && detail.data.id === activeRunId ? detail.data : undefined);
  const selectedJobName = selectedRun
    ? (jobNameById.get(selectedRun.job_id) ?? `Job #${selectedRun.job_id}`)
    : null;

  const sameJobRuns = useMemo(() => {
    if (!selectedRun || !runs.data?.items) return [];
    return runs.data.items.filter((run) => run.job_id === selectedRun.job_id);
  }, [selectedRun, runs.data]);

  const completedSameJobRuns = useMemo(
    () =>
      sameJobRuns
        .filter((run) => run.status === "completed" && run.id !== activeRunId)
        .sort((a, b) => (b.finished_at ?? "").localeCompare(a.finished_at ?? "")),
    [sameJobRuns, activeRunId]
  );

  const jobBaseline = useQuery({
    queryKey: ["job-baseline", selectedRun?.job_id],
    queryFn: () => api.getJobBaseline(selectedRun!.job_id),
    enabled: selectedRun != null,
  });

  useEffect(() => {
    if (activeRunId == null) {
      setCompareBaselineRunId(null);
      return;
    }
    setCompareBaselineRunId(
      defaultBaselineRunId(sameJobRuns, activeRunId, jobBaseline.data?.baseline_run_id)
    );
    setDriftChangeFilter("all");
    setDriftHostFilter("all");
    setDriftRuleFilter("");
  }, [activeRunId, sameJobRuns, jobBaseline.data?.baseline_run_id]);

  const drift = useQuery({
    queryKey: ["run-diff", compareBaselineRunId, activeRunId],
    queryFn: () => api.getRunsDiff(compareBaselineRunId!, activeRunId!),
    enabled: activeRunId != null && compareBaselineRunId != null && activeRunId !== compareBaselineRunId,
  });

  const setBaselineMutation = useMutation({
    mutationFn: (runId: number) => api.setJobBaseline(selectedRun!.job_id, runId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["job-baseline", selectedRun?.job_id] });
      toast.success(t("reports.baselineSet"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const selectedJob = useMemo(() => {
    if (!selectedRun || !jobs.data) return null;
    return jobs.data.find((job) => job.id === selectedRun.job_id) ?? null;
  }, [selectedRun, jobs.data]);

  const profileId = selectedJob?.profile_id ?? null;

  const profileRules = useQuery({
    queryKey: ["profile-rules", profileId],
    queryFn: () => api.getProfileRules(profileId!),
    enabled: profileId != null && activeRunId != null,
  });

  useEffect(() => {
    setExpandedCheckId(null);
    if (!urlHost && !urlHostId) {
      setCheckHostFilter("all");
    }
    setCheckRuleFilter("");
    setCheckStatusFilter("all");
    setCheckSeverityFilter("all");
    setCheckMessageFilter("");
    setMultiCompareIds(activeRunId != null ? [activeRunId] : []);
    setMultiCompareActive(false);
    setMultiCompareSeverityFilter("all");
    setMultiCompareRuleFilter("");
  }, [activeRunId, urlHost, urlHostId]);

  useEffect(() => {
    if (!urlHost && !urlHostId) return;
    if (!detail.data?.check_results?.length) return;
    const matchedHostId = findCheckResultHostId(detail.data.check_results, hostLabelById, {
      hostId: urlHostId,
      host: urlHost,
    });
    if (matchedHostId != null) {
      setCheckHostFilter(String(matchedHostId));
    }
  }, [urlHost, urlHostId, detail.data, hostLabelById]);

  useEffect(() => {
    if (urlRunId == null || activeRunId !== urlRunId) return;
    if (urlFocusChecks) {
      if (!detail.data?.check_results?.length) return;
      const target = checkDetailsRef.current;
      if (!target) return;
      requestAnimationFrame(() => {
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      });
      return;
    }
    const target = reportPanelRef.current;
    if (!target) return;
    requestAnimationFrame(() => {
      target.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, [urlRunId, activeRunId, urlFocusChecks, detail.data, checkHostFilter]);

  const toggleCheckDetails = (checkId: number) => {
    setExpandedCheckId((current) => (current === checkId ? null : checkId));
  };

  const ruleLabels = useMemo(
    () => ({
      description: t("profiles.ruleDescription"),
      risk: t("profiles.ruleRisk"),
      location: t("profiles.ruleLocation"),
      scapRuleId: t("profiles.scapRuleId"),
    }),
    [t]
  );

  const checkHostOptions = useMemo(() => {
    if (!detail.data) return [];
    return [...new Set(detail.data.check_results.map((row) => row.host_id))]
      .sort((a, b) => hostLabel(a).localeCompare(hostLabel(b), undefined, { sensitivity: "base" }));
  }, [detail.data, hostLabelById]);

  const checkStatusOptions = useMemo(() => {
    if (!detail.data) return [];
    return [...new Set(detail.data.check_results.map((row) => row.status.toLowerCase()))].sort();
  }, [detail.data]);

  const checkSeverityOf = (ruleTechName: string): string => {
    const rule = findProfileRule(profileRules.data, ruleTechName);
    return (rule?.criticality || rule?.impact || "unknown").trim().toLowerCase();
  };

  const filteredCheckResults = useMemo(() => {
    if (!detail.data) return [];
    const ruleQuery = checkRuleFilter.trim().toLowerCase();
    const messageQuery = checkMessageFilter.trim().toLowerCase();

    return detail.data.check_results.filter((row) => {
      if (checkHostFilter !== "all" && String(row.host_id) !== checkHostFilter) return false;
      if (ruleQuery && !row.rule_tech_name.toLowerCase().includes(ruleQuery)) return false;
      if (checkStatusFilter !== "all" && row.status.toLowerCase() !== checkStatusFilter) return false;
      if (checkSeverityFilter !== "all" && checkSeverityOf(row.rule_tech_name) !== checkSeverityFilter.toLowerCase()) {
        return false;
      }
      if (messageQuery && !(row.message ?? "").toLowerCase().includes(messageQuery)) return false;
      return true;
    });
  }, [
    detail.data,
    checkHostFilter,
    checkRuleFilter,
    checkStatusFilter,
    checkSeverityFilter,
    checkMessageFilter,
    profileRules.data,
  ]);

  const checkSortAccessor = useCallback(
    (row: CheckResult, key: CheckSortKey) => {
      if (key === "host") return hostLabel(row.host_id);
      if (key === "rule") return row.rule_tech_name;
      if (key === "severity") return checkSeverityOf(row.rule_tech_name);
      if (key === "status") return row.status.toLowerCase();
      return row.message ?? "";
    },
    [hostLabelById, profileRules.data]
  );

  const {
    sortedRows: sortedCheckResults,
    sort: checkSort,
    toggleSort: toggleCheckSort,
  } = useTableSort<CheckResult, CheckSortKey>(
    filteredCheckResults,
    { key: "host", direction: "asc" },
    checkSortAccessor
  );

  const severityOptions = useMemo(() => {
    if (!detail.data) return [];
    const set = new Set<string>();
    for (const row of detail.data.check_results) {
      const sev = checkSeverityOf(row.rule_tech_name);
      if (sev) set.add(sev);
    }
    return Array.from(set).sort();
  }, [detail.data, profileRules.data]);

  const hasActiveCheckFilters =
    checkHostFilter !== "all" ||
    checkRuleFilter.trim() !== "" ||
    checkStatusFilter !== "all" ||
    checkSeverityFilter !== "all" ||
    checkMessageFilter.trim() !== "";

  const clearCheckFilters = () => {
    setCheckHostFilter("all");
    setCheckRuleFilter("");
    setCheckStatusFilter("all");
    setCheckSeverityFilter("all");
    setCheckMessageFilter("");
  };

  const multiCompareCandidates = useMemo(
    () =>
      sameJobRuns
        .filter((run) => run.status === "completed")
        .sort((a, b) => (b.finished_at ?? "").localeCompare(a.finished_at ?? "")),
    [sameJobRuns]
  );

  const multiCompareQuery = useQuery({
    queryKey: ["runs-compare", [...multiCompareIds].sort((a, b) => a - b).join(",")],
    queryFn: () => api.getRunsCompare(multiCompareIds),
    enabled: multiCompareActive && multiCompareIds.length >= 2 && multiCompareIds.length <= 8,
    retry: false,
  });

  const filteredMultiRows = useMemo(() => {
    const rows = multiCompareQuery.data?.rows ?? [];
    const ruleQuery = multiCompareRuleFilter.trim().toLowerCase();
    return rows.filter((row) => {
      if (
        multiCompareSeverityFilter !== "all" &&
        (row.severity || "unknown").toLowerCase() !== multiCompareSeverityFilter.toLowerCase()
      ) {
        return false;
      }
      if (ruleQuery && !row.rule_tech_name.toLowerCase().includes(ruleQuery)) return false;
      return true;
    });
  }, [multiCompareQuery.data, multiCompareSeverityFilter, multiCompareRuleFilter]);

  const toggleMultiCompareId = (runId: number) => {
    setMultiCompareIds((prev) => {
      if (prev.includes(runId)) return prev.filter((id) => id !== runId);
      if (prev.length >= 8) return prev;
      return [...prev, runId];
    });
  };

  useEffect(() => {
    setMultiCompareActive(multiCompareIds.length >= 2 && multiCompareIds.length <= 8);
  }, [multiCompareIds]);

  const handleMultiCompareCsv = async () => {
    if (multiCompareIds.length < 2) return;
    setDownloadError(null);
    try {
      await api.downloadRunsCompareCsv(multiCompareIds);
    } catch (err) {
      setDownloadError(err instanceof Error ? err.message : t("reports.downloadError"));
    }
  };

  const multiCompareCanExport = multiCompareIds.length >= 2;
  const multiSelectedLabel = t("reports.multiCompareSelected", {
    count: multiCompareIds.length,
    max: 8,
  });
  const multiCompareHasActiveFilters =
    multiCompareSeverityFilter !== "all" || multiCompareRuleFilter.trim() !== "";

  const clearMultiCompareFilters = () => {
    setMultiCompareSeverityFilter("all");
    setMultiCompareRuleFilter("");
  };

  const driftHostOptions = useMemo(() => {
    if (!drift.data) return [];
    return [...new Set(drift.data.items.map((row) => row.host_id))].sort((a, b) => a - b);
  }, [drift.data]);

  const filteredDriftItems = useMemo((): DiffRow[] => {
    if (!drift.data) return [];
    const ruleQuery = driftRuleFilter.trim().toLowerCase();
    return drift.data.items.filter((row) => {
      if (driftChangeFilter !== "all" && row.change !== driftChangeFilter) return false;
      if (driftHostFilter !== "all" && String(row.host_id) !== driftHostFilter) return false;
      if (ruleQuery && !row.rule_tech_name.toLowerCase().includes(ruleQuery)) return false;
      return true;
    });
  }, [drift.data, driftChangeFilter, driftHostFilter, driftRuleFilter]);

  const hasActiveDriftFilters =
    driftChangeFilter !== "all" || driftHostFilter !== "all" || driftRuleFilter.trim() !== "";

  const clearDriftFilters = () => {
    setDriftChangeFilter("all");
    setDriftHostFilter("all");
    setDriftRuleFilter("");
  };

  const handleDriftCardClick = (change: DriftChange) => {
    setDriftChangeFilter((current) => (current === change ? "all" : change));
    document.getElementById("drift-table")?.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const showDriftSection =
    activeRunId != null && compareBaselineRunId != null && activeRunId !== compareBaselineRunId;

  return (
    <>
      <PageHeader title={t("reports.title")} description={t("reports.description")} />

      {(canManageScheduledReports || canOperate) && (
        <Panel title={t("scheduledReports.title")} description={t("scheduledReports.description")} noPadding>
          <ScheduledReportsPanel canManage={canManageScheduledReports} />
        </Panel>
      )}

      <Panel title={t("reports.runs")} noPadding>
        <ReportsRunsPanel
          selectedRunId={activeRunId}
          onSelectComplianceRun={selectRun}
          onDeleteComplianceRun={handleDeleteRun}
          canOperate={canOperate}
          canAccessRemediation={canAccessRemediation}
          deletePending={deleteRunMutation.isPending}
        />
      </Panel>

      {!activeRunId && runsTotal > 0 && (
        <Panel title={t("reports.report")}>
          <EmptyState title={t("reports.selectRun")} description={t("reports.selectRunDesc")} />
        </Panel>
      )}

      {activeRunId && (
        <div ref={reportPanelRef}>
          <Panel
            title={t("reports.reportForRun", { id: activeRunId })}
            toolbar={
              <div className="pf-report-toolbar">
                <Button variant="secondary" className="pf-btn--sm" onClick={() => handleDownload("html")} disabled={downloading !== null}>
                  {downloading === "html" ? t("reports.downloading") : t("reports.downloadHtml")}
                </Button>
                <Button variant="secondary" className="pf-btn--sm" onClick={() => handleDownload("pdf")} disabled={downloading !== null}>
                  {downloading === "pdf" ? t("reports.downloading") : t("reports.downloadPdf")}
                </Button>
                <Button variant="secondary" className="pf-btn--sm" onClick={() => handleDownload("csv")} disabled={downloading !== null}>
                  {downloading === "csv" ? t("reports.downloading") : t("reports.downloadCsv")}
                </Button>
                {canOperate && selectedRun?.status === "completed" && (
                  <Button
                    variant="secondary"
                    className="pf-btn--sm"
                    onClick={() => setBaselineMutation.mutate(activeRunId)}
                    disabled={setBaselineMutation.isPending}
                  >
                    {t("reports.setAsBaseline")}
                  </Button>
                )}
              </div>
            }
          >
            {selectedRun && (
              <div className="pf-report-run-meta">
                <div className="pf-report-run-meta__main">
                  <span className="pf-insight-compliance__meta-label">{t("reports.jobLabel")}</span>
                  <div className="pf-report-run-meta__row">
                    <span className="pf-report-run-meta__job">{selectedJobName}</span>
                    <Badge variant={checkStatusVariant(selectedRun.status)}>
                      {runStatusLabel(t, selectedRun.status)}
                    </Badge>
                  </div>
                  <p className="pf-report-run-meta__times">
                    {t("reports.started")}:{" "}
                    {selectedRun.started_at
                      ? new Date(selectedRun.started_at).toLocaleString(dateLocale)
                      : t("common.dash")}
                    {" · "}
                    {t("reports.finished")}:{" "}
                    {selectedRun.finished_at
                      ? new Date(selectedRun.finished_at).toLocaleString(dateLocale)
                      : t("common.dash")}
                  </p>
                </div>
              </div>
            )}

            {downloadError && <div className="pf-alert pf-alert--error">{downloadError}</div>}

            {selectedRun?.error_message && (
              <div className="pf-alert pf-alert--warning">{selectedRun.error_message}</div>
            )}

            {summary.isLoading && (
              <div className="pf-dashboard-empty pf-dashboard-empty--centered">
                <Spinner />
              </div>
            )}
            {summary.isError && <div className="pf-alert pf-alert--error">{t("reports.summaryError")}</div>}
          </Panel>

          {summary.data && (
            <div className="pf-dashboard-grid pf-dashboard-grid--insights pf-report-insight-grid">
              <Panel title={t("dashboard.compliance")} className="pf-dashboard-panel pf-dashboard-panel--insight">
                <ComplianceSummaryInsight
                  summary={summary.data}
                  complianceLevelLabel={t("dashboard.complianceLevel")}
                  metaLabel={t("reports.report")}
                  runId={activeRunId}
                  jobName={selectedJobName}
                  totalChecksLabel={t("dashboard.totalChecks", { count: summary.data.total_checks })}
                />
              </Panel>

              <Panel title={t("reports.checkDistribution")} className="pf-dashboard-panel pf-dashboard-panel--insight">
                <CheckDistributionInsight
                  summary={summary.data}
                  totalLabel={t("reports.totalChecks")}
                  barAriaLabel={t("reports.checkDistribution")}
                />
              </Panel>
            </div>
          )}

          {canAccessRemediation && selectedRun && activeRunId != null ? (
            <RemediationWorkflowPanel
              runId={activeRunId}
              jobId={selectedRun.job_id}
              runStatus={selectedRun.status}
              canOperate={canAccessRemediation}
              onReauditComplete={(reauditRunId) => {
                if (activeRunId != null) {
                  setCompareBaselineRunId(activeRunId);
                }
                setSelectedRunId(reauditRunId);
                setSearchParams({ run: String(reauditRunId) });
              }}
            />
          ) : null}
        </div>
      )}

      {showDriftSection && (
        <Panel
          title={t("reports.driftTitle")}
          toolbar={
            <div className="pf-report-toolbar">
              <label className="pf-drift-baseline-picker" htmlFor="drift-baseline-select">
                <span className="pf-drift-baseline-picker__label">{t("reports.compareTo")}</span>
                <select
                  id="drift-baseline-select"
                  className="pf-select"
                  value={compareBaselineRunId ?? ""}
                  onChange={(event) => setCompareBaselineRunId(Number(event.target.value))}
                >
                  {jobBaseline.data?.baseline_run_id != null &&
                    jobBaseline.data.baseline_run_id !== activeRunId && (
                      <option value={jobBaseline.data.baseline_run_id}>
                        {t("reports.jobBaseline", { id: jobBaseline.data.baseline_run_id })}
                      </option>
                    )}
                  {completedSameJobRuns.map((run) => (
                    <option key={run.id} value={run.id}>
                      {t("reports.runOption", { id: run.id })}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          }
        >
          {drift.isLoading && (
            <div className="pf-dashboard-empty pf-dashboard-empty--centered">
              <Spinner />
            </div>
          )}
          {drift.isError && <div className="pf-alert pf-alert--error">{t("reports.driftError")}</div>}
          {drift.data && (
            <>
              <div className="pf-drift-summary-meta">
                <span>
                  {t("reports.complianceDelta")}:{" "}
                  <strong
                    className={
                      drift.data.summary.compliance_delta > 0
                        ? "pf-drift-delta--positive"
                        : drift.data.summary.compliance_delta < 0
                          ? "pf-drift-delta--negative"
                          : undefined
                    }
                  >
                    {drift.data.summary.compliance_delta > 0 ? "+" : ""}
                    {drift.data.summary.compliance_delta}%
                  </strong>
                </span>
                <span className="pf-drift-summary-meta__sep">·</span>
                <span>
                  {t("reports.leftCompliance", {
                    percent: drift.data.summary.left_compliance_percent,
                  })}
                </span>
                <span className="pf-drift-summary-meta__sep">·</span>
                <span>
                  {t("reports.rightCompliance", {
                    percent: drift.data.summary.right_compliance_percent,
                  })}
                </span>
              </div>

              <div className="pf-drift-cards">
                {DRIFT_CHANGE_KEYS.map((change) => {
                  const count = drift.data.summary[change];
                  const isClickable = count > 0;
                  return (
                    <button
                      key={change}
                      type="button"
                      className={`pf-drift-card pf-drift-card--${change}${isClickable ? " pf-drift-card--clickable" : ""}${driftChangeFilter === change ? " pf-drift-card--active" : ""}`}
                      onClick={isClickable ? () => handleDriftCardClick(change) : undefined}
                      disabled={!isClickable}
                    >
                      <span className="pf-drift-card__count">{count}</span>
                      <span className="pf-drift-card__label">{t(`reports.drift.${change}`)}</span>
                    </button>
                  );
                })}
              </div>
            </>
          )}
        </Panel>
      )}

      {showDriftSection && drift.data && (
        <div id="drift-table">
        <Panel title={t("reports.driftDetails")} noPadding>
          <div className="pf-filters">
            <div className="pf-filters__grid pf-filters__grid--checks">
              <div className="pf-filters__group">
                <label htmlFor="drift-filter-change">{t("reports.driftChange")}</label>
                <select
                  id="drift-filter-change"
                  className="pf-select"
                  value={driftChangeFilter}
                  onChange={(event) => setDriftChangeFilter(event.target.value)}
                >
                  <option value="all">{t("reports.allDriftChanges")}</option>
                  {DRIFT_CHANGE_KEYS.map((change) => (
                    <option key={change} value={change}>
                      {t(`reports.drift.${change}`)}
                    </option>
                  ))}
                </select>
              </div>
              <div className="pf-filters__group">
                <label htmlFor="drift-filter-host">{t("reports.hostId")}</label>
                <select
                  id="drift-filter-host"
                  className="pf-select"
                  value={driftHostFilter}
                  onChange={(event) => setDriftHostFilter(event.target.value)}
                >
                  <option value="all">{t("reports.allHosts")}</option>
                  {driftHostOptions.map((hostId) => (
                    <option key={hostId} value={String(hostId)}>
                      {hostId}
                    </option>
                  ))}
                </select>
              </div>
              <div className="pf-filters__group">
                <label htmlFor="drift-filter-rule">{t("reports.rule")}</label>
                <input
                  id="drift-filter-rule"
                  className="pf-input"
                  type="search"
                  value={driftRuleFilter}
                  onChange={(event) => setDriftRuleFilter(event.target.value)}
                  placeholder={t("reports.filterRulePlaceholder")}
                />
              </div>
            </div>
            <div className="pf-filters__footer">
              <p className="pf-filters__summary">
                {hasActiveDriftFilters
                  ? t("reports.filterResultsActive", {
                      count: filteredDriftItems.length,
                      total: drift.data.items.length,
                    })
                  : t("reports.filterShown", {
                      count: filteredDriftItems.length,
                      total: drift.data.items.length,
                    })}
              </p>
              {hasActiveDriftFilters && (
                <Button variant="secondary" className="pf-btn--sm" onClick={clearDriftFilters}>
                  {t("profiles.clearFilters")}
                </Button>
              )}
            </div>
          </div>

          {filteredDriftItems.length === 0 ? (
            <EmptyState
              title={t("reports.noFilterResults")}
              description={t("reports.noFilterResultsDesc")}
            />
          ) : (
            <div className="pf-table-wrap pf-diff-table-wrap">
              <table className="pf-table pf-diff-table">
                <thead>
                  <tr>
                    <th rowSpan={2} className="pf-diff-table__key">
                      {t("reports.diffHostRule")}
                    </th>
                    <th colSpan={2} className="pf-diff-table__col-head pf-diff-table__col-head--left">
                      {t("reports.diffRunA", { id: drift.data.summary.left_run_id })}
                    </th>
                    <th colSpan={2} className="pf-diff-table__col-head pf-diff-table__col-head--right">
                      {t("reports.diffRunB", { id: drift.data.summary.right_run_id })}
                    </th>
                    <th rowSpan={2}>{t("reports.driftChange")}</th>
                  </tr>
                  <tr>
                    <th className="pf-diff-table__subhead">{t("reports.diffStatus")}</th>
                    <th className="pf-diff-table__subhead">{t("reports.diffMessage")}</th>
                    <th className="pf-diff-table__subhead">{t("reports.diffStatus")}</th>
                    <th className="pf-diff-table__subhead">{t("reports.diffMessage")}</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredDriftItems.map((row) => (
                    <tr
                      key={row.key}
                      className={
                        row.change !== "unchanged"
                          ? `pf-diff-row pf-diff-row--${row.change}`
                          : "pf-diff-row"
                      }
                    >
                      <td className="pf-diff-table__key-cell">
                        <span className="pf-table__mono">{row.host_id}</span>
                        <span className="pf-diff-table__rule pf-table__mono">{row.rule_tech_name}</span>
                      </td>
                      <td className="pf-diff-cell pf-diff-cell--left">
                        {row.left_status ? (
                          <Badge variant={checkStatusVariant(row.left_status)}>
                            {row.left_status}
                          </Badge>
                        ) : (
                          <span className="pf-diff-absent">{t("common.dash")}</span>
                        )}
                      </td>
                      <td className="pf-diff-cell pf-diff-cell--left pf-diff-cell--message">
                        {row.left_message || t("common.dash")}
                      </td>
                      <td className="pf-diff-cell pf-diff-cell--right">
                        {row.right_status ? (
                          <Badge variant={checkStatusVariant(row.right_status)}>
                            {row.right_status}
                          </Badge>
                        ) : (
                          <span className="pf-diff-absent">{t("common.dash")}</span>
                        )}
                      </td>
                      <td className="pf-diff-cell pf-diff-cell--right pf-diff-cell--message">
                        {row.right_message || t("common.dash")}
                      </td>
                      <td>
                        <Badge variant={driftChangeVariant(row.change)}>
                          {t(`reports.drift.${row.change}`)}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
        </div>
      )}

      {activeRunId && detail.data && detail.data.check_results.length > 0 && (
        <div ref={checkDetailsRef}>
        <Panel title={t("reports.checkDetails")} noPadding>
          <div className="pf-check-details__filters">
            <div className="pf-check-details__filters-grid">
              <label className="pf-check-details__field" htmlFor="check-filter-host">
                <span className="pf-check-details__field-label">{t("reports.host")}</span>
                <select
                  id="check-filter-host"
                  className={`pf-select${checkHostFilter !== "all" ? " is-filtered" : ""}`}
                  value={checkHostFilter}
                  onChange={(event) => setCheckHostFilter(event.target.value)}
                >
                  <option value="all">{t("reports.allHosts")}</option>
                  {checkHostOptions.map((hostId) => (
                    <option key={hostId} value={String(hostId)}>
                      {hostLabel(hostId)}
                    </option>
                  ))}
                </select>
              </label>

              <label className="pf-check-details__field pf-check-details__field--grow" htmlFor="check-filter-rule">
                <span className="pf-check-details__field-label">{t("reports.rule")}</span>
                <input
                  id="check-filter-rule"
                  className={`pf-input${checkRuleFilter.trim() ? " is-filtered" : ""}`}
                  type="search"
                  value={checkRuleFilter}
                  onChange={(event) => setCheckRuleFilter(event.target.value)}
                  placeholder={t("reports.filterRulePlaceholder")}
                />
              </label>

              <label className="pf-check-details__field" htmlFor="check-filter-severity">
                <span className="pf-check-details__field-label">{t("reports.severity")}</span>
                <select
                  id="check-filter-severity"
                  className={`pf-select${checkSeverityFilter !== "all" ? " is-filtered" : ""}`}
                  value={checkSeverityFilter}
                  onChange={(event) => setCheckSeverityFilter(event.target.value)}
                >
                  <option value="all">{t("reports.allSeverities")}</option>
                  {severityOptions.map((severity) => (
                    <option key={severity} value={severity}>
                      {severity}
                    </option>
                  ))}
                </select>
              </label>

              <label className="pf-check-details__field" htmlFor="check-filter-status">
                <span className="pf-check-details__field-label">{t("common.status")}</span>
                <select
                  id="check-filter-status"
                  className={`pf-select${checkStatusFilter !== "all" ? " is-filtered" : ""}`}
                  value={checkStatusFilter}
                  onChange={(event) => setCheckStatusFilter(event.target.value)}
                >
                  <option value="all">{t("reports.allStatuses")}</option>
                  {checkStatusOptions.map((status) => (
                    <option key={status} value={status}>
                      {status}
                    </option>
                  ))}
                </select>
              </label>

              <label className="pf-check-details__field pf-check-details__field--grow" htmlFor="check-filter-message">
                <span className="pf-check-details__field-label">{t("reports.message")}</span>
                <input
                  id="check-filter-message"
                  className={`pf-input${checkMessageFilter.trim() ? " is-filtered" : ""}`}
                  type="search"
                  value={checkMessageFilter}
                  onChange={(event) => setCheckMessageFilter(event.target.value)}
                  placeholder={t("reports.filterMessagePlaceholder")}
                />
              </label>
            </div>

            <div className="pf-check-details__filters-meta">
              <p className="pf-filters__summary">
                {hasActiveCheckFilters
                  ? t("reports.filterResultsActive", {
                      count: filteredCheckResults.length,
                      total: detail.data.check_results.length,
                    })
                  : t("reports.filterShown", {
                      count: filteredCheckResults.length,
                      total: detail.data.check_results.length,
                    })}
              </p>

              {hasActiveCheckFilters ? (
                <div className="pf-check-details__chips" aria-label={t("profiles.clearFilters")}>
                  {checkHostFilter !== "all" ? (
                    <button
                      type="button"
                      className="pf-check-details__chip"
                      onClick={() => setCheckHostFilter("all")}
                    >
                      <span className="pf-check-details__chip-key">{t("reports.host")}</span>
                      <span className="pf-check-details__chip-val">
                        {hostLabel(Number(checkHostFilter))}
                      </span>
                      <span className="pf-check-details__chip-x" aria-hidden>
                        ×
                      </span>
                    </button>
                  ) : null}
                  {checkRuleFilter.trim() ? (
                    <button
                      type="button"
                      className="pf-check-details__chip"
                      onClick={() => setCheckRuleFilter("")}
                    >
                      <span className="pf-check-details__chip-key">{t("reports.rule")}</span>
                      <span className="pf-check-details__chip-val">{checkRuleFilter.trim()}</span>
                      <span className="pf-check-details__chip-x" aria-hidden>
                        ×
                      </span>
                    </button>
                  ) : null}
                  {checkSeverityFilter !== "all" ? (
                    <button
                      type="button"
                      className="pf-check-details__chip"
                      onClick={() => setCheckSeverityFilter("all")}
                    >
                      <span className="pf-check-details__chip-key">{t("reports.severity")}</span>
                      <span className="pf-check-details__chip-val">{checkSeverityFilter}</span>
                      <span className="pf-check-details__chip-x" aria-hidden>
                        ×
                      </span>
                    </button>
                  ) : null}
                  {checkStatusFilter !== "all" ? (
                    <button
                      type="button"
                      className="pf-check-details__chip"
                      onClick={() => setCheckStatusFilter("all")}
                    >
                      <span className="pf-check-details__chip-key">{t("common.status")}</span>
                      <span className="pf-check-details__chip-val">{checkStatusFilter}</span>
                      <span className="pf-check-details__chip-x" aria-hidden>
                        ×
                      </span>
                    </button>
                  ) : null}
                  {checkMessageFilter.trim() ? (
                    <button
                      type="button"
                      className="pf-check-details__chip"
                      onClick={() => setCheckMessageFilter("")}
                    >
                      <span className="pf-check-details__chip-key">{t("reports.message")}</span>
                      <span className="pf-check-details__chip-val">{checkMessageFilter.trim()}</span>
                      <span className="pf-check-details__chip-x" aria-hidden>
                        ×
                      </span>
                    </button>
                  ) : null}
                  <button type="button" className="pf-check-details__clear" onClick={clearCheckFilters}>
                    {t("profiles.clearFilters")}
                  </button>
                </div>
              ) : null}
            </div>
          </div>

          <div className="pf-table-wrap">
            <table className="pf-table pf-table--check-details">
              <thead>
                <tr>
                  <SortableTh<CheckSortKey>
                    label={t("reports.host")}
                    sortKey="host"
                    activeKey={checkSort.key}
                    direction={checkSort.direction}
                    onSort={toggleCheckSort}
                  />
                  <SortableTh<CheckSortKey>
                    label={t("reports.rule")}
                    sortKey="rule"
                    activeKey={checkSort.key}
                    direction={checkSort.direction}
                    onSort={toggleCheckSort}
                  />
                  <SortableTh<CheckSortKey>
                    label={t("reports.severity")}
                    sortKey="severity"
                    activeKey={checkSort.key}
                    direction={checkSort.direction}
                    onSort={toggleCheckSort}
                  />
                  <SortableTh<CheckSortKey>
                    label={t("common.status")}
                    sortKey="status"
                    activeKey={checkSort.key}
                    direction={checkSort.direction}
                    onSort={toggleCheckSort}
                  />
                  <SortableTh<CheckSortKey>
                    label={t("reports.message")}
                    sortKey="message"
                    activeKey={checkSort.key}
                    direction={checkSort.direction}
                    onSort={toggleCheckSort}
                  />
                  <th scope="col" />
                </tr>
              </thead>
              <tbody>
                {sortedCheckResults.length === 0 ? (
                  <tr>
                    <td colSpan={6}>
                      <div className="pf-check-details__empty">
                        <strong>{t("reports.noFilterResults")}</strong>
                        <p>{t("reports.noFilterResultsDesc")}</p>
                      </div>
                    </td>
                  </tr>
                ) : (
                sortedCheckResults.map((row) => {
                  const ruleMeta = findProfileRule(profileRules.data, row.rule_tech_name);
                  const hasDetails = hasProfileRuleMetadata(ruleMeta);
                  const expanded = expandedCheckId === row.id;
                  const severityLabel = (ruleMeta?.criticality || ruleMeta?.impact || "").toString().trim();
                  const canRequestWaiver =
                    canOperate &&
                    profileId != null &&
                    row.status.toLowerCase() === "fail" &&
                    !row.is_waived;

                  return (
                    <Fragment key={row.id}>
                      <tr>
                        <td>
                          <div className="pf-check-details__host">
                            <span className="pf-check-details__host-name">{hostLabel(row.host_id)}</span>
                            {hostLabel(row.host_id) !== `#${row.host_id}` ? (
                              <span className="pf-table__mono pf-table__muted pf-check-details__host-id">
                                #{row.host_id}
                              </span>
                            ) : null}
                          </div>
                        </td>
                        <td
                          className={`pf-table__mono${hasDetails ? " pf-table__rule-cell" : ""}`}
                          onClick={hasDetails ? () => toggleCheckDetails(row.id) : undefined}
                          onKeyDown={
                            hasDetails
                              ? (event) => {
                                  if (event.key === "Enter" || event.key === " ") {
                                    event.preventDefault();
                                    toggleCheckDetails(row.id);
                                  }
                                }
                              : undefined
                          }
                          role={hasDetails ? "button" : undefined}
                          tabIndex={hasDetails ? 0 : undefined}
                          aria-expanded={hasDetails ? expanded : undefined}
                        >
                          <span
                            className={
                              hasDetails
                                ? `pf-table__rule-link${expanded ? " pf-table__rule-link--active" : ""}`
                                : undefined
                            }
                          >
                            {row.rule_tech_name}
                          </span>
                        </td>
                        <td className="pf-check-details__severity">
                          {severityLabel ? (
                            <Badge variant={severityVariant(severityLabel)} literal>
                              {severityLabel}
                            </Badge>
                          ) : (
                            t("common.dash")
                          )}
                        </td>
                        <td>
                          <div className="pf-table__actions" style={{ justifyContent: "flex-start" }}>
                            <Badge variant={checkStatusVariant(row.status)}>{row.status}</Badge>
                            {row.is_waived ? (
                              <Badge variant="info">{t("reports.waivedBadge")}</Badge>
                            ) : null}
                          </div>
                        </td>
                        <td>{row.message || t("common.dash")}</td>
                        <td onClick={(e) => e.stopPropagation()}>
                          {canRequestWaiver ? (
                            <Button
                              variant="secondary"
                              className="pf-btn--sm"
                              onClick={() => {
                                if (profileId == null || selectedRun == null) return;
                                void (async () => {
                                  const reason = await prompt({
                                    title: t("waivers.requestTitle"),
                                    subtitle: row.rule_tech_name,
                                    message: t("waivers.requestMessage"),
                                    label: t("waivers.reason"),
                                    placeholder: t("waivers.reasonPlaceholder"),
                                    confirmLabel: t("reports.requestWaiver"),
                                  });
                                  if (!reason) return;
                                  try {
                                    await api.createWaiver({
                                      profile_id: profileId,
                                      rule_tech_name: row.rule_tech_name,
                                      host_id: row.host_id,
                                      job_id: selectedRun.job_id,
                                      reason,
                                    });
                                    toast.success(t("waivers.requested"));
                                    queryClient.invalidateQueries({ queryKey: ["waivers"] });
                                    queryClient.invalidateQueries({ queryKey: ["run-detail", activeRunId] });
                                    queryClient.invalidateQueries({ queryKey: ["summary", activeRunId] });
                                  } catch (err) {
                                    toast.error(
                                      err instanceof Error ? err.message : t("toast.genericError")
                                    );
                                  }
                                })();
                              }}
                            >
                              {t("reports.requestWaiver")}
                            </Button>
                          ) : null}
                        </td>
                      </tr>
                      {expanded && ruleMeta && hasDetails && (
                        <tr className="pf-table__detail-row">
                          <td colSpan={6}>
                            <div className="pf-profile-rule__body pf-profile-rule__body--table">
                              <ProfileRuleMetadata rule={ruleMeta} labels={ruleLabels} />
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })
                )}
              </tbody>
            </table>
          </div>
        </Panel>
        </div>
      )}

      {activeRunId && detail.data && detail.data.check_results.length === 0 && !detail.isLoading && (
        <Panel title={t("reports.checkDetails")}>
          <p className="pf-table__muted">{t("reports.noCheckResults")}</p>
        </Panel>
      )}

      {activeRunId && multiCompareCandidates.length >= 2 && (
        <Panel title={t("reports.multiCompareTitle")} noPadding>
          <div className="pf-multi-compare">
            <div className="pf-multi-compare__head">
              <p className="pf-multi-compare__desc">{t("reports.multiCompareDesc")}</p>
            </div>

            <div className="pf-multi-compare__picker">
              <div className="pf-multi-compare__picker-toolbar">
                <div className="pf-multi-compare__picker-copy">
                  <span className="pf-multi-compare__picker-label">{t("reports.multiCompareRunsLabel")}</span>
                  <span
                    className={`pf-multi-compare__picker-badge${multiCompareCanExport ? " is-ready" : ""}`}
                  >
                    {multiSelectedLabel}
                  </span>
                </div>
                <Button
                  variant="secondary"
                  className="pf-btn--sm"
                  onClick={() => void handleMultiCompareCsv()}
                  disabled={!multiCompareCanExport}
                >
                  {t("reports.downloadCompareCsv")}
                </Button>
              </div>

              {!multiCompareCanExport ? (
                <p className="pf-multi-compare__hint">{t("reports.multiCompareNeedMore")}</p>
              ) : null}

              <div className="pf-multi-compare__tiles" role="group" aria-label={t("reports.multiCompareRunsLabel")}>
                {multiCompareCandidates.map((run) => {
                  const checked = multiCompareIds.includes(run.id);
                  const selectionIndex = multiCompareIds.indexOf(run.id);
                  const isCurrent = run.id === activeRunId;
                  const duration = formatRunDuration(run.started_at, run.finished_at);
                  const finishedLabel = run.finished_at
                    ? new Date(run.finished_at).toLocaleString(dateLocale)
                    : t("common.dash");

                  return (
                    <button
                      key={run.id}
                      type="button"
                      className={`pf-multi-compare__tile${checked ? " is-selected" : ""}${isCurrent ? " is-current" : ""}`}
                      aria-pressed={checked}
                      aria-label={
                        checked
                          ? `${t("reports.runOption", { id: run.id })}, ${t("reports.multiCompareOrder", { order: selectionIndex + 1 })}`
                          : t("reports.runOption", { id: run.id })
                      }
                      disabled={!checked && multiCompareIds.length >= 8}
                      onClick={() => toggleMultiCompareId(run.id)}
                    >
                      <span className="pf-multi-compare__tile-badge" aria-hidden>
                        {checked ? selectionIndex + 1 : `#${run.id}`}
                      </span>
                      <span className="pf-multi-compare__tile-copy">
                        <span className="pf-multi-compare__tile-title">
                          {t("reports.runOption", { id: run.id })}
                          {isCurrent ? <Badge variant="info">{t("reports.currentRun")}</Badge> : null}
                        </span>
                        <span className="pf-multi-compare__tile-meta">{finishedLabel}</span>
                        {duration ? (
                          <span className="pf-multi-compare__tile-sub">{duration}</span>
                        ) : null}
                      </span>
                      <span className="pf-multi-compare__tile-check" aria-hidden>
                        {checked ? <IconCheck /> : <span className="pf-multi-compare__tile-ring" />}
                      </span>
                    </button>
                  );
                })}
              </div>
            </div>

            {multiCompareActive && multiCompareIds.length >= 2 ? (
              <div className="pf-multi-compare__results">
                {multiCompareQuery.isLoading ? (
                  <div className="pf-multi-compare__state">
                    <Spinner />
                  </div>
                ) : null}

                {multiCompareQuery.isError ? (
                  <div className="pf-multi-compare__state">
                    <div className="pf-alert pf-alert--error">
                      {multiCompareQuery.error instanceof Error
                        ? multiCompareQuery.error.message
                        : t("reports.multiCompareError")}
                    </div>
                  </div>
                ) : null}

                {multiCompareQuery.data ? (
                  <>
                    <div className="pf-multi-compare__summary">
                      {multiCompareQuery.data.runs.map((run, index) => {
                        const pct = Math.max(0, Math.min(100, run.compliance_percent));
                        const prev = multiCompareQuery.data.runs[index - 1];
                        const delta =
                          prev != null
                            ? Number((run.compliance_percent - prev.compliance_percent).toFixed(2))
                            : null;
                        return (
                          <div key={run.run_id} className="pf-multi-compare__metric">
                            <div className="pf-multi-compare__metric-top">
                              <span className="pf-multi-compare__metric-label">
                                {t("reports.runOption", { id: run.run_id })}
                                {run.run_id === activeRunId ? (
                                  <Badge variant="info">{t("reports.currentRun")}</Badge>
                                ) : null}
                              </span>
                              {delta != null ? (
                                <span
                                  className={
                                    delta > 0
                                      ? "pf-multi-compare__delta pf-multi-compare__delta--up"
                                      : delta < 0
                                        ? "pf-multi-compare__delta pf-multi-compare__delta--down"
                                        : "pf-multi-compare__delta"
                                  }
                                >
                                  {delta > 0 ? "+" : ""}
                                  {delta}%
                                </span>
                              ) : null}
                            </div>
                            <div className="pf-multi-compare__metric-value">
                              {run.compliance_percent.toFixed(1)}%
                            </div>
                            <div className="pf-multi-compare__meter" role="presentation" aria-hidden>
                              <span className="pf-multi-compare__meter-fill" style={{ width: `${pct}%` }} />
                            </div>
                            <div className="pf-multi-compare__metric-foot">
                              <span>
                                {t("reports.multiComparePassTotal", {
                                  passed: run.passed,
                                  total: run.total_checks,
                                })}
                              </span>
                              <span className="pf-multi-compare__metric-split">
                                {t("reports.multiCompareFailSkip", {
                                  failed: run.failed,
                                  skipped: run.skipped,
                                })}
                              </span>
                            </div>
                          </div>
                        );
                      })}
                    </div>

                    <div className="pf-check-details__filters pf-multi-compare__filters">
                      <div className="pf-multi-compare__filters-grid">
                        <label className="pf-check-details__field" htmlFor="multi-filter-severity">
                          <span className="pf-check-details__field-label">{t("reports.severity")}</span>
                          <select
                            id="multi-filter-severity"
                            className={`pf-select${multiCompareSeverityFilter !== "all" ? " is-filtered" : ""}`}
                            value={multiCompareSeverityFilter}
                            onChange={(e) => setMultiCompareSeverityFilter(e.target.value)}
                          >
                            <option value="all">{t("reports.allSeverities")}</option>
                            {[
                              ...new Set(
                                (multiCompareQuery.data.rows ?? [])
                                  .map((r) => (r.severity || "").toLowerCase())
                                  .filter(Boolean)
                              ),
                            ]
                              .sort()
                              .map((sev) => (
                                <option key={sev} value={sev}>
                                  {sev}
                                </option>
                              ))}
                          </select>
                        </label>
                        <label
                          className="pf-check-details__field pf-check-details__field--grow"
                          htmlFor="multi-filter-rule"
                        >
                          <span className="pf-check-details__field-label">{t("reports.rule")}</span>
                          <input
                            id="multi-filter-rule"
                            className={`pf-input${multiCompareRuleFilter.trim() ? " is-filtered" : ""}`}
                            type="search"
                            value={multiCompareRuleFilter}
                            onChange={(e) => setMultiCompareRuleFilter(e.target.value)}
                            placeholder={t("reports.filterRulePlaceholder")}
                          />
                        </label>
                      </div>

                      <div className="pf-check-details__filters-meta">
                        <p className="pf-filters__summary">
                          {multiCompareHasActiveFilters
                            ? t("reports.filterResultsActive", {
                                count: filteredMultiRows.length,
                                total: multiCompareQuery.data.rows.length,
                              })
                            : t("reports.filterShown", {
                                count: filteredMultiRows.length,
                                total: multiCompareQuery.data.rows.length,
                              })}
                        </p>

                        {multiCompareHasActiveFilters ? (
                          <div className="pf-check-details__chips" aria-label={t("profiles.clearFilters")}>
                            {multiCompareSeverityFilter !== "all" ? (
                              <button
                                type="button"
                                className="pf-check-details__chip"
                                onClick={() => setMultiCompareSeverityFilter("all")}
                              >
                                <span className="pf-check-details__chip-key">{t("reports.severity")}</span>
                                <span className="pf-check-details__chip-val">{multiCompareSeverityFilter}</span>
                                <span className="pf-check-details__chip-x" aria-hidden>
                                  ×
                                </span>
                              </button>
                            ) : null}
                            {multiCompareRuleFilter.trim() ? (
                              <button
                                type="button"
                                className="pf-check-details__chip"
                                onClick={() => setMultiCompareRuleFilter("")}
                              >
                                <span className="pf-check-details__chip-key">{t("reports.rule")}</span>
                                <span className="pf-check-details__chip-val">{multiCompareRuleFilter.trim()}</span>
                                <span className="pf-check-details__chip-x" aria-hidden>
                                  ×
                                </span>
                              </button>
                            ) : null}
                            <button
                              type="button"
                              className="pf-check-details__clear"
                              onClick={clearMultiCompareFilters}
                            >
                              {t("profiles.clearFilters")}
                            </button>
                          </div>
                        ) : null}
                      </div>
                    </div>

                    {filteredMultiRows.length === 0 ? (
                      <div className="pf-multi-compare__state">
                        <EmptyState
                          title={t("reports.noFilterResults")}
                          description={t("reports.noFilterResultsDesc")}
                        />
                      </div>
                    ) : (
                      <div className="pf-table-wrap">
                        <table className="pf-table pf-table--multi-compare">
                          <thead>
                            <tr>
                              <th>{t("reports.hostId")}</th>
                              <th>{t("reports.rule")}</th>
                              <th>{t("reports.severity")}</th>
                              {multiCompareQuery.data.runs.map((run) => (
                                <th key={run.run_id} className="pf-multi-compare__run-col">
                                  #{run.run_id}
                                </th>
                              ))}
                            </tr>
                          </thead>
                          <tbody>
                            {filteredMultiRows.map((row) => (
                              <tr key={`${row.host_id}-${row.rule_tech_name}`}>
                                <td className="pf-table__mono">{row.host_id}</td>
                                <td className="pf-table__mono">{row.rule_tech_name}</td>
                                <td>
                                  <span className="pf-multi-compare__sev">
                                    {row.severity || t("common.dash")}
                                  </span>
                                </td>
                                {row.cells.map((cell) => (
                                  <td key={cell.run_id} className="pf-multi-compare__run-col">
                                    {cell.status ? (
                                      <Badge variant={checkStatusVariant(cell.status)}>{cell.status}</Badge>
                                    ) : (
                                      t("common.dash")
                                    )}
                                  </td>
                                ))}
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </>
                ) : null}
              </div>
            ) : null}
          </div>
        </Panel>
      )}
    </>
  );
}
