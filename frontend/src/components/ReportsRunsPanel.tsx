import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type Job, type JobRun, type RemediationRun } from "../api/client";
import { useTranslation } from "../i18n/I18nProvider";
import { useTableSort } from "../hooks/useTableSort";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { EmptyState } from "./ui/EmptyState";
import { QueryErrorState } from "./ui/QueryErrorState";
import { Pagination, usePagination } from "./ui/Pagination";
import { SortableTh } from "./ui/SortableTh";
import { Spinner } from "./ui/Spinner";
import { checkStatusVariant } from "../utils/statusVariant";

const RUN_STATUS_KEYS = ["completed", "running", "pending", "failed", "cancelled"] as const;
const REPORTS_RUNS_LIMIT = 200;

export type ReportsRunCategory = "compliance" | "playbooks" | "remediation";

function runStatusLabel(t: (key: string) => string, status: string): string {
  const key = `runStatus.${status}` as const;
  const translated = t(key);
  return translated === key ? status : translated;
}

function isComplianceJob(job: Job | undefined): boolean {
  if (!job) return true;
  if (job.playbook_id != null && job.profile_id == null) return false;
  return job.profile_id != null || (job.profile_id == null && job.playbook_id == null);
}

function isPlaybookJob(job: Job | undefined): boolean {
  return job != null && job.playbook_id != null && job.profile_id == null;
}

async function fetchAllJobs(): Promise<Job[]> {
  const [standardJobs, networkJobs] = await Promise.all([
    api.jobs("standard"),
    api.jobs("network"),
  ]);
  const byId = new Map<number, Job>();
  [...standardJobs, ...networkJobs].forEach((job) => byId.set(job.id, job));
  return Array.from(byId.values());
}

type ComplianceSortKey = "id" | "job_name" | "profile" | "status" | "started_at" | "finished_at";
type PlaybookSortKey = "id" | "playbook" | "job_name" | "status" | "hosts" | "started_at" | "finished_at";
type RemediationSortKey = "id" | "job_name" | "status" | "started_at" | "finished_at";

type ReportsRunsPanelProps = {
  selectedRunId: number | null;
  onSelectComplianceRun: (runId: number) => void;
  onDeleteComplianceRun: (run: JobRun) => void;
  canOperate: boolean;
  canAccessRemediation: boolean;
  deletePending: boolean;
};

export function ReportsRunsPanel({
  selectedRunId,
  onSelectComplianceRun,
  onDeleteComplianceRun,
  canOperate,
  canAccessRemediation,
  deletePending,
}: ReportsRunsPanelProps) {
  const { t, dateLocale } = useTranslation();
  const [category, setCategory] = useState<ReportsRunCategory>("compliance");

  useEffect(() => {
    if (!canAccessRemediation && category === "remediation") {
      setCategory("compliance");
    }
  }, [canAccessRemediation, category]);

  const [complianceSearch, setComplianceSearch] = useState("");
  const [complianceStatus, setComplianceStatus] = useState("all");
  const [complianceProfile, setComplianceProfile] = useState("all");

  const [playbookSearch, setPlaybookSearch] = useState("");
  const [playbookStatus, setPlaybookStatus] = useState("all");
  const [playbookFilter, setPlaybookFilter] = useState("all");

  const [remediationSearch, setRemediationSearch] = useState("");
  const [remediationStatus, setRemediationStatus] = useState("all");
  const [remediationJobFilter, setRemediationJobFilter] = useState("all");

  const jobs = useQuery({ queryKey: ["jobs", "reports-all"], queryFn: fetchAllJobs });
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api.profiles() });
  const playbooks = useQuery({ queryKey: ["playbooks", "reports-all"], queryFn: () => api.playbooks() });
  const remediations = useQuery({
    queryKey: ["remediations", "reports-all"],
    queryFn: async () => {
      const [standardJobs, networkJobs] = await Promise.all([
        api.remediations("standard"),
        api.remediations("network"),
      ]);
      const byId = new Map<number, (typeof standardJobs)[number]>();
      [...standardJobs, ...networkJobs].forEach((job) => byId.set(job.id, job));
      return Array.from(byId.values());
    },
    enabled: canAccessRemediation,
  });

  const jobRuns = useQuery({
    queryKey: ["job-runs", "reports", REPORTS_RUNS_LIMIT],
    queryFn: () => api.jobRuns({ offset: 0, limit: REPORTS_RUNS_LIMIT }),
    refetchInterval: 15000,
  });

  const remediationRuns = useQuery({
    queryKey: ["remediation-runs", "reports", REPORTS_RUNS_LIMIT],
    queryFn: () => api.remediationRuns({ offset: 0, limit: REPORTS_RUNS_LIMIT }),
    refetchInterval: 15000,
    enabled: canAccessRemediation,
  });

  const jobById = useMemo(() => {
    const map = new Map<number, Job>();
    jobs.data?.forEach((job) => map.set(job.id, job));
    return map;
  }, [jobs.data]);

  const jobNameById = useMemo(() => {
    const map = new Map<number, string>();
    jobs.data?.forEach((job) => map.set(job.id, job.name));
    return map;
  }, [jobs.data]);

  const profileLabelById = useMemo(() => {
    const map = new Map<number, string>();
    profiles.data?.forEach((profile) => map.set(profile.id, profile.profile_name));
    return map;
  }, [profiles.data]);

  const remediationNameById = useMemo(() => {
    const map = new Map<number, string>();
    remediations.data?.forEach((job) => map.set(job.id, job.name));
    return map;
  }, [remediations.data]);

  const playbookNameById = useMemo(() => {
    const map = new Map<number, string>();
    playbooks.data?.forEach((playbook) => map.set(playbook.id, playbook.name));
    return map;
  }, [playbooks.data]);

  const complianceRunList = useMemo(() => {
    return (jobRuns.data?.items ?? []).filter((run) => isComplianceJob(jobById.get(run.job_id)));
  }, [jobRuns.data, jobById]);

  const complianceAccessor = useCallback(
    (run: JobRun, key: ComplianceSortKey) => {
      const job = jobById.get(run.job_id);
      if (key === "job_name") return job?.name ?? "";
      if (key === "profile") {
        const profileId = job?.profile_id;
        if (profileId == null) return "";
        return profileLabelById.get(profileId) ?? String(profileId);
      }
      return run[key as keyof JobRun];
    },
    [jobById, profileLabelById]
  );

  const {
    sortedRows: sortedComplianceRuns,
    sort: complianceSort,
    toggleSort: toggleComplianceSort,
  } = useTableSort<JobRun, ComplianceSortKey>(
    complianceRunList,
    { key: "finished_at", direction: "desc" },
    complianceAccessor
  );

  const filteredComplianceRuns = useMemo(() => {
    const query = complianceSearch.trim().toLowerCase();
    return sortedComplianceRuns.filter((run) => {
      if (complianceStatus !== "all" && run.status !== complianceStatus) return false;
      if (complianceProfile !== "all") {
        const profileId = jobById.get(run.job_id)?.profile_id;
        if (String(profileId ?? "") !== complianceProfile) return false;
      }
      if (!query) return true;
      const jobName = jobNameById.get(run.job_id) ?? "";
      const profileId = jobById.get(run.job_id)?.profile_id;
      const profileLabel = profileId != null ? profileLabelById.get(profileId) ?? "" : "";
      const haystack = `${run.id} ${run.job_id} ${jobName} ${profileLabel}`.toLowerCase();
      return haystack.includes(query);
    });
  }, [
    sortedComplianceRuns,
    complianceSearch,
    complianceStatus,
    complianceProfile,
    jobById,
    jobNameById,
    profileLabelById,
  ]);

  const playbookRunList = useMemo(() => {
    return (jobRuns.data?.items ?? []).filter((run) => isPlaybookJob(jobById.get(run.job_id)));
  }, [jobRuns.data, jobById]);

  const playbookAccessor = useCallback(
    (run: JobRun, key: PlaybookSortKey) => {
      const job = jobById.get(run.job_id);
      if (key === "id") return run.id;
      if (key === "status") return run.status;
      if (key === "started_at") return run.started_at ?? "";
      if (key === "finished_at") return run.finished_at ?? "";
      if (key === "hosts") return job?.host_ids.length ?? 0;
      if (key === "job_name") return job?.name ?? jobNameById.get(run.job_id) ?? "";
      if (key === "playbook") {
        const playbookId = job?.playbook_id;
        return playbookId != null ? playbookNameById.get(playbookId) ?? `#${playbookId}` : "";
      }
      return "";
    },
    [jobById, jobNameById, playbookNameById]
  );

  const {
    sortedRows: sortedPlaybookRuns,
    sort: playbookSort,
    toggleSort: togglePlaybookSort,
  } = useTableSort<JobRun, PlaybookSortKey>(
    playbookRunList,
    { key: "finished_at", direction: "desc" },
    playbookAccessor
  );

  const filteredPlaybookRuns = useMemo(() => {
    const query = playbookSearch.trim().toLowerCase();
    return sortedPlaybookRuns.filter((run) => {
      if (playbookStatus !== "all" && run.status !== playbookStatus) return false;
      const playbookId = jobById.get(run.job_id)?.playbook_id ?? null;
      if (playbookFilter !== "all" && String(playbookId ?? "") !== playbookFilter) return false;
      if (!query) return true;
      const playbookLabel = playbookAccessor(run, "playbook");
      const jobLabel = playbookAccessor(run, "job_name");
      const haystack = `${run.id} ${playbookLabel} ${jobLabel}`.toLowerCase();
      return haystack.includes(query);
    });
  }, [
    sortedPlaybookRuns,
    playbookSearch,
    playbookStatus,
    playbookFilter,
    jobById,
    playbookAccessor,
  ]);

  const remediationRunList = useMemo(
    () => remediationRuns.data?.items ?? [],
    [remediationRuns.data]
  );

  const remediationAccessor = useCallback(
    (run: RemediationRun, key: RemediationSortKey) => {
      if (key === "job_name") return remediationNameById.get(run.remediation_job_id) ?? "";
      return run[key as keyof RemediationRun];
    },
    [remediationNameById]
  );

  const {
    sortedRows: sortedRemediationRuns,
    sort: remediationSort,
    toggleSort: toggleRemediationSort,
  } = useTableSort<RemediationRun, RemediationSortKey>(
    remediationRunList,
    { key: "finished_at", direction: "desc" },
    remediationAccessor
  );

  const filteredRemediationRuns = useMemo(() => {
    const query = remediationSearch.trim().toLowerCase();
    return sortedRemediationRuns.filter((run) => {
      if (remediationStatus !== "all" && run.status !== remediationStatus) return false;
      if (remediationJobFilter !== "all" && String(run.remediation_job_id) !== remediationJobFilter) {
        return false;
      }
      if (!query) return true;
      const jobName = remediationNameById.get(run.remediation_job_id) ?? "";
      const haystack = `${run.id} ${run.remediation_job_id} ${jobName}`.toLowerCase();
      return haystack.includes(query);
    });
  }, [
    sortedRemediationRuns,
    remediationSearch,
    remediationStatus,
    remediationJobFilter,
    remediationNameById,
  ]);

  const compliancePagination = usePagination(filteredComplianceRuns);
  const playbookPagination = usePagination(filteredPlaybookRuns);
  const remediationPagination = usePagination(filteredRemediationRuns);

  const resetCompliancePage = () => compliancePagination.setPage(1);
  const resetPlaybookPage = () => playbookPagination.setPage(1);
  const resetRemediationPage = () => remediationPagination.setPage(1);

  const categoryTabs = useMemo(() => {
    const tabs: { id: ReportsRunCategory; labelKey: string; descKey: string; count: number }[] = [
      {
        id: "compliance",
        labelKey: "reports.categoryCompliance",
        descKey: "reports.categoryComplianceDesc",
        count: complianceRunList.length,
      },
      {
        id: "playbooks",
        labelKey: "reports.categoryPlaybooks",
        descKey: "reports.categoryPlaybooksDesc",
        count: playbookRunList.length,
      },
    ];
    if (canAccessRemediation) {
      tabs.push({
        id: "remediation",
        labelKey: "reports.categoryRemediation",
        descKey: "reports.categoryRemediationDesc",
        count: remediationRunList.length,
      });
    }
    return tabs;
  }, [
    canAccessRemediation,
    complianceRunList.length,
    playbookRunList.length,
    remediationRunList.length,
  ]);

  const activeCategoryDesc =
    categoryTabs.find((tab) => tab.id === category)?.descKey ?? "reports.categoryComplianceDesc";

  const renderStatusFilter = (
    id: string,
    value: string,
    onChange: (value: string) => void
  ) => (
    <div className="pf-filters__group">
      <label htmlFor={id}>{t("common.status")}</label>
      <select id={id} className="pf-select" value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="all">{t("reports.allStatuses")}</option>
        {RUN_STATUS_KEYS.map((status) => (
          <option key={status} value={status}>
            {runStatusLabel(t, status)}
          </option>
        ))}
      </select>
    </div>
  );

  const renderSearchFilter = (
    id: string,
    value: string,
    onChange: (value: string) => void,
    placeholderKey: string
  ) => (
    <div className="pf-filters__group pf-filters__group--grow">
      <label htmlFor={id}>{t("reports.runSearchLabel")}</label>
      <input
        id={id}
        className="pf-input"
        type="search"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={t(placeholderKey)}
      />
    </div>
  );

  const renderFilterFooter = (
    filtered: number,
    total: number,
    hasActive: boolean,
    onClear: () => void
  ) => (
    <div className="pf-filters__footer">
      <p className="pf-filters__summary">
        {hasActive
          ? t("reports.filterResultsActive", { count: filtered, total })
          : t("reports.filterShown", { count: filtered, total })}
      </p>
      {hasActive ? (
        <Button variant="secondary" className="pf-btn--sm" type="button" onClick={onClear}>
          {t("profiles.clearFilters")}
        </Button>
      ) : null}
    </div>
  );

  const complianceHasActive =
    complianceSearch.trim() !== "" || complianceStatus !== "all" || complianceProfile !== "all";

  const playbookHasActive =
    playbookSearch.trim() !== "" || playbookStatus !== "all" || playbookFilter !== "all";

  const remediationHasActive =
    remediationSearch.trim() !== "" || remediationStatus !== "all" || remediationJobFilter !== "all";

  const isLoading =
    jobRuns.isLoading ||
    jobs.isLoading ||
    (category === "compliance" && profiles.isLoading) ||
    (category === "playbooks" && playbooks.isLoading) ||
    (category === "remediation" && canAccessRemediation && (remediationRuns.isLoading || remediations.isLoading));

  const isError =
    jobRuns.isError ||
    jobs.isError ||
    (category === "remediation" && canAccessRemediation && remediationRuns.isError);

  const errorQuery =
    category === "remediation" && remediationRuns.isError ? remediationRuns : jobRuns;

  return (
    <div className="pf-reports-runs">
      <div className="pf-reports-runs__head">
        <nav className="pf-reports-runs__tabs" aria-label={t("reports.runCategoriesAria")}>
          <div className="pf-segmented pf-reports-runs__segmented" role="tablist">
            {categoryTabs.map((tab) => (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={category === tab.id}
                className={`pf-segmented__option pf-reports-runs__tab${category === tab.id ? " is-active" : ""}`}
                onClick={() => setCategory(tab.id)}
              >
                <span className="pf-segmented__label">{t(tab.labelKey)}</span>
                <span className="pf-reports-runs__tab-count">{tab.count}</span>
              </button>
            ))}
          </div>
        </nav>
        <p className="pf-reports-runs__category-desc">{t(activeCategoryDesc)}</p>
      </div>

      {category === "compliance" && (
        <div className="pf-filters pf-runs-filters">
          <div className="pf-filters__grid pf-filters__grid--runs">
            {renderSearchFilter(
              "reports-compliance-search",
              complianceSearch,
              (value) => {
                setComplianceSearch(value);
                resetCompliancePage();
              },
              "reports.runSearchCompliance"
            )}
            <div className="pf-filters__group">
              <label htmlFor="reports-compliance-profile">{t("reports.profile")}</label>
              <select
                id="reports-compliance-profile"
                className="pf-select"
                value={complianceProfile}
                onChange={(e) => {
                  setComplianceProfile(e.target.value);
                  resetCompliancePage();
                }}
              >
                <option value="all">{t("reports.allProfiles")}</option>
                {(profiles.data ?? []).map((profile) => (
                  <option key={profile.id} value={String(profile.id)}>
                    {profile.profile_name}
                  </option>
                ))}
              </select>
            </div>
            {renderStatusFilter("reports-compliance-status", complianceStatus, (value) => {
              setComplianceStatus(value);
              resetCompliancePage();
            })}
          </div>
          {renderFilterFooter(
            filteredComplianceRuns.length,
            complianceRunList.length,
            complianceHasActive,
            () => {
              setComplianceSearch("");
              setComplianceStatus("all");
              setComplianceProfile("all");
              resetCompliancePage();
            }
          )}
        </div>
      )}

      {category === "playbooks" && (
        <div className="pf-filters pf-runs-filters">
          <div className="pf-filters__grid pf-filters__grid--runs">
            {renderSearchFilter(
              "reports-playbook-search",
              playbookSearch,
              (value) => {
                setPlaybookSearch(value);
                resetPlaybookPage();
              },
              "reports.runSearchPlaybooks"
            )}
            <div className="pf-filters__group">
              <label htmlFor="reports-playbook-filter">{t("playbooks.playbookCol")}</label>
              <select
                id="reports-playbook-filter"
                className="pf-select"
                value={playbookFilter}
                onChange={(e) => {
                  setPlaybookFilter(e.target.value);
                  resetPlaybookPage();
                }}
              >
                <option value="all">{t("playbooks.jobsListPlaybookAll")}</option>
                {(playbooks.data ?? []).map((playbook) => (
                  <option key={playbook.id} value={String(playbook.id)}>
                    {playbook.name}
                  </option>
                ))}
              </select>
            </div>
            {renderStatusFilter("reports-playbook-status", playbookStatus, (value) => {
              setPlaybookStatus(value);
              resetPlaybookPage();
            })}
          </div>
          {renderFilterFooter(
            filteredPlaybookRuns.length,
            playbookRunList.length,
            playbookHasActive,
            () => {
              setPlaybookSearch("");
              setPlaybookStatus("all");
              setPlaybookFilter("all");
              resetPlaybookPage();
            }
          )}
        </div>
      )}

      {category === "remediation" && (
        <div className="pf-filters pf-runs-filters">
          <div className="pf-filters__grid pf-filters__grid--runs">
            {renderSearchFilter(
              "reports-remediation-search",
              remediationSearch,
              (value) => {
                setRemediationSearch(value);
                resetRemediationPage();
              },
              "reports.runSearchRemediation"
            )}
            <div className="pf-filters__group">
              <label htmlFor="reports-remediation-job">{t("reports.job")}</label>
              <select
                id="reports-remediation-job"
                className="pf-select"
                value={remediationJobFilter}
                onChange={(e) => {
                  setRemediationJobFilter(e.target.value);
                  resetRemediationPage();
                }}
              >
                <option value="all">{t("reports.allJobs")}</option>
                {(remediations.data ?? []).map((job) => (
                  <option key={job.id} value={String(job.id)}>
                    {job.name}
                  </option>
                ))}
              </select>
            </div>
            {renderStatusFilter("reports-remediation-status", remediationStatus, (value) => {
              setRemediationStatus(value);
              resetRemediationPage();
            })}
          </div>
          {renderFilterFooter(
            filteredRemediationRuns.length,
            remediationRunList.length,
            remediationHasActive,
            () => {
              setRemediationSearch("");
              setRemediationStatus("all");
              setRemediationJobFilter("all");
              resetRemediationPage();
            }
          )}
        </div>
      )}

      {isLoading ? (
        <div className="pf-reports-runs__state">
          <Spinner />
        </div>
      ) : isError ? (
        <div className="pf-reports-runs__state">
          <QueryErrorState
          title={t("common.listLoadError")}
          message={errorQuery.error instanceof Error ? errorQuery.error.message : undefined}
          onRetry={() => errorQuery.refetch()}
        />
        </div>
      ) : category === "compliance" ? (
        filteredComplianceRuns.length === 0 ? (
          <div className="pf-reports-runs__state">
            <EmptyState title={t("reports.noRuns")} description={t("reports.noRunsDesc")} />
          </div>
        ) : (
          <div className="pf-table-wrap">
            <table className="pf-table">
              <thead>
                <tr>
                  <SortableTh<ComplianceSortKey>
                    label={t("jobs.runId")}
                    sortKey="id"
                    activeKey={complianceSort.key}
                    direction={complianceSort.direction}
                    onSort={toggleComplianceSort}
                  />
                  <SortableTh<ComplianceSortKey>
                    label={t("reports.job")}
                    sortKey="job_name"
                    activeKey={complianceSort.key}
                    direction={complianceSort.direction}
                    onSort={toggleComplianceSort}
                  />
                  <SortableTh<ComplianceSortKey>
                    label={t("reports.profile")}
                    sortKey="profile"
                    activeKey={complianceSort.key}
                    direction={complianceSort.direction}
                    onSort={toggleComplianceSort}
                  />
                  <SortableTh<ComplianceSortKey>
                    label={t("common.status")}
                    sortKey="status"
                    activeKey={complianceSort.key}
                    direction={complianceSort.direction}
                    onSort={toggleComplianceSort}
                  />
                  <SortableTh<ComplianceSortKey>
                    label={t("reports.started")}
                    sortKey="started_at"
                    activeKey={complianceSort.key}
                    direction={complianceSort.direction}
                    onSort={toggleComplianceSort}
                  />
                  <SortableTh<ComplianceSortKey>
                    label={t("reports.finished")}
                    sortKey="finished_at"
                    activeKey={complianceSort.key}
                    direction={complianceSort.direction}
                    onSort={toggleComplianceSort}
                  />
                  <th className="pf-table__col-actions">{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {compliancePagination.items.map((run) => (
                  <tr
                    key={run.id}
                    className={`pf-table__row--clickable${run.id === selectedRunId ? " pf-table__row--selected" : ""}`}
                    onClick={() => onSelectComplianceRun(run.id)}
                  >
                    <td className="pf-table__mono">{run.id}</td>
                    <td>{jobNameById.get(run.job_id) ?? `Job #${run.job_id}`}</td>
                    <td>
                      {(() => {
                        const profileId = jobById.get(run.job_id)?.profile_id;
                        if (profileId == null) return t("common.dash");
                        return profileLabelById.get(profileId) ?? `#${profileId}`;
                      })()}
                    </td>
                    <td>
                      <Badge variant={checkStatusVariant(run.status)}>
                        {runStatusLabel(t, run.status)}
                      </Badge>
                    </td>
                    <td>
                      {run.started_at
                        ? new Date(run.started_at).toLocaleString(dateLocale)
                        : t("common.dash")}
                    </td>
                    <td>
                      {run.finished_at
                        ? new Date(run.finished_at).toLocaleString(dateLocale)
                        : t("common.dash")}
                    </td>
                    <td className="pf-table__col-actions" onClick={(e) => e.stopPropagation()}>
                      <div className="pf-table__actions">
                        <Button
                          variant="secondary"
                          className="pf-btn--sm"
                          onClick={() => onSelectComplianceRun(run.id)}
                        >
                          {t("common.open")}
                        </Button>
                        {canOperate ? (
                          <Button
                            variant="danger-secondary"
                            className="pf-btn--sm"
                            onClick={() => onDeleteComplianceRun(run)}
                            disabled={deletePending}
                          >
                            {t("common.delete")}
                          </Button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination
              page={compliancePagination.page}
              pageSize={compliancePagination.pageSize}
              total={compliancePagination.total}
              onPageChange={compliancePagination.setPage}
            />
          </div>
        )
      ) : category === "playbooks" ? (
        filteredPlaybookRuns.length === 0 ? (
          <div className="pf-reports-runs__state">
            <EmptyState title={t("playbooks.noRuns")} description={t("playbooks.noRunsDesc")} />
          </div>
        ) : (
          <div className="pf-table-wrap">
            <table className="pf-table">
              <thead>
                <tr>
                  <SortableTh<PlaybookSortKey>
                    label={t("jobs.runId")}
                    sortKey="id"
                    activeKey={playbookSort.key}
                    direction={playbookSort.direction}
                    onSort={togglePlaybookSort}
                  />
                  <SortableTh<PlaybookSortKey>
                    label={t("playbooks.playbookCol")}
                    sortKey="playbook"
                    activeKey={playbookSort.key}
                    direction={playbookSort.direction}
                    onSort={togglePlaybookSort}
                  />
                  <SortableTh<PlaybookSortKey>
                    label={t("reports.job")}
                    sortKey="job_name"
                    activeKey={playbookSort.key}
                    direction={playbookSort.direction}
                    onSort={togglePlaybookSort}
                  />
                  <SortableTh<PlaybookSortKey>
                    label={t("common.status")}
                    sortKey="status"
                    activeKey={playbookSort.key}
                    direction={playbookSort.direction}
                    onSort={togglePlaybookSort}
                  />
                  <SortableTh<PlaybookSortKey>
                    label={t("playbooks.hostsCount")}
                    sortKey="hosts"
                    activeKey={playbookSort.key}
                    direction={playbookSort.direction}
                    onSort={togglePlaybookSort}
                  />
                  <SortableTh<PlaybookSortKey>
                    label={t("reports.started")}
                    sortKey="started_at"
                    activeKey={playbookSort.key}
                    direction={playbookSort.direction}
                    onSort={togglePlaybookSort}
                  />
                  <SortableTh<PlaybookSortKey>
                    label={t("reports.finished")}
                    sortKey="finished_at"
                    activeKey={playbookSort.key}
                    direction={playbookSort.direction}
                    onSort={togglePlaybookSort}
                  />
                  <th className="pf-table__col-actions">{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {playbookPagination.items.map((run) => {
                  const playbookLabel = playbookAccessor(run, "playbook");
                  const jobLabel = playbookAccessor(run, "job_name");
                  const hosts = playbookAccessor(run, "hosts");
                  const openHref = canOperate ? `/playbooks?view=jobs&run=${run.id}` : null;

                  return (
                    <tr key={run.id}>
                      <td className="pf-table__mono">{run.id}</td>
                      <td>{playbookLabel || t("common.dash")}</td>
                      <td>{jobLabel || t("common.dash")}</td>
                      <td>
                        <Badge variant={checkStatusVariant(run.status)}>
                          {runStatusLabel(t, run.status)}
                        </Badge>
                      </td>
                      <td>{hosts}</td>
                      <td>
                        {run.started_at
                          ? new Date(run.started_at).toLocaleString(dateLocale)
                          : t("common.dash")}
                      </td>
                      <td>
                        {run.finished_at
                          ? new Date(run.finished_at).toLocaleString(dateLocale)
                          : t("common.dash")}
                      </td>
                      <td className="pf-table__col-actions">
                        <div className="pf-table__actions">
                          {openHref ? (
                            <Link to={openHref} className="pf-btn pf-btn--secondary pf-btn--sm">
                              {t("common.open")}
                            </Link>
                          ) : (
                            <span className="pf-table__muted">{t("common.dash")}</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
            <Pagination
              page={playbookPagination.page}
              pageSize={playbookPagination.pageSize}
              total={playbookPagination.total}
              onPageChange={playbookPagination.setPage}
            />
          </div>
        )
      ) : filteredRemediationRuns.length === 0 ? (
        <div className="pf-reports-runs__state">
          <EmptyState title={t("reports.noRuns")} description={t("remediation.noRunsDesc")} />
        </div>
      ) : (
        <div className="pf-table-wrap">
          <table className="pf-table">
            <thead>
              <tr>
                <SortableTh<RemediationSortKey>
                  label={t("jobs.runId")}
                  sortKey="id"
                  activeKey={remediationSort.key}
                  direction={remediationSort.direction}
                  onSort={toggleRemediationSort}
                />
                <SortableTh<RemediationSortKey>
                  label={t("reports.job")}
                  sortKey="job_name"
                  activeKey={remediationSort.key}
                  direction={remediationSort.direction}
                  onSort={toggleRemediationSort}
                />
                <SortableTh<RemediationSortKey>
                  label={t("common.status")}
                  sortKey="status"
                  activeKey={remediationSort.key}
                  direction={remediationSort.direction}
                  onSort={toggleRemediationSort}
                />
                <SortableTh<RemediationSortKey>
                  label={t("reports.started")}
                  sortKey="started_at"
                  activeKey={remediationSort.key}
                  direction={remediationSort.direction}
                  onSort={toggleRemediationSort}
                />
                <SortableTh<RemediationSortKey>
                  label={t("reports.finished")}
                  sortKey="finished_at"
                  activeKey={remediationSort.key}
                  direction={remediationSort.direction}
                  onSort={toggleRemediationSort}
                />
                <th className="pf-table__col-actions">{t("common.actions")}</th>
              </tr>
            </thead>
            <tbody>
              {remediationPagination.items.map((run) => (
                <tr key={run.id}>
                  <td className="pf-table__mono">{run.id}</td>
                  <td>
                    {remediationNameById.get(run.remediation_job_id) ??
                      `Job #${run.remediation_job_id}`}
                  </td>
                  <td>
                    <Badge variant={checkStatusVariant(run.status)}>
                      {runStatusLabel(t, run.status)}
                    </Badge>
                  </td>
                  <td>
                    {run.started_at
                      ? new Date(run.started_at).toLocaleString(dateLocale)
                      : t("common.dash")}
                  </td>
                  <td>
                    {run.finished_at
                      ? new Date(run.finished_at).toLocaleString(dateLocale)
                      : t("common.dash")}
                  </td>
                  <td className="pf-table__col-actions">
                    <div className="pf-table__actions">
                      <Link to="/remediation" className="pf-btn pf-btn--secondary pf-btn--sm">
                        {t("common.open")}
                      </Link>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <Pagination
            page={remediationPagination.page}
            pageSize={remediationPagination.pageSize}
            total={remediationPagination.total}
            onPageChange={remediationPagination.setPage}
          />
        </div>
      )}
    </div>
  );
}
