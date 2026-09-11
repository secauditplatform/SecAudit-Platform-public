import { useQueries, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef } from "react";
import { Link } from "react-router-dom";
import { api, type JobRun, type ReportSummary } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { scrollAppToTop } from "../components/ScrollToTop";
import { MiniComplianceRing } from "../components/InsightSummary";
import { Badge } from "../components/ui/Badge";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { Spinner } from "../components/ui/Spinner";
import { StatTile } from "../components/ui/StatTile";
import { useTranslation } from "../i18n/I18nProvider";
import { runStatusVariant } from "../utils/statusVariant";

function RecentJobCard({
  run,
  jobName,
  summary,
  summaryLoading,
  dateLocale,
}: {
  run: JobRun;
  jobName: string;
  summary?: ReportSummary;
  summaryLoading: boolean;
  dateLocale: string;
}) {
  const { t } = useTranslation();
  const timestamp = run.started_at
    ? new Date(run.started_at).toLocaleString(dateLocale, {
        day: "2-digit",
        month: "short",
        hour: "2-digit",
        minute: "2-digit",
      })
    : t("common.dash");

  return (
    <Link to={`/reports?run=${run.id}`} className="pf-job-card">
      <div className="pf-job-card__header">
        <span className="pf-job-card__run">#{run.id}</span>
        <Badge variant={runStatusVariant(run.status)}>{run.status}</Badge>
      </div>
      <h3 className="pf-job-card__title">{jobName}</h3>
      <p className="pf-job-card__time">{timestamp}</p>
      <div className="pf-job-card__stats">
        {run.status === "completed" ? (
          summaryLoading ? (
            <span className="pf-job-card__loading">{t("common.loading")}</span>
          ) : summary ? (
            <>
              <MiniComplianceRing percent={summary.compliance_percent} />
              <div className="pf-job-card__checks">
                <span className="pf-job-card__pass">PASS {summary.passed}</span>
                <span className="pf-job-card__fail">FAIL {summary.failed}</span>
              </div>
            </>
          ) : (
            <span className="pf-table__muted">{t("dashboard.noSummary")}</span>
          )
        ) : (
          <span className="pf-table__muted">{t("dashboard.noSummary")}</span>
        )}
      </div>
      <span className="pf-job-card__link">{t("dashboard.viewReport")} →</span>
    </Link>
  );
}

export function DashboardPage() {
  const { t, dateLocale } = useTranslation();
  const { isAuditorPortal, canOperate, canAccessRemediation } = useAuth();
  const queryClient = useQueryClient();
  const health = useQuery({ queryKey: ["health"], queryFn: api.health, refetchInterval: 30000 });
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api.profiles() });
  const hosts = useQuery({ queryKey: ["hosts"], queryFn: () => api.hosts({ limit: 200 }) });
  const jobs = useQuery({ queryKey: ["jobs"], queryFn: () => api.jobs() });
  const remediations = useQuery({
    queryKey: ["remediations"],
    queryFn: () => api.remediations(),
    enabled: canAccessRemediation,
  });
  const playbooks = useQuery({
    queryKey: ["playbooks"],
    queryFn: () => api.playbooks(),
    enabled: !isAuditorPortal,
  });
  const credentials = useQuery({
    queryKey: ["credentials"],
    queryFn: api.credentials,
    enabled: canOperate,
  });
  const runs = useQuery({
    queryKey: ["job-runs"],
    queryFn: () => api.jobRuns({ limit: 200 }),
    refetchInterval: 10000,
  });

  const dataLoadError =
    profiles.isError ||
    hosts.isError ||
    jobs.isError ||
    runs.isError ||
    (canAccessRemediation && remediations.isError) ||
    (!isAuditorPortal && playbooks.isError) ||
    (canOperate && credentials.isError);

  const dataLoading =
    profiles.isLoading ||
    hosts.isLoading ||
    jobs.isLoading ||
    runs.isLoading ||
    (canAccessRemediation && remediations.isLoading) ||
    (!isAuditorPortal && playbooks.isLoading) ||
    (canOperate && credentials.isLoading);

  const hostItems = hosts.data?.items ?? [];
  const runItems = runs.data?.items ?? [];

  const apiOnline = health.data?.status === "ok";
  const prevApiOnline = useRef<boolean | null>(null);

  const retryDashboard = () => {
    void queryClient.invalidateQueries({ queryKey: ["profiles"] });
    void queryClient.invalidateQueries({ queryKey: ["hosts"] });
    void queryClient.invalidateQueries({ queryKey: ["jobs"] });
    void queryClient.invalidateQueries({ queryKey: ["job-runs"] });
    void queryClient.invalidateQueries({ queryKey: ["remediations"] });
    void queryClient.invalidateQueries({ queryKey: ["playbooks"] });
    void queryClient.invalidateQueries({ queryKey: ["credentials"] });
    void queryClient.invalidateQueries({ queryKey: ["dashboard-summary"] });
  };

  useEffect(() => {
    const wasOffline = prevApiOnline.current === false;
    prevApiOnline.current = apiOnline;
    if (!apiOnline || !wasOffline) return;
    retryDashboard();
  }, [apiOnline, queryClient]);

  const statValue = (loading: boolean, errored: boolean, value: number | string) => {
    if (loading) return "…";
    if (errored) return "—";
    return value;
  };
  const activeHosts = hostItems.filter((h) => h.is_active).length;
  const activeJobs = jobs.data?.filter((j) => j.is_active).length ?? 0;
  const scheduledJobs = jobs.data?.filter((j) => j.is_scheduled).length ?? 0;
  const activeRemediations = remediations.data?.filter((j) => j.is_active).length ?? 0;
  const scheduledRemediations = remediations.data?.filter((j) => j.is_scheduled).length ?? 0;

  const runStats = useMemo(() => {
    const list = runItems;
    return {
      total: list.length,
      running: list.filter((r) => r.status === "running").length,
      completed: list.filter((r) => r.status === "completed").length,
      failed: list.filter((r) => r.status === "failed" || r.status === "cancelled").length,
      pending: list.filter((r) => r.status === "pending").length,
    };
  }, [runItems]);

  const recentRuns = useMemo(() => runItems.slice(0, 12), [runItems]);

  const summaryQueries = useQueries({
    queries: recentRuns
      .filter((r) => r.status === "completed")
      .map((run) => ({
        queryKey: ["dashboard-summary", run.id],
        queryFn: () => api.runSummary(run.id),
        staleTime: 60_000,
      })),
  });

  const summaryByRunId = useMemo(() => {
    const map = new Map<number, ReportSummary>();
    recentRuns
      .filter((r) => r.status === "completed")
      .forEach((run, index) => {
        const data = summaryQueries[index]?.data;
        if (data) map.set(run.id, data);
      });
    return map;
  }, [recentRuns, summaryQueries]);

  const summaryLoadingByRunId = useMemo(() => {
    const map = new Map<number, boolean>();
    recentRuns
      .filter((r) => r.status === "completed")
      .forEach((run, index) => {
        map.set(run.id, summaryQueries[index]?.isLoading ?? false);
      });
    return map;
  }, [recentRuns, summaryQueries]);

  const jobNameById = useMemo(() => {
    const map = new Map<number, string>();
    jobs.data?.forEach((j) => map.set(j.id, j.name));
    return map;
  }, [jobs.data]);

  return (
    <>
      <PageHeader
        title={t("dashboard.title")}
        description={isAuditorPortal ? t("auditorPortal.dashboardDescription") : t("dashboard.description")}
      />

      {dataLoadError ? (
        <div className="pf-alert pf-alert--error pf-dashboard-load-error">
          <p>{t("dashboard.loadError")}</p>
          <button type="button" className="pf-btn pf-btn--secondary pf-btn--sm" onClick={retryDashboard}>
            {t("dashboard.retryLoad")}
          </button>
        </div>
      ) : null}

      <div className={`pf-dashboard-hero${apiOnline ? " pf-dashboard-hero--online" : ""}`}>
        <div className="pf-dashboard-hero__brand">
          {isAuditorPortal ? (
            <span className="pf-brand-mark" aria-hidden />
          ) : (
            <Link
              to="/overview"
              className="pf-brand-mark pf-brand-mark--link"
              aria-label={t("dashboard.openInfographic")}
              onClick={() => scrollAppToTop()}
            />
          )}
          <div className="pf-dashboard-hero__content">
            <div className="pf-dashboard-hero__badge">
              <span className={`pf-dashboard-hero__dot${apiOnline ? " pf-dashboard-hero__dot--live" : ""}`} />
              {apiOnline ? t("dashboard.platformOnline") : t("dashboard.checkingApi")}
            </div>
            <h2 className="pf-dashboard-hero__title">{health.data?.app_name ?? "SecAudit Platform"}</h2>
            <p className="pf-dashboard-hero__desc">
              {isAuditorPortal
                ? t("auditorPortal.heroDesc", {
                    hosts: activeHosts,
                    profiles: profiles.data?.length ?? 0,
                    runs: runStats.completed,
                  })
                : t("dashboard.heroDesc", {
                    hosts: activeHosts,
                    jobs: activeJobs,
                    profiles: profiles.data?.length ?? 0,
                  })}
            </p>
          </div>
        </div>
      </div>

      <div className="pf-stat-grid pf-dashboard-stats">
        <StatTile
          label={t("dashboard.hosts")}
          value={statValue(hosts.isLoading, hosts.isError, activeHosts)}
          variant="info"
          sublabel={t("dashboard.hostsTotal", { count: hosts.data?.total ?? hostItems.length })}
          to={isAuditorPortal ? undefined : "/hosts"}
        />
        {!isAuditorPortal ? (
          <>
            <StatTile
              label={t("dashboard.jobs")}
              value={statValue(jobs.isLoading, jobs.isError, activeJobs)}
              sublabel={t("dashboard.jobsScheduled", { count: scheduledJobs })}
              to="/jobs"
            />
            {canAccessRemediation ? (
              <StatTile
                label={t("dashboard.remediations")}
                value={statValue(remediations.isLoading, remediations.isError, activeRemediations)}
                sublabel={t("dashboard.remediationsScheduled", { count: scheduledRemediations })}
                to="/remediation"
              />
            ) : null}
          </>
        ) : null}
        <StatTile
          label={t("dashboard.profiles")}
          value={statValue(profiles.isLoading, profiles.isError, profiles.data?.length ?? 0)}
          variant="success"
          to={isAuditorPortal ? undefined : "/profiles"}
        />
        {!isAuditorPortal ? (
          <>
            <StatTile
              label={t("nav.playbooks")}
              value={statValue(playbooks.isLoading, playbooks.isError, playbooks.data?.length ?? 0)}
              to="/playbooks"
            />
          </>
        ) : null}
        {canOperate ? (
          <StatTile
            label={t("dashboard.credentials")}
            value={statValue(credentials.isLoading, credentials.isError, credentials.data?.length ?? 0)}
            to="/credentials"
          />
        ) : null}
        <StatTile
          label={t("dashboard.activeRuns")}
          value={statValue(runs.isLoading, runs.isError, runStats.running + runStats.pending)}
          variant={runStats.running > 0 ? "warning" : "default"}
          sublabel={t("dashboard.runsCompleted", { count: runStats.completed })}
          to="/reports"
        />
      </div>

      <Panel
        title={t("dashboard.latestJobs")}
        toolbar={
          <Link to="/reports" className="pf-link">
            {isAuditorPortal ? t("auditorPortal.allReports") : t("dashboard.allJobs")}
          </Link>
        }
      >
        <p className="pf-dashboard-panel-desc">{t("dashboard.latestJobsDesc")}</p>
        {runs.isLoading || dataLoading ? (
          <Spinner />
        ) : runs.isError ? (
          <p className="pf-dashboard-empty">{t("dashboard.loadError")}</p>
        ) : recentRuns.length === 0 ? (
          <p className="pf-dashboard-empty">{t("dashboard.noRunsYet")}</p>
        ) : (
          <div className="pf-job-card-grid">
            {recentRuns.map((run) => (
              <RecentJobCard
                key={run.id}
                run={run}
                jobName={jobNameById.get(run.job_id) ?? `Job #${run.job_id}`}
                summary={summaryByRunId.get(run.id)}
                summaryLoading={summaryLoadingByRunId.get(run.id) ?? false}
                dateLocale={dateLocale}
              />
            ))}
          </div>
        )}
      </Panel>

      {!isAuditorPortal ? (
        <Panel title={t("dashboard.quickStart")} className="pf-dashboard-quick-start">
          <ol className="pf-steps pf-steps--wide">
            <li>
              <div className="pf-steps__body">
                <span className="pf-steps__title">{t("dashboard.step1")}</span>
                <p className="pf-steps__desc">{t("dashboard.step1Desc")}</p>
              </div>
              <Link to="/profiles" className="pf-steps__link">
                {t("nav.profiles")}
              </Link>
            </li>
            <li>
              <div className="pf-steps__body">
                <span className="pf-steps__title">{t("dashboard.step2")}</span>
                <p className="pf-steps__desc">{t("dashboard.step2Desc")}</p>
              </div>
              <span className="pf-steps__links">
                <Link to="/credentials" className="pf-steps__link">
                  {t("nav.credentials")}
                </Link>
                <Link to="/hosts" className="pf-steps__link">
                  {t("nav.hosts")}
                </Link>
              </span>
            </li>
            <li>
              <div className="pf-steps__body">
                <span className="pf-steps__title">{t("dashboard.step3")}</span>
                <p className="pf-steps__desc">{t("dashboard.step3Desc")}</p>
              </div>
              <Link to="/jobs" className="pf-steps__link">
                {t("nav.jobs")}
              </Link>
            </li>
            <li>
              <div className="pf-steps__body">
                <span className="pf-steps__title">{t("dashboard.step4")}</span>
                <p className="pf-steps__desc">{t("dashboard.step4Desc")}</p>
              </div>
              <Link to="/reports" className="pf-steps__link">
                {t("nav.reports")}
              </Link>
            </li>
          </ol>
        </Panel>
      ) : null}
    </>
  );
}
