import { useQueries, useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";
import { ComplianceRing } from "../components/InsightSummary";
import { scrollAppToTop } from "../components/ScrollToTop";
import { ComplianceTimelineInfographic } from "../components/ComplianceTimelineInfographic";
import { HorizontalBarChart, type HorizontalBarItem } from "../components/TrendsCharts";
import { TrendsListLimitSelect } from "../components/TrendsListLimitSelect";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { Spinner } from "../components/ui/Spinner";
import { useTranslation } from "../i18n/I18nProvider";
import { useTrendsListLimit } from "../utils/trendsListLimit";

const PLATFORM_PERIOD_OPTIONS = [7, 14, 30, 90] as const;
type PlatformPeriodDays = (typeof PLATFORM_PERIOD_OPTIONS)[number];

function HeroMetricTile({
  value,
  label,
  hint,
  to,
  accent,
}: {
  value: number | string;
  label: string;
  hint?: string;
  to?: string;
  accent?: "cyan" | "gold" | "rose" | "neutral";
}) {
  const className = `pf-platform-metric${accent ? ` pf-platform-metric--${accent}` : ""}`;
  const content = (
    <>
      <span className="pf-platform-metric__value">{value}</span>
      <span className="pf-platform-metric__label">{label}</span>
      {hint && <span className="pf-platform-metric__hint">{hint}</span>}
    </>
  );

  if (to) {
    return (
      <Link to={to} className={className} onClick={() => scrollAppToTop()}>
        {content}
      </Link>
    );
  }

  return <div className={className}>{content}</div>;
}

function PlatformScoreCard({
  percent,
  label,
  meta,
  deltaLabel,
  deltaPositive,
  emptyLabel,
}: {
  percent: number | null;
  label: string;
  meta?: string;
  deltaLabel?: string;
  deltaPositive?: boolean;
  emptyLabel: string;
}) {
  return (
    <div className="pf-platform-hero__snapshot-score-panel">
      {percent != null ? (
        <>
          <div className="pf-platform-hero__snapshot-ring-shell">
            <ComplianceRing percent={percent} compact />
          </div>
          <div className="pf-platform-hero__snapshot-score-copy">
            <span className="pf-platform-hero__snapshot-score-label">{label}</span>
            {meta ? <span className="pf-platform-hero__snapshot-score-meta">{meta}</span> : null}
            {deltaLabel ? (
              <span
                className={`pf-platform-hero__snapshot-delta${
                  deltaPositive === true
                    ? " pf-platform-hero__snapshot-delta--up"
                    : deltaPositive === false
                      ? " pf-platform-hero__snapshot-delta--down"
                      : ""
                }`}
              >
                {deltaLabel}
              </span>
            ) : null}
          </div>
        </>
      ) : (
        <div className="pf-platform-hero__snapshot-empty">
          <span className="pf-platform-hero__snapshot-empty-value">—</span>
          <p className="pf-platform-hero__snapshot-empty-label">{emptyLabel}</p>
        </div>
      )}
    </div>
  );
}

function HeroFact({ label, value, meta }: { label: string; value: string; meta?: string }) {
  return (
    <div className="pf-platform-fact">
      <span className="pf-platform-fact__label">{label}</span>
      <span className="pf-platform-fact__value" title={value}>
        {value}
      </span>
      {meta ? <span className="pf-platform-fact__meta">{meta}</span> : null}
    </div>
  );
}

function truncateText(text: string, max = 32): string {
  return text.length > max ? `${text.slice(0, max - 1)}…` : text;
}

function PipelineNav({
  steps,
  ariaLabel,
}: {
  steps: { label: string; to: string; value?: string | number }[];
  ariaLabel: string;
}) {
  return (
    <nav className="pf-platform-pipeline" aria-label={ariaLabel}>
      {steps.map((step, index) => (
        <span key={step.to} className="pf-platform-pipeline__item">
          {index > 0 && (
            <span className="pf-platform-pipeline__sep" aria-hidden>
              ›
            </span>
          )}
          <Link to={step.to} className="pf-platform-pipeline__link" onClick={() => scrollAppToTop()}>
            <span>{step.label}</span>
            {step.value != null && <span className="pf-platform-pipeline__badge">{step.value}</span>}
          </Link>
        </span>
      ))}
    </nav>
  );
}

export function PlatformOverviewPage() {
  const { t } = useTranslation();
  const [platformTrendsDays, setPlatformTrendsDays] = useState<PlatformPeriodDays>(30);
  const [byProfileListLimit, setByProfileListLimit] = useTrendsListLimit("byProfile");
  const [byHostListLimit, setByHostListLimit] = useTrendsListLimit("byHost");

  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api.profiles() });
  const categories = useQuery({ queryKey: ["categories"], queryFn: api.categories });
  const hosts = useQuery({ queryKey: ["hosts"], queryFn: () => api.hosts({ limit: 200 }) });
  const jobs = useQuery({ queryKey: ["jobs"], queryFn: () => api.jobs() });
  const remediations = useQuery({ queryKey: ["remediations"], queryFn: () => api.remediations() });
  const runs = useQuery({
    queryKey: ["job-runs"],
    queryFn: () => api.jobRuns({ limit: 50 }),
    refetchInterval: 15000,
  });

  const runItems = runs.data?.items ?? [];
  const hostItems = hosts.data?.items ?? [];
  const activeHosts = hostItems.filter((host) => host.is_active).length;

  const runStats = useMemo(() => {
    const list = runItems;
    return {
      total: list.length,
      running: list.filter((r) => r.status === "running").length,
      completed: list.filter((r) => r.status === "completed").length,
      failed: list.filter((r) => r.status === "failed" || r.status === "cancelled").length,
    };
  }, [runItems]);

  const activeProfiles = profiles.data?.filter((s) => s.is_active).length ?? 0;
  const inactiveProfiles = (profiles.data?.length ?? 0) - activeProfiles;
  const complianceJobCount = jobs.data?.length ?? 0;
  const activeJobs = jobs.data?.filter((j) => j.is_active).length ?? 0;
  const scheduledJobs = jobs.data?.filter((j) => j.is_scheduled).length ?? 0;
  const remediationJobCount = remediations.data?.length ?? 0;
  const activeRemediations = remediations.data?.filter((j) => j.is_active).length ?? 0;
  const scheduledRemediations = remediations.data?.filter((j) => j.is_scheduled).length ?? 0;

  const completedRuns = useMemo(
    () => runItems.filter((r) => r.status === "completed").slice(0, 5),
    [runItems]
  );

  const rulesQueries = useQueries({
    queries: (profiles.data ?? []).map((profile) => ({
      queryKey: ["profile-rules", profile.id],
      queryFn: () => api.getProfileRules(profile.id),
      staleTime: 120_000,
    })),
  });

  const detailQueries = useQueries({
    queries: (profiles.data ?? []).map((profile) => ({
      queryKey: ["profile-detail", profile.id],
      queryFn: () => api.getProfile(profile.id),
      staleTime: 120_000,
    })),
  });

  const rulesCountByProfileId = useMemo(() => {
    const map = new Map<number, number>();
    (profiles.data ?? []).forEach((profile, index) => {
      map.set(profile.id, rulesQueries[index]?.data?.length ?? 0);
    });
    return map;
  }, [profiles.data, rulesQueries]);

  const totalRules = useMemo(
    () => Array.from(rulesCountByProfileId.values()).reduce((sum, n) => sum + n, 0),
    [rulesCountByProfileId]
  );

  const scriptCounts = useMemo(() => {
    let audit = 0;
    let remediation = 0;
    detailQueries.forEach((query) => {
      audit += query.data?.check_scripts.length ?? 0;
      remediation += query.data?.remediation_scripts?.length ?? 0;
    });
    return { audit, remediation };
  }, [detailQueries]);

  const rulesLoading = rulesQueries.some((q) => q.isLoading);
  const scriptsLoading = detailQueries.some((q) => q.isLoading);

  const trendsTimeline = useQuery({
    queryKey: ["platform-overview-trends-timeline", platformTrendsDays],
    queryFn: () => api.complianceTimeline({ days: platformTrendsDays, limit: 200 }),
  });

  const trendsByProfile = useQuery({
    queryKey: ["platform-overview-trends-profile", platformTrendsDays],
    queryFn: () => api.complianceByProfile({ days: platformTrendsDays }),
  });

  const selectedHostRunId = completedRuns[0]?.id;

  const trendsByHost = useQuery({
    queryKey: ["platform-overview-trends-host", selectedHostRunId],
    queryFn: () => api.complianceByHost(selectedHostRunId!),
    enabled: selectedHostRunId != null,
  });

  const complianceCoverage = useMemo(() => {
    const items = trendsByProfile.data ?? [];
    if (items.length === 0) return null;
    const withRuns = items.filter((item) => item.job_count > 0);
    const avgCompliance =
      withRuns.length > 0
        ? Math.round(
            withRuns.reduce((sum, item) => sum + item.avg_compliance_percent, 0) / withRuns.length
          )
        : null;
    return {
      tracked: withRuns.length,
      total: items.length,
      avgCompliance,
    };
  }, [trendsByProfile.data]);

  const byProfileSummaryBars = useMemo<HorizontalBarItem[]>(
    () =>
      (trendsByProfile.data ?? [])
        .slice()
        .sort((a, b) => b.avg_compliance_percent - a.avg_compliance_percent)
        .slice(0, byProfileListLimit)
        .map((item) => ({
          key: item.profile_id,
          label: item.profile_name,
          value: item.avg_compliance_percent,
        })),
    [trendsByProfile.data, byProfileListLimit]
  );

  const byHostSummaryBars = useMemo<HorizontalBarItem[]>(
    () =>
      (trendsByHost.data ?? [])
        .slice()
        .sort((a, b) => b.compliance_percent - a.compliance_percent)
        .slice(0, byHostListLimit)
        .map((item) => ({
          key: item.host_id,
          label: item.host_name,
          value: item.compliance_percent,
        })),
    [trendsByHost.data, byHostListLimit]
  );

  const platformComplianceSnapshot = useMemo(() => {
    const points = [...(trendsTimeline.data ?? [])].sort(
      (a, b) => new Date(a.finished_at).getTime() - new Date(b.finished_at).getTime()
    );
    if (points.length === 0) return null;

    let checksPassed = 0;
    let checksFailed = 0;
    let checksTotal = 0;
    for (const point of points) {
      checksPassed += point.passed;
      checksFailed += point.failed;
      checksTotal += point.total_checks;
    }

    const otherChecks = Math.max(0, checksTotal - checksPassed - checksFailed);
    const uniqueJobs = new Set(points.map((point) => point.job_id)).size;
    const checkPassRate =
      checksTotal > 0 ? Math.round((checksPassed / checksTotal) * 100) : null;

    let complianceDelta: number | null = null;
    if (points.length >= 2) {
      const mid = Math.max(1, Math.floor(points.length / 2));
      const older = points.slice(0, mid);
      const newer = points.slice(mid);
      const averageCompliance = (items: typeof points) =>
        items.reduce((sum, item) => sum + item.compliance_percent, 0) / items.length;
      complianceDelta = Math.round((averageCompliance(newer) - averageCompliance(older)) * 100) / 100;
    }

    return {
      runCount: points.length,
      uniqueJobs,
      checksPassed,
      checksFailed,
      checksTotal,
      otherChecks,
      checkPassRate,
      complianceDelta,
    };
  }, [trendsTimeline.data]);

  /** Profiles at/above this avg compliance are treated as "in good standing". */
  const PROFILE_HEALTHY_THRESHOLD = 70;

  const platformRingMetrics = useMemo(() => {
    const profileItems = (trendsByProfile.data ?? []).filter((item) => item.job_count > 0);
    const healthyProfiles =
      profileItems.length > 0
        ? Math.round(
            (profileItems.filter((item) => item.avg_compliance_percent >= PROFILE_HEALTHY_THRESHOLD)
              .length /
              profileItems.length) *
              100
          )
        : null;

    const runSuccess =
      runStats.total > 0 ? Math.round((runStats.completed / runStats.total) * 100) : null;

    const profileTotal = profiles.data?.length ?? 0;
    const profilesWithRemediation = detailQueries.filter(
      (query) => (query.data?.remediation_scripts?.length ?? 0) > 0
    ).length;
    const remediationReady =
      !scriptsLoading && profileTotal > 0
        ? Math.round((profilesWithRemediation / profileTotal) * 100)
        : null;

    return {
      checkPassRate: platformComplianceSnapshot?.checkPassRate ?? null,
      checksPassed: platformComplianceSnapshot?.checksPassed ?? 0,
      checksFailed: platformComplianceSnapshot?.checksFailed ?? 0,
      checksTotal: platformComplianceSnapshot?.checksTotal ?? 0,
      healthyProfiles,
      healthyCount:
        profileItems.filter((item) => item.avg_compliance_percent >= PROFILE_HEALTHY_THRESHOLD)
          .length,
      trackedProfiles: profileItems.length,
      healthyThreshold: PROFILE_HEALTHY_THRESHOLD,
      runSuccess,
      remediationReady,
      profilesWithRemediation,
      profileTotal,
    };
  }, [
    trendsByProfile.data,
    runStats.completed,
    runStats.total,
    platformComplianceSnapshot,
    profiles.data,
    detailQueries,
    scriptsLoading,
  ]);

  const profileHighlights = useMemo(() => {
    const items = (trendsByProfile.data ?? []).filter((item) => item.job_count > 0);
    if (items.length === 0) return null;

    const sorted = [...items].sort((a, b) => b.avg_compliance_percent - a.avg_compliance_percent);
    return {
      best: sorted[0],
      worst: sorted[sorted.length - 1],
    };
  }, [trendsByProfile.data]);

  const isLoading = profiles.isLoading || jobs.isLoading || hosts.isLoading;

  const periodControl = (
    <div className="pf-audit-period" role="group" aria-label={t("platformOverview.periodAria")}>
      <span className="pf-audit-period__label">{t("platformOverview.periodLabel")}</span>
      <div className="pf-audit-period__presets">
        {PLATFORM_PERIOD_OPTIONS.map((days) => (
          <button
            key={days}
            type="button"
            className={`pf-audit-period__preset${platformTrendsDays === days ? " is-active" : ""}`}
            aria-pressed={platformTrendsDays === days}
            onClick={() => setPlatformTrendsDays(days)}
          >
            {t("platformOverview.periodDays", { count: days })}
          </button>
        ))}
      </div>
    </div>
  );

  return (
    <>
      <PageHeader
        title={t("platformOverview.title")}
        description={t("platformOverview.description")}
        actions={
          <Link to="/" className="pf-btn pf-btn--secondary" onClick={() => scrollAppToTop()}>
            {t("platformOverview.backToDashboard")}
          </Link>
        }
      />

      <div className="pf-platform-overview">
        <section className="pf-platform-hero">
          <div className="pf-platform-hero__brand">
            <div className="pf-brand-mark pf-brand-mark--lg" aria-hidden />
            <div>
              <p className="pf-platform-hero__eyebrow">{t("platformOverview.eyebrow")}</p>
              <h2 className="pf-platform-hero__title">{t("platformOverview.heroTitle")}</h2>
            </div>
          </div>

          {isLoading ? (
            <div className="pf-platform-hero__loading">
              <Spinner />
            </div>
          ) : (
            <div className="pf-platform-hero__body">
              <PipelineNav
                ariaLabel={t("platformOverview.flowAria")}
                steps={[
                  { label: t("platformOverview.flowHosts"), to: "/hosts", value: activeHosts },
                  { label: t("platformOverview.flowProfiles"), to: "/profiles", value: profiles.data?.length ?? 0 },
                  { label: t("platformOverview.flowJobs"), to: "/jobs", value: complianceJobCount + remediationJobCount },
                  { label: t("platformOverview.flowChecks"), to: "/profiles", value: rulesLoading ? "…" : totalRules },
                  {
                    label: t("platformOverview.flowCompliance"),
                    to: "/trends",
                    value: complianceCoverage?.avgCompliance != null ? `${complianceCoverage.avgCompliance}%` : "—",
                  },
                ]}
              />

              <section className="pf-platform-hero__snapshot" aria-label={t("platformOverview.heroComplianceBoardAria")}>
                <div className="pf-platform-hero__snapshot-header">
                  <div className="pf-platform-hero__snapshot-heading">
                    <h3 className="pf-platform-hero__snapshot-title">{t("platformOverview.heroComplianceBoardTitle")}</h3>
                    {platformComplianceSnapshot ? (
                      <p className="pf-platform-hero__snapshot-subtitle">
                        {t("platformOverview.heroPlatformScope", {
                          days: platformTrendsDays,
                          runs: platformComplianceSnapshot.runCount,
                          jobs: platformComplianceSnapshot.uniqueJobs,
                          hosts: activeHosts,
                        })}
                      </p>
                    ) : null}
                  </div>
                  <div className="pf-platform-hero__snapshot-actions">
                    <div className="pf-platform-period" role="group" aria-label={t("platformOverview.periodAria")}>
                      <span className="pf-platform-period__label">{t("platformOverview.periodLabel")}</span>
                      <div className="pf-platform-period__presets">
                        {PLATFORM_PERIOD_OPTIONS.map((days) => (
                          <button
                            key={days}
                            type="button"
                            className={`pf-platform-period__preset${platformTrendsDays === days ? " is-active" : ""}`}
                            aria-pressed={platformTrendsDays === days}
                            onClick={() => setPlatformTrendsDays(days)}
                          >
                            {t("platformOverview.periodDays", { count: days })}
                          </button>
                        ))}
                      </div>
                    </div>
                    <Link to="/trends" className="pf-platform-hero__snapshot-link" onClick={() => scrollAppToTop()}>
                      {t("nav.trends")} →
                    </Link>
                  </div>
                </div>

                <div className="pf-platform-hero__snapshot-main pf-platform-hero__snapshot-rings">
                  <PlatformScoreCard
                    percent={complianceCoverage?.avgCompliance ?? null}
                    label={t("platformOverview.profilesAvgCompliance")}
                    meta={
                      complianceCoverage
                        ? t("platformOverview.profilesTracked", {
                            tracked: complianceCoverage.tracked,
                            total: complianceCoverage.total,
                          })
                        : undefined
                    }
                    deltaLabel={
                      platformComplianceSnapshot?.complianceDelta != null
                        ? t("platformOverview.heroComplianceDelta", {
                            delta: `${platformComplianceSnapshot.complianceDelta > 0 ? "+" : ""}${platformComplianceSnapshot.complianceDelta}`,
                          })
                        : undefined
                    }
                    deltaPositive={
                      platformComplianceSnapshot?.complianceDelta != null
                        ? platformComplianceSnapshot.complianceDelta >= 0
                        : undefined
                    }
                    emptyLabel={t("platformOverview.profilesNoCompliance")}
                  />
                  <PlatformScoreCard
                    percent={platformRingMetrics.checkPassRate}
                    label={t("platformOverview.heroRingCheckPass")}
                    meta={
                      platformRingMetrics.checksTotal > 0
                        ? t("platformOverview.heroRingCheckPassMeta", {
                            passed: platformRingMetrics.checksPassed,
                            failed: platformRingMetrics.checksFailed,
                            total: platformRingMetrics.checksTotal,
                          })
                        : undefined
                    }
                    emptyLabel={t("platformOverview.flowComplianceEmpty")}
                  />
                  <PlatformScoreCard
                    percent={platformRingMetrics.healthyProfiles}
                    label={t("platformOverview.heroRingProfilesHealthy")}
                    meta={
                      platformRingMetrics.trackedProfiles > 0
                        ? t("platformOverview.heroRingProfilesHealthyMeta", {
                            healthy: platformRingMetrics.healthyCount,
                            total: platformRingMetrics.trackedProfiles,
                            threshold: platformRingMetrics.healthyThreshold,
                          })
                        : undefined
                    }
                    emptyLabel={t("platformOverview.profilesNoCompliance")}
                  />
                  <PlatformScoreCard
                    percent={platformRingMetrics.runSuccess}
                    label={t("platformOverview.heroRingRunSuccess")}
                    meta={t("platformOverview.heroRingRunSuccessMeta", {
                      completed: runStats.completed,
                      failed: runStats.failed,
                    })}
                    emptyLabel={t("platformOverview.flowComplianceEmpty")}
                  />
                  <PlatformScoreCard
                    percent={platformRingMetrics.remediationReady}
                    label={t("platformOverview.heroRingRemediationReady")}
                    meta={
                      platformRingMetrics.profileTotal > 0 && !scriptsLoading
                        ? t("platformOverview.heroRingRemediationReadyMeta", {
                            ready: platformRingMetrics.profilesWithRemediation,
                            total: platformRingMetrics.profileTotal,
                          })
                        : undefined
                    }
                    emptyLabel={
                      scriptsLoading
                        ? "…"
                        : t("platformOverview.heroRingRemediationReadyEmpty")
                    }
                  />
                </div>

                <div className="pf-platform-hero__snapshot-facts">
                    <HeroFact
                      label={t("platformOverview.heroActivityRunsLabel")}
                      value={t("platformOverview.heroActivityRunsDetail", {
                        running: runStats.running,
                        completed: runStats.completed,
                        failed: runStats.failed,
                      })}
                    />
                    <HeroFact
                      label={t("platformOverview.heroActivityScriptsLabel")}
                      value={
                        scriptsLoading
                          ? "…"
                          : t("platformOverview.heroActivityScriptsDetail", {
                              audit: scriptCounts.audit,
                              remediation: scriptCounts.remediation,
                            })
                      }
                    />
                    <HeroFact
                      label={t("platformOverview.heroActivityJobsLabel")}
                      value={t("platformOverview.heroActivityJobsDetail", {
                        compliance: complianceJobCount,
                        remediation: remediationJobCount,
                        scheduled: scheduledJobs + scheduledRemediations,
                      })}
                    />
                    {profileHighlights ? (
                      <>
                        <HeroFact
                          label={t("platformOverview.heroBestProfile")}
                          value={`${truncateText(profileHighlights.best.profile_name)} · ${profileHighlights.best.avg_compliance_percent}%`}
                        />
                        <HeroFact
                          label={t("platformOverview.heroWorstProfile")}
                          value={`${truncateText(profileHighlights.worst.profile_name)} · ${profileHighlights.worst.avg_compliance_percent}%`}
                        />
                      </>
                    ) : null}
                </div>
              </section>

              <div className="pf-platform-hero__metrics pf-platform-hero__metrics--strip" aria-label={t("platformOverview.heroKpisAria")}>
                <HeroMetricTile
                  value={activeHosts}
                  label={t("platformOverview.flowHosts")}
                  hint={t("platformOverview.flowHostsHint", { total: hostItems.length })}
                  to="/hosts"
                  accent="cyan"
                />
                <HeroMetricTile
                  value={profiles.data?.length ?? 0}
                  label={t("platformOverview.flowProfiles")}
                  hint={t("platformOverview.flowProfilesHint", {
                    active: activeProfiles,
                    categories: categories.data?.length ?? 0,
                  })}
                  to="/profiles"
                  accent="cyan"
                />
                <HeroMetricTile
                  value={complianceJobCount + remediationJobCount}
                  label={t("platformOverview.flowJobs")}
                  hint={t("platformOverview.flowJobsHint", {
                    active: activeJobs + activeRemediations,
                    scheduled: scheduledJobs + scheduledRemediations,
                  })}
                  to="/jobs"
                  accent="gold"
                />
                <HeroMetricTile
                  value={rulesLoading ? "…" : totalRules}
                  label={t("platformOverview.flowChecks")}
                  hint={
                    scriptsLoading
                      ? "…"
                      : t("platformOverview.flowChecksHint", {
                          scripts: scriptCounts.audit,
                          remediation: scriptCounts.remediation,
                        })
                  }
                  to="/profiles"
                  accent="rose"
                />
                <HeroMetricTile
                  value={runStats.completed}
                  label={t("platformOverview.heroRunsCompleted")}
                  hint={t("platformOverview.heroActivityRuns", {
                    running: runStats.running,
                    total: runStats.total,
                  })}
                  to="/jobs"
                  accent="neutral"
                />
                <HeroMetricTile
                  value={categories.data?.length ?? 0}
                  label={t("platformOverview.heroCategories")}
                  hint={t("platformOverview.heroActivityProfiles", {
                    inactive: inactiveProfiles,
                    scheduled: scheduledJobs + scheduledRemediations,
                  })}
                  to="/profiles"
                  accent="neutral"
                />
              </div>
            </div>
          )}
        </section>

        <Panel
          title={t("platformOverview.trendsSection")}
          description={t("platformOverview.trendsSectionDesc")}
          className="pf-platform-panel pf-platform-panel--wide"
          toolbar={periodControl}
          collapsible={false}
        >
          <div className="pf-platform-trends">
            <section className="pf-platform-trends__block pf-platform-trends__block--timeline">
              <div className="pf-platform-trends__head">
                <h3>{t("platformOverview.trendsOverTime")}</h3>
                <span>{t("platformOverview.trendsPeriodDays", { count: platformTrendsDays })}</span>
              </div>
              {trendsTimeline.isLoading ? (
                <Spinner />
              ) : (trendsTimeline.data ?? []).length === 0 ? (
                <p className="pf-table__muted">{t("trends.noData")}</p>
              ) : (
                <ComplianceTimelineInfographic
                  points={trendsTimeline.data ?? []}
                  days={platformTrendsDays}
                  ariaLabel={t("platformOverview.trendsOverTimeAria")}
                />
              )}
            </section>

            <section className="pf-platform-trends__block">
              <div className="pf-platform-trends__head">
                <h3>{t("platformOverview.trendsByProfile")}</h3>
                <TrendsListLimitSelect value={byProfileListLimit} onChange={setByProfileListLimit} />
              </div>
              {trendsByProfile.isLoading ? (
                <Spinner />
              ) : byProfileSummaryBars.length === 0 ? (
                <p className="pf-table__muted">{t("trends.noData")}</p>
              ) : (
                <HorizontalBarChart
                  items={byProfileSummaryBars}
                  ariaLabel={t("platformOverview.trendsByProfileAria")}
                />
              )}
            </section>

            <section className="pf-platform-trends__block">
              <div className="pf-platform-trends__head">
                <h3>{t("platformOverview.trendsByHost")}</h3>
                <div className="pf-platform-trends__head-meta">
                  <span>
                    {selectedHostRunId != null
                      ? t("platformOverview.trendsRunLabel", { id: selectedHostRunId })
                      : t("trends.noRuns")}
                  </span>
                  <TrendsListLimitSelect value={byHostListLimit} onChange={setByHostListLimit} />
                </div>
              </div>
              {trendsByHost.isLoading ? (
                <Spinner />
              ) : byHostSummaryBars.length === 0 ? (
                <p className="pf-table__muted">{t("trends.noData")}</p>
              ) : (
                <HorizontalBarChart
                  items={byHostSummaryBars}
                  ariaLabel={t("platformOverview.trendsByHostAria")}
                />
              )}
            </section>
          </div>
          <div className="pf-platform-panel__footer">
            <Link to="/trends" className="pf-platform-panel__link" onClick={() => scrollAppToTop()}>
              {t("nav.trends")} →
            </Link>
          </div>
        </Panel>
      </div>
    </>
  );
}
