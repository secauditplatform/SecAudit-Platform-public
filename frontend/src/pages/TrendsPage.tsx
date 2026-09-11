import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type ComplianceTimelinePoint, type ProfileCompliancePoint, type WeekdayHeatCell } from "../api/client";
import {
  ComplianceHeatmap,
  HeatmapDayRuns,
  heatCellKey,
  JobCards,
  PlatformCards,
  timelinePointsForHeatCell,
} from "../components/ComplianceOpsCharts";
import { complianceColor } from "../components/InsightSummary";
import { TimelineChart } from "../components/TrendsCharts";
import { Button } from "../components/ui/Button";
import { DateInput } from "../components/ui/DateInput";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { Spinner } from "../components/ui/Spinner";
import { scrollAppToTop } from "../components/ScrollToTop";
import { useTranslation } from "../i18n/I18nProvider";

function complianceBarClass(percent: number): string {
  if (percent >= 80) return "pf-trends-bar--good";
  if (percent >= 50) return "pf-trends-bar--warn";
  return "pf-trends-bar--bad";
}

type OpsMetricAccent = "cyan" | "gold" | "rose" | "neutral";

function OpsMetricTile({
  value,
  label,
  to,
  accent,
}: {
  value: string;
  label: string;
  to?: string;
  accent?: OpsMetricAccent;
}) {
  const className = `pf-platform-metric${accent ? ` pf-platform-metric--${accent}` : ""}`;
  const content = (
    <>
      <span className="pf-platform-metric__value">{value}</span>
      <span className="pf-platform-metric__label">{label}</span>
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

const DAY_OPTIONS = [7, 30, 90] as const;

function utcDateKey(offsetFromToday = 0): string {
  const date = new Date();
  date.setUTCHours(0, 0, 0, 0);
  date.setUTCDate(date.getUTCDate() - offsetFromToday);
  return date.toISOString().slice(0, 10);
}

function periodFromDays(days: number): { from: string; to: string } {
  return { from: utcDateKey(days - 1), to: utcDateKey(0) };
}

type TimelineTableFilters = {
  run: string;
  job: string;
  finished: string;
  complianceMin: string;
  complianceMax: string;
};

const EMPTY_TABLE_FILTERS: TimelineTableFilters = {
  run: "",
  job: "",
  finished: "",
  complianceMin: "",
  complianceMax: "",
};

function filterTimelinePoints(
  points: ComplianceTimelinePoint[],
  filters: TimelineTableFilters,
  dateLocale: string
): ComplianceTimelinePoint[] {
  const runQuery = filters.run.trim().toLowerCase();
  const jobQuery = filters.job.trim().toLowerCase();
  const finishedQuery = filters.finished.trim().toLowerCase();
  const min =
    filters.complianceMin.trim() === "" ? null : Number.parseFloat(filters.complianceMin);
  const max =
    filters.complianceMax.trim() === "" ? null : Number.parseFloat(filters.complianceMax);

  return points.filter((point) => {
    if (runQuery) {
      const runText = String(point.run_id);
      if (!runText.includes(runQuery) && !`#${runText}`.includes(runQuery)) return false;
    }
    if (jobQuery && !point.job_name.toLowerCase().includes(jobQuery)) return false;
    if (finishedQuery) {
      const localized = new Date(point.finished_at).toLocaleString(dateLocale).toLowerCase();
      const raw = point.finished_at.toLowerCase();
      if (!localized.includes(finishedQuery) && !raw.includes(finishedQuery)) return false;
    }
    if (min != null && !Number.isNaN(min) && point.compliance_percent < min) return false;
    if (max != null && !Number.isNaN(max) && point.compliance_percent > max) return false;
    return true;
  });
}

function hasActiveTableFilters(filters: TimelineTableFilters): boolean {
  return Object.values(filters).some((value) => value.trim() !== "");
}

function complianceTone(percent: number): "good" | "warn" | "bad" {
  if (percent >= 80) return "good";
  if (percent >= 50) return "warn";
  return "bad";
}

export function TrendsPage() {
  const { t, dateLocale } = useTranslation();
  const [period, setPeriod] = useState(() => periodFromDays(30));
  const days = useMemo(() => {
    const from = new Date(`${period.from}T00:00:00Z`).getTime();
    const to = new Date(`${period.to}T00:00:00Z`).getTime();
    return Math.max(1, Math.round((to - from) / 86_400_000) + 1);
  }, [period]);
  const periodQuery = { date_from: period.from, date_to: period.to, days };
  const [jobFilter, setJobFilter] = useState<string>("all");
  const [profileFilter, setProfileFilter] = useState<string>("all");
  const [tableFilters, setTableFilters] = useState<TimelineTableFilters>(EMPTY_TABLE_FILTERS);
  const [refineOpen, setRefineOpen] = useState(false);
  const [selectedHeatCell, setSelectedHeatCell] = useState<WeekdayHeatCell | null>(null);

  const jobs = useQuery({ queryKey: ["jobs"], queryFn: () => api.jobs() });
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api.profiles() });

  const jobId = jobFilter === "all" ? undefined : Number(jobFilter);
  const profileId = profileFilter === "all" ? undefined : Number(profileFilter);

  const timeline = useQuery({
    queryKey: ["trends-timeline", period.from, period.to, jobId, profileId],
    queryFn: () => api.complianceTimeline({ job_id: jobId, profile_id: profileId, ...periodQuery }),
  });

  const byProfile = useQuery({
    queryKey: ["trends-by-profile", period.from, period.to],
    queryFn: () => api.complianceByProfile(periodQuery),
  });
  const operations = useQuery({
    queryKey: ["trends-operations", period.from, period.to],
    queryFn: () => api.complianceOperations(periodQuery),
  });

  const timelinePoints = timeline.data ?? [];

  const filteredTimelinePoints = useMemo(
    () => filterTimelinePoints(timelinePoints, tableFilters, dateLocale),
    [timelinePoints, tableFilters, dateLocale]
  );

  const activeTableFilters = hasActiveTableFilters(tableFilters);

  const chartPoints = activeTableFilters ? filteredTimelinePoints : timelinePoints;

  const chartStats = useMemo(() => {
    if (chartPoints.length === 0) return null;
    const chronological = [...chartPoints].sort(
      (a, b) => new Date(a.finished_at).getTime() - new Date(b.finished_at).getTime()
    );
    const sum = chartPoints.reduce((acc, point) => acc + point.compliance_percent, 0);
    const first = chronological[0];
    const latest = chronological[chronological.length - 1];
    const latestPct = Math.round(latest.compliance_percent);
    const firstPct = Math.round(first.compliance_percent);
    return {
      avg: Math.round(sum / chartPoints.length),
      count: chartPoints.length,
      latest: latestPct,
      delta: latestPct - firstPct,
      passed: chartPoints.reduce((acc, point) => acc + point.passed, 0),
      failed: chartPoints.reduce((acc, point) => acc + point.failed, 0),
    };
  }, [chartPoints]);

  const activeScopeFilters = jobFilter !== "all" || profileFilter !== "all";

  const filterChips = useMemo(() => {
    const chips: { key: string; label: string; onClear: () => void }[] = [];
    if (jobFilter !== "all") {
      const jobName = jobs.data?.find((job) => String(job.id) === jobFilter)?.name ?? jobFilter;
      chips.push({
        key: "scope-job",
        label: `${t("trends.jobFilter")}: ${jobName}`,
        onClear: () => setJobFilter("all"),
      });
    }
    if (profileFilter !== "all") {
      const profileName =
        profiles.data?.find((profile) => String(profile.id) === profileFilter)?.label ?? profileFilter;
      chips.push({
        key: "scope-profile",
        label: `${t("trends.profileFilter")}: ${profileName}`,
        onClear: () => setProfileFilter("all"),
      });
    }
    if (tableFilters.run.trim()) {
      chips.push({
        key: "run",
        label: `${t("trends.run")}: ${tableFilters.run.trim()}`,
        onClear: () => setTableFilters((f) => ({ ...f, run: "" })),
      });
    }
    if (tableFilters.job.trim()) {
      chips.push({
        key: "job",
        label: `${t("trends.job")}: ${tableFilters.job.trim()}`,
        onClear: () => setTableFilters((f) => ({ ...f, job: "" })),
      });
    }
    if (tableFilters.finished.trim()) {
      chips.push({
        key: "finished",
        label: `${t("trends.finished")}: ${tableFilters.finished.trim()}`,
        onClear: () => setTableFilters((f) => ({ ...f, finished: "" })),
      });
    }
    const min = tableFilters.complianceMin.trim();
    const max = tableFilters.complianceMax.trim();
    if (min || max) {
      const range = min && max ? `${min}–${max}%` : min ? `≥ ${min}%` : `≤ ${max}%`;
      chips.push({
        key: "compliance",
        label: `${t("trends.complianceRange")}: ${range}`,
        onClear: () => setTableFilters((f) => ({ ...f, complianceMin: "", complianceMax: "" })),
      });
    }
    return chips;
  }, [jobFilter, profileFilter, tableFilters, jobs.data, profiles.data, t]);

  useEffect(() => {
    if (activeTableFilters) setRefineOpen(true);
  }, [activeTableFilters]);

  useEffect(() => {
    setSelectedHeatCell(null);
  }, [period.from, period.to, jobFilter, profileFilter]);

  const profileRows = useMemo(
    () =>
      [...(byProfile.data ?? [])].sort(
        (a, b) => b.avg_compliance_percent - a.avg_compliance_percent
      ),
    [byProfile.data]
  );

  const profileSummary = useMemo(() => {
    if (profileRows.length === 0) return null;
    const avg = Math.round(
      profileRows.reduce((sum, row) => sum + row.avg_compliance_percent, 0) / profileRows.length
    );
    const jobsTotal = profileRows.reduce((sum, row) => sum + row.job_count, 0);
    return { count: profileRows.length, avg, jobsTotal };
  }, [profileRows]);

  const clearTableFilters = () => setTableFilters(EMPTY_TABLE_FILTERS);
  const ops = operations.data;
  const kpis = ops?.kpis;
  const weekdayLabels = [
    t("trends.weekdayMon"),
    t("trends.weekdayTue"),
    t("trends.weekdayWed"),
    t("trends.weekdayThu"),
    t("trends.weekdayFri"),
    t("trends.weekdaySat"),
    t("trends.weekdaySun"),
  ];
  const platformLabel = (platform: string) => {
    const key = `trends.platform_${platform}`;
    const translated = t(key);
    return translated === key ? platform : translated;
  };
  const formatNumber = (value: number) => value.toLocaleString(dateLocale);

  const selectedHeatRuns = useMemo(
    () => (selectedHeatCell ? timelinePointsForHeatCell(selectedHeatCell, timelinePoints) : []),
    [selectedHeatCell, timelinePoints]
  );

  const kpiGroups = kpis
    ? [
        {
          title: t("trends.kpiGroupRuns"),
          items: [
            { label: t("trends.kpiCompleted"), value: kpis.completed_runs, accent: "cyan" as const, to: "/jobs" },
            { label: t("trends.kpiFailedRuns"), value: kpis.failed_runs, accent: "rose" as const, to: "/jobs" },
            { label: t("trends.kpiRunning"), value: kpis.running_runs, accent: "gold" as const, to: "/jobs" },
            {
              label: t("trends.kpiTotalRuns"),
              value: kpis.completed_runs + kpis.failed_runs + kpis.running_runs,
              accent: "neutral" as const,
              to: "/jobs",
            },
          ],
        },
        {
          title: t("trends.kpiGroupChecks"),
          items: [
            { label: t("trends.kpiChecks"), value: kpis.total_checks, accent: "neutral" as const },
            { label: t("trends.kpiPass"), value: kpis.passed, accent: "cyan" as const },
            { label: t("trends.kpiFail"), value: kpis.failed, accent: "rose" as const },
            { label: t("trends.kpiSkipped"), value: kpis.skipped, accent: "gold" as const },
          ],
        },
        {
          title: t("trends.kpiGroupCoverage"),
          items: [
            { label: t("trends.kpiJobs"), value: kpis.jobs ?? 0, accent: "gold" as const, to: "/jobs" },
            { label: t("trends.kpiHosts"), value: kpis.hosts, accent: "cyan" as const, to: "/hosts" },
            { label: t("trends.kpiProfiles"), value: kpis.profiles, accent: "cyan" as const, to: "/profiles" },
            { label: t("trends.kpiWaivers"), value: kpis.waivers_approved, accent: "neutral" as const, to: "/waivers" },
          ],
        },
      ]
    : [];

  const applyPeriod = (next: { from: string; to: string }) => {
    if (next.from && next.to && next.from > next.to) {
      setPeriod({ from: next.to, to: next.from });
      return;
    }
    setPeriod(next);
  };

  const hiddenJobs = Math.max(0, (ops?.by_job ?? []).length - 8);
  const periodControls = (
    <div className="pf-ops-period">
      <label className="pf-ops-period__field">
        <span>{t("trends.dateFrom")}</span>
        <DateInput
          className="pf-input"
          value={period.from}
          max={period.to}
          onChange={(e) => applyPeriod({ ...period, from: e.target.value })}
        />
      </label>
      <label className="pf-ops-period__field">
        <span>{t("trends.dateTo")}</span>
        <DateInput
          className="pf-input"
          value={period.to}
          min={period.from}
          max={utcDateKey(0)}
          onChange={(e) => applyPeriod({ ...period, to: e.target.value })}
        />
      </label>
      <div className="pf-ops-period__presets" role="group" aria-label={t("trends.period")}>
        {DAY_OPTIONS.map((option) => (
          <button
            key={option}
            type="button"
            className={`pf-ops-period__preset${days === option && period.to === utcDateKey(0) ? " is-active" : ""}`}
            onClick={() => applyPeriod(periodFromDays(option))}
          >
            {t("trends.days", { count: option })}
          </button>
        ))}
      </div>
    </div>
  );

  return (
    <>
      <PageHeader title={t("trends.title")} description={t("trends.description")} />

      <section className="pf-platform-hero pf-ops-kpis-board" aria-label={t("trends.heroAria")}>
        <div className="pf-platform-hero__snapshot-header">
          <div className="pf-platform-hero__snapshot-heading">
            <h3 className="pf-platform-hero__snapshot-title">{t("trends.heroAria")}</h3>
            <p className="pf-platform-hero__snapshot-subtitle">{t("trends.period")}</p>
          </div>
          {periodControls}
        </div>
        {operations.isLoading ? (
          <Spinner />
        ) : kpis ? (
          <div className="pf-ops-kpis-board__grid">
            {kpiGroups.map((group) => (
              <div key={group.title} className="pf-ops-kpis-board__group">
                <h4 className="pf-ops-kpis-board__group-title">{group.title}</h4>
                <div className="pf-platform-hero__metrics pf-ops-kpis-board__metrics">
                  {group.items.map((item) => (
                    <OpsMetricTile
                      key={item.label}
                      value={formatNumber(item.value)}
                      label={item.label}
                      accent={item.accent}
                      to={"to" in item ? item.to : undefined}
                    />
                  ))}
                </div>
              </div>
            ))}
          </div>
        ) : null}
      </section>

      {ops && kpis ? (
        <>

          <Panel title={t("trends.byJob")} className="pf-trends-panel">
            {(ops.by_job ?? []).length === 0 ? (
              <EmptyState title={t("trends.noData")} />
            ) : (
              <JobCards
                items={ops.by_job ?? []}
                runsLabel={t("trends.kpiRuns")}
                passLabel={t("trends.kpiPass")}
                failLabel={t("trends.kpiFail")}
                moreLabel={t("trends.showMoreJobs", { count: hiddenJobs })}
                lessLabel={t("trends.showLessJobs")}
              />
            )}
          </Panel>

          <div
            className={`pf-ops-heatmap-split${selectedHeatCell ? " pf-ops-heatmap-split--expanded" : ""}`}
          >
            <Panel
              title={t("trends.heatmap")}
              className="pf-ops-heatmap-split__heatmap pf-trends-panel pf-trends-panel--heatmap"
            >
              {ops.heatmap.every((cell) => cell.runs === 0) ? (
                <div className="pf-trends-heatmap__state">
                  <EmptyState title={t("trends.noData")} />
                </div>
              ) : (
                <div className="pf-trends-heatmap">
                  <ComplianceHeatmap
                    cells={ops.heatmap}
                    weekdayLabels={weekdayLabels}
                    ariaLabel={t("trends.heatmap")}
                    lessLabel={t("trends.heatLow")}
                    moreLabel={t("trends.heatHigh")}
                    runsLabel={t("trends.kpiRuns")}
                    checksLabel={t("trends.heatmapSelectHint")}
                    dateLocale={dateLocale}
                    selectedKey={selectedHeatCell ? heatCellKey(selectedHeatCell) : null}
                    onSelect={setSelectedHeatCell}
                  />
                </div>
              )}
            </Panel>
            <Panel
              title={t("trends.byPlatform")}
              className="pf-ops-heatmap-split__platform pf-trends-panel pf-trends-panel--platform"
            >
              {ops.by_platform.length === 0 ? (
                <EmptyState title={t("trends.noData")} />
              ) : (
                <PlatformCards
                  items={ops.by_platform}
                  labelOf={platformLabel}
                  hostsLabel={t("trends.kpiHosts")}
                  checksLabel={t("trends.kpiChecks")}
                />
              )}
            </Panel>
            {selectedHeatCell ? (
              <div className="pf-ops-heatmap-split__detail">
                <HeatmapDayRuns
                  cell={selectedHeatCell}
                  runs={selectedHeatRuns}
                  dateLocale={dateLocale}
                  runLabel={t("trends.run")}
                  jobLabel={t("trends.job")}
                  finishedLabel={t("trends.finished")}
                  complianceLabel={t("trends.compliance")}
                  passLabel="PASS"
                  failLabel="FAIL"
                  checksLabel={t("trends.kpiChecks")}
                  summaryLabel={t("trends.heatmapDayMeta", {
                    count: selectedHeatRuns.length,
                    avg: selectedHeatCell.avg_compliance_percent ?? 0,
                  })}
                  emptyTitle={t("trends.heatmapNoRuns")}
                  emptyDesc={activeScopeFilters ? t("trends.heatmapNoRunsFiltered") : undefined}
                />
              </div>
            ) : null}
          </div>
        </>
      ) : null}

      <Panel title={t("trends.overTime")} className="pf-trends-panel pf-trends-panel--over-time" noPadding>
        <div className="pf-trends-over-time">
          <div className="pf-filters pf-trends-over-time__filters">
            <div className="pf-trends-over-time__toolbar">
              <div className="pf-trends-over-time__scope">
                <div className="pf-filters__group">
                  <label htmlFor="trends-scope-job">{t("trends.jobFilter")}</label>
                  <select
                    id="trends-scope-job"
                    className="pf-select"
                    value={jobFilter}
                    onChange={(e) => setJobFilter(e.target.value)}
                  >
                    <option value="all">{t("common.all")}</option>
                    {jobs.data?.map((job) => (
                      <option key={job.id} value={job.id}>
                        {job.name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="pf-filters__group">
                  <label htmlFor="trends-scope-profile">{t("trends.profileFilter")}</label>
                  <select
                    id="trends-scope-profile"
                    className="pf-select"
                    value={profileFilter}
                    onChange={(e) => setProfileFilter(e.target.value)}
                  >
                    <option value="all">{t("common.all")}</option>
                    {profiles.data?.map((profile) => (
                      <option key={profile.id} value={profile.id}>
                        {profile.profile_name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="pf-trends-over-time__toolbar-actions">
                <button
                  type="button"
                  className={`pf-trends-over-time__refine-toggle${refineOpen ? " is-open" : ""}`}
                  aria-expanded={refineOpen}
                  onClick={() => setRefineOpen((open) => !open)}
                >
                  <span>{refineOpen ? t("trends.refineHide") : t("trends.refineShow")}</span>
                  {activeTableFilters ? (
                    <span className="pf-trends-over-time__refine-badge" aria-hidden>
                      !
                    </span>
                  ) : null}
                </button>
              </div>
            </div>

            <div
              className={`pf-trends-over-time__refine${refineOpen ? " is-open" : ""}`}
              aria-hidden={!refineOpen}
            >
              <div className="pf-filters__grid pf-filters__grid--trends-refine">
                <div className="pf-filters__group">
                  <label htmlFor="trends-filter-run">{t("trends.run")}</label>
                  <input
                    id="trends-filter-run"
                    className="pf-input"
                    type="search"
                    value={tableFilters.run}
                    onChange={(e) => setTableFilters((f) => ({ ...f, run: e.target.value }))}
                    placeholder={t("trends.filterRunPlaceholder")}
                  />
                </div>
                <div className="pf-filters__group">
                  <label htmlFor="trends-filter-job">{t("trends.job")}</label>
                  <input
                    id="trends-filter-job"
                    className="pf-input"
                    type="search"
                    value={tableFilters.job}
                    onChange={(e) => setTableFilters((f) => ({ ...f, job: e.target.value }))}
                    placeholder={t("trends.filterJobPlaceholder")}
                  />
                </div>
                <div className="pf-filters__group">
                  <label htmlFor="trends-filter-finished">{t("trends.finished")}</label>
                  <input
                    id="trends-filter-finished"
                    className="pf-input"
                    type="search"
                    value={tableFilters.finished}
                    onChange={(e) => setTableFilters((f) => ({ ...f, finished: e.target.value }))}
                    placeholder={t("trends.filterFinishedPlaceholder")}
                  />
                </div>
                <div className="pf-filters__group pf-filters__group--range">
                  <span className="pf-filters__group-label">{t("trends.complianceRange")}</span>
                  <div className="pf-filters__range">
                    <input
                      id="trends-filter-compliance-min"
                      className="pf-input"
                      type="number"
                      min={0}
                      max={100}
                      value={tableFilters.complianceMin}
                      onChange={(e) =>
                        setTableFilters((f) => ({ ...f, complianceMin: e.target.value }))
                      }
                      placeholder="0"
                      aria-label={t("trends.filterComplianceMin")}
                    />
                    <span className="pf-filters__range-sep" aria-hidden>
                      –
                    </span>
                    <input
                      id="trends-filter-compliance-max"
                      className="pf-input"
                      type="number"
                      min={0}
                      max={100}
                      value={tableFilters.complianceMax}
                      onChange={(e) =>
                        setTableFilters((f) => ({ ...f, complianceMax: e.target.value }))
                      }
                      placeholder="100"
                      aria-label={t("trends.filterComplianceMax")}
                    />
                  </div>
                </div>
              </div>
            </div>

            {filterChips.length > 0 ? (
              <div className="pf-trends-over-time__chips" role="list" aria-label={t("trends.activeFilters")}>
                {filterChips.map((chip) => (
                  <button
                    key={chip.key}
                    type="button"
                    className="pf-trends-over-time__chip"
                    role="listitem"
                    onClick={chip.onClear}
                    title={t("trends.removeFilter")}
                  >
                    <span>{chip.label}</span>
                    <span className="pf-trends-over-time__chip-x" aria-hidden>
                      ×
                    </span>
                  </button>
                ))}
                {(activeTableFilters || activeScopeFilters) && (
                  <button
                    type="button"
                    className="pf-trends-over-time__chip pf-trends-over-time__chip--clear"
                    onClick={() => {
                      clearTableFilters();
                      setJobFilter("all");
                      setProfileFilter("all");
                    }}
                  >
                    {t("trends.clearAllFilters")}
                  </button>
                )}
              </div>
            ) : null}

            <div className="pf-filters__footer pf-trends-over-time__filter-footer">
              <p className="pf-filters__summary">
                {activeTableFilters
                  ? t("reports.filterResultsActive", {
                      count: filteredTimelinePoints.length,
                      total: timelinePoints.length,
                    })
                  : t("reports.filterShown", {
                      count: filteredTimelinePoints.length,
                      total: timelinePoints.length,
                    })}
              </p>
              {activeTableFilters ? (
                <Button variant="secondary" className="pf-btn--sm" onClick={clearTableFilters}>
                  {t("profiles.clearFilters")}
                </Button>
              ) : null}
            </div>
          </div>

          {timeline.isLoading ? (
            <div className="pf-trends-over-time__loading">
              <Spinner />
            </div>
          ) : timelinePoints.length === 0 ? (
            <div className="pf-trends-over-time__empty">
              <EmptyState title={t("trends.noData")} />
            </div>
          ) : chartPoints.length === 0 ? (
            <div className="pf-trends-over-time__empty">
              <EmptyState
                title={t("reports.noFilterResults")}
                description={t("reports.noFilterResultsDesc")}
              />
            </div>
          ) : (
            <>
              <div className="pf-trends-over-time__chart">
                {chartStats ? (
                  <div className="pf-trends-over-time__summary">
                    <div className="pf-compliance-info__kpis pf-trends-over-time__kpis">
                      <div
                        className={`pf-compliance-info__kpi pf-compliance-info__kpi--${complianceTone(chartStats.avg)}`}
                      >
                        <span className="pf-compliance-info__kpi-label">{t("trends.avgCompliance")}</span>
                        <strong
                          className="pf-compliance-info__kpi-value"
                          style={{ color: complianceColor(chartStats.avg) }}
                        >
                          {chartStats.avg}%
                        </strong>
                      </div>
                      <div
                        className={`pf-compliance-info__kpi pf-compliance-info__kpi--${complianceTone(chartStats.latest)}`}
                      >
                        <span className="pf-compliance-info__kpi-label">{t("trends.chartLatest")}</span>
                        <strong
                          className="pf-compliance-info__kpi-value"
                          style={{ color: complianceColor(chartStats.latest) }}
                        >
                          {chartStats.latest}%
                        </strong>
                        {chartStats.count > 1 ? (
                          <span
                            className={`pf-compliance-info__kpi-hint${
                              chartStats.delta > 0
                                ? " pf-compliance-info__kpi--delta-up"
                                : chartStats.delta < 0
                                  ? " pf-compliance-info__kpi--delta-down"
                                  : ""
                            }`}
                          >
                            {chartStats.delta > 0 ? "+" : ""}
                            {chartStats.delta}% {t("trends.vsPeriodStart")}
                          </span>
                        ) : null}
                      </div>
                      <div className="pf-compliance-info__kpi">
                        <span className="pf-compliance-info__kpi-label">{t("trends.kpiRuns")}</span>
                        <strong className="pf-compliance-info__kpi-value">{chartStats.count}</strong>
                      </div>
                      <div className="pf-compliance-info__kpi">
                        <span className="pf-compliance-info__kpi-label">{t("trends.passFailShort")}</span>
                        <strong className="pf-compliance-info__kpi-value">
                          <span className="pf-trends-kpi__pass">{chartStats.passed}</span>
                          <span className="pf-trends-kpi__sep"> / </span>
                          <span className="pf-trends-kpi__fail">{chartStats.failed}</span>
                        </strong>
                      </div>
                    </div>
                  </div>
                ) : null}
                <TimelineChart
                  points={chartPoints}
                  ariaLabel={t("trends.overTime")}
                  dateLocale={dateLocale}
                  avgCompliance={chartStats?.avg}
                />
                <p className="pf-trends-over-time__chart-hint">{t("trends.chartZoomHint")}</p>
              </div>

              <div className="pf-trends-over-time__table">
                <div className="pf-table-wrap pf-trends-table-wrap">
                  <table className="pf-table pf-table--compact">
                    <thead>
                      <tr>
                        <th>{t("trends.run")}</th>
                        <th>{t("trends.job")}</th>
                        <th>{t("trends.finished")}</th>
                        <th>{t("trends.compliance")}</th>
                        <th>PASS</th>
                        <th>FAIL</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredTimelinePoints.map((point) => (
                        <tr key={point.run_id}>
                          <td>
                            <Link to={`/reports?run=${point.run_id}`}>#{point.run_id}</Link>
                          </td>
                          <td>{point.job_name}</td>
                          <td className="pf-table__muted">
                            {new Date(point.finished_at).toLocaleString(dateLocale)}
                          </td>
                          <td>
                            <span
                              className="pf-trends-compliance-cell"
                              style={{ color: complianceColor(point.compliance_percent) }}
                            >
                              {point.compliance_percent}%
                            </span>
                          </td>
                          <td>{point.passed}</td>
                          <td>{point.failed}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>
      </Panel>

      <Panel
        title={t("trends.byProfile")}
        description={t("trends.byProfileDesc")}
        className="pf-trends-panel pf-trends-panel--profiles"
        noPadding
      >
        {byProfile.isLoading ? (
          <div className="pf-trends-profiles__state">
            <Spinner />
          </div>
        ) : profileRows.length === 0 ? (
          <div className="pf-trends-profiles__state">
            <EmptyState title={t("trends.noData")} />
          </div>
        ) : (
          <>
            {profileSummary ? (
              <div className="pf-trends-profiles__summary" aria-label={t("trends.byProfileSummaryAria")}>
                <div className="pf-trends-profiles__summary-item">
                  <span className="pf-trends-profiles__summary-label">{t("trends.profileCount")}</span>
                  <strong className="pf-trends-profiles__summary-value">
                    {formatNumber(profileSummary.count)}
                  </strong>
                </div>
                <div className="pf-trends-profiles__summary-item">
                  <span className="pf-trends-profiles__summary-label">{t("trends.profileAvgCompliance")}</span>
                  <strong
                    className="pf-trends-profiles__summary-value"
                    style={{ color: complianceColor(profileSummary.avg) }}
                  >
                    {profileSummary.avg}%
                  </strong>
                </div>
                <div className="pf-trends-profiles__summary-item">
                  <span className="pf-trends-profiles__summary-label">{t("trends.profileJobsTotal")}</span>
                  <strong className="pf-trends-profiles__summary-value">
                    {formatNumber(profileSummary.jobsTotal)}
                  </strong>
                </div>
              </div>
            ) : null}

            <div className="pf-table-wrap">
              <table className="pf-table pf-table--trends-profiles">
                <thead>
                  <tr>
                    <th>{t("trends.profileColumn")}</th>
                    <th>{t("trends.compliance")}</th>
                    <th>{t("trends.profileJobs")}</th>
                    <th>{t("trends.profileLatestRun")}</th>
                  </tr>
                </thead>
                <tbody>
                  {profileRows.map((row: ProfileCompliancePoint) => {
                    const pct = Math.round(row.avg_compliance_percent);
                    return (
                      <tr key={row.profile_id}>
                        <td>
                          <div className="pf-trends-profiles__profile">
                            <Link to={`/profiles`} className="pf-trends-profiles__profile-name">
                              {row.profile_name}
                            </Link>
                            <span className="pf-table__muted pf-trends-profiles__profile-id">
                              #{row.profile_id}
                            </span>
                          </div>
                        </td>
                        <td>
                          <div className="pf-trends-profiles__compliance">
                            <div className="pf-trends-profiles__meter" role="presentation" aria-hidden>
                              <span
                                className={`pf-trends-profiles__meter-fill pf-trends-bar ${complianceBarClass(pct)}`}
                                style={{ width: `${Math.max(0, Math.min(100, pct))}%` }}
                              />
                            </div>
                            <span
                              className="pf-trends-profiles__compliance-value"
                              style={{ color: complianceColor(pct) }}
                            >
                              {pct}%
                            </span>
                          </div>
                        </td>
                        <td>
                          <span className="pf-trends-profiles__jobs">{formatNumber(row.job_count)}</span>
                        </td>
                        <td>
                          {row.latest_run_id != null ? (
                            <Link to={`/reports?run=${row.latest_run_id}`} className="pf-trends-profiles__run-link">
                              #{row.latest_run_id}
                            </Link>
                          ) : (
                            <span className="pf-table__muted">{t("common.dash")}</span>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </>
        )}
      </Panel>
    </>
  );
}
