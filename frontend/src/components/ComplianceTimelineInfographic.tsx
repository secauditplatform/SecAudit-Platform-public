import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { ComplianceTimelinePoint } from "../api/client";
import { ComplianceRing, complianceColor } from "./InsightSummary";
import { TrendsListLimitSelect } from "./TrendsListLimitSelect";
import { useTranslation } from "../i18n/I18nProvider";
import { useTrendsListLimit } from "../utils/trendsListLimit";

type DayBucket = {
  dateKey: string;
  date: Date;
  avgCompliance: number;
  runCount: number;
  passed: number;
  failed: number;
  totalChecks: number;
};

type TimelineStats = {
  sorted: ComplianceTimelinePoint[];
  periodAvg: number;
  latest: ComplianceTimelinePoint;
  peak: ComplianceTimelinePoint;
  low: ComplianceTimelinePoint;
  complianceDelta: number | null;
  uniqueJobs: number;
  checksPassed: number;
  checksFailed: number;
  checksTotal: number;
  otherChecks: number;
  dayBuckets: DayBucket[];
};


function complianceBandClass(percent: number): string {
  if (percent >= 80) return "pf-compliance-info__bar--good";
  if (percent >= 50) return "pf-compliance-info__bar--warn";
  return "pf-compliance-info__bar--bad";
}

function buildTimelineStats(points: ComplianceTimelinePoint[]): TimelineStats {
  const sorted = [...points].sort(
    (a, b) => new Date(a.finished_at).getTime() - new Date(b.finished_at).getTime()
  );

  let checksPassed = 0;
  let checksFailed = 0;
  let checksTotal = 0;
  for (const point of sorted) {
    checksPassed += point.passed;
    checksFailed += point.failed;
    checksTotal += point.total_checks;
  }

  const otherChecks = Math.max(0, checksTotal - checksPassed - checksFailed);
  const uniqueJobs = new Set(sorted.map((point) => point.job_id)).size;
  const periodAvg = Math.round(
    sorted.reduce((sum, point) => sum + point.compliance_percent, 0) / sorted.length
  );

  let peak = sorted[0];
  let low = sorted[0];
  for (const point of sorted) {
    if (point.compliance_percent > peak.compliance_percent) peak = point;
    if (point.compliance_percent < low.compliance_percent) low = point;
  }

  let complianceDelta: number | null = null;
  if (sorted.length >= 2) {
    const mid = Math.max(1, Math.floor(sorted.length / 2));
    const older = sorted.slice(0, mid);
    const newer = sorted.slice(mid);
    const averageCompliance = (items: ComplianceTimelinePoint[]) =>
      items.reduce((sum, item) => sum + item.compliance_percent, 0) / items.length;
    complianceDelta =
      Math.round((averageCompliance(newer) - averageCompliance(older)) * 100) / 100;
  }

  const bucketMap = new Map<string, DayBucket>();
  for (const point of sorted) {
    const date = new Date(point.finished_at);
    const dateKey = date.toISOString().slice(0, 10);
    const existing = bucketMap.get(dateKey);
    if (existing) {
      const nextCount = existing.runCount + 1;
      existing.avgCompliance =
        Math.round(
          ((existing.avgCompliance * existing.runCount + point.compliance_percent) / nextCount) * 100
        ) / 100;
      existing.runCount = nextCount;
      existing.passed += point.passed;
      existing.failed += point.failed;
      existing.totalChecks += point.total_checks;
    } else {
      bucketMap.set(dateKey, {
        dateKey,
        date,
        avgCompliance: point.compliance_percent,
        runCount: 1,
        passed: point.passed,
        failed: point.failed,
        totalChecks: point.total_checks,
      });
    }
  }

  const dayBuckets = Array.from(bucketMap.values()).sort(
    (a, b) => a.date.getTime() - b.date.getTime()
  );

  return {
    sorted,
    periodAvg,
    latest: sorted[sorted.length - 1],
    peak,
    low,
    complianceDelta,
    uniqueJobs,
    checksPassed,
    checksFailed,
    checksTotal,
    otherChecks,
    dayBuckets,
  };
}

function formatShortDate(date: Date, dateLocale: string): string {
  return date.toLocaleDateString(dateLocale, { day: "2-digit", month: "short" });
}

function formatFullDateTime(iso: string, dateLocale: string): string {
  return new Date(iso).toLocaleString(dateLocale, {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function KpiTile({
  label,
  value,
  hint,
  tone,
}: {
  label: string;
  value: string;
  hint?: string;
  tone?: "good" | "warn" | "bad" | "neutral" | "delta-up" | "delta-down";
}) {
  return (
    <div className={`pf-compliance-info__kpi${tone ? ` pf-compliance-info__kpi--${tone}` : ""}`}>
      <span className="pf-compliance-info__kpi-label">{label}</span>
      <span className="pf-compliance-info__kpi-value">{value}</span>
      {hint ? <span className="pf-compliance-info__kpi-hint">{hint}</span> : null}
    </div>
  );
}

export function ComplianceTimelineInfographic({
  points,
  days,
  ariaLabel,
}: {
  points: ComplianceTimelinePoint[];
  days: number;
  ariaLabel: string;
}) {
  const { t, dateLocale } = useTranslation();
  const [hoveredBucketKey, setHoveredBucketKey] = useState<string | null>(null);
  const [recentRunsLimit, setRecentRunsLimit] = useTrendsListLimit("recentRuns");

  const stats = useMemo(() => buildTimelineStats(points), [points]);
  const recentRuns = useMemo(
    () => [...stats.sorted].reverse().slice(0, recentRunsLimit),
    [stats.sorted, recentRunsLimit]
  );

  const passedPct =
    stats.checksTotal > 0 ? Math.round((stats.checksPassed / stats.checksTotal) * 100) : 0;
  const failedPct =
    stats.checksTotal > 0 ? Math.round((stats.checksFailed / stats.checksTotal) * 100) : 0;
  const otherPct = Math.max(0, 100 - passedPct - failedPct);

  const axisLabels = useMemo(() => {
    const buckets = stats.dayBuckets;
    if (buckets.length === 0) return [];
    if (buckets.length <= 4) {
      return buckets.map((bucket) => ({
        key: bucket.dateKey,
        label: formatShortDate(bucket.date, dateLocale),
      }));
    }
    const indices = [0, Math.floor(buckets.length / 2), buckets.length - 1];
    return indices.map((index) => ({
      key: buckets[index].dateKey,
      label: formatShortDate(buckets[index].date, dateLocale),
    }));
  }, [stats.dayBuckets, dateLocale]);

  const hoveredBucket = stats.dayBuckets.find((bucket) => bucket.dateKey === hoveredBucketKey) ?? null;

  return (
    <div className="pf-compliance-info" role="img" aria-label={ariaLabel}>
      <div className="pf-compliance-info__kpis" aria-hidden>
        <KpiTile
          label={t("platformOverview.timelineInfographic.periodAvg")}
          value={`${stats.periodAvg}%`}
          tone={
            stats.periodAvg >= 80 ? "good" : stats.periodAvg >= 50 ? "warn" : "bad"
          }
        />
        <KpiTile
          label={t("platformOverview.timelineInfographic.latest")}
          value={`${Math.round(stats.latest.compliance_percent)}%`}
          hint={formatShortDate(new Date(stats.latest.finished_at), dateLocale)}
          tone={
            stats.latest.compliance_percent >= 80
              ? "good"
              : stats.latest.compliance_percent >= 50
                ? "warn"
                : "bad"
          }
        />
        <KpiTile
          label={t("platformOverview.timelineInfographic.peak")}
          value={`${Math.round(stats.peak.compliance_percent)}%`}
          hint={formatShortDate(new Date(stats.peak.finished_at), dateLocale)}
          tone="good"
        />
        <KpiTile
          label={t("platformOverview.timelineInfographic.low")}
          value={`${Math.round(stats.low.compliance_percent)}%`}
          hint={formatShortDate(new Date(stats.low.finished_at), dateLocale)}
          tone="bad"
        />
        <KpiTile
          label={t("platformOverview.timelineInfographic.delta")}
          value={
            stats.complianceDelta != null
              ? `${stats.complianceDelta > 0 ? "+" : ""}${stats.complianceDelta}%`
              : "—"
          }
          hint={t("platformOverview.heroComplianceDelta", {
            delta:
              stats.complianceDelta != null
                ? `${stats.complianceDelta > 0 ? "+" : ""}${stats.complianceDelta}`
                : "0",
          })}
          tone={
            stats.complianceDelta == null
              ? "neutral"
              : stats.complianceDelta >= 0
                ? "delta-up"
                : "delta-down"
          }
        />
      </div>

      <div className="pf-compliance-info__main">
        <section className="pf-compliance-info__corridor" aria-hidden>
          <div className="pf-compliance-info__corridor-head">
            <h4>{t("platformOverview.timelineInfographic.corridorTitle")}</h4>
            <div className="pf-compliance-info__legend">
              <span className="pf-compliance-info__legend-item pf-compliance-info__legend-item--good">
                {t("platformOverview.timelineInfographic.legendGood")}
              </span>
              <span className="pf-compliance-info__legend-item pf-compliance-info__legend-item--warn">
                {t("platformOverview.timelineInfographic.legendWarn")}
              </span>
              <span className="pf-compliance-info__legend-item pf-compliance-info__legend-item--bad">
                {t("platformOverview.timelineInfographic.legendBad")}
              </span>
            </div>
          </div>

          <div className="pf-compliance-info__corridor-body">
            <div className="pf-compliance-info__scale" aria-hidden>
              {[100, 75, 50, 25, 0].map((tick) => (
                <span key={tick} className="pf-compliance-info__scale-tick">
                  {tick}%
                </span>
              ))}
            </div>

            <div className="pf-compliance-info__corridor-chart">
              <div className="pf-compliance-info__zones" aria-hidden>
                <span className="pf-compliance-info__zone pf-compliance-info__zone--high" />
                <span className="pf-compliance-info__zone pf-compliance-info__zone--mid" />
                <span className="pf-compliance-info__zone pf-compliance-info__zone--low" />
              </div>

              <div className="pf-compliance-info__bars">
                {stats.dayBuckets.map((bucket) => (
                  <div
                    key={bucket.dateKey}
                    className="pf-compliance-info__bar-cell"
                    onMouseEnter={() => setHoveredBucketKey(bucket.dateKey)}
                    onMouseLeave={() => setHoveredBucketKey(null)}
                  >
                    <div
                      className={`pf-compliance-info__bar ${complianceBandClass(bucket.avgCompliance)}${
                        hoveredBucketKey === bucket.dateKey ? " pf-compliance-info__bar--active" : ""
                      }`}
                      style={{ height: `${Math.max(4, bucket.avgCompliance)}%` }}
                      title={t("platformOverview.timelineInfographic.bucketTooltip", {
                        date: formatShortDate(bucket.date, dateLocale),
                        compliance: Math.round(bucket.avgCompliance),
                        runs: bucket.runCount,
                      })}
                    />
                    {bucket.runCount > 1 ? (
                      <span className="pf-compliance-info__bar-count">{bucket.runCount}</span>
                    ) : null}
                  </div>
                ))}
              </div>

              {hoveredBucket ? (
                <div className="pf-compliance-info__corridor-tooltip">
                  <span className="pf-compliance-info__corridor-tooltip-date">
                    {formatShortDate(hoveredBucket.date, dateLocale)}
                  </span>
                  <span
                    className="pf-compliance-info__corridor-tooltip-value"
                    style={{ color: complianceColor(hoveredBucket.avgCompliance) }}
                  >
                    {Math.round(hoveredBucket.avgCompliance)}%
                  </span>
                  <span className="pf-compliance-info__corridor-tooltip-meta">
                    {t("platformOverview.timelineInfographic.bucketRuns", {
                      count: hoveredBucket.runCount,
                    })}
                  </span>
                </div>
              ) : null}
            </div>
          </div>

          <div className="pf-compliance-info__axis">
            {axisLabels.map((item) => (
              <span key={item.key} className="pf-compliance-info__axis-label">
                {item.label}
              </span>
            ))}
          </div>
        </section>

        <aside className="pf-compliance-info__aside">
          <div className="pf-compliance-info__ring-panel">
            <ComplianceRing percent={stats.periodAvg} compact />
            <div className="pf-compliance-info__ring-copy">
              <span className="pf-compliance-info__ring-label">
                {t("platformOverview.timelineInfographic.periodAvg")}
              </span>
              <span className="pf-compliance-info__ring-meta">
                {t("platformOverview.timelineInfographic.scope", {
                  days,
                  runs: stats.sorted.length,
                  jobs: stats.uniqueJobs,
                })}
              </span>
            </div>
          </div>

          <div className="pf-compliance-info__checks">
            <div className="pf-compliance-info__checks-head">
              <h4>{t("platformOverview.timelineInfographic.checksTitle")}</h4>
              <span>{stats.checksTotal.toLocaleString(dateLocale)}</span>
            </div>
            <div className="pf-compliance-info__checks-track" aria-hidden>
              {passedPct > 0 ? (
                <span
                  className="pf-compliance-info__checks-seg pf-compliance-info__checks-seg--pass"
                  style={{ width: `${passedPct}%` }}
                />
              ) : null}
              {failedPct > 0 ? (
                <span
                  className="pf-compliance-info__checks-seg pf-compliance-info__checks-seg--fail"
                  style={{ width: `${failedPct}%` }}
                />
              ) : null}
              {otherPct > 0 ? (
                <span
                  className="pf-compliance-info__checks-seg pf-compliance-info__checks-seg--other"
                  style={{ width: `${otherPct}%` }}
                />
              ) : null}
            </div>
            <ul className="pf-compliance-info__checks-legend">
              <li>
                <span className="pf-compliance-info__checks-dot pf-compliance-info__checks-dot--pass" />
                <span>{t("platformOverview.timelineInfographic.checksPassed")}</span>
                <strong>{stats.checksPassed.toLocaleString(dateLocale)}</strong>
                <em>{passedPct}%</em>
              </li>
              <li>
                <span className="pf-compliance-info__checks-dot pf-compliance-info__checks-dot--fail" />
                <span>{t("platformOverview.timelineInfographic.checksFailed")}</span>
                <strong>{stats.checksFailed.toLocaleString(dateLocale)}</strong>
                <em>{failedPct}%</em>
              </li>
              {stats.otherChecks > 0 ? (
                <li>
                  <span className="pf-compliance-info__checks-dot pf-compliance-info__checks-dot--other" />
                  <span>{t("platformOverview.timelineInfographic.checksOther")}</span>
                  <strong>{stats.otherChecks.toLocaleString(dateLocale)}</strong>
                  <em>{otherPct}%</em>
                </li>
              ) : null}
            </ul>
          </div>
        </aside>
      </div>

      <section className="pf-compliance-info__recent">
        <div className="pf-compliance-info__recent-head">
          <h4>{t("platformOverview.timelineInfographic.recentTitle")}</h4>
          <TrendsListLimitSelect value={recentRunsLimit} onChange={setRecentRunsLimit} />
        </div>
        <ul className="pf-compliance-info__recent-list">
          {recentRuns.map((run) => {
            const compliance = Math.round(run.compliance_percent);
            return (
              <li key={run.run_id} className="pf-compliance-info__recent-item">
                <span className="pf-compliance-info__recent-date">
                  {formatFullDateTime(run.finished_at, dateLocale)}
                </span>
                <Link to={`/reports?run=${run.run_id}`} className="pf-compliance-info__recent-job">
                  {run.job_name}
                </Link>
                <div className="pf-compliance-info__recent-track" aria-hidden>
                  <span
                    className={`pf-compliance-info__recent-bar ${complianceBandClass(compliance)}`}
                    style={{ width: `${compliance}%` }}
                  />
                </div>
                <span
                  className="pf-compliance-info__recent-pct"
                  style={{ color: complianceColor(compliance) }}
                >
                  {compliance}%
                </span>
              </li>
            );
          })}
        </ul>
      </section>
    </div>
  );
}
