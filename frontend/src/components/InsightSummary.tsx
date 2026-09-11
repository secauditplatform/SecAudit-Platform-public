import type { ReactNode } from "react";
import { useId } from "react";
import { Link } from "react-router-dom";
import type { ReportSummary } from "../api/client";

export function complianceColor(percent: number): string {
  if (percent >= 80) return "var(--pf-green-500)";
  if (percent >= 50) return "var(--pf-gold-400)";
  return "var(--pf-red-600)";
}

const INSIGHT_RING_SIZE = 96;
const INSIGHT_RING_STROKE = 9;

const TONE_COLORS: Record<string, string> = {
  pass: "var(--pf-green-500)",
  fail: "var(--pf-red-600)",
  skip: "var(--pf-gold-400)",
  error: "var(--pf-black-600)",
  completed: "var(--pf-green-500)",
  running: "var(--pf-cyan-400)",
  failed: "var(--pf-red-600)",
  pending: "var(--pf-gold-400)",
};

type InsightTone = keyof typeof TONE_COLORS;

function InsightVisualPod({ children, caption }: { children: ReactNode; caption?: string }) {
  return (
    <div className="pf-insight-card__visual">
      <div className="pf-insight-card__ring-shell">{children}</div>
      {caption && <span className="pf-insight-card__caption">{caption}</span>}
    </div>
  );
}

function InsightRingTrack({
  gradientId,
  size,
  radius,
  stroke,
}: {
  gradientId: string;
  size: number;
  radius: number;
  stroke: number;
}) {
  return (
    <circle
      cx={size / 2}
      cy={size / 2}
      r={radius}
      fill="none"
      stroke={`url(#${gradientId})`}
      strokeWidth={stroke}
    />
  );
}

export function ComplianceRing({ percent, compact = false }: { percent: number; compact?: boolean }) {
  const uid = useId().replace(/:/g, "");
  const size = compact ? INSIGHT_RING_SIZE : 128;
  const stroke = compact ? INSIGHT_RING_STROKE : 12;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.min(100, Math.max(0, percent));
  const offset = circumference - (clamped / 100) * circumference;
  const color = complianceColor(clamped);
  const gradientId = `compliance-ring-${compact ? "sm" : "lg"}-${uid}`;

  return (
    <div className={`pf-insight-ring pf-insight-ring--compliance${compact ? " pf-insight-ring--compact" : ""}`}>
      <div className="pf-insight-ring__chart" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden>
          <defs>
            <linearGradient id={`${gradientId}-track`} x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="var(--insight-ring-track)" />
              <stop offset="100%" stopColor="var(--insight-ring-track-end)" />
            </linearGradient>
            <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={color} />
              <stop offset="100%" stopColor={color} stopOpacity="0.72" />
            </linearGradient>
          </defs>
          <InsightRingTrack gradientId={`${gradientId}-track`} size={size} radius={radius} stroke={stroke} />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={`url(#${gradientId})`}
            strokeWidth={stroke}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
            className="pf-insight-ring__progress"
          />
        </svg>
        <div className="pf-insight-ring__center">
          <span className="pf-insight-ring__value" style={{ color }}>
            {Math.round(clamped)}%
          </span>
        </div>
      </div>
    </div>
  );
}

export function MiniComplianceRing({ percent }: { percent: number }) {
  const radius = 20;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.min(100, Math.max(0, percent));
  const offset = circumference - (clamped / 100) * circumference;
  const color = complianceColor(clamped);

  return (
    <svg width="48" height="48" viewBox="0 0 48 48" aria-hidden className="pf-job-card__ring">
      <circle cx="24" cy="24" r={radius} fill="none" stroke="var(--insight-ring-track)" strokeWidth="5" />
      <circle
        cx="24"
        cy="24"
        r={radius}
        fill="none"
        stroke={color}
        strokeWidth="5"
        strokeDasharray={circumference}
        strokeDashoffset={offset}
        strokeLinecap="round"
        transform="rotate(-90 24 24)"
      />
      <text x="24" y="27" textAnchor="middle" className="pf-job-card__ring-label" fill={color}>
        {Math.round(clamped)}%
      </text>
    </svg>
  );
}

const CIRCULAR_STAT_SIZE = 68;
const CIRCULAR_STAT_STROKE = 6;

const CIRCULAR_STAT_COLORS: Record<string, string> = {
  pass: "var(--pf-green-500)",
  fail: "var(--pf-red-600)",
  skip: "var(--pf-gold-400)",
  neutral: "rgba(255, 255, 255, 0.55)",
};

export function CircularStat({
  percent,
  center,
  label,
  detail,
  tone,
}: {
  percent: number;
  center?: string;
  label: string;
  detail?: string;
  tone: "pass" | "fail" | "skip" | "neutral";
}) {
  const uid = useId().replace(/:/g, "");
  const size = CIRCULAR_STAT_SIZE;
  const stroke = CIRCULAR_STAT_STROKE;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const clamped = Math.min(100, Math.max(0, percent));
  const offset = circumference - (clamped / 100) * circumference;
  const color = CIRCULAR_STAT_COLORS[tone];
  const gradientId = `circular-stat-${tone}-${uid}`;

  return (
    <div className={`pf-circular-stat pf-circular-stat--${tone}`}>
      <div className="pf-circular-stat__chart" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden>
          <defs>
            <linearGradient id={`${gradientId}-track`} x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="var(--insight-ring-track)" />
              <stop offset="100%" stopColor="var(--insight-ring-track-end)" />
            </linearGradient>
            <linearGradient id={gradientId} x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor={color} />
              <stop offset="100%" stopColor={color} stopOpacity="0.72" />
            </linearGradient>
          </defs>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={`url(#${gradientId}-track)`}
            strokeWidth={stroke}
          />
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke={`url(#${gradientId})`}
            strokeWidth={stroke}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            transform={`rotate(-90 ${size / 2} ${size / 2})`}
            className="pf-insight-ring__progress"
          />
        </svg>
        <span className="pf-circular-stat__value">{center ?? `${clamped}%`}</span>
      </div>
      <span className="pf-circular-stat__label">{label}</span>
      {detail ? <span className="pf-circular-stat__pct">{detail}</span> : null}
    </div>
  );
}

function DistributionDonut({
  total,
  segments,
  centerValue,
}: {
  total: number;
  segments: { tone: InsightTone; count: number }[];
  centerValue: string | number;
}) {
  const size = INSIGHT_RING_SIZE;
  const stroke = INSIGHT_RING_STROKE;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const active = segments.filter((item) => item.count > 0);
  let offset = 0;

  return (
    <div className="pf-insight-ring pf-insight-ring--distribution">
      <div className="pf-insight-ring__chart" style={{ width: size, height: size }}>
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden>
          <defs>
            <linearGradient id="distribution-ring-track" x1="0%" y1="0%" x2="100%" y2="100%">
              <stop offset="0%" stopColor="var(--insight-ring-track)" />
              <stop offset="100%" stopColor="var(--insight-ring-track-end)" />
            </linearGradient>
          </defs>
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="url(#distribution-ring-track)"
            strokeWidth={stroke}
          />
          <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
            {active.map((item) => {
              const length = (item.count / total) * circumference;
              const segment = (
                <circle
                  key={item.tone}
                  cx={size / 2}
                  cy={size / 2}
                  r={radius}
                  fill="none"
                  stroke={TONE_COLORS[item.tone]}
                  strokeWidth={stroke}
                  strokeDasharray={`${length} ${circumference - length}`}
                  strokeDashoffset={-offset}
                  strokeLinecap="butt"
                  opacity={0.95}
                />
              );
              offset += length;
              return segment;
            })}
          </g>
        </svg>
        <div className="pf-insight-ring__center">
          <span className="pf-insight-ring__value">{centerValue}</span>
        </div>
      </div>
    </div>
  );
}

export type InsightMetricTone =
  | "pass"
  | "fail"
  | "skip"
  | "error"
  | "completed"
  | "running"
  | "failed"
  | "pending";

export function InsightMetric({
  value,
  label,
  tone,
  percent,
}: {
  value: number;
  label: string;
  tone: InsightMetricTone;
  percent?: number;
}) {
  return (
    <div className={`pf-insight-metric pf-insight-metric--${tone}`}>
      <span className="pf-insight-metric__value">{value}</span>
      <span className="pf-insight-metric__label">{label}</span>
      {percent !== undefined && <span className="pf-insight-metric__pct">{percent}%</span>}
    </div>
  );
}

type DistributionItem = {
  tone: InsightMetricTone;
  label: string;
  count: number;
};

function DistributionInsight({
  total,
  items,
  totalLabel,
  barAriaLabel,
  emptyMessage,
}: {
  total: number;
  items: DistributionItem[];
  totalLabel: string;
  barAriaLabel: string;
  emptyMessage?: string;
}) {
  if (total === 0) {
    return emptyMessage ? (
      <p className="pf-dashboard-empty pf-dashboard-empty--centered">{emptyMessage}</p>
    ) : null;
  }

  return (
    <div className="pf-insight-runs">
      <div className="pf-insight-runs__header">
        <span className="pf-insight-runs__total">{total}</span>
        <span className="pf-insight-runs__caption">{totalLabel}</span>
      </div>

      <div className="pf-insight-runs__bar" role="img" aria-label={barAriaLabel}>
        {items
          .filter((item) => item.count > 0)
          .map((item) => (
            <span
              key={item.tone}
              className={`pf-insight-runs__seg pf-insight-runs__seg--${item.tone}`}
              style={{ flexGrow: item.count }}
              title={`${item.label}: ${item.count}`}
            />
          ))}
      </div>

      <div className="pf-insight-metrics pf-insight-metrics--runs">
        {items.map((item) => (
          <InsightMetric
            key={item.tone}
            value={item.count}
            label={item.label}
            tone={item.tone}
            percent={Math.round((item.count / total) * 100)}
          />
        ))}
      </div>
    </div>
  );
}

export function ComplianceSummaryInsight({
  summary,
  complianceLevelLabel,
  metaLabel,
  runId,
  jobName,
  totalChecksLabel,
}: {
  summary: ReportSummary;
  complianceLevelLabel: string;
  metaLabel: string;
  runId?: number;
  jobName?: string | null;
  totalChecksLabel: string;
}) {
  const total = summary.total_checks || 1;

  return (
    <div className="pf-insight-card">
      <InsightVisualPod caption={complianceLevelLabel}>
        <ComplianceRing percent={summary.compliance_percent} compact />
      </InsightVisualPod>
      <div className="pf-insight-card__body">
        {(runId != null || jobName) && (
          <div className="pf-insight-card__meta">
            <span className="pf-insight-card__meta-label">{metaLabel}</span>
            <div className="pf-insight-card__meta-row">
              {runId != null && (
                <Link to={`/reports?run=${runId}`} className="pf-insight-card__run">
                  #{runId}
                </Link>
              )}
              {jobName && <span className="pf-insight-card__job">{jobName}</span>}
            </div>
          </div>
        )}
        <div className="pf-insight-metrics">
          <InsightMetric
            value={summary.passed}
            label="PASS"
            tone="pass"
            percent={Math.round((summary.passed / total) * 100)}
          />
          <InsightMetric
            value={summary.failed}
            label="FAIL"
            tone="fail"
            percent={Math.round((summary.failed / total) * 100)}
          />
          <InsightMetric
            value={summary.skipped}
            label="SKIP"
            tone="skip"
            percent={Math.round((summary.skipped / total) * 100)}
          />
          <InsightMetric
            value={summary.errors}
            label="ERROR"
            tone="error"
            percent={Math.round((summary.errors / total) * 100)}
          />
        </div>
        <p className="pf-insight-card__footer">{totalChecksLabel}</p>
      </div>
    </div>
  );
}

export function CheckDistributionInsight({
  summary,
  totalLabel,
  barAriaLabel,
}: {
  summary: ReportSummary;
  totalLabel: string;
  barAriaLabel: string;
}) {
  const items: DistributionItem[] = [
    { tone: "pass", label: "PASS", count: summary.passed },
    { tone: "fail", label: "FAIL", count: summary.failed },
    { tone: "skip", label: "SKIP", count: summary.skipped },
    { tone: "error", label: "ERROR", count: summary.errors },
  ];

  return (
    <DistributionInsight
      total={summary.total_checks}
      items={items}
      totalLabel={totalLabel}
      barAriaLabel={barAriaLabel}
    />
  );
}

export function RunStatusInsight({
  stats,
  labels,
  totalLabel,
  barAriaLabel,
  emptyMessage,
}: {
  stats: { total: number; completed: number; running: number; failed: number; pending: number };
  labels: { completed: string; running: string; failed: string; pending: string };
  totalLabel: string;
  barAriaLabel: string;
  emptyMessage: string;
}) {
  if (stats.total === 0) {
    return <p className="pf-dashboard-empty pf-dashboard-empty--centered">{emptyMessage}</p>;
  }

  const segments = [
    { tone: "completed" as const, label: labels.completed, count: stats.completed },
    { tone: "running" as const, label: labels.running, count: stats.running },
    { tone: "failed" as const, label: labels.failed, count: stats.failed },
    { tone: "pending" as const, label: labels.pending, count: stats.pending },
  ];

  return (
    <div className="pf-insight-card" role="img" aria-label={barAriaLabel}>
      <InsightVisualPod caption={totalLabel}>
        <DistributionDonut total={stats.total} segments={segments} centerValue={stats.total} />
      </InsightVisualPod>
      <div className="pf-insight-card__body">
        <div className="pf-insight-metrics pf-insight-metrics--runs">
          {segments.map((item) => (
            <InsightMetric
              key={item.tone}
              value={item.count}
              label={item.label}
              tone={item.tone}
              percent={Math.round((item.count / stats.total) * 100)}
            />
          ))}
        </div>
      </div>
    </div>
  );
}
