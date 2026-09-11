import { useMemo, useState, type CSSProperties } from "react";
import { Link } from "react-router-dom";
import type {
  ComplianceTimelinePoint,
  DailyOpsPoint,
  JobOpsPoint,
  PlatformOpsPoint,
  RuleFailPoint,
  StatusCountPoint,
  WeekdayHeatCell,
} from "../api/client";
import { complianceColor } from "./InsightSummary";

const STATUS_COLORS: Record<string, string> = {
  pass: "var(--pf-green-500)",
  fail: "var(--pf-red-600)",
  skip: "var(--pf-gold-400)",
  error: "var(--pf-black-600)",
  pending: "var(--pf-cyan-400)",
  completed: "var(--pf-green-500)",
  running: "var(--pf-cyan-400)",
  failed: "var(--pf-red-600)",
  cancelled: "var(--pf-gold-400)",
};

function statusColor(key: string): string {
  return STATUS_COLORS[key] || "var(--pf-blue-400)";
}

function share(count: number, total: number): number {
  if (!total) return 0;
  return Math.round((count / total) * 1000) / 10;
}

function utcDayKey(offsetFromToday: number): string {
  const date = new Date();
  date.setUTCHours(0, 0, 0, 0);
  date.setUTCDate(date.getUTCDate() - offsetFromToday);
  return date.toISOString().slice(0, 10);
}

export function fillDailySeries(points: DailyOpsPoint[], days: number): DailyOpsPoint[] {
  const byDay = new Map(points.map((point) => [point.day, point]));
  return Array.from({ length: days }, (_, index) => {
    const day = utcDayKey(days - 1 - index);
    return (
      byDay.get(day) ?? {
        day,
        runs: 0,
        passed: 0,
        failed: 0,
        avg_compliance_percent: 0,
      }
    );
  });
}

export function OutcomeDonut({
  items,
  centerValue,
  centerLabel,
  labelOf,
  ariaLabel,
}: {
  items: StatusCountPoint[];
  centerValue: string;
  centerLabel: string;
  labelOf: (key: string) => string;
  ariaLabel: string;
}) {
  const size = 168;
  const stroke = 20;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const total = items.reduce((sum, item) => sum + item.count, 0);
  const active = items.filter((item) => item.count > 0);
  let offset = 0;

  return (
    <div className="pf-ops-figure">
      <div className="pf-ops-figure__visual">
        <div className="pf-ops-donut" role="img" aria-label={ariaLabel}>
          <svg viewBox={`0 0 ${size} ${size}`} aria-hidden>
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke="var(--insight-ring-track)"
              strokeWidth={stroke}
            />
            {total > 0 ? (
              <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
                {active.map((item) => {
                  const length = (item.count / total) * circumference;
                  const node = (
                    <circle
                      key={item.key}
                      cx={size / 2}
                      cy={size / 2}
                      r={radius}
                      fill="none"
                      stroke={statusColor(item.key)}
                      strokeWidth={stroke}
                      strokeLinecap="butt"
                      strokeDasharray={`${length} ${circumference - length}`}
                      strokeDashoffset={-offset}
                    />
                  );
                  offset += length;
                  return node;
                })}
              </g>
            ) : null}
          </svg>
          <div className="pf-ops-donut__center">
            <span className="pf-ops-donut__value">{centerValue}</span>
            <span className="pf-ops-donut__caption">{centerLabel}</span>
          </div>
        </div>
      </div>
      <ul className="pf-ops-breakdown">
        {items.map((item) => (
          <li key={item.key}>
            <span className="pf-ops-breakdown__dot" style={{ background: statusColor(item.key) }} />
            <span className="pf-ops-breakdown__label">{labelOf(item.key)}</span>
            <span className="pf-ops-breakdown__value">{item.count.toLocaleString()}</span>
            <span className="pf-ops-breakdown__share">{share(item.count, total)}%</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function BandStrip({
  segments,
  ariaLabel,
}: {
  segments: { key: string; label: string; count: number; color: string }[];
  ariaLabel: string;
}) {
  const total = segments.reduce((sum, item) => sum + item.count, 0);

  return (
    <div className="pf-ops-figure" role="img" aria-label={ariaLabel}>
      <div className="pf-ops-figure__visual">
        <div className="pf-ops-band">
          <div className="pf-ops-band__track">
            {total === 0 ? (
              <span className="pf-ops-band__empty" />
            ) : (
              segments
                .filter((segment) => segment.count > 0)
                .map((segment) => (
                  <span
                    key={segment.key}
                    className="pf-ops-band__seg"
                    style={{ flexGrow: segment.count, background: segment.color }}
                    title={`${segment.label}: ${segment.count}`}
                  >
                    {share(segment.count, total) >= 14 ? `${share(segment.count, total)}%` : ""}
                  </span>
                ))
            )}
          </div>
        </div>
      </div>
      <ul className="pf-ops-breakdown">
        {segments.map((segment) => (
          <li key={segment.key}>
            <span className="pf-ops-breakdown__dot" style={{ background: segment.color }} />
            <span className="pf-ops-breakdown__label">{segment.label}</span>
            <span className="pf-ops-breakdown__value">{segment.count.toLocaleString()}</span>
            <span className="pf-ops-breakdown__share">{share(segment.count, total)}%</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function StatusBars({
  items,
  labelOf,
  ariaLabel,
}: {
  items: StatusCountPoint[];
  labelOf: (key: string) => string;
  ariaLabel: string;
}) {
  const total = items.reduce((sum, item) => sum + item.count, 0);

  return (
    <div className="pf-ops-figure" role="img" aria-label={ariaLabel}>
      <div className="pf-ops-figure__visual">
        <div className="pf-ops-band">
          <div className="pf-ops-band__track">
            {total === 0 ? (
              <span className="pf-ops-band__empty" />
            ) : (
              items
                .filter((item) => item.count > 0)
                .map((item) => (
                  <span
                    key={item.key}
                    className="pf-ops-band__seg"
                    style={{ flexGrow: item.count, background: statusColor(item.key) }}
                    title={`${labelOf(item.key)}: ${item.count}`}
                  >
                    {share(item.count, total) >= 14 ? `${share(item.count, total)}%` : ""}
                  </span>
                ))
            )}
          </div>
        </div>
      </div>
      <ul className="pf-ops-breakdown">
        {items.map((item) => (
          <li key={item.key}>
            <span className="pf-ops-breakdown__dot" style={{ background: statusColor(item.key) }} />
            <span className="pf-ops-breakdown__label">{labelOf(item.key)}</span>
            <span className="pf-ops-breakdown__value">{item.count.toLocaleString()}</span>
            <span className="pf-ops-breakdown__share">{share(item.count, total)}%</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function FailRuleRanking({
  items,
  ariaLabel,
}: {
  items: RuleFailPoint[];
  ariaLabel: string;
}) {
  const max = Math.max(...items.map((item) => item.fail_count), 1);

  return (
    <ol className="pf-ops-rank pf-ops-rank--numbered" role="img" aria-label={ariaLabel}>
      {items.map((item, index) => (
        <li key={item.rule_tech_name} className="pf-ops-rank__row">
          <span className="pf-ops-rank__index">{index + 1}</span>
          <span className="pf-ops-rank__label" title={item.rule_tech_name}>
            {item.rule_tech_name}
          </span>
          <span className="pf-ops-rank__track">
            <span
              className="pf-ops-rank__bar pf-ops-rank__bar--fail"
              style={{ width: `${(item.fail_count / max) * 100}%` }}
            />
          </span>
          <span className="pf-ops-rank__value">{item.fail_count}</span>
        </li>
      ))}
    </ol>
  );
}

const JOB_PREVIEW_COUNT = 8;

export function JobCards({
  items,
  runsLabel,
  passLabel,
  failLabel,
  moreLabel,
  lessLabel,
}: {
  items: JobOpsPoint[];
  runsLabel: string;
  passLabel: string;
  failLabel: string;
  moreLabel: string;
  lessLabel: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const hiddenCount = Math.max(0, items.length - JOB_PREVIEW_COUNT);
  const visible = expanded || hiddenCount === 0 ? items : items.slice(0, JOB_PREVIEW_COUNT);

  return (
    <div className="pf-ops-jobs-wrap">
    <div className="pf-ops-jobs">
      {visible.map((item, index) => {
        const body = (
          <>
            <header className="pf-ops-job__head">
              <span className="pf-ops-job__index">{index + 1}</span>
              <h3 className="pf-ops-job__name" title={item.job_name}>
                {item.job_name}
              </h3>
              <span className="pf-ops-job__pct" style={{ color: complianceColor(item.avg_compliance_percent) }}>
                {item.avg_compliance_percent}%
              </span>
            </header>
            <span className="pf-ops-job__track">
              <span
                className="pf-ops-job__bar"
                style={{
                  width: `${Math.min(100, item.avg_compliance_percent)}%`,
                  background: complianceColor(item.avg_compliance_percent),
                }}
              />
            </span>
            <footer className="pf-ops-job__meta">
              <span>
                {runsLabel}: <strong>{item.runs}</strong>
              </span>
              <span>
                {passLabel} <strong>{item.passed}</strong>
              </span>
              <span>
                {failLabel} <strong>{item.failed}</strong>
              </span>
            </footer>
          </>
        );

        if (item.latest_run_id) {
          return (
            <Link
              key={item.job_id}
              to={`/reports?run=${item.latest_run_id}`}
              className="pf-ops-job pf-ops-job--link"
            >
              {body}
            </Link>
          );
        }

        return (
          <article key={item.job_id} className="pf-ops-job">
            {body}
          </article>
        );
      })}
    </div>
      {hiddenCount > 0 ? (
        <button type="button" className="pf-ops-jobs__more" onClick={() => setExpanded((open) => !open)}>
          {expanded ? lessLabel : moreLabel.replace("{{count}}", String(hiddenCount))}
        </button>
      ) : null}
    </div>
  );
}

export function PlatformCards({
  items,
  labelOf,
  hostsLabel,
  checksLabel,
}: {
  items: PlatformOpsPoint[];
  labelOf: (platform: string) => string;
  hostsLabel: string;
  checksLabel: string;
}) {
  return (
    <div className="pf-ops-platforms">
      {items.map((item) => (
        <article key={item.platform} className="pf-ops-platform">
          <header className="pf-ops-platform__head">
            <span className="pf-ops-platform__name">{labelOf(item.platform)}</span>
            <span className="pf-ops-platform__pct" style={{ color: complianceColor(item.avg_compliance_percent) }}>
              {item.avg_compliance_percent}%
            </span>
          </header>
          <span className="pf-ops-platform__track">
            <span
              className="pf-ops-platform__bar"
              style={{
                width: `${Math.min(100, item.avg_compliance_percent)}%`,
                background: complianceColor(item.avg_compliance_percent),
              }}
            />
          </span>
          <footer className="pf-ops-platform__meta">
            <span>
              {hostsLabel}: <strong>{item.hosts}</strong>
            </span>
            <span>
              {checksLabel}: <strong>{item.checks}</strong>
            </span>
          </footer>
        </article>
      ))}
    </div>
  );
}

export function DailyVolumeChart({
  points,
  days,
  ariaLabel,
  passLabel,
  failLabel,
  complianceLabel,
  runsLabel,
  dateLocale,
}: {
  points: DailyOpsPoint[];
  days: number;
  ariaLabel: string;
  passLabel: string;
  failLabel: string;
  complianceLabel: string;
  runsLabel: string;
  dateLocale: string;
}) {
  const series = useMemo(() => fillDailySeries(points, days), [points, days]);
  const [hovered, setHovered] = useState<number | null>(null);
  if (series.length === 0) return null;

  const width = 960;
  const height = 268;
  const padLeft = 48;
  const padRight = 44;
  const padTop = 18;
  const padBottom = 36;
  const innerW = width - padLeft - padRight;
  const innerH = height - padTop - padBottom;
  const max = Math.max(...series.map((point) => point.passed + point.failed), 1);
  const step = innerW / series.length;
  const barW = Math.min(22, Math.max(3, step * 0.62));
  const labelEvery = Math.max(1, Math.ceil(series.length / 10));
  const columnX = (index: number) => padLeft + step * index + step / 2;
  const lineY = (percent: number) => padTop + innerH * (1 - percent / 100);
  const activePoints = series
    .map((point, index) => ({ point, index }))
    .filter(({ point }) => point.runs > 0);
  const linePath = activePoints
    .map(({ point, index }, order) => `${order === 0 ? "M" : "L"}${columnX(index)} ${lineY(point.avg_compliance_percent)}`)
    .join(" ");
  const active = hovered != null ? series[hovered] : null;
  const tooltipLeft = hovered != null ? (columnX(hovered) / width) * 100 : 0;

  return (
    <div className="pf-ops-daily" role="img" aria-label={ariaLabel}>
      <div className="pf-ops-daily__plot">
        <svg viewBox={`0 0 ${width} ${height}`} className="pf-ops-daily__svg">
          {[0, 0.25, 0.5, 0.75, 1].map((ratio) => {
            const y = padTop + innerH * (1 - ratio);
            return (
              <g key={ratio}>
                <line x1={padLeft} x2={width - padRight} y1={y} y2={y} className="pf-ops-daily__grid" />
                <text x={padLeft - 10} y={y + 4} textAnchor="end" className="pf-ops-daily__tick">
                  {Math.round(max * ratio)}
                </text>
                <text x={width - padRight + 10} y={y + 4} className="pf-ops-daily__tick">
                  {Math.round(100 * ratio)}%
                </text>
              </g>
            );
          })}

          {series.map((point, index) => {
            const x = columnX(index) - barW / 2;
            const passH = (point.passed / max) * innerH;
            const failH = (point.failed / max) * innerH;
            const passY = padTop + innerH - passH;
            const failY = passY - failH;
            return (
              <g key={point.day}>
                {hovered === index ? (
                  <rect
                    x={padLeft + step * index}
                    y={padTop}
                    width={step}
                    height={innerH}
                    className="pf-ops-daily__hover"
                  />
                ) : null}
                {passH > 0 ? (
                  <rect x={x} y={passY} width={barW} height={passH} className="pf-ops-daily__pass" rx={2} />
                ) : null}
                {failH > 0 ? (
                  <rect x={x} y={failY} width={barW} height={failH} className="pf-ops-daily__fail" rx={2} />
                ) : null}
                {index % labelEvery === 0 ? (
                  <text x={columnX(index)} y={height - 10} textAnchor="middle" className="pf-ops-daily__x">
                    {point.day.slice(5)}
                  </text>
                ) : null}
              </g>
            );
          })}

          {linePath ? <path d={linePath} className="pf-ops-daily__line" fill="none" /> : null}
          {activePoints.map(({ point, index }) => (
            <circle
              key={`dot-${point.day}`}
              cx={columnX(index)}
              cy={lineY(point.avg_compliance_percent)}
              r={hovered === index ? 5 : 3}
              className="pf-ops-daily__dot"
            />
          ))}

          {series.map((point, index) => (
            <rect
              key={`hit-${point.day}`}
              x={padLeft + step * index}
              y={padTop}
              width={step}
              height={innerH}
              fill="transparent"
              onPointerEnter={() => setHovered(index)}
              onPointerLeave={() => setHovered(null)}
            />
          ))}
        </svg>

        {active ? (
          <div
            className="pf-ops-daily__tooltip"
            style={{ left: `${tooltipLeft}%`, transform: `translateX(${tooltipLeft > 70 ? "-100%" : "-50%"})` }}
          >
            <span className="pf-ops-daily__tooltip-day">
              {new Date(`${active.day}T00:00:00Z`).toLocaleDateString(dateLocale)}
            </span>
            <span>
              {complianceLabel}: <strong>{active.runs ? `${active.avg_compliance_percent}%` : "—"}</strong>
            </span>
            <span>
              {runsLabel}: <strong>{active.runs}</strong>
            </span>
            <span>
              {passLabel}: <strong>{active.passed}</strong>
            </span>
            <span>
              {failLabel}: <strong>{active.failed}</strong>
            </span>
          </div>
        ) : null}
      </div>

      <ul className="pf-ops-legend">
        <li>
          <span className="pf-ops-legend__swatch pf-ops-swatch--pass" />
          {passLabel}
        </li>
        <li>
          <span className="pf-ops-legend__swatch pf-ops-swatch--fail" />
          {failLabel}
        </li>
        <li>
          <span className="pf-ops-legend__swatch pf-ops-legend__swatch--line" />
          {complianceLabel}
        </li>
      </ul>
    </div>
  );
}

export function heatCellKey(cell: WeekdayHeatCell): string {
  return `${cell.week_index}-${cell.weekday}`;
}

export function heatCellDay(cell: WeekdayHeatCell): string | null {
  if (cell.day) return cell.day;
  if (!cell.week_start) return null;
  const date = new Date(`${cell.week_start}T00:00:00Z`);
  date.setUTCDate(date.getUTCDate() + cell.weekday);
  return date.toISOString().slice(0, 10);
}

export function timelinePointsForHeatCell(
  cell: WeekdayHeatCell,
  points: ComplianceTimelinePoint[]
): ComplianceTimelinePoint[] {
  const day = heatCellDay(cell);
  if (!day) return [];
  return points.filter((point) => {
    const finished = new Date(point.finished_at);
    const pointDay = `${finished.getUTCFullYear()}-${String(finished.getUTCMonth() + 1).padStart(2, "0")}-${String(finished.getUTCDate()).padStart(2, "0")}`;
    return pointDay === day;
  });
}

export function ComplianceHeatmap({
  cells,
  weekdayLabels,
  ariaLabel,
  lessLabel,
  moreLabel,
  runsLabel,
  checksLabel,
  dateLocale,
  selectedKey,
  onSelect,
  wide = false,
}: {
  cells: WeekdayHeatCell[];
  weekdayLabels: string[];
  ariaLabel: string;
  lessLabel: string;
  moreLabel: string;
  runsLabel: string;
  checksLabel: string;
  dateLocale: string;
  selectedKey?: string | null;
  onSelect?: (cell: WeekdayHeatCell | null) => void;
  wide?: boolean;
}) {
  const weeks = Math.max(0, ...cells.map((cell) => cell.week_index)) + 1;
  if (cells.length === 0 || weeks < 1) return null;
  const byKey = new Map(cells.map((cell) => [heatCellKey(cell), cell]));
  const weekStarts = Array.from({ length: weeks }, (_, week) => {
    const cell = cells.find((item) => item.week_index === week && item.week_start);
    return cell?.week_start ?? null;
  });

  return (
    <div
      className={`pf-ops-heat${wide ? " pf-ops-heat--wide" : ""}`}
      role="group"
      aria-label={ariaLabel}
    >
      <div
        className={`pf-ops-heat__chart${wide ? " pf-ops-heat__chart--wide" : ""}`}
        style={
          wide
            ? ({ "--heat-weeks": weeks } as CSSProperties)
            : { gridTemplateColumns: `2.1rem repeat(${weeks}, 1.85rem)` }
        }
      >
        <span className="pf-ops-heat__corner" />
        {weekStarts.map((start, week) => (
          <span key={`week-${week}`} className="pf-ops-heat__week">
            {start ? new Date(`${start}T00:00:00Z`).toLocaleDateString(dateLocale, { day: "2-digit", month: "2-digit" }) : week + 1}
          </span>
        ))}
        {weekdayLabels.map((label, weekday) =>
          [
            <span key={`day-${label}`} className="pf-ops-heat__day">
              {label}
            </span>,
            ...Array.from({ length: weeks }, (_, week) => {
              const cell = byKey.get(`${week}-${weekday}`);
              const pct = cell?.avg_compliance_percent ?? null;
              const hasRuns = (cell?.runs ?? 0) > 0;
              const key = `${week}-${weekday}`;
              const isSelected = selectedKey === key;
              const day = cell ? heatCellDay(cell) : null;
              const dayNum = day
                ? new Date(`${day}T00:00:00Z`).toLocaleDateString(dateLocale, { day: "numeric" })
                : null;
              const title =
                pct == null
                  ? weekdayLabels[weekday]
                  : `${weekdayLabels[weekday]}${day ? ` · ${new Date(`${day}T00:00:00Z`).toLocaleDateString(dateLocale)}` : ""} · ${pct}% · ${runsLabel}: ${cell?.runs ?? 0}`;

              if (!hasRuns || !cell || !onSelect) {
                return (
                  <span
                    key={key}
                    className={`pf-ops-heat__cell${pct == null ? " is-empty" : ""}`}
                    style={
                      pct == null
                        ? undefined
                        : { background: complianceColor(pct), opacity: 0.42 + (pct / 100) * 0.58 }
                    }
                    title={title}
                  />
                );
              }

              return (
                <button
                  key={key}
                  type="button"
                  className={`pf-ops-heat__cell pf-ops-heat__cell--interactive${isSelected ? " is-selected" : ""}`}
                  style={{ background: complianceColor(pct), opacity: 0.42 + (pct / 100) * 0.58 }}
                  title={title}
                  aria-pressed={isSelected}
                  aria-label={title}
                  onClick={() => onSelect(isSelected ? null : cell)}
                >
                  <span className="pf-ops-heat__cell-day">{dayNum}</span>
                  <span className="pf-ops-heat__cell-runs">{cell.runs}</span>
                </button>
              );
            }),
          ]
        )}
      </div>
      <div className="pf-ops-heat__footer">
        <div className="pf-ops-heat__scale">
          <span>{lessLabel}</span>
          <span className="pf-ops-heat__scale-bar" />
          <span>{moreLabel}</span>
        </div>
        {onSelect ? <p className="pf-ops-heat__hint">{checksLabel}</p> : null}
      </div>
    </div>
  );
}

export function HeatmapDayRuns({
  cell,
  runs,
  dateLocale,
  runLabel,
  jobLabel,
  finishedLabel,
  complianceLabel,
  passLabel,
  failLabel,
  checksLabel,
  emptyTitle,
  emptyDesc,
  summaryLabel,
}: {
  cell: WeekdayHeatCell;
  runs: ComplianceTimelinePoint[];
  dateLocale: string;
  runLabel: string;
  jobLabel: string;
  finishedLabel: string;
  complianceLabel: string;
  passLabel: string;
  failLabel: string;
  checksLabel: string;
  emptyTitle: string;
  emptyDesc?: string;
  summaryLabel: string;
}) {
  const day = heatCellDay(cell);
  if (!day) return null;

  const sortedRuns = [...runs].sort(
    (a, b) => new Date(b.finished_at).getTime() - new Date(a.finished_at).getTime()
  );
  const dayTitle = new Date(`${day}T00:00:00Z`).toLocaleDateString(dateLocale, {
    weekday: "long",
    day: "numeric",
    month: "long",
    year: "numeric",
  });

  return (
    <div className="pf-ops-heat-detail">
      <div className="pf-ops-heat-detail__header">
        <h3 className="pf-ops-heat-detail__title">{dayTitle}</h3>
        <p className="pf-ops-heat-detail__meta">{summaryLabel}</p>
      </div>
      {sortedRuns.length === 0 ? (
        <p className="pf-ops-heat-detail__empty">
          <strong>{emptyTitle}</strong>
          {emptyDesc ? ` — ${emptyDesc}` : null}
        </p>
      ) : (
        <div className="pf-table-wrap pf-ops-heat-detail__table">
          <table className="pf-table pf-table--compact">
            <thead>
              <tr>
                <th>{runLabel}</th>
                <th>{jobLabel}</th>
                <th>{finishedLabel}</th>
                <th>{complianceLabel}</th>
                <th>{checksLabel}</th>
                <th>{passLabel}</th>
                <th>{failLabel}</th>
              </tr>
            </thead>
            <tbody>
              {sortedRuns.map((point) => (
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
                  <td>{point.total_checks}</td>
                  <td>{point.passed}</td>
                  <td>{point.failed}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
