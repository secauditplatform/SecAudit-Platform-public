import { useState, type CSSProperties } from "react";
import { Link } from "react-router-dom";
import type {
  ComplianceTimelinePoint,
  JobOpsPoint,
  PlatformOpsPoint,
  WeekdayHeatCell,
} from "../api/client";
import { complianceColor } from "./InsightSummary";

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
                  style={{ background: complianceColor(pct ?? 0), opacity: 0.42 + ((pct ?? 0) / 100) * 0.58 }}
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
