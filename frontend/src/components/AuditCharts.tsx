import { useMemo, useState } from "react";
import type { AuditMetricPoint, AuditTimelinePoint } from "../api/client";

const AUDIT_BAR_ACCENTS = ["primary", "cyan", "gold", "rose", "neutral", "primary"] as const;

export type AuditBarItem = {
  key: string;
  label: string;
  count: number;
};

export function AuditBarChart({
  items,
  ariaLabel,
}: {
  items: AuditBarItem[];
  ariaLabel: string;
}) {
  const max = Math.max(...items.map((item) => item.count), 1);

  if (items.length === 0) {
    return null;
  }

  return (
    <div className="pf-audit-chart pf-audit-chart--bars" role="img" aria-label={ariaLabel}>
      {items.map((item, index) => {
        const widthPct = (item.count / max) * 100;
        const accent = AUDIT_BAR_ACCENTS[index % AUDIT_BAR_ACCENTS.length];
        const showInline = widthPct >= 28;

        return (
          <div key={item.key} className="pf-audit-bar-row">
            <span className="pf-audit-bar-row__label" title={item.label}>
              {item.label}
            </span>
            <div className="pf-audit-bar-row__track">
              <span
                className={`pf-audit-bar pf-audit-bar--${accent}`}
                style={{ width: `${widthPct}%` }}
              >
                {showInline && <span className="pf-audit-bar__value">{item.count}</span>}
              </span>
            </div>
            <span className="pf-audit-bar-row__count">{item.count}</span>
          </div>
        );
      })}
    </div>
  );
}

function niceMax(value: number): number {
  if (value <= 5) return 5;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const normalized = value / magnitude;
  if (normalized <= 2) return 2 * magnitude;
  if (normalized <= 5) return 5 * magnitude;
  return 10 * magnitude;
}

export function AuditTimelineChart({
  points,
  ariaLabel,
  dateLocale,
}: {
  points: AuditTimelinePoint[];
  ariaLabel: string;
  dateLocale: string;
}) {
  const [hoveredDay, setHoveredDay] = useState<string | null>(null);

  if (points.length === 0) return null;

  const width = 720;
  const height = 240;
  const padLeft = 44;
  const padRight = 16;
  const padTop = 20;
  const padBottom = 36;
  const chartW = width - padLeft - padRight;
  const chartH = height - padTop - padBottom;
  const baseY = padTop + chartH;
  const rawMax = Math.max(...points.map((p) => p.count), 1);
  const max = niceMax(rawMax);
  const tickCount = 4;
  const ticks = Array.from({ length: tickCount + 1 }, (_, i) => Math.round((max / tickCount) * i));

  const coords = points.map((point, index) => {
    const x = padLeft + (points.length === 1 ? chartW / 2 : (index / (points.length - 1)) * chartW);
    const y = padTop + chartH - (point.count / max) * chartH;
    return { x, y, point };
  });

  const linePath = coords.map((c, i) => `${i === 0 ? "M" : "L"} ${c.x} ${c.y}`).join(" ");
  const areaPath =
    coords.length > 0
      ? `${linePath} L ${coords[coords.length - 1].x} ${baseY} L ${coords[0].x} ${baseY} Z`
      : "";

  const xLabelIndices =
    points.length <= 8 ? points.map((_, i) => i) : [0, Math.floor((points.length - 1) / 2), points.length - 1];

  const hovered = coords.find((c) => c.point.day === hoveredDay);

  return (
    <div className="pf-audit-chart pf-audit-chart--timeline">
      <svg viewBox={`0 0 ${width} ${height}`} className="pf-audit-timeline" role="img" aria-label={ariaLabel}>
        <defs>
          <linearGradient id="pf-audit-line-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="var(--pf-blue-400)" />
            <stop offset="100%" stopColor="var(--pf-cyan-400)" stopOpacity="0.9" />
          </linearGradient>
          <linearGradient id="pf-audit-area-gradient" x1="0%" y1="0%" x2="0%" y2="100%">
            <stop offset="0%" stopColor="var(--pf-blue-400)" stopOpacity="0.2" />
            <stop offset="100%" stopColor="var(--pf-blue-400)" stopOpacity="0.02" />
          </linearGradient>
        </defs>

        <line x1={padLeft} y1={baseY} x2={width - padRight} y2={baseY} className="pf-audit-timeline__axis" />

        {ticks.map((tick) => {
          const y = padTop + chartH - (tick / max) * chartH;
          return (
            <g key={tick}>
              <line
                x1={padLeft}
                y1={y}
                x2={width - padRight}
                y2={y}
                className="pf-audit-timeline__grid"
              />
              <text x={padLeft - 8} y={y + 4} textAnchor="end" className="pf-audit-timeline__tick">
                {tick}
              </text>
            </g>
          );
        })}

        {areaPath && <path d={areaPath} className="pf-audit-timeline__area" fill="url(#pf-audit-area-gradient)" />}
        <path d={linePath} className="pf-audit-timeline__line" fill="none" />

        {xLabelIndices.map((index) => {
          const { x, point } = coords[index];
          return (
            <text key={point.day} x={x} y={height - 10} textAnchor="middle" className="pf-audit-timeline__x-label">
              {new Date(`${point.day}T12:00:00`).toLocaleDateString(dateLocale, {
                day: "2-digit",
                month: "short",
              })}
            </text>
          );
        })}

        {coords.map(({ x, y, point }) => {
          const active = hoveredDay === point.day;
          return (
            <g
              key={point.day}
              onMouseEnter={() => setHoveredDay(point.day)}
              onMouseLeave={() => setHoveredDay(null)}
              onFocus={() => setHoveredDay(point.day)}
              onBlur={() => setHoveredDay(null)}
              tabIndex={0}
              role="button"
              aria-label={`${point.day}: ${point.count}`}
            >
              {active && <circle cx={x} cy={y} r={10} className="pf-audit-timeline__dot-halo" />}
              <circle
                cx={x}
                cy={y}
                r={active ? 6 : 4.5}
                className={`pf-audit-timeline__dot${active ? " pf-audit-timeline__dot--active" : ""}`}
              />
            </g>
          );
        })}
      </svg>

      {hovered && (
        <div
          className="pf-audit-timeline__tooltip"
          style={{
            left: `${(hovered.x / width) * 100}%`,
            top: `${(hovered.y / height) * 100}%`,
          }}
        >
          <span className="pf-audit-timeline__tooltip-value">{hovered.point.count}</span>
          <span className="pf-audit-timeline__tooltip-date">
            {new Date(`${hovered.point.day}T12:00:00`).toLocaleDateString(dateLocale, {
              weekday: "short",
              day: "2-digit",
              month: "short",
            })}
          </span>
        </div>
      )}
    </div>
  );
}

export function AuditSparkline({
  points,
  ariaLabel,
}: {
  points: AuditTimelinePoint[];
  ariaLabel: string;
}) {
  if (points.length < 2) return null;

  const width = 120;
  const height = 36;
  const pad = 3;
  const max = Math.max(...points.map((p) => p.count), 1);
  const coords = points.map((point, index) => {
    const x = pad + (index / (points.length - 1)) * (width - pad * 2);
    const y = height - pad - (point.count / max) * (height - pad * 2);
    return { x, y };
  });
  const path = coords.map((c, i) => `${i === 0 ? "M" : "L"} ${c.x} ${c.y}`).join(" ");

  return (
    <svg viewBox={`0 0 ${width} ${height}`} className="pf-audit-sparkline" role="img" aria-label={ariaLabel}>
      <path d={path} className="pf-audit-sparkline__line" fill="none" />
    </svg>
  );
}

const OUTCOME_COLORS: Record<string, string> = {
  success: "var(--pf-green-500)",
  failed: "var(--pf-red-600)",
};

export function AuditOutcomeChart({
  outcomes,
  successLabel,
  failedLabel,
  totalLabel,
  ariaLabel,
}: {
  outcomes: AuditMetricPoint[];
  successLabel: string;
  failedLabel: string;
  totalLabel: string;
  ariaLabel: string;
}) {
  const total = outcomes.reduce((sum, item) => sum + item.count, 0);
  const segments = useMemo(
    () =>
      outcomes.map((item) => ({
        key: item.label,
        label: item.label === "success" ? successLabel : failedLabel,
        count: item.count,
        color: OUTCOME_COLORS[item.label] ?? "var(--pf-black-400)",
      })),
    [failedLabel, outcomes, successLabel],
  );

  if (total === 0) return null;

  const size = 96;
  const stroke = 9;
  const radius = (size - stroke) / 2;
  const circumference = 2 * Math.PI * radius;
  const active = segments.filter((item) => item.count > 0);
  let offset = 0;
  const successCount = segments.find((s) => s.key === "success")?.count ?? 0;
  const successPct = Math.round((successCount / total) * 100);

  return (
    <div className="pf-audit-outcome" role="img" aria-label={ariaLabel}>
      <div className="pf-audit-outcome__visual">
        <div className="pf-audit-outcome__ring">
          <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} aria-hidden>
            <circle
              cx={size / 2}
              cy={size / 2}
              r={radius}
              fill="none"
              stroke="var(--pf-black-200)"
              strokeWidth={stroke}
            />
            <g transform={`rotate(-90 ${size / 2} ${size / 2})`}>
              {active.map((item) => {
                const length = (item.count / total) * circumference;
                const segment = (
                  <circle
                    key={item.key}
                    cx={size / 2}
                    cy={size / 2}
                    r={radius}
                    fill="none"
                    stroke={item.color}
                    strokeWidth={stroke}
                    strokeDasharray={`${length} ${circumference - length}`}
                    strokeDashoffset={-offset}
                    strokeLinecap="butt"
                  />
                );
                offset += length;
                return segment;
              })}
            </g>
          </svg>
          <div className="pf-audit-outcome__ring-center">
            <span className="pf-audit-outcome__ring-value">{successPct}%</span>
          </div>
        </div>
        <span className="pf-audit-outcome__ring-caption">{totalLabel}</span>
      </div>

      <div className="pf-audit-outcome__bar" aria-hidden>
        {active.map((item) => (
          <span
            key={item.key}
            className={`pf-audit-outcome__seg pf-audit-outcome__seg--${item.key}`}
            style={{ flexGrow: item.count }}
            title={`${item.label}: ${item.count}`}
          />
        ))}
      </div>

      <dl className="pf-audit-outcome__legend">
        {segments.map((item) => (
          <div key={item.key} className="pf-audit-outcome__legend-row">
            <dt>
              <span className={`pf-audit-outcome__swatch pf-audit-outcome__swatch--${item.key}`} aria-hidden />
              {item.label}
            </dt>
            <dd>
              <strong>{item.count}</strong>
              <span className="pf-audit-outcome__pct">{Math.round((item.count / total) * 100)}%</span>
            </dd>
          </div>
        ))}
      </dl>
    </div>
  );
}
