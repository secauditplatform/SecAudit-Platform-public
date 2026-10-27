import { Fragment, useMemo, type CSSProperties } from "react";
import type { AuditMapNode } from "../api/client";
import { RADAR_H, RADAR_W, buildRadarClusters } from "./auditMapRadarLayout";

type TFunction = (key: string, params?: Record<string, string | number>) => string;

export type DonutMapGroup = { key: string | null; status: string; nodes: AuditMapNode[] };

type Props = {
  groups: DonutMapGroup[];
  titleFor: (key: string | null) => string;
  selectedKey: string | null;
  onSelect: (key: string | null) => void;
  t: TFunction;
};

const DONUT_STROKE: Record<string, string> = {
  pass: "#3fae6a",
  fail: "#e5484d",
  error: "#e0a02a",
  unchecked: "#9aa9b8",
};

const STATUS_ORDER = ["pass", "fail", "error", "unchecked"] as const;

function statusCounts(items: { status: string }[]): Record<string, number> {
  const counts: Record<string, number> = { pass: 0, fail: 0, error: 0, unchecked: 0 };
  for (const item of items) {
    const key = item.status in counts ? item.status : "unchecked";
    counts[key] += 1;
  }
  return counts;
}

function pct(value: number, total: number): string {
  return `${(value / total) * 100}%`;
}

function Donut({ counts, total, label, size }: { counts: Record<string, number>; total: number; label: string; size: number }) {
  const radius = 34;
  const circle = 2 * Math.PI * radius;
  let taken = 0;
  return (
    <span
      className="pf-audit-map__donut pf-audit-map__donut--map"
      role="img"
      aria-label={label}
      style={{ "--donut-size": `clamp(44px, ${size / 12}cqw, 120px)` } as CSSProperties}
    >
      <svg viewBox="0 0 88 88" width="100%" height="100%" aria-hidden="true">
        <circle
          cx="44"
          cy="44"
          r={radius}
          fill="none"
          strokeWidth="12"
          style={{ stroke: "color-mix(in srgb, var(--text-secondary) 16%, transparent)" }}
        />
        <g transform="rotate(-90 44 44)">
          {STATUS_ORDER.map((status) => {
            const value = counts[status] ?? 0;
            if (!value || !total) return null;
            const length = (value / total) * circle;
            const offset = -(taken / total) * circle;
            taken += value;
            return (
              <circle
                key={status}
                cx="44"
                cy="44"
                r={radius}
                fill="none"
                strokeWidth="12"
                style={{ stroke: DONUT_STROKE[status] }}
                strokeDasharray={`${length} ${circle - length}`}
                strokeDashoffset={offset}
              />
            );
          })}
        </g>
      </svg>
      <span className="pf-audit-map__donut-total" aria-hidden="true">
        {total}
      </span>
    </span>
  );
}

export function AuditMapDonutMap({ groups, titleFor, selectedKey, onSelect, t }: Props) {
  const clusters = useMemo(
    () => buildRadarClusters(groups.map((group) => ({ key: group.key, count: group.nodes.length }))),
    [groups],
  );
  const many = groups.length > 12;
  const size = many ? 52 : groups.length > 8 ? 72 : 110;

  return (
    <div className={`pf-audit-map__radar-stage pf-audit-map__donut-map${many ? " is-many" : ""}`} role="group" aria-label={t("auditMap.displayDonut")}>
      <svg className="pf-audit-map__radar-wires" viewBox={`0 0 ${RADAR_W} ${RADAR_H}`} aria-hidden="true">
        {[110, 210, 320].map((radius) => (
          <circle key={radius} cx={RADAR_W / 2} cy={RADAR_H / 2} r={radius} className="pf-audit-map__radar-ring" />
        ))}
        <line x1={RADAR_W / 2} y1="30" x2={RADAR_W / 2} y2={RADAR_H - 30} className="pf-audit-map__radar-axis" />
        <line x1="120" y1={RADAR_H / 2} x2={RADAR_W - 120} y2={RADAR_H / 2} className="pf-audit-map__radar-axis" />
        {clusters.map((cluster, index) => (
          <circle
            key={`halo-${cluster.key ?? "other"}-${index}`}
            cx={cluster.gx}
            cy={cluster.gy}
            r={cluster.r + size / 2 + 8}
            fill="none"
            stroke={DONUT_STROKE[groups[index]?.status ?? "unchecked"] ?? DONUT_STROKE.unchecked}
            strokeOpacity="0.22"
            strokeDasharray="3 7"
          />
        ))}
      </svg>

      {clusters.map((cluster, index) => {
        const group = groups[index];
        const counts = statusCounts(group.nodes);
        const total = group.nodes.length;
        const selected = selectedKey === (cluster.key ?? "");
        return (
          <Fragment key={`donut-${cluster.key ?? "other"}-${index}`}>
            {!many ? (
              <button
                type="button"
                className={`pf-audit-map__donut-map-label${selected ? " is-selected" : ""}`}
                style={{
                  left: pct(cluster.gx, RADAR_W),
                  top: pct(cluster.gy - size / 2 - 16, RADAR_H),
                }}
                aria-label={`${titleFor(cluster.key)} · ${total} ${t("auditMap.radarNodes")}`}
                onClick={() => onSelect(cluster.key)}
              >
                <span className={`pf-audit-map__dot pf-audit-map__dot--${group.status}`} aria-hidden />
                <span>{titleFor(cluster.key)}</span>
              </button>
            ) : null}
            <button
              type="button"
              className={`pf-audit-map__donut-map-node${selected ? " is-selected" : ""}`}
              style={
                {
                  left: pct(cluster.gx, RADAR_W),
                  top: pct(cluster.gy, RADAR_H),
                  "--donut-size": `clamp(44px, ${size / 12}cqw, 120px)`,
                } as CSSProperties
              }
              aria-label={`${titleFor(cluster.key)} · ${total} ${t("auditMap.radarNodes")}`}
              aria-pressed={selected}
              title={`${titleFor(cluster.key)} · ${total} ${t("auditMap.radarNodes")}`}
              onClick={() => onSelect(cluster.key)}
            >
              <Donut counts={counts} total={total} label={`${titleFor(cluster.key)} · ${total}`} size={size} />
            </button>
          </Fragment>
        );
      })}
    </div>
  );
}
