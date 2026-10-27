import { Fragment, useMemo, useState, type CSSProperties } from "react";
import type { AuditMapNode } from "../api/client";
import { IconLinux, IconNetwork, IconWindows } from "../components/ui/Icons";
import {
  RADAR_H,
  RADAR_W,
  buildRadarClusters,
  isRadarAggregate,
  radarNodePoint,
} from "./auditMapRadarLayout";

export type RadarGroup = { key: string | null; status: string; nodes: AuditMapNode[] };
export type RadarEdge = {
  id: number;
  source_host_id: number;
  source_port: number;
  target_host_id: number;
  target_port: number;
};

type TFunction = (key: string, params?: Record<string, string | number>) => string;

type Props = {
  groups: RadarGroup[];
  edges: RadarEdge[];
  labelFor: (node: AuditMapNode) => string;
  titleFor: (key: string | null) => string;
  isSelected: (node: AuditMapNode, groupKey: string) => boolean;
  runningHostId: number | null;
  focusKey: string | null;
  zoom: number;
  pan: { x: number; y: number };
  onPan: (pan: { x: number; y: number }) => void;
  onSelect: (node: AuditMapNode, groupKey: string) => void;
  onFocusGroup: (key: string | null) => void;
  t: TFunction;
};

const RADAR_COLOR: Record<string, string> = {
  pass: "#5bd68a",
  fail: "#ff6363",
  error: "#f3b64a",
  unchecked: "#8093ab",
};

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

function PlatformGlyph({ osType }: { osType: string | null }) {
  const kind = (osType ?? "").toLowerCase();
  if (kind === "windows") return <IconWindows />;
  if (kind === "network") return <IconNetwork />;
  return <IconLinux />;
}

export function AuditMapRadar({
  groups,
  edges,
  labelFor,
  titleFor,
  isSelected,
  runningHostId,
  focusKey,
  zoom,
  pan,
  onPan,
  onSelect,
  onFocusGroup,
  t,
}: Props) {
  const aggregate = isRadarAggregate(groups);
  const many = groups.length > 12;
  const [dragging, setDragging] = useState(false);
  // Many small groups get smaller bubbles so the ring does not overlap itself.
  const clusterSize = many
    ? Math.max(34, Math.min(62, ((2 * Math.PI * 300) / Math.max(1, groups.length)) * 0.86))
    : 74;
  const clusters = useMemo(
    () => buildRadarClusters(groups.map((group) => ({ key: group.key, count: group.nodes.length }))),
    [groups],
  );
  const points = useMemo(() => {
    const next = new Map<number, { x: number; y: number }>();
    clusters.forEach((cluster, index) => {
      groups[index]?.nodes.forEach((node, nodeIndex) => {
        next.set(node.host_id, radarNodePoint(cluster, nodeIndex));
      });
    });
    return next;
  }, [clusters, groups]);

  function startPan(event: React.PointerEvent) {
    if (event.button !== 0) return;
    if ((event.target as HTMLElement).closest("button")) return;
    const startX = event.clientX;
    const startY = event.clientY;
    const origin = { ...pan };
    setDragging(true);
    const move = (ev: PointerEvent) => {
      onPan({ x: origin.x + (ev.clientX - startX), y: origin.y + (ev.clientY - startY) });
    };
    const up = () => {
      setDragging(false);
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }

  function statusLabel(status: string): string {
    return status === "unchecked" ? t("auditMap.radarUnchecked") : t(`auditMap.legend.${status}`);
  }

  function groupLabelStyle(cluster: (typeof clusters)[number]): CSSProperties {
    if (aggregate) {
      return { left: pct(cluster.gx, RADAR_W), top: pct(cluster.gy - 56, RADAR_H), transform: "translate(-50%, -100%)" };
    }
    // A wide ring keeps the chip clear of the host labels; a small ring does not.
    if (cluster.count >= 2) {
      return {
        left: pct(cluster.gx, RADAR_W),
        top: pct(cluster.gy, RADAR_H),
        transform: "translate(-50%, -50%)",
      };
    }
    return {
      left: pct(cluster.gx, RADAR_W),
      top: pct(cluster.gy - cluster.r - 20, RADAR_H),
      transform: "translate(-50%, -100%)",
    };
  }

  return (
    <div className="pf-audit-map__radar">
      <div
        className={`pf-audit-map__radar-stage${aggregate ? " is-aggregate" : ""}${many ? " is-many" : ""}${
          dragging ? " is-panning" : ""
        }`}
        role="group"
        aria-label={t("auditMap.displayRadar")}
        onPointerDown={startPan}
      >
        <div
          className="pf-audit-map__radar-world"
          style={{ transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})` }}
        >
        <svg className="pf-audit-map__radar-wires" viewBox={`0 0 ${RADAR_W} ${RADAR_H}`} aria-hidden="true">
          {[110, 210, 320].map((radius) => (
            <circle
              key={radius}
              cx={RADAR_W / 2}
              cy={RADAR_H / 2}
              r={radius}
              className="pf-audit-map__radar-ring"
            />
          ))}
          <line x1={RADAR_W / 2} y1="30" x2={RADAR_W / 2} y2={RADAR_H - 30} className="pf-audit-map__radar-axis" />
          <line x1="120" y1={RADAR_H / 2} x2={RADAR_W - 120} y2={RADAR_H / 2} className="pf-audit-map__radar-axis" />
          {clusters.map((cluster, index) => (
            <circle
              key={`halo-${cluster.key ?? "other"}-${index}`}
              cx={cluster.gx}
              cy={cluster.gy}
              r={aggregate ? (many ? 28 : 44) : cluster.r + 22}
              fill="none"
              stroke={RADAR_COLOR[groups[index]?.status ?? "unchecked"] ?? RADAR_COLOR.unchecked}
              strokeOpacity="0.22"
              strokeDasharray="3 7"
            />
          ))}
          {!aggregate &&
            clusters.flatMap((cluster, index) =>
              groups[index]?.nodes.map((node, nodeIndex) => {
                const point = radarNodePoint(cluster, nodeIndex);
                return (
                  <line
                    key={`spoke-${cluster.key ?? "other"}-${node.host_id}`}
                    x1={cluster.gx}
                    y1={cluster.gy}
                    x2={point.x}
                    y2={point.y}
                    className="pf-audit-map__radar-spoke"
                  />
                );
              }),
            )}
          {!aggregate &&
            edges.map((edge) => {
              const from = points.get(edge.source_host_id);
              const to = points.get(edge.target_host_id);
              if (!from || !to) return null;
              return (
                <g key={edge.id}>
                  <line x1={from.x} y1={from.y} x2={to.x} y2={to.y} className="pf-audit-map__radar-trace" />
                  <circle cx={to.x} cy={to.y} r="2.5" className="pf-audit-map__radar-trace-end" />
                </g>
              );
            })}
        </svg>

        {clusters.map((cluster, index) => {
          const group = groups[index];
          const focused = focusKey !== null && (cluster.key ?? "") === focusKey;
          return (
            <button
              key={`label-${cluster.key ?? "other"}-${index}`}
              type="button"
              className="pf-audit-map__radar-group"
              style={groupLabelStyle(cluster)}
              aria-pressed={focused}
              aria-label={`${titleFor(cluster.key)} · ${cluster.count}`}
              onClick={() => onFocusGroup(cluster.key)}
            >
              <span
                className="pf-audit-map__radar-group-dot"
                style={{ background: RADAR_COLOR[group?.status ?? "unchecked"] ?? RADAR_COLOR.unchecked }}
                aria-hidden
              />
              <span className="pf-audit-map__radar-group-name">{titleFor(cluster.key)}</span>
              <span className="pf-audit-map__radar-group-count">{cluster.count}</span>
            </button>
          );
        })}

        {aggregate
          ? clusters.map((cluster, index) => {
              const group = groups[index];
              const counts = statusCounts(group?.nodes ?? []);
              return (
                <button
                  key={`cluster-${cluster.key ?? "other"}-${index}`}
                  type="button"
                  className={`pf-audit-map__cluster pf-audit-map__cluster--${group?.status ?? "unchecked"}`}
                  style={{
                    left: pct(cluster.gx, RADAR_W),
                    top: pct(cluster.gy, RADAR_H),
                    "--cluster-size": many
                      ? `clamp(20px, ${clusterSize / 12}cqw, 62px)`
                      : "74px",
                  } as CSSProperties}
                  aria-label={`${titleFor(cluster.key)} · ${cluster.count} ${t("auditMap.radarNodes")}`}
                  title={`${titleFor(cluster.key)} · ${cluster.count} ${t("auditMap.radarNodes")}`}
                  onClick={() => onFocusGroup(cluster.key)}
                >
                  <span className="pf-audit-map__cluster-ring">
                    <strong>{cluster.count}</strong>
                    <span>{t("auditMap.radarNodes")}</span>
                  </span>
                  {counts.fail > 0 ? <span className="pf-audit-map__cluster-fail">{counts.fail}</span> : null}
                </button>
              );
            })
          : clusters.flatMap((cluster, index) =>
              (groups[index]?.nodes ?? []).map((node, nodeIndex) => {
                const point = radarNodePoint(cluster, nodeIndex);
                const selected = isSelected(node, cluster.key ?? "");
                const running = runningHostId === node.host_id;
                const spacing = cluster.count > 1 ? (2 * Math.PI * cluster.r) / cluster.count : Infinity;
                const showHostLabels = groups.length <= 8 || cluster.count === 1;
                const radial = showHostLabels && cluster.count >= 2;
                const tight = spacing < 46;
                const size = Math.min(40, Math.max(22, spacing * 0.72));
                const nodeAngle = -Math.PI / 2 + (nodeIndex * 2 * Math.PI) / cluster.count;
                const ringOffset = cluster.count >= 8 ? (nodeIndex % 2 === 0 ? 45 : 85) : 45;
                const labelRadius = Math.min(
                  cluster.r + ringOffset,
                  Math.min(cluster.gx, RADAR_W - cluster.gx, cluster.gy, RADAR_H - cluster.gy) - 12,
                );
                const labelPoint = {
                  x: Math.min(RADAR_W - 92, Math.max(92, cluster.gx + labelRadius * Math.cos(nodeAngle))),
                  y: Math.min(RADAR_H - 20, Math.max(20, cluster.gy + labelRadius * Math.sin(nodeAngle) * 0.92)),
                };
                return (
                  <Fragment key={`blip-${cluster.key ?? "other"}:${node.host_id}`}>
                    <button
                      type="button"
                    className={`pf-audit-map__blip pf-audit-map__blip--${node.status}${
                      nodeIndex % 2 === 1 ? " pf-audit-map__blip--label-above" : ""
                    }${tight ? " pf-audit-map__blip--dense" : ""}${selected ? " is-selected" : ""}${
                      running ? " is-running" : ""
                    }`}
                    style={{
                      left: pct(point.x, RADAR_W),
                      top: pct(point.y, RADAR_H),
                      "--blip-size": `clamp(20px, ${size / 12}cqw, 40px)`,
                    } as CSSProperties}
                    aria-pressed={selected}
                    aria-label={`${node.name}, ${node.ip || node.dns || node.hostname || "—"}, ${statusLabel(node.status)}`}
                    onClick={() => onSelect(node, cluster.key ?? "")}
                  >
                    <span className="pf-audit-map__blip-ring" aria-hidden>
                      <PlatformGlyph osType={node.os_type} />
                    </span>
                    {radial || !showHostLabels ? null : <span className="pf-audit-map__blip-label">{labelFor(node)}</span>}
                    <span className="pf-audit-map__blip-tip" aria-hidden>
                      <strong>{node.name}</strong>
                      <span>
                        {node.ip || node.dns || node.hostname || "—"}:{node.port} · {statusLabel(node.status)}
                      </span>
                    </span>
                    </button>
                    {radial && !tight ? (
                      <span
                        className="pf-audit-map__radar-hostlabel"
                        style={{ left: pct(labelPoint.x, RADAR_W), top: pct(labelPoint.y, RADAR_H) }}
                        aria-hidden
                      >
                        {labelFor(node)}
                      </span>
                    ) : null}
                  </Fragment>
                );
              }),
            )}

        </div>
      </div>
    </div>
  );
}

