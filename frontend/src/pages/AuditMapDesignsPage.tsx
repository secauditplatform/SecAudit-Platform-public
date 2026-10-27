import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type AuditMapNode, type AuditMapPayload } from "../api/client";
import { EmptyState } from "../components/ui/EmptyState";
import { IconLinux, IconNetwork, IconWindows } from "../components/ui/Icons";
import { PageHeader } from "../components/ui/PageHeader";
import { Spinner } from "../components/ui/Spinner";
import { useTranslation } from "../i18n/I18nProvider";
import { gridCells, treemap, type TreeItem, type TreeRect } from "./auditMapDesignsLayout";
import "./auditMapDesigns.css";

type DesignGroup = AuditMapPayload["views"]["network"][number];
type Variant = "board" | "radar" | "tree";
type TFunction = (key: string, params?: Record<string, string | number>) => string;
type Selection = { hostId: number; groupKey: string };

const STATUS_ORDER = ["pass", "fail", "error", "unchecked"] as const;
type Status = (typeof STATUS_ORDER)[number];

const VARIANTS: {
  id: Variant;
  tag: string;
  nameKey: string;
  descKey: string;
  conceptKey: string;
  bestKey: string;
}[] = [
  {
    id: "board",
    tag: "A",
    nameKey: "auditMapDesigns.boardName",
    descKey: "auditMapDesigns.boardDesc",
    conceptKey: "auditMapDesigns.boardConcept",
    bestKey: "auditMapDesigns.boardBest",
  },
  {
    id: "radar",
    tag: "B",
    nameKey: "auditMapDesigns.radarName",
    descKey: "auditMapDesigns.radarDesc",
    conceptKey: "auditMapDesigns.radarConcept",
    bestKey: "auditMapDesigns.radarBest",
  },
  {
    id: "tree",
    tag: "C",
    nameKey: "auditMapDesigns.treeName",
    descKey: "auditMapDesigns.treeDesc",
    conceptKey: "auditMapDesigns.treeConcept",
    bestKey: "auditMapDesigns.treeBest",
  },
];

/** Radar palette is intentionally fixed: the situation display owns its dark field. */
const RADAR_COLOR: Record<string, string> = {
  pass: "#5bd68a",
  fail: "#ff6363",
  error: "#f3b64a",
  unchecked: "#8093ab",
};

function variantParam(value: string | null): Variant {
  if (value === "radar" || value === "tree") return value;
  return "board";
}

function statusCounts(items: { status: string }[]): Record<Status, number> {
  const counts: Record<Status, number> = { pass: 0, fail: 0, error: 0, unchecked: 0 };
  for (const item of items) {
    const key = (STATUS_ORDER as readonly string[]).includes(item.status)
      ? (item.status as Status)
      : "unchecked";
    counts[key] += 1;
  }
  return counts;
}

function checksOf(node: AuditMapNode): Record<Status, number> {
  if (node.checks) return { ...node.checks, unchecked: 0 };
  return statusCounts(node.services);
}

function checkTotals(nodes: AuditMapNode[]): Record<Status, number> {
  const totals: Record<Status, number> = { pass: 0, fail: 0, error: 0, unchecked: 0 };
  for (const node of nodes) {
    const counts = checksOf(node);
    for (const status of STATUS_ORDER) totals[status] += counts[status];
  }
  return totals;
}

/** Risk colour follows the worst check outcome, not the rolled-up host status. */
function riskTone(counts: Record<Status, number>): Status {
  if (counts.fail > 0) return "fail";
  if (counts.error > 0) return "error";
  if (counts.pass > 0) return "pass";
  return "unchecked";
}

function shortStatus(t: TFunction, status: string): string {
  const key = (STATUS_ORDER as readonly string[]).includes(status) ? status : "unchecked";
  return t(`auditMapDesigns.status.${key}`);
}

function addressOf(node: AuditMapNode): string {
  return node.ip || node.dns || node.hostname || "—";
}

function groupTitle(key: string | null, t: TFunction): string {
  return key || t("auditMap.otherAddresses");
}

function platformLabel(osType: string | null, t: TFunction): string {
  const key = (osType ?? "").toLowerCase();
  if (key === "linux") return t("hosts.osLinux");
  if (key === "windows") return t("hosts.osWindows");
  if (key === "network") return t("hosts.osNetwork");
  if (!key || key === "other") return t("auditMap.otherPlatform");
  return osType ?? t("auditMap.otherPlatform");
}

function PlatformGlyph({ osType }: { osType: string | null }) {
  const kind = (osType ?? "").toLowerCase();
  if (kind === "windows") return <IconWindows />;
  if (kind === "network") return <IconNetwork />;
  return <IconLinux />;
}

function pct(value: number, total: number): string {
  return `${(value / total) * 100}%`;
}

/* ---------- shared summary ---------- */

function Totals({
  counts,
  total,
  t,
  unitKey = "auditMapDesigns.hosts",
}: {
  counts: Record<Status, number>;
  total: number;
  t: TFunction;
  unitKey?: string;
}) {
  return (
    <div className="pf-dmap-kpi">
      <div className="pf-dmap-kpi__total">
        <strong>{total}</strong>
        <span>{t(unitKey)}</span>
      </div>
      <div className="pf-dmap-kpi__meter" role="img" aria-label={t("auditMap.lastCheckStats")}>
        {STATUS_ORDER.map((status) =>
          counts[status] ? (
            <i
              key={status}
              className={`pf-dmap-kpi__seg pf-dmap-kpi__seg--${status}`}
              style={{ width: `${(counts[status] / total) * 100}%` }}
            />
          ) : null,
        )}
      </div>
      <ul className="pf-dmap-kpi__legend">
        {STATUS_ORDER.map((status) => (
          <li key={status}>
            <span className={`pf-dmap-dot pf-dmap-dot--${status}`} aria-hidden />
            <span>{t(`auditMapDesigns.status.${status}`)}</span>
            <strong>{counts[status]}</strong>
          </li>
        ))}
      </ul>
    </div>
  );
}

/* ---------- A. Ops Board ---------- */

function BoardTile({
  node,
  selected,
  onSelect,
  t,
}: {
  node: AuditMapNode;
  selected: boolean;
  onSelect: (node: AuditMapNode) => void;
  t: TFunction;
}) {
  const checks = checksOf(node);
  const total = checks.pass + checks.fail + checks.error;
  const summary = t("auditMapDesigns.checksSummary", {
    pass: checks.pass,
    fail: checks.fail,
    error: checks.error,
  });
  return (
    <button
      type="button"
      className={`pf-dmap-tile pf-dmap-tile--${node.status}${selected ? " is-selected" : ""}`}
      aria-pressed={selected}
      aria-label={`${node.name}, ${shortStatus(t, node.status)}, ${summary}`}
      onClick={() => onSelect(node)}
    >
      <span className="pf-dmap-tile__row">
        <span className="pf-dmap-tile__glyph" aria-hidden>
          <PlatformGlyph osType={node.os_type} />
        </span>
        <span className="pf-dmap-tile__name">{node.name}</span>
        {node.status === "unchecked" ? null : (
          <span className="pf-dmap-tile__state">{shortStatus(t, node.status)}</span>
        )}
      </span>
      <span className="pf-dmap-tile__row pf-dmap-tile__row--meta">
        <span className="pf-dmap-tile__addr">
          {addressOf(node)}:{node.port}
        </span>
        {total > 0 ? (
          <span className="pf-dmap-tile__nums">
            <span className="pf-dmap-tile__num pf-dmap-tile__num--pass">
              <span aria-hidden>✓</span> {checks.pass}
            </span>
            <span className="pf-dmap-tile__num pf-dmap-tile__num--fail">
              <span aria-hidden>✕</span> {checks.fail}
            </span>
            <span className="pf-dmap-tile__num pf-dmap-tile__num--error">
              <span aria-hidden>!</span> {checks.error}
            </span>
          </span>
        ) : (
          <span className="pf-dmap-tile__none">{t("auditMapDesigns.notChecked")}</span>
        )}
      </span>
    </button>
  );
}

function BoardVariant({
  groups,
  selectedHostId,
  onSelect,
  t,
}: {
  groups: DesignGroup[];
  selectedHostId: number | null;
  onSelect: (node: AuditMapNode, groupKey: string) => void;
  t: TFunction;
}) {
  const nodes = useMemo(() => groups.flatMap((group) => group.nodes), [groups]);
  return (
    <div className="pf-dmap-board">
      <Totals counts={statusCounts(nodes)} total={nodes.length} t={t} />
      <div className="pf-dmap-board__lanes">
        {groups.map((group, index) => {
          const counts = statusCounts(group.nodes);
          return (
            <section
              key={`${group.key ?? "other"}-${index}`}
              className={`pf-dmap-lane pf-dmap-lane--${group.status}`}
              aria-label={`${groupTitle(group.key, t)} · ${group.nodes.length}`}
            >
              <header className="pf-dmap-lane__head">
                <span className={`pf-dmap-dot pf-dmap-dot--${group.status}`} aria-hidden />
                <h2>{groupTitle(group.key, t)}</h2>
                <span className="pf-dmap-lane__count">{group.nodes.length}</span>
                <span className="pf-dmap-lane__spacer" />
                {counts.pass > 0 ? (
                  <span className="pf-dmap-lane__ok">
                    {t("auditMapDesigns.status.pass")} {counts.pass}
                  </span>
                ) : null}
                {counts.fail > 0 ? (
                  <span className="pf-dmap-chip pf-dmap-chip--fail">
                    {t("auditMapDesigns.status.fail")} {counts.fail}
                  </span>
                ) : null}
                {counts.error > 0 ? (
                  <span className="pf-dmap-chip pf-dmap-chip--error">
                    {t("auditMapDesigns.status.error")} {counts.error}
                  </span>
                ) : null}
              </header>
              <div className="pf-dmap-lane__grid">
                {group.nodes.map((node) => (
                  <BoardTile
                    key={`${group.key ?? "other"}:${node.host_id}`}
                    node={node}
                    selected={selectedHostId === node.host_id}
                    onSelect={(picked) => onSelect(picked, group.key ?? "")}
                    t={t}
                  />
                ))}
              </div>
            </section>
          );
        })}
      </div>
    </div>
  );
}

/* ---------- B. Radar ---------- */

type RadarNode = { node: AuditMapNode; x: number; y: number };
type RadarCluster = {
  group: DesignGroup;
  gx: number;
  gy: number;
  r: number;
  angle: number;
  nodes: RadarNode[];
};

const RADAR_W = 1200;
const RADAR_H = 680;

function buildRadar(groups: DesignGroup[]): { clusters: RadarCluster[]; points: Map<number, { x: number; y: number }> } {
  const total = groups.length;
  const points = new Map<number, { x: number; y: number }>();
  const clusters = groups.map((group, index) => {
    const angle = total === 1 ? 0 : -Math.PI / 2 + (index * 2 * Math.PI) / total;
    const gx = total === 1 ? RADAR_W / 2 : RADAR_W / 2 + 300 * Math.cos(angle);
    const gy = total === 1 ? RADAR_H / 2 : RADAR_H / 2 + 200 * Math.sin(angle);
    const count = group.nodes.length;
    const r = count <= 1 ? 0 : 44 + Math.min(35, (count - 1) * 7);
    const nodes = group.nodes.map((node, nodeIndex) => {
      const nodeAngle = count === 1 ? 0 : -Math.PI / 2 + (nodeIndex * 2 * Math.PI) / count;
      const x = gx + r * Math.cos(nodeAngle);
      const y = gy + r * Math.sin(nodeAngle) * 0.92;
      points.set(node.host_id, { x, y });
      return { node, x, y };
    });
    return { group, gx, gy, r, angle, nodes };
  });
  return { clusters, points };
}

function RadarVariant({
  groups,
  edges,
  selectedHostId,
  onSelect,
  t,
}: {
  groups: DesignGroup[];
  edges: AuditMapPayload["edges"];
  selectedHostId: number | null;
  onSelect: (node: AuditMapNode, groupKey: string) => void;
  t: TFunction;
}) {
  const { clusters, points } = useMemo(() => buildRadar(groups), [groups]);
  const nodes = useMemo(() => groups.flatMap((group) => group.nodes), [groups]);
  const counts = statusCounts(nodes);
  return (
    <div className="pf-dmap-radar">
      <div className="pf-dmap-radar__stage">
        <svg className="pf-dmap-radar__wires" viewBox={`0 0 ${RADAR_W} ${RADAR_H}`} aria-hidden="true">
          {[110, 210, 320].map((r) => (
            <circle key={r} cx={RADAR_W / 2} cy={RADAR_H / 2} r={r} className="pf-dmap-radar__ring" />
          ))}
          <line x1={RADAR_W / 2} y1="30" x2={RADAR_W / 2} y2={RADAR_H - 30} className="pf-dmap-radar__axis" />
          <line x1="120" y1={RADAR_H / 2} x2={RADAR_W - 120} y2={RADAR_H / 2} className="pf-dmap-radar__axis" />
          {clusters.map((cluster, index) => (
            <circle
              key={`halo-${cluster.group.key ?? "other"}-${index}`}
              cx={cluster.gx}
              cy={cluster.gy}
              r={cluster.r + 22}
              fill="none"
              stroke={RADAR_COLOR[cluster.group.status] ?? RADAR_COLOR.unchecked}
              strokeOpacity="0.22"
              strokeDasharray="3 7"
            />
          ))}
          {clusters.flatMap((cluster) =>
            cluster.nodes.map(({ node, x, y }) => (
              <line
                key={`spoke-${cluster.group.key ?? "other"}-${node.host_id}`}
                x1={cluster.gx}
                y1={cluster.gy}
                x2={x}
                y2={y}
                className="pf-dmap-radar__spoke"
              />
            )),
          )}
          {edges.map((edge) => {
            const from = points.get(edge.source_host_id);
            const to = points.get(edge.target_host_id);
            if (!from || !to) return null;
            return (
              <g key={edge.id}>
                <line x1={from.x} y1={from.y} x2={to.x} y2={to.y} className="pf-dmap-radar__trace" />
                <circle cx={to.x} cy={to.y} r="2.5" className="pf-dmap-radar__trace-end" />
              </g>
            );
          })}
        </svg>

        {clusters.map((cluster, index) => {
          const nearVertical = Math.abs(Math.sin(cluster.angle)) > 0.8;
          const side = Math.cos(cluster.angle) >= 0 ? 1 : -1;
          const labelStyle = nearVertical
            ? {
                left: pct(cluster.gx, RADAR_W),
                top: pct(cluster.gy - cluster.r - 20, RADAR_H),
                transform: "translate(-50%, -100%)",
              }
            : {
                left: pct(cluster.gx + side * (cluster.r + 24), RADAR_W),
                top: pct(cluster.gy, RADAR_H),
                transform: side > 0 ? "translate(0, -50%)" : "translate(-100%, -50%)",
              };
          return (
            <div
              key={`label-${cluster.group.key ?? "other"}-${index}`}
              className="pf-dmap-radar__group"
              style={labelStyle}
            >
              <span
                className="pf-dmap-radar__group-dot"
                style={{ background: RADAR_COLOR[cluster.group.status] ?? RADAR_COLOR.unchecked }}
                aria-hidden
              />
              <span className="pf-dmap-radar__group-name">{groupTitle(cluster.group.key, t)}</span>
              <span className="pf-dmap-radar__group-count">{cluster.group.nodes.length}</span>
            </div>
          );
        })}

        {clusters.flatMap((cluster) =>
          cluster.nodes.map(({ node, x, y }) => {
            const checks = checksOf(node);
            const summary = t("auditMapDesigns.checksSummary", {
              pass: checks.pass,
              fail: checks.fail,
              error: checks.error,
            });
            return (
              <button
                key={`blip-${cluster.group.key ?? "other"}-${node.host_id}`}
                type="button"
                className={`pf-dmap-blip pf-dmap-blip--${node.status}${
                  selectedHostId === node.host_id ? " is-selected" : ""
                }`}
                style={{ left: pct(x, RADAR_W), top: pct(y, RADAR_H) }}
                aria-pressed={selectedHostId === node.host_id}
                aria-label={`${node.name}, ${addressOf(node)}, ${shortStatus(t, node.status)}, ${summary}`}
                onClick={() => onSelect(node, cluster.group.key ?? "")}
              >
                <span className="pf-dmap-blip__ring" aria-hidden>
                  <PlatformGlyph osType={node.os_type} />
                </span>
                <span className="pf-dmap-blip__label">{addressOf(node)}</span>
                <span className="pf-dmap-blip__tip" aria-hidden>
                  <strong>{node.name}</strong>
                  <span>
                    {shortStatus(t, node.status)} · {summary}
                  </span>
                </span>
              </button>
            );
          }),
        )}

        <div className="pf-dmap-radar__hud">
          <p className="pf-dmap-radar__eyebrow">{t("auditMapDesigns.situation")}</p>
          <div className="pf-dmap-radar__big">
            <strong>{nodes.length}</strong>
            <span>{t("auditMapDesigns.hosts")}</span>
          </div>
          <div className="pf-dmap-radar__numbers">
            {STATUS_ORDER.map((status) => (
              <span key={status} className="pf-dmap-radar__number" style={{ color: RADAR_COLOR[status] }}>
                <i style={{ background: RADAR_COLOR[status] }} aria-hidden />
                <span className="pf-dmap-radar__number-label">{shortStatus(t, status)}</span>
                <b>{counts[status]}</b>
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/* ---------- C. Risk Treemap ---------- */

const TREE_W = 1000;
const TREE_H = 540;
const TREE_HEAD = 28;

type TreeTile = { node: AuditMapNode; groupKey: string; x: number; y: number; w: number; h: number };
type TreeGroupBox = { group: DesignGroup; rect: TreeRect; tiles: TreeTile[] };

function buildTree(groups: DesignGroup[]): { boxes: TreeGroupBox[]; tiles: TreeTile[] } {
  const groupItems: TreeItem<DesignGroup>[] = groups
    .map((group, order) => ({ value: Math.max(1, group.nodes.length), order, payload: group }))
    .sort((a, b) => b.value - a.value || a.order - b.order);
  const boxes = treemap(groupItems, { x: 0, y: 0, w: TREE_W, h: TREE_H }).map(({ item, rect }) => {
    const box = {
      x: rect.x + 3,
      y: rect.y + 3,
      w: Math.max(1, rect.w - 6),
      h: Math.max(1, rect.h - 6),
    };
    const inner: TreeRect = {
      x: box.x + 3,
      y: box.y + TREE_HEAD,
      w: Math.max(1, box.w - 6),
      h: Math.max(1, box.h - TREE_HEAD - 3),
    };
    const tiles = gridCells(item.payload.nodes, inner).map(({ item: node, rect: nodeRect }) => ({
      node,
      groupKey: item.payload.key ?? "",
      x: nodeRect.x + 1,
      y: nodeRect.y + 1,
      w: Math.max(1, nodeRect.w - 2),
      h: Math.max(1, nodeRect.h - 2),
    }));
    return { group: item.payload, rect: box, tiles };
  });
  return { boxes, tiles: boxes.flatMap((box) => box.tiles) };
}

function TreeVariant({
  groups,
  selectedHostId,
  onSelect,
  t,
}: {
  groups: DesignGroup[];
  selectedHostId: number | null;
  onSelect: (node: AuditMapNode, groupKey: string) => void;
  t: TFunction;
}) {
  const [hoveredId, setHoveredId] = useState<number | null>(null);
  const { boxes, tiles } = useMemo(() => buildTree(groups), [groups]);
  const nodes = useMemo(() => groups.flatMap((group) => group.nodes), [groups]);
  const totals = useMemo(() => checkTotals(nodes), [nodes]);
  const hovered = hoveredId == null ? null : tiles.find((tile) => tile.node.host_id === hoveredId);
  const hoveredChecks = hovered ? checksOf(hovered.node) : null;

  return (
    <div className="pf-dmap-tree-wrap" onMouseLeave={() => setHoveredId(null)}>
      <Totals
        counts={totals}
        total={totals.pass + totals.fail + totals.error + totals.unchecked}
        t={t}
        unitKey="auditMapDesigns.checks"
      />
      <p className="pf-dmap-tree__focus" aria-live="polite">
        {hovered && hoveredChecks ? (
          <>
            <strong>{hovered.node.name}</strong>
            <span>
              {" "}
              · {addressOf(hovered.node)} · {shortStatus(t, hovered.node.status)} ·{" "}
              {t("auditMapDesigns.checksSummary", {
                pass: hoveredChecks.pass,
                fail: hoveredChecks.fail,
                error: hoveredChecks.error,
              })}
            </span>
          </>
        ) : null}
      </p>
      <div className="pf-dmap-tree">
        {boxes.map((box, index) => {
          const counts = checkTotals(box.group.nodes);
          const tone = riskTone(counts);
          const narrow = box.rect.w < 190;
          return (
            <div
              key={`head-${box.group.key ?? "other"}-${index}`}
              className={`pf-dmap-tree__head pf-dmap-tree__head--${tone}${
                narrow ? " is-narrow" : ""
              }`}
              style={{
                left: pct(box.rect.x, TREE_W),
                top: pct(box.rect.y, TREE_H),
                width: pct(box.rect.w, TREE_W),
              }}
            >
              <span className={`pf-dmap-dot pf-dmap-dot--${tone}`} aria-hidden />
              <span className="pf-dmap-tree__head-name">{groupTitle(box.group.key, t)}</span>
              <span className="pf-dmap-tree__head-count">{box.group.nodes.length}</span>
              {counts.fail > 0 ? <span className="pf-dmap-tree__head-fail">{counts.fail}</span> : null}
            </div>
          );
        })}
        {tiles.map((tile, tileIndex) => {
          const checks = checksOf(tile.node);
          const tone = riskTone(checks);
          const tiny = tile.w < 70 || tile.h < 40;
          const compact = !tiny && (tile.w < 116 || tile.h < 64);
          const rich = !compact && tile.w >= 150 && tile.h >= 95;
          const checked = checks.pass + checks.fail + checks.error;
          const total = checked + checks.unchecked;
          const summary = t("auditMapDesigns.checksSummary", {
            pass: checks.pass,
            fail: checks.fail,
            error: checks.error,
          });
          return (
            <button
              key={`tile-${tile.node.host_id}-${tileIndex}`}
              type="button"
              className={`pf-dmap-tree__tile pf-dmap-tree__tile--${tone}${
                tiny ? " is-tiny" : compact ? " is-compact" : ""
              }${selectedHostId === tile.node.host_id ? " is-selected" : ""}`}
              style={{
                left: pct(tile.x, TREE_W),
                top: pct(tile.y, TREE_H),
                width: pct(tile.w, TREE_W),
                height: pct(tile.h, TREE_H),
              }}
              title={`${tile.node.name} · ${addressOf(tile.node)} · ${shortStatus(t, tile.node.status)}`}
              aria-label={`${tile.node.name}, ${addressOf(tile.node)}, ${shortStatus(
                t,
                tile.node.status,
              )}, ${summary}`}
              aria-pressed={selectedHostId === tile.node.host_id}
              onMouseEnter={() => setHoveredId(tile.node.host_id)}
              onFocus={() => setHoveredId(tile.node.host_id)}
              onClick={() => onSelect(tile.node, tile.groupKey)}
            >
              {tiny ? (
                <span className="pf-dmap-tree__tiny-dot" aria-hidden />
              ) : compact ? (
                <>
                  {checks.fail > 0 ? (
                    <span className="pf-dmap-tree__badge pf-dmap-tree__badge--float">{checks.fail}</span>
                  ) : null}
                  <span className="pf-dmap-tree__tile-center pf-dmap-tree__tile-center--compact">
                    <span className="pf-dmap-tree__tile-ip">{addressOf(tile.node)}</span>
                    <span className="pf-dmap-tree__tile-state">
                      <i aria-hidden />
                    </span>
                  </span>
                </>
              ) : (
                <>
                  {checks.fail > 0 ? (
                    <span className="pf-dmap-tree__badge pf-dmap-tree__badge--float">{checks.fail}</span>
                  ) : null}
                  <span className="pf-dmap-tree__tile-center">
                    <span className="pf-dmap-tree__tile-ip">{addressOf(tile.node)}</span>
                    <span className="pf-dmap-tree__tile-host">{tile.node.name}</span>
                    {checked > 0 ? (
                      <>
                        <span className="pf-dmap-tree__tile-metrics">
                          {STATUS_ORDER.filter((status) => status !== "unchecked").map((status) => (
                            <span
                              key={status}
                              className={`pf-dmap-tree__tile-metric pf-dmap-tree__tile-metric--${status}`}
                            >
                              <strong>{checks[status]}</strong>
                              <span>{t(`auditMapDesigns.status.${status}`)}</span>
                            </span>
                          ))}
                        </span>
                        {rich ? (
                          <span className="pf-dmap-tree__tile-meter" aria-hidden>
                            {STATUS_ORDER.map((status) =>
                              checks[status] ? (
                                <i
                                  key={status}
                                  className={`pf-dmap-tree__tile-seg pf-dmap-tree__tile-seg--${status}`}
                                  style={{ width: `${(checks[status] / total) * 100}%` }}
                                />
                              ) : null,
                            )}
                          </span>
                        ) : null}
                      </>
                    ) : (
                      <span className="pf-dmap-tree__tile-none">{t("auditMapDesigns.notChecked")}</span>
                    )}
                  </span>
                </>
              )}
            </button>
          );
        })}
      </div>
    </div>
  );
}

/* ---------- Inspector ---------- */

function Inspector({
  node,
  groupKey,
  variant,
  onClose,
  t,
}: {
  node: AuditMapNode;
  groupKey: string;
  variant: Variant;
  onClose: () => void;
  t: TFunction;
}) {
  const checks = checksOf(node);
  const total = checks.pass + checks.fail + checks.error + checks.unchecked;
  const facts: { label: string; value: string }[] = [
    { label: t("auditMap.labelIp"), value: node.ip || t("common.dash") },
    { label: t("auditMap.labelDns"), value: node.dns || t("common.dash") },
    { label: t("auditMap.port"), value: String(node.port) },
    { label: t("hosts.osType"), value: platformLabel(node.os_type, t) },
    { label: t("auditMap.viewNetwork"), value: groupTitle(groupKey || null, t) },
    { label: t("hosts.site"), value: node.site || t("auditMap.unassignedSite") },
    { label: t("hosts.environment"), value: node.environment || t("common.dash") },
    {
      label: t("hosts.criticality"),
      value: node.criticality
        ? t(`hosts.criticalityLabel.${node.criticality}`)
        : t("hosts.criticalityUnset"),
    },
    { label: t("auditMap.filterProfile"), value: node.profile_name || t("common.dash") },
    { label: t("auditMap.filterTag"), value: node.tags.length ? node.tags.join(", ") : t("common.dash") },
  ];

  return (
    <aside className={`pf-dmap-insp pf-dmap-insp--${variant} pf-dmap-insp--${node.status}`} aria-label={node.name}>
      <div className="pf-dmap-insp__head">
        <span className="pf-dmap-insp__glyph" aria-hidden>
          <PlatformGlyph osType={node.os_type} />
        </span>
        <div className="pf-dmap-insp__title">
          <h2 title={node.name}>{node.name}</h2>
          <p>
            <span className="pf-dmap-insp__addr">
              {addressOf(node)}:{node.port}
            </span>
            <span className="pf-dmap-insp__status">{shortStatus(t, node.status)}</span>
          </p>
        </div>
        <button
          type="button"
          className="pf-dmap-insp__close"
          onClick={onClose}
          aria-label={t("auditMapDesigns.close")}
        >
          ×
        </button>
      </div>
      <div className="pf-dmap-insp__body">
        <p className="pf-dmap-insp__eyebrow">{t("auditMapDesigns.lastCheck")}</p>
        <div className="pf-dmap-insp__meter" role="img" aria-label={t("auditMap.lastCheckStats")}>
          {STATUS_ORDER.map((status) =>
            checks[status] && total ? (
              <i
                key={status}
                className={`pf-dmap-insp__seg pf-dmap-insp__seg--${status}`}
                style={{ width: `${(checks[status] / total) * 100}%` }}
              />
            ) : null,
          )}
        </div>
        <ul className="pf-dmap-insp__counts">
          {STATUS_ORDER.map((status) => (
            <li key={status}>
              <span className={`pf-dmap-dot pf-dmap-dot--${status}`} aria-hidden />
              <span>{t(`auditMapDesigns.status.${status}`)}</span>
              <strong>{checks[status]}</strong>
            </li>
          ))}
        </ul>

        <p className="pf-dmap-insp__eyebrow">{t("auditMapDesigns.facts")}</p>
        <dl className="pf-dmap-insp__facts">
          {facts.map((fact) => (
            <div key={fact.label}>
              <dt>{fact.label}</dt>
              <dd>{fact.value}</dd>
            </div>
          ))}
        </dl>

        <p className="pf-dmap-insp__eyebrow">{t("auditMapDesigns.services")}</p>
        <div className="pf-dmap-insp__ports">
          {node.services.length ? (
            node.services.map((service) => (
              <span key={`${service.port}/${service.protocol}`} className="pf-dmap-insp__port">
                {service.port}/{service.protocol}
              </span>
            ))
          ) : (
            <span className="pf-dmap-insp__muted">{t("common.dash")}</span>
          )}
        </div>

        <div className="pf-dmap-insp__links">
          <Link to={`/hosts?edit=${node.host_id}`}>{t("auditMapDesigns.openHost")}</Link>
          {node.last_job_run_id ? (
            <Link to={`/reports?run=${node.last_job_run_id}`}>{t("auditMapDesigns.openReport")}</Link>
          ) : null}
          <Link to="/audit-map">{t("auditMapDesigns.liveMap")}</Link>
        </div>
      </div>
    </aside>
  );
}

/* ---------- Page ---------- */

export function AuditMapDesignsPage() {
  const { t } = useTranslation();
  const [params, setParams] = useSearchParams();
  const variant = variantParam(params.get("variant"));
  const [selection, setSelection] = useState<Selection | null>(null);

  const mapQuery = useQuery({
    queryKey: ["audit-map-designs"],
    queryFn: () => api.auditMap(),
  });
  const data = mapQuery.data;
  const groups = useMemo<DesignGroup[]>(() => data?.views.network ?? [], [data]);
  const nodes = useMemo(() => groups.flatMap((group) => group.nodes), [groups]);
  const activeVariant = VARIANTS.find((item) => item.id === variant) ?? VARIANTS[0];

  const active = useMemo(() => {
    if (!selection) return null;
    for (const group of groups) {
      const node = group.nodes.find((item) => item.host_id === selection.hostId);
      if (node) return { node, groupKey: group.key ?? "" };
    }
    return null;
  }, [groups, selection]);

  function setVariant(next: Variant) {
    const nextParams = new URLSearchParams(params);
    nextParams.set("variant", next);
    setParams(nextParams, { replace: true });
    setSelection(null);
  }

  function select(node: AuditMapNode, groupKey: string) {
    setSelection((current) =>
      current && current.hostId === node.host_id ? null : { hostId: node.host_id, groupKey },
    );
  }

  const hint =
    variant === "radar"
      ? t("auditMapDesigns.radarHint")
      : variant === "tree"
        ? t("auditMapDesigns.treeHint")
        : t("auditMapDesigns.boardHint");

  return (
    <section className="pf-page pf-dmap">
      <PageHeader
        title={t("auditMapDesigns.title")}
        description={t("auditMapDesigns.subtitle")}
        actions={
          <Link className="pf-btn pf-btn--secondary" to="/audit-map">
            {t("auditMapDesigns.back")}
          </Link>
        }
      />

      <div className="pf-dmap-switch" role="tablist" aria-label={t("auditMapDesigns.variantsAria")}>
        {VARIANTS.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={variant === item.id}
            className={`pf-dmap-switch__tab${variant === item.id ? " is-active" : ""}`}
            onClick={() => setVariant(item.id)}
          >
            <span className="pf-dmap-switch__tag" aria-hidden>
              {item.tag}
            </span>
            <span className="pf-dmap-switch__body">
              <span className="pf-dmap-switch__name">{t(item.nameKey)}</span>
              <span className="pf-dmap-switch__desc">{t(item.descKey)}</span>
            </span>
          </button>
        ))}
      </div>

      <div className="pf-dmap-concept">
        <p>{t(activeVariant.conceptKey)}</p>
        <p className="pf-dmap-concept__meta">
          <span>
            {t("auditMapDesigns.bestFor")}: {t(activeVariant.bestKey)}
          </span>
          <span className="pf-dmap-concept__dot" aria-hidden>
            ·
          </span>
          <span>{t("auditMapDesigns.prototypeNote")}</span>
          {data ? (
            <>
              <span className="pf-dmap-concept__dot" aria-hidden>
                ·
              </span>
              <span>{t("auditMapDesigns.dataNote", { groups: groups.length, hosts: nodes.length })}</span>
            </>
          ) : null}
        </p>
      </div>

      {mapQuery.isLoading ? <Spinner /> : null}
      {mapQuery.isError ? <EmptyState title={(mapQuery.error as Error).message} /> : null}
      {data && nodes.length === 0 ? <EmptyState title={t("auditMap.empty")} /> : null}

      {data && nodes.length > 0 ? (
        <>
          <p className="pf-dmap-hint">{hint}</p>
          <div className={active ? "pf-dmap-stage pf-dmap-stage--open" : "pf-dmap-stage"}>
            <div className="pf-dmap-stage__main">
              {variant === "board" ? (
                <BoardVariant
                  groups={groups}
                  selectedHostId={active?.node.host_id ?? null}
                  onSelect={select}
                  t={t}
                />
              ) : null}
              {variant === "radar" ? (
                <RadarVariant
                  groups={groups}
                  edges={data.edges}
                  selectedHostId={active?.node.host_id ?? null}
                  onSelect={select}
                  t={t}
                />
              ) : null}
              {variant === "tree" ? (
                <TreeVariant
                  groups={groups}
                  selectedHostId={active?.node.host_id ?? null}
                  onSelect={select}
                  t={t}
                />
              ) : null}
            </div>
            {active ? (
              <Inspector
                node={active.node}
                groupKey={active.groupKey}
                variant={variant}
                onClose={() => setSelection(null)}
                t={t}
              />
            ) : null}
          </div>
        </>
      ) : null}
    </section>
  );
}
