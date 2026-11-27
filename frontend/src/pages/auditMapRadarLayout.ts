/** Pure geometry for the Audit Map radar display. */

export const RADAR_W = 1200;
export const RADAR_H = 680;
/** Above this many visible hosts the radar collapses subnets into clusters. */
export const RADAR_DETAIL_LIMIT = 60;

/** Blip + glow radius in world units (covers ~40px on a typical stage). */
const HOST_R = 28;
/** Subnet chip half-size in world units (CIDR + count). */
const LABEL_HW = 72;
const LABEL_HH = 12;
const LABEL_GAP = 6;

export type RadarGroupCount = { key: string | null; count: number };
export type RadarCluster = {
  key: string | null;
  angle: number;
  gx: number;
  gy: number;
  r: number;
  count: number;
};
export type RadarPoint = { x: number; y: number };

export function buildRadarClusters(
  groups: RadarGroupCount[],
  width = RADAR_W,
  height = RADAR_H,
): RadarCluster[] {
  const total = groups.length;
  const single = total === 1;
  // Leave the quadrant grid once there are 5+ groups. An ellipse crushed top/bottom
  // clusters into their neighbours; a circle keeps subnet chips clear of hosts.
  const ring =
    total > 12 ? 300 : total >= 5 ? Math.min(300, 210 + total * 8) : null;
  // A handful of groups gets a quadrant layout: long host names need the room.
  const grid: Array<[number, number]> | null =
    total === 1
      ? [[width / 2, height / 2]]
      : total === 2
        ? [
            [width * 0.275, height / 2],
            [width * 0.725, height / 2],
          ]
        : total === 3
          ? [
              [width * 0.275, height * 0.382],
              [width * 0.725, height * 0.382],
              [width / 2, height * 0.794],
            ]
          : total === 4
            ? [
                [width * 0.275, height * 0.368],
                [width * 0.725, height * 0.368],
                [width * 0.275, height * 0.794],
                [width * 0.725, height * 0.794],
              ]
            : null;
  return groups.map((group, index) => {
    const angle = single ? 0 : -Math.PI / 2 + (index * 2 * Math.PI) / total;
    const orbit = ring ?? 300;
    const gx = grid ? grid[index][0] : width / 2 + orbit * Math.cos(angle);
    const gy = grid ? grid[index][1] : height / 2 + orbit * Math.sin(angle);
    // Keep host rings compact so the subnet chip still fits outside them.
    const maxNodeRadius = total <= 4 ? 150 : total <= 8 ? 80 : total <= 12 ? 56 : 48;
    const base =
      group.count <= 1
        ? 0
        : single
          ? Math.min(250, 60 + (group.count - 1) * 9)
          : 40 + Math.min(maxNodeRadius - 40, (group.count - 1) * 9);
    // Margin for an outward chip past the outer host (HOST_R + label + gap).
    const room = Math.min(gx, width - gx, gy, height - gy) - (HOST_R + LABEL_HH + LABEL_GAP + 8);
    const r = Math.min(base, Math.max(0, room));
    return { key: group.key, angle, gx, gy, r, count: group.count };
  });
}

export function radarNodePoint(cluster: RadarCluster, index: number): { x: number; y: number } {
  if (cluster.count <= 1) return { x: cluster.gx, y: cluster.gy };
  const angle = -Math.PI / 2 + (index * 2 * Math.PI) / cluster.count;
  return {
    x: cluster.gx + cluster.r * Math.cos(angle),
    y: cluster.gy + cluster.r * Math.sin(angle) * 0.92,
  };
}

function clampLabel(x: number, y: number, width: number, height: number): RadarPoint {
  return {
    x: Math.min(width - LABEL_HW, Math.max(LABEL_HW, x)),
    y: Math.min(height - LABEL_HH - 4, Math.max(LABEL_HH + 4, y)),
  };
}

/** Signed gap from chip AABB to a host circle; negative means overlap. */
function labelHostGap(lx: number, ly: number, hx: number, hy: number): number {
  const closestX = Math.max(lx - LABEL_HW, Math.min(hx, lx + LABEL_HW));
  const closestY = Math.max(ly - LABEL_HH, Math.min(hy, ly + LABEL_HH));
  return Math.hypot(hx - closestX, hy - closestY) - HOST_R;
}

function minLabelGap(lx: number, ly: number, hosts: RadarPoint[]): number {
  let min = Infinity;
  for (const host of hosts) {
    min = Math.min(min, labelHostGap(lx, ly, host.x, host.y));
  }
  return min;
}

/**
 * Place the subnet chip just clear of its hosts — nearest safe spot, not the
 * farthest. World-unit gaps stay valid under uniform zoom.
 */
export function radarGroupLabelPoint(
  cluster: RadarCluster,
  hosts?: RadarPoint[],
  width = RADAR_W,
  height = RADAR_H,
): RadarPoint {
  const hostPts =
    hosts && hosts.length > 0
      ? hosts
      : cluster.count <= 1
        ? [{ x: cluster.gx, y: cluster.gy }]
        : Array.from({ length: cluster.count }, (_, index) => radarNodePoint(cluster, index));

  const cx = width / 2;
  const cy = height / 2;
  const dx = cluster.gx - cx;
  const dy = cluster.gy - cy;
  const len = Math.hypot(dx, dy);
  const ux = len < 8 ? 0 : dx / len;
  const uy = len < 8 ? -1 : dy / len;
  const tx = -uy;
  const ty = ux;

  const near = HOST_R + LABEL_HH + LABEL_GAP;
  const reach =
    cluster.count <= 1
      ? [near, near + 18, near + 36]
      : [cluster.r + near, cluster.r + near + 18, cluster.r + near + 36];

  const dirs: Array<[number, number]> = [
    [ux, uy],
    [tx, ty],
    [-tx, -ty],
    [(ux + tx) / Math.SQRT2, (uy + ty) / Math.SQRT2],
    [(ux - tx) / Math.SQRT2, (uy - ty) / Math.SQRT2],
    [-ux, -uy],
  ];

  const raw: RadarPoint[] = [];
  // Hollow ring: chip sits in the middle when it clears every host.
  if (cluster.count >= 2) raw.push({ x: cluster.gx, y: cluster.gy });
  for (const dist of reach) {
    for (const [ox, oy] of dirs) {
      raw.push({ x: cluster.gx + ox * dist, y: cluster.gy + oy * dist });
    }
  }

  let best = clampLabel(cluster.gx + ux * reach[0], cluster.gy + uy * reach[0], width, height);
  let bestGap = minLabelGap(best.x, best.y, hostPts);
  let bestDist = Math.hypot(best.x - cluster.gx, best.y - cluster.gy);
  for (const candidate of raw) {
    const point = clampLabel(candidate.x, candidate.y, width, height);
    const gap = minLabelGap(point.x, point.y, hostPts);
    const dist = Math.hypot(point.x - cluster.gx, point.y - cluster.gy);
    const clear = gap >= LABEL_GAP;
    const bestClear = bestGap >= LABEL_GAP;
    // Prefer any clear spot; among clear (or among overlapping) take the nearest.
    if (clear !== bestClear) {
      if (!clear) continue;
    } else if (dist > bestDist + 0.5) {
      continue;
    } else if (dist >= bestDist - 0.5 && gap <= bestGap) {
      continue;
    }
    best = point;
    bestGap = gap;
    bestDist = dist;
  }
  return best;
}

export function isRadarAggregate(groups: { nodes: unknown[] }[]): boolean {
  const total = groups.reduce((sum, group) => sum + group.nodes.length, 0);
  return groups.length > 1 && (groups.length > 12 || total > RADAR_DETAIL_LIMIT);
}
