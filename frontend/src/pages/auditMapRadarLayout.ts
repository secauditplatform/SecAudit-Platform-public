/** Pure geometry for the Audit Map radar display. */

export const RADAR_W = 1200;
export const RADAR_H = 680;
/** Above this many visible hosts the radar collapses subnets into clusters. */
export const RADAR_DETAIL_LIMIT = 60;

export type RadarGroupCount = { key: string | null; count: number };
export type RadarCluster = {
  key: string | null;
  angle: number;
  gx: number;
  gy: number;
  r: number;
  count: number;
};

export function buildRadarClusters(
  groups: RadarGroupCount[],
  width = RADAR_W,
  height = RADAR_H,
): RadarCluster[] {
  const total = groups.length;
  const single = total === 1;
  // Many groups need a circle: an ellipse makes the side clusters collide.
  const ring = total > 12 ? 300 : null;
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
    const gx = grid ? grid[index][0] : width / 2 + (ring ?? 300) * Math.cos(angle);
    const gy = grid ? grid[index][1] : height / 2 + (ring ?? 180) * Math.sin(angle);
    // Fewer groups can afford a much wider host ring, so long names fit.
    const maxNodeRadius = total <= 4 ? 150 : total <= 8 ? 105 : 90;
    const base =
      group.count <= 1
        ? 0
        : single
          ? Math.min(250, 60 + (group.count - 1) * 9)
          : 44 + Math.min(maxNodeRadius - 44, (group.count - 1) * 10);
    // Keep the ring inside the stage even for the top/bottom clusters.
    const room = Math.min(gx, width - gx, gy, height - gy) - 34;
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

export function isRadarAggregate(groups: { nodes: unknown[] }[]): boolean {
  const total = groups.reduce((sum, group) => sum + group.nodes.length, 0);
  return groups.length > 1 && (groups.length > 12 || total > RADAR_DETAIL_LIMIT);
}
