export type MapPoint = { x: number; y: number };

/** Matches `.pf-audit-map__object`. Height fits the name, address, port, and one stats row. */
export const AUDIT_MAP_CARD_W = 208;
export const AUDIT_MAP_CARD_H = 112;
/** Opening scale is the 1:1 view. Fit never zooms in past it. */
export const AUDIT_MAP_DEFAULT_ZOOM = 1;
export const AUDIT_MAP_MIN_ZOOM = 0.2;
export const AUDIT_MAP_MAX_ZOOM = 2.2;

const CARD_GAP = 16;
const PAD_X = 18;
const PAD_TOP = 54;
const PAD_BOTTOM = 18;
const FRAME_GAP = 32;
const WORLD_MARGIN = 20;
const WORLD_WIDTH = 1680;
const BOTTOM_GUTTER = 76;
const CLEARANCE = 8;

export type MapLayoutGroup = {
  key: string | null;
  status: string;
  nodes: { host_id: number; status: string }[];
};

export type MapFrame = {
  key: string;
  status: string;
  top: number;
  left: number;
  width: number;
  height: number;
  count: number;
  stats: Record<string, number>;
};

function columnsFor(total: number): number {
  if (total <= 1) return 1;
  if (total <= 4) return 2;
  if (total <= 9) return 3;
  return 4;
}

function overlaps(a: MapPoint, b: MapPoint): boolean {
  return (
    a.x < b.x + AUDIT_MAP_CARD_W + CLEARANCE &&
    a.x + AUDIT_MAP_CARD_W + CLEARANCE > b.x &&
    a.y < b.y + AUDIT_MAP_CARD_H + CLEARANCE &&
    a.y + AUDIT_MAP_CARD_H + CLEARANCE > b.y
  );
}

function gridPoint(left: number, top: number, index: number, cols: number): MapPoint {
  const col = index % cols;
  const row = Math.floor(index / cols);
  return {
    x: left + PAD_X + col * (AUDIT_MAP_CARD_W + CARD_GAP),
    y: top + PAD_TOP + row * (AUDIT_MAP_CARD_H + CARD_GAP),
  };
}

function insideFrame(point: MapPoint, left: number, top: number, width: number, height: number): boolean {
  return (
    point.x >= left + PAD_X - 2 &&
    point.y >= top + PAD_TOP - 2 &&
    point.x + AUDIT_MAP_CARD_W <= left + width - PAD_X + 2 &&
    point.y + AUDIT_MAP_CARD_H <= top + height - PAD_BOTTOM + 2
  );
}

export function packAuditMap(
  groups: MapLayoutGroup[],
  saved: Map<number, MapPoint>,
  draft: Record<string, MapPoint>,
  useSaved: boolean,
): { placed: Map<string, MapPoint>; frames: MapFrame[]; height: number; width: number } {
  const placed = new Map<string, MapPoint>();
  const frames: MapFrame[] = [];
  let cursorX = WORLD_MARGIN;
  let cursorY = WORLD_MARGIN;
  let rowHeight = 0;

  for (const group of groups) {
    const total = group.nodes.length;
    const cols = columnsFor(total);
    const rows = Math.max(1, Math.ceil(total / cols));
    const boxWidth = PAD_X * 2 + cols * AUDIT_MAP_CARD_W + Math.max(0, cols - 1) * CARD_GAP;
    const boxHeight = PAD_TOP + rows * AUDIT_MAP_CARD_H + Math.max(0, rows - 1) * CARD_GAP + PAD_BOTTOM;
    if (cursorX > WORLD_MARGIN && cursorX + boxWidth > WORLD_WIDTH - WORLD_MARGIN) {
      cursorX = WORLD_MARGIN;
      cursorY += rowHeight + FRAME_GAP;
      rowHeight = 0;
    }

    const frameKey = group.key ?? "";
    const stats: Record<string, number> = { pass: 0, fail: 0, error: 0, unchecked: 0 };
    for (const node of group.nodes) stats[node.status] = (stats[node.status] ?? 0) + 1;
    frames.push({
      key: frameKey,
      status: group.status,
      top: cursorY,
      left: cursorX,
      width: boxWidth,
      height: boxHeight,
      count: total,
      stats,
    });

    const occupied: MapPoint[] = [];
    const cells = Array.from({ length: Math.max(total, 1) }, (_, index) =>
      gridPoint(cursorX, cursorY, index, cols),
    );
    group.nodes.forEach((node, index) => {
      const id = `${frameKey}:${node.host_id}`;
      const moved = draft[id];
      let point: MapPoint | null = null;
      if (moved) {
        point = moved;
      } else if (useSaved) {
        const stored = saved.get(node.host_id);
        if (
          stored &&
          insideFrame(stored, cursorX, cursorY, boxWidth, boxHeight) &&
          !occupied.some((item) => overlaps(item, stored))
        ) {
          point = stored;
        }
      }
      if (!point) {
        point =
          cells.find((cell) => !occupied.some((item) => overlaps(item, cell))) ??
          cells[Math.min(index, cells.length - 1)];
      }
      placed.set(id, point);
      occupied.push(point);
    });

    cursorX += boxWidth + FRAME_GAP;
    rowHeight = Math.max(rowHeight, boxHeight);
  }

  return {
    placed,
    frames,
    height: Math.max(420, cursorY + rowHeight + BOTTOM_GUTTER),
    width: WORLD_WIDTH,
  };
}

export function fitAuditMapCamera(
  points: Iterable<MapPoint>,
  viewport: { width: number; height: number },
  padding = 36,
): { zoom: number; pan: MapPoint } {
  let minX = Infinity;
  let minY = Infinity;
  let maxX = -Infinity;
  let maxY = -Infinity;
  let count = 0;
  for (const point of points) {
    count += 1;
    minX = Math.min(minX, point.x);
    minY = Math.min(minY, point.y);
    maxX = Math.max(maxX, point.x + AUDIT_MAP_CARD_W);
    maxY = Math.max(maxY, point.y + AUDIT_MAP_CARD_H);
  }
  if (count === 0 || viewport.width < 40 || viewport.height < 40) {
    return { zoom: AUDIT_MAP_DEFAULT_ZOOM, pan: { x: padding, y: padding } };
  }
  const width = Math.max(1, maxX - minX);
  const height = Math.max(1, maxY - minY);
  const availW = Math.max(1, viewport.width - padding * 2);
  const availH = Math.max(1, viewport.height - padding * 2);
  const fit = Math.min(availW / width, availH / height);
  const zoom = Math.min(AUDIT_MAP_DEFAULT_ZOOM, Math.max(AUDIT_MAP_MIN_ZOOM, fit));
  return {
    zoom,
    pan: {
      x: (viewport.width - width * zoom) / 2 - minX * zoom,
      y: (viewport.height - height * zoom) / 2 - minY * zoom,
    },
  };
}
