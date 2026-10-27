/** Pure layout helpers for the risk-treemap design variant. */

export type TreeRect = { x: number; y: number; w: number; h: number };
export type TreeItem<T> = { value: number; order: number; payload: T };

function sumValues<T>(items: TreeItem<T>[]): number {
  return items.reduce((sum, item) => sum + item.value, 0);
}

/** Binary treemap: split by half the mass, alternate on the longer side. Stable and cheap. */
export function treemap<T>(items: TreeItem<T>[], rect: TreeRect): { item: TreeItem<T>; rect: TreeRect }[] {
  if (items.length === 0) return [];
  if (items.length === 1) return [{ item: items[0], rect }];
  const total = sumValues(items);
  let acc = 0;
  let split = items.length - 1;
  for (let index = 0; index < items.length - 1; index += 1) {
    acc += items[index].value;
    if (acc >= total / 2) {
      split = index + 1;
      break;
    }
  }
  const left = items.slice(0, split);
  const right = items.slice(split);
  if (!left.length || !right.length) return [{ item: items[0], rect }];
  const ratio = sumValues(left) / total;
  if (rect.w >= rect.h) {
    const w = rect.w * ratio;
    return [
      ...treemap(left, { x: rect.x, y: rect.y, w, h: rect.h }),
      ...treemap(right, { x: rect.x + w, y: rect.y, w: rect.w - w, h: rect.h }),
    ];
  }
  const h = rect.h * ratio;
  return [
    ...treemap(left, { x: rect.x, y: rect.y, w: rect.w, h }),
    ...treemap(right, { x: rect.x, y: rect.y + h, w: rect.w, h: rect.h - h }),
  ];
}

/** Pick the column count that keeps host cells closest to square, penalising empty cells. */
export function gridColumns(count: number, width: number, height: number): number {
  let best = 1;
  let bestScore = Number.POSITIVE_INFINITY;
  for (let cols = 1; cols <= count; cols += 1) {
    const rows = Math.ceil(count / cols);
    const cellW = width / cols;
    const cellH = height / rows;
    const ratio = Math.max(0.01, cellW / Math.max(1, cellH));
    const score = Math.abs(Math.log(ratio)) + 0.25 * (cols * rows - count);
    if (score < bestScore) {
      bestScore = score;
      best = cols;
    }
  }
  return best;
}

/** Equal-height grid inside a group: the last row stretches to fill the rect. */
export function gridCells<T>(items: T[], rect: TreeRect): { item: T; rect: TreeRect }[] {
  const cols = gridColumns(items.length, rect.w, rect.h);
  const rows = Math.ceil(items.length / cols);
  const cellH = rect.h / rows;
  return items.map((item, index) => {
    const row = Math.floor(index / cols);
    const col = index % cols;
    const inRow = Math.min(cols, items.length - row * cols);
    const cellW = rect.w / inRow;
    return {
      item,
      rect: { x: rect.x + col * cellW, y: rect.y + row * cellH, w: cellW, h: cellH },
    };
  });
}
