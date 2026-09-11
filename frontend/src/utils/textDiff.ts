export type DiffLineKind = "context" | "add" | "del";

export interface DiffLine {
  kind: DiffLineKind;
  text: string;
}

export interface LineDiffStats {
  added: number;
  removed: number;
}

/** Count added/removed lines via a simple LCS-based alignment. */
export function lineDiffStats(before: string, after: string): LineDiffStats {
  const a = before.replace(/\r\n/g, "\n").split("\n");
  const b = after.replace(/\r\n/g, "\n").split("\n");
  const lcs = longestCommonSubsequence(a, b);
  return {
    added: Math.max(0, b.length - lcs),
    removed: Math.max(0, a.length - lcs),
  };
}

/**
 * Build a compact unified diff with surrounding context.
 * Caps output size for large YAML playbooks.
 */
export function buildUnifiedDiff(
  before: string,
  after: string,
  options?: { context?: number; maxLines?: number }
): DiffLine[] {
  const context = options?.context ?? 2;
  const maxLines = options?.maxLines ?? 160;
  let a = before.replace(/\r\n/g, "\n").split("\n");
  let b = after.replace(/\r\n/g, "\n").split("\n");
  // Cap alignment cost for very large YAML playbooks.
  const maxAlign = 1800;
  if (a.length > maxAlign || b.length > maxAlign) {
    a = a.slice(0, maxAlign);
    b = b.slice(0, maxAlign);
  }
  const aligned = alignLines(a, b);

  const changedIdx: number[] = [];
  aligned.forEach((row, index) => {
    if (row.kind !== "context") changedIdx.push(index);
  });
  if (changedIdx.length === 0) return [];

  const keep = new Set<number>();
  for (const index of changedIdx) {
    for (let i = Math.max(0, index - context); i <= Math.min(aligned.length - 1, index + context); i += 1) {
      keep.add(i);
    }
  }

  const out: DiffLine[] = [];
  let lastKept = -2;
  for (let i = 0; i < aligned.length; i += 1) {
    if (!keep.has(i)) continue;
    if (lastKept >= 0 && i - lastKept > 1) {
      out.push({ kind: "context", text: "…" });
    }
    out.push(aligned[i]);
    lastKept = i;
    if (out.length >= maxLines) {
      out.push({ kind: "context", text: "…" });
      break;
    }
  }
  return out;
}

function longestCommonSubsequence(a: string[], b: string[]): number {
  const n = a.length;
  const m = b.length;
  if (n === 0 || m === 0) return 0;
  // Memory-optimized DP: only previous row.
  let prev = new Array<number>(m + 1).fill(0);
  let curr = new Array<number>(m + 1).fill(0);
  for (let i = 1; i <= n; i += 1) {
    for (let j = 1; j <= m; j += 1) {
      curr[j] = a[i - 1] === b[j - 1] ? prev[j - 1] + 1 : Math.max(prev[j], curr[j - 1]);
    }
    const tmp = prev;
    prev = curr;
    curr = tmp;
    curr.fill(0);
  }
  return prev[m];
}

function alignLines(a: string[], b: string[]): DiffLine[] {
  const n = a.length;
  const m = b.length;
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = n - 1; i >= 0; i -= 1) {
    for (let j = m - 1; j >= 0; j -= 1) {
      dp[i][j] =
        a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }

  const out: DiffLine[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      out.push({ kind: "context", text: a[i] });
      i += 1;
      j += 1;
    } else if (dp[i + 1][j] >= dp[i][j + 1]) {
      out.push({ kind: "del", text: a[i] });
      i += 1;
    } else {
      out.push({ kind: "add", text: b[j] });
      j += 1;
    }
  }
  while (i < n) {
    out.push({ kind: "del", text: a[i] });
    i += 1;
  }
  while (j < m) {
    out.push({ kind: "add", text: b[j] });
    j += 1;
  }
  return out;
}
