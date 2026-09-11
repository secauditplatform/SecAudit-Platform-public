export const OPS_LIST_INITIAL = 20;
export const OPS_LIST_MAX = 50;

export function sliceOpsList<T>(items: T[], expanded: boolean): T[] {
  const limit = expanded ? OPS_LIST_MAX : OPS_LIST_INITIAL;
  return items.slice(0, limit);
}
