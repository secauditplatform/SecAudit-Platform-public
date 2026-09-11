import { useMemo, useState } from "react";

export type SortDirection = "asc" | "desc";

export type SortState<K extends string> = {
  key: K;
  direction: SortDirection;
};

function compareValues(a: unknown, b: unknown): number {
  if (a == null && b == null) return 0;
  if (a == null) return 1;
  if (b == null) return -1;
  if (typeof a === "number" && typeof b === "number") return a - b;
  if (typeof a === "boolean" && typeof b === "boolean") return Number(a) - Number(b);
  return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" });
}

export function useTableSort<T, K extends string>(
  rows: T[],
  defaultSort: SortState<K>,
  accessor: (row: T, key: K) => unknown
) {
  const [sort, setSort] = useState<SortState<K>>(defaultSort);

  const sortedRows = useMemo(() => {
    const copy = [...rows];
    copy.sort((left, right) => {
      const cmp = compareValues(accessor(left, sort.key), accessor(right, sort.key));
      return sort.direction === "asc" ? cmp : -cmp;
    });
    return copy;
  }, [rows, sort, accessor]);

  const toggleSort = (key: K) => {
    setSort((prev) =>
      prev.key === key
        ? { key, direction: prev.direction === "asc" ? "desc" : "asc" }
        : { key, direction: "asc" }
    );
  };

  return { sort, toggleSort: toggleSort as (key: K) => void, sortedRows };
}
