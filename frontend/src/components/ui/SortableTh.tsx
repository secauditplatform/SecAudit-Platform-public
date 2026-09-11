import type { ReactNode } from "react";
import type { SortDirection } from "../../hooks/useTableSort";

type SortableThProps<K extends string> = {
  label: ReactNode;
  sortKey: K;
  activeKey: K;
  direction: SortDirection;
  onSort: (key: K) => void;
  className?: string;
};

export function SortableTh<K extends string>({
  label,
  sortKey,
  activeKey,
  direction,
  onSort,
  className,
}: SortableThProps<K>) {
  const isActive = activeKey === sortKey;
  const indicator = isActive ? (direction === "asc" ? " ▲" : " ▼") : "";

  return (
    <th className={className}>
      <button
        type="button"
        className={`pf-table__sort${isActive ? " pf-table__sort--active" : ""}`}
        onClick={() => onSort(sortKey)}
      >
        {label}
        {indicator}
      </button>
    </th>
  );
}
