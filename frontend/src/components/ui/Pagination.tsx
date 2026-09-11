import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "../../i18n/I18nProvider";
import { Button } from "./Button";

const DEFAULT_PAGE_SIZE = 25;

export { DEFAULT_PAGE_SIZE };

export function useServerPagination(total: number, pageSize = DEFAULT_PAGE_SIZE) {
  const [page, setPage] = useState(1);
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);

  const safePage = Math.min(page, totalPages);
  const offset = (safePage - 1) * pageSize;
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + pageSize, total);

  return {
    page: safePage,
    setPage,
    pageSize,
    offset,
    total,
    totalPages,
    from,
    to,
  };
}

export function usePagination<T>(items: T[], pageSize = DEFAULT_PAGE_SIZE) {
  const [page, setPage] = useState(1);

  const total = items.length;
  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  useEffect(() => {
    if (page > totalPages) {
      setPage(totalPages);
    }
  }, [page, totalPages]);

  const safePage = Math.min(page, totalPages);
  const from = total === 0 ? 0 : (safePage - 1) * pageSize + 1;
  const to = Math.min(safePage * pageSize, total);

  const pageItems = useMemo(
    () => items.slice((safePage - 1) * pageSize, safePage * pageSize),
    [items, safePage, pageSize]
  );

  return {
    page: safePage,
    setPage,
    pageSize,
    total,
    totalPages,
    from,
    to,
    items: pageItems,
  };
}

type PaginationProps = {
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
};

export function Pagination({ page, pageSize, total, onPageChange }: PaginationProps) {
  const { t } = useTranslation();

  if (total <= pageSize) return null;

  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, total);

  return (
    <div className="pf-pagination">
      <span className="pf-pagination__info">
        {t("pagination.info", { from, to, total })}
      </span>
      <div className="pf-pagination__controls">
        <Button
          variant="secondary"
          className="pf-btn--sm"
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1}
        >
          {t("pagination.previous")}
        </Button>
        <Button
          variant="secondary"
          className="pf-btn--sm"
          onClick={() => onPageChange(page + 1)}
          disabled={page >= totalPages}
        >
          {t("pagination.next")}
        </Button>
      </div>
    </div>
  );
}
