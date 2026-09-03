import { useEffect, useMemo, useState } from "react";

export const DEFAULT_PAGE_SIZE = 20;

export function usePagination(items = [], resetKey = "", pageSize = DEFAULT_PAGE_SIZE) {
  const [page, setPage] = useState(1);
  const total = items.length;
  const pageCount = Math.max(1, Math.ceil(total / pageSize));

  useEffect(() => {
    setPage(1);
  }, [resetKey, pageSize]);

  useEffect(() => {
    if (page > pageCount) {
      setPage(pageCount);
    }
  }, [page, pageCount]);

  const pageItems = useMemo(() => {
    const start = (page - 1) * pageSize;
    return items.slice(start, start + pageSize);
  }, [items, page, pageSize]);

  return { page, pageCount, pageItems, pageSize, setPage, total };
}

export function Pagination({
  label = "rows",
  onPageChange,
  page,
  pageCount,
  pageSize = DEFAULT_PAGE_SIZE,
  total,
}) {
  if (total <= pageSize) {
    return null;
  }

  const first = (page - 1) * pageSize + 1;
  const last = Math.min(total, page * pageSize);

  return (
    <div className="pagination-bar" aria-label={`${label} pagination`}>
      <button disabled={page <= 1} onClick={() => onPageChange(page - 1)} type="button">
        Previous
      </button>
      <span>
        {first}-{last} of {total} · Page {page} / {pageCount}
      </span>
      <button disabled={page >= pageCount} onClick={() => onPageChange(page + 1)} type="button">
        Next
      </button>
    </div>
  );
}
