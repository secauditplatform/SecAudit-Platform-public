import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api, type SearchResultItem, type SearchResultType } from "../api/client";
import { useTranslation } from "../i18n/I18nProvider";
import { IconSearch } from "./ui/Icons";

const TYPE_ORDER: SearchResultType[] = ["host", "job", "run", "profile", "remediation"];

const TYPE_BADGE_VARIANT: Record<SearchResultType, string> = {
  host: "info",
  job: "neutral",
  run: "success",
  profile: "warning",
  remediation: "danger",
};

function useDebouncedValue<T>(value: T, delayMs: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delayMs);
    return () => window.clearTimeout(timer);
  }, [value, delayMs]);
  return debounced;
}

export function GlobalSearch() {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const rootRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [activeIndex, setActiveIndex] = useState(0);
  const debouncedQuery = useDebouncedValue(query.trim(), 250);

  const search = useQuery({
    queryKey: ["global-search", debouncedQuery],
    queryFn: () => api.search({ q: debouncedQuery, limit: 25, per_type: 5 }),
    enabled: open && debouncedQuery.length > 0,
  });

  const items = search.data?.items ?? [];

  const grouped = useMemo(() => {
    const map = new Map<SearchResultType, SearchResultItem[]>();
    for (const item of items) {
      const list = map.get(item.type) ?? [];
      list.push(item);
      map.set(item.type, list);
    }
    return TYPE_ORDER.filter((type) => map.has(type)).map((type) => ({
      type,
      items: map.get(type)!,
    }));
  }, [items]);

  const flatItems = useMemo(() => grouped.flatMap((group) => group.items), [grouped]);

  useEffect(() => {
    setActiveIndex(0);
  }, [debouncedQuery, items.length]);

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setOpen(false);
        setQuery("");
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [open]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(event.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onPointerDown);
    return () => document.removeEventListener("mousedown", onPointerDown);
  }, [open]);

  const openPanel = () => {
    setOpen(true);
    window.setTimeout(() => inputRef.current?.focus(), 0);
  };

  const closePanel = () => {
    setOpen(false);
    setQuery("");
  };

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      const key = event.key.toLowerCase();
      if ((event.metaKey || event.ctrlKey) && key === "k") {
        event.preventDefault();
        setOpen(true);
        window.setTimeout(() => inputRef.current?.focus(), 0);
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, []);

  const selectItem = (item: SearchResultItem) => {
    navigate(item.href);
    closePanel();
  };

  const onInputKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      if (flatItems.length === 0) return;
      setActiveIndex((prev) => (prev + 1) % flatItems.length);
      return;
    }
    if (event.key === "ArrowUp") {
      event.preventDefault();
      if (flatItems.length === 0) return;
      setActiveIndex((prev) => (prev - 1 + flatItems.length) % flatItems.length);
      return;
    }
    if (event.key === "Enter") {
      event.preventDefault();
      const item = flatItems[activeIndex];
      if (item) selectItem(item);
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      closePanel();
    }
  };

  const typeLabel = (type: SearchResultType) => t(`search.types.${type}`);

  const showIdle = !debouncedQuery;
  const showLoading = Boolean(debouncedQuery && search.isFetching);
  const showEmpty = Boolean(debouncedQuery && !search.isFetching && flatItems.length === 0);
  const showResults = flatItems.length > 0;

  return (
    <div className="pf-global-search" ref={rootRef}>
      <button
        type="button"
        className="pf-global-search__trigger"
        onClick={openPanel}
        aria-label={t("search.openAria")}
        aria-expanded={open}
        aria-haspopup="dialog"
      >
        <IconSearch />
        <span className="pf-global-search__trigger-label">{t("search.placeholder")}</span>
        <kbd className="pf-global-search__shortcut" aria-hidden>
          {navigator.platform.includes("Mac") ? "⌘K" : "Ctrl+K"}
        </kbd>
      </button>

      {open && (
        <div className="pf-global-search__panel" role="dialog" aria-label={t("search.title")}>
          <div className="pf-global-search__input-wrap">
            <IconSearch />
            <input
              ref={inputRef}
              type="search"
              className="pf-global-search__input"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              onKeyDown={onInputKeyDown}
              placeholder={t("search.placeholder")}
              aria-label={t("search.placeholder")}
              autoComplete="off"
              autoFocus
            />
          </div>

          <div className="pf-global-search__results" role="listbox">
            {showIdle && (
              <div className="pf-global-search__state">
                <div className="pf-global-search__state-icon" aria-hidden="true">
                  <IconSearch />
                </div>
                <div className="pf-global-search__state-title">{t("search.hintTitle")}</div>
                <div className="pf-global-search__state-desc">{t("search.hint")}</div>
              </div>
            )}
            {showLoading && (
              <div className="pf-global-search__state pf-global-search__state--loading" role="status">
                <span className="pf-global-search__spinner" aria-hidden="true" />
                <div className="pf-global-search__state-title">{t("common.loading")}</div>
              </div>
            )}
            {showEmpty && (
              <div className="pf-global-search__state">
                <div className="pf-global-search__state-title">{t("search.empty")}</div>
                <div className="pf-global-search__state-desc">{t("search.emptyHint")}</div>
              </div>
            )}
            {showResults &&
              grouped.map((group) => (
                <div key={group.type} className="pf-global-search__group">
                  <div className="pf-global-search__group-title">{typeLabel(group.type)}</div>
                  {group.items.map((item) => {
                    const index = flatItems.indexOf(item);
                    const active = index === activeIndex;
                    return (
                      <button
                        key={`${item.type}-${item.id}`}
                        type="button"
                        role="option"
                        aria-selected={active}
                        className={`pf-global-search__item${active ? " pf-global-search__item--active" : ""}`}
                        onMouseEnter={() => setActiveIndex(index)}
                        onClick={() => selectItem(item)}
                      >
                        <span
                          className={`pf-global-search__type-badge pf-label pf-label--${TYPE_BADGE_VARIANT[item.type]}`}
                        >
                          {typeLabel(item.type)}
                        </span>
                        <span className="pf-global-search__item-body">
                          <span className="pf-global-search__item-title">{item.title}</span>
                          {item.subtitle && (
                            <span className="pf-global-search__item-subtitle">{item.subtitle}</span>
                          )}
                        </span>
                      </button>
                    );
                  })}
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
}
