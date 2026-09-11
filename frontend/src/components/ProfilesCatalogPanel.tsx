import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { api, type ProfileRule, type ProfilesCatalogEntry } from "../api/client";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Spinner } from "./ui/Spinner";
import { useToast } from "./ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";

function formatSyncInterval(seconds: number, t: (key: string, vars?: Record<string, string | number>) => string): string {
  if (seconds >= 3600 && seconds % 3600 === 0) {
    return t("profiles.catalogSyncIntervalHours", { count: seconds / 3600 });
  }
  if (seconds >= 60 && seconds % 60 === 0) {
    return t("profiles.catalogSyncIntervalMinutes", { count: seconds / 60 });
  }
  return `${seconds}s`;
}

function familyBadgeVariant(_family: string): "success" | "warning" | "info" | "neutral" {
  return "neutral";
}

function versionSortKey(version: string | null | undefined): number[] {
  return String(version || "0")
    .split(/[.\-_]/)
    .map((part) => (/^\d+$/.test(part) ? Number(part) : 0));
}

function compareVersion(a: string | null | undefined, b: string | null | undefined): number {
  const left = versionSortKey(a);
  const right = versionSortKey(b);
  const len = Math.max(left.length, right.length);
  for (let i = 0; i < len; i += 1) {
    const diff = (left[i] ?? 0) - (right[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

function enrichCatalogEntries(entries: ProfilesCatalogEntry[]): ProfilesCatalogEntry[] {
  const newest = new Map<string, string>();
  for (const entry of entries) {
    const current = newest.get(entry.profile_name);
    if (!current || compareVersion(entry.version, current) > 0) {
      newest.set(entry.profile_name, entry.version);
    }
  }

  return [...entries]
    .map((entry) => {
      const latest = newest.get(entry.profile_name) ?? entry.version;
      const isLatest = compareVersion(entry.version, latest) === 0;
      const updateAvailable = Boolean(
        entry.imported_version && compareVersion(latest, entry.imported_version) > 0
      );
      return { ...entry, is_latest: isLatest, update_available: updateAvailable };
    })
    .sort((a, b) => {
      const familyCmp = a.profile_family.localeCompare(b.profile_family);
      if (familyCmp !== 0) return familyCmp;
      const labelCmp = a.profile_name.localeCompare(b.profile_name, undefined, { sensitivity: "base" });
      if (labelCmp !== 0) return labelCmp;
      const techCmp = a.profile_name.localeCompare(b.profile_name);
      if (techCmp !== 0) return techCmp;
      return compareVersion(a.version, b.version);
    });
}

export function ProfilesCatalogPanel() {
  const { t, dateLocale } = useTranslation();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [platformFilter, setPlatformFilter] = useState("all");
  const [search, setSearch] = useState("");
  const [selectedPaths, setSelectedPaths] = useState<Set<string>>(new Set());
  const [updateExisting, setUpdateExisting] = useState(true);
  const [previewEntry, setPreviewEntry] = useState<ProfilesCatalogEntry | null>(null);
  const [catalogEntries, setCatalogEntries] = useState<ProfilesCatalogEntry[]>([]);
  const [catalogScanning, setCatalogScanning] = useState(true);
  const [catalogError, setCatalogError] = useState<string | null>(null);
  const [catalogReloadToken, setCatalogReloadToken] = useState(0);
  const flushTimerRef = useRef<number | null>(null);
  const pendingEntriesRef = useRef<ProfilesCatalogEntry[]>([]);

  const syncStatus = useQuery({
    queryKey: ["profiles-catalog-sync-status"],
    queryFn: () => api.profilesCatalogSyncStatus(),
    staleTime: 60_000,
  });

  const preview = useQuery({
    queryKey: ["catalog-rules-preview", previewEntry?.package_path ?? null],
    queryFn: () => api.previewCatalogRules(previewEntry!.package_path, 200),
    enabled: previewEntry != null,
  });

  useEffect(() => {
    const controller = new AbortController();
    let cancelled = false;

    const flushPending = (force = false) => {
      if (!pendingEntriesRef.current.length) return;
      if (!force && pendingEntriesRef.current.length < 4) return;
      const batch = pendingEntriesRef.current;
      pendingEntriesRef.current = [];
      setCatalogEntries((prev) => {
        const byPath = new Map(prev.map((item) => [item.package_path, item]));
        for (const item of batch) {
          byPath.set(item.package_path, item);
        }
        return enrichCatalogEntries(Array.from(byPath.values()));
      });
    };

    const scheduleFlush = () => {
      if (flushTimerRef.current != null) return;
      flushTimerRef.current = window.setTimeout(() => {
        flushTimerRef.current = null;
        flushPending(true);
      }, 80);
    };

    setCatalogEntries([]);
    setCatalogError(null);
    setCatalogScanning(true);
    pendingEntriesRef.current = [];

    (async () => {
      try {
        for await (const item of api.streamProfilesCatalog(
          undefined,
          platformFilter === "all" ? undefined : platformFilter,
          controller.signal
        )) {
          if (cancelled) break;
          if ("type" in item && item.type === "done") {
            flushPending(true);
            break;
          }
          pendingEntriesRef.current.push(item as ProfilesCatalogEntry);
          scheduleFlush();
        }
        if (!cancelled) {
          flushPending(true);
          setCatalogScanning(false);
        }
      } catch (error) {
        if (cancelled || (error instanceof DOMException && error.name === "AbortError")) {
          return;
        }
        setCatalogError(error instanceof Error ? error.message : String(error));
        setCatalogScanning(false);
      }
    })();

    return () => {
      cancelled = true;
      controller.abort();
      if (flushTimerRef.current != null) {
        window.clearTimeout(flushTimerRef.current);
        flushTimerRef.current = null;
      }
    };
  }, [platformFilter, catalogReloadToken]);

  const filtered = useMemo(() => {
    const query = search.trim().toLowerCase();
    if (!query) return catalogEntries;
    return catalogEntries.filter((entry) => {
      const haystack = `${entry.profile_name} ${entry.summary ?? ""} ${entry.benchmark_ref ?? ""}`.toLowerCase();
      return haystack.includes(query);
    });
  }, [catalogEntries, search]);

  const syncQueue = useMemo(() => {
    const latestByName = new Map<string, ProfilesCatalogEntry>();
    for (const entry of catalogEntries) {
      if (!entry.is_latest) continue;
      latestByName.set(entry.profile_name, entry);
    }
    let pendingImports = 0;
    let pendingUpdates = 0;
    for (const entry of latestByName.values()) {
      if (!entry.imported_version) pendingImports += 1;
      else if (entry.update_available) pendingUpdates += 1;
    }
    return { pendingImports, pendingUpdates };
  }, [catalogEntries]);

  const importable = filtered.filter((entry) => !entry.imported);
  const allImportableSelected =
    importable.length > 0 && importable.every((entry) => selectedPaths.has(entry.package_path));

  const togglePath = (path: string) => {
    setSelectedPaths((prev) => {
      const next = new Set(prev);
      if (next.has(path)) next.delete(path);
      else next.add(path);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (allImportableSelected) {
      setSelectedPaths(new Set());
      return;
    }
    setSelectedPaths(new Set(importable.map((entry) => entry.package_path)));
  };

  const bulkImport = useMutation({
    mutationFn: (paths: string[]) => api.importProfilesBulk(paths, true, updateExisting),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["profiles"] });
      queryClient.invalidateQueries({ queryKey: ["profiles-catalog-sync-status"] });
      setCatalogReloadToken((token) => token + 1);
      setSelectedPaths(new Set());
      const imported = result.imported.length;
      const skipped = result.skipped.length;
      if (result.errors.length > 0) {
        toast.error(
          t("profiles.catalogImportPartial", {
            imported,
            skipped,
            errors: result.errors.length,
          })
        );
      } else {
        toast.success(
          t(
            updateExisting
              ? "profiles.catalogImportSuccessWithUpdates"
              : "profiles.catalogImportSuccess",
            { imported, skipped }
          )
        );
      }
    },
    onError: (error: Error) => toast.error(error.message),
  });

  const renderRow = (entry: ProfilesCatalogEntry) => {
    const checked = selectedPaths.has(entry.package_path);
    return (
      <tr key={entry.package_path} className={entry.imported ? "pf-catalog-row--imported" : undefined}>
        <td>
          <input
            type="checkbox"
            className="pf-checkbox-control"
            checked={checked}
            disabled={entry.imported || bulkImport.isPending}
            onChange={() => togglePath(entry.package_path)}
            aria-label={t("profiles.catalogSelect", { name: entry.profile_name })}
          />
        </td>
        <td>
          <div className="pf-catalog-row__title">{entry.profile_name}</div>
        </td>
        <td>
          <Badge variant={familyBadgeVariant(entry.profile_family)}>
            {t(`profiles.profileFamily.${entry.profile_family}`)}
          </Badge>
        </td>
        <td>{t(`profiles.platform.${entry.platform}`)}</td>
        <td className="pf-catalog-row__benchmark">{entry.benchmark_ref ?? t("common.dash")}</td>
        <td>{entry.version}</td>
        <td>
          {entry.imported ? (
            <div className="pf-table__actions" style={{ justifyContent: "flex-start" }}>
              <Badge variant="success">{t("profiles.catalogImported")}</Badge>
              {entry.update_available && entry.is_latest ? (
                <Badge variant="warning">{t("profiles.catalogUpdateAvailable")}</Badge>
              ) : null}
            </div>
          ) : (
            <Badge variant="neutral">{t("profiles.catalogAvailable")}</Badge>
          )}
        </td>
        <td>
          <div className="pf-table__actions">
            <Button
              variant="secondary"
              className="pf-btn--sm"
              onClick={() => setPreviewEntry(entry)}
            >
              {t("profiles.catalogPreviewRules")}
            </Button>
          </div>
        </td>
      </tr>
    );
  };

  return (
    <div className="pf-profiles-catalog">
      <p className="pf-profiles-catalog__hint">{t("profiles.catalogHint")}</p>

      <div className="pf-profiles-catalog__sync" aria-live="polite">
        <div className="pf-profiles-catalog__sync-top">
          <div className="pf-profiles-catalog__sync-title">
            <strong>{t("profiles.catalogSyncTitle")}</strong>
            {syncStatus.isLoading ? (
              <Spinner />
            ) : (
              <Badge variant={syncStatus.data?.enabled ? "success" : "neutral"}>
                {syncStatus.data?.enabled
                  ? t("profiles.catalogSyncEnabled")
                  : t("profiles.catalogSyncDisabled")}
              </Badge>
            )}
          </div>
          {syncStatus.data ? (
            <div className="pf-profiles-catalog__sync-inline">
              <span>
                {t("profiles.catalogSyncInterval", {
                  interval: formatSyncInterval(syncStatus.data.interval_seconds, t),
                })}
              </span>
              <span>
                {syncStatus.data.mount_available
                  ? t("profiles.catalogSyncMount", { path: syncStatus.data.mount_path })
                  : t("profiles.catalogSyncMountMissing")}
              </span>
            </div>
          ) : null}
        </div>

        {syncStatus.data ? (
          <div className="pf-profiles-catalog__sync-body">
            <div className="pf-profiles-catalog__sync-queue">
              {syncQueue.pendingImports > 0 ? (
                <Badge variant="info">
                  {t("profiles.catalogSyncPendingImports", {
                    count: syncQueue.pendingImports,
                  })}
                </Badge>
              ) : null}
              {syncQueue.pendingUpdates > 0 ? (
                <Badge variant="warning">
                  {t("profiles.catalogSyncPendingUpdates", {
                    count: syncQueue.pendingUpdates,
                  })}
                </Badge>
              ) : null}
              {!catalogScanning &&
              syncQueue.pendingImports === 0 &&
              syncQueue.pendingUpdates === 0 ? (
                <span className="pf-profiles-catalog__sync-muted">
                  {t("profiles.catalogSyncPendingNone")}
                </span>
              ) : null}
            </div>

            <div className="pf-profiles-catalog__sync-last-run">
              {syncStatus.data.last_run_at ? (
                <>
                  <span>
                    {t("profiles.catalogSyncLastRun", {
                      time: new Date(syncStatus.data.last_run_at).toLocaleString(dateLocale),
                    })}
                  </span>
                  {syncStatus.data.last_run_skipped ? (
                    <span className="pf-profiles-catalog__sync-muted">
                      {t("profiles.catalogSyncLastRunSkipped", {
                        reason:
                          syncStatus.data.last_run_skip_reason ===
                          "profiles_catalog_sync_disabled"
                            ? t(
                                "profiles.catalogSyncSkipReason.profiles_catalog_sync_disabled"
                              )
                            : syncStatus.data.last_run_skip_reason === "lock_not_acquired"
                              ? t("profiles.catalogSyncSkipReason.lock_not_acquired")
                              : syncStatus.data.last_run_skip_reason || t("common.dash"),
                      })}
                    </span>
                  ) : (
                    <div className="pf-profiles-catalog__sync-metrics">
                      {syncStatus.data.last_imported_count > 0 ? (
                        <span className="pf-profiles-catalog__sync-metric pf-profiles-catalog__sync-metric--ok">
                          {t("profiles.catalogSyncMetricImported", {
                            count: syncStatus.data.last_imported_count,
                          })}
                        </span>
                      ) : null}
                      {syncStatus.data.last_updated_count > 0 ? (
                        <span className="pf-profiles-catalog__sync-metric pf-profiles-catalog__sync-metric--ok">
                          {t("profiles.catalogSyncMetricUpdated", {
                            count: syncStatus.data.last_updated_count,
                          })}
                        </span>
                      ) : null}
                      {syncStatus.data.last_skipped_count > 0 ? (
                        <span className="pf-profiles-catalog__sync-metric">
                          {t("profiles.catalogSyncMetricSkipped", {
                            count: syncStatus.data.last_skipped_count,
                          })}
                        </span>
                      ) : null}
                      {syncStatus.data.last_error_count > 0 ? (
                        <span className="pf-profiles-catalog__sync-metric pf-profiles-catalog__sync-metric--error">
                          {t("profiles.catalogSyncMetricErrors", {
                            count: syncStatus.data.last_error_count,
                          })}
                        </span>
                      ) : null}
                    </div>
                  )}
                </>
              ) : (
                <span className="pf-profiles-catalog__sync-muted">
                  {t("profiles.catalogSyncLastRunNever")}
                </span>
              )}
            </div>
          </div>
        ) : null}
      </div>

      <div className="pf-profiles-catalog__toolbar">
        <div className="pf-profiles-catalog__filter-row">
          <input
            type="search"
            className="pf-input"
            placeholder={t("profiles.catalogSearchPlaceholder")}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
          <select
            className="pf-select"
            value={platformFilter}
            onChange={(event) => setPlatformFilter(event.target.value)}
            aria-label={t("profiles.catalogPlatformColumn")}
          >
            <option value="all">{t("profiles.catalogPlatformAll")}</option>
            <option value="linux">{t("profiles.platform.linux")}</option>
            <option value="windows">{t("profiles.platform.windows")}</option>
            <option value="network">{t("profiles.platform.network")}</option>
          </select>
        </div>

        <div className="pf-profiles-catalog__action-row">
          <label className="pf-profiles-catalog__option">
            <input
              type="checkbox"
              className="pf-checkbox-control"
              checked={updateExisting}
              onChange={(event) => setUpdateExisting(event.target.checked)}
            />
            <span>{t("profiles.catalogUpdateImported")}</span>
          </label>
          <div className="pf-profiles-catalog__action-group">
            <Button
              variant="secondary"
              className="pf-btn--sm"
              disabled={importable.length === 0 || bulkImport.isPending}
              onClick={toggleSelectAll}
            >
              {allImportableSelected
                ? t("profiles.catalogClearSelection")
                : t("profiles.catalogSelectAll")}
            </Button>
            <Button
              variant="primary"
              className="pf-btn--sm"
              disabled={selectedPaths.size === 0 || bulkImport.isPending}
              onClick={() => bulkImport.mutate(Array.from(selectedPaths))}
            >
              {bulkImport.isPending
                ? t("profiles.importing")
                : t("profiles.catalogImportSelected", { count: selectedPaths.size })}
            </Button>
          </div>
        </div>
      </div>

      {catalogScanning ? (
        <div className="pf-profiles-catalog__scan-status">
          <Spinner />
          <span>
            {t("profiles.catalogScanning")}
            {catalogEntries.length > 0
              ? ` · ${t("profiles.catalogScanProgress", { count: catalogEntries.length })}`
              : null}
          </span>
        </div>
      ) : null}

      {catalogError ? (
        <div className="pf-alert pf-alert--error">{catalogError}</div>
      ) : !catalogScanning && filtered.length === 0 ? (
        <p className="pf-profiles-catalog__empty">{t("profiles.catalogEmpty")}</p>
      ) : filtered.length > 0 ? (
        <div className="pf-table-wrap">
          <table className="pf-table pf-table--compact">
            <thead>
              <tr>
                <th scope="col" aria-label={t("profiles.catalogSelectColumn")} />
                <th scope="col">{t("common.name")}</th>
                <th scope="col">{t("profiles.catalogFamilyColumn")}</th>
                <th scope="col">{t("profiles.catalogPlatformColumn")}</th>
                <th scope="col">{t("profiles.catalogBenchmarkColumn")}</th>
                <th scope="col">{t("profiles.version")}</th>
                <th scope="col">{t("common.status")}</th>
                <th scope="col">{t("common.actions")}</th>
              </tr>
            </thead>
            <tbody>{filtered.map(renderRow)}</tbody>
          </table>
        </div>
      ) : null}

      {previewEntry ? (
        <div className="pf-modal pf-modal--script" role="presentation" onClick={() => setPreviewEntry(null)}>
          <div
            className="pf-modal__panel pf-modal__panel--script"
            role="dialog"
            aria-modal="true"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="pf-modal__header">
              <div>
                <h3 className="pf-modal__title">{t("profiles.catalogPreviewTitle")}</h3>
                <p className="pf-modal__subtitle">
                  {previewEntry.profile_name} · <span className="pf-table__mono">{previewEntry.version}</span>
                </p>
              </div>
              <Button variant="secondary" className="pf-btn--sm" onClick={() => setPreviewEntry(null)}>
                {t("common.close")}
              </Button>
            </div>
            {preview.isLoading ? <Spinner /> : null}
            {preview.isError ? (
              <div className="pf-alert pf-alert--error">{(preview.error as Error).message}</div>
            ) : null}
            {preview.data ? (
              preview.data.length > 0 ? (
                <div className="pf-table-wrap">
                  <table className="pf-table pf-table--compact">
                    <thead>
                      <tr>
                        <th>{t("profiles.checkItem")}</th>
                        <th>{t("profiles.ruleSummary")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {preview.data.map((rule: ProfileRule, idx) => (
                        <tr key={`${rule.requirement_id}-${idx}`}>
                          <td className="pf-table__mono">{rule.requirement_id || rule.tech_name}</td>
                          <td>{rule.title || rule.explanation || t("common.dash")}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="pf-table__muted">{t("profiles.catalogPreviewEmpty")}</p>
              )
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}
