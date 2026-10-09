import { useQuery } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, type Host } from "../api/client";
import { HostPicker } from "./HostPicker";
import { Button } from "./ui/Button";
import { useTranslation } from "../i18n/I18nProvider";
import { mergeInventoryHostsIntoTargets } from "../utils/auditFlowInventoryImport";

type AuditFlowInventoryImportProps = {
  currentTargets: string[];
  onImport: (targets: string[], summary: { added: number; skipped: number; truncated: boolean }) => void;
};

export function AuditFlowInventoryImport({ currentTargets, onImport }: AuditFlowInventoryImportProps) {
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [tagFilter, setTagFilter] = useState<string | null>(null);

  const hostsQuery = useQuery({
    queryKey: ["hosts", "audit-flow-import"],
    // API pagination max is 200 (see api/app/pagination.py MAX_PAGE_LIMIT).
    queryFn: () => api.hosts({ limit: 200 }),
    enabled: open,
    retry: 1,
  });
  const tagsQuery = useQuery({
    queryKey: ["host-tags"],
    queryFn: api.hostTags,
    enabled: open,
    retry: 1,
  });

  const allActiveHosts = useMemo(
    () => (hostsQuery.data?.items ?? []).filter((host) => host.is_active),
    [hostsQuery.data?.items]
  );

  const hosts = useMemo(() => {
    if (!tagFilter) return allActiveHosts;
    const needle = tagFilter.toLowerCase();
    return allActiveHosts.filter((host) =>
      (host.tags ?? []).some((tag) => tag.toLowerCase() === needle)
    );
  }, [allActiveHosts, tagFilter]);

  const selectedHosts = useMemo(
    () => allActiveHosts.filter((host) => selectedIds.includes(host.id)),
    [allActiveHosts, selectedIds]
  );

  const toggleHost = (id: number) => {
    setSelectedIds((current) =>
      current.includes(id) ? current.filter((item) => item !== id) : [...current, id]
    );
  };

  const applyImport = () => {
    const result = mergeInventoryHostsIntoTargets(currentTargets, selectedHosts);
    onImport(result.targets, {
      added: result.added,
      skipped: result.skippedDuplicate + result.skippedFingerprint,
      truncated: result.truncated,
    });
    setSelectedIds([]);
    setOpen(false);
    setTagFilter(null);
  };

  const tags = tagsQuery.data ?? [];
  const isBusy = hostsQuery.isPending || hostsQuery.isFetching;

  return (
    <div className="pf-audit-flow-inventory-import">
      <div className="pf-audit-flow-inventory-import__bar">
        <div className="pf-audit-flow-inventory-import__copy">
          <strong className="pf-audit-flow-inventory-import__title">
            {t("auditFlow.importFromInventory")}
          </strong>
          <p className="pf-audit-flow-inventory-import__hint">
            {t("auditFlow.importFromInventoryHint")}
          </p>
        </div>
        <Button
          type="button"
          variant="secondary"
          className="pf-btn--sm"
          onClick={() => setOpen((value) => !value)}
        >
          {open ? t("common.cancel") : t("auditFlow.importFromInventory")}
        </Button>
      </div>

      {open ? (
        <div className="pf-audit-flow-inventory-import__panel">
          {tags.length > 0 ? (
            <div className="pf-audit-flow-inventory-import__tags" role="group" aria-label={t("jobs.dynamicTags")}>
              <button
                type="button"
                className={`pf-audit-flow-inventory-import__tag${tagFilter == null ? " is-active" : ""}`}
                onClick={() => setTagFilter(null)}
              >
                {t("auditFlow.importAllTags")}
              </button>
              {tags.map((tag) => (
                <button
                  key={tag.id}
                  type="button"
                  className={`pf-audit-flow-inventory-import__tag${
                    tagFilter === tag.name ? " is-active" : ""
                  }`}
                  onClick={() => setTagFilter(tag.name)}
                >
                  {tag.name}
                </button>
              ))}
            </div>
          ) : null}

          {isBusy ? (
            <p className="pf-form__hint">{t("common.loading")}</p>
          ) : hostsQuery.isError ? (
            <div className="pf-audit-flow-inventory-import__error">
              <p className="pf-form__hint">
                {hostsQuery.error instanceof Error
                  ? hostsQuery.error.message
                  : t("auditFlow.importLoadFailed")}
              </p>
              <Button
                type="button"
                variant="secondary"
                className="pf-btn--sm"
                onClick={() => void hostsQuery.refetch()}
              >
                {t("common.retry")}
              </Button>
            </div>
          ) : (
            <HostPicker
              hosts={hosts as Host[]}
              selectedIds={selectedIds}
              onToggle={toggleHost}
              onSelectAll={(ids) => setSelectedIds(ids)}
              onClearAll={() => setSelectedIds([])}
              hint={t("auditFlow.importPickerHint")}
            />
          )}

          <div className="pf-audit-flow-inventory-import__actions">
            <span className="pf-form__hint">
              {t("auditFlow.importSelectedCount", { count: selectedIds.length })}
            </span>
            <Button
              type="button"
              className="pf-btn--sm"
              disabled={selectedIds.length === 0 || isBusy || hostsQuery.isError}
              onClick={applyImport}
            >
              {t("auditFlow.importApply")}
            </Button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
