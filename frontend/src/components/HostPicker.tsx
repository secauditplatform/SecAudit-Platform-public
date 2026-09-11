import { useMemo, useState } from "react";
import { HostSelectionToolbar } from "./HostSelectionToolbar";
import { Badge } from "./ui/Badge";
import type { Host } from "../api/client";
import { useTranslation } from "../i18n/I18nProvider";

type HostPickerProps = {
  hosts: Host[];
  selectedIds: number[];
  onToggle: (id: number) => void;
  onSelectAll: (hostIds: number[]) => void;
  onClearAll: () => void;
  hint?: string;
};

function filterHosts(hosts: Host[], filters: { search: string; tags: string }): Host[] {
  const search = filters.search.trim().toLowerCase();
  const tagList = filters.tags
    .split(",")
    .map((tag) => tag.trim().toLowerCase())
    .filter(Boolean);

  return hosts.filter((host) => {
    if (search) {
      const name = host.name.toLowerCase();
      const hostname = host.hostname.toLowerCase();
      if (!name.includes(search) && !hostname.includes(search)) return false;
    }
    if (tagList.length > 0) {
      const hostTags = (host.tags ?? []).map((tag) => tag.toLowerCase());
      if (!tagList.some((tag) => hostTags.includes(tag))) return false;
    }
    return true;
  });
}

export function HostPicker({
  hosts,
  selectedIds,
  onToggle,
  onSelectAll,
  onClearAll,
  hint,
}: HostPickerProps) {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [tags, setTags] = useState("");

  const filteredHosts = useMemo(
    () => filterHosts(hosts, { search, tags }),
    [hosts, search, tags]
  );

  const hasFilters = search.trim() !== "" || tags.trim() !== "";

  if (hosts.length === 0) {
    return <p className="pf-host-picker__empty">{t("jobs.noHosts")}</p>;
  }

  return (
    <div className="pf-host-picker">
      <div className="pf-host-picker__filters">
        <div className="pf-form__group">
          <label htmlFor="host-picker-search">{t("jobs.dynamicSearch")}</label>
          <input
            id="host-picker-search"
            className="pf-input"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder={t("jobs.dynamicSearch")}
          />
        </div>
        <div className="pf-form__group">
          <label htmlFor="host-picker-tags">{t("jobs.dynamicTags")}</label>
          <input
            id="host-picker-tags"
            className="pf-input"
            value={tags}
            onChange={(e) => setTags(e.target.value)}
            placeholder={t("jobs.dynamicTags")}
          />
        </div>
      </div>

      <HostSelectionToolbar
        selectedCount={selectedIds.length}
        onSelectAll={() => onSelectAll(filteredHosts.map((host) => host.id))}
        onClear={onClearAll}
        customHint={
          hint ??
          (hasFilters
            ? t("hostSelection.filtered", {
                shown: filteredHosts.length,
                total: hosts.length,
              })
            : undefined)
        }
      />

      {filteredHosts.length === 0 ? (
        <p className="pf-host-picker__empty">{t("hostSelection.noMatches")}</p>
      ) : (
        <div className="pf-host-picker__grid">
          {filteredHosts.map((host) => {
            const selected = selectedIds.includes(host.id);
            return (
              <label
                key={host.id}
                className={`pf-host-picker__card${selected ? " pf-host-picker__card--selected" : ""}${!host.is_active ? " pf-host-picker__card--inactive" : ""}`}
              >
                <input
                  type="checkbox"
                  className="pf-checkbox-control pf-host-picker__checkbox"
                  checked={selected}
                  onChange={() => onToggle(host.id)}
                />
                <span className="pf-host-picker__card-body">
                  <span className="pf-host-picker__name">{host.name}</span>
                  <span className="pf-host-picker__meta">
                    {host.hostname}:{host.port}
                  </span>
                  <span className="pf-host-picker__tags">
                    {host.os_type && <Badge variant="info">{host.os_type}</Badge>}
                    <Badge variant={host.is_active ? "success" : "neutral"}>
                      {host.is_active ? t("common.active") : t("common.inactive")}
                    </Badge>
                  </span>
                </span>
              </label>
            );
          })}
        </div>
      )}
    </div>
  );
}
