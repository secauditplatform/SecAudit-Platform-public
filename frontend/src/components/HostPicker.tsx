import { useMemo, useState } from "react";
import { HostSelectionToolbar } from "./HostSelectionToolbar";
import { Badge } from "./ui/Badge";
import type { Host, HostCriticality } from "../api/client";
import { useTranslation } from "../i18n/I18nProvider";
import { hostCriticalityVariant } from "../utils/statusVariant";

type HostPickerProps = {
  hosts: Host[];
  selectedIds: number[];
  onToggle: (id: number) => void;
  onSelectAll: (hostIds: number[]) => void;
  onClearAll: () => void;
  hint?: string;
};

type PickerFilters = {
  search: string;
  tags: string;
  site: string;
  environment: string;
  criticality: HostCriticality | "all";
};

function uniqueSorted(values: Array<string | null | undefined>): string[] {
  return [...new Set(values.map((value) => value?.trim()).filter(Boolean) as string[])].sort((a, b) =>
    a.localeCompare(b)
  );
}

function filterHosts(hosts: Host[], filters: PickerFilters): Host[] {
  const search = filters.search.trim().toLowerCase();
  const tagList = filters.tags
    .split(",")
    .map((tag) => tag.trim().toLowerCase())
    .filter(Boolean);

  return hosts.filter((host) => {
    if (filters.site !== "all" && (host.site ?? "") !== filters.site) return false;
    if (filters.environment !== "all" && (host.environment ?? "") !== filters.environment) {
      return false;
    }
    if (filters.criticality !== "all" && (host.criticality ?? "") !== filters.criticality) {
      return false;
    }
    if (search) {
      const haystack = [
        host.name,
        host.hostname,
        host.site ?? "",
        host.environment ?? "",
        host.criticality ?? "",
      ]
        .join(" ")
        .toLowerCase();
      if (!haystack.includes(search)) return false;
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
  const [site, setSite] = useState("all");
  const [environment, setEnvironment] = useState("all");
  const [criticality, setCriticality] = useState<HostCriticality | "all">("all");

  const siteOptions = useMemo(() => uniqueSorted(hosts.map((host) => host.site)), [hosts]);
  const environmentOptions = useMemo(
    () => uniqueSorted(hosts.map((host) => host.environment)),
    [hosts]
  );

  const filteredHosts = useMemo(
    () => filterHosts(hosts, { search, tags, site, environment, criticality }),
    [hosts, search, tags, site, environment, criticality]
  );

  const hasFilters =
    search.trim() !== "" ||
    tags.trim() !== "" ||
    site !== "all" ||
    environment !== "all" ||
    criticality !== "all";

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
        <div className="pf-form__group">
          <label htmlFor="host-picker-site">{t("hosts.site")}</label>
          <select
            id="host-picker-site"
            className="pf-select"
            value={site}
            onChange={(e) => setSite(e.target.value)}
          >
            <option value="all">{t("hosts.listSiteAll")}</option>
            {siteOptions.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
        <div className="pf-form__group">
          <label htmlFor="host-picker-environment">{t("hosts.environment")}</label>
          <select
            id="host-picker-environment"
            className="pf-select"
            value={environment}
            onChange={(e) => setEnvironment(e.target.value)}
          >
            <option value="all">{t("hosts.listEnvironmentAll")}</option>
            {environmentOptions.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </div>
        <div className="pf-form__group">
          <label htmlFor="host-picker-criticality">{t("hosts.criticality")}</label>
          <select
            id="host-picker-criticality"
            className="pf-select"
            value={criticality}
            onChange={(e) => setCriticality(e.target.value as HostCriticality | "all")}
          >
            <option value="all">{t("hosts.listCriticalityAll")}</option>
            <option value="low">{t("hosts.criticalityLow")}</option>
            <option value="medium">{t("hosts.criticalityMedium")}</option>
            <option value="high">{t("hosts.criticalityHigh")}</option>
            <option value="critical">{t("hosts.criticalityCritical")}</option>
          </select>
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
                    <span className="pf-host-picker__tags-row">
                      {host.os_type ? <Badge variant="info">{host.os_type}</Badge> : null}
                      <Badge variant={host.is_active ? "success" : "neutral"}>
                        {host.is_active ? t("common.active") : t("common.inactive")}
                      </Badge>
                    </span>
                    {host.site || host.environment || host.criticality ? (
                      <span className="pf-host-picker__tags-row">
                        {host.site ? (
                          <Badge variant="info" literal>
                            {host.site}
                          </Badge>
                        ) : null}
                        {host.environment ? (
                          <Badge variant="info" literal>
                            {host.environment}
                          </Badge>
                        ) : null}
                        {host.criticality ? (
                          <Badge variant={hostCriticalityVariant(host.criticality)} literal>
                            {t(`hosts.criticalityLabel.${host.criticality}`)}
                          </Badge>
                        ) : null}
                      </span>
                    ) : null}
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
