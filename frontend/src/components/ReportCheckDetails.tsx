import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import type { CheckResult, ProfileRule } from "../api/client";
import { useTranslation } from "../i18n/I18nProvider";
import { useTableSort } from "../hooks/useTableSort";
import { checkStatusVariant, severityVariant } from "../utils/statusVariant";
import {
  findProfileRule,
  hasProfileRuleMetadata,
  ProfileRuleMetadata,
} from "./ProfileRuleDetail";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Panel } from "./ui/Panel";
import { SortableTh } from "./ui/SortableTh";

export type CheckResultFilterState = {
  host: string;
  rule: string;
  status: string;
  severity: string;
  message: string;
};

type CheckSortKey = "host" | "rule" | "severity" | "status" | "message";

type ReportCheckDetailsProps = {
  rows: CheckResult[];
  profileRules?: ProfileRule[];
  hostLabel: (hostId: number) => string;
  filters: CheckResultFilterState;
  onFiltersChange: (patch: Partial<CheckResultFilterState>) => void;
  onClearFilters: () => void;
  resetKey: number | null;
  canOperate: boolean;
  profileId: number | null;
  runId?: number | null;
  onRequestWaiver: (row: CheckResult) => void;
};

function severityOf(rules: ProfileRule[] | undefined, ruleTechName: string): string {
  const rule = findProfileRule(rules, ruleTechName);
  return (rule?.criticality || rule?.impact || "unknown").trim().toLowerCase();
}

function filterCheckResults(
  rows: CheckResult[],
  filters: CheckResultFilterState,
  rules: ProfileRule[] | undefined
): CheckResult[] {
  const ruleQuery = filters.rule.trim().toLowerCase();
  const messageQuery = filters.message.trim().toLowerCase();
  return rows.filter((row) => {
    if (filters.host !== "all" && String(row.host_id) !== filters.host) return false;
    if (ruleQuery && !row.rule_tech_name.toLowerCase().includes(ruleQuery)) return false;
    if (filters.status !== "all" && row.status.toLowerCase() !== filters.status) return false;
    if (filters.severity !== "all" && severityOf(rules, row.rule_tech_name) !== filters.severity.toLowerCase()) {
      return false;
    }
    if (messageQuery && !(row.message ?? "").toLowerCase().includes(messageQuery)) return false;
    return true;
  });
}

function matchedLabelKey(matchedBy: "rule" | "package" | "rule_and_package"): string {
  if (matchedBy === "package") return "reports.cveMatchedPackage";
  if (matchedBy === "rule_and_package") return "reports.cveMatchedBoth";
  return "reports.cveMatchedRule";
}

export function ReportCheckDetails({
  rows,
  profileRules,
  hostLabel,
  filters,
  onFiltersChange,
  onClearFilters,
  resetKey,
  canOperate,
  profileId,
  runId,
  onRequestWaiver,
}: ReportCheckDetailsProps) {
  const { t } = useTranslation();
  const [expandedCheckId, setExpandedCheckId] = useState<number | null>(null);

  useEffect(() => {
    setExpandedCheckId(null);
  }, [resetKey]);

  const ruleLabels = useMemo(
    () => ({
      description: t("profiles.ruleDescription"),
      risk: t("profiles.ruleRisk"),
      location: t("profiles.ruleLocation"),
      scapRuleId: t("profiles.scapRuleId"),
    }),
    [t]
  );

  const hostOptions = useMemo(() => {
    return [...new Set(rows.map((row) => row.host_id))].sort((a, b) =>
      hostLabel(a).localeCompare(hostLabel(b), undefined, { sensitivity: "base" })
    );
  }, [rows, hostLabel]);

  const statusOptions = useMemo(() => {
    return [...new Set(rows.map((row) => row.status.toLowerCase()))].sort();
  }, [rows]);

  const severityOptions = useMemo(() => {
    const set = new Set<string>();
    for (const row of rows) {
      const severity = severityOf(profileRules, row.rule_tech_name);
      if (severity) set.add(severity);
    }
    return Array.from(set).sort();
  }, [rows, profileRules]);

  const filtered = useMemo(
    () => filterCheckResults(rows, filters, profileRules),
    [rows, filters, profileRules]
  );

  const sortAccessor = useCallback(
    (row: CheckResult, key: CheckSortKey) => {
      if (key === "host") return hostLabel(row.host_id);
      if (key === "rule") return row.rule_tech_name;
      if (key === "severity") return severityOf(profileRules, row.rule_tech_name);
      if (key === "status") return row.status.toLowerCase();
      return row.message ?? "";
    },
    [hostLabel, profileRules]
  );

  const { sortedRows, sort, toggleSort } = useTableSort<CheckResult, CheckSortKey>(
    filtered,
    { key: "host", direction: "asc" },
    sortAccessor
  );

  const hasActiveFilters =
    filters.host !== "all" ||
    filters.rule.trim() !== "" ||
    filters.status !== "all" ||
    filters.severity !== "all" ||
    filters.message.trim() !== "";

  return (
    <Panel title={t("reports.checkDetails")} noPadding>
      <div className="pf-check-details__filters">
        <div className="pf-check-details__filters-grid">
          <label className="pf-check-details__field" htmlFor="check-filter-host">
            <span className="pf-check-details__field-label">{t("reports.host")}</span>
            <select
              id="check-filter-host"
              className={`pf-select${filters.host !== "all" ? " is-filtered" : ""}`}
              value={filters.host}
              onChange={(event) => onFiltersChange({ host: event.target.value })}
            >
              <option value="all">{t("reports.allHosts")}</option>
              {hostOptions.map((hostId) => (
                <option key={hostId} value={String(hostId)}>
                  {hostLabel(hostId)}
                </option>
              ))}
            </select>
          </label>

          <label className="pf-check-details__field pf-check-details__field--grow" htmlFor="check-filter-rule">
            <span className="pf-check-details__field-label">{t("reports.rule")}</span>
            <input
              id="check-filter-rule"
              className={`pf-input${filters.rule.trim() ? " is-filtered" : ""}`}
              type="search"
              value={filters.rule}
              onChange={(event) => onFiltersChange({ rule: event.target.value })}
              placeholder={t("reports.filterRulePlaceholder")}
            />
          </label>

          <label className="pf-check-details__field" htmlFor="check-filter-severity">
            <span className="pf-check-details__field-label">{t("reports.severity")}</span>
            <select
              id="check-filter-severity"
              className={`pf-select${filters.severity !== "all" ? " is-filtered" : ""}`}
              value={filters.severity}
              onChange={(event) => onFiltersChange({ severity: event.target.value })}
            >
              <option value="all">{t("reports.allSeverities")}</option>
              {severityOptions.map((severity) => (
                <option key={severity} value={severity}>
                  {severity}
                </option>
              ))}
            </select>
          </label>

          <label className="pf-check-details__field" htmlFor="check-filter-status">
            <span className="pf-check-details__field-label">{t("common.status")}</span>
            <select
              id="check-filter-status"
              className={`pf-select${filters.status !== "all" ? " is-filtered" : ""}`}
              value={filters.status}
              onChange={(event) => onFiltersChange({ status: event.target.value })}
            >
              <option value="all">{t("reports.allStatuses")}</option>
              {statusOptions.map((status) => (
                <option key={status} value={status}>
                  {status}
                </option>
              ))}
            </select>
          </label>

          <label className="pf-check-details__field pf-check-details__field--grow" htmlFor="check-filter-message">
            <span className="pf-check-details__field-label">{t("reports.message")}</span>
            <input
              id="check-filter-message"
              className={`pf-input${filters.message.trim() ? " is-filtered" : ""}`}
              type="search"
              value={filters.message}
              onChange={(event) => onFiltersChange({ message: event.target.value })}
              placeholder={t("reports.filterMessagePlaceholder")}
            />
          </label>
        </div>

        <div className="pf-check-details__filters-meta">
          <p className="pf-filters__summary">
            {hasActiveFilters
              ? t("reports.filterResultsActive", { count: filtered.length, total: rows.length })
              : t("reports.filterShown", { count: filtered.length, total: rows.length })}
          </p>

          {hasActiveFilters ? (
            <div className="pf-check-details__chips" aria-label={t("profiles.clearFilters")}>
              {filters.host !== "all" ? (
                <button type="button" className="pf-check-details__chip" onClick={() => onFiltersChange({ host: "all" })}>
                  <span className="pf-check-details__chip-key">{t("reports.host")}</span>
                  <span className="pf-check-details__chip-val">{hostLabel(Number(filters.host))}</span>
                  <span className="pf-check-details__chip-x" aria-hidden>
                    ×
                  </span>
                </button>
              ) : null}
              {filters.rule.trim() ? (
                <button type="button" className="pf-check-details__chip" onClick={() => onFiltersChange({ rule: "" })}>
                  <span className="pf-check-details__chip-key">{t("reports.rule")}</span>
                  <span className="pf-check-details__chip-val">{filters.rule.trim()}</span>
                  <span className="pf-check-details__chip-x" aria-hidden>
                    ×
                  </span>
                </button>
              ) : null}
              {filters.severity !== "all" ? (
                <button
                  type="button"
                  className="pf-check-details__chip"
                  onClick={() => onFiltersChange({ severity: "all" })}
                >
                  <span className="pf-check-details__chip-key">{t("reports.severity")}</span>
                  <span className="pf-check-details__chip-val">{filters.severity}</span>
                  <span className="pf-check-details__chip-x" aria-hidden>
                    ×
                  </span>
                </button>
              ) : null}
              {filters.status !== "all" ? (
                <button
                  type="button"
                  className="pf-check-details__chip"
                  onClick={() => onFiltersChange({ status: "all" })}
                >
                  <span className="pf-check-details__chip-key">{t("common.status")}</span>
                  <span className="pf-check-details__chip-val">{filters.status}</span>
                  <span className="pf-check-details__chip-x" aria-hidden>
                    ×
                  </span>
                </button>
              ) : null}
              {filters.message.trim() ? (
                <button
                  type="button"
                  className="pf-check-details__chip"
                  onClick={() => onFiltersChange({ message: "" })}
                >
                  <span className="pf-check-details__chip-key">{t("reports.message")}</span>
                  <span className="pf-check-details__chip-val">{filters.message.trim()}</span>
                  <span className="pf-check-details__chip-x" aria-hidden>
                    ×
                  </span>
                </button>
              ) : null}
              <button type="button" className="pf-check-details__clear" onClick={onClearFilters}>
                {t("profiles.clearFilters")}
              </button>
            </div>
          ) : null}
        </div>
      </div>

      <div className="pf-table-wrap">
        <table className="pf-table pf-table--check-details">
          <thead>
            <tr>
              <SortableTh<CheckSortKey>
                label={t("reports.host")}
                sortKey="host"
                activeKey={sort.key}
                direction={sort.direction}
                onSort={toggleSort}
              />
              <SortableTh<CheckSortKey>
                label={t("reports.rule")}
                sortKey="rule"
                activeKey={sort.key}
                direction={sort.direction}
                onSort={toggleSort}
              />
              <SortableTh<CheckSortKey>
                label={t("reports.severity")}
                sortKey="severity"
                activeKey={sort.key}
                direction={sort.direction}
                onSort={toggleSort}
              />
              <SortableTh<CheckSortKey>
                label={t("common.status")}
                sortKey="status"
                activeKey={sort.key}
                direction={sort.direction}
                onSort={toggleSort}
              />
              <SortableTh<CheckSortKey>
                label={t("reports.message")}
                sortKey="message"
                activeKey={sort.key}
                direction={sort.direction}
                onSort={toggleSort}
              />
              <th scope="col" className="pf-table__col-actions" />
            </tr>
          </thead>
          <tbody>
            {sortedRows.length === 0 ? (
              <tr>
                <td colSpan={6}>
                  <div className="pf-check-details__empty">
                    <strong>{t("reports.noFilterResults")}</strong>
                    <p>{t("reports.noFilterResultsDesc")}</p>
                  </div>
                </td>
              </tr>
            ) : (
              sortedRows.map((row) => {
                const ruleMeta = findProfileRule(profileRules, row.rule_tech_name);
                const hasDetails = hasProfileRuleMetadata(ruleMeta);
                const expanded = expandedCheckId === row.id;
                const severityLabel = (ruleMeta?.criticality || ruleMeta?.impact || "").toString().trim();
                const canRequestWaiver =
                  canOperate && profileId != null && row.status.toLowerCase() === "fail" && !row.is_waived;
                const cveRefs = row.status.toLowerCase() === "fail" ? row.cve_refs ?? [] : [];

                return (
                  <Fragment key={row.id}>
                    <tr>
                      <td>
                        <div className="pf-check-details__host">
                          <span className="pf-check-details__host-name">{hostLabel(row.host_id)}</span>
                          {hostLabel(row.host_id) !== `#${row.host_id}` ? (
                            <span className="pf-table__mono pf-table__muted pf-check-details__host-id">
                              #{row.host_id}
                            </span>
                          ) : null}
                        </div>
                      </td>
                      <td
                        className={`pf-table__mono${hasDetails ? " pf-table__rule-cell" : ""}`}
                        onClick={hasDetails ? () => setExpandedCheckId(expanded ? null : row.id) : undefined}
                        onKeyDown={
                          hasDetails
                            ? (event) => {
                                if (event.key === "Enter" || event.key === " ") {
                                  event.preventDefault();
                                  setExpandedCheckId(expanded ? null : row.id);
                                }
                              }
                            : undefined
                        }
                        role={hasDetails ? "button" : undefined}
                        tabIndex={hasDetails ? 0 : undefined}
                        aria-expanded={hasDetails ? expanded : undefined}
                      >
                        <span
                          className={
                            hasDetails
                              ? `pf-table__rule-link${expanded ? " pf-table__rule-link--active" : ""}`
                              : undefined
                          }
                        >
                          {row.rule_tech_name}
                        </span>
                      </td>
                      <td className="pf-check-details__severity">
                        {severityLabel ? (
                          <Badge variant={severityVariant(severityLabel)} literal>
                            {severityLabel}
                          </Badge>
                        ) : (
                          t("common.dash")
                        )}
                      </td>
                      <td>
                        <div className="pf-table__actions" style={{ justifyContent: "flex-start" }}>
                          <Badge variant={checkStatusVariant(row.status)}>{row.status}</Badge>
                          {row.is_waived ? <Badge variant="info">{t("reports.waivedBadge")}</Badge> : null}
                        </div>
                      </td>
                      <td>{row.message || t("common.dash")}</td>
                      <td className="pf-table__col-actions" onClick={(event) => event.stopPropagation()}>
                        <div className="pf-table__actions pf-check-details__actions">
                          {canRequestWaiver ? (
                            <Button variant="secondary" className="pf-btn--sm" onClick={() => onRequestWaiver(row)}>
                              {t("reports.requestWaiver")}
                            </Button>
                          ) : null}
                          {runId != null &&
                          (row.status.toLowerCase() === "fail" || row.status.toLowerCase() === "error") ? (
                            <Link
                              to={`/aag/explain?runId=${runId}&checks=${row.id}`}
                              className="pf-btn pf-btn--secondary pf-btn--sm"
                            >
                              {t("aag.openExplain")}
                            </Link>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                    {cveRefs.length > 0 ? (
                      <tr className="pf-cve-refs-row">
                        <td colSpan={6}>
                          <div className="pf-cve-refs" role="group" aria-label={t("reports.cveRefsLabel")}>
                            <p className="pf-cve-refs__label">{t("reports.cveRefsLabel")}</p>
                            <ul className="pf-cve-refs__list">
                              {cveRefs.map((ref) => (
                                <li key={`${ref.cve_id}-${ref.matched_by}`} className="pf-cve-refs__item">
                                  <Badge variant="warning" literal>
                                    {ref.cve_id}
                                  </Badge>
                                  <span className="pf-cve-refs__match">{t(matchedLabelKey(ref.matched_by))}</span>
                                  {ref.summary ? <span className="pf-cve-refs__summary">{ref.summary}</span> : null}
                                </li>
                              ))}
                            </ul>
                          </div>
                        </td>
                      </tr>
                    ) : null}
                    {expanded && ruleMeta && hasDetails ? (
                      <tr className="pf-table__detail-row">
                        <td colSpan={6}>
                          <div className="pf-profile-rule__body pf-profile-rule__body--table">
                            <ProfileRuleMetadata rule={ruleMeta} labels={ruleLabels} />
                          </div>
                        </td>
                      </tr>
                    ) : null}
                  </Fragment>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </Panel>
  );
}
