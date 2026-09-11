import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import {
  AuditBarChart,
  AuditOutcomeChart,
  AuditSparkline,
  AuditTimelineChart,
  type AuditBarItem,
} from "../components/AuditCharts";
import { Badge } from "../components/ui/Badge";
import { DateInput } from "../components/ui/DateInput";
import { EmptyState } from "../components/ui/EmptyState";
import { QueryErrorState } from "../components/ui/QueryErrorState";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { Pagination, DEFAULT_PAGE_SIZE } from "../components/ui/Pagination";
import { Spinner } from "../components/ui/Spinner";
import { useTranslation } from "../i18n/I18nProvider";

const OVERVIEW_DAY_OPTIONS = [7, 14, 30, 90] as const;

function toBarItems(items: { label: string; count: number }[]): AuditBarItem[] {
  return items.map((item) => ({
    key: item.label,
    label: item.label,
    count: item.count,
  }));
}

export function AuditLogsPage() {
  const { t, dateLocale } = useTranslation();
  const { canViewAuditLogs } = useAuth();
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [resourceType, setResourceType] = useState("");
  const [outcome, setOutcome] = useState("");
  const [fromDate, setFromDate] = useState("");
  const [toDate, setToDate] = useState("");
  const [overviewDays, setOverviewDays] = useState<(typeof OVERVIEW_DAY_OPTIONS)[number]>(30);
  const [page, setPage] = useState(1);
  const pageSize = DEFAULT_PAGE_SIZE;
  const offset = (page - 1) * pageSize;

  const auditLogs = useQuery({
    queryKey: ["audit-logs", offset, pageSize, actor, action, resourceType, outcome, fromDate, toDate],
    queryFn: () =>
      api.auditLogs({
        offset,
        limit: pageSize,
        actor_username: actor.trim() || undefined,
        action: action.trim() || undefined,
        resource_type: resourceType.trim() || undefined,
        outcome: outcome || undefined,
        from: fromDate || undefined,
        to: toDate || undefined,
      }),
    enabled: canViewAuditLogs,
    refetchInterval: 30000,
  });
  const auditOverview = useQuery({
    queryKey: ["audit-overview", overviewDays],
    queryFn: () => api.auditOverview({ days: overviewDays, top: 6 }),
    enabled: canViewAuditLogs,
    refetchInterval: 30000,
  });

  const auditTotal = auditLogs.data?.total ?? 0;
  const auditTotalPages = Math.max(1, Math.ceil(auditTotal / pageSize));
  useEffect(() => {
    if (page > auditTotalPages) {
      setPage(auditTotalPages);
    }
  }, [page, auditTotalPages]);

  useEffect(() => {
    setPage(1);
  }, [actor, action, resourceType, outcome, fromDate, toDate]);

  if (!canViewAuditLogs) {
    return <Navigate to="/" replace />;
  }
  const logRows = auditLogs.data?.items ?? [];

  const overview = auditOverview.data;
  const avgPerDay = overview ? Math.round(overview.total_events / Math.max(overview.period_days, 1)) : 0;
  const successCount = overview?.outcomes.find((item) => item.label === "success")?.count ?? 0;
  const outcomeTotal = overview?.outcomes.reduce((sum, item) => sum + item.count, 0) ?? 0;
  const successRate = outcomeTotal > 0 ? Math.round((successCount / outcomeTotal) * 100) : 0;
  const sparklineWindow = Math.min(7, overviewDays);
  const recentSparkline = overview?.events_over_time.slice(-sparklineWindow) ?? [];

  const hasActiveFilters = !!(actor || action || resourceType || outcome || fromDate || toDate);

  const periodToolbar = (
    <div className="pf-audit-period" role="group" aria-label={t("auditLogs.periodAria")}>
      <span className="pf-audit-period__label">{t("auditLogs.periodLabel")}</span>
      <div className="pf-audit-period__presets">
        {OVERVIEW_DAY_OPTIONS.map((days) => (
          <button
            key={days}
            type="button"
            className={`pf-audit-period__preset${overviewDays === days ? " is-active" : ""}`}
            aria-pressed={overviewDays === days}
            onClick={() => setOverviewDays(days)}
          >
            {t("auditLogs.periodDays", { count: days })}
          </button>
        ))}
      </div>
    </div>
  );

  return (
    <>
      <PageHeader title={t("auditLogs.title")} description={t("auditLogs.description")} />
      <Panel
        title={t("auditLogs.analyticsTitle")}
        className="pf-audit-analytics-panel"
        toolbar={periodToolbar}
        collapsible={false}
      >
        {auditOverview.isLoading ? (
          <Spinner />
        ) : !overview ? (
          <EmptyState title={t("auditLogs.noData")} description={t("auditLogs.noDataDesc")} />
        ) : (
          <div className="pf-audit-analytics">
            <div className="pf-audit-kpis" aria-label={t("auditLogs.kpiAria")}>
              <article className="pf-audit-kpi pf-audit-kpi--cyan">
                <span className="pf-audit-kpi__label">{t("auditLogs.kpiTotalEvents")}</span>
                <strong className="pf-audit-kpi__value">{overview.total_events}</strong>
                <span className="pf-audit-kpi__hint">
                  {t("auditLogs.periodDays", { count: overview.period_days })}
                </span>
              </article>
              <article className="pf-audit-kpi pf-audit-kpi--gold">
                <span className="pf-audit-kpi__label">{t("auditLogs.kpiAvgPerDay")}</span>
                <strong className="pf-audit-kpi__value">{avgPerDay}</strong>
                <AuditSparkline points={recentSparkline} ariaLabel={t("auditLogs.recentActivityAria")} />
              </article>
              <article className="pf-audit-kpi pf-audit-kpi--rose">
                <span className="pf-audit-kpi__label">{t("auditLogs.kpiSuccessRate")}</span>
                <strong className="pf-audit-kpi__value">{successRate}%</strong>
                <span className="pf-audit-kpi__hint">
                  {t("auditLogs.kpiSuccessHint", { count: successCount, total: outcomeTotal })}
                </span>
              </article>
              <article className="pf-audit-kpi pf-audit-kpi--neutral">
                <span className="pf-audit-kpi__label">{t("auditLogs.kpiTopActor")}</span>
                <strong className="pf-audit-kpi__value">
                  {overview.top_actors[0]?.label ?? t("common.dash")}
                </strong>
                {overview.top_actors[0] && (
                  <span className="pf-audit-kpi__hint">
                    {t("auditLogs.kpiTopActorHint", { count: overview.top_actors[0].count })}
                  </span>
                )}
              </article>
            </div>

            <div className="pf-audit-analytics__grid">
              <section className="pf-audit-widget pf-audit-widget--timeline">
                <div className="pf-audit-widget__head">
                  <h3>{t("auditLogs.eventsTimeline")}</h3>
                  <span>{t("auditLogs.timelinePeriod", { count: overview.period_days })}</span>
                </div>
                {overview.events_over_time.length === 0 ? (
                  <p className="pf-table__muted">{t("auditLogs.noData")}</p>
                ) : (
                  <AuditTimelineChart
                    points={overview.events_over_time}
                    ariaLabel={t("auditLogs.eventsTimelineAria")}
                    dateLocale={dateLocale}
                  />
                )}
              </section>

              <section className="pf-audit-widget">
                <div className="pf-audit-widget__head">
                  <h3>{t("auditLogs.topActions")}</h3>
                </div>
                {overview.top_actions.length === 0 ? (
                  <p className="pf-table__muted">{t("auditLogs.noData")}</p>
                ) : (
                  <AuditBarChart items={toBarItems(overview.top_actions)} ariaLabel={t("auditLogs.topActionsAria")} />
                )}
              </section>

              <section className="pf-audit-widget">
                <div className="pf-audit-widget__head">
                  <h3>{t("auditLogs.topActors")}</h3>
                </div>
                {overview.top_actors.length === 0 ? (
                  <p className="pf-table__muted">{t("auditLogs.noData")}</p>
                ) : (
                  <AuditBarChart items={toBarItems(overview.top_actors)} ariaLabel={t("auditLogs.topActorsAria")} />
                )}
              </section>

              <section className="pf-audit-widget">
                <div className="pf-audit-widget__head">
                  <h3>{t("auditLogs.resourceTypes")}</h3>
                </div>
                {overview.resource_types.length === 0 ? (
                  <p className="pf-table__muted">{t("auditLogs.noData")}</p>
                ) : (
                  <AuditBarChart
                    items={toBarItems(overview.resource_types)}
                    ariaLabel={t("auditLogs.resourceTypesAria")}
                  />
                )}
              </section>

              <section className="pf-audit-widget">
                <div className="pf-audit-widget__head">
                  <h3>{t("auditLogs.outcomeSplit")}</h3>
                </div>
                {overview.outcomes.length === 0 ? (
                  <p className="pf-table__muted">{t("auditLogs.noData")}</p>
                ) : (
                  <AuditOutcomeChart
                    outcomes={overview.outcomes}
                    successLabel={t("auditLogs.success")}
                    failedLabel={t("auditLogs.failed")}
                    totalLabel={t("auditLogs.outcomeSuccessRate")}
                    ariaLabel={t("auditLogs.outcomeSplitAria")}
                  />
                )}
              </section>
            </div>
          </div>
        )}
      </Panel>
      <Panel title={t("auditLogs.tableTitle")} noPadding>
        <div className="pf-check-details__filters pf-audit-events__filters">
          <div className="pf-audit-events__filters-grid">
            <label className="pf-check-details__field" htmlFor="audit-filter-actor">
              <span className="pf-check-details__field-label">{t("auditLogs.actor")}</span>
              <input
                id="audit-filter-actor"
                className={`pf-input${actor.trim() ? " is-filtered" : ""}`}
                type="search"
                value={actor}
                onChange={(event) => setActor(event.target.value)}
                placeholder={t("auditLogs.filterActorPlaceholder")}
              />
            </label>
            <label className="pf-check-details__field" htmlFor="audit-filter-action">
              <span className="pf-check-details__field-label">{t("auditLogs.action")}</span>
              <input
                id="audit-filter-action"
                className={`pf-input${action.trim() ? " is-filtered" : ""}`}
                type="search"
                value={action}
                onChange={(event) => setAction(event.target.value)}
                placeholder={t("auditLogs.filterActionPlaceholder")}
              />
            </label>
            <label className="pf-check-details__field" htmlFor="audit-filter-resource">
              <span className="pf-check-details__field-label">{t("auditLogs.resource")}</span>
              <input
                id="audit-filter-resource"
                className={`pf-input${resourceType.trim() ? " is-filtered" : ""}`}
                type="search"
                value={resourceType}
                onChange={(event) => setResourceType(event.target.value)}
                placeholder={t("auditLogs.filterResourcePlaceholder")}
              />
            </label>
            <label className="pf-check-details__field" htmlFor="audit-filter-outcome">
              <span className="pf-check-details__field-label">{t("auditLogs.outcome")}</span>
              <select
                id="audit-filter-outcome"
                className={`pf-select${outcome ? " is-filtered" : ""}`}
                value={outcome}
                onChange={(event) => setOutcome(event.target.value)}
              >
                <option value="">{t("common.all")}</option>
                <option value="success">{t("auditLogs.success")}</option>
                <option value="failed">{t("auditLogs.failed")}</option>
              </select>
            </label>
            <div className="pf-check-details__field pf-audit-events__field--range">
              <span className="pf-check-details__field-label">{t("auditLogs.dateRange")}</span>
              <div
                className={`pf-audit-events__range${fromDate || toDate ? " is-filtered" : ""}`}
              >
                <DateInput
                  id="audit-filter-from"
                  className="pf-input pf-audit-events__range-input"
                  value={fromDate}
                  onChange={(event) => setFromDate(event.target.value)}
                  aria-label={t("auditLogs.from")}
                />
                <span className="pf-audit-events__range-sep" aria-hidden>
                  –
                </span>
                <DateInput
                  id="audit-filter-to"
                  className="pf-input pf-audit-events__range-input"
                  value={toDate}
                  onChange={(event) => setToDate(event.target.value)}
                  aria-label={t("auditLogs.to")}
                />
              </div>
            </div>
          </div>

          <div className="pf-check-details__filters-meta">
            <p className="pf-filters__summary">
              {hasActiveFilters
                ? t("reports.filterResultsActive", { count: logRows.length, total: auditTotal })
                : t("reports.filterShown", { count: logRows.length, total: auditTotal })}
            </p>

            {hasActiveFilters ? (
              <div className="pf-check-details__chips" aria-label={t("profiles.clearFilters")}>
                {actor.trim() ? (
                  <button type="button" className="pf-check-details__chip" onClick={() => setActor("")}>
                    <span className="pf-check-details__chip-key">{t("auditLogs.actor")}</span>
                    <span className="pf-check-details__chip-val">{actor.trim()}</span>
                    <span className="pf-check-details__chip-x" aria-hidden>
                      ×
                    </span>
                  </button>
                ) : null}
                {action.trim() ? (
                  <button type="button" className="pf-check-details__chip" onClick={() => setAction("")}>
                    <span className="pf-check-details__chip-key">{t("auditLogs.action")}</span>
                    <span className="pf-check-details__chip-val">{action.trim()}</span>
                    <span className="pf-check-details__chip-x" aria-hidden>
                      ×
                    </span>
                  </button>
                ) : null}
                {resourceType.trim() ? (
                  <button
                    type="button"
                    className="pf-check-details__chip"
                    onClick={() => setResourceType("")}
                  >
                    <span className="pf-check-details__chip-key">{t("auditLogs.resource")}</span>
                    <span className="pf-check-details__chip-val">{resourceType.trim()}</span>
                    <span className="pf-check-details__chip-x" aria-hidden>
                      ×
                    </span>
                  </button>
                ) : null}
                {outcome ? (
                  <button type="button" className="pf-check-details__chip" onClick={() => setOutcome("")}>
                    <span className="pf-check-details__chip-key">{t("auditLogs.outcome")}</span>
                    <span className="pf-check-details__chip-val">
                      {outcome === "success" ? t("auditLogs.success") : t("auditLogs.failed")}
                    </span>
                    <span className="pf-check-details__chip-x" aria-hidden>
                      ×
                    </span>
                  </button>
                ) : null}
                {fromDate || toDate ? (
                  <button
                    type="button"
                    className="pf-check-details__chip"
                    onClick={() => {
                      setFromDate("");
                      setToDate("");
                    }}
                  >
                    <span className="pf-check-details__chip-key">{t("auditLogs.dateRange")}</span>
                    <span className="pf-check-details__chip-val">
                      {fromDate || "…"} – {toDate || "…"}
                    </span>
                    <span className="pf-check-details__chip-x" aria-hidden>
                      ×
                    </span>
                  </button>
                ) : null}
                <button
                  type="button"
                  className="pf-check-details__clear"
                  onClick={() => {
                    setActor("");
                    setAction("");
                    setResourceType("");
                    setOutcome("");
                    setFromDate("");
                    setToDate("");
                  }}
                >
                  {t("profiles.clearFilters")}
                </button>
              </div>
            ) : null}
          </div>
        </div>

        {auditLogs.isLoading ? (
          <Spinner />
        ) : auditLogs.isError ? (
          <QueryErrorState
            title={t("common.listLoadError")}
            message={auditLogs.error instanceof Error ? auditLogs.error.message : undefined}
            onRetry={() => auditLogs.refetch()}
          />
        ) : auditTotal === 0 ? (
          <EmptyState title={t("auditLogs.noData")} description={t("auditLogs.noDataDesc")} />
        ) : (
          <div className="pf-table-wrap">
            <table className="pf-table">
              <thead>
                <tr>
                  <th>{t("auditLogs.time")}</th>
                  <th>{t("auditLogs.actor")}</th>
                  <th>{t("auditLogs.action")}</th>
                  <th>{t("auditLogs.resource")}</th>
                  <th>{t("auditLogs.outcome")}</th>
                  <th>{t("auditLogs.details")}</th>
                </tr>
              </thead>
              <tbody>
                {logRows.map((row) => (
                  <tr key={row.id}>
                    <td>{new Date(row.created_at).toLocaleString(dateLocale)}</td>
                    <td>{row.actor_username}</td>
                    <td>
                      <Badge variant="info">{row.action}</Badge>
                    </td>
                    <td>
                      <Badge variant="neutral">
                        {row.resource_type}
                        {row.resource_name ? `: ${row.resource_name}` : ""}
                      </Badge>
                    </td>
                    <td>
                      <Badge variant={row.outcome === "success" ? "success" : "danger"}>
                        {row.outcome === "success" ? t("auditLogs.success") : t("auditLogs.failed")}
                      </Badge>
                    </td>
                    <td className="pf-table__muted">
                      {row.metadata_json ? JSON.stringify(row.metadata_json) : t("common.dash")}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination
              page={page}
              pageSize={pageSize}
              total={auditTotal}
              onPageChange={setPage}
            />
          </div>
        )}
      </Panel>
    </>
  );
}
