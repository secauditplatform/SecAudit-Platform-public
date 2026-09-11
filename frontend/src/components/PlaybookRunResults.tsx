import { useEffect, useId, useMemo, useState } from "react";
import { createPortal } from "react-dom";
import type { CheckResult, JobRunDetail } from "../api/client";
import { useTranslation } from "../i18n/I18nProvider";
import {
  parsePlaybookComplianceChecks,
  type PlaybookComplianceCheck,
} from "../utils/parsePlaybookComplianceChecks";
import { checkStatusVariant } from "../utils/statusVariant";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";

type PlaybookRunResultsProps = {
  run: JobRunDetail;
  hostNameById: Map<number, string>;
};

type OutputLineKind = "task" | "ok" | "changed" | "failed" | "skipped" | "play" | "plain";

type HostResultGroup = {
  hostId: number;
  shell: CheckResult;
  storedChecks: CheckResult[];
  rawOutput: string;
};

type StatusSummary = {
  pass: number;
  fail: number;
  error: number;
  skip: number;
  other: number;
};

const SHELL_RULES = new Set(["PLAYBOOK_OK", "PLAYBOOK_ERROR"]);
const OUTPUT_LINE_PREVIEW_CHARS = 4000;

function resultStatusVariant(status: string): "success" | "danger" | "warning" | "info" | "neutral" {
  if (status === "pass") return "success";
  if (status === "fail" || status === "error") return "danger";
  if (status === "skip") return "warning";
  return "neutral";
}

function resultAccentClass(status: string): string {
  if (status === "pass") return "pf-playbook-run-results__card--pass";
  if (status === "fail" || status === "error") return "pf-playbook-run-results__card--fail";
  if (status === "skip") return "pf-playbook-run-results__card--skip";
  return "pf-playbook-run-results__card--neutral";
}

function formatDuration(startedAt?: string, finishedAt?: string): string | null {
  if (!startedAt || !finishedAt) return null;
  const ms = new Date(finishedAt).getTime() - new Date(startedAt).getTime();
  if (!Number.isFinite(ms) || ms < 0) return null;
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  const rest = seconds % 60;
  return rest > 0 ? `${minutes}m ${rest}s` : `${minutes}m`;
}

function summarizeStatuses(statuses: string[]): StatusSummary {
  return statuses.reduce(
    (acc, status) => {
      if (status === "pass") acc.pass += 1;
      else if (status === "fail") acc.fail += 1;
      else if (status === "error") acc.error += 1;
      else if (status === "skip") acc.skip += 1;
      else acc.other += 1;
      return acc;
    },
    { pass: 0, fail: 0, error: 0, skip: 0, other: 0 }
  );
}

function groupHostResults(results: CheckResult[]): HostResultGroup[] {
  const byHost = new Map<number, CheckResult[]>();
  for (const result of results) {
    const list = byHost.get(result.host_id) ?? [];
    list.push(result);
    byHost.set(result.host_id, list);
  }

  return [...byHost.entries()].map(([hostId, items]) => {
    const shell =
      items.find((row) => SHELL_RULES.has(row.rule_tech_name)) ??
      items.find((row) => Boolean(row.raw_output?.trim())) ??
      items[0];
    const storedChecks = items.filter((row) => !SHELL_RULES.has(row.rule_tech_name));
    return {
      hostId,
      shell,
      storedChecks,
      rawOutput: shell?.raw_output?.trim() ?? "",
    };
  });
}

function resolveHostChecks(group: HostResultGroup): PlaybookComplianceCheck[] {
  if (group.storedChecks.length > 0) {
    return group.storedChecks
      .map((row) => ({
        rule: row.rule_tech_name,
        status: (row.status === "pass" || row.status === "fail" || row.status === "skip" || row.status === "error"
          ? row.status
          : "error") as PlaybookComplianceCheck["status"],
        summary: "",
        detail: row.message ?? "",
        message: row.message ?? "",
      }))
      .sort((a, b) => a.rule.localeCompare(b.rule));
  }
  return parsePlaybookComplianceChecks(group.rawOutput);
}

function classifyOutputLine(line: string): OutputLineKind {
  const trimmed = line.trim();
  if (!trimmed) return "plain";
  if (/^PLAY \[/i.test(trimmed)) return "play";
  if (/^TASK \[/i.test(trimmed) || /^OK \[/i.test(trimmed)) return "task";
  if (/^ok:/i.test(trimmed)) return "ok";
  if (/^changed:/i.test(trimmed)) return "changed";
  if (/^(fatal:|FAILED!)/i.test(trimmed)) return "failed";
  if (/^skipping:/i.test(trimmed)) return "skipped";
  return "plain";
}

function PlaybookOutputViewer({ output, emptyLabel }: { output: string; emptyLabel: string }) {
  const lines = useMemo(() => output.trim().split("\n"), [output]);

  if (lines.length === 0 || (lines.length === 1 && !lines[0].trim())) {
    return <p className="pf-playbook-output__empty">{emptyLabel}</p>;
  }

  return (
    <div className="pf-playbook-output" role="log" aria-live="polite">
      {lines.map((line, index) => {
        const kind = classifyOutputLine(line);
        const truncated = line.length > OUTPUT_LINE_PREVIEW_CHARS;
        const display = truncated
          ? `${line.slice(0, OUTPUT_LINE_PREVIEW_CHARS)}… [truncated ${line.length - OUTPUT_LINE_PREVIEW_CHARS} chars]`
          : line;
        return (
          <div
            key={`${index}-${line.slice(0, 24)}`}
            className={`pf-playbook-output__line pf-playbook-output__line--${kind}`}
          >
            <span className="pf-playbook-output__gutter">{index + 1}</span>
            <span className="pf-playbook-output__text" title={truncated ? `Full line: ${line.length} chars` : undefined}>
              {display || " "}
            </span>
          </div>
        );
      })}
    </div>
  );
}

function HostStatusIcon({ status }: { status: string }) {
  if (status === "pass") {
    return (
      <span className="pf-playbook-run-results__status-icon pf-playbook-run-results__status-icon--pass" aria-hidden>
        ✓
      </span>
    );
  }
  if (status === "fail" || status === "error") {
    return (
      <span className="pf-playbook-run-results__status-icon pf-playbook-run-results__status-icon--fail" aria-hidden>
        !
      </span>
    );
  }
  if (status === "skip") {
    return (
      <span className="pf-playbook-run-results__status-icon pf-playbook-run-results__status-icon--skip" aria-hidden>
        −
      </span>
    );
  }
  return (
    <span className="pf-playbook-run-results__status-icon pf-playbook-run-results__status-icon--neutral" aria-hidden>
      •
    </span>
  );
}

function hostDisplayStatus(shellStatus: string, checks: PlaybookComplianceCheck[]): string {
  if (checks.length === 0) return shellStatus;
  if (checks.some((c) => c.status === "fail" || c.status === "error")) return "fail";
  if (checks.every((c) => c.status === "skip")) return "skip";
  if (shellStatus === "error") return "error";
  return "pass";
}

type ComplianceChecksModalProps = {
  open: boolean;
  onClose: () => void;
  checks: PlaybookComplianceCheck[];
  hostName: string;
  runId: number;
};

function ComplianceChecksModal({ open, onClose, checks, hostName, runId }: ComplianceChecksModalProps) {
  const { t } = useTranslation();
  const titleId = useId();
  const searchId = useId();
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [query, setQuery] = useState("");

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    window.addEventListener("keydown", onKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [open, onClose]);

  useEffect(() => {
    if (!open) {
      setStatusFilter("all");
      setQuery("");
    }
  }, [open]);

  const summary = useMemo(() => summarizeStatuses(checks.map((c) => c.status)), [checks]);

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return checks.filter((row) => {
      if (statusFilter !== "all" && row.status !== statusFilter) return false;
      if (!q) return true;
      return (
        row.rule.toLowerCase().includes(q) ||
        row.message.toLowerCase().includes(q) ||
        row.summary.toLowerCase().includes(q) ||
        row.detail.toLowerCase().includes(q)
      );
    });
  }, [checks, query, statusFilter]);

  const filtersActive = statusFilter !== "all" || query.trim().length > 0;

  if (!open) return null;

  const statusChips: Array<{ value: string; label: string; count: number; tone: string }> = [
    { value: "all", label: t("playbooks.complianceStatusAll"), count: checks.length, tone: "neutral" },
    { value: "pass", label: "PASS", count: summary.pass, tone: "pass" },
    { value: "fail", label: "FAIL", count: summary.fail + summary.error, tone: "fail" },
    ...(summary.skip > 0
      ? [{ value: "skip", label: "SKIP", count: summary.skip, tone: "skip" }]
      : []),
  ];

  return createPortal(
    <div className="pf-modal pf-modal--playbook-compliance" role="presentation" onClick={onClose}>
      <div
        className="pf-modal__panel pf-modal__panel--playbook-compliance"
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="pf-modal__header pf-playbook-compliance-modal__header">
          <div className="pf-playbook-compliance-modal__heading">
            <h3 id={titleId} className="pf-modal__title">
              {t("playbooks.complianceChecks")}
            </h3>
            <p className="pf-modal__subtitle">
              {t("playbooks.complianceModalSubtitle", { host: hostName, runId })}
            </p>
          </div>
          <Button variant="secondary" className="pf-btn--sm" onClick={onClose}>
            {t("common.close")}
          </Button>
        </div>

        <div className="pf-playbook-compliance-modal__toolbar">
          <div className="pf-playbook-compliance-modal__chips" role="tablist" aria-label={t("common.status")}>
            {statusChips.map((chip) => (
              <button
                key={chip.value}
                type="button"
                role="tab"
                aria-selected={statusFilter === chip.value}
                className={`pf-playbook-compliance-modal__chip pf-playbook-compliance-modal__chip--${chip.tone}${
                  statusFilter === chip.value ? " is-active" : ""
                }`}
                onClick={() => setStatusFilter(chip.value)}
              >
                <span className="pf-playbook-compliance-modal__chip-label">{chip.label}</span>
                <strong className="pf-playbook-compliance-modal__chip-count">{chip.count}</strong>
              </button>
            ))}
          </div>

          <div className="pf-playbook-compliance-modal__filters">
            <label className="pf-playbook-compliance-modal__field" htmlFor={searchId}>
              <span className="pf-playbook-compliance-modal__field-label">
                {t("playbooks.complianceSearchLabel")}
              </span>
              <input
                id={searchId}
                className="pf-input"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder={t("playbooks.complianceSearchPlaceholder")}
              />
            </label>
            {filtersActive && (
              <Button
                variant="secondary"
                className="pf-btn--sm pf-playbook-compliance-modal__clear"
                onClick={() => {
                  setStatusFilter("all");
                  setQuery("");
                }}
              >
                {t("playbooks.complianceClearFilters")}
              </Button>
            )}
          </div>
        </div>

        <div className="pf-playbook-compliance-modal__meta">
          <span>
            {t("playbooks.complianceShowing", {
              shown: filtered.length,
              total: checks.length,
            })}
          </span>
          <span className="pf-playbook-compliance-modal__meta-hint">
            {t("playbooks.complianceChecksHint", {
              passed: summary.pass,
              failed: summary.fail + summary.error,
              total: checks.length,
            })}
          </span>
        </div>

        <div className="pf-table-wrap pf-playbook-compliance-modal__table-wrap">
          <table className="pf-table pf-playbook-compliance-modal__table">
            <thead>
              <tr>
                <th scope="col">{t("reports.rule")}</th>
                <th scope="col">{t("common.status")}</th>
                <th scope="col">{t("reports.message")}</th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 ? (
                <tr>
                  <td colSpan={3}>
                    <div className="pf-check-details__empty">
                      <strong>{t("reports.noFilterResults")}</strong>
                      <p>{t("playbooks.complianceNoFilterDesc")}</p>
                    </div>
                  </td>
                </tr>
              ) : (
                filtered.map((row) => (
                  <tr key={row.rule}>
                    <td className="pf-table__mono pf-playbook-compliance-modal__rule">{row.rule}</td>
                    <td className="pf-playbook-compliance-modal__status">
                      <Badge variant={checkStatusVariant(row.status)}>{row.status}</Badge>
                    </td>
                    <td className="pf-playbook-compliance-modal__message">{row.message || t("common.dash")}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>,
    document.body
  );
}

type ComplianceLaunchBarProps = {
  summary: StatusSummary;
  total: number;
  onOpen: () => void;
};

function ComplianceLaunchBar({ summary, total, onOpen }: ComplianceLaunchBarProps) {
  const { t } = useTranslation();
  return (
    <div className="pf-playbook-compliance-launch">
      <div className="pf-playbook-compliance-launch__copy">
        <span className="pf-playbook-compliance-launch__title">{t("playbooks.complianceChecks")}</span>
        <span className="pf-playbook-compliance-launch__hint">
          {t("playbooks.complianceChecksHint", {
            passed: summary.pass,
            failed: summary.fail + summary.error,
            total,
          })}
        </span>
      </div>
      <div className="pf-playbook-compliance-launch__stats" aria-hidden>
        <span className="pf-playbook-compliance-launch__stat pf-playbook-compliance-launch__stat--pass">
          {summary.pass}
        </span>
        <span className="pf-playbook-compliance-launch__stat pf-playbook-compliance-launch__stat--fail">
          {summary.fail + summary.error}
        </span>
      </div>
      <Button variant="secondary" className="pf-btn--sm" onClick={onOpen}>
        {t("playbooks.complianceOpen")}
      </Button>
    </div>
  );
}

export function PlaybookRunResults({ run, hostNameById }: PlaybookRunResultsProps) {
  const { t, dateLocale } = useTranslation();
  const [expandedHostIds, setExpandedHostIds] = useState<Set<number>>(new Set());
  const [complianceHostId, setComplianceHostId] = useState<number | null>(null);

  const hostGroups = useMemo(() => groupHostResults(run.check_results), [run.check_results]);
  const checksByHost = useMemo(() => {
    const map = new Map<number, PlaybookComplianceCheck[]>();
    for (const group of hostGroups) {
      map.set(group.hostId, resolveHostChecks(group));
    }
    return map;
  }, [hostGroups]);

  const allChecks = useMemo(
    () => hostGroups.flatMap((group) => checksByHost.get(group.hostId) ?? []),
    [hostGroups, checksByHost]
  );
  const hasComplianceChecks = allChecks.length > 0;
  const summary = useMemo(() => {
    if (hasComplianceChecks) return summarizeStatuses(allChecks.map((c) => c.status));
    return summarizeStatuses(hostGroups.map((g) => g.shell.status));
  }, [allChecks, hasComplianceChecks, hostGroups]);

  const duration = formatDuration(run.started_at, run.finished_at);
  const allExpanded = hostGroups.length > 0 && expandedHostIds.size === hostGroups.length;
  const hostIdsKey = hostGroups.map((group) => group.hostId).join(",");

  const complianceHost = hostGroups.find((group) => group.hostId === complianceHostId) ?? null;
  const complianceChecks = complianceHost ? checksByHost.get(complianceHost.hostId) ?? [] : [];
  const complianceHostName = complianceHost
    ? hostNameById.get(complianceHost.hostId) ?? `Host #${complianceHost.hostId}`
    : "";

  useEffect(() => {
    if (hostGroups.length > 0) {
      setExpandedHostIds(new Set([hostGroups[0].hostId]));
    } else {
      setExpandedHostIds(new Set());
    }
    setComplianceHostId(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- hostIdsKey captures host identity
  }, [run.id, hostIdsKey]);

  const toggleHost = (hostId: number) => {
    setExpandedHostIds((prev) => {
      const next = new Set(prev);
      if (next.has(hostId)) next.delete(hostId);
      else next.add(hostId);
      return next;
    });
  };

  const toggleAll = () => {
    if (allExpanded) {
      setExpandedHostIds(new Set());
      return;
    }
    setExpandedHostIds(new Set(hostGroups.map((group) => group.hostId)));
  };

  if (hostGroups.length === 0) {
    return <p className="pf-table__muted">{t("playbooks.noHostResults")}</p>;
  }

  const metrics = [
    {
      key: "hosts",
      label: t("playbooks.resultsHosts"),
      value: String(hostGroups.length),
      tone: "neutral" as const,
    },
    {
      key: "pass",
      label: hasComplianceChecks ? t("playbooks.checksPass") : t("playbooks.resultsPass"),
      value: String(summary.pass),
      tone: "pass" as const,
    },
    {
      key: "fail",
      label: hasComplianceChecks ? t("playbooks.checksFail") : t("playbooks.resultsFail"),
      value: String(summary.fail + summary.error),
      tone: "fail" as const,
    },
    ...(summary.skip > 0
      ? [
          {
            key: "skip",
            label: t("playbooks.resultsSkip"),
            value: String(summary.skip),
            tone: "skip" as const,
          },
        ]
      : []),
    ...(duration
      ? [
          {
            key: "duration",
            label: t("playbooks.resultsDuration"),
            value: duration,
            tone: "neutral" as const,
          },
        ]
      : []),
    ...(run.started_at
      ? [
          {
            key: "started",
            label: t("reports.started"),
            value: new Date(run.started_at).toLocaleString(dateLocale),
            tone: "neutral" as const,
          },
        ]
      : []),
  ];

  return (
    <div className="pf-playbook-run-results">
      <div className="pf-playbook-run-results__summary">
        {metrics.map((metric) => (
          <div
            key={metric.key}
            className={`pf-playbook-run-results__metric pf-playbook-run-results__metric--${metric.tone}`}
          >
            <span className="pf-playbook-run-results__metric-label">{metric.label}</span>
            <strong className="pf-playbook-run-results__metric-value">{metric.value}</strong>
          </div>
        ))}
      </div>

      <div className="pf-playbook-run-results__toolbar">
        <div className="pf-playbook-run-results__toolbar-copy">
          <span className="pf-playbook-run-results__toolbar-title">{t("playbooks.resultsByHost")}</span>
          <span className="pf-playbook-run-results__toolbar-subtitle">
            {hasComplianceChecks ? t("playbooks.resultsByHostComplianceHint") : t("playbooks.resultsByHostHint")}
          </span>
        </div>
        <Button variant="secondary" className="pf-btn--sm" onClick={toggleAll}>
          {allExpanded ? t("playbooks.collapseAll") : t("playbooks.expandAll")}
        </Button>
      </div>

      <div className="pf-playbook-run-results__list">
        {hostGroups.map((group) => {
          const hostName = hostNameById.get(group.hostId) ?? `Host #${group.hostId}`;
          const expanded = expandedHostIds.has(group.hostId);
          const output = group.rawOutput;
          const checks = checksByHost.get(group.hostId) ?? [];
          const displayStatus = hostDisplayStatus(group.shell.status, checks);
          const checkSummary = summarizeStatuses(checks.map((c) => c.status));
          const displayMessage =
            checks.length > 0
              ? group.shell.message ||
                t("playbooks.complianceChecksHint", {
                  passed: checkSummary.pass,
                  failed: checkSummary.fail + checkSummary.error,
                  total: checks.length,
                })
              : group.shell.message || t("common.dash");

          return (
            <article
              key={group.hostId}
              className={`pf-playbook-run-results__card ${resultAccentClass(displayStatus)}${
                expanded ? " is-expanded" : ""
              }`}
            >
              <button
                type="button"
                className="pf-playbook-run-results__card-header"
                onClick={() => toggleHost(group.hostId)}
                aria-expanded={expanded}
              >
                <HostStatusIcon status={displayStatus} />
                <div className="pf-playbook-run-results__card-body">
                  <div className="pf-playbook-run-results__card-top">
                    <span className="pf-playbook-run-results__host">{hostName}</span>
                    <Badge variant={resultStatusVariant(displayStatus)}>{displayStatus}</Badge>
                  </div>
                  <p className="pf-playbook-run-results__message" title={displayMessage || undefined}>
                    {displayMessage}
                  </p>
                </div>
                <span className="pf-playbook-run-results__chevron" aria-hidden>
                  {expanded ? "▾" : "▸"}
                </span>
              </button>
              {expanded && (
                <>
                  <div className="pf-playbook-run-results__output-wrap">
                    <div className="pf-playbook-run-results__output-header">
                      <span>{t("playbooks.taskOutput")}</span>
                      {output && (
                        <span className="pf-playbook-run-results__output-meta">
                          {t("playbooks.outputLines", { count: output.split("\n").length })}
                        </span>
                      )}
                    </div>
                    <PlaybookOutputViewer output={output} emptyLabel={t("playbooks.noOutput")} />
                  </div>
                  {checks.length > 0 && (
                    <ComplianceLaunchBar
                      summary={checkSummary}
                      total={checks.length}
                      onOpen={() => setComplianceHostId(group.hostId)}
                    />
                  )}
                </>
              )}
            </article>
          );
        })}
      </div>

      <ComplianceChecksModal
        open={complianceHostId !== null && complianceChecks.length > 0}
        onClose={() => setComplianceHostId(null)}
        checks={complianceChecks}
        hostName={complianceHostName}
        runId={run.id}
      />
    </div>
  );
}
