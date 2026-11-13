import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, type ProfileRule, type RemediationSuggestion } from "../api/client";
import {
  findProfileRule,
  hasProfileRuleMetadata,
  ProfileRuleMetadata,
  ProfileRuleSeverityChip,
  profileRuleDisplayName,
} from "./ProfileRuleDetail";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Panel } from "./ui/Panel";
import { Spinner } from "./ui/Spinner";
import { useConfirm } from "./ui/ConfirmDialog";
import { useToast } from "./ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";
import {
  getProfileRuleSeverityBucket,
  type ProfileSeverityBucket,
} from "../utils/profileRuleSeverity";

const WORKFLOW_STORAGE_PREFIX = "secaudit-workflow:";

type WorkflowState = {
  remediationJobId: number;
  remediationRunId: number | null;
  sourceRunId: number;
  sourceJobId: number;
  reauditRunId: number | null;
  reauditCompleted: boolean;
};

function normalizeWorkflowState(raw: WorkflowState | null): WorkflowState | null {
  if (!raw) return null;
  return {
    ...raw,
    reauditRunId: raw.reauditRunId ?? null,
    reauditCompleted: raw.reauditCompleted ?? false,
  };
}

function readWorkflowState(runId: number): WorkflowState | null {
  try {
    const raw = sessionStorage.getItem(`${WORKFLOW_STORAGE_PREFIX}${runId}`);
    return raw ? normalizeWorkflowState(JSON.parse(raw) as WorkflowState) : null;
  } catch {
    return null;
  }
}

function writeWorkflowState(runId: number, state: WorkflowState) {
  sessionStorage.setItem(`${WORKFLOW_STORAGE_PREFIX}${runId}`, JSON.stringify(state));
}

function findWorkflowContext(
  viewRunId: number
): { storageRunId: number; state: WorkflowState } | null {
  const direct = readWorkflowState(viewRunId);
  if (direct) return { storageRunId: viewRunId, state: direct };

  for (let index = 0; index < sessionStorage.length; index += 1) {
    const key = sessionStorage.key(index);
    if (!key?.startsWith(WORKFLOW_STORAGE_PREFIX)) continue;
    const storageRunId = Number(key.slice(WORKFLOW_STORAGE_PREFIX.length));
    if (!Number.isFinite(storageRunId)) continue;
    const state = readWorkflowState(storageRunId);
    if (state?.reauditRunId === viewRunId) {
      return { storageRunId, state };
    }
  }

  return null;
}

type RemediationWorkflowPanelProps = {
  runId: number;
  jobId: number;
  runStatus: string;
  canOperate: boolean;
  profileRules?: ProfileRule[];
  onReauditComplete?: (reauditRunId: number) => void;
};

function WorkflowStep({
  index,
  title,
  state,
  children,
}: {
  index: number;
  title: string;
  state: "done" | "active" | "pending";
  children: ReactNode;
}) {
  return (
    <li className={`pf-workflow-rail__step pf-workflow-rail__step--${state}`}>
      <div className="pf-workflow-rail__marker" aria-hidden>
        {state === "done" ? (
          <svg className="pf-workflow-rail__check" viewBox="0 0 12 12" aria-hidden>
            <path d="M2 6.2 4.8 9 10 3" fill="none" stroke="currentColor" strokeWidth="1.75" strokeLinecap="round" />
          </svg>
        ) : (
          <span className="pf-workflow-rail__index">{index}</span>
        )}
      </div>
      <div className="pf-workflow-rail__content">
        <h3 className="pf-workflow-rail__title">{title}</h3>
        {children}
      </div>
    </li>
  );
}

export function RemediationWorkflowPanel({
  runId,
  jobId,
  runStatus,
  canOperate,
  profileRules,
  onReauditComplete,
}: RemediationWorkflowPanelProps) {
  const { t } = useTranslation();
  const toast = useToast();
  const { confirm } = useConfirm();
  const queryClient = useQueryClient();
  const [workflowCtx, setWorkflowCtx] = useState(() => findWorkflowContext(runId));
  const [selectedScriptId, setSelectedScriptId] = useState<number | "">("");
  const [selectedRules, setSelectedRules] = useState<string[]>([]);
  const [ruleQuery, setRuleQuery] = useState("");
  const [hostFilter, setHostFilter] = useState<number | "">("");
  const [severityFilter, setSeverityFilter] = useState<ProfileSeverityBucket | "">("");
  const [activeRule, setActiveRule] = useState<string | null>(null);
  const [checkMode, setCheckMode] = useState(false);
  const [autoRecheck, setAutoRecheck] = useState(true);
  const rulesSeededRunRef = useRef<number | null>(null);

  useEffect(() => {
    setWorkflowCtx(findWorkflowContext(runId));
  }, [runId]);

  // DB is the source of truth; 404 means no workflow for this run (or it is a re-audit run → sessionStorage fallback).
  // Poll while remediation may still enqueue auto-recheck so workflow_reaudit_run_id appears.
  const dbWorkflow = useQuery({
    queryKey: ["remediation-workflow", runId],
    queryFn: () => api.getRemediationWorkflow(runId),
    enabled: canOperate && runStatus === "completed",
    retry: false,
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data?.auto_recheck_failed || data.check_mode) return false;
      if (data.reaudit_run_id != null) return false;
      return data.remediation_run_id != null ? 4000 : false;
    },
  });

  useEffect(() => {
    const db = dbWorkflow.data;
    if (!db) return;
    const state: WorkflowState = {
      remediationJobId: db.remediation_job_id,
      remediationRunId: db.remediation_run_id,
      sourceRunId: db.source_run_id,
      sourceJobId: db.source_job_id ?? jobId,
      reauditRunId: db.reaudit_run_id,
      reauditCompleted: db.reaudit_completed,
    };
    writeWorkflowState(db.source_run_id, state);
    setWorkflowCtx({ storageRunId: db.source_run_id, state });
  }, [dbWorkflow.data, jobId]);

  const workflow = workflowCtx?.state ?? null;
  const storageRunId = workflowCtx?.storageRunId ?? runId;
  const isSourceRun = storageRunId === runId;
  const sourceRunId = workflow?.sourceRunId ?? storageRunId;

  const reauditRunId = workflow?.reauditRunId ?? null;

  const reauditRun = useQuery({
    queryKey: ["workflow-reaudit-run", reauditRunId],
    queryFn: () => api.getJobRun(reauditRunId!),
    enabled: reauditRunId != null,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "running" || status === "pending" ? 5000 : false;
    },
  });

  // DB marks failed/cancelled re-audits as terminal too; only a completed run closes the cycle here.
  const reauditStatusNow = reauditRun.data?.status;
  const reauditCompleted =
    (workflow?.reauditCompleted ?? false) &&
    reauditStatusNow !== "failed" &&
    reauditStatusNow !== "cancelled";

  const closedFailQuery = useQuery({
    queryKey: ["workflow-closed-fail", storageRunId, reauditRunId],
    queryFn: () => api.getRunsDiff(storageRunId, reauditRunId!),
    enabled: Boolean(reauditCompleted && reauditRunId != null),
  });

  useEffect(() => {
    if (!workflow || reauditCompleted || reauditRunId == null) return;
    const status = reauditRun.data?.status;
    if (status !== "completed") return;

    const next: WorkflowState = { ...workflow, reauditCompleted: true };
    writeWorkflowState(storageRunId, next);
    setWorkflowCtx({ storageRunId, state: next });
    onReauditComplete?.(reauditRunId);
    void queryClient.invalidateQueries({ queryKey: ["job-runs"] });
  }, [
    workflow,
    reauditCompleted,
    reauditRunId,
    reauditRun.data?.status,
    storageRunId,
    onReauditComplete,
    queryClient,
  ]);

  const suggestions = useQuery({
    queryKey: ["remediation-suggestions", storageRunId],
    queryFn: () => api.getRemediationSuggestions(storageRunId),
    enabled: canOperate && runStatus === "completed" && isSourceRun,
  });

  useEffect(() => {
    const data = suggestions.data;
    if (!data) return;
    if (selectedScriptId === "" && data.default_remediation_script_id != null) {
      setSelectedScriptId(data.default_remediation_script_id);
    }
    if (rulesSeededRunRef.current !== data.source_run_id) {
      rulesSeededRunRef.current = data.source_run_id;
      setSelectedRules(
        [...new Set(data.failed_checks.map((item) => item.rule_tech_name))].sort()
      );
      setRuleQuery("");
      setHostFilter("");
      setSeverityFilter("");
      setActiveRule(null);
    }
  }, [suggestions.data, selectedScriptId]);

  const fallbackProfileRules = useQuery({
    queryKey: ["profile-rules", suggestions.data?.profile_id],
    queryFn: () => api.getProfileRules(suggestions.data!.profile_id),
    enabled: !profileRules && suggestions.data?.profile_id != null,
  });

  const effectiveRules = profileRules ?? fallbackProfileRules.data;

  const fromRunMutation = useMutation({
    mutationFn: (payload: {
      source_run_id: number;
      remediation_script_id?: number;
      run_remediation: boolean;
      set_baseline: boolean;
      rule_tech_names?: string[];
      check_mode?: boolean;
      auto_recheck_failed?: boolean;
    }) => api.createRemediationFromRun(payload),
    onSuccess: (result) => {
      const next: WorkflowState = {
        remediationJobId: result.remediation_job_id,
        remediationRunId: result.remediation_run_id,
        sourceRunId: result.source_run_id,
        sourceJobId: result.source_job_id,
        reauditRunId: null,
        reauditCompleted: false,
      };
      writeWorkflowState(storageRunId, next);
      setWorkflowCtx({ storageRunId, state: next });
      void queryClient.invalidateQueries({ queryKey: ["remediation-workflow", storageRunId] });
      void queryClient.invalidateQueries({ queryKey: ["remediations"] });
      void queryClient.invalidateQueries({ queryKey: ["remediation-runs"] });
      void queryClient.invalidateQueries({ queryKey: ["job-baseline", jobId] });
      toast.success(
        checkMode ? t("workflow.remediationDryRunStarted") : t("workflow.remediationStarted")
      );
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const reauditMutation = useMutation({
    mutationFn: () => api.rerunJobRun(sourceRunId, { subset: "failed" }),
    onSuccess: (newRun) => {
      setWorkflowCtx((prev) => {
        if (!prev?.state) return prev;
        const next: WorkflowState = {
          ...prev.state,
          reauditRunId: newRun.id,
          reauditCompleted: false,
        };
        writeWorkflowState(prev.storageRunId, next);
        return { storageRunId: prev.storageRunId, state: next };
      });
      const sourceId = workflowCtx?.storageRunId ?? runId;
      api
        .setRemediationWorkflowReaudit(sourceId, newRun.id)
        .then(() => queryClient.invalidateQueries({ queryKey: ["remediation-workflow", sourceId] }))
        .catch((err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")));
      toast.success(t("workflow.reauditStarted", { id: newRun.id }));
      void queryClient.invalidateQueries({ queryKey: ["job-runs"] });
      void queryClient.invalidateQueries({ queryKey: ["workflow-reaudit-run", newRun.id] });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const hasCompletedCycle =
    workflow?.reauditCompleted === true && (isSourceRun || workflow.reauditRunId === runId);
  const data: RemediationSuggestion | undefined = suggestions.data;

  const ruleRows = useMemo(() => {
    if (!data) return [];
    const byRule = new Map<
      string,
      {
        fails: number;
        hosts: Map<number, { id: number; name: string; fails: number }>;
        message: string | null;
      }
    >();
    for (const item of data.failed_checks) {
      const hostId = Number(item.host_id);
      const current = byRule.get(item.rule_tech_name) ?? {
        fails: 0,
        hosts: new Map(),
        message: null,
      };
      current.fails += 1;
      const label = item.host_name?.trim() || `#${hostId}`;
      const hostRow = current.hosts.get(hostId) ?? { id: hostId, name: label, fails: 0 };
      hostRow.fails += 1;
      if (!hostRow.name || hostRow.name.startsWith("#")) hostRow.name = label;
      current.hosts.set(hostId, hostRow);
      if (!current.message && item.message?.trim()) {
        current.message = item.message.trim();
      }
      byRule.set(item.rule_tech_name, current);
    }

    const profileIndex = new Map<string, number>();
    effectiveRules?.forEach((rule, index) => {
      if (rule.requirement_id) profileIndex.set(rule.requirement_id, index);
      if (rule.tech_name) profileIndex.set(rule.tech_name, index);
    });

    const ruleOrderKey = (rule: string): [number, number, string] => {
      const meta = findProfileRule(effectiveRules, rule);
      const fromNum = Number.parseInt(String(meta?.num ?? "").trim(), 10);
      if (Number.isFinite(fromNum)) return [fromNum, profileIndex.get(rule) ?? Number.POSITIVE_INFINITY, rule];
      const fromId = rule.match(/(\d+)(?:\.\d+)*\s*$/);
      if (fromId) {
        return [Number.parseInt(fromId[1], 10), profileIndex.get(rule) ?? Number.POSITIVE_INFINITY, rule];
      }
      return [
        Number.POSITIVE_INFINITY,
        profileIndex.get(rule) ?? Number.POSITIVE_INFINITY,
        rule,
      ];
    };

    return [...byRule.entries()]
      .map(([rule, stats]) => {
        const hosts = [...stats.hosts.values()].sort((a, b) =>
          a.name.localeCompare(b.name, undefined, { sensitivity: "base" })
        );
        return {
          rule,
          fails: stats.fails,
          hosts,
          hostIds: hosts.map((host) => host.id),
          hostNames: hosts.map((host) => host.name),
          message: stats.message,
        };
      })
      .sort((a, b) => {
        const [oa, ia, sa] = ruleOrderKey(a.rule);
        const [ob, ib, sb] = ruleOrderKey(b.rule);
        if (oa !== ob) return oa - ob;
        if (ia !== ib) return ia - ib;
        return sa.localeCompare(sb, undefined, { numeric: true, sensitivity: "base" });
      });
  }, [data, effectiveRules]);

  const hostFilterOptions = useMemo(() => {
    if (!data) return [];
    const byId = new Map<number, string>();
    for (const item of data.failed_checks) {
      const hostId = Number(item.host_id);
      if (byId.has(hostId)) continue;
      byId.set(hostId, item.host_name?.trim() || `#${hostId}`);
    }
    return [...byId.entries()]
      .map(([id, name]) => ({ id, name }))
      .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: "base" }));
  }, [data]);

  const uniqueRules = useMemo(() => ruleRows.map((row) => row.rule), [ruleRows]);
  const filteredRules = useMemo(() => {
    const query = ruleQuery.trim().toLowerCase();
    const selectedHostId = hostFilter === "" ? null : Number(hostFilter);
    return ruleRows.flatMap((row) => {
      const hosts =
        selectedHostId == null
          ? row.hosts
          : row.hosts.filter((host) => host.id === selectedHostId);
      if (hosts.length === 0) return [];

      if (severityFilter) {
        const meta = findProfileRule(effectiveRules, row.rule);
        const bucket = getProfileRuleSeverityBucket(meta);
        if (bucket !== severityFilter) return [];
      }

      if (query) {
        const meta = findProfileRule(effectiveRules, row.rule);
        const title = meta ? profileRuleDisplayName(meta).toLowerCase() : "";
        const matchesRule =
          row.rule.toLowerCase().includes(query) || title.includes(query);
        const matchesHost = hosts.some((host) => host.name.toLowerCase().includes(query));
        if (!matchesRule && !matchesHost) return [];
      }

      const fails = hosts.reduce((sum, host) => sum + host.fails, 0);
      return [
        {
          ...row,
          hosts,
          hostIds: hosts.map((host) => host.id),
          hostNames: hosts.map((host) => host.name),
          fails,
        },
      ];
    });
  }, [ruleRows, ruleQuery, hostFilter, severityFilter, effectiveRules]);

  const filteredRuleIds = useMemo(
    () => filteredRules.map((row) => row.rule),
    [filteredRules]
  );

  const ruleLabels = useMemo(
    () => ({
      description: t("profiles.ruleDescription"),
      risk: t("profiles.ruleRisk"),
      location: t("profiles.ruleLocation"),
      scapRuleId: t("profiles.scapRuleId"),
    }),
    [t]
  );

  const selectedHostCount = data
    ? new Set(
        data.failed_checks
          .filter((item) => selectedRules.includes(item.rule_tech_name))
          .map((item) => item.host_id)
      ).size
    : 0;
  const selectedFailCount = data
    ? data.failed_checks.filter((item) => selectedRules.includes(item.rule_tech_name)).length
    : 0;

  const toggleRule = (rule: string) => {
    setSelectedRules((prev) =>
      prev.includes(rule) ? prev.filter((item) => item !== rule) : [...prev, rule]
    );
  };

  const handleConfirmRemediation = async () => {
    if (!data || selectedRules.length === 0) return;
    const ok = await confirm({
      title: checkMode ? t("workflow.confirmDryRunTitle") : t("workflow.confirmTitle"),
      message: t("workflow.confirmMessageScoped", {
        failed: selectedFailCount,
        hosts: selectedHostCount,
        rules: selectedRules.length,
      }),
      confirmLabel: checkMode ? t("workflow.confirmDryRun") : t("workflow.confirmRun"),
      variant: "default",
    });
    if (!ok) return;
    fromRunMutation.mutate({
      source_run_id: storageRunId,
      remediation_script_id: selectedScriptId === "" ? undefined : selectedScriptId,
      run_remediation: true,
      set_baseline: !checkMode,
      rule_tech_names: selectedRules,
      check_mode: checkMode,
      auto_recheck_failed: !checkMode && autoRecheck,
    });
  };

  const reauditStatus = reauditRun.data?.status;
  const reauditRunning =
    reauditRunId != null &&
    !reauditCompleted &&
    (reauditStatus === "running" || reauditStatus === "pending");
  const reauditFailed =
    reauditRunId != null &&
    !reauditCompleted &&
    (reauditStatus === "failed" || reauditStatus === "cancelled");
  const stepReauditState: "done" | "active" | "pending" = reauditCompleted
    ? "done"
    : workflow
      ? "active"
      : "pending";
  const stepDriftState: "done" | "active" | "pending" = reauditCompleted ? "done" : "pending";

  if (!canOperate || runStatus !== "completed") return null;

  if (!hasCompletedCycle) {
    if (isSourceRun && suggestions.isLoading) {
      return (
        <Panel title={t("workflow.title")} description={t("workflow.intro")} className="pf-workflow-panel">
          <Spinner />
        </Panel>
      );
    }
    if (!isSourceRun || suggestions.isError || !data || data.failed_count === 0) return null;
  }

  return (
    <Panel
      title={t("workflow.title")}
      description={t("workflow.intro")}
      className="pf-workflow-panel"
    >
      <ol className="pf-workflow-rail" aria-label={t("workflow.title")}>
        <WorkflowStep index={1} title={t("workflow.stepAudit")} state="done">
          <div className="pf-workflow-rail__summary">
            <Badge variant="success">{t("workflow.runComplete", { id: sourceRunId })}</Badge>
          </div>
        </WorkflowStep>

        <WorkflowStep index={2} title={t("workflow.stepRemediate")} state={workflow ? "done" : "active"}>
          {!workflow ? (
            data ? (
            <div className="pf-workflow-rail__card">
              <div className="pf-workflow-rail__metrics">
                <span className="pf-workflow-rail__metric pf-workflow-rail__metric--fail">
                  <span className="pf-workflow-rail__metric-value">{data.failed_count}</span>
                  <span className="pf-workflow-rail__metric-label">{t("workflow.failedLabel")}</span>
                </span>
                <span className="pf-workflow-rail__metric">
                  <span className="pf-workflow-rail__metric-value">{data.host_ids.length}</span>
                  <span className="pf-workflow-rail__metric-label">{t("workflow.hostsLabel")}</span>
                </span>
              </div>

              {data.remediation_scripts.length > 0 ? (
                <label className="pf-workflow-rail__field">
                  <span className="pf-workflow-rail__field-label">{t("workflow.script")}</span>
                  <select
                    className="pf-select"
                    value={selectedScriptId}
                    onChange={(e) =>
                      setSelectedScriptId(e.target.value ? Number(e.target.value) : "")
                    }
                  >
                    {data.remediation_scripts.map((script) => (
                      <option key={script.id} value={script.id}>
                        {script.name} ({script.execution_type})
                      </option>
                    ))}
                  </select>
                </label>
              ) : (
                <p className="pf-workflow-rail__note pf-workflow-rail__note--warning">{t("workflow.noScripts")}</p>
              )}

              <section className="pf-workflow-rail__rules" aria-labelledby="workflow-rules-heading">
                <div className="pf-workflow-rail__rules-head">
                  <div className="pf-workflow-rail__rules-title-row">
                    <h4 id="workflow-rules-heading" className="pf-workflow-rail__rules-title">
                      {t("workflow.rulesLabel")}
                    </h4>
                    <span className="pf-workflow-rail__rules-count">
                      {t("workflow.rulesSelected", {
                        selected: selectedRules.filter((rule) => filteredRuleIds.includes(rule))
                          .length,
                        total: filteredRuleIds.length || uniqueRules.length,
                      })}
                    </span>
                  </div>
                  <div className="pf-workflow-rail__rules-controls">
                    <div className="pf-workflow-rail__rules-filters">
                      <div className="pf-workflow-rail__rules-search">
                        <input
                          type="search"
                          className="pf-input"
                          value={ruleQuery}
                          onChange={(event) => setRuleQuery(event.target.value)}
                          placeholder={t("workflow.rulesSearchPlaceholder")}
                          aria-label={t("workflow.rulesSearchPlaceholder")}
                        />
                      </div>
                      {hostFilterOptions.length > 1 ? (
                        <div className="pf-workflow-rail__rules-filter">
                          <select
                            className="pf-select"
                            value={hostFilter === "" ? "" : String(hostFilter)}
                            onChange={(event) =>
                              setHostFilter(event.target.value ? Number(event.target.value) : "")
                            }
                            aria-label={t("workflow.rulesHostFilter")}
                          >
                            <option value="">{t("workflow.rulesHostAll")}</option>
                            {hostFilterOptions.map((host) => (
                              <option key={host.id} value={host.id}>
                                {host.name}
                              </option>
                            ))}
                          </select>
                        </div>
                      ) : null}
                      <div className="pf-workflow-rail__rules-filter">
                        <select
                          className="pf-select"
                          value={severityFilter}
                          onChange={(event) =>
                            setSeverityFilter(
                              (event.target.value || "") as ProfileSeverityBucket | ""
                            )
                          }
                          aria-label={t("workflow.rulesSeverityFilter")}
                        >
                          <option value="">{t("workflow.rulesSeverityAll")}</option>
                          <option value="high">{t("workflow.rulesSeverityHigh")}</option>
                          <option value="medium">{t("workflow.rulesSeverityMedium")}</option>
                          <option value="low">{t("workflow.rulesSeverityLow")}</option>
                        </select>
                      </div>
                    </div>
                    <div className="pf-workflow-rail__rule-actions" role="group" aria-label={t("workflow.rulesLabel")}>
                      <Button
                        type="button"
                        variant="link"
                        className="pf-btn--sm"
                        onClick={() => setSelectedRules(filteredRuleIds)}
                        disabled={
                          filteredRuleIds.length === 0 ||
                          filteredRuleIds.every((rule) => selectedRules.includes(rule))
                        }
                      >
                        {t("workflow.rulesSelectAll")}
                      </Button>
                      <span className="pf-workflow-rail__rule-actions-sep" aria-hidden="true" />
                      <Button
                        type="button"
                        variant="link"
                        className="pf-btn--sm"
                        onClick={() => setSelectedRules([])}
                        disabled={selectedRules.length === 0}
                      >
                        {t("workflow.rulesClear")}
                      </Button>
                    </div>
                  </div>
                </div>

                <div className="pf-workflow-rail__rule-list pf-profile-rules">
                  {filteredRules.length === 0 ? (
                    <p className="pf-workflow-rail__rule-empty">{t("workflow.rulesNoMatch")}</p>
                  ) : (
                    filteredRules.map((row) => {
                      const selected = selectedRules.includes(row.rule);
                      const expanded = activeRule === row.rule;
                      const meta = findProfileRule(effectiveRules, row.rule);
                      const title = meta ? profileRuleDisplayName(meta) : row.rule;
                      const showTitle = Boolean(title && title !== row.rule);
                      const hostsLabel = row.hostNames.join(", ");
                      const tip = [showTitle ? `${row.rule} — ${title}` : row.rule, hostsLabel]
                        .filter(Boolean)
                        .join(" · ");
                      const displayNumber =
                        meta?.num?.trim() ||
                        row.rule.match(/(\d+)\s*$/)?.[1] ||
                        row.rule;
                      const canExpand = hasProfileRuleMetadata(meta) || Boolean(row.message) || showTitle;
                      return (
                        <div
                          key={row.rule}
                          className={`pf-profile-rule${expanded ? " pf-profile-rule--expanded" : ""}${selected ? " pf-workflow-rail__rule--picked" : ""}`}
                        >
                          <div className="pf-profile-rule__head">
                            <label className="pf-profile-rule__pick">
                              <input
                                type="checkbox"
                                className="pf-checkbox-control"
                                checked={selected}
                                onChange={() => toggleRule(row.rule)}
                                aria-label={tip}
                              />
                            </label>
                            <button
                              type="button"
                              className="pf-profile-rule__toggle"
                              onClick={() => {
                                if (!canExpand) return;
                                setActiveRule(expanded ? null : row.rule);
                              }}
                              aria-expanded={expanded}
                              disabled={!canExpand}
                              title={tip}
                            >
                              <span className="pf-profile-rule__chevron" aria-hidden />
                              <span className="pf-profile-rule__number">{displayNumber}</span>
                              <span className="pf-profile-rule__title">
                                {showTitle ? title : row.rule}
                              </span>
                              <span className="pf-profile-rule__tags">
                                {showTitle ? (
                                  <span className="pf-profile-rule__id pf-table__mono">{row.rule}</span>
                                ) : null}
                                {meta ? <ProfileRuleSeverityChip rule={meta} /> : null}
                                {row.hosts.map((host) => (
                                  <span
                                    key={`${row.rule}:${host.id}`}
                                    className="pf-workflow-rail__rule-host"
                                    title={host.name}
                                  >
                                    {host.name}
                                  </span>
                                ))}
                                {row.fails > row.hosts.length ? (
                                  <span
                                    className="pf-workflow-rail__rule-meta"
                                    title={t("workflow.rulesFailMeta", { count: row.fails })}
                                  >
                                    ×{row.fails}
                                  </span>
                                ) : null}
                              </span>
                            </button>
                          </div>
                          {expanded ? (
                            <div className="pf-profile-rule__body" role="region" aria-label={row.rule}>
                              {hasProfileRuleMetadata(meta) ? (
                                <ProfileRuleMetadata rule={meta} labels={ruleLabels} />
                              ) : row.message ? (
                                <p className="pf-workflow-rail__rule-detail-msg">{row.message}</p>
                              ) : (
                                <p className="pf-workflow-rail__rule-detail-empty">
                                  {showTitle ? title : row.rule}
                                </p>
                              )}
                            </div>
                          ) : null}
                        </div>
                      );
                    })
                  )}
                </div>
              </section>

              <div className="pf-workflow-rail__toggles">
                <label className={`pf-workflow-rail__toggle${checkMode ? " pf-workflow-rail__toggle--on" : ""}`}>
                  <input
                    type="checkbox"
                    className="pf-checkbox-control"
                    checked={checkMode}
                    onChange={(event) => setCheckMode(event.target.checked)}
                  />
                  <span className="pf-workflow-rail__toggle-copy">
                    <span className="pf-workflow-rail__toggle-title">{t("workflow.dryRunTitle")}</span>
                    <span className="pf-workflow-rail__toggle-hint">{t("workflow.dryRunHint")}</span>
                  </span>
                </label>
                <label
                  className={`pf-workflow-rail__toggle${autoRecheck && !checkMode ? " pf-workflow-rail__toggle--on" : ""}${checkMode ? " pf-workflow-rail__toggle--disabled" : ""}`}
                >
                  <input
                    type="checkbox"
                    className="pf-checkbox-control"
                    checked={autoRecheck}
                    disabled={checkMode}
                    onChange={(event) => setAutoRecheck(event.target.checked)}
                  />
                  <span className="pf-workflow-rail__toggle-copy">
                    <span className="pf-workflow-rail__toggle-title">{t("workflow.autoRecheckTitle")}</span>
                    <span className="pf-workflow-rail__toggle-hint">{t("workflow.autoRecheckHint")}</span>
                  </span>
                </label>
              </div>

              <div className="pf-workflow-rail__footer">
                <p className="pf-workflow-rail__scope">
                  {t("workflow.rulesScope", {
                    rules: selectedRules.length,
                    failed: selectedFailCount,
                    hosts: selectedHostCount,
                  })}
                </p>
                <div className="pf-workflow-rail__actions">
                  <Button
                    variant="primary"
                    onClick={() => void handleConfirmRemediation()}
                    disabled={
                      fromRunMutation.isPending ||
                      data.remediation_scripts.length === 0 ||
                      selectedRules.length === 0
                    }
                  >
                    {checkMode ? t("workflow.startDryRun") : t("workflow.startRemediation")}
                  </Button>
                </div>
              </div>
            </div>
            ) : null
          ) : (
            <div className="pf-workflow-rail__summary">
              <p className="pf-workflow-rail__text">{t("workflow.remediationCreated", { id: workflow.remediationJobId })}</p>
              {workflow.remediationRunId != null ? (
                <Link to="/remediation" className="pf-link">
                  {t("workflow.viewRemediationRun", { id: workflow.remediationRunId })}
                </Link>
              ) : null}
            </div>
          )}
        </WorkflowStep>

        <WorkflowStep index={3} title={t("workflow.stepReaudit")} state={stepReauditState}>
          {reauditCompleted && reauditRunId != null ? (
            <div className="pf-workflow-rail__summary">
              <Badge variant="success">{t("workflow.reauditComplete", { id: reauditRunId })}</Badge>
            </div>
          ) : (
            <div className={`pf-workflow-rail__card${workflow ? "" : " pf-workflow-rail__card--muted"}`}>
              {reauditRunning ? (
                <div className="pf-workflow-rail__summary">
                  <Spinner />
                  <Badge variant="info">{t("workflow.reauditRunning", { id: reauditRunId })}</Badge>
                </div>
              ) : (
                <>
                  {reauditFailed ? (
                    <p className="pf-workflow-rail__note pf-workflow-rail__note--warning">
                      {t("workflow.reauditFailed", { id: reauditRunId })}
                    </p>
                  ) : (
                    <p className="pf-workflow-rail__text">{t("workflow.reauditHint")}</p>
                  )}
                  <div className="pf-workflow-rail__actions">
                    <Button
                      variant="secondary"
                      onClick={() => reauditMutation.mutate()}
                      disabled={!workflow || reauditMutation.isPending || reauditRunning}
                    >
                      {reauditFailed ? t("workflow.reauditRetry") : t("workflow.reaudit")}
                    </Button>
                  </div>
                </>
              )}
            </div>
          )}
        </WorkflowStep>

        <WorkflowStep index={4} title={t("workflow.stepDrift")} state={stepDriftState}>
          {reauditCompleted && reauditRunId != null ? (
            <div className="pf-workflow-rail__summary">
              {closedFailQuery.data?.summary.closed_fail_percent != null ? (
                <p className="pf-workflow-rail__metric pf-workflow-rail__metric--closed">
                  {t("workflow.closedFailPercent", {
                    percent: closedFailQuery.data.summary.closed_fail_percent,
                  })}
                  <span className="pf-workflow-rail__note">
                    {t("workflow.closedFailDetail", {
                      closed: closedFailQuery.data.summary.closed_failed ?? 0,
                      baseline: closedFailQuery.data.summary.baseline_failed ?? 0,
                    })}
                  </span>
                </p>
              ) : null}
              <p className="pf-workflow-rail__text">{t("workflow.driftReady")}</p>
              <Link to={`/reports?run=${reauditRunId}`} className="pf-link">
                {t("workflow.viewReauditRun", { id: reauditRunId })}
              </Link>
            </div>
          ) : (
            <p className="pf-workflow-rail__hint">{t("workflow.driftHint")}</p>
          )}
        </WorkflowStep>
      </ol>
    </Panel>
  );
}
