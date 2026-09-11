import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { api, type RemediationSuggestion } from "../api/client";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Panel } from "./ui/Panel";
import { Spinner } from "./ui/Spinner";
import { useConfirm } from "./ui/ConfirmDialog";
import { useToast } from "./ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";

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
  onReauditComplete,
}: RemediationWorkflowPanelProps) {
  const { t } = useTranslation();
  const toast = useToast();
  const { confirm } = useConfirm();
  const queryClient = useQueryClient();
  const [workflowCtx, setWorkflowCtx] = useState(() => findWorkflowContext(runId));
  const [selectedScriptId, setSelectedScriptId] = useState<number | "">("");

  useEffect(() => {
    setWorkflowCtx(findWorkflowContext(runId));
  }, [runId]);

  const workflow = workflowCtx?.state ?? null;
  const storageRunId = workflowCtx?.storageRunId ?? runId;
  const isSourceRun = storageRunId === runId;
  const sourceRunId = workflow?.sourceRunId ?? storageRunId;

  const reauditRunId = workflow?.reauditRunId ?? null;
  const reauditCompleted = workflow?.reauditCompleted ?? false;

  const reauditRun = useQuery({
    queryKey: ["workflow-reaudit-run", reauditRunId],
    queryFn: () => api.getJobRun(reauditRunId!),
    enabled: reauditRunId != null && !reauditCompleted,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "running" || status === "pending" ? 5000 : false;
    },
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
  }, [suggestions.data, selectedScriptId]);

  const fromRunMutation = useMutation({
    mutationFn: (payload: {
      source_run_id: number;
      remediation_script_id?: number;
      run_remediation: boolean;
      set_baseline: boolean;
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
      void queryClient.invalidateQueries({ queryKey: ["remediations"] });
      void queryClient.invalidateQueries({ queryKey: ["remediation-runs"] });
      void queryClient.invalidateQueries({ queryKey: ["job-baseline", jobId] });
      toast.success(t("workflow.remediationStarted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const reauditMutation = useMutation({
    mutationFn: () => api.runJob(jobId),
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
      toast.success(t("workflow.reauditStarted", { id: newRun.id }));
      void queryClient.invalidateQueries({ queryKey: ["job-runs"] });
      void queryClient.invalidateQueries({ queryKey: ["workflow-reaudit-run", newRun.id] });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  if (!canOperate || runStatus !== "completed") return null;

  const hasCompletedCycle =
    workflow?.reauditCompleted === true && (isSourceRun || workflow.reauditRunId === runId);
  const data: RemediationSuggestion | undefined = suggestions.data;

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

  const handleConfirmRemediation = async () => {
    if (!data) return;
    const ok = await confirm({
      title: t("workflow.confirmTitle"),
      message: t("workflow.confirmMessage", {
        failed: data.failed_count,
        hosts: data.host_ids.length,
      }),
      confirmLabel: t("workflow.confirmRun"),
      variant: "default",
    });
    if (!ok) return;
    fromRunMutation.mutate({
      source_run_id: storageRunId,
      remediation_script_id: selectedScriptId === "" ? undefined : selectedScriptId,
      run_remediation: true,
      set_baseline: true,
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

              <div className="pf-workflow-rail__actions">
                <Button
                  variant="primary"
                  onClick={() => void handleConfirmRemediation()}
                  disabled={fromRunMutation.isPending || data.remediation_scripts.length === 0}
                >
                  {t("workflow.startRemediation")}
                </Button>
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
