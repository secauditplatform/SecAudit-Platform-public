import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Navigate, useSearchParams } from "react-router-dom";
import { api, type CheckScript, type RemediationJob } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { HostPicker } from "../components/HostPicker";
import {
  OperationsPageHeader,
  hostMatchesOperationsPlatform,
  jobMatchesOperationsPlatform,
  operationsScopeForPlatform,
  parseOperationsPlatform,
  profileMatchesOperationsPlatform,
  type OperationsPlatform,
  type OperationsScope,
} from "../components/OperationsTabs";
import { NetworkRemediationConfigPanel } from "../components/NetworkRemediationConfigPanel";
import { JobSchedulePicker, useScheduleLabels } from "../components/JobSchedulePicker";
import { RemediationRunLogs } from "../components/RemediationRunLogs";
import { ObjectOwnerCell } from "../components/ObjectOwnerCell";
import { ScriptCodeEditor } from "../components/ScriptCodeEditor";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { EmptyState } from "../components/ui/EmptyState";
import { QueryErrorState } from "../components/ui/QueryErrorState";
import { IconRemediation } from "../components/ui/Icons";
import { OpsListExpandFooter } from "../components/OpsListExpandFooter";
import { Panel } from "../components/ui/Panel";
import { Spinner } from "../components/ui/Spinner";
import { useConfirm } from "../components/ui/ConfirmDialog";
import { useToast } from "../components/ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";
import { sliceOpsList, OPS_LIST_MAX } from "../utils/opsListLimit";
import { RUN_STATUS_KEYS, runStatusLabel, runStatusVariant } from "../utils/statusVariant";
import {
  buildCronExpression,
  DEFAULT_SCHEDULE,
  formatScheduleLabel,
  parseCronExpression,
  type ScheduleConfig,
} from "../utils/jobSchedule";

function parseRemediationEditId(value: string | null): number | null {
  if (!value) return null;
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

export function RemediationPage({
  operationsScope: operationsScopeProp,
  platform: platformProp,
}: {
  operationsScope?: OperationsScope;
  platform?: OperationsPlatform;
} = {}) {
  const { t, dateLocale } = useTranslation();
  const { confirm } = useConfirm();
  const toast = useToast();
  const { isAdmin, canSeeObjectOwners, canOperate, canExecute, canAccessRemediation } = useAuth();
  const scheduleLabels = useScheduleLabels();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();

  const [name, setName] = useState("");
  const [profileId, setProfileId] = useState<number | "">("");
  const [remediationScriptId, setRemediationScriptId] = useState<number | "">("");
  const [jobType, setJobType] = useState<"ssh" | "winrm" | "python" | "ansible">("ssh");
  const [hostIds, setHostIds] = useState<number[]>([]);
  const [isScheduled, setIsScheduled] = useState(false);
  const [scheduleConfig, setScheduleConfig] = useState<ScheduleConfig>(DEFAULT_SCHEDULE);
  const [selectedJobId, setSelectedJobId] = useState<number | null>(null);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [, setLastRunId] = useState<number | null>(null);
  const [editorScriptId, setEditorScriptId] = useState<number | null>(null);
  const [editedContent, setEditedContent] = useState("");
  const [isDirty, setIsDirty] = useState(false);
  const [saveStatus, setSaveStatus] = useState<"success" | "error" | null>(null);
  const jobFormPanelRef = useRef<HTMLElement>(null);
  const selectedJobPanelRef = useRef<HTMLElement>(null);
  const pendingScrollToJobIdRef = useRef<number | null>(null);

  const urlEditJobId = parseRemediationEditId(searchParams.get("edit"));

  const operationsPlatform: OperationsPlatform =
    platformProp ??
    (operationsScopeProp === "network"
      ? "network"
      : parseOperationsPlatform(searchParams.get("platform"), "linux"));
  const operationsScope = operationsScopeProp ?? operationsScopeForPlatform(operationsPlatform);
  const isNetwork = operationsScope === "network";

  useEffect(() => {
    if (isNetwork) return;
    if (searchParams.get("platform") === operationsPlatform) return;
    const next = new URLSearchParams(searchParams);
    next.set("platform", operationsPlatform);
    setSearchParams(next, { replace: true });
  }, [isNetwork, operationsPlatform, searchParams, setSearchParams]);

  useEffect(() => {
    setHostIds([]);
    setProfileId("");
    setRemediationScriptId("");
    setSelectedJobId(null);
    if (operationsPlatform === "windows") setJobType("winrm");
    else if (operationsPlatform === "network") setJobType("python");
    else setJobType("ssh");
  }, [operationsPlatform]);

  useEffect(() => {
    if (operationsPlatform === "linux" && jobType !== "ssh" && jobType !== "ansible") {
      setJobType("ssh");
    } else if (operationsPlatform === "windows" && jobType !== "winrm" && jobType !== "ansible") {
      setJobType("winrm");
    } else if (operationsPlatform === "network" && jobType !== "python") {
      setJobType("python");
    }
  }, [operationsPlatform, jobType]);

  const jobs = useQuery({
    queryKey: ["remediations", operationsScope],
    queryFn: () => api.remediations(operationsScope),
  });
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api.profiles() });
  const hosts = useQuery({ queryKey: ["hosts", operationsScope], queryFn: () => api.hosts({ limit: 200 }) });
  const [jobSearch, setJobSearch] = useState("");
  const [jobProfileFilter, setJobProfileFilter] = useState("all");
  const [jobScheduleFilter, setJobScheduleFilter] = useState<"all" | "scheduled" | "manual">("all");
  const [jobsListExpanded, setJobsListExpanded] = useState(false);
  const [runSearch, setRunSearch] = useState("");
  const [runStatusFilter, setRunStatusFilter] = useState("all");
  const [runsListExpanded, setRunsListExpanded] = useState(false);

  const runs = useQuery({
    queryKey: ["remediation-runs", operationsScope, OPS_LIST_MAX],
    queryFn: () => api.remediationRuns({ offset: 0, limit: OPS_LIST_MAX }),
    refetchInterval: 10000,
  });

  useEffect(() => {
    setJobSearch("");
    setJobProfileFilter("all");
    setJobScheduleFilter("all");
    setJobsListExpanded(false);
    setRunSearch("");
    setRunStatusFilter("all");
    setRunsListExpanded(false);
  }, [operationsPlatform]);

  const jobList = useMemo(() => {
    const all = jobs.data ?? [];
    const profileCategoryById = new Map(
      (profiles.data ?? []).map((profile) => [profile.id, profile.category_name] as const)
    );
    const hostOsById = new Map(
      (hosts.data?.items ?? []).map((host) => [host.id, host.os_type] as const)
    );
    return all.filter((job) =>
      jobMatchesOperationsPlatform(job, operationsPlatform, { profileCategoryById, hostOsById })
    );
  }, [jobs.data, profiles.data, hosts.data, operationsPlatform]);

  const sortedJobs = useMemo(
    () => [...jobList].sort((a, b) => b.id - a.id),
    [jobList]
  );

  const filteredJobs = useMemo(() => {
    const query = jobSearch.trim().toLowerCase();
    return sortedJobs.filter((job) => {
      if (query) {
        const haystack = `${job.name} ${job.id}`.toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      if (jobProfileFilter !== "all" && String(job.profile_id) !== jobProfileFilter) return false;
      if (jobScheduleFilter === "scheduled" && !job.is_scheduled) return false;
      if (jobScheduleFilter === "manual" && job.is_scheduled) return false;
      return true;
    });
  }, [sortedJobs, jobSearch, jobProfileFilter, jobScheduleFilter]);

  const visibleJobs = useMemo(
    () => sliceOpsList(filteredJobs, jobsListExpanded),
    [filteredJobs, jobsListExpanded]
  );

  const hasActiveJobFilters =
    jobSearch.trim() !== "" || jobProfileFilter !== "all" || jobScheduleFilter !== "all";

  const jobNameById = useMemo(() => {
    const map = new Map<number, string>();
    jobList.forEach((job) => map.set(job.id, job.name));
    return map;
  }, [jobList]);

  const runList = useMemo(() => {
    const visibleJobIds = new Set(jobList.map((job) => job.id));
    return (runs.data?.items ?? [])
      .filter((run) => visibleJobIds.has(run.remediation_job_id))
      .sort(
        (a, b) =>
          new Date(b.finished_at ?? b.started_at ?? 0).getTime() -
          new Date(a.finished_at ?? a.started_at ?? 0).getTime()
      );
  }, [runs.data?.items, jobList]);

  const filteredRuns = useMemo(() => {
    const query = runSearch.trim().toLowerCase();
    return runList.filter((run) => {
      if (runStatusFilter !== "all" && run.status !== runStatusFilter) return false;
      if (!query) return true;
      const jobName = jobNameById.get(run.remediation_job_id) ?? "";
      const haystack = `${run.id} ${run.remediation_job_id} ${jobName}`.toLowerCase();
      return haystack.includes(query);
    });
  }, [runList, runSearch, runStatusFilter, jobNameById]);

  const visibleRuns = useMemo(
    () => sliceOpsList(filteredRuns, runsListExpanded),
    [filteredRuns, runsListExpanded]
  );

  const hasActiveRunFilters = runSearch.trim() !== "" || runStatusFilter !== "all";

  const availableProfiles = (profiles.data ?? []).filter((profile) =>
    profileMatchesOperationsPlatform(profile.category_name, operationsPlatform)
  );
  const availableHosts = (hosts.data?.items ?? []).filter((host) =>
    hostMatchesOperationsPlatform(host.os_type, operationsPlatform)
  );

  const activeProfileId = profileId !== "" ? profileId : null;
  const profileDetail = useQuery({
    queryKey: ["profile-detail", activeProfileId],
    queryFn: () => api.getProfile(activeProfileId!),
    enabled: activeProfileId != null,
  });

  const remediationScripts = useMemo(
    () => profileDetail.data?.remediation_scripts ?? [],
    [profileDetail.data]
  );

  const filteredRemediationScripts = useMemo(
    () =>
      remediationScripts.filter((script) =>
        script.execution_type === (isNetwork ? "python" : jobType)
      ),
    [remediationScripts, jobType, isNetwork]
  );

  const activeJobId = selectedJobId ?? jobList[0]?.id ?? null;
  const selectedJob = jobList.find((j) => j.id === activeJobId);

  useEffect(() => {
    const pendingId = pendingScrollToJobIdRef.current;
    if (pendingId == null || selectedJob?.id !== pendingId) return;
    pendingScrollToJobIdRef.current = null;
    requestAnimationFrame(() => {
      selectedJobPanelRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, [selectedJob?.id]);

  useEffect(() => {
    setLastRunId(null);
  }, [activeJobId]);

  const selectedRunId = useMemo(() => {
    if (!activeJobId) return null;
    const jobRuns = runs.data?.items?.filter((r) => r.remediation_job_id === activeJobId) ?? [];
    if (jobRuns.length === 0) return null;
    return jobRuns[0]?.id ?? null;
  }, [activeJobId, runs.data]);

  const editorScript = useMemo(() => {
    if (editorScriptId == null) return null;
    return remediationScripts.find((script) => script.id === editorScriptId) ?? null;
  }, [editorScriptId, remediationScripts]);

  const scriptContent = useQuery({
    queryKey: ["remediation-script-content", activeProfileId, editorScriptId],
    queryFn: () => api.getCheckScriptContent(activeProfileId!, editorScriptId!),
    enabled: activeProfileId != null && editorScriptId != null && isAdmin,
  });

  useEffect(() => {
    if (scriptContent.data) {
      setEditedContent(scriptContent.data.content);
      setIsDirty(false);
    }
  }, [scriptContent.data]);

  useEffect(() => {
    if (filteredRemediationScripts.length === 0) {
      setEditorScriptId(null);
      return;
    }
    if (editorScriptId == null || !filteredRemediationScripts.some((s) => s.id === editorScriptId)) {
      setEditorScriptId(filteredRemediationScripts[0]?.id ?? null);
    }
  }, [filteredRemediationScripts, editorScriptId]);

  const createMutation = useMutation({
    mutationFn: api.createRemediation,
    onSuccess: (job) => {
      queryClient.setQueryData<RemediationJob[]>(["remediations", operationsScope], (current) => {
        const list = current ?? [];
        if (list.some((item) => item.id === job.id)) return list;
        return [job, ...list];
      });
      void queryClient.invalidateQueries({ queryKey: ["remediations"] });
      setSelectedJobId(job.id);
      setEditingId(null);
      pendingScrollToJobIdRef.current = job.id;
      resetForm();
      toast.success(t("toast.remediationCreated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Parameters<typeof api.updateRemediation>[1] }) =>
      api.updateRemediation(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["remediations"] });
      setEditingId(null);
      resetForm();
      toast.success(t("toast.remediationUpdated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const saveScriptMutation = useMutation({
    mutationFn: () => {
      if (!isAdmin || activeProfileId == null || editorScriptId == null) {
        return Promise.reject(new Error("Forbidden"));
      }
      return api.updateCheckScriptContent(activeProfileId, editorScriptId, editedContent);
    },
    onSuccess: (data) => {
      queryClient.setQueryData(["remediation-script-content", activeProfileId, editorScriptId], data);
      setIsDirty(false);
      setSaveStatus("success");
    },
    onError: () => setSaveStatus("error"),
  });

  const runMutation = useMutation({
    mutationFn: api.runRemediation,
    onSuccess: (run) => {
      setLastRunId(run.id);
      setSelectedJobId(run.remediation_job_id);
      queryClient.invalidateQueries({ queryKey: ["remediation-runs"] });
      toast.success(t("toast.remediationRunStarted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const stopRunMutation = useMutation({
    mutationFn: api.stopRemediationRun,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["remediation-runs"] });
      toast.success(t("toast.remediationRunStopped"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteRunMutation = useMutation({
    mutationFn: api.deleteRemediationRun,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["remediation-runs"] });
      toast.success(t("toast.remediationRunDeleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteJobMutation = useMutation({
    mutationFn: api.deleteRemediation,
    onSuccess: (_data, jobId) => {
      queryClient.invalidateQueries({ queryKey: ["remediations"] });
      queryClient.invalidateQueries({ queryKey: ["remediation-runs"] });
      if (selectedJobId === jobId) setSelectedJobId(null);
      if (editingId === jobId) {
        setEditingId(null);
        resetForm();
      }
      toast.success(t("toast.remediationDeleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const resetForm = () => {
    setName("");
    setProfileId("");
    setRemediationScriptId("");
    setJobType("ssh");
    setHostIds([]);
    setIsScheduled(false);
    setScheduleConfig(DEFAULT_SCHEDULE);
  };

  const startEdit = (job: RemediationJob, options?: { updateUrl?: boolean; scroll?: boolean }) => {
    setEditingId(job.id);
    setSelectedJobId(job.id);
    setName(job.name);
    setProfileId(job.profile_id);
    setRemediationScriptId(job.remediation_script_id ?? "");
    setJobType(job.execution_type);
    setHostIds(job.host_ids);
    setIsScheduled(job.is_scheduled);
    setScheduleConfig(parseCronExpression(job.cron_expression));
    if (options?.updateUrl !== false) {
      const next = new URLSearchParams(searchParams);
      next.set("edit", String(job.id));
      if (!isNetwork) next.set("platform", operationsPlatform);
      setSearchParams(next, { replace: true });
    }
    if (options?.scroll !== false) {
      requestAnimationFrame(() => {
        jobFormPanelRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      });
    }
  };

  useEffect(() => {
    if (urlEditJobId == null || !jobs.data || editingId === urlEditJobId) return;
    const job = jobs.data.find((item) => item.id === urlEditJobId);
    if (!job) return;
    startEdit(job, { updateUrl: false, scroll: true });
  }, [urlEditJobId, jobs.data, editingId]);

  const cancelEdit = () => {
    setEditingId(null);
    resetForm();
    if (searchParams.has("edit")) {
      const next = new URLSearchParams(searchParams);
      next.delete("edit");
      setSearchParams(next, { replace: true });
    }
  };

  const isEditing = editingId !== null;
  const cronExpression = buildCronExpression(scheduleConfig);
  const hasTarget = hostIds.length > 0;
  const isFormValid = !!name && profileId !== "" && hasTarget;

  const buildPayload = () => ({
    name,
    profile_id: profileId as number,
    remediation_script_id: remediationScriptId !== "" ? remediationScriptId : undefined,
    // Network Platform remediations use Python (Netmiko) on the worker — not Ansible.
    execution_type: isNetwork ? ("python" as const) : jobType,
    scope: operationsScope,
    host_ids: hostIds,
    dynamic_filter: null,
    is_scheduled: isScheduled,
    cron_expression: isScheduled ? cronExpression : undefined,
  });

  const profileNameById = useMemo(() => {
    const map = new Map<number, string>();
    profiles.data?.forEach((s) => map.set(s.id, s.label));
    return map;
  }, [profiles.data]);

  const selectScriptInEditor = async (script: CheckScript) => {
    if (!isAdmin) return;
    if (isDirty) {
      const ok = await confirm({
        title: t("common.confirm"),
        message: t("remediation.discardScriptChanges"),
        variant: "warning",
      });
      if (!ok) return;
    }
    setEditorScriptId(script.id);
    setSaveStatus(null);
  };

  const handleRunJob = async (job: RemediationJob) => {
    const ok = await confirm({
      title: t("remediation.runConfirmTitle"),
      message: t("remediation.runConfirmMessage"),
      subtitle: job.name,
      variant: "warning",
      confirmLabel: t("remediation.runConfirmButton"),
      icon: <IconRemediation />,
    });
    if (ok) {
      setSelectedJobId(job.id);
      runMutation.mutate(job.id);
    }
  };

  const handleDeleteJob = async (job: RemediationJob) => {
    const ok = await confirm({
      title: t("common.delete"),
      message: t("remediation.deleteConfirm", { name: job.name }),
      variant: "danger",
      confirmLabel: t("common.delete"),
    });
    if (ok) deleteJobMutation.mutate(job.id);
  };

  if (!canAccessRemediation) {
    return <Navigate to="/jobs" replace />;
  }

  return (
    <>
      <OperationsPageHeader task="remediation" platform={operationsPlatform} />

      <Panel
        ref={jobFormPanelRef}
        title={isEditing ? t("remediation.editTitle", { name }) : t("remediation.createJob")}
      >
        <div className="pf-form pf-form--wide">
          <div className="pf-form__row">
            <div className="pf-form__group">
              <label htmlFor="remediation-name">{t("remediation.jobName")}</label>
              <input
                id="remediation-name"
                className="pf-input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder={t("remediation.namePlaceholder")}
              />
            </div>
            <div className="pf-form__group">
              <label>{t("remediation.jobType")}</label>
              <select
                className="pf-select"
                value={isNetwork ? "python" : jobType}
                disabled={isNetwork}
                onChange={(e) =>
                  setJobType(e.target.value as "ssh" | "winrm" | "python" | "ansible")
                }
              >
                {operationsPlatform === "linux" && (
                  <>
                    <option value="ssh">{t("jobs.typeSsh")}</option>
                    <option value="ansible">{t("jobs.typePlaybook")}</option>
                  </>
                )}
                {operationsPlatform === "windows" && (
                  <>
                    <option value="winrm">{t("jobs.typeWinrm")}</option>
                    <option value="ansible">{t("jobs.typePlaybook")}</option>
                  </>
                )}
                {isNetwork && <option value="python">{t("jobs.typePython")}</option>}
              </select>
            </div>
            <div className="pf-form__group">
              <label htmlFor="remediation-profile">{t("jobs.profile")}</label>
              <select
                id="remediation-profile"
                className="pf-select"
                value={profileId}
                onChange={(e) => {
                  setProfileId(e.target.value ? Number(e.target.value) : "");
                  setRemediationScriptId("");
                }}
              >
                <option value="">{t("jobs.selectProfile")}</option>
                {availableProfiles.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="pf-form__group">
              <label htmlFor="remediation-script">{t("remediation.script")}</label>
              <select
                id="remediation-script"
                className="pf-select"
                value={remediationScriptId}
                onChange={(e) =>
                  setRemediationScriptId(e.target.value ? Number(e.target.value) : "")
                }
                disabled={!activeProfileId || filteredRemediationScripts.length === 0}
              >
                <option value="">{t("remediation.allScripts")}</option>
                {filteredRemediationScripts.map((script) => (
                  <option key={script.id} value={script.id}>
                    {script.name}
                  </option>
                ))}
              </select>
            </div>
          </div>

          <HostPicker
            hosts={availableHosts}
            selectedIds={hostIds}
            onToggle={(id) =>
              setHostIds((prev) => (prev.includes(id) ? prev.filter((h) => h !== id) : [...prev, id]))
            }
            onSelectAll={(ids) => setHostIds(ids)}
            onClearAll={() => setHostIds([])}
          />

          <JobSchedulePicker
            enabled={isScheduled}
            onEnabledChange={setIsScheduled}
            config={scheduleConfig}
            onConfigChange={setScheduleConfig}
          />

          <div className="pf-form__actions">
            {isEditing ? (
              <>
                <Button
                  onClick={() => updateMutation.mutate({ id: editingId, data: buildPayload() })}
                  disabled={!isFormValid || updateMutation.isPending}
                >
                  {t("jobs.saveChanges")}
                </Button>
                <Button variant="secondary" onClick={cancelEdit}>
                  {t("common.cancel")}
                </Button>
              </>
            ) : (
              <Button
                onClick={() => createMutation.mutate(buildPayload())}
                disabled={!isFormValid || createMutation.isPending}
              >
                {t("remediation.createButton")}
              </Button>
            )}
          </div>
        </div>
      </Panel>

      {isAdmin && activeProfileId && (
        <Panel
          title={t("remediation.scriptEditor")}
          description={t("remediation.scriptEditorDesc")}
        >
          {profileDetail.isLoading ? (
            <Spinner />
          ) : filteredRemediationScripts.length === 0 ? (
            <EmptyState
              title={t("remediation.noScripts")}
              description={t("remediation.noScriptsDesc")}
            />
          ) : (
            <div className="pf-remediation-editor">
              <div className="pf-remediation-editor__toolbar">
                <select
                  className="pf-select"
                  value={editorScriptId ?? ""}
                  onChange={(e) => {
                    const script = filteredRemediationScripts.find(
                      (item) => item.id === Number(e.target.value)
                    );
                    if (script) selectScriptInEditor(script);
                  }}
                >
                  {filteredRemediationScripts.map((script) => (
                    <option key={script.id} value={script.id}>
                      {script.name} ({script.script_file})
                    </option>
                  ))}
                </select>
                <Button
                  onClick={() => saveScriptMutation.mutate()}
                  loading={saveScriptMutation.isPending}
                  disabled={!isDirty || !editorScript}
                >
                  {saveScriptMutation.isPending ? t("common.saving") : t("common.save")}
                </Button>
                {saveStatus === "success" && (
                  <span className="pf-form__hint pf-form__hint--success">{t("remediation.scriptSaved")}</span>
                )}
                {saveStatus === "error" && (
                  <span className="pf-form__hint pf-form__hint--error">{t("remediation.scriptSaveError")}</span>
                )}
              </div>
              {scriptContent.isLoading ? (
                <Spinner />
              ) : scriptContent.isError ? (
                <p className="pf-form__hint pf-form__hint--error">
                  {scriptContent.error instanceof Error
                    ? scriptContent.error.message || t("profiles.fileNotFound")
                    : t("profiles.fileNotFound")}
                </p>
              ) : editorScript ? (
                <ScriptCodeEditor
                  value={editedContent}
                  onChange={(value) => {
                    setEditedContent(value);
                    setIsDirty(true);
                    setSaveStatus(null);
                  }}
                  executionType={editorScript.execution_type}
                  readOnly={false}
                />
              ) : null}
            </div>
          )}
        </Panel>
      )}

      {selectedJob && (
        <Panel
          ref={selectedJobPanelRef}
          title={t("jobs.selectedJob", { name: selectedJob.name })}
          toolbar={
            <div className="pf-panel-toolbar-actions">
              <Button variant="secondary" className="pf-btn--sm" onClick={() => startEdit(selectedJob)}>
                {t("common.edit")}
              </Button>
              <Button
                variant="danger-secondary"
                className="pf-btn--sm"
                onClick={() => void handleDeleteJob(selectedJob)}
                disabled={deleteJobMutation.isPending}
              >
                {t("common.delete")}
              </Button>
              <Button
                variant="secondary"
                className="pf-btn--sm pf-selected-job__run"
                onClick={() => void handleRunJob(selectedJob)}
                disabled={!canExecute || runMutation.isPending}
                title={!canExecute ? t("common.demoActionDisabled") : undefined}
              >
                <IconRemediation />
                {t("remediation.runJob")}
              </Button>
            </div>
          }
        >
          <div className="pf-selected-job">
            <div className="pf-selected-job__meta">
              <Badge variant="neutral">ID {selectedJob.id}</Badge>
              <Badge variant="info">
                {profileNameById.get(selectedJob.profile_id) ??
                  t("jobs.profileRef", { id: selectedJob.profile_id })}
              </Badge>
              <Badge variant={selectedJob.is_scheduled ? "warning" : "neutral"}>
                {selectedJob.is_scheduled
                  ? formatScheduleLabel(selectedJob.cron_expression, scheduleLabels)
                  : t("jobs.manualRun")}
              </Badge>
              <Badge variant="neutral">
                {selectedJob.host_ids.length > 0
                  ? t("remediation.hostsCount", { count: selectedJob.host_ids.length })
                  : t("common.all")}
              </Badge>
            </div>
            <p className="pf-selected-job__hint">{t("remediation.selectedJobHint")}</p>
          </div>
        </Panel>
      )}

      <Panel title={t("remediation.jobList")} noPadding>
        <div className="pf-filters">
          <div className="pf-filters__grid pf-filters__grid--ops-jobs">
            <div className="pf-filters__group">
              <label htmlFor="remediation-jobs-filter-search">{t("jobs.jobListSearchLabel")}</label>
              <input
                id="remediation-jobs-filter-search"
                className="pf-input"
                value={jobSearch}
                onChange={(e) => {
                  setJobSearch(e.target.value);
                  setJobsListExpanded(false);
                }}
                placeholder={t("jobs.jobListSearch")}
              />
            </div>
            <div className="pf-filters__group">
              <label htmlFor="remediation-jobs-filter-profile">{t("jobs.profile")}</label>
              <select
                id="remediation-jobs-filter-profile"
                className="pf-select"
                value={jobProfileFilter}
                onChange={(e) => {
                  setJobProfileFilter(e.target.value);
                  setJobsListExpanded(false);
                }}
              >
                <option value="all">{t("reports.allProfiles")}</option>
                {availableProfiles.map((profile) => (
                  <option key={profile.id} value={String(profile.id)}>
                    {profile.profile_name}
                  </option>
                ))}
              </select>
            </div>
            <div className="pf-filters__group">
              <label htmlFor="remediation-jobs-filter-schedule">{t("jobs.jobListScheduleFilter")}</label>
              <select
                id="remediation-jobs-filter-schedule"
                className="pf-select"
                value={jobScheduleFilter}
                onChange={(e) => {
                  setJobScheduleFilter(e.target.value as "all" | "scheduled" | "manual");
                  setJobsListExpanded(false);
                }}
              >
                <option value="all">{t("jobs.jobListScheduleAll")}</option>
                <option value="scheduled">{t("jobs.jobListScheduleScheduled")}</option>
                <option value="manual">{t("jobs.jobListScheduleManual")}</option>
              </select>
            </div>
          </div>
          <div className="pf-filters__footer">
            <p className="pf-filters__summary">
              {hasActiveJobFilters
                ? t("profiles.filterResultsActive", {
                    count: filteredJobs.length,
                    total: jobList.length,
                  })
                : t("profiles.filterShown", {
                    count: filteredJobs.length,
                    total: jobList.length,
                  })}
            </p>
            {hasActiveJobFilters ? (
              <Button
                variant="secondary"
                className="pf-btn--sm"
                type="button"
                onClick={() => {
                  setJobSearch("");
                  setJobProfileFilter("all");
                  setJobScheduleFilter("all");
                  setJobsListExpanded(false);
                }}
              >
                {t("profiles.clearFilters")}
              </Button>
            ) : null}
          </div>
        </div>
        {jobs.isLoading ? (
          <Spinner />
        ) : jobs.isError ? (
          <QueryErrorState
            title={t("common.listLoadError")}
            message={jobs.error instanceof Error ? jobs.error.message : undefined}
            onRetry={() => jobs.refetch()}
          />
        ) : jobList.length === 0 ? (
          <EmptyState title={t("remediation.noJobs")} description={t("remediation.noJobsDesc")} />
        ) : filteredJobs.length === 0 ? (
          <EmptyState title={t("jobs.noFilterResults")} description={t("jobs.noFilterResultsDesc")} />
        ) : (
          <div className="pf-table-wrap">
            <table className="pf-table pf-ops-table">
              <thead>
                <tr>
                  <th>{t("common.id")}</th>
                  <th>{t("common.name")}</th>
                  <th>{t("jobs.profile")}</th>
                  <th>{t("remediation.script")}</th>
                  <th>{t("jobs.schedule")}</th>
                  {canSeeObjectOwners ? <th>{t("objectRbac.owner")}</th> : null}
                  <th className="pf-ops-table__actions" scope="col">
                    {t("common.actions")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {visibleJobs.map((job) => (
                  <tr
                    key={job.id}
                    className={`pf-table__row--clickable${job.id === activeJobId ? " pf-table__row--selected" : ""}`}
                    onClick={() => setSelectedJobId(job.id)}
                  >
                    <td className="pf-table__mono">{job.id}</td>
                    <td>{job.name}</td>
                    <td>{profileNameById.get(job.profile_id) ?? job.profile_id}</td>
                    <td className="pf-table__mono">
                      {job.remediation_script_id ? `#${job.remediation_script_id}` : t("remediation.allScripts")}
                    </td>
                    <td>
                      {job.is_scheduled
                        ? formatScheduleLabel(job.cron_expression, scheduleLabels)
                        : t("jobs.manualRun")}
                    </td>
                    {canSeeObjectOwners ? (
                      <td>
                        <ObjectOwnerCell ownerSub={job.owner_sub} />
                      </td>
                    ) : null}
                    <td className="pf-ops-table__actions" onClick={(e) => e.stopPropagation()}>
                      <div className="pf-ops-row-actions">
                        <Button variant="secondary" className="pf-btn--sm" onClick={() => startEdit(job)}>
                          {t("common.edit")}
                        </Button>
                        <Button
                          variant="secondary"
                          className="pf-btn--sm"
                          onClick={() => void handleRunJob(job)}
                          disabled={!canExecute || runMutation.isPending}
                          title={!canExecute ? t("common.demoActionDisabled") : undefined}
                        >
                          {t("common.run")}
                        </Button>
                        <Button
                          variant="danger-secondary"
                          className="pf-btn--sm"
                          onClick={() => void handleDeleteJob(job)}
                          disabled={deleteJobMutation.isPending}
                        >
                          {t("common.delete")}
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <OpsListExpandFooter
              shown={visibleJobs.length}
              total={filteredJobs.length}
              expanded={jobsListExpanded}
              onToggle={() => setJobsListExpanded((value) => !value)}
            />
          </div>
        )}
      </Panel>

      <Panel title={t("remediation.recentRuns")} noPadding>
        <div className="pf-filters">
          <div className="pf-filters__grid pf-filters__grid--ops-runs">
            <div className="pf-filters__group">
              <label htmlFor="remediation-runs-filter-search">{t("jobs.runListSearchLabel")}</label>
              <input
                id="remediation-runs-filter-search"
                className="pf-input"
                value={runSearch}
                onChange={(e) => {
                  setRunSearch(e.target.value);
                  setRunsListExpanded(false);
                }}
                placeholder={t("jobs.runListSearch")}
              />
            </div>
            <div className="pf-filters__group">
              <label htmlFor="remediation-runs-filter-status">{t("jobs.runListStatusFilter")}</label>
              <select
                id="remediation-runs-filter-status"
                className="pf-select"
                value={runStatusFilter}
                onChange={(e) => {
                  setRunStatusFilter(e.target.value);
                  setRunsListExpanded(false);
                }}
              >
                <option value="all">{t("reports.allStatuses")}</option>
                {RUN_STATUS_KEYS.map((status) => (
                  <option key={status} value={status}>
                    {runStatusLabel(t, status)}
                  </option>
                ))}
              </select>
            </div>
          </div>
          <div className="pf-filters__footer">
            <p className="pf-filters__summary">
              {hasActiveRunFilters
                ? t("profiles.filterResultsActive", {
                    count: filteredRuns.length,
                    total: runList.length,
                  })
                : t("profiles.filterShown", {
                    count: filteredRuns.length,
                    total: runList.length,
                  })}
            </p>
            {hasActiveRunFilters ? (
              <Button
                variant="secondary"
                className="pf-btn--sm"
                type="button"
                onClick={() => {
                  setRunSearch("");
                  setRunStatusFilter("all");
                  setRunsListExpanded(false);
                }}
              >
                {t("profiles.clearFilters")}
              </Button>
            ) : null}
          </div>
        </div>
        {runs.isLoading ? (
          <Spinner />
        ) : runs.isError ? (
          <QueryErrorState
            title={t("common.listLoadError")}
            message={runs.error instanceof Error ? runs.error.message : undefined}
            onRetry={() => runs.refetch()}
          />
        ) : runList.length === 0 ? (
          <EmptyState title={t("remediation.noRuns")} description={t("remediation.noRunsDesc")} />
        ) : filteredRuns.length === 0 ? (
          <EmptyState title={t("jobs.noFilterResults")} description={t("jobs.noFilterResultsDesc")} />
        ) : (
          <div className="pf-table-wrap">
            <table className="pf-table">
              <thead>
                <tr>
                  <th>{t("jobs.runId")}</th>
                  <th>{t("jobs.jobId")}</th>
                  <th>{t("common.status")}</th>
                  <th>{t("jobs.started")}</th>
                  <th>{t("jobs.finished")}</th>
                  <th className="pf-table__col-actions">{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {visibleRuns.map((run) => (
                  <tr key={run.id}>
                    <td className="pf-table__mono">{run.id}</td>
                    <td className="pf-table__mono">{run.remediation_job_id}</td>
                    <td>
                      <Badge variant={runStatusVariant(run.status)}>{runStatusLabel(t, run.status)}</Badge>
                    </td>
                    <td>
                      {run.started_at ? new Date(run.started_at).toLocaleString(dateLocale) : t("common.dash")}
                    </td>
                    <td>
                      {run.finished_at ? new Date(run.finished_at).toLocaleString(dateLocale) : t("common.dash")}
                    </td>
                    <td className="pf-ops-table__actions">
                      <div className="pf-ops-row-actions">
                        {(run.status === "pending" || run.status === "running") && (
                          <Button
                            variant="secondary"
                            className="pf-btn--sm"
                            onClick={async () => {
                              const ok = await confirm({
                                title: t("common.stop"),
                                message: t("remediation.stopConfirm", { id: run.id }),
                                variant: "warning",
                              });
                              if (ok) stopRunMutation.mutate(run.id);
                            }}
                          >
                            {t("common.stop")}
                          </Button>
                        )}
                        {run.status !== "pending" && run.status !== "running" && (
                          <Button
                            variant="danger-secondary"
                            className="pf-btn--sm"
                            onClick={() => deleteRunMutation.mutate(run.id)}
                          >
                            {t("common.delete")}
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <OpsListExpandFooter
              shown={visibleRuns.length}
              total={filteredRuns.length}
              expanded={runsListExpanded}
              onToggle={() => setRunsListExpanded((value) => !value)}
            />
          </div>
        )}
      </Panel>

      <RemediationRunLogs key={selectedRunId ?? "none"} runId={selectedRunId} />
      {isNetwork && selectedRunId ? <NetworkRemediationConfigPanel runId={selectedRunId} /> : null}
    </>
  );
}
