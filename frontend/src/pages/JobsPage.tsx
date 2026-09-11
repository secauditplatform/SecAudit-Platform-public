import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type Job, type JobRun, type JobTemplate } from "../api/client";
import { JobRunLogs } from "../components/JobRunLogs";
import { JobTemplatesPanel } from "../components/JobTemplatesPanel";
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
import { NetworkConfigUploadPanel } from "../components/NetworkConfigUploadPanel";
import { ObjectOwnerCell } from "../components/ObjectOwnerCell";
import { JobSchedulePicker, useScheduleLabels } from "../components/JobSchedulePicker";
import { HostPicker } from "../components/HostPicker";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { IconRefresh } from "../components/ui/Icons";
import { EmptyState } from "../components/ui/EmptyState";
import { QueryErrorState } from "../components/ui/QueryErrorState";
import { CollapsibleFormField } from "../components/ui/CollapsibleFormField";
import { OpsListExpandFooter } from "../components/OpsListExpandFooter";
import { Panel } from "../components/ui/Panel";
import { SortableTh } from "../components/ui/SortableTh";
import { Spinner } from "../components/ui/Spinner";
import { useConfirm } from "../components/ui/ConfirmDialog";
import { useToast } from "../components/ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";
import { useAuth } from "../auth/AuthProvider";
import { useTableSort } from "../hooks/useTableSort";
import { sliceOpsList, OPS_LIST_MAX } from "../utils/opsListLimit";
import { RUN_STATUS_KEYS, runStatusLabel, runStatusVariant } from "../utils/statusVariant";
import {
  buildCronExpression,
  DEFAULT_SCHEDULE,
  formatScheduleLabel,
  parseCronExpression,
  type ScheduleConfig,
} from "../utils/jobSchedule";

function canViewRunReport(status: string): boolean {
  return status !== "pending" && status !== "running";
}

function parseJobEditId(value: string | null): number | null {
  if (!value) return null;
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function populateFormFromJob(
  job: Job,
  setters: {
    setEditingId: (id: number) => void;
    setSelectedJobId: (id: number) => void;
    setName: (name: string) => void;
    setJobType: (type: "ssh" | "winrm" | "python" | "playbook" | "ansible") => void;
    setProfileId: (id: number | "") => void;
    setPlaybookId: (id: number | "") => void;
    setHostIds: (ids: number[]) => void;
    setIsScheduled: (scheduled: boolean) => void;
    setScheduleConfig: (config: ScheduleConfig) => void;
    setNetworkCheckMode?: (mode: "remote" | "config_upload" | "both") => void;
  }
) {
  setters.setEditingId(job.id);
  setters.setSelectedJobId(job.id);
  setters.setName(job.name);
  if (job.playbook_id) {
    setters.setJobType("playbook");
    setters.setPlaybookId(job.playbook_id);
    setters.setProfileId("");
  } else {
    const exec = job.execution_type;
    setters.setJobType(
      exec === "ansible"
        ? "ansible"
        : exec === "winrm"
          ? "winrm"
          : exec === "python"
            ? "python"
            : "ssh"
    );
    setters.setProfileId(job.profile_id ?? "");
    setters.setPlaybookId("");
  }
  setters.setHostIds(job.host_ids);
  setters.setIsScheduled(job.is_scheduled);
  setters.setScheduleConfig(parseCronExpression(job.cron_expression));
  if (setters.setNetworkCheckMode && job.network_check_mode) {
    setters.setNetworkCheckMode(job.network_check_mode);
  }
}

export function JobsPage({
  operationsScope: operationsScopeProp,
  platform: platformProp,
}: {
  operationsScope?: OperationsScope;
  platform?: OperationsPlatform;
} = {}) {
  const { t, dateLocale } = useTranslation();
  const { canOperate, canExecute, canSeeObjectOwners } = useAuth();
  const { confirm } = useConfirm();
  const toast = useToast();
  const navigate = useNavigate();
  const [searchParams, setSearchParams] = useSearchParams();
  const jobFormPanelRef = useRef<HTMLElement>(null);
  const selectedJobPanelRef = useRef<HTMLElement>(null);
  const pendingScrollToJobIdRef = useRef<number | null>(null);
  const scheduleLabels = useScheduleLabels();
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [jobType, setJobType] = useState<"ssh" | "winrm" | "python" | "playbook" | "ansible">("ssh");
  const [profileId, setProfileId] = useState<number | "">("");
  const [playbookId, setPlaybookId] = useState<number | "">("");
  const [hostIds, setHostIds] = useState<number[]>([]);
  const [isScheduled, setIsScheduled] = useState(false);
  const [scheduleConfig, setScheduleConfig] = useState<ScheduleConfig>(DEFAULT_SCHEDULE);
  const [lastRunId, setLastRunId] = useState<number | null>(null);
  const [selectedJobId, setSelectedJobId] = useState<number | null>(null);
  const [editingId, setEditingId] = useState<number | null>(null);

  const [networkCheckMode, setNetworkCheckMode] = useState<"remote" | "config_upload" | "both">("both");

  const urlEditJobId = parseJobEditId(searchParams.get("edit"));
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
    setPlaybookId("");
    setSelectedJobId(null);
    if (operationsPlatform === "windows") setJobType("winrm");
    else if (operationsPlatform === "network") setJobType("python");
    else setJobType("ssh");
  }, [operationsPlatform]);

  useEffect(() => {
    if (operationsPlatform === "linux" && jobType !== "ssh" && jobType !== "playbook") {
      setJobType("ssh");
    } else if (operationsPlatform === "windows" && jobType !== "winrm" && jobType !== "playbook") {
      setJobType("winrm");
    } else if (operationsPlatform === "network" && jobType !== "python") {
      setJobType("python");
    }
  }, [operationsPlatform, jobType]);

  const jobs = useQuery({ queryKey: ["jobs", operationsScope], queryFn: () => api.jobs(operationsScope) });
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api.profiles() });
  const playbooks = useQuery({
    queryKey: ["playbooks", operationsScope, operationsPlatform],
    queryFn: () => api.playbooks(operationsScope, operationsPlatform === "network" ? undefined : operationsPlatform),
    enabled: !isNetwork,
  });
  const hosts = useQuery({
    queryKey: ["hosts", operationsScope],
    queryFn: () =>
      api.hosts({
        limit: 200,
      }),
  });
  const [jobSearch, setJobSearch] = useState("");
  const [jobProfileFilter, setJobProfileFilter] = useState("all");
  const [jobScheduleFilter, setJobScheduleFilter] = useState<"all" | "scheduled" | "manual">("all");
  const [jobsListExpanded, setJobsListExpanded] = useState(false);
  const [runSearch, setRunSearch] = useState("");
  const [runStatusFilter, setRunStatusFilter] = useState("all");
  const [runsListExpanded, setRunsListExpanded] = useState(false);

  const runs = useQuery({
    queryKey: ["job-runs", operationsScope, OPS_LIST_MAX],
    queryFn: () => api.jobRuns({ offset: 0, limit: OPS_LIST_MAX }),
    refetchInterval: (query) => {
      const items = query.state.data?.items ?? [];
      const hasActive = items.some((run) => run.status === "pending" || run.status === "running");
      return hasActive ? 3000 : 10000;
    },
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
  const jobById = useMemo(() => new Map(jobList.map((job) => [job.id, job])), [jobList]);
  type JobSortKey = "id" | "name" | "profile_id" | "is_scheduled";
  const jobAccessor = useCallback((job: Job, key: JobSortKey) => {
    if (key === "profile_id") return job.profile_id ?? job.playbook_id ?? 0;
    if (key === "is_scheduled") return job.is_scheduled;
    return job[key];
  }, []);
  const { sortedRows: sortedJobs, sort: jobSort, toggleSort: toggleJobSort } = useTableSort<
    Job,
    JobSortKey
  >(jobList, { key: "id", direction: "desc" }, jobAccessor);

  const filteredJobs = useMemo(() => {
    const query = jobSearch.trim().toLowerCase();
    return sortedJobs.filter((job) => {
      if (query) {
        const haystack = `${job.name} ${job.id}`.toLowerCase();
        if (!haystack.includes(query)) return false;
      }
      if (jobProfileFilter !== "all") {
        if (jobProfileFilter.startsWith("profile:")) {
          const profileId = Number(jobProfileFilter.slice("profile:".length));
          if (job.profile_id !== profileId) return false;
        } else if (jobProfileFilter.startsWith("playbook:")) {
          const playbookId = Number(jobProfileFilter.slice("playbook:".length));
          if (job.playbook_id !== playbookId) return false;
        }
      }
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

  const runList = useMemo(() => {
    const items = runs.data?.items ?? [];
    const visibleJobIds = new Set(jobList.map((job) => job.id));
    return items.filter((run) => visibleJobIds.has(run.job_id));
  }, [runs.data?.items, jobList]);
  type RunSortKey = "id" | "job_id" | "job_name" | "profile_id" | "status" | "finished_at";
  const runAccessor = useCallback(
    (run: JobRun, key: RunSortKey) => {
      if (key === "job_name") return jobById.get(run.job_id)?.name ?? "";
      if (key === "profile_id") {
        const job = jobById.get(run.job_id);
        return job?.profile_id ?? job?.playbook_id ?? 0;
      }
      return run[key];
    },
    [jobById]
  );
  const { sortedRows: sortedRuns, sort: runSort, toggleSort: toggleRunSort } = useTableSort<
    JobRun,
    RunSortKey
  >(runList, { key: "finished_at", direction: "desc" }, runAccessor);

  const filteredRuns = useMemo(() => {
    const query = runSearch.trim().toLowerCase();
    return sortedRuns.filter((run) => {
      if (runStatusFilter !== "all" && run.status !== runStatusFilter) return false;
      if (!query) return true;
      const jobName = jobById.get(run.job_id)?.name ?? "";
      const haystack = `${run.id} ${run.job_id} ${jobName}`.toLowerCase();
      return haystack.includes(query);
    });
  }, [sortedRuns, runSearch, runStatusFilter, jobById]);

  const visibleRuns = useMemo(
    () => sliceOpsList(filteredRuns, runsListExpanded),
    [filteredRuns, runsListExpanded]
  );

  const hasActiveRunFilters = runSearch.trim() !== "" || runStatusFilter !== "all";

  const availableHosts = (hosts.data?.items ?? []).filter((host) =>
    hostMatchesOperationsPlatform(host.os_type, operationsPlatform)
  );
  const availableProfiles = (profiles.data ?? []).filter((profile) =>
    profileMatchesOperationsPlatform(profile.category_name, operationsPlatform)
  );

  const activeJobId = selectedJobId ?? jobList[0]?.id ?? null;
  const selectedJob = jobList.find((j) => j.id === activeJobId);

  useEffect(() => {
    setLastRunId(null);
  }, [activeJobId]);

  const selectedJobRunId = useMemo(() => {
    if (!activeJobId) return null;
    const jobRuns = runs.data?.items?.filter((r) => r.job_id === activeJobId) ?? [];
    if (jobRuns.length === 0) return null;
    const activeRun = jobRuns.find((run) => run.status === "running" || run.status === "pending");
    if (activeRun) return activeRun.id;
    return jobRuns.reduce((latest, run) => (run.id > latest.id ? run : latest), jobRuns[0]).id;
  }, [activeJobId, runs.data]);

  const liveRunId = lastRunId ?? selectedJobRunId;
  const liveRunStatus = useMemo(() => {
    if (!liveRunId) return null;
    return runs.data?.items?.find((run) => run.id === liveRunId)?.status ?? null;
  }, [liveRunId, runs.data?.items]);

  const createMutation = useMutation({
    mutationFn: api.createJob,
    onSuccess: (job) => {
      if (isNetwork) {
        queryClient.setQueryData<Job[]>(["jobs", operationsScope], (current) => {
          const list = current ?? [];
          if (list.some((item) => item.id === job.id)) return list;
          return [job, ...list];
        });
        void queryClient.invalidateQueries({ queryKey: ["jobs"] });
        populateFormFromJob(job, formSetters);
        scrollToJobForm();
      } else {
        focusCreatedJob(job);
        resetForm();
      }
      toast.success(t("toast.jobCreated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Parameters<typeof api.updateJob>[1] }) =>
      api.updateJob(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
      setEditingId(null);
      resetForm();
      if (searchParams.has("edit")) {
        const next = new URLSearchParams(searchParams);
        next.delete("edit");
        setSearchParams(next, { replace: true });
      }
      toast.success(t("toast.jobUpdated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const runMutation = useMutation({
    mutationFn: api.runJob,
    onSuccess: (run) => {
      setLastRunId(run.id);
      setSelectedJobId(run.job_id);
      queryClient.invalidateQueries({ queryKey: ["job-runs"] });
      toast.success(t("toast.jobRunStarted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const restartRunMutation = useMutation({
    mutationFn: (run: JobRun) => {
      if (!run.job_id || !jobById.get(run.job_id)) {
        return Promise.reject(new Error(t("jobs.restartMissingJob")));
      }
      return api.runJob(run.job_id);
    },
    onSuccess: (run) => {
      setLastRunId(run.id);
      setSelectedJobId(run.job_id);
      queryClient.invalidateQueries({ queryKey: ["job-runs"] });
      toast.success(t("toast.jobRunStarted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const stopRunMutation = useMutation({
    mutationFn: api.stopJobRun,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["job-runs"] });
      toast.success(t("toast.jobRunStopped"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteRunMutation = useMutation({
    mutationFn: api.deleteJobRun,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["job-runs"] });
      toast.success(t("toast.jobRunDeleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteJobMutation = useMutation({
    mutationFn: api.deleteJob,
    onSuccess: (_data, jobId) => {
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
      if (selectedJobId === jobId) setSelectedJobId(null);
      toast.success(t("toast.jobDeleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const saveTemplateMutation = useMutation({
    mutationFn: api.createJobTemplate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["job-templates"] });
      toast.success(t("toast.jobTemplateCreated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const toggleHost = (id: number) => {
    setHostIds((prev) => (prev.includes(id) ? prev.filter((h) => h !== id) : [...prev, id]));
  };

  const resetForm = () => {
    setName("");
    setJobType("ssh");
    setProfileId("");
    setPlaybookId("");
    setHostIds([]);
    setIsScheduled(false);
    setScheduleConfig(DEFAULT_SCHEDULE);
  };

  const formSetters = {
    setEditingId,
    setSelectedJobId,
    setName,
    setJobType,
    setProfileId,
    setPlaybookId,
    setHostIds,
    setIsScheduled,
    setScheduleConfig,
    setNetworkCheckMode,
  };

  const scrollToJobForm = () => {
    requestAnimationFrame(() => {
      jobFormPanelRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };

  const focusCreatedJob = (job: Job) => {
    queryClient.setQueryData<Job[]>(["jobs", operationsScope], (current) => {
      const list = current ?? [];
      if (list.some((item) => item.id === job.id)) return list;
      return [job, ...list];
    });
    void queryClient.invalidateQueries({ queryKey: ["jobs"] });
    setSelectedJobId(job.id);
    setEditingId(null);
    pendingScrollToJobIdRef.current = job.id;
    if (searchParams.has("edit")) {
      const next = new URLSearchParams(searchParams);
      next.delete("edit");
      setSearchParams(next, { replace: true });
    }
  };

  useEffect(() => {
    const pendingId = pendingScrollToJobIdRef.current;
    if (pendingId == null || selectedJob?.id !== pendingId) return;
    pendingScrollToJobIdRef.current = null;
    requestAnimationFrame(() => {
      selectedJobPanelRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, [selectedJob?.id]);

  const startEdit = (job: Job, options?: { updateUrl?: boolean; scroll?: boolean }) => {
    populateFormFromJob(job, formSetters);
    if (options?.updateUrl !== false) {
      const next = new URLSearchParams(searchParams);
      next.set("edit", String(job.id));
      if (!isNetwork) next.set("platform", operationsPlatform);
      setSearchParams(next, { replace: true });
    }
    if (options?.scroll !== false) {
      scrollToJobForm();
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

  const buildCreatePayload = () => {
    const executionType =
      jobType === "ssh"
        ? ("ssh" as const)
        : jobType === "winrm"
          ? ("winrm" as const)
          : jobType === "python"
            ? ("python" as const)
            : undefined;
    return {
      name,
      host_ids: hostIds,
      dynamic_filter: null,
      is_scheduled: isScheduled,
      cron_expression: isScheduled ? cronExpression : undefined,
      profile_id: jobType !== "playbook" && profileId !== "" ? profileId : undefined,
      playbook_id: !isNetwork && jobType === "playbook" && playbookId !== "" ? playbookId : undefined,
      // Network Platform packages run Python (Netmiko) on the worker — not Ansible.
      execution_type: isNetwork ? ("python" as const) : executionType,
      scope: operationsScope,
      network_check_mode: isNetwork ? networkCheckMode : undefined,
    };
  };

  const buildUpdatePayload = (): Parameters<typeof api.updateJob>[1] => {
    if (isNetwork) {
      return {
        name,
        host_ids: hostIds,
        dynamic_filter: null,
        is_scheduled: isScheduled,
        cron_expression: isScheduled ? cronExpression : null,
        profile_id: profileId !== "" ? profileId : null,
        playbook_id: null,
        execution_type: "python",
        network_check_mode: networkCheckMode,
      };
    }
    if (jobType === "playbook") {
      return {
        name,
        host_ids: hostIds,
        dynamic_filter: null,
        is_scheduled: isScheduled,
        cron_expression: isScheduled ? cronExpression : null,
        playbook_id: playbookId !== "" ? playbookId : null,
        profile_id: null,
        execution_type: null,
      };
    }
    const executionType =
      jobType === "ssh"
        ? ("ssh" as const)
        : jobType === "winrm"
          ? ("winrm" as const)
          : ("python" as const);
    return {
      name,
      host_ids: hostIds,
      dynamic_filter: null,
      is_scheduled: isScheduled,
      cron_expression: isScheduled ? cronExpression : null,
      profile_id: profileId !== "" ? profileId : null,
      playbook_id: null,
      execution_type: executionType,
    };
  };

  const hasTarget = hostIds.length > 0;
  const isFormValid =
    !!name &&
    (isNetwork ? profileId !== "" : jobType !== "playbook" ? profileId !== "" : playbookId !== "") &&
    hasTarget;

  const selectAllHosts = (ids: number[]) => setHostIds(ids);
  const clearHosts = () => setHostIds([]);

  const applyTemplateToForm = (template: JobTemplate) => {
    setEditingId(null);
    setName(template.name);
    if (template.playbook_id) {
      setJobType("playbook");
      setPlaybookId(template.playbook_id);
      setProfileId("");
    } else {
      const exec = template.execution_type;
      setJobType(exec === "winrm" ? "winrm" : exec === "python" ? "python" : "ssh");
      setProfileId(template.profile_id ?? "");
      setPlaybookId("");
    }
    setHostIds(template.host_ids);
    setIsScheduled(template.is_scheduled);
    setScheduleConfig(parseCronExpression(template.cron_expression));
    toast.success(t("jobTemplates.loadedIntoForm"));
  };

  const saveCurrentAsTemplate = () => {
    if (!isFormValid) return;
    const payload = buildCreatePayload();
    saveTemplateMutation.mutate({
      name: `${name} ${t("jobTemplates.templateSuffix")}`,
      description: t("jobTemplates.savedFromForm"),
      profile_id: payload.profile_id,
      playbook_id: payload.playbook_id,
      execution_type: payload.execution_type,
      host_ids: payload.host_ids,
      dynamic_filter: payload.dynamic_filter,
      is_scheduled: payload.is_scheduled,
      cron_expression: payload.cron_expression,
      is_active: true,
    });
  };

  const configJobId = editingId ?? selectedJobId ?? activeJobId;
  const configJob = jobList.find((job) => job.id === configJobId);
  const configHostOptions = configJob
    ? availableHosts.filter((host) => configJob.host_ids.includes(host.id))
    : [];

  return (
    <>
      <OperationsPageHeader task="compliance" platform={operationsPlatform} />

      {canOperate ? (
      <Panel
        ref={jobFormPanelRef}
        title={isEditing ? t("jobs.editTitle", { name }) : t("jobs.createJob")}
      >
        <div className="pf-form pf-form--wide">
          <div className="pf-form__row">
            <div className="pf-form__group">
              <label htmlFor="job-name">{t("jobs.jobName")}</label>
              <input
                id="job-name"
                className="pf-input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="AlterOS weekly audit"
              />
            </div>
            <div className="pf-form__group">
              <label>{t("jobs.jobType")}</label>
              <select
                className="pf-select"
                value={isNetwork ? "python" : jobType}
                disabled={isNetwork}
                onChange={(e) =>
                  setJobType(e.target.value as "ssh" | "winrm" | "python" | "playbook" | "ansible")
                }
              >
                {operationsPlatform === "linux" && (
                  <>
                    <option value="ssh">{t("jobs.typeSsh")}</option>
                    <option value="playbook">{t("jobs.typePlaybook")}</option>
                  </>
                )}
                {operationsPlatform === "windows" && (
                  <>
                    <option value="winrm">{t("jobs.typeWinrm")}</option>
                    <option value="playbook">{t("jobs.typePlaybook")}</option>
                  </>
                )}
                {isNetwork && <option value="python">{t("jobs.typePython")}</option>}
              </select>
            </div>
            {isNetwork && (
              <div className="pf-form__group">
                <label htmlFor="job-network-mode">{t("network.checkMode")}</label>
                <select
                  id="job-network-mode"
                  className="pf-select"
                  value={networkCheckMode}
                  onChange={(e) =>
                    setNetworkCheckMode(e.target.value as "remote" | "config_upload" | "both")
                  }
                >
                  <option value="config_upload">{t("network.modeConfigUpload")}</option>
                  <option value="remote">{t("network.modeRemote")}</option>
                  <option value="both">{t("network.modeBoth")}</option>
                </select>
              </div>
            )}
            {jobType !== "playbook" || isNetwork ? (
              <div className="pf-form__group">
                <label htmlFor="job-profile">{t("jobs.profile")}</label>
                <select
                  id="job-profile"
                  className="pf-select"
                  value={profileId}
                  onChange={(e) => setProfileId(e.target.value ? Number(e.target.value) : "")}
                >
                  <option value="">{t("jobs.selectProfile")}</option>
                  {availableProfiles.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.label}
                    </option>
                  ))}
                </select>
              </div>
            ) : (
              <div className="pf-form__group">
                <label htmlFor="job-playbook">{t("jobs.playbook")}</label>
                <select
                  id="job-playbook"
                  className="pf-select"
                  value={playbookId}
                  onChange={(e) => setPlaybookId(e.target.value ? Number(e.target.value) : "")}
                >
                  <option value="">{t("jobs.selectPlaybook")}</option>
                  {playbooks.data?.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </div>
            )}
          </div>

          <CollapsibleFormField
            id="job-hosts-field"
            label={t("jobs.hosts")}
            summary={t("jobs.hostsSummary", {
              total: availableHosts.length,
              selected: hostIds.length,
            })}
          >
            {hosts.isLoading ? (
              <Spinner />
            ) : (
              <HostPicker
                hosts={availableHosts}
                selectedIds={hostIds}
                onToggle={toggleHost}
                onSelectAll={selectAllHosts}
                onClearAll={clearHosts}
              />
            )}
          </CollapsibleFormField>

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
                  onClick={() => updateMutation.mutate({ id: editingId, data: buildUpdatePayload() })}
                  disabled={!isFormValid || updateMutation.isPending}
                >
                  {t("jobs.saveChanges")}
                </Button>
                <Button variant="secondary" onClick={cancelEdit}>
                  {t("common.cancel")}
                </Button>
              </>
            ) : (
              <>
                <Button
                  onClick={() => createMutation.mutate(buildCreatePayload())}
                  disabled={!isFormValid || createMutation.isPending}
                >
                  {t("jobs.createButton")}
                </Button>
                <Button
                  variant="secondary"
                  onClick={saveCurrentAsTemplate}
                  disabled={!isFormValid || saveTemplateMutation.isPending}
                >
                  {t("jobTemplates.saveAsTemplate")}
                </Button>
              </>
            )}
          </div>
        </div>
      </Panel>
      ) : null}

      {canOperate && !isNetwork ? (
        <Panel title={t("jobTemplates.title")} description={t("jobTemplates.description")} noPadding>
          <JobTemplatesPanel
            canManage={canOperate}
            onUseTemplate={applyTemplateToForm}
            onJobCreated={focusCreatedJob}
          />
        </Panel>
      ) : null}

      {isNetwork ? (
        <NetworkConfigUploadPanel
          jobId={configJobId}
          jobs={jobList.map((job) => ({ id: job.id, name: job.name }))}
          onJobChange={(id) => {
            setSelectedJobId(id);
            const job = jobList.find((item) => item.id === id);
            if (job) startEdit(job, { updateUrl: true, scroll: false });
          }}
          hostOptions={configHostOptions.map((host) => ({ id: host.id, name: host.name }))}
        />
      ) : null}

      {lastRunId && (
        <div className="pf-alert pf-alert--info">
          {t("jobs.runStarted", { id: lastRunId })}{" "}
          <Link to={`/reports?run=${lastRunId}`}>{t("jobs.goToReport")}</Link>
        </div>
      )}

      <Panel title={t("jobs.jobList")} noPadding>
        <div className="pf-filters">
          <div className="pf-filters__grid pf-filters__grid--ops-jobs">
            <div className="pf-filters__group">
              <label htmlFor="jobs-filter-search">{t("jobs.jobListSearchLabel")}</label>
              <input
                id="jobs-filter-search"
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
              <label htmlFor="jobs-filter-profile">{t("jobs.jobListProfileFilter")}</label>
              <select
                id="jobs-filter-profile"
                className="pf-select"
                value={jobProfileFilter}
                onChange={(e) => {
                  setJobProfileFilter(e.target.value);
                  setJobsListExpanded(false);
                }}
              >
                <option value="all">{t("reports.allProfiles")}</option>
                {availableProfiles.map((profile) => (
                  <option key={`profile-${profile.id}`} value={`profile:${profile.id}`}>
                    {profile.profile_name}
                  </option>
                ))}
                {!isNetwork
                  ? (playbooks.data ?? []).map((playbook) => (
                      <option key={`playbook-${playbook.id}`} value={`playbook:${playbook.id}`}>
                        {playbook.name}
                      </option>
                    ))
                  : null}
              </select>
            </div>
            <div className="pf-filters__group">
              <label htmlFor="jobs-filter-schedule">{t("jobs.jobListScheduleFilter")}</label>
              <select
                id="jobs-filter-schedule"
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
          <EmptyState title={t("jobs.noJobs")} description={t("jobs.noJobsDesc")} />
        ) : filteredJobs.length === 0 ? (
          <EmptyState title={t("jobs.noFilterResults")} description={t("jobs.noFilterResultsDesc")} />
        ) : (
          <div className="pf-table-wrap">
            <table className="pf-table pf-ops-table">
              <thead>
                <tr>
                  <SortableTh<JobSortKey>
                    label={t("common.id")}
                    sortKey="id"
                    activeKey={jobSort.key}
                    direction={jobSort.direction}
                    onSort={toggleJobSort}
                  />
                  <SortableTh<JobSortKey>
                    label={t("common.name")}
                    sortKey="name"
                    activeKey={jobSort.key}
                    direction={jobSort.direction}
                    onSort={toggleJobSort}
                  />
                  <SortableTh<JobSortKey>
                    label={t("jobs.profileCol")}
                    sortKey="profile_id"
                    activeKey={jobSort.key}
                    direction={jobSort.direction}
                    onSort={toggleJobSort}
                  />
                  <th>{t("jobs.hostsCol")}</th>
                  <SortableTh<JobSortKey>
                    label={t("jobs.schedule")}
                    sortKey="is_scheduled"
                    activeKey={jobSort.key}
                    direction={jobSort.direction}
                    onSort={toggleJobSort}
                  />
                  {canSeeObjectOwners ? <th>{t("objectRbac.owner")}</th> : null}
                  {canOperate ? (
                    <th className="pf-ops-table__actions" scope="col">
                      {t("common.actions")}
                    </th>
                  ) : null}
                </tr>
              </thead>
              <tbody>
                {visibleJobs.map((job) => (
                  <tr
                    key={job.id}
                    className={`pf-table__row--clickable${job.id === activeJobId || editingId === job.id ? " pf-table__row--selected" : ""}`}
                    onClick={() => setSelectedJobId(job.id)}
                  >
                    <td className="pf-table__mono">{job.id}</td>
                    <td>{job.name}</td>
                    <td>
                      {job.playbook_id
                        ? t("jobs.playbookRef", { id: job.playbook_id })
                        : t("jobs.profileRef", { id: job.profile_id ?? 0 })}
                    </td>
                    <td>
                      {job.host_ids.length === 0
                        ? t("common.all")
                        : t("jobTemplates.hostsCount", { count: job.host_ids.length })}
                    </td>
                    <td>
                      {job.is_scheduled
                        ? formatScheduleLabel(job.cron_expression, scheduleLabels)
                        : t("common.manual")}
                    </td>
                    {canSeeObjectOwners ? (
                      <td>
                        <ObjectOwnerCell ownerSub={job.owner_sub} />
                      </td>
                    ) : null}
                    {canOperate ? (
                    <td className="pf-ops-table__actions" onClick={(e) => e.stopPropagation()}>
                      <div className="pf-ops-row-actions">
                        <Button
                          variant="secondary"
                          className="pf-btn--sm"
                          onClick={() => startEdit(job)}
                        >
                          {t("common.edit")}
                        </Button>
                        <Button
                          variant="secondary"
                          className="pf-btn--sm"
                          onClick={() => runMutation.mutate(job.id)}
                          disabled={!canExecute || runMutation.isPending}
                          title={!canExecute ? t("common.demoActionDisabled") : undefined}
                        >
                          {t("common.run")}
                        </Button>
                        <Button
                          variant="danger-secondary"
                          className="pf-btn--sm"
                          onClick={() => deleteJobMutation.mutate(job.id)}
                          disabled={deleteJobMutation.isPending}
                        >
                          {t("common.delete")}
                        </Button>
                      </div>
                    </td>
                    ) : null}
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

      {selectedJob && (
        <Panel ref={selectedJobPanelRef} title={t("jobs.selectedJob", { name: selectedJob.name })}>
          <p className="pf-form__hint" style={{ marginBottom: "0.75rem" }}>
            {t("jobs.selectedJobMeta", {
              id: selectedJob.id,
              target: selectedJob.playbook_id
                ? t("jobs.playbookRef", { id: selectedJob.playbook_id })
                : t("jobs.profileRef", { id: selectedJob.profile_id ?? 0 }),
              schedule: selectedJob.is_scheduled
                ? formatScheduleLabel(selectedJob.cron_expression, scheduleLabels)
                : t("jobs.manualRun"),
            })}
          </p>
          <div className="pf-form__actions">
            {canOperate ? (
            <Button
              variant="secondary"
              onClick={() => runMutation.mutate(selectedJob.id)}
              disabled={!canExecute || runMutation.isPending}
              title={!canExecute ? t("common.demoActionDisabled") : undefined}
            >
              {t("jobs.runJob")}
            </Button>
            ) : null}
          </div>
        </Panel>
      )}

      <Panel title={t("jobs.recentRuns")} noPadding>
        <div className="pf-filters">
          <div className="pf-filters__grid pf-filters__grid--ops-runs">
            <div className="pf-filters__group">
              <label htmlFor="runs-filter-search">{t("jobs.runListSearchLabel")}</label>
              <input
                id="runs-filter-search"
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
              <label htmlFor="runs-filter-status">{t("jobs.runListStatusFilter")}</label>
              <select
                id="runs-filter-status"
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
          <EmptyState title={t("jobs.noRuns")} description={t("jobs.noRunsDesc")} />
        ) : filteredRuns.length === 0 ? (
          <EmptyState title={t("jobs.noFilterResults")} description={t("jobs.noFilterResultsDesc")} />
        ) : (
          <div className="pf-table-wrap">
            <table className="pf-table pf-ops-table">
              <thead>
                <tr>
                  <SortableTh<RunSortKey>
                    label={t("jobs.runId")}
                    sortKey="id"
                    activeKey={runSort.key}
                    direction={runSort.direction}
                    onSort={toggleRunSort}
                  />
                  <SortableTh<RunSortKey>
                    label={t("jobs.jobId")}
                    sortKey="job_id"
                    activeKey={runSort.key}
                    direction={runSort.direction}
                    onSort={toggleRunSort}
                  />
                  <SortableTh<RunSortKey>
                    label={t("common.name")}
                    sortKey="job_name"
                    activeKey={runSort.key}
                    direction={runSort.direction}
                    onSort={toggleRunSort}
                  />
                  <SortableTh<RunSortKey>
                    label={t("jobs.profileCol")}
                    sortKey="profile_id"
                    activeKey={runSort.key}
                    direction={runSort.direction}
                    onSort={toggleRunSort}
                  />
                  <SortableTh<RunSortKey>
                    label={t("common.status")}
                    sortKey="status"
                    activeKey={runSort.key}
                    direction={runSort.direction}
                    onSort={toggleRunSort}
                  />
                  <th>{t("jobs.started")}</th>
                  <SortableTh<RunSortKey>
                    label={t("jobs.finished")}
                    sortKey="finished_at"
                    activeKey={runSort.key}
                    direction={runSort.direction}
                    onSort={toggleRunSort}
                  />
                  {canOperate ? (
                    <th className="pf-ops-table__actions" scope="col">
                      {t("common.actions")}
                    </th>
                  ) : null}
                </tr>
              </thead>
              <tbody>
                {visibleRuns.map((run) => {
                  const job = jobById.get(run.job_id);
                  return (
                  <tr
                    key={run.id}
                    className={canViewRunReport(run.status) ? "pf-table__row--clickable" : undefined}
                    onClick={
                      canViewRunReport(run.status)
                        ? () => navigate(`/reports?run=${run.id}`)
                        : undefined
                    }
                  >
                    <td className="pf-table__mono">
                      {canViewRunReport(run.status) ? (
                        <Link to={`/reports?run=${run.id}`} onClick={(e) => e.stopPropagation()}>
                          #{run.id}
                        </Link>
                      ) : (
                        run.id
                      )}
                    </td>
                    <td className="pf-table__mono">{run.job_id}</td>
                    <td>{job?.name ?? t("common.dash")}</td>
                    <td>
                      {job
                        ? job.playbook_id
                          ? t("jobs.playbookRef", { id: job.playbook_id })
                          : t("jobs.profileRef", { id: job.profile_id ?? 0 })
                        : t("common.dash")}
                    </td>
                    <td>
                      <Badge variant={runStatusVariant(run.status)}>{runStatusLabel(t, run.status)}</Badge>
                    </td>
                    <td>
                      {run.started_at ? new Date(run.started_at).toLocaleString(dateLocale) : t("common.dash")}
                    </td>
                    <td>
                      {run.finished_at ? new Date(run.finished_at).toLocaleString(dateLocale) : t("common.dash")}
                    </td>
                    <td className="pf-ops-table__actions" onClick={(e) => e.stopPropagation()}>
                      <div className="pf-ops-row-actions">
                        {canViewRunReport(run.status) && (
                          <Button
                            variant="secondary"
                            className="pf-btn--sm"
                            onClick={() => navigate(`/reports?run=${run.id}`)}
                          >
                            {t("common.open")}
                          </Button>
                        )}
                        {canOperate && (
                          <Button
                            variant="secondary"
                            className="pf-btn--sm"
                            onClick={() => restartRunMutation.mutate(run)}
                            disabled={
                              restartRunMutation.isPending ||
                              !job ||
                              run.status === "pending" ||
                              run.status === "running"
                            }
                            title={job ? t("jobs.restartRun") : t("jobs.restartMissingJob")}
                          >
                            <IconRefresh className="pf-btn__icon" />
                            {t("jobs.restartRun")}
                          </Button>
                        )}
                        {(run.status === "pending" || run.status === "running") && canOperate && (
                          <Button
                            variant="secondary"
                            className="pf-btn--sm"
                            onClick={async () => {
                              const ok = await confirm({
                                title: t("common.stop"),
                                message: t("jobs.stopConfirm", { id: run.id }),
                                variant: "warning",
                              });
                              if (ok) stopRunMutation.mutate(run.id);
                            }}
                            disabled={stopRunMutation.isPending}
                          >
                            {t("common.stop")}
                          </Button>
                        )}
                        {canViewRunReport(run.status) && canOperate && (
                          <Button
                            variant="danger-secondary"
                            className="pf-btn--sm"
                            onClick={() => deleteRunMutation.mutate(run.id)}
                            disabled={deleteRunMutation.isPending}
                          >
                            {t("common.delete")}
                          </Button>
                        )}
                      </div>
                    </td>
                  </tr>
                  );
                })}
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

      <JobRunLogs key={liveRunId ?? "none"} runId={liveRunId} runStatus={liveRunStatus} />
    </>
  );
}
