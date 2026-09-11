import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  api,
  type OperationsScope,
  type PlaybookChangelogEntry,
  type PlaybookConnectionMode,
  type PlaybookTemplate,
} from "../api/client";
import { HostPicker } from "../components/HostPicker";
import { JobRunLogs } from "../components/JobRunLogs";
import { OpsListExpandFooter } from "../components/OpsListExpandFooter";
import { PlaybookRunResults } from "../components/PlaybookRunResults";
import { PlaybookYamlEditor } from "../components/PlaybookYamlEditor";
import {
  PlaybooksPageHeader,
  type PlaybookPageView,
  type PlaybookPlatformScope,
} from "../components/PlaybooksScopeTabs";
import { scrollAppToTop } from "../components/ScrollToTop";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { IconEye, IconRefresh, IconTrash } from "../components/ui/Icons";
import { EmptyState } from "../components/ui/EmptyState";
import { Panel } from "../components/ui/Panel";
import { Spinner } from "../components/ui/Spinner";
import { useConfirm } from "../components/ui/ConfirmDialog";
import { useToast } from "../components/ui/Toast";
import { useAuth } from "../auth/AuthProvider";
import { useTranslation } from "../i18n/I18nProvider";
import { runStatusVariant, RUN_STATUS_KEYS, runStatusLabel } from "../utils/statusVariant";
import { sliceOpsList, OPS_LIST_MAX } from "../utils/opsListLimit";
import { buildUnifiedDiff, lineDiffStats } from "../utils/textDiff";
import {
  COMPLIANCE_CATEGORY_ORDER,
  complianceDisplayName,
  complianceTemplateCategory,
  type ComplianceTemplateCategory,
} from "../utils/complianceTemplateMeta";

type TemplateProfile = "extended" | "fast";

const DEFAULT_PLAYBOOK_VERSION = "1.0";

function formatPlaybookVersion(value?: string | null): string {
  const version = (value || "").trim() || DEFAULT_PLAYBOOK_VERSION;
  if (version === "1.0.0" || version === "1.0.1" || version === "1.1.0") {
    return DEFAULT_PLAYBOOK_VERSION;
  }
  return version;
}

function parsePageView(value: string | null): PlaybookPageView {
  return value === "jobs" ? "jobs" : "catalog";
}

function parseRunId(value: string | null): number | null {
  if (!value) return null;
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function apiScopeForPlatform(platform: PlaybookPlatformScope): OperationsScope {
  return platform === "network" ? "network" : "standard";
}

function templateMatchesPlatform(template: PlaybookTemplate, platform: PlaybookPlatformScope): boolean {
  if (template.id === "network-remediation") return false;
  if (platform === "network") {
    return template.id.startsWith("network");
  }
  const prefix = platform === "linux" ? "linux" : "windows";
  return template.id.startsWith(prefix) || template.id === "connectivity-check";
}

function hostMatchesPlatform(osType: string | undefined, platform: PlaybookPlatformScope): boolean {
  const normalized = (osType ?? "linux").toLowerCase();
  if (platform === "network") return normalized === "network";
  if (platform === "windows") return normalized === "windows";
  return normalized !== "network" && normalized !== "windows";
}

function playbookMatchesPlatform(
  playbook: { name: string; scope?: OperationsScope; platform?: string | null },
  platform: PlaybookPlatformScope
): boolean {
  if (playbook.platform === "linux" || playbook.platform === "windows" || playbook.platform === "network") {
    return playbook.platform === platform;
  }
  // Legacy rows without platform: keep previous name/scope heuristics.
  const name = playbook.name.toLowerCase();
  if (platform === "network") {
    return playbook.scope === "network" || name.startsWith("network");
  }
  if (playbook.scope === "network") return false;
  if (platform === "windows") {
    return name.startsWith("windows") || name.includes("win-");
  }
  return !name.startsWith("windows") && !name.includes("win-");
}

function slugifyName(value: string): string {
  return value
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48);
}

function groupPlaybookChangelog(entries: PlaybookChangelogEntry[]): { version: string; entries: PlaybookChangelogEntry[] }[] {
  const groups = new Map<string, PlaybookChangelogEntry[]>();
  for (const entry of entries) {
    const version = formatPlaybookVersion(
      entry.playbook_version_after || entry.playbook_version_before,
    );
    const list = groups.get(version) ?? [];
    list.push(entry);
    groups.set(version, list);
  }
  return Array.from(groups.entries()).map(([version, items]) => ({ version, entries: items }));
}

function formatPlaybookDate(value: string | null | undefined, locale: string): string {
  if (!value) return "";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "";
  return date.toLocaleString(locale, {
    day: "2-digit",
    month: "2-digit",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function PlaybooksPage() {
  const { t, dateLocale } = useTranslation();
  const { canExecute } = useAuth();
  const toast = useToast();
  const { confirm } = useConfirm();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [name, setName] = useState("new-playbook");
  const [description, setDescription] = useState("");
  const [content, setContent] = useState("");
  const [hostIds, setHostIds] = useState<number[]>([]);
  const [connectionMode, setConnectionMode] = useState<PlaybookConnectionMode>("auto");
  const [selectedRunId, setSelectedRunId] = useState<number | null>(() => parseRunId(searchParams.get("run")));
  const [editorModalOpen, setEditorModalOpen] = useState(false);
  const [editorOpen, setEditorOpen] = useState(false);
  const [editingComplianceTemplate, setEditingComplianceTemplate] = useState(false);
  const [playbookVersion, setPlaybookVersion] = useState<string>(DEFAULT_PLAYBOOK_VERSION);
  const [showPlaybookChangelog, setShowPlaybookChangelog] = useState(false);
  const [expandedChangelogIds, setExpandedChangelogIds] = useState<Set<string>>(() => new Set());
  const [selectedComplianceIds, setSelectedComplianceIds] = useState<number[]>([]);
  const [complianceQuery, setComplianceQuery] = useState("");
  const [complianceCategory, setComplianceCategory] = useState<"all" | ComplianceTemplateCategory>("all");
  const [complianceProfileFilter, setComplianceProfileFilter] = useState("all");
  const [complianceListExpanded, setComplianceListExpanded] = useState(false);
  const [playbookJobSearch, setPlaybookJobSearch] = useState("");
  const [playbookJobStatusFilter, setPlaybookJobStatusFilter] = useState("all");
  const [playbookJobPlaybookFilter, setPlaybookJobPlaybookFilter] = useState("all");
  const [playbookJobsListExpanded, setPlaybookJobsListExpanded] = useState(false);
  const [batchHostIds, setBatchHostIds] = useState<number[]>([]);
  const [batchConnectionMode, setBatchConnectionMode] = useState<PlaybookConnectionMode>("auto");
  const [playbookPlatform, setPlaybookPlatform] = useState<PlaybookPlatformScope>("linux");
  const [pageView, setPageView] = useState<PlaybookPageView>(() => {
    const view = parsePageView(searchParams.get("view"));
    const runId = parseRunId(searchParams.get("run"));
    return view === "jobs" || runId != null ? "jobs" : "catalog";
  });
  const playbookScope = apiScopeForPlatform(playbookPlatform);

  const syncPlaybooksUrl = useCallback(
    (nextView: PlaybookPageView, nextRunId: number | null) => {
      setSearchParams(
        (prev) => {
          const next = new URLSearchParams(prev);
          if (nextView === "jobs") {
            next.set("view", "jobs");
          } else {
            next.delete("view");
          }
          if (nextRunId != null) {
            next.set("run", String(nextRunId));
          } else {
            next.delete("run");
          }
          return next;
        },
        { replace: true }
      );
    },
    [setSearchParams]
  );

  const selectRun = useCallback(
    (runId: number) => {
      setSelectedRunId(runId);
      syncPlaybooksUrl(pageView, runId);
    },
    [pageView, syncPlaybooksUrl]
  );

  const handlePageViewChange = useCallback(
    (view: PlaybookPageView) => {
      setPageView(view);
      if (view === "jobs") {
        setEditorOpen(false);
        syncPlaybooksUrl("jobs", selectedRunId);
        return;
      }
      setSelectedRunId(null);
      syncPlaybooksUrl("catalog", null);
    },
    [selectedRunId, syncPlaybooksUrl]
  );

  const playbooks = useQuery({
    queryKey: ["playbooks", playbookScope, playbookPlatform],
    queryFn: () => api.playbooks(playbookScope, playbookPlatform),
  });
  const templates = useQuery({
    queryKey: ["playbook-templates", "v2", playbookScope],
    queryFn: () => api.playbookTemplates(playbookScope),
  });
  const hosts = useQuery({
    queryKey: ["hosts", playbookPlatform],
    queryFn: () => api.hosts({ limit: 200 }),
  });
  const playbookRuns = useQuery({
    queryKey: ["playbook-runs", selectedId],
    queryFn: () => api.playbookRuns({ playbookId: selectedId ?? undefined, limit: 50 }),
    enabled: selectedId !== null,
    refetchInterval: (query) => {
      const runs = query.state.data ?? [];
      const hasActive = runs.some((run) => run.status === "pending" || run.status === "running");
      return hasActive ? 3000 : false;
    },
  });

  const platformPlaybooks = useMemo(
    () => (playbooks.data ?? []).filter((playbook) => playbookMatchesPlatform(playbook, playbookPlatform)),
    [playbooks.data, playbookPlatform]
  );
  const userPlaybooks = useMemo(
    () => platformPlaybooks.filter((playbook) => (playbook.kind ?? "user") !== "compliance_template"),
    [platformPlaybooks]
  );
  const complianceTaskTemplates = useMemo(
    () => platformPlaybooks.filter((playbook) => playbook.kind === "compliance_template"),
    [platformPlaybooks]
  );

  useEffect(() => {
    setComplianceQuery("");
    setComplianceCategory("all");
    setComplianceProfileFilter("all");
    setComplianceListExpanded(false);
    setSelectedComplianceIds([]);
    setPlaybookJobSearch("");
    setPlaybookJobStatusFilter("all");
    setPlaybookJobPlaybookFilter("all");
    setPlaybookJobsListExpanded(false);
  }, [playbookPlatform]);

  const complianceProfileOptions = useMemo(() => {
    const labels = new Set<string>();
    for (const playbook of complianceTaskTemplates) {
      const label = (playbook.profile_name || playbook.name || "").trim();
      if (label) labels.add(label);
    }
    return [...labels].sort((left, right) => left.localeCompare(right, undefined, { sensitivity: "base" }));
  }, [complianceTaskTemplates]);

  const filteredComplianceTemplates = useMemo(() => {
    const q = complianceQuery.trim().toLowerCase();
    return complianceTaskTemplates
      .filter((pb) => {
        const title = complianceDisplayName(pb.name, pb.profile_name);
        const category = complianceTemplateCategory(pb.name, pb.profile_name);
        const profileLabel = (pb.profile_name || pb.name || "").trim();
        if (complianceCategory !== "all" && category !== complianceCategory) return false;
        if (complianceProfileFilter !== "all" && profileLabel !== complianceProfileFilter) return false;
        if (!q) return true;
        return `${title} ${pb.name} ${pb.profile_name ?? ""} ${pb.version ?? ""}`.toLowerCase().includes(q);
      })
      .sort((left, right) =>
        complianceDisplayName(left.name, left.profile_name).localeCompare(
          complianceDisplayName(right.name, right.profile_name),
          undefined,
          { sensitivity: "base" }
        )
      );
  }, [complianceTaskTemplates, complianceQuery, complianceCategory, complianceProfileFilter]);

  const visibleComplianceTemplates = useMemo(
    () => sliceOpsList(filteredComplianceTemplates, complianceListExpanded),
    [filteredComplianceTemplates, complianceListExpanded]
  );

  const hasActiveComplianceFilters =
    complianceQuery.trim() !== "" ||
    complianceCategory !== "all" ||
    complianceProfileFilter !== "all";

  const selectedPlaybook = useMemo(
    () => playbooks.data?.find((playbook) => playbook.id === selectedId) ?? null,
    [playbooks.data, selectedId]
  );
  const playbookChangelog = useQuery({
    queryKey: ["playbook-changelog", selectedId],
    queryFn: () => api.getPlaybookChangelog(selectedId!),
    enabled: selectedId != null && editingComplianceTemplate && showPlaybookChangelog,
  });

  const allPlaybookRuns = useQuery({
    queryKey: ["playbook-runs-all", playbookScope, playbookPlatform, OPS_LIST_MAX],
    queryFn: () =>
      api.playbookRuns({ limit: OPS_LIST_MAX, scope: playbookScope, platform: playbookPlatform }),
    enabled: pageView === "jobs",
    refetchInterval: (query) => {
      const runs = query.state.data ?? [];
      const hasActive = runs.some((run) => run.status === "pending" || run.status === "running");
      return hasActive ? 3000 : false;
    },
  });

  const playbookJobList = useMemo(() => {
    return [...(allPlaybookRuns.data ?? [])].sort(
      (left, right) =>
        new Date(right.finished_at ?? right.started_at ?? right.created_at).getTime() -
        new Date(left.finished_at ?? left.started_at ?? left.created_at).getTime()
    );
  }, [allPlaybookRuns.data]);

  const playbookJobPlaybookOptions = useMemo(() => {
    const options = new Map<number, string>();
    for (const run of playbookJobList) {
      if (run.playbook_id == null) continue;
      options.set(run.playbook_id, run.playbook_name || `Playbook #${run.playbook_id}`);
    }
    return [...options.entries()].sort((left, right) =>
      left[1].localeCompare(right[1], undefined, { sensitivity: "base" })
    );
  }, [playbookJobList]);

  const filteredPlaybookJobs = useMemo(() => {
    const query = playbookJobSearch.trim().toLowerCase();
    return playbookJobList.filter((run) => {
      if (playbookJobStatusFilter !== "all" && run.status !== playbookJobStatusFilter) return false;
      if (playbookJobPlaybookFilter !== "all" && String(run.playbook_id) !== playbookJobPlaybookFilter) {
        return false;
      }
      if (!query) return true;
      const haystack = `${run.id} ${run.playbook_id ?? ""} ${run.playbook_name ?? ""}`.toLowerCase();
      return haystack.includes(query);
    });
  }, [playbookJobList, playbookJobSearch, playbookJobStatusFilter, playbookJobPlaybookFilter]);

  const visiblePlaybookJobs = useMemo(
    () => sliceOpsList(filteredPlaybookJobs, playbookJobsListExpanded),
    [filteredPlaybookJobs, playbookJobsListExpanded]
  );

  const hasActivePlaybookJobFilters =
    playbookJobSearch.trim() !== "" ||
    playbookJobStatusFilter !== "all" ||
    playbookJobPlaybookFilter !== "all";

  const runDetail = useQuery({
    queryKey: ["playbook-run-detail", selectedRunId],
    queryFn: () => api.getJobRun(selectedRunId!),
    enabled: selectedRunId !== null,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "pending" || status === "running" ? 3000 : false;
    },
  });

  const activeHosts = useMemo(
    () =>
      (hosts.data?.items ?? []).filter(
        (host) => host.is_active && hostMatchesPlatform(host.os_type, playbookPlatform)
      ),
    [hosts.data, playbookPlatform]
  );

  const platformTemplates = useMemo(
    () => (templates.data ?? []).filter((item) => templateMatchesPlatform(item, playbookPlatform)),
    [templates.data, playbookPlatform]
  );

  const inventoryTemplates = platformTemplates.filter((item) => item.category === "inventory");
  const remediationTemplates =
    playbookPlatform === "network"
      ? []
      : platformTemplates.filter((item) => item.category === "remediation");
  const utilityTemplate = platformTemplates.find((item) => item.category === "utility");
  const defaultTemplateContent =
    utilityTemplate?.content ?? inventoryTemplates[0]?.content ?? platformTemplates[0]?.content ?? "";

  const hostNameById = useMemo(() => {
    const map = new Map<number, string>();
    (hosts.data?.items ?? []).forEach((host) => map.set(host.id, host.name));
    return map;
  }, [hosts.data?.items]);

  const createMutation = useMutation({
    mutationFn: api.createPlaybook,
    onSuccess: (pb) => {
      queryClient.invalidateQueries({ queryKey: ["playbooks"] });
      setSelectedId(pb.id);
      setEditorOpen(false);
      setEditorModalOpen(false);
      toast.success(t("toast.playbookSaved"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Parameters<typeof api.updatePlaybook>[1] }) =>
      api.updatePlaybook(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["playbooks"] });
      toast.success(t("toast.playbookSaved"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const updateContentMutation = useMutation({
    mutationFn: ({ id, content: nextContent }: { id: number; content: string }) =>
      api.updatePlaybookContent(id, nextContent),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["playbooks"] });
      queryClient.invalidateQueries({ queryKey: ["playbook-changelog", result.playbook.id] });
      setPlaybookVersion(formatPlaybookVersion(result.playbook_version));
      setContent(result.playbook.content);
      toast.success(t("playbooks.complianceSaveSuccess", { version: formatPlaybookVersion(result.playbook_version) }));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteMutation = useMutation({
    mutationFn: api.deletePlaybook,
    onSuccess: (_data, id) => {
      queryClient.invalidateQueries({ queryKey: ["playbooks"] });
      queryClient.invalidateQueries({ queryKey: ["playbook-runs"] });
      queryClient.invalidateQueries({ queryKey: ["job-runs"] });
      setSelectedComplianceIds((prev) => prev.filter((item) => item !== id));
      if (selectedId === id) {
        setSelectedId(null);
        setSelectedRunId(null);
        setName("new-playbook");
        setDescription("");
        setContent(defaultTemplateContent);
        setEditorOpen(false);
        setEditorModalOpen(false);
      }
      toast.success(t("toast.playbookDeleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const validateMutation = useMutation({
    mutationFn: () => api.validatePlaybook({ name, description, content }),
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const runMutation = useMutation({
    mutationFn: ({
      playbookId,
      ids,
      mode,
    }: {
      playbookId: number;
      ids: number[];
      mode: PlaybookConnectionMode;
    }) => api.runPlaybook(playbookId, ids, mode),
    onSuccess: (run) => {
      selectRun(run.id);
      queryClient.invalidateQueries({ queryKey: ["playbook-runs", selectedId] });
      queryClient.invalidateQueries({ queryKey: ["playbook-runs-all"] });
      queryClient.invalidateQueries({ queryKey: ["job-runs"] });
      toast.success(t("toast.playbookRunStarted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const runSelectedComplianceMutation = useMutation({
    mutationFn: async ({
      playbookIds,
      ids,
      mode,
    }: {
      playbookIds: number[];
      ids: number[];
      mode: PlaybookConnectionMode;
    }) => {
      const runs = [];
      for (const playbookId of playbookIds) {
        runs.push(await api.runPlaybook(playbookId, ids, mode));
      }
      return runs;
    },
    onSuccess: (runs) => {
      if (runs.length > 0) {
        selectRun(runs[runs.length - 1].id);
        setPageView("jobs");
        syncPlaybooksUrl("jobs", runs[runs.length - 1].id);
      }
      setSelectedComplianceIds([]);
      queryClient.invalidateQueries({ queryKey: ["playbook-runs-all"] });
      queryClient.invalidateQueries({ queryKey: ["job-runs"] });
      toast.success(t("playbooks.complianceBatchStarted", { count: runs.length }));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const toggleComplianceSelected = (id: number) => {
    setSelectedComplianceIds((prev) =>
      prev.includes(id) ? prev.filter((item) => item !== id) : [...prev, id]
    );
  };

  const toggleChangelogExpanded = (id: string) => {
    setExpandedChangelogIds((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const deleteRunMutation = useMutation({
    mutationFn: api.deleteJobRun,
    onSuccess: (_data, deletedRunId) => {
      queryClient.invalidateQueries({ queryKey: ["playbook-runs", selectedId] });
      queryClient.invalidateQueries({ queryKey: ["playbook-runs-all"] });
      queryClient.invalidateQueries({ queryKey: ["job-runs"] });
      if (selectedRunId === deletedRunId) {
        setSelectedRunId(null);
        syncPlaybooksUrl(pageView, null);
      }
      toast.success(t("toast.playbookRunDeleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const restartRunMutation = useMutation({
    mutationFn: (run: { playbook_id?: number | null; host_ids?: number[] }) => {
      if (!run.playbook_id) {
        return Promise.reject(new Error(t("playbooks.restartMissingPlaybook")));
      }
      const hostIds = run.host_ids ?? [];
      if (hostIds.length === 0) {
        return Promise.reject(new Error(t("playbooks.restartMissingHosts")));
      }
      return api.runPlaybook(run.playbook_id, hostIds, connectionMode);
    },
    onSuccess: (run) => {
      selectRun(run.id);
      queryClient.invalidateQueries({ queryKey: ["playbook-runs", selectedId] });
      queryClient.invalidateQueries({ queryKey: ["playbook-runs-all"] });
      queryClient.invalidateQueries({ queryKey: ["job-runs"] });
      toast.success(t("toast.playbookRunStarted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const openEditor = () => {
    setEditorOpen(true);
    setEditorModalOpen(false);
    scrollAppToTop();
  };

  const closeEditor = () => {
    setEditorOpen(false);
    setEditorModalOpen(false);
    validateMutation.reset();
    scrollAppToTop();
  };

  const startNewPlaybook = () => {
    setSelectedId(null);
    setEditingComplianceTemplate(false);
    setPlaybookVersion(DEFAULT_PLAYBOOK_VERSION);
    setShowPlaybookChangelog(false);
    setName("new-playbook");
    setDescription("");
    setContent(defaultTemplateContent);
    setSelectedRunId(null);
    validateMutation.reset();
    openEditor();
  };

  const loadPlaybook = (id: number) => {
    const pb = playbooks.data?.find((p) => p.id === id);
    if (!pb) return;
    setSelectedId(pb.id);
    setEditingComplianceTemplate(pb.kind === "compliance_template");
    setPlaybookVersion(formatPlaybookVersion(pb.version));
    setShowPlaybookChangelog(false);
    setName(pb.name);
    setDescription(pb.description || "");
    setContent(pb.content);
    setSelectedRunId(null);
    validateMutation.reset();
    openEditor();
  };

  const openComplianceTemplate = (id: number, options?: { focusRun?: boolean }) => {
    loadPlaybook(id);
    if (!options?.focusRun) return;
    window.setTimeout(() => {
      document.querySelector(".pf-playbooks-run")?.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 80);
  };

  const templateText = (
    template: PlaybookTemplate,
    profile: TemplateProfile,
    kind: "name" | "description",
  ) => {
    const key =
      kind === "name"
        ? profile === "fast"
          ? (`playbooks.templateNamesFast.${template.id}` as const)
          : (`playbooks.templateNames.${template.id}` as const)
        : profile === "fast" && template.content_fast
          ? (`playbooks.templateDescriptionsFast.${template.id}` as const)
          : (`playbooks.templateDescriptions.${template.id}` as const);
    const translated = t(key);
    if (translated !== key) return translated;
    return kind === "name" ? template.name : template.description ?? "";
  };

  const applyTemplate = (template: PlaybookTemplate, profile: TemplateProfile = "extended") => {
    const yaml =
      profile === "fast" && template.content_fast ? template.content_fast : template.content;
    const slug = slugifyName(template.id) || slugifyName(template.name) || "new-playbook";

    setSelectedId(null);
    setName(profile === "fast" ? `${slug}-fast` : slug);
    setDescription(templateText(template, profile, "description"));
    setContent(yaml);
    setSelectedRunId(null);
    validateMutation.reset();
    openEditor();
  };

  const renderTemplateCard = (template: PlaybookTemplate, profile: TemplateProfile) => (
    <button
      key={`${template.id}-${profile}`}
      type="button"
      className={`pf-template-card${profile === "fast" ? " pf-template-card--fast" : ""}`}
      onClick={() => applyTemplate(template, profile)}
    >
      <span className="pf-template-card__title">{templateText(template, profile, "name")}</span>
      <span className="pf-template-card__desc">{templateText(template, profile, "description")}</span>
      <span className="pf-template-card__action">{t("playbooks.useTemplate")}</span>
    </button>
  );

  const handleDelete = async (id: number) => {
    const playbook = playbooks.data?.find((item) => item.id === id);
    const title = playbook
      ? playbook.kind === "compliance_template"
        ? complianceDisplayName(playbook.name, playbook.profile_name)
        : playbook.name
      : String(id);
    const ok = await confirm({
      title: t("common.delete"),
      message: t("playbooks.deleteConfirm", { name: title }),
      variant: "danger",
    });
    if (ok) deleteMutation.mutate(id);
  };

  const handleDeleteSelectedCompliance = async () => {
    if (selectedComplianceIds.length === 0) return;
    const ok = await confirm({
      title: t("playbooks.complianceDeleteSelected"),
      message: t("playbooks.complianceDeleteSelectedConfirm", { count: selectedComplianceIds.length }),
      variant: "danger",
    });
    if (!ok) return;
    const ids = [...selectedComplianceIds];
    for (const id of ids) {
      try {
        await api.deletePlaybook(id);
      } catch (err) {
        toast.error(err instanceof Error ? err.message : t("toast.genericError"));
        queryClient.invalidateQueries({ queryKey: ["playbooks"] });
        return;
      }
    }
    setSelectedComplianceIds([]);
    if (selectedId != null && ids.includes(selectedId)) {
      setSelectedId(null);
      setSelectedRunId(null);
      setName("new-playbook");
      setDescription("");
      setContent(defaultTemplateContent);
      setEditorOpen(false);
      setEditorModalOpen(false);
    }
    queryClient.invalidateQueries({ queryKey: ["playbooks"] });
    queryClient.invalidateQueries({ queryKey: ["playbook-runs"] });
    queryClient.invalidateQueries({ queryKey: ["job-runs"] });
    toast.success(t("toast.playbookDeleted"));
  };

  const toggleHost = (id: number) => {
    setHostIds((prev) => (prev.includes(id) ? prev.filter((hostId) => hostId !== id) : [...prev, id]));
  };

  const handleDeleteRun = (runId: number) => {
    deleteRunMutation.mutate(runId);
  };

  const yamlFileName = `${slugifyName(name) || "playbook"}.yml`;

  const handleSavePlaybook = () => {
    if (selectedId && editingComplianceTemplate) {
      updateContentMutation.mutate({ id: selectedId, content });
      return;
    }
    if (selectedId) {
      updateMutation.mutate({ id: selectedId, data: { name, description, content } });
      return;
    }
    createMutation.mutate({
      name,
      description,
      content,
      scope: playbookScope,
      platform: playbookPlatform,
    });
  };

  const renderYamlEditor = (height: string) => (
    <PlaybookYamlEditor value={content} onChange={setContent} height={height} />
  );

  const renderValidationAlert = () =>
    validateMutation.data ? (
      <div className={`pf-alert ${validateMutation.data.valid ? "pf-alert--success" : "pf-alert--error"}`}>
        {validateMutation.data.message}
      </div>
    ) : null;

  const renderRunResultsPanel = () =>
    selectedRunId ? (
      <Panel title={t("playbooks.resultsTitle", { id: selectedRunId })} className="pf-playbooks-results">
        {runDetail.isLoading && <Spinner />}
        {runDetail.isError && (
          <div className="pf-alert pf-alert--error">{(runDetail.error as Error).message}</div>
        )}

        {runDetail.data && (
          <>
            <div className="pf-playbooks-results__meta">
              <Badge variant={runStatusVariant(runDetail.data.status)}>{runDetail.data.status}</Badge>
              {runDetail.data.error_message && (
                <span className="pf-playbooks-results__error">{runDetail.data.error_message}</span>
              )}
            </div>

            <PlaybookRunResults run={runDetail.data} hostNameById={hostNameById} />

            <JobRunLogs
              key={selectedRunId ?? "none"}
              runId={selectedRunId}
              runStatus={runDetail.data.status}
            />
          </>
        )}
      </Panel>
    ) : null;

  const renderRunsTable = (
    runs: typeof playbookRuns.data,
    options: { isLoading: boolean; showPlaybookColumn?: boolean }
  ) => {
    if (options.isLoading) return <Spinner />;
    if ((runs?.length ?? 0) === 0) {
      return <EmptyState title={t("playbooks.noRuns")} description={t("playbooks.noRunsDesc")} />;
    }

    return (
      <div className="pf-table-wrap">
        <table className="pf-table">
          <thead>
            <tr>
              <th>{t("jobs.runId")}</th>
              {options.showPlaybookColumn && <th>{t("playbooks.playbookCol")}</th>}
              <th>{t("common.status")}</th>
              <th>{t("playbooks.hostsCount")}</th>
              <th>{t("reports.started")}</th>
              <th>{t("reports.finished")}</th>
              <th className="pf-table__col-actions">{t("common.actions")}</th>
            </tr>
          </thead>
          <tbody>
            {runs?.map((run) => (
              <tr
                key={run.id}
                className={`pf-table__row--clickable${selectedRunId === run.id ? " pf-table__row--selected" : ""}`}
                onClick={() => selectRun(run.id)}
              >
                <td className="pf-table__mono">{run.id}</td>
                {options.showPlaybookColumn && (
                  <td>
                    <div className="pf-playbooks-list__name">{run.playbook_name || t("common.dash")}</div>
                  </td>
                )}
                <td>
                  <Badge variant={runStatusVariant(run.status)}>{run.status}</Badge>
                </td>
                <td>{run.host_count}</td>
                <td>
                  {run.started_at
                    ? new Date(run.started_at).toLocaleString(dateLocale)
                    : t("common.dash")}
                </td>
                <td>
                  {run.finished_at
                    ? new Date(run.finished_at).toLocaleString(dateLocale)
                    : t("common.dash")}
                </td>
                <td className="pf-table__col-actions" onClick={(event) => event.stopPropagation()}>
                  <div className="pf-table__actions pf-playbook-run-actions">
                    <Button
                      variant="secondary"
                      className="pf-btn--sm"
                      onClick={() => selectRun(run.id)}
                    >
                      <IconEye className="pf-btn__icon" />
                      {t("playbooks.viewResults")}
                    </Button>
                    <Button
                      variant="secondary"
                      className="pf-btn--sm"
                      onClick={() => restartRunMutation.mutate(run)}
                      disabled={
                        restartRunMutation.isPending ||
                        !run.playbook_id ||
                        (run.host_ids?.length ?? 0) === 0 ||
                        run.status === "pending" ||
                        run.status === "running"
                      }
                      title={t("playbooks.restartRun")}
                    >
                      <IconRefresh className="pf-btn__icon" />
                      {t("playbooks.restartRun")}
                    </Button>
                    <Button
                      variant="danger-secondary"
                      className="pf-btn--sm"
                      onClick={() => handleDeleteRun(run.id)}
                      disabled={deleteRunMutation.isPending}
                    >
                      <IconTrash className="pf-btn__icon" />
                      {t("playbooks.deleteRun")}
                    </Button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  };

  return (
    <>
      <PlaybooksPageHeader
        platform={playbookPlatform}
        onPlatformChange={(platform) => {
          setPlaybookPlatform(platform);
          setHostIds([]);
          setBatchHostIds([]);
          setSelectedComplianceIds([]);
          setSelectedId(null);
          setSelectedRunId(null);
          syncPlaybooksUrl(pageView, null);
        }}
        pageView={pageView}
        onPageViewChange={handlePageViewChange}
      />

      {pageView === "jobs" ? (
        <>
          <Panel
            title={t("playbooks.jobsListTitle")}
            className="pf-playbooks-jobs-panel"
            noPadding
          >
            <p className="pf-playbooks-jobs-panel__hint">{t("playbooks.jobsListDesc")}</p>
            <div className="pf-filters">
              <div className="pf-filters__grid pf-filters__grid--playbooks-jobs">
                <div className="pf-filters__group">
                  <label htmlFor="playbook-jobs-filter-search">{t("jobs.runListSearchLabel")}</label>
                  <input
                    id="playbook-jobs-filter-search"
                    className="pf-input"
                    value={playbookJobSearch}
                    onChange={(e) => {
                      setPlaybookJobSearch(e.target.value);
                      setPlaybookJobsListExpanded(false);
                    }}
                    placeholder={t("jobs.runListSearch")}
                  />
                </div>
                <div className="pf-filters__group">
                  <label htmlFor="playbook-jobs-filter-status">{t("jobs.runListStatusFilter")}</label>
                  <select
                    id="playbook-jobs-filter-status"
                    className="pf-select"
                    value={playbookJobStatusFilter}
                    onChange={(e) => {
                      setPlaybookJobStatusFilter(e.target.value);
                      setPlaybookJobsListExpanded(false);
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
                <div className="pf-filters__group">
                  <label htmlFor="playbook-jobs-filter-playbook">{t("playbooks.playbookCol")}</label>
                  <select
                    id="playbook-jobs-filter-playbook"
                    className="pf-select"
                    value={playbookJobPlaybookFilter}
                    onChange={(e) => {
                      setPlaybookJobPlaybookFilter(e.target.value);
                      setPlaybookJobsListExpanded(false);
                    }}
                  >
                    <option value="all">{t("playbooks.jobsListPlaybookAll")}</option>
                    {playbookJobPlaybookOptions.map(([id, label]) => (
                      <option key={id} value={String(id)}>
                        {label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="pf-filters__footer">
                <p className="pf-filters__summary">
                  {hasActivePlaybookJobFilters
                    ? t("profiles.filterResultsActive", {
                        count: filteredPlaybookJobs.length,
                        total: playbookJobList.length,
                      })
                    : t("profiles.filterShown", {
                        count: filteredPlaybookJobs.length,
                        total: playbookJobList.length,
                      })}
                </p>
                {hasActivePlaybookJobFilters ? (
                  <Button
                    variant="secondary"
                    className="pf-btn--sm"
                    type="button"
                    onClick={() => {
                      setPlaybookJobSearch("");
                      setPlaybookJobStatusFilter("all");
                      setPlaybookJobPlaybookFilter("all");
                      setPlaybookJobsListExpanded(false);
                    }}
                  >
                    {t("profiles.clearFilters")}
                  </Button>
                ) : null}
              </div>
            </div>
            {allPlaybookRuns.isLoading ? (
              <Spinner />
            ) : playbookJobList.length === 0 ? (
              <EmptyState title={t("playbooks.noRuns")} description={t("playbooks.noRunsDesc")} />
            ) : filteredPlaybookJobs.length === 0 ? (
              <EmptyState title={t("jobs.noFilterResults")} description={t("jobs.noFilterResultsDesc")} />
            ) : (
              <>
                {renderRunsTable(visiblePlaybookJobs, {
                  isLoading: false,
                  showPlaybookColumn: true,
                })}
                <OpsListExpandFooter
                  shown={visiblePlaybookJobs.length}
                  total={filteredPlaybookJobs.length}
                  expanded={playbookJobsListExpanded}
                  onToggle={() => setPlaybookJobsListExpanded((value) => !value)}
                />
              </>
            )}
            {deleteRunMutation.isError && (
              <div className="pf-alert pf-alert--error" style={{ margin: "1rem" }}>
                {(deleteRunMutation.error as Error).message}
              </div>
            )}
          </Panel>

          {renderRunResultsPanel()}
        </>
      ) : !editorOpen ? (
        <>
      <Panel title={t("playbooks.templates")} className="pf-playbooks-templates">
        {templates.isLoading ? (
          <Spinner />
        ) : (
          <div className="pf-template-groups">
            {playbookPlatform === "network" ? (
              <section className="pf-template-group">
                <div className="pf-template-group__header">
                  <p className="pf-template-group__hint">{t("playbooks.templateGroupNetworkInventoryHint")}</p>
                </div>
                <div className="pf-template-grid">
                  {inventoryTemplates.map((template) => renderTemplateCard(template, "extended"))}
                </div>
              </section>
            ) : (
              <>
            <section className="pf-template-group pf-template-group--extended">
              <div className="pf-template-group__header">
                <h3 className="pf-template-group__title">{t("playbooks.templateGroupExtended")}</h3>
                <p className="pf-template-group__hint">{t("playbooks.templateGroupExtendedHint")}</p>
              </div>
              <div className="pf-template-grid">
                {inventoryTemplates.map((template) => renderTemplateCard(template, "extended"))}
              </div>
            </section>

            <section className="pf-template-group pf-template-group--fast">
              <div className="pf-template-group__header">
                <h3 className="pf-template-group__title">{t("playbooks.templateGroupFast")}</h3>
                <p className="pf-template-group__hint">{t("playbooks.templateGroupFastHint")}</p>
              </div>
              <div className="pf-template-grid">
                {inventoryTemplates.map((template) => renderTemplateCard(template, "fast"))}
                {utilityTemplate && (
                  <button
                    key={utilityTemplate.id}
                    type="button"
                    className="pf-template-card pf-template-card--fast"
                    onClick={() => applyTemplate(utilityTemplate)}
                  >
                    <span className="pf-template-card__title">
                      {t(`playbooks.templateNames.${utilityTemplate.id}`)}
                    </span>
                    <span className="pf-template-card__desc">
                      {t(`playbooks.templateDescriptions.${utilityTemplate.id}`)}
                    </span>
                    <span className="pf-template-card__action">{t("playbooks.useTemplate")}</span>
                  </button>
                )}
              </div>
            </section>
              </>
            )}

            {remediationTemplates.length > 0 ? (
              <section className="pf-template-group pf-template-group--extended">
                <div className="pf-template-group__header">
                  <h3 className="pf-template-group__title">{t("playbooks.templateGroupRemediation")}</h3>
                  <p className="pf-template-group__hint">{t("playbooks.templateGroupRemediationHint")}</p>
                </div>
                <div className="pf-template-grid">
                  {remediationTemplates.map((template) => renderTemplateCard(template, "extended"))}
                  {remediationTemplates.map((template) => renderTemplateCard(template, "fast"))}
                </div>
              </section>
            ) : null}
          </div>
        )}
      </Panel>

      {complianceTaskTemplates.length > 0 && (
        <Panel
          title={t("playbooks.complianceTaskTemplates")}
          className="pf-playbooks-templates pf-playbooks-compliance-tasks"
          noPadding
        >
          <div className="pf-filters">
            <div className="pf-filters__grid pf-filters__grid--playbooks-compliance">
              <div className="pf-filters__group">
                <label htmlFor="compliance-filter-search">{t("playbooks.complianceSearchLabel")}</label>
                <input
                  id="compliance-filter-search"
                  type="search"
                  className="pf-input"
                  value={complianceQuery}
                  onChange={(e) => {
                    setComplianceQuery(e.target.value);
                    setComplianceListExpanded(false);
                  }}
                  placeholder={t("playbooks.complianceSearch")}
                />
              </div>
              <div className="pf-filters__group">
                <label htmlFor="compliance-filter-category">{t("playbooks.complianceCategory")}</label>
                <select
                  id="compliance-filter-category"
                  className="pf-select"
                  value={complianceCategory}
                  onChange={(e) => {
                    setComplianceCategory(e.target.value as "all" | ComplianceTemplateCategory);
                    setComplianceListExpanded(false);
                  }}
                >
                  <option value="all">{t("playbooks.complianceCategoryAll")}</option>
                  {COMPLIANCE_CATEGORY_ORDER.map((key) => (
                    <option key={key} value={key}>
                      {t(`playbooks.complianceCategories.${key}`)}
                    </option>
                  ))}
                </select>
              </div>
              <div className="pf-filters__group">
                <label htmlFor="compliance-filter-profile">{t("playbooks.complianceListProfileFilter")}</label>
                <select
                  id="compliance-filter-profile"
                  className="pf-select"
                  value={complianceProfileFilter}
                  onChange={(e) => {
                    setComplianceProfileFilter(e.target.value);
                    setComplianceListExpanded(false);
                  }}
                >
                  <option value="all">{t("reports.allProfiles")}</option>
                  {complianceProfileOptions.map((label) => (
                    <option key={label} value={label}>
                      {label}
                    </option>
                  ))}
                </select>
              </div>
            </div>
            <div className="pf-filters__footer">
              <p className="pf-filters__summary">
                {hasActiveComplianceFilters
                  ? t("profiles.filterResultsActive", {
                      count: filteredComplianceTemplates.length,
                      total: complianceTaskTemplates.length,
                    })
                  : t("profiles.filterShown", {
                      count: filteredComplianceTemplates.length,
                      total: complianceTaskTemplates.length,
                    })}
              </p>
              {hasActiveComplianceFilters ? (
                <Button
                  variant="secondary"
                  className="pf-btn--sm"
                  type="button"
                  onClick={() => {
                    setComplianceQuery("");
                    setComplianceCategory("all");
                    setComplianceProfileFilter("all");
                    setComplianceListExpanded(false);
                  }}
                >
                  {t("profiles.clearFilters")}
                </Button>
              ) : null}
            </div>
          </div>

          <div className="pf-playbooks-compliance-tasks__bar-actions">
            <Button
              type="button"
              variant="secondary"
              className="pf-btn--sm"
              onClick={() =>
                setSelectedComplianceIds(filteredComplianceTemplates.map((item) => item.id))
              }
            >
              {t("playbooks.complianceSelectAll")}
            </Button>
            {selectedComplianceIds.length > 0 && (
              <>
                <Button
                  type="button"
                  variant="link"
                  className="pf-btn--sm"
                  onClick={() => setSelectedComplianceIds([])}
                >
                  {t("playbooks.complianceClearSelection")}
                </Button>
                <Button
                  type="button"
                  variant="danger-secondary"
                  className="pf-btn--sm"
                  onClick={() => void handleDeleteSelectedCompliance()}
                  disabled={deleteMutation.isPending}
                >
                  {t("playbooks.complianceDeleteSelected")}
                </Button>
              </>
            )}
          </div>

          {filteredComplianceTemplates.length === 0 ? (
            <EmptyState
              title={t("playbooks.complianceFilterEmpty")}
              description={t("jobs.noFilterResultsDesc")}
            />
          ) : (
            <div className="pf-table-wrap">
              <table className="pf-table pf-compliance-tasks-table">
                <thead>
                  <tr>
                    <th
                      scope="col"
                      className="pf-compliance-tasks-table__check"
                      aria-label={t("playbooks.complianceSelect")}
                    />
                    <th className="pf-compliance-tasks-table__name">{t("common.name")}</th>
                    <th className="pf-compliance-tasks-table__category">{t("playbooks.complianceCategory")}</th>
                    <th className="pf-compliance-tasks-table__version">{t("playbooks.complianceVersionLabel")}</th>
                    <th className="pf-compliance-tasks-table__actions">{t("common.actions")}</th>
                  </tr>
                </thead>
                <tbody>
                  {visibleComplianceTemplates.map((pb) => {
                    const selected = selectedComplianceIds.includes(pb.id);
                    const title = complianceDisplayName(pb.name, pb.profile_name);
                    const category = complianceTemplateCategory(pb.name, pb.profile_name);
                    return (
                      <tr
                        key={pb.id}
                        className={selected ? "pf-table__row--selected" : undefined}
                      >
                        <td className="pf-compliance-tasks-table__check">
                          <input
                            type="checkbox"
                            className="pf-checkbox-control"
                            checked={selected}
                            onChange={() => toggleComplianceSelected(pb.id)}
                            aria-label={t("playbooks.complianceSelect")}
                          />
                        </td>
                        <td className="pf-compliance-tasks-table__name">
                          <span className="pf-compliance-tasks-table__name-text" title={title}>
                            {title}
                          </span>
                        </td>
                        <td className="pf-compliance-tasks-table__category">
                          <span className="pf-compliance-tasks-table__category-text">
                            {t(`playbooks.complianceCategories.${category}`)}
                          </span>
                        </td>
                        <td className="pf-compliance-tasks-table__version">
                          <span className="pf-compliance-tasks-table__version-value">
                            {DEFAULT_PLAYBOOK_VERSION}
                          </span>
                        </td>
                        <td className="pf-compliance-tasks-table__actions">
                          <div className="pf-compliance-tasks-table__row-actions">
                            <Button
                              type="button"
                              variant="secondary"
                              className="pf-btn--sm"
                              onClick={() => openComplianceTemplate(pb.id)}
                            >
                              {t("playbooks.complianceEdit")}
                            </Button>
                            <Button
                              type="button"
                              variant="primary"
                              className="pf-btn--sm"
                              onClick={() => openComplianceTemplate(pb.id, { focusRun: true })}
                            >
                              {t("playbooks.complianceRun")}
                            </Button>
                            <Button
                              type="button"
                              variant="danger-secondary"
                              className="pf-btn--sm"
                              onClick={() => void handleDelete(pb.id)}
                              disabled={deleteMutation.isPending}
                            >
                              {t("playbooks.complianceDelete")}
                            </Button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}

          <OpsListExpandFooter
            shown={visibleComplianceTemplates.length}
            total={filteredComplianceTemplates.length}
            expanded={complianceListExpanded}
            onToggle={() => setComplianceListExpanded((value) => !value)}
          />

          {selectedComplianceIds.length > 0 && (
            <div className="pf-compliance-batch-run">
              <div className="pf-compliance-batch-run__head">
                <div>
                  <h3 className="pf-compliance-batch-run__title">
                    {t("playbooks.complianceRunSelected")}
                  </h3>
                  <p className="pf-compliance-batch-run__hint">
                    {t("playbooks.complianceSelectedCount", {
                      count: selectedComplianceIds.length,
                    })}
                    {" · "}
                    {t("playbooks.complianceRunSelectedHint")}
                  </p>
                </div>
                <Button
                  type="button"
                  className="pf-btn--sm"
                  disabled={
                    batchHostIds.length === 0 || runSelectedComplianceMutation.isPending
                  }
                  onClick={() =>
                    runSelectedComplianceMutation.mutate({
                      playbookIds: selectedComplianceIds,
                      ids: batchHostIds,
                      mode: batchConnectionMode,
                    })
                  }
                >
                  {runSelectedComplianceMutation.isPending
                    ? t("playbooks.complianceBatchRunning")
                    : t("playbooks.complianceRunSelected")}
                </Button>
              </div>
              <div className="pf-form__row" style={{ marginBottom: "0.75rem" }}>
                <div className="pf-form__group">
                  <label htmlFor="compliance-batch-connection-mode">
                    {t("playbooks.connectionMode")}
                  </label>
                  <select
                    id="compliance-batch-connection-mode"
                    className="pf-select"
                    value={batchConnectionMode}
                    onChange={(event) =>
                      setBatchConnectionMode(event.target.value as PlaybookConnectionMode)
                    }
                  >
                    <option value="auto">{t("playbooks.connectionAuto")}</option>
                    <option value="ssh">{t("playbooks.connectionSsh")}</option>
                    <option value="paramiko">{t("playbooks.connectionParamiko")}</option>
                    <option value="winrm">{t("playbooks.connectionWinrm")}</option>
                  </select>
                </div>
              </div>
              <HostPicker
                hosts={activeHosts}
                selectedIds={batchHostIds}
                onToggle={(id) =>
                  setBatchHostIds((prev) =>
                    prev.includes(id) ? prev.filter((hostId) => hostId !== id) : [...prev, id]
                  )
                }
                onSelectAll={(ids) => setBatchHostIds(ids)}
                onClearAll={() => setBatchHostIds([])}
                hint={t("playbooks.hostPickerHint")}
              />
            </div>
          )}
        </Panel>
      )}

      <Panel
        title={t("playbooks.list")}
        className="pf-playbooks-list-panel"
        noPadding
        toolbar={
          <Button variant="secondary" className="pf-btn--sm" onClick={startNewPlaybook}>
            {t("playbooks.newPlaybook")}
          </Button>
        }
      >
        {playbooks.isLoading ? (
          <Spinner />
        ) : userPlaybooks.length === 0 ? (
          <div className="pf-playbooks-list-empty">
            <EmptyState title={t("playbooks.none")} />
            <div className="pf-playbooks-list-empty__action">
              <Button onClick={startNewPlaybook}>{t("playbooks.newPlaybook")}</Button>
            </div>
          </div>
        ) : (
          <div className="pf-table-wrap">
            <table className="pf-table">
              <thead>
                <tr>
                  <th>{t("hosts.name")}</th>
                  <th>{t("playbooks.descriptionLabel")}</th>
                  <th className="pf-table__col-actions">{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {userPlaybooks.map((pb) => (
                  <tr key={pb.id}>
                    <td>
                      <div className="pf-playbooks-list__name">{pb.name}</div>
                    </td>
                    <td>
                      <div className="pf-table__muted pf-playbooks-list__desc">
                        {pb.description || t("common.dash")}
                      </div>
                    </td>
                    <td className="pf-table__col-actions">
                      <div className="pf-table__actions pf-playbook-run-actions">
                        <Button
                          type="button"
                          variant="secondary"
                          className="pf-btn--sm"
                          onClick={() => loadPlaybook(pb.id)}
                        >
                          {t("playbooks.editPlaybook")}
                        </Button>
                        <Button
                          type="button"
                          variant="danger-secondary"
                          className="pf-btn--sm"
                          onClick={() => handleDelete(pb.id)}
                          disabled={deleteMutation.isPending}
                        >
                          {t("common.delete")}
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {deleteMutation.isError && (
          <div className="pf-alert pf-alert--error" style={{ margin: "1rem" }}>
            {(deleteMutation.error as Error).message}
          </div>
        )}
      </Panel>
        </>
      ) : (
        <div className="pf-playbooks-editor-view">
        <Panel
          title={selectedId ? t("playbooks.editor", { name }) : t("playbooks.new")}
          className="pf-playbooks-editor-panel"
          collapsible={false}
          toolbar={
            <div className="pf-playbooks-editor-view__toolbar">
              <Button variant="secondary" className="pf-btn--sm" onClick={closeEditor}>
                {t("playbooks.backToList")}
              </Button>
              {utilityTemplate && (
                <Button
                  variant="secondary"
                  className="pf-btn--sm"
                  onClick={() => applyTemplate(utilityTemplate)}
                >
                  {t("playbooks.createFromTemplate")}
                </Button>
              )}
            </div>
          }
        >
          <div className="pf-playbooks-editor-form pf-form pf-form--wide">
            {editingComplianceTemplate ? (
              <div className="pf-compliance-editor-bar">
                <div className="pf-compliance-editor-bar__identity">
                  <span className="pf-compliance-editor-bar__kind">
                    {t("playbooks.complianceTaskTemplates")}
                  </span>
                  <h3 className="pf-compliance-editor-bar__name">{name}</h3>
                  <div className="pf-compliance-editor-bar__meta">
                    <span className="pf-profiles-imported-table__version-value">
                      v{formatPlaybookVersion(playbookVersion)}
                    </span>
                    {selectedPlaybook?.updated_at ? (
                      <time
                        className="pf-compliance-editor-bar__date"
                        dateTime={selectedPlaybook.updated_at}
                      >
                        {formatPlaybookDate(selectedPlaybook.updated_at, dateLocale)}
                      </time>
                    ) : null}
                    {selectedPlaybook?.profile_name ? (
                      <span className="pf-compliance-editor-bar__profile">
                        {t("playbooks.complianceFromProfile", {
                          label: selectedPlaybook.profile_name,
                        })}
                      </span>
                    ) : null}
                  </div>
                </div>
                <div className="pf-compliance-editor-bar__actions">
                  <Button
                    type="button"
                    variant="secondary"
                    className="pf-btn--sm"
                    onClick={() => setShowPlaybookChangelog(true)}
                  >
                    {t("playbooks.complianceChangelog")}
                  </Button>
                  <Button
                    className="pf-btn--sm"
                    onClick={handleSavePlaybook}
                    disabled={updateContentMutation.isPending}
                  >
                    {t("playbooks.complianceSaveVersioned")}
                  </Button>
                </div>
              </div>
            ) : (
              <>
                <div className="pf-form__row">
                  <div className="pf-form__group">
                    <label htmlFor="playbook-name">{t("hosts.name")}</label>
                    <input
                      id="playbook-name"
                      className="pf-input"
                      value={name}
                      onChange={(event) => setName(event.target.value)}
                    />
                  </div>
                  <div className="pf-form__group">
                    <label htmlFor="playbook-description">{t("playbooks.descriptionLabel")}</label>
                    <input
                      id="playbook-description"
                      className="pf-input"
                      value={description}
                      onChange={(event) => setDescription(event.target.value)}
                    />
                  </div>
                </div>
                <div className="pf-form__actions">
                  {selectedId ? (
                    <Button
                      onClick={handleSavePlaybook}
                      disabled={updateMutation.isPending || updateContentMutation.isPending}
                    >
                      {t("common.save")}
                    </Button>
                  ) : (
                    <Button
                      onClick={handleSavePlaybook}
                      disabled={!name || !content || createMutation.isPending}
                    >
                      {t("common.create")}
                    </Button>
                  )}
                  {selectedId && (
                    <Button
                      type="button"
                      variant="danger-secondary"
                      className="pf-btn--sm"
                      onClick={() => handleDelete(selectedId)}
                      disabled={deleteMutation.isPending}
                    >
                      {t("common.delete")}
                    </Button>
                  )}
                </div>
              </>
            )}
            {showPlaybookChangelog && editingComplianceTemplate && (
              <div className="pf-playbook-changelog">
                <div className="pf-playbook-changelog__head">
                  <h4 className="pf-playbook-changelog__title">
                    {t("playbooks.complianceChangelog")}
                  </h4>
                  <Button
                    type="button"
                    variant="secondary"
                    className="pf-btn--sm"
                    onClick={() => setShowPlaybookChangelog(false)}
                  >
                    {t("playbooks.complianceChangelogClose")}
                  </Button>
                </div>
                {playbookChangelog.isLoading && <Spinner />}
                {playbookChangelog.isError && (
                  <div className="pf-alert pf-alert--error">
                    {(playbookChangelog.error as Error).message}
                  </div>
                )}
                {playbookChangelog.data && playbookChangelog.data.length === 0 && (
                  <p className="pf-playbook-changelog__empty">
                    {t("playbooks.complianceChangelogEmpty")}
                  </p>
                )}
                {playbookChangelog.data && playbookChangelog.data.length > 0 && (
                  <div className="pf-playbook-changelog__groups">
                    {groupPlaybookChangelog(playbookChangelog.data).map((group) => (
                      <section key={group.version} className="pf-playbook-changelog__group">
                        <header className="pf-playbook-changelog__group-head">
                          <span className="pf-playbook-changelog__version">
                            {t("playbooks.complianceChangelogVersion", {
                              version: group.version,
                            })}
                          </span>
                          <span className="pf-playbook-changelog__count">
                            {group.entries.length}
                          </span>
                        </header>
                        <div className="pf-playbook-changelog__entries">
                          {group.entries.map((entry) => {
                            const contentChange = entry.changes.content;
                            const fromText = contentChange?.from ?? "";
                            const toText = contentChange?.to ?? "";
                            const hasDiff = Boolean(contentChange);
                            const stats = hasDiff
                              ? lineDiffStats(fromText, toText)
                              : { added: 0, removed: 0 };
                            const expanded = expandedChangelogIds.has(entry.id);
                            const diffLines =
                              expanded && hasDiff
                                ? buildUnifiedDiff(fromText, toText, {
                                    context: 2,
                                    maxLines: 180,
                                  })
                                : [];
                            const atLabel = formatPlaybookDate(entry.at, dateLocale);
                            return (
                              <article key={entry.id} className="pf-playbook-changelog__entry">
                                <div className="pf-playbook-changelog__entry-head">
                                  <div className="pf-playbook-changelog__entry-meta">
                                    <time dateTime={entry.at}>{atLabel}</time>
                                    {entry.actor ? <span>{entry.actor}</span> : null}
                                    {entry.playbook_version_before &&
                                    entry.playbook_version_after ? (
                                      <span className="pf-playbook-changelog__bump">
                                        {formatPlaybookVersion(entry.playbook_version_before)} →{" "}
                                        {formatPlaybookVersion(entry.playbook_version_after)}
                                      </span>
                                    ) : null}
                                  </div>
                                  {hasDiff ? (
                                    <span className="pf-playbook-changelog__stats">
                                      {t("playbooks.complianceChangelogStats", {
                                        added: stats.added,
                                        removed: stats.removed,
                                      })}
                                    </span>
                                  ) : null}
                                </div>
                                {hasDiff ? (
                                  <div className="pf-playbook-changelog__change">
                                    <div className="pf-playbook-changelog__change-head">
                                      <span className="pf-playbook-changelog__field">
                                        {t("playbooks.complianceChangelogContent")}
                                      </span>
                                      <button
                                        type="button"
                                        className="pf-playbook-changelog__toggle"
                                        onClick={() => toggleChangelogExpanded(entry.id)}
                                      >
                                        {expanded
                                          ? t("playbooks.complianceChangelogHideDiff")
                                          : t("playbooks.complianceChangelogShowDiff")}
                                      </button>
                                    </div>
                                    {expanded ? (
                                      diffLines.length > 0 ? (
                                        <pre className="pf-playbook-changelog__diff">
                                          {diffLines.map((line, index) => (
                                            <span
                                              key={`${entry.id}-${index}`}
                                              className={`pf-playbook-changelog__diff-line pf-playbook-changelog__diff-line--${line.kind}`}
                                            >
                                              {line.kind === "add"
                                                ? "+"
                                                : line.kind === "del"
                                                  ? "-"
                                                  : " "}
                                              {line.text}
                                            </span>
                                          ))}
                                        </pre>
                                      ) : (
                                        <p className="pf-playbook-changelog__empty">
                                          {t("playbooks.complianceChangelogNoDiff")}
                                        </p>
                                      )
                                    ) : null}
                                  </div>
                                ) : (
                                  <p className="pf-playbook-changelog__empty">
                                    {t("playbooks.complianceChangelogNoDiff")}
                                  </p>
                                )}
                              </article>
                            );
                          })}
                        </div>
                      </section>
                    ))}
                  </div>
                )}
              </div>
            )}
            {deleteMutation.isError && (
              <div className="pf-alert pf-alert--error">{deleteMutation.error.message}</div>
            )}
          </div>

          <div className="pf-playbook-editor-workspace">
            <div className="pf-playbook-editor-workspace__header">
              <div>
                <h3 className="pf-playbook-editor-workspace__title">{t("playbooks.yamlEditor")}</h3>
                <p className="pf-playbook-editor-workspace__subtitle">
                  <span className="pf-table__mono">
                    {t("playbooks.yamlFile", { name: slugifyName(name) || "playbook" })}
                  </span>
                </p>
              </div>
              <div className="pf-playbook-editor-workspace__actions">
                <Button
                  variant="secondary"
                  className="pf-btn--sm"
                  onClick={() => validateMutation.mutate()}
                  disabled={validateMutation.isPending || !content}
                >
                  {t("playbooks.validateSyntax")}
                </Button>
                <Button
                  variant="secondary"
                  className="pf-btn--sm"
                  onClick={() => setEditorModalOpen(true)}
                  disabled={!content && !name}
                >
                  {t("playbooks.expandEditor")}
                </Button>
              </div>
            </div>

            {renderValidationAlert()}

            <div className="pf-modal__editor pf-playbook-editor">
              {renderYamlEditor("calc(100dvh - 24rem)")}
            </div>
          </div>
        </Panel>

      {selectedId && (
        <Panel title={t("playbooks.runTitle")} className="pf-playbooks-run">
          <p className="pf-form__hint" style={{ marginTop: 0 }}>
            {t("playbooks.runHint")}
          </p>
          <div className="pf-form__row" style={{ marginBottom: "1rem" }}>
            <div className="pf-form__group">
              <label htmlFor="playbook-connection-mode">{t("playbooks.connectionMode")}</label>
              <select
                id="playbook-connection-mode"
                className="pf-select"
                value={connectionMode}
                onChange={(event) =>
                  setConnectionMode(event.target.value as PlaybookConnectionMode)
                }
              >
                <option value="auto">{t("playbooks.connectionAuto")}</option>
                <option value="ssh">{t("playbooks.connectionSsh")}</option>
                <option value="paramiko">{t("playbooks.connectionParamiko")}</option>
                <option value="winrm">{t("playbooks.connectionWinrm")}</option>
              </select>
              <p className="pf-form__hint">{t("playbooks.connectionModeHint")}</p>
            </div>
          </div>
          <HostPicker
            hosts={activeHosts}
            selectedIds={hostIds}
            onToggle={toggleHost}
            onSelectAll={(ids) => setHostIds(ids)}
            onClearAll={() => setHostIds([])}
            hint={t("playbooks.hostPickerHint")}
          />
          <div className="pf-form__actions" style={{ marginTop: "1rem" }}>
            <Button
              onClick={() =>
                runMutation.mutate({ playbookId: selectedId, ids: hostIds, mode: connectionMode })
              }
              disabled={!canExecute || !hostIds.length || runMutation.isPending}
              title={!canExecute ? t("common.demoActionDisabled") : undefined}
            >
              {runMutation.isPending ? t("playbooks.running") : t("playbooks.runPlaybook")}
            </Button>
          </div>
          {runMutation.isError && (
            <div className="pf-alert pf-alert--error">{(runMutation.error as Error).message}</div>
          )}
        </Panel>
      )}

      {selectedId && (
        <Panel title={t("playbooks.runHistory")} noPadding>
          {renderRunsTable(playbookRuns.data, { isLoading: playbookRuns.isLoading })}
          {deleteRunMutation.isError && (
            <div className="pf-alert pf-alert--error" style={{ margin: "1rem" }}>
              {(deleteRunMutation.error as Error).message}
            </div>
          )}
        </Panel>
      )}

      {renderRunResultsPanel()}
        </div>
      )}

      {editorOpen && editorModalOpen && (
        <div
          className="pf-modal pf-modal--script"
          role="presentation"
          onClick={() => setEditorModalOpen(false)}
        >
          <div
            className="pf-modal__panel pf-modal__panel--script"
            role="dialog"
            aria-modal="true"
            aria-label={t("playbooks.yamlEditor")}
            onClick={(event) => event.stopPropagation()}
          >
            <div className="pf-modal__header">
              <div>
                <h3 className="pf-modal__title">{t("playbooks.yamlEditor")}</h3>
                <p className="pf-modal__subtitle">
                  {name}
                  {" · "}
                  <span className="pf-table__mono">{yamlFileName}</span>
                </p>
              </div>
              <div className="pf-playbook-editor-workspace__actions">
                <Button
                  onClick={handleSavePlaybook}
                  disabled={
                    selectedId
                      ? updateMutation.isPending
                      : !name || !content || createMutation.isPending
                  }
                >
                  {selectedId ? t("common.save") : t("common.create")}
                </Button>
                <Button
                  variant="secondary"
                  className="pf-btn--sm"
                  onClick={() => validateMutation.mutate()}
                  disabled={validateMutation.isPending || !content}
                >
                  {t("playbooks.validateSyntax")}
                </Button>
                <Button variant="secondary" className="pf-btn--sm" onClick={() => setEditorModalOpen(false)}>
                  {t("common.cancel")}
                </Button>
              </div>
            </div>

            {renderValidationAlert()}

            <div className="pf-modal__editor pf-modal__editor--script">
              {renderYamlEditor("calc(100dvh - 10.5rem)")}
            </div>
          </div>
        </div>
      )}
    </>
  );
}
