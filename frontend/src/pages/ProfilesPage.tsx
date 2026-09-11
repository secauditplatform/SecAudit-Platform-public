import Editor from "@monaco-editor/react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, type CheckScript, type ProfileDependencies, type ProfileRule, type ProfileRuleChangelogEntry, type ProfileRuleUpdate } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import {
  ProfileRuleMetadata,
  ProfileRuleSeverityChip,
  hasProfileRuleMetadata,
  profileRuleDisplayName,
} from "../components/ProfileRuleDetail";
import { ProfilesCatalogPanel } from "../components/ProfilesCatalogPanel";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { EmptyState } from "../components/ui/EmptyState";
import { FileUploadZone } from "../components/ui/FileUploadZone";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { Spinner } from "../components/ui/Spinner";
import { StatTile } from "../components/ui/StatTile";
import { useConfirm } from "../components/ui/ConfirmDialog";
import { useToast } from "../components/ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";
import { summarizeProfileRuleSeverities } from "../utils/profileRuleSeverity";

function parseProfileId(value: string | null): number | null {
  if (!value) return null;
  const id = Number(value);
  return Number.isInteger(id) && id > 0 ? id : null;
}

function scriptEditorLanguage(executionType: string): string {
  switch (executionType.toUpperCase()) {
    case "WINRM":
    case "POWERSHELL":
      return "powershell";
    case "PYTHON":
      return "python";
    case "ANSIBLE":
      return "yaml";
    default:
      return "shell";
  }
}

function formatExecutionType(type: string): string {
  return type.toLowerCase();
}

function scriptContentErrorMessage(error: Error, t: (key: string) => string): string {
  const message = error.message;
  if (message.includes("Insufficient permissions") || message.includes("403")) {
    return t("profiles.scriptAccessDenied");
  }
  if (message) {
    return message;
  }
  return t("profiles.fileNotFound");
}

function profileRuleKey(rule: ProfileRule, index: number): string {
  return `${rule.num ?? index + 1}:${rule.requirement_id}`;
}

function ruleEditDraft(rule: ProfileRule): ProfileRuleUpdate {
  return {
    title: rule.title ?? "",
    explanation: rule.explanation ?? "",
    impact: rule.impact ?? "",
    scope: rule.scope ?? "",
  };
}

function formatChangelogAt(value: string): string {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}

const RULE_FIELD_LABELS = {
  title: "ruleSummary",
  explanation: "ruleDescription",
  impact: "ruleRisk",
  scope: "ruleLocation",
} as const;

type ChangelogGroup = {
  version: string;
  entries: ProfileRuleChangelogEntry[];
};

function groupChangelogByVersion(entries: ProfileRuleChangelogEntry[]): ChangelogGroup[] {
  const groups = new Map<string, ChangelogGroup>();
  for (const entry of entries) {
    const version = entry.profile_version_after?.trim() || entry.profile_version_before?.trim() || "—";
    const existing = groups.get(version);
    if (existing) {
      existing.entries.push(entry);
    } else {
      groups.set(version, { version, entries: [entry] });
    }
  }
  return Array.from(groups.values());
}

export function ProfilesPage() {
  const { t } = useTranslation();
  const { confirm } = useConfirm();
  const toast = useToast();
  const { isAdmin, canOperate } = useAuth();
  const queryClient = useQueryClient();
  const [searchParams, setSearchParams] = useSearchParams();
  const detailPanelRef = useRef<HTMLElement>(null);
  const [showImport, setShowImport] = useState(false);
  const [showCatalog, setShowCatalog] = useState(false);
  const [importFiles, setImportFiles] = useState<File[]>([]);
  const [compliancePlaybookFile, setCompliancePlaybookFile] = useState<File | null>(null);
  const [scapProfiles, setScapProfiles] = useState<
    Array<{ profile_id: string; title: string; profile_family: string; benchmark_title: string }>
  >([]);
  const [selectedScapProfileId, setSelectedScapProfileId] = useState("");
  const [filterName, setFilterName] = useState("");
  const [filterCategory, setFilterCategory] = useState("all");
  const [filterVersion, setFilterVersion] = useState("");
  const [filterStatus, setFilterStatus] = useState<"all" | "active" | "inactive">("all");
  const [selectedProfileIds, setSelectedProfileIds] = useState<Set<number>>(new Set());
  const [bulkPending, setBulkPending] = useState(false);
  const [viewingScript, setViewingScript] = useState<CheckScript | null>(null);
  const [editedContent, setEditedContent] = useState("");
  const [isDirty, setIsDirty] = useState(false);
  const [saveStatus, setSaveStatus] = useState<"success" | "error" | null>(null);
  const [expandedRuleKey, setExpandedRuleKey] = useState<string | null>(null);
  const [editingRuleKey, setEditingRuleKey] = useState<string | null>(null);
  const [ruleDraft, setRuleDraft] = useState<ProfileRuleUpdate | null>(null);
  const [showRuleChangelog, setShowRuleChangelog] = useState(false);

  const urlProfileId = parseProfileId(searchParams.get("id"));
  const [selectedProfileId, setSelectedProfileId] = useState<number | null>(urlProfileId);

  const profiles = useQuery({
    queryKey: ["profiles"],
    queryFn: () => api.profiles(),
  });

  const categoryOptions = useMemo(() => {
    const names = new Set<string>();
    profiles.data?.forEach((std) => {
      if (std.category_name) names.add(std.category_name);
    });
    return Array.from(names).sort((a, b) => a.localeCompare(b));
  }, [profiles.data]);

  const filteredProfiles = useMemo(() => {
    const list = profiles.data ?? [];
    const nameQuery = filterName.trim().toLowerCase();
    const versionQuery = filterVersion.trim().toLowerCase();

    return list.filter((std) => {
      if (nameQuery && !std.profile_name.toLowerCase().includes(nameQuery)) return false;
      if (filterCategory !== "all" && std.category_name !== filterCategory) return false;
      if (versionQuery && !std.version.toLowerCase().includes(versionQuery)) return false;
      if (filterStatus === "active" && !std.is_active) return false;
      if (filterStatus === "inactive" && std.is_active) return false;
      return true;
    });
  }, [profiles.data, filterName, filterCategory, filterVersion, filterStatus]);

  const hasActiveFilters =
    filterName.trim() !== "" ||
    filterCategory !== "all" ||
    filterVersion.trim() !== "" ||
    filterStatus !== "all";

  const clearFilters = () => {
    setFilterName("");
    setFilterCategory("all");
    setFilterVersion("");
    setFilterStatus("all");
  };

  const toggleProfileSelection = (profileId: number) => {
    setSelectedProfileIds((prev) => {
      const next = new Set(prev);
      if (next.has(profileId)) next.delete(profileId);
      else next.add(profileId);
      return next;
    });
  };

  const toggleSelectAllFiltered = () => {
    const ids = filteredProfiles.map((std) => std.id);
    const allSelected = ids.length > 0 && ids.every((id) => selectedProfileIds.has(id));
    if (allSelected) {
      setSelectedProfileIds(new Set());
      return;
    }
    setSelectedProfileIds(new Set(ids));
  };

  const invalidateAfterProfileDelete = () => {
    queryClient.invalidateQueries({ queryKey: ["profiles"] });
    queryClient.invalidateQueries({ queryKey: ["profiles-catalog"] });
    queryClient.invalidateQueries({ queryKey: ["jobs"] });
    queryClient.invalidateQueries({ queryKey: ["job-runs"] });
    queryClient.invalidateQueries({ queryKey: ["runs"] });
    queryClient.invalidateQueries({ queryKey: ["remediations"] });
    queryClient.invalidateQueries({ queryKey: ["remediation-runs"] });
    queryClient.invalidateQueries({ queryKey: ["waivers"] });
    queryClient.invalidateQueries({ queryKey: ["scheduled-reports"] });
    queryClient.invalidateQueries({ queryKey: ["job-templates"] });
  };

  const hasDeleteDependencies = (deps: ProfileDependencies) =>
    deps.jobs > 0 || deps.remediation_jobs > 0 || deps.waivers > 0;

  const confirmCascadeDelete = async (
    deps: ProfileDependencies,
    options: { name?: string; count?: number }
  ) => {
    const jobsTotal = deps.jobs + deps.remediation_jobs;
    return confirm({
      title: t("common.confirm"),
      message:
        options.name != null
          ? t("profiles.deleteCascadeConfirm", {
              name: options.name,
              jobs: jobsTotal,
              runs: deps.job_runs + deps.remediation_runs,
              results: deps.check_results,
              waivers: deps.waivers,
            })
          : t("profiles.bulkDeleteCascadeConfirm", {
              count: options.count ?? 0,
              jobs: jobsTotal,
              runs: deps.job_runs + deps.remediation_runs,
              results: deps.check_results,
              waivers: deps.waivers,
            }),
      subtitle: t("profiles.deleteCascadeWarning"),
      confirmLabel: t("profiles.deleteCascadeAction"),
      cancelLabel: t("common.cancel"),
      variant: "danger",
    });
  };

  const runBulkAction = async (
    action: "enable" | "disable" | "delete" | "sync"
  ) => {
    const ids = Array.from(selectedProfileIds);
    if (ids.length === 0) return;
    if (action === "delete") {
      const ok = await confirm({
        title: t("common.confirm"),
        message: t("profiles.bulkDeleteConfirm", { count: ids.length }),
        variant: "danger",
        confirmLabel: t("common.delete"),
      });
      if (!ok) return;
    }
    setBulkPending(true);
    try {
      let result =
        action === "enable"
          ? await api.bulkEnableProfiles(ids)
          : action === "disable"
            ? await api.bulkDisableProfiles(ids)
            : action === "delete"
              ? await api.bulkDeleteProfiles(ids)
              : await api.bulkSyncProfiles(ids);

      if (action === "delete") {
        const blocked = result.failed.filter(
          (item) => item.code === "profile_has_dependencies" && item.dependencies
        );
        if (blocked.length > 0) {
          const aggregated: ProfileDependencies = {
            jobs: 0,
            remediation_jobs: 0,
            waivers: 0,
            job_runs: 0,
            check_results: 0,
            remediation_runs: 0,
            active_runs: 0,
          };
          for (const item of blocked) {
            const deps = item.dependencies!;
            aggregated.jobs += deps.jobs;
            aggregated.remediation_jobs += deps.remediation_jobs;
            aggregated.waivers += deps.waivers;
            aggregated.job_runs += deps.job_runs;
            aggregated.check_results += deps.check_results;
            aggregated.remediation_runs += deps.remediation_runs;
            aggregated.active_runs += deps.active_runs;
          }
          if (aggregated.active_runs > 0) {
            toast.error(t("profiles.deleteActiveRunsBlock"));
            invalidateAfterProfileDelete();
            setSelectedProfileIds(new Set());
            return;
          }
          const cascadeOk = await confirmCascadeDelete(aggregated, {
            count: blocked.length,
          });
          if (cascadeOk) {
            const cascadeResult = await api.bulkDeleteProfiles(
              blocked.map((item) => item.profile_id),
              { cascade: true }
            );
            result = {
              succeeded: [...result.succeeded, ...cascadeResult.succeeded],
              failed: [
                ...result.failed.filter((item) => item.code !== "profile_has_dependencies"),
                ...cascadeResult.failed,
              ],
            };
          }
        }
        invalidateAfterProfileDelete();
      } else {
        queryClient.invalidateQueries({ queryKey: ["profiles"] });
        queryClient.invalidateQueries({ queryKey: ["profiles-catalog"] });
      }
      setSelectedProfileIds(new Set());
      if (result.failed.length > 0) {
        toast.error(
          t("profiles.bulkPartial", {
            succeeded: result.succeeded.length,
            failed: result.failed.length,
          })
        );
      } else {
        toast.success(t(`profiles.bulkSuccess.${action}`, { count: result.succeeded.length }));
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("toast.genericError"));
    } finally {
      setBulkPending(false);
    }
  };

  const activeProfileId = useMemo(() => {
    if (selectedProfileId == null) return null;
    if ((profiles.data ?? []).some((std) => std.id === selectedProfileId)) {
      return selectedProfileId;
    }
    return null;
  }, [selectedProfileId, profiles.data]);

  useEffect(() => {
    if (urlProfileId == null || !profiles.data) return;
    if (!profiles.data.some((std) => std.id === urlProfileId)) return;
    setSelectedProfileId(urlProfileId);
  }, [urlProfileId, profiles.data]);

  useEffect(() => {
    if (urlProfileId == null || activeProfileId !== urlProfileId) return;
    requestAnimationFrame(() => {
      detailPanelRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  }, [urlProfileId, activeProfileId]);

  const selectProfile = (profileId: number) => {
    setSelectedProfileId(profileId);
    setSearchParams({ id: String(profileId) }, { replace: true });
    requestAnimationFrame(() => {
      detailPanelRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };

  const detail = useQuery({
    queryKey: ["profile-detail", activeProfileId],
    queryFn: () => api.getProfile(activeProfileId!),
    enabled: activeProfileId !== null,
  });

  const profileRules = useQuery({
    queryKey: ["profile-rules", activeProfileId],
    queryFn: () => api.getProfileRules(activeProfileId!),
    enabled: activeProfileId !== null,
  });

  const ruleSeverityStats = useMemo(
    () => summarizeProfileRuleSeverities(profileRules.data ?? []),
    [profileRules.data]
  );

  const ruleChangelog = useQuery({
    queryKey: ["profile-rule-changelog", activeProfileId],
    queryFn: () => api.getProfileRuleChangelog(activeProfileId!),
    enabled: activeProfileId !== null && showRuleChangelog,
  });

  const scriptContent = useQuery({
    queryKey: ["profile-script-content", activeProfileId, viewingScript?.id],
    queryFn: () => api.getCheckScriptContent(activeProfileId!, viewingScript!.id),
    enabled: activeProfileId !== null && viewingScript !== null && isAdmin,
    retry: false,
  });

  useEffect(() => {
    setViewingScript(null);
    setEditedContent("");
    setIsDirty(false);
    setSaveStatus(null);
    setExpandedRuleKey(null);
    setEditingRuleKey(null);
    setRuleDraft(null);
    setShowRuleChangelog(false);
  }, [activeProfileId]);

  useEffect(() => {
    if (scriptContent.data) {
      setEditedContent(scriptContent.data.content);
      setIsDirty(false);
      setSaveStatus(null);
    }
  }, [scriptContent.data]);

  useEffect(() => {
    if (!showRuleChangelog) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setShowRuleChangelog(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [showRuleChangelog]);

  const saveScriptMutation = useMutation({
    mutationFn: () => {
      if (!isAdmin || activeProfileId == null || viewingScript == null) {
        return Promise.reject(new Error("Forbidden"));
      }
      return api.updateCheckScriptContent(activeProfileId, viewingScript.id, editedContent);
    },
    onSuccess: (data) => {
      queryClient.setQueryData(
        ["profile-script-content", activeProfileId, viewingScript?.id],
        data
      );
      setEditedContent(data.content);
      setIsDirty(false);
      setSaveStatus("success");
    },
    onError: () => {
      setSaveStatus("error");
    },
  });

  const saveRuleMutation = useMutation({
    mutationFn: ({
      requirementId,
      data,
    }: {
      requirementId: string;
      data: ProfileRuleUpdate;
    }) => {
      if (!canOperate || activeProfileId == null) {
        return Promise.reject(new Error("Forbidden"));
      }
      return api.updateProfileRule(activeProfileId, requirementId, data);
    },
    onSuccess: () => {
      setEditingRuleKey(null);
      setRuleDraft(null);
      queryClient.invalidateQueries({ queryKey: ["profile-rules", activeProfileId] });
      queryClient.invalidateQueries({ queryKey: ["profile-detail", activeProfileId] });
      queryClient.invalidateQueries({ queryKey: ["profiles"] });
      queryClient.invalidateQueries({ queryKey: ["profile-rule-changelog", activeProfileId] });
      toast.success(t("profiles.saveRuleSuccess"));
    },
    onError: (err) =>
      toast.error(err instanceof Error ? err.message : t("profiles.saveRuleFailed")),
  });

  const importMutation = useMutation({
    mutationFn: (payload: {
      files: File[];
      scapProfileId?: string;
      compliancePlaybook?: File | null;
    }) =>
      api.importProfilePackage(
        payload.files,
        undefined,
        payload.scapProfileId,
        payload.compliancePlaybook
      ),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["profiles"] });
      queryClient.invalidateQueries({ queryKey: ["profiles-catalog"] });
      queryClient.invalidateQueries({ queryKey: ["playbooks"] });
      setImportFiles([]);
      setCompliancePlaybookFile(null);
      setScapProfiles([]);
      setSelectedScapProfileId("");
      setShowImport(false);
      toast.success(t("toast.profileImported"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteMutation = useMutation({
    mutationFn: ({ id, cascade }: { id: number; cascade: boolean }) =>
      api.deleteProfile(id, { cascade }),
    onSuccess: (_data, variables) => {
      invalidateAfterProfileDelete();
      if (activeProfileId === variables.id) {
        setSelectedProfileId(null);
        setSearchParams({}, { replace: true });
      }
      toast.success(t("toast.profileDeleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const handleDelete = async (id: number, name: string) => {
    try {
      const deps = await api.getProfileDependencies(id);
      if (deps.active_runs > 0) {
        toast.error(t("profiles.deleteActiveRunsBlock"));
        return;
      }
      if (hasDeleteDependencies(deps)) {
        const ok = await confirmCascadeDelete(deps, { name });
        if (!ok) return;
        deleteMutation.mutate({ id, cascade: true });
        return;
      }
      const ok = await confirm({
        title: t("common.confirm"),
        message: t("profiles.deleteConfirm", { name }),
        confirmLabel: t("common.delete"),
        variant: "danger",
      });
      if (!ok) return;
      deleteMutation.mutate({ id, cascade: false });
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("toast.genericError"));
    }
  };

  const canImport = importFiles.length > 0;

  const handleImportFilesChange = async (files: File[]) => {
    setImportFiles(files);
    setScapProfiles([]);
    setSelectedScapProfileId("");
    if (files.length === 0) return;
    const hasScap = files.some((file) => /\.(xml|xccdf|zip)$/i.test(file.name));
    if (!hasScap) return;
    try {
      const profiles = await api.previewScapProfiles(files);
      setScapProfiles(profiles);
      if (profiles.length === 1) {
        setSelectedScapProfileId(profiles[0].profile_id);
      }
    } catch {
      setScapProfiles([]);
    }
  };

  const selectedProfile = profiles.data?.find((std) => std.id === activeProfileId);

  const openScriptViewer = (script: CheckScript) => {
    if (!isAdmin) return;
    setViewingScript(script);
    setEditedContent("");
    setIsDirty(false);
    setSaveStatus(null);
  };

  const closeScriptViewer = async () => {
    if (isDirty) {
      const ok = await confirm({
        title: t("common.confirm"),
        message: t("profiles.unsavedChanges"),
        variant: "warning",
      });
      if (!ok) return;
    }
    setViewingScript(null);
    setEditedContent("");
    setIsDirty(false);
    setSaveStatus(null);
  };

  useEffect(() => {
    if (!viewingScript) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") closeScriptViewer();
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [viewingScript, isDirty]);

  return (
    <>
      <PageHeader title={t("profiles.title")} description={t("profiles.description")} />

      <Panel
        title={t("profiles.imported")}
        toolbar={
          <Button variant="secondary" className="pf-btn--sm" onClick={() => setShowImport((open) => !open)}>
            {showImport ? t("profiles.hideImport") : t("profiles.importPackage")}
          </Button>
        }
        noPadding
      >
        {showImport && (
          <div className="pf-import-panel">
            <section className="pf-import-panel__section" aria-labelledby="import-package-heading">
              <div className="pf-import-panel__section-head">
                <h3 id="import-package-heading" className="pf-import-panel__section-title">
                  {t("profiles.importPackageSection")}
                </h3>
                <p className="pf-import-panel__section-desc">{t("profiles.uploadPackageHint")}</p>
              </div>

              <FileUploadZone
                id="import-files"
                label={t("profiles.uploadPackage")}
                accept=".zip,.tar,.tar.gz,.tgz,.xml,.xccdf,.json,.sh,.py,.ps1"
                formatLabels={[
                  t("profiles.uploadFormatArchive"),
                  t("profiles.uploadFormatScap"),
                  t("profiles.uploadFormatPackage"),
                ]}
                files={importFiles}
                onFilesChange={handleImportFilesChange}
                disabled={importMutation.isPending}
                variant="profiles"
              />
            </section>

            <section
              className="pf-import-panel__section pf-import-panel__section--requirements"
              aria-label={t("profiles.packageStructureTitle")}
            >
              <div className="pf-import-panel__section-head">
                <h3 className="pf-import-panel__section-title">{t("profiles.packageStructureTitle")}</h3>
              </div>
              <div className="pf-import-panel__requirements">
                <div className="pf-import-panel__req-row">
                  <span className="pf-import-panel__req-label">{t("profiles.packageStructureRequired")}</span>
                  <div className="pf-import-panel__chips">
                    <span className="pf-import-panel__chip" title={t("profiles.packageFileDescription")}>
                      description.json
                    </span>
                    <span className="pf-import-panel__chip" title={t("profiles.packageFileRules")}>
                      profile_rules.json
                    </span>
                    <span className="pf-import-panel__chip" title={t("profiles.packageFileScript")}>
                      *.sh / *.py / *.ps1
                    </span>
                  </div>
                </div>
                <div className="pf-import-panel__req-row">
                  <span className="pf-import-panel__req-label">{t("profiles.packageStructureOptional")}</span>
                  <div className="pf-import-panel__chips">
                    <span
                      className="pf-import-panel__chip pf-import-panel__chip--muted"
                      title={t("profiles.packageFileRemediation")}
                    >
                      *_remediation*
                    </span>
                    <span
                      className="pf-import-panel__chip pf-import-panel__chip--muted"
                      title={t("profiles.packageFileCompliancePlaybook")}
                    >
                      *_compliance.yml
                    </span>
                  </div>
                </div>
              </div>
            </section>

            <section className="pf-import-panel__section" aria-labelledby="import-options-heading">
              <div className="pf-import-panel__section-head">
                <h3 id="import-options-heading" className="pf-import-panel__section-title">
                  {t("profiles.importOptionsSection")}
                </h3>
              </div>

              <div className="pf-import-panel__fields">
                <FileUploadZone
                  id="compliance-playbook-upload"
                  label={t("profiles.compliancePlaybookUpload")}
                  accept=".yml,.yaml"
                  formatLabels={[".yml", ".yaml"]}
                  multiple={false}
                  files={compliancePlaybookFile ? [compliancePlaybookFile] : []}
                  onFilesChange={(files) => setCompliancePlaybookFile(files[0] ?? null)}
                  disabled={importMutation.isPending}
                  variant="compact"
                  hint={t("profiles.compliancePlaybookUploadHint")}
                />

                {scapProfiles.length > 0 && (
                  <div className="pf-form__group">
                    <label htmlFor="scap-profile-select">{t("profiles.scapProfileSelect")}</label>
                    <select
                      id="scap-profile-select"
                      className="pf-select"
                      value={selectedScapProfileId}
                      onChange={(event) => setSelectedScapProfileId(event.target.value)}
                      disabled={importMutation.isPending}
                    >
                      <option value="">{t("profiles.scapProfileDefault")}</option>
                      {scapProfiles.map((profile) => (
                        <option key={profile.profile_id} value={profile.profile_id}>
                          {profile.title} ({t(`profiles.profileFamily.${profile.profile_family}`)})
                        </option>
                      ))}
                    </select>
                    <p className="pf-form__hint">{t("profiles.scapProfileHint")}</p>
                  </div>
                )}
              </div>
            </section>

            <div className="pf-import-panel__footer">
              <div className="pf-form__actions pf-import-panel__actions">
                <Button
                  onClick={() =>
                    importMutation.mutate({
                      files: importFiles,
                      scapProfileId: selectedScapProfileId || undefined,
                      compliancePlaybook: compliancePlaybookFile,
                    })
                  }
                  disabled={!canImport || importMutation.isPending}
                  loading={importMutation.isPending}
                >
                  {importMutation.isPending ? t("profiles.importing") : t("profiles.import")}
                </Button>
                <Button variant="secondary" onClick={() => setShowImport(false)}>
                  {t("common.cancel")}
                </Button>
              </div>

              {importMutation.isError && (
                <div className="pf-alert pf-alert--error">{(importMutation.error as Error).message}</div>
              )}
              {importMutation.isSuccess && (
                <div className="pf-alert pf-alert--success">{t("profiles.importSuccess")}</div>
              )}
            </div>
          </div>
        )}

        {profiles.isLoading ? (
          <Spinner />
        ) : profiles.data?.length === 0 ? (
          <EmptyState title={t("profiles.noneImported")} description={t("profiles.noneImportedDesc")} />
        ) : (
          <>
            <div className="pf-filters pf-filters--profiles">
              <div className="pf-filters__grid pf-filters__grid--profiles">
                <div className="pf-filters__group">
                  <label htmlFor="profiles-filter-name">{t("common.name")}</label>
                  <input
                    id="profiles-filter-name"
                    className="pf-input"
                    type="search"
                    value={filterName}
                    onChange={(event) => setFilterName(event.target.value)}
                    placeholder={t("profiles.filterNamePlaceholder")}
                  />
                </div>
                <div className="pf-filters__group">
                  <label htmlFor="profiles-filter-category">{t("profiles.category").replace(" *", "")}</label>
                  <select
                    id="profiles-filter-category"
                    className="pf-select"
                    value={filterCategory}
                    onChange={(event) => setFilterCategory(event.target.value)}
                  >
                    <option value="all">{t("profiles.allCategories")}</option>
                    {categoryOptions.map((name) => (
                      <option key={name} value={name}>
                        {name}
                      </option>
                    ))}
                  </select>
                </div>
                <div className="pf-filters__group">
                  <label htmlFor="profiles-filter-version">{t("profiles.version")}</label>
                  <input
                    id="profiles-filter-version"
                    className="pf-input"
                    type="search"
                    value={filterVersion}
                    onChange={(event) => setFilterVersion(event.target.value)}
                    placeholder={t("profiles.filterVersionPlaceholder")}
                  />
                </div>
                <div className="pf-filters__group">
                  <label htmlFor="profiles-filter-status">{t("common.status")}</label>
                  <select
                    id="profiles-filter-status"
                    className="pf-select"
                    value={filterStatus}
                    onChange={(event) =>
                      setFilterStatus(event.target.value as "all" | "active" | "inactive")
                    }
                  >
                    <option value="all">{t("profiles.allStatuses")}</option>
                    <option value="active">{t("common.active")}</option>
                    <option value="inactive">{t("common.inactive")}</option>
                  </select>
                </div>
              </div>

              <div className="pf-profiles-imported__toolbar">
                <div className="pf-profiles-imported__toolbar-start">
                  {canOperate && filteredProfiles.length > 0 && (
                    <Button
                      variant="secondary"
                      className="pf-btn--sm"
                      disabled={bulkPending}
                      onClick={toggleSelectAllFiltered}
                    >
                      {filteredProfiles.every((std) => selectedProfileIds.has(std.id))
                        ? t("profiles.catalogClearSelection")
                        : t("profiles.selectAllFiltered")}
                    </Button>
                  )}
                  <p className="pf-profiles-imported__meta">
                    {canOperate && filteredProfiles.length > 0 ? (
                      <>
                        <span>{t("hostSelection.selected", { count: selectedProfileIds.size })}</span>
                        <span className="pf-profiles-imported__meta-sep" aria-hidden="true">
                          ·
                        </span>
                      </>
                    ) : null}
                    <span>
                      {hasActiveFilters
                        ? t("profiles.filterResultsActive", {
                            count: filteredProfiles.length,
                            total: profiles.data?.length ?? 0,
                          })
                        : t("profiles.filterShown", {
                            count: filteredProfiles.length,
                            total: profiles.data?.length ?? 0,
                          })}
                    </span>
                  </p>
                </div>

                <div className="pf-profiles-imported__toolbar-end">
                  {hasActiveFilters && (
                    <Button variant="secondary" className="pf-btn--sm" onClick={clearFilters}>
                      {t("profiles.clearFilters")}
                    </Button>
                  )}
                  {canOperate && filteredProfiles.length > 0 && (
                    <div className="pf-profiles-imported__bulk-group" role="group" aria-label={t("profiles.imported")}>
                      <Button
                        variant="secondary"
                        className="pf-btn--sm"
                        disabled={selectedProfileIds.size === 0 || bulkPending}
                        onClick={() => runBulkAction("enable")}
                      >
                        {t("profiles.bulkEnable")}
                      </Button>
                      <Button
                        variant="secondary"
                        className="pf-btn--sm"
                        disabled={selectedProfileIds.size === 0 || bulkPending}
                        onClick={() => runBulkAction("disable")}
                      >
                        {t("profiles.bulkDisable")}
                      </Button>
                      <Button
                        variant="secondary"
                        className="pf-btn--sm"
                        disabled={selectedProfileIds.size === 0 || bulkPending}
                        onClick={() => runBulkAction("sync")}
                      >
                        {t("profiles.bulkSync")}
                      </Button>
                      <Button
                        variant="danger-secondary"
                        className="pf-btn--sm"
                        disabled={selectedProfileIds.size === 0 || bulkPending}
                        onClick={() => runBulkAction("delete")}
                      >
                        {t("profiles.bulkDelete")}
                      </Button>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {filteredProfiles.length === 0 ? (
              <EmptyState
                title={t("profiles.noFilterResults")}
                description={t("profiles.noFilterResultsDesc")}
              />
            ) : (
              <div className="pf-table-wrap">
                <table className="pf-table pf-profiles-imported-table">
                  <thead>
                    <tr>
                      {canOperate && (
                        <th scope="col" className="pf-profiles-imported-table__check" aria-label={t("profiles.catalogSelectColumn")} />
                      )}
                      <th className="pf-profiles-imported-table__name">{t("common.name")}</th>
                      <th className="pf-profiles-imported-table__category">{t("profiles.category").replace(" *", "")}</th>
                      <th className="pf-profiles-imported-table__version-col">{t("profiles.version")}</th>
                      <th className="pf-profiles-imported-table__source">{t("profiles.sourceFormat")}</th>
                      <th className="pf-profiles-imported-table__status">{t("common.status")}</th>
                      <th className="pf-profiles-imported-table__actions" scope="col">
                        {t("common.actions")}
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredProfiles.map((std) => (
                      <tr
                        key={std.id}
                        className={`pf-table__row--clickable${std.id === activeProfileId ? " pf-table__row--selected" : ""}`}
                        onClick={() => selectProfile(std.id)}
                      >
                        {canOperate && (
                          <td className="pf-profiles-imported-table__check" onClick={(e) => e.stopPropagation()}>
                            <input
                              type="checkbox"
                              className="pf-checkbox-control"
                              checked={selectedProfileIds.has(std.id)}
                              disabled={bulkPending}
                              onChange={() => toggleProfileSelection(std.id)}
                              aria-label={t("profiles.catalogSelect", { name: std.profile_name })}
                            />
                          </td>
                        )}
                        <td className="pf-profiles-imported-table__name">
                          <span className="pf-profiles-imported-table__name-text" title={std.profile_name}>
                            {std.profile_name}
                          </span>
                        </td>
                        <td className="pf-profiles-imported-table__category">
                          <span
                            className="pf-profiles-imported-table__category-text"
                            title={std.category_name ?? undefined}
                          >
                            {std.category_name ?? t("common.dash")}
                          </span>
                        </td>
                        <td className="pf-profiles-imported-table__version-col">
                          <div className="pf-profiles-imported-table__version">
                            <span className="pf-profiles-imported-table__version-value">{std.version}</span>
                            {std.needs_update ? (
                              <Badge variant="warning">{t("profiles.catalogUpdateAvailable")}</Badge>
                            ) : null}
                          </div>
                        </td>
                        <td className="pf-profiles-imported-table__source">
                          <Badge variant={std.source_format === "xccdf" ? "info" : "neutral"} literal>
                            {std.source_format === "xccdf"
                              ? t("profiles.sourceFormatXccdf")
                              : t("profiles.sourceFormatCustom")}
                          </Badge>
                        </td>
                        <td className="pf-profiles-imported-table__status">
                          <Badge variant={std.is_active ? "success" : "danger"}>
                            {std.is_active ? t("common.active") : t("common.inactive")}
                          </Badge>
                        </td>
                        <td className="pf-profiles-imported-table__actions" onClick={(e) => e.stopPropagation()}>
                          <div className="pf-profiles-row-actions">
                            <Button variant="secondary" className="pf-btn--sm" onClick={() => selectProfile(std.id)}>
                              {t("common.open")}
                            </Button>
                            <Button
                              variant="danger-secondary"
                              className="pf-btn--sm"
                              onClick={() => handleDelete(std.id, std.profile_name)}
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
          </>
        )}
        {deleteMutation.isError && (
          <div className="pf-alert pf-alert--error" style={{ margin: "1rem" }}>
            {(deleteMutation.error as Error).message}
          </div>
        )}
      </Panel>

      <Panel
        title={t("profiles.catalogTitle")}
        toolbar={
          <Button variant="link" className="pf-btn--sm" onClick={() => setShowCatalog((open) => !open)}>
            {showCatalog ? t("profiles.hideCatalog") : t("profiles.showCatalog")}
          </Button>
        }
        noPadding
      >
        {showCatalog ? (
          <ProfilesCatalogPanel />
        ) : (
          <div className="pf-profiles-catalog pf-profiles-catalog--dormant">
            <p className="pf-profiles-catalog__hint">{t("profiles.catalogHint")}</p>
            <Button variant="secondary" className="pf-btn--sm" onClick={() => setShowCatalog(true)}>
              {t("profiles.showCatalog")}
            </Button>
          </div>
        )}
      </Panel>

      {!activeProfileId && (filteredProfiles.length ?? 0) > 0 && (
        <Panel title={t("profiles.detail")}>
          <EmptyState title={t("profiles.selectProfile")} description={t("profiles.selectProfileDesc")} />
        </Panel>
      )}

      {activeProfileId && (
        <Panel
          ref={detailPanelRef}
          title={t("profiles.detailTitle", { name: selectedProfile?.profile_name ?? activeProfileId })}
        >
          {detail.isLoading && <Spinner />}
          {detail.isError && (
            <div className="pf-alert pf-alert--error">{(detail.error as Error).message}</div>
          )}

          {detail.data && (
            <div className="pf-profile-detail">
              {detail.data.summary ? (
                <p className="pf-profile-detail__summary">{detail.data.summary}</p>
              ) : null}

              <dl className="pf-profile-detail__meta">
                <div className="pf-profile-detail__meta-item">
                  <dt>{t("profiles.category").replace(" *", "")}</dt>
                  <dd>{detail.data.category_name ?? t("common.dash")}</dd>
                </div>
                <div className="pf-profile-detail__meta-item">
                  <dt>{t("profiles.version")}</dt>
                  <dd>{detail.data.version}</dd>
                </div>
                <div className="pf-profile-detail__meta-item">
                  <dt>{t("common.status")}</dt>
                  <dd>
                    <Badge variant={detail.data.is_active ? "success" : "danger"}>
                      {detail.data.is_active ? t("common.active") : t("common.inactive")}
                    </Badge>
                  </dd>
                </div>
                <div className="pf-profile-detail__meta-item">
                  <dt>{t("profiles.sourceFormat")}</dt>
                  <dd>
                    <Badge variant={detail.data.source_format === "xccdf" ? "info" : "neutral"} literal>
                      {detail.data.source_format === "xccdf"
                        ? t("profiles.sourceFormatXccdf")
                        : t("profiles.sourceFormatCustom")}
                    </Badge>
                  </dd>
                </div>
              </dl>

              <section className="pf-profile-detail__checks" aria-label={t("profiles.detailChecksTitle")}>
                <h4 className="pf-profile-detail__checks-title">{t("profiles.detailChecksTitle")}</h4>
                {profileRules.isLoading ? (
                  <Spinner />
                ) : profileRules.isError ? (
                  <div className="pf-alert pf-alert--error">
                    {(profileRules.error as Error).message}
                  </div>
                ) : (
                  <div className="pf-stat-grid pf-profile-detail__stats">
                    <StatTile
                      label={t("profiles.detailChecksTotal")}
                      value={ruleSeverityStats.total}
                    />
                    <StatTile
                      label={t("profiles.detailSeverityHigh")}
                      value={ruleSeverityStats.high}
                      variant="danger"
                    />
                    <StatTile
                      label={t("profiles.detailSeverityMedium")}
                      value={ruleSeverityStats.medium}
                      variant="warning"
                    />
                    <StatTile
                      label={t("profiles.detailSeverityLow")}
                      value={ruleSeverityStats.low}
                      variant="info"
                    />
                    {ruleSeverityStats.other > 0 ? (
                      <StatTile
                        label={t("profiles.detailSeverityOther")}
                        value={ruleSeverityStats.other}
                      />
                    ) : null}
                  </div>
                )}
              </section>
            </div>
          )}
        </Panel>
      )}

      {activeProfileId && (
        <Panel
          title={t("profiles.checkItems")}
          toolbar={
            <div className="pf-profile-rules__toolbar">
              {detail.data?.version ? (
                <span className="pf-profile-rules__version" title={t("profiles.version")}>
                  <span className="pf-profile-rules__version-label">{t("profiles.version")}</span>
                  <span className="pf-profile-rules__version-value">{detail.data.version}</span>
                </span>
              ) : null}
              {profileRules.data ? (
                <span className="pf-profile-rules__count">
                  {t("profiles.checkItemsCount", { count: profileRules.data.length })}
                </span>
              ) : null}
              <span className="pf-profile-rules__toolbar-sep" aria-hidden="true" />
              <Button
                variant="secondary"
                className="pf-btn--sm pf-profile-rules__changelog-btn"
                onClick={() => setShowRuleChangelog(true)}
              >
                {t("profiles.ruleChangelogShow")}
              </Button>
            </div>
          }
          noPadding
        >
          {profileRules.isLoading && <Spinner />}
          {profileRules.isError && (
            <div className="pf-alert pf-alert--error" style={{ margin: "1rem" }}>
              {(profileRules.error as Error).message}
            </div>
          )}
          {profileRules.data && profileRules.data.length === 0 && !profileRules.isLoading && (
            <p className="pf-table__muted" style={{ padding: "1rem" }}>
              {t("profiles.noCheckItems")}
            </p>
          )}
          {profileRules.data && profileRules.data.length > 0 && (
            <div className="pf-profile-rules">
              {profileRules.data.map((rule, index) => {
                const ruleKey = profileRuleKey(rule, index);
                const expanded = expandedRuleKey === ruleKey;
                const editing = editingRuleKey === ruleKey;
                const displayNumber = rule.num?.trim() || String(index + 1);
                const hasDetails = hasProfileRuleMetadata(rule);
                const canExpand = hasDetails || canOperate;
                const displayName = profileRuleDisplayName(rule);

                return (
                  <div
                    key={ruleKey}
                    className={`pf-profile-rule${expanded ? " pf-profile-rule--expanded" : ""}${
                      editing ? " pf-profile-rule--editing" : ""
                    }`}
                  >
                    <button
                      type="button"
                      className="pf-profile-rule__toggle"
                      onClick={() => {
                        if (editing) return;
                        setExpandedRuleKey(expanded ? null : ruleKey);
                      }}
                      aria-expanded={expanded}
                      disabled={!canExpand}
                    >
                      <span className="pf-profile-rule__chevron" aria-hidden />
                      <span className="pf-profile-rule__number">{displayNumber}</span>
                      <span className="pf-profile-rule__title">{displayName}</span>
                      {(rule.requirement_id && rule.requirement_id !== displayName) ||
                      rule.criticality?.trim() ? (
                        <span className="pf-profile-rule__tags">
                          {rule.requirement_id && rule.requirement_id !== displayName ? (
                            <span className="pf-profile-rule__id pf-table__mono">
                              {rule.requirement_id}
                            </span>
                          ) : null}
                          <ProfileRuleSeverityChip rule={rule} />
                        </span>
                      ) : null}
                    </button>
                    {expanded && canExpand && (
                      <div className="pf-profile-rule__body">
                        {editing && ruleDraft ? (
                          <div className="pf-profile-rule__editor">
                            <div className="pf-profile-rule__editor-head">
                              <div className="pf-profile-rule__editor-head-text">
                                <p className="pf-profile-rule__editor-kicker">{t("profiles.ruleEditing")}</p>
                                <p className="pf-profile-rule__editor-id pf-table__mono">
                                  {rule.requirement_id}
                                </p>
                              </div>
                              <div className="pf-profile-rule__editor-actions">
                                <Button
                                  variant="secondary"
                                  className="pf-btn--sm"
                                  onClick={() => {
                                    setEditingRuleKey(null);
                                    setRuleDraft(null);
                                  }}
                                  disabled={saveRuleMutation.isPending}
                                >
                                  {t("profiles.cancelEditRule")}
                                </Button>
                                <Button
                                  variant="primary"
                                  className="pf-btn--sm"
                                  loading={saveRuleMutation.isPending}
                                  onClick={() => {
                                    if (!ruleDraft) return;
                                    saveRuleMutation.mutate({
                                      requirementId: rule.requirement_id,
                                      data: {
                                        title: ruleDraft.title ?? "",
                                        explanation: ruleDraft.explanation ?? "",
                                        impact: ruleDraft.impact ?? "",
                                        scope: ruleDraft.scope ?? "",
                                      },
                                    });
                                  }}
                                >
                                  {t("profiles.saveRule")}
                                </Button>
                              </div>
                            </div>
                            <div className="pf-profile-rule__editor-fields">
                              <div className="pf-profile-rule__field">
                                <label htmlFor={`rule-summary-${ruleKey}`}>{t("profiles.ruleSummary")}</label>
                                <input
                                  id={`rule-summary-${ruleKey}`}
                                  value={ruleDraft.title ?? ""}
                                  onChange={(event) =>
                                    setRuleDraft((prev) =>
                                      prev ? { ...prev, title: event.target.value } : prev
                                    )
                                  }
                                />
                              </div>
                              <div className="pf-profile-rule__field">
                                <label htmlFor={`rule-description-${ruleKey}`}>
                                  {t("profiles.ruleDescription")}
                                </label>
                                <textarea
                                  id={`rule-description-${ruleKey}`}
                                  rows={5}
                                  value={ruleDraft.explanation ?? ""}
                                  onChange={(event) =>
                                    setRuleDraft((prev) =>
                                      prev ? { ...prev, explanation: event.target.value } : prev
                                    )
                                  }
                                />
                              </div>
                              <div className="pf-profile-rule__field-grid">
                                <div className="pf-profile-rule__field pf-profile-rule__field--risk">
                                  <label htmlFor={`rule-risk-${ruleKey}`}>{t("profiles.ruleRisk")}</label>
                                  <textarea
                                    id={`rule-risk-${ruleKey}`}
                                    rows={4}
                                    value={ruleDraft.impact ?? ""}
                                    onChange={(event) =>
                                      setRuleDraft((prev) =>
                                        prev ? { ...prev, impact: event.target.value } : prev
                                      )
                                    }
                                  />
                                </div>
                                <div className="pf-profile-rule__field pf-profile-rule__field--location">
                                  <label htmlFor={`rule-location-${ruleKey}`}>
                                    {t("profiles.ruleLocation")}
                                  </label>
                                  <textarea
                                    id={`rule-location-${ruleKey}`}
                                    rows={4}
                                    value={ruleDraft.scope ?? ""}
                                    onChange={(event) =>
                                      setRuleDraft((prev) =>
                                        prev ? { ...prev, scope: event.target.value } : prev
                                      )
                                    }
                                  />
                                </div>
                              </div>
                            </div>
                          </div>
                        ) : (
                          <ProfileRuleMetadata
                            rule={rule}
                            toolbar={
                              <div className="pf-profile-rule__meta-toolbar">
                                <div className="pf-profile-rule__meta-tags">
                                  <span className="pf-profile-rule__meta-kicker">
                                    {rule.requirement_id}
                                  </span>
                                  <ProfileRuleSeverityChip rule={rule} />
                                </div>
                                {canOperate ? (
                                  <Button
                                    variant="secondary"
                                    className="pf-btn--sm pf-profile-rule__edit-btn"
                                    onClick={() => {
                                      setEditingRuleKey(ruleKey);
                                      setRuleDraft(ruleEditDraft(rule));
                                    }}
                                  >
                                    {t("profiles.editRule")}
                                  </Button>
                                ) : null}
                              </div>
                            }
                            labels={{
                              description: t("profiles.ruleDescription"),
                              risk: t("profiles.ruleRisk"),
                              location: t("profiles.ruleLocation"),
                              scapRuleId: t("profiles.scapRuleId"),
                            }}
                          />
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </Panel>
      )}

      {activeProfileId && showRuleChangelog && (
        <div
          className="pf-modal pf-modal--changelog"
          role="presentation"
          onClick={() => setShowRuleChangelog(false)}
        >
          <div
            className="pf-modal__panel pf-modal__panel--changelog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="profile-rule-changelog-title"
            onClick={(event) => event.stopPropagation()}
          >
            <div className="pf-modal__header">
              <div>
                <h3 id="profile-rule-changelog-title" className="pf-modal__title">
                  {t("profiles.ruleChangelog")}
                </h3>
                <p className="pf-modal__subtitle">
                  {t("profiles.ruleChangelogSubtitle")}
                  {detail.data?.version
                    ? ` · ${t("profiles.ruleVersionLabel", { version: detail.data.version })}`
                    : ""}
                </p>
              </div>
              <Button
                variant="secondary"
                className="pf-btn--sm"
                onClick={() => setShowRuleChangelog(false)}
              >
                {t("profiles.close")}
              </Button>
            </div>

            {ruleChangelog.isLoading && <Spinner />}
            {ruleChangelog.isError && (
              <div className="pf-alert pf-alert--error">
                {(ruleChangelog.error as Error).message}
              </div>
            )}
            {ruleChangelog.data && ruleChangelog.data.length === 0 && !ruleChangelog.isLoading && (
              <p className="pf-profile-rule-changelog__empty">{t("profiles.ruleChangelogEmpty")}</p>
            )}
            {ruleChangelog.data && ruleChangelog.data.length > 0 && (
              <div className="pf-profile-rule-changelog">
                {groupChangelogByVersion(ruleChangelog.data).map((group) => (
                  <section key={group.version} className="pf-profile-rule-changelog__group">
                    <header className="pf-profile-rule-changelog__group-head">
                      <span className="pf-profile-rule-changelog__version">
                        {t("profiles.ruleChangelogVersion", { version: group.version })}
                      </span>
                      <span className="pf-profile-rule-changelog__group-count">
                        {group.entries.length}
                      </span>
                    </header>
                    <div className="pf-profile-rule-changelog__group-body">
                      {group.entries.map((entry) => (
                        <article key={entry.id} className="pf-profile-rule-changelog__entry">
                          <div className="pf-profile-rule-changelog__head">
                            <span className="pf-profile-rule-changelog__req">{entry.requirement_id}</span>
                            <span className="pf-profile-rule-changelog__meta">
                              {formatChangelogAt(entry.at)}
                              {entry.actor ? ` · ${entry.actor}` : ""}
                              {entry.profile_version_before &&
                              entry.profile_version_after &&
                              entry.profile_version_before !== entry.profile_version_after
                                ? ` · ${t("profiles.ruleVersionBump", {
                                    from: entry.profile_version_before,
                                    to: entry.profile_version_after,
                                  })}`
                                : ""}
                            </span>
                          </div>
                          <ul className="pf-profile-rule-changelog__changes">
                            {Object.entries(entry.changes).map(([field, change]) => (
                              <li key={field} className="pf-profile-rule-changelog__change">
                                <span className="pf-profile-rule-changelog__field">
                                  {t(
                                    `profiles.${
                                      RULE_FIELD_LABELS[field as keyof typeof RULE_FIELD_LABELS] ??
                                      field
                                    }`
                                  )}
                                </span>
                                <div className="pf-profile-rule-changelog__diff">
                                  <span className="pf-profile-rule-changelog__from">
                                    {change.from || t("common.dash")}
                                  </span>
                                  <span className="pf-profile-rule-changelog__arrow" aria-hidden>
                                    →
                                  </span>
                                  <span className="pf-profile-rule-changelog__to">
                                    {change.to || t("common.dash")}
                                  </span>
                                </div>
                              </li>
                            ))}
                          </ul>
                        </article>
                      ))}
                    </div>
                  </section>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {isAdmin && activeProfileId && detail.data && detail.data.check_scripts.length > 0 && (
        <Panel title={t("profiles.checkScripts")} noPadding>
          <div className="pf-table-wrap">
            <table className="pf-table">
              <thead>
                <tr>
                  <th>{t("common.id")}</th>
                  <th>{t("common.name")}</th>
                  <th>{t("profiles.executionType")}</th>
                  <th>{t("profiles.scriptFile")}</th>
                  <th>{t("profiles.summary")}</th>
                  <th className="pf-table__col-actions">{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {detail.data.check_scripts.map((script) => (
                  <tr key={script.id}>
                    <td className="pf-table__mono">{script.id}</td>
                    <td>{script.name}</td>
                    <td>
                      <Badge variant="info" literal>
                        {formatExecutionType(script.execution_type)}
                      </Badge>
                    </td>
                    <td className="pf-table__mono">
                      <Button
                        variant="link"
                        className="pf-btn--sm"
                        onClick={() => openScriptViewer(script)}
                      >
                        {script.script_file}
                      </Button>
                    </td>
                    <td>{script.description || t("common.dash")}</td>
                    <td className="pf-table__col-actions">
                      <Button variant="secondary" className="pf-btn--sm" onClick={() => openScriptViewer(script)}>
                        {t("profiles.editScript")}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {isAdmin && activeProfileId && detail.data && (detail.data.remediation_scripts?.length ?? 0) > 0 && (
        <Panel title={t("remediation.remediationScripts")} noPadding>
          <div className="pf-table-wrap">
            <table className="pf-table">
              <thead>
                <tr>
                  <th>{t("common.id")}</th>
                  <th>{t("common.name")}</th>
                  <th>{t("profiles.executionType")}</th>
                  <th>{t("profiles.scriptFile")}</th>
                  <th className="pf-table__col-actions">{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {detail.data.remediation_scripts?.map((script) => (
                  <tr key={script.id}>
                    <td className="pf-table__mono">{script.id}</td>
                    <td>{script.name}</td>
                    <td>
                      <Badge variant="warning" literal>
                        {formatExecutionType(script.execution_type)}
                      </Badge>
                    </td>
                    <td className="pf-table__mono">
                      <Button
                        variant="link"
                        className="pf-btn--sm"
                        onClick={() => openScriptViewer(script)}
                      >
                        {script.script_file}
                      </Button>
                    </td>
                    <td className="pf-table__col-actions">
                      <Button variant="secondary" className="pf-btn--sm" onClick={() => openScriptViewer(script)}>
                        {t("profiles.editScript")}
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )}

      {isAdmin && activeProfileId && detail.data && detail.data.check_scripts.length === 0 && !detail.isLoading && (
        <Panel title={t("profiles.checkScripts")}>
          <p className="pf-table__muted">{t("profiles.noCheckScripts")}</p>
        </Panel>
      )}

      {isAdmin && viewingScript && (
        <div className="pf-modal pf-modal--script" role="presentation" onClick={closeScriptViewer}>
          <div
            className="pf-modal__panel pf-modal__panel--script"
            role="dialog"
            aria-modal="true"
            aria-label={t("profiles.scriptContent")}
            onClick={(event) => event.stopPropagation()}
          >
            <div className="pf-modal__header">
              <div>
                <h3 className="pf-modal__title">{t("profiles.editScript")}</h3>
                <p className="pf-modal__subtitle">
                  {viewingScript.name}
                  {" · "}
                  <span className="pf-table__mono">{viewingScript.script_file}</span>
                </p>
              </div>
              <div style={{ display: "flex", gap: "0.5rem" }}>
                <Button
                  onClick={() => saveScriptMutation.mutate()}
                  loading={saveScriptMutation.isPending}
                  disabled={!isDirty || scriptContent.isLoading}
                >
                  {saveScriptMutation.isPending ? t("common.saving") : t("profiles.saveScript")}
                </Button>
                <Button variant="secondary" className="pf-btn--sm" onClick={closeScriptViewer}>
                  {t("common.cancel")}
                </Button>
              </div>
            </div>

            {saveStatus === "success" && (
              <div className="pf-alert pf-alert--success">{t("profiles.saveSuccess")}</div>
            )}
            {saveStatus === "error" && (
              <div className="pf-alert pf-alert--error">{t("profiles.saveFailed")}</div>
            )}

            {scriptContent.isLoading && <Spinner />}
            {scriptContent.isError && (
              <div className="pf-alert pf-alert--error">
                {scriptContentErrorMessage(scriptContent.error as Error, t)}
              </div>
            )}
            {scriptContent.data && (
              <div className="pf-modal__editor pf-modal__editor--script">
                <Editor
                  height="calc(100dvh - 10.5rem)"
                  language={scriptEditorLanguage(viewingScript.execution_type)}
                  theme="vs-dark"
                  value={editedContent}
                  onChange={(value) => {
                    setEditedContent(value ?? "");
                    setIsDirty(true);
                    setSaveStatus(null);
                  }}
                  options={{
                    minimap: { enabled: true },
                    fontSize: 14,
                    lineHeight: 22,
                    wordWrap: "on",
                    scrollBeyondLastLine: false,
                    automaticLayout: true,
                  }}
                />
              </div>
            )}
          </div>
        </div>
      )}
    </>
  );
}
