import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { api, type Job, type JobTemplate } from "../api/client";
import { HostPicker } from "./HostPicker";
import { JobSchedulePicker, useScheduleLabels } from "./JobSchedulePicker";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { EmptyState } from "./ui/EmptyState";
import { Spinner } from "./ui/Spinner";
import { useToast } from "./ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";
import { useAuth } from "../auth/AuthProvider";
import { ObjectOwnerCell } from "./ObjectOwnerCell";
import {
  buildCronExpression,
  DEFAULT_SCHEDULE,
  formatScheduleLabel,
  parseCronExpression,
  type ScheduleConfig,
} from "../utils/jobSchedule";

type TemplateForm = {
  name: string;
  description: string;
  jobType: "ssh" | "winrm" | "python" | "playbook";
  profileId: number | "";
  playbookId: number | "";
  hostIds: number[];
  isScheduled: boolean;
  scheduleConfig: ScheduleConfig;
  isActive: boolean;
};

const emptyForm = (): TemplateForm => ({
  name: "",
  description: "",
  jobType: "ssh",
  profileId: "",
  playbookId: "",
  hostIds: [],
  isScheduled: false,
  scheduleConfig: { ...DEFAULT_SCHEDULE },
  isActive: true,
});

function formFromTemplate(template: JobTemplate): TemplateForm {
  const jobType = template.playbook_id
    ? "playbook"
    : template.execution_type === "winrm"
      ? "winrm"
      : template.execution_type === "python"
        ? "python"
        : "ssh";

  return {
    name: template.name,
    description: template.description ?? "",
    jobType,
    profileId: template.profile_id ?? "",
    playbookId: template.playbook_id ?? "",
    hostIds: template.host_ids,
    isScheduled: template.is_scheduled,
    scheduleConfig: parseCronExpression(template.cron_expression),
    isActive: template.is_active,
  };
}

function buildPayload(form: TemplateForm) {
  const executionType =
    form.jobType === "ssh"
      ? ("ssh" as const)
      : form.jobType === "winrm"
        ? ("winrm" as const)
        : form.jobType === "python"
          ? ("python" as const)
          : undefined;

  return {
    name: form.name,
    description: form.description.trim() || undefined,
    profile_id: form.jobType !== "playbook" && form.profileId !== "" ? form.profileId : undefined,
    playbook_id: form.jobType === "playbook" && form.playbookId !== "" ? form.playbookId : undefined,
    execution_type: executionType,
    host_ids: form.hostIds,
    dynamic_filter: null,
    is_scheduled: form.isScheduled,
    cron_expression: form.isScheduled ? buildCronExpression(form.scheduleConfig) : undefined,
    is_active: form.isActive,
  };
}

type JobTemplatesPanelProps = {
  canManage: boolean;
  onUseTemplate: (template: JobTemplate) => void;
  onJobCreated?: (job: Job) => void;
};

export function JobTemplatesPanel({ canManage, onUseTemplate, onJobCreated }: JobTemplatesPanelProps) {
  const { t } = useTranslation();
  const { canSeeObjectOwners } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const scheduleLabels = useScheduleLabels();
  const [form, setForm] = useState<TemplateForm>(emptyForm());
  const [editingId, setEditingId] = useState<number | null>(null);
  const [showForm, setShowForm] = useState(false);

  const templates = useQuery({ queryKey: ["job-templates"], queryFn: api.jobTemplates });
  const profiles = useQuery({ queryKey: ["profiles"], queryFn: () => api.profiles() });
  const playbooks = useQuery({ queryKey: ["playbooks"], queryFn: () => api.playbooks() });
  const hosts = useQuery({ queryKey: ["hosts"], queryFn: () => api.hosts({ limit: 200 }) });

  const availableHosts = hosts.data?.items ?? [];
  const hasTemplates = Boolean(templates.data?.length);
  const isEditing = editingId !== null;
  const cronPreview = formatScheduleLabel(buildCronExpression(form.scheduleConfig), scheduleLabels);

  const createMutation = useMutation({
    mutationFn: api.createJobTemplate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["job-templates"] });
      setForm(emptyForm());
      setShowForm(false);
      toast.success(t("toast.jobTemplateCreated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: ReturnType<typeof buildPayload> }) =>
      api.updateJobTemplate(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["job-templates"] });
      setEditingId(null);
      setForm(emptyForm());
      setShowForm(false);
      toast.success(t("toast.jobTemplateUpdated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteJobTemplate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["job-templates"] });
      if (editingId != null) {
        setEditingId(null);
        setForm(emptyForm());
        setShowForm(false);
      }
      toast.success(t("toast.jobTemplateDeleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const applyMutation = useMutation({
    mutationFn: ({ id, name }: { id: number; name?: string }) =>
      api.applyJobTemplate(id, { name, run_after_create: false }),
    onSuccess: (job) => {
      queryClient.invalidateQueries({ queryKey: ["jobs"] });
      onJobCreated?.(job);
      toast.success(t("toast.jobTemplateApplied"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const profileLabelById = useMemo(() => {
    const map = new Map<number, string>();
    profiles.data?.forEach((item) => map.set(item.id, item.label));
    return map;
  }, [profiles.data]);

  const isFormValid =
    !!form.name &&
    (form.jobType !== "playbook" ? form.profileId !== "" : form.playbookId !== "") &&
    form.hostIds.length > 0;

  const cancelForm = () => {
    setEditingId(null);
    setForm(emptyForm());
    setShowForm(false);
  };

  const startCreate = () => {
    setEditingId(null);
    setForm(emptyForm());
    setShowForm(true);
  };

  const startEdit = (template: JobTemplate) => {
    setEditingId(template.id);
    setForm(formFromTemplate(template));
    setShowForm(true);
  };

  const submit = () => {
    if (!isFormValid) return;
    const payload = buildPayload(form);
    if (isEditing && editingId != null) {
      updateMutation.mutate({ id: editingId, data: payload });
      return;
    }
    createMutation.mutate(payload);
  };

  const toggleHost = (id: number) => {
    setForm((current) => ({
      ...current,
      hostIds: current.hostIds.includes(id)
        ? current.hostIds.filter((hostId) => hostId !== id)
        : [...current.hostIds, id],
    }));
  };

  if (!canManage && !hasTemplates) {
    return null;
  }

  return (
    <div className="pf-job-templates">
      {showForm && canManage ? (
        <div className="pf-job-templates__composer">
          <div className="pf-job-templates__composer-head">
            <h4 className="pf-job-templates__composer-title">
              {isEditing ? t("jobTemplates.editTitle", { name: form.name }) : t("jobTemplates.add")}
            </h4>
            <button type="button" className="pf-job-templates__composer-close" onClick={cancelForm}>
              {t("common.cancel")}
            </button>
          </div>

          <div className="pf-job-templates__composer-body pf-form pf-form--wide">
            <div className="pf-form__row">
              <div className="pf-form__group">
                <label htmlFor="template-name">{t("common.name")}</label>
                <input
                  id="template-name"
                  className="pf-input"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                />
              </div>
              <div className="pf-form__group">
                <label htmlFor="template-description">{t("jobTemplates.descriptionField")}</label>
                <input
                  id="template-description"
                  className="pf-input"
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                />
              </div>
            </div>

            <div className="pf-form__row">
              <div className="pf-form__group">
                <label>{t("jobs.jobType")}</label>
                <select
                  className="pf-select"
                  value={form.jobType}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      jobType: e.target.value as TemplateForm["jobType"],
                    })
                  }
                >
                  <option value="ssh">{t("jobs.typeSsh")}</option>
                  <option value="winrm">{t("jobs.typeWinrm")}</option>
                  <option value="python">{t("jobs.typePython")}</option>
                  <option value="playbook">{t("jobs.typePlaybook")}</option>
                </select>
              </div>
              {form.jobType !== "playbook" ? (
                <div className="pf-form__group">
                  <label htmlFor="template-profile">{t("jobs.profile")}</label>
                  <select
                    id="template-profile"
                    className="pf-select"
                    value={form.profileId}
                    onChange={(e) =>
                      setForm({ ...form, profileId: e.target.value ? Number(e.target.value) : "" })
                    }
                  >
                    <option value="">{t("jobs.selectProfile")}</option>
                    {profiles.data?.map((profile) => (
                      <option key={profile.id} value={profile.id}>
                        {profile.profile_name}
                      </option>
                    ))}
                  </select>
                </div>
              ) : (
                <div className="pf-form__group">
                  <label htmlFor="template-playbook">{t("jobs.playbook")}</label>
                  <select
                    id="template-playbook"
                    className="pf-select"
                    value={form.playbookId}
                    onChange={(e) =>
                      setForm({ ...form, playbookId: e.target.value ? Number(e.target.value) : "" })
                    }
                  >
                    <option value="">{t("jobs.selectPlaybook")}</option>
                    {playbooks.data?.map((playbook) => (
                      <option key={playbook.id} value={playbook.id}>
                        {playbook.name}
                      </option>
                    ))}
                  </select>
                </div>
              )}
            </div>

            <HostPicker
              hosts={availableHosts}
              selectedIds={form.hostIds}
              onToggle={toggleHost}
              onSelectAll={(hostIds) => setForm({ ...form, hostIds })}
              onClearAll={() => setForm({ ...form, hostIds: [] })}
            />

            <JobSchedulePicker
              enabled={form.isScheduled}
              onEnabledChange={(isScheduled) => setForm({ ...form, isScheduled })}
              config={form.scheduleConfig}
              onConfigChange={(scheduleConfig) => setForm({ ...form, scheduleConfig })}
            />
            {form.isScheduled ? <p className="pf-job-templates__cron-preview">{cronPreview}</p> : null}

            <label className="pf-notify-switch">
              <input
                type="checkbox"
                checked={form.isActive}
                onChange={(e) => setForm({ ...form, isActive: e.target.checked })}
              />
              <span className="pf-notify-switch__track" aria-hidden />
              <span className="pf-notify-switch__label">{t("jobTemplates.active")}</span>
            </label>
          </div>

          <div className="pf-job-templates__composer-foot">
            <Button
              onClick={submit}
              disabled={!isFormValid || createMutation.isPending || updateMutation.isPending}
            >
              {isEditing ? t("jobTemplates.saveChanges") : t("common.create")}
            </Button>
          </div>
        </div>
      ) : (
        <>
          {canManage && hasTemplates ? (
            <div className="pf-job-templates__toolbar">
              <span className="pf-job-templates__toolbar-label">{t("jobTemplates.list")}</span>
              <Button onClick={startCreate}>{t("jobTemplates.add")}</Button>
            </div>
          ) : null}

          <div className="pf-job-templates__list">
            {templates.isLoading ? (
              <Spinner />
            ) : !hasTemplates ? (
              canManage ? (
                <div className="pf-job-templates__empty">
                  <EmptyState title={t("jobTemplates.empty")} description={t("jobTemplates.emptyDesc")} />
                  <div className="pf-job-templates__empty-action">
                    <Button onClick={startCreate}>{t("jobTemplates.add")}</Button>
                  </div>
                </div>
              ) : (
                <EmptyState title={t("jobTemplates.empty")} description={t("jobTemplates.emptyDesc")} />
              )
            ) : (
              <div className="pf-table-wrap">
                <table className="pf-table pf-table--compact">
                  <thead>
                    <tr>
                      <th>{t("common.name")}</th>
                      <th>{t("jobs.profile")}</th>
                      <th>{t("jobs.schedule")}</th>
                      <th>{t("common.status")}</th>
                      {canSeeObjectOwners ? <th>{t("objectRbac.owner")}</th> : null}
                      <th className="pf-table__col-actions">{t("common.actions")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {templates.data?.map((template) => (
                      <tr key={template.id}>
                        <td>
                          <div className="pf-job-templates__name">{template.name}</div>
                          {template.description ? (
                            <div className="pf-job-templates__description">{template.description}</div>
                          ) : null}
                          <div className="pf-job-templates__meta">
                            {template.host_ids.length ? (
                              <Badge variant="info">
                                {t("jobTemplates.hostsCount", { count: template.host_ids.length })}
                              </Badge>
                            ) : (
                              <Badge variant="neutral">{t("jobTemplates.hostsOnApply")}</Badge>
                            )}
                          </div>
                        </td>
                        <td>
                          {template.playbook_name ??
                            template.profile_name ??
                            profileLabelById.get(template.profile_id ?? -1) ??
                            "—"}
                        </td>
                        <td>
                          {template.is_scheduled
                            ? formatScheduleLabel(template.cron_expression, scheduleLabels)
                            : t("common.manual")}
                        </td>
                        <td>
                          <Badge variant={template.is_active ? "success" : "neutral"}>
                            {template.is_active ? t("common.active") : t("common.inactive")}
                          </Badge>
                        </td>
                        {canSeeObjectOwners ? (
                          <td>
                            <ObjectOwnerCell ownerSub={template.owner_sub} />
                          </td>
                        ) : null}
                        <td className="pf-ops-table__actions">
                          {canManage ? (
                            <div className="pf-ops-row-actions">
                              <Button variant="secondary" className="pf-btn--sm" onClick={() => onUseTemplate(template)}>
                                {t("jobTemplates.useInForm")}
                              </Button>
                              <Button
                                variant="primary"
                                className="pf-btn--sm"
                                onClick={() => applyMutation.mutate({ id: template.id })}
                              >
                                {t("jobTemplates.createJob")}
                              </Button>
                              <Button variant="secondary" className="pf-btn--sm" onClick={() => startEdit(template)}>
                                {t("common.edit")}
                              </Button>
                              <Button
                                variant="danger-secondary"
                                className="pf-btn--sm"
                                onClick={() => deleteMutation.mutate(template.id)}
                              >
                                {t("common.delete")}
                              </Button>
                            </div>
                          ) : null}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
