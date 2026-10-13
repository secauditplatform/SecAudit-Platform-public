import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type AuditFlowInventoryScope, type AuditFlowRun, type AuditFlowTemplate } from "../api/client";
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

type SaveDraft = {
  name: string;
  description: string;
  tags: string[];
  site: string;
  isScheduled: boolean;
  scheduleConfig: ScheduleConfig;
  isActive: boolean;
};

type AuditFlowTemplatesPanelProps = {
  canManage: boolean;
  draftTargets: string[];
  draftCredentials: Array<{
    label?: string;
    credential_type: "ssh_password" | "ssh_key" | "winrm";
    username: string;
    secret: string;
    key_passphrase?: string;
    service_username?: string;
    service_secret?: string;
  }>;
  saveToInventory: boolean;
  onRunStarted?: (run: AuditFlowRun) => void;
};

const emptySave = (): SaveDraft => ({
  name: "",
  description: "",
  tags: [],
  site: "",
  isScheduled: false,
  scheduleConfig: { ...DEFAULT_SCHEDULE },
  isActive: true,
});

function scopeFromDraft(draft: SaveDraft): { tags: string[]; site: string | null } | null {
  const tags = draft.tags.map((tag) => tag.trim()).filter(Boolean);
  const site = draft.site.trim();
  if (tags.length === 0 && !site) return null;
  return { tags, site: site || null };
}

function draftFromScope(scope: AuditFlowInventoryScope | null | undefined): Pick<SaveDraft, "tags" | "site"> {
  return {
    tags: scope?.tags ?? [],
    site: scope?.site ?? "",
  };
}

function InventoryScopeFields({
  idPrefix,
  draft,
  tags,
  onChange,
}: {
  idPrefix: string;
  draft: SaveDraft;
  tags: Array<{ id: number; name: string }>;
  onChange: (patch: Pick<SaveDraft, "tags" | "site">) => void;
}) {
  const { t } = useTranslation();
  const toggleTag = (name: string) => {
    const selected = draft.tags.includes(name);
    onChange({
      tags: selected ? draft.tags.filter((tag) => tag !== name) : [...draft.tags, name],
      site: draft.site,
    });
  };
  return (
    <div className="pf-form__group">
      <label>{t("auditFlow.inventoryScopeLabel")}</label>
      <p className="pf-form__hint">{t("auditFlow.inventoryScopeHint")}</p>
      {tags.length > 0 ? (
        <div className="pf-audit-flow-inventory-import__tags" role="group" aria-label={t("auditFlow.inventoryScopeTags")}>
          {tags.map((tag) => (
            <button
              key={tag.id}
              type="button"
              className={`pf-audit-flow-inventory-import__tag${draft.tags.includes(tag.name) ? " is-active" : ""}`}
              onClick={() => toggleTag(tag.name)}
            >
              {tag.name}
            </button>
          ))}
        </div>
      ) : (
        <p className="pf-form__hint">{t("auditFlow.inventoryScopeNoTags")}</p>
      )}
      <label htmlFor={`${idPrefix}-site`}>{t("auditFlow.inventoryScopeSite")}</label>
      <input
        id={`${idPrefix}-site`}
        className="pf-input"
        value={draft.site}
        placeholder={t("auditFlow.inventoryScopeAnySite")}
        onChange={(event) => onChange({ tags: draft.tags, site: event.target.value })}
      />
    </div>
  );
}

export function AuditFlowTemplatesPanel({
  canManage,
  draftTargets,
  draftCredentials,
  saveToInventory,
  onRunStarted,
}: AuditFlowTemplatesPanelProps) {
  const { t } = useTranslation();
  const { canSeeObjectOwners } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const scheduleLabels = useScheduleLabels();
  const [showSave, setShowSave] = useState(false);
  const [saveForm, setSaveForm] = useState<SaveDraft>(emptySave());
  const [editingId, setEditingId] = useState<number | null>(null);
  const [editForm, setEditForm] = useState<SaveDraft>(emptySave());

  const templates = useQuery({
    queryKey: ["audit-flow-templates"],
    queryFn: api.listAuditFlowTemplates,
  });
  const tagsQuery = useQuery({
    queryKey: ["host-tags"],
    queryFn: api.hostTags,
    enabled: canManage,
  });

  const createMutation = useMutation({
    mutationFn: api.createAuditFlowTemplate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["audit-flow-templates"] });
      setSaveForm(emptySave());
      setShowSave(false);
      toast.success(t("toast.auditFlowTemplateCreated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      data,
    }: {
      id: number;
      data: {
        name?: string;
        description?: string;
        is_scheduled?: boolean;
        cron_expression?: string | null;
        is_active?: boolean;
        inventory_scope?: { tags: string[]; site?: string | null } | null;
      };
    }) => api.updateAuditFlowTemplate(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["audit-flow-templates"] });
      setEditingId(null);
      setEditForm(emptySave());
      toast.success(t("toast.auditFlowTemplateUpdated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteAuditFlowTemplate,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["audit-flow-templates"] });
      if (editingId != null) {
        setEditingId(null);
        setEditForm(emptySave());
      }
      toast.success(t("toast.auditFlowTemplateDeleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const runMutation = useMutation({
    mutationFn: api.runAuditFlowTemplate,
    onSuccess: (run) => {
      queryClient.invalidateQueries({ queryKey: ["audit-flow-runs"] });
      toast.success(t("toast.auditFlowTemplateRun"));
      onRunStarted?.(run);
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const items = templates.data ?? [];
  const hasTemplates = items.length > 0;
  const targetsReady =
    draftTargets.flatMap((item) => item.split(/[\s,;\r\n]+/)).filter((item) => item.trim()).length > 0;
  const saveScope = scopeFromDraft(saveForm);
  const editScope = scopeFromDraft(editForm);
  const canSave = targetsReady || saveScope != null;
  const targetCount = draftTargets.flatMap((item) => item.split(/[\s,;\r\n]+/)).filter((item) => item.trim())
    .length;
  const cronPreview = formatScheduleLabel(buildCronExpression(saveForm.scheduleConfig), scheduleLabels);
  const editCronPreview = formatScheduleLabel(buildCronExpression(editForm.scheduleConfig), scheduleLabels);

  const openSave = () => {
    setEditingId(null);
    setEditForm(emptySave());
    setSaveForm(emptySave());
    setShowSave(true);
  };

  const cancelSave = () => {
    setShowSave(false);
    setSaveForm(emptySave());
  };

  const submitSave = () => {
    if (!saveForm.name.trim() || !canSave) return;
    const written = draftTargets.flatMap((item) => item.split(/[\s,;\r\n]+/)).map((item) => item.trim()).filter(Boolean);
    createMutation.mutate({
      name: saveForm.name.trim(),
      description: saveForm.description.trim() || undefined,
      targets: written,
      inventory_scope: saveScope,
      credentials: draftCredentials,
      save_to_inventory: saveToInventory,
      is_scheduled: saveForm.isScheduled,
      cron_expression: saveForm.isScheduled
        ? buildCronExpression(saveForm.scheduleConfig)
        : undefined,
      is_active: saveForm.isActive,
    });
  };

  const startEdit = (template: AuditFlowTemplate) => {
    setShowSave(false);
    setSaveForm(emptySave());
    setEditingId(template.id);
    setEditForm({
      name: template.name,
      description: template.description ?? "",
      ...draftFromScope(template.inventory_scope),
      isScheduled: template.is_scheduled,
      scheduleConfig: parseCronExpression(template.cron_expression),
      isActive: template.is_active,
    });
  };

  const cancelEdit = () => {
    setEditingId(null);
    setEditForm(emptySave());
  };

  const submitEdit = () => {
    if (editingId == null || !editForm.name.trim()) return;
    updateMutation.mutate({
      id: editingId,
      data: {
        name: editForm.name.trim(),
        description: editForm.description.trim() || undefined,
        is_scheduled: editForm.isScheduled,
        cron_expression: editForm.isScheduled
          ? buildCronExpression(editForm.scheduleConfig)
          : null,
        is_active: editForm.isActive,
        inventory_scope: editScope,
      },
    });
  };

  if (!canManage && !hasTemplates && !templates.isLoading) {
    return null;
  }

  return (
    <div className="pf-audit-flow-templates">
      {showSave && canManage ? (
        <div className="pf-audit-flow-templates__composer">
          <div className="pf-audit-flow-templates__composer-head">
            <div>
              <h4 className="pf-audit-flow-templates__composer-title">{t("auditFlow.saveAsTemplate")}</h4>
              <p className="pf-audit-flow-templates__composer-hint">
                {t("auditFlow.templateSaveHint", {
                  targets: targetCount,
                  creds: draftCredentials.length,
                })}
              </p>
            </div>
            <button type="button" className="pf-audit-flow-templates__composer-close" onClick={cancelSave}>
              {t("common.cancel")}
            </button>
          </div>

          <div className="pf-audit-flow-templates__composer-body pf-form pf-form--wide">
            <div className="pf-form__row">
              <div className="pf-form__group">
                <label htmlFor="af-template-name">{t("auditFlow.templateName")}</label>
                <input
                  id="af-template-name"
                  className="pf-input"
                  value={saveForm.name}
                  onChange={(e) => setSaveForm((prev) => ({ ...prev, name: e.target.value }))}
                  placeholder={t("auditFlow.templateNamePlaceholder")}
                  autoFocus
                />
              </div>
              <div className="pf-form__group">
                <label htmlFor="af-template-description">{t("auditFlow.templateDescription")}</label>
                <input
                  id="af-template-description"
                  className="pf-input"
                  value={saveForm.description}
                  onChange={(e) => setSaveForm((prev) => ({ ...prev, description: e.target.value }))}
                />
              </div>
            </div>

            <InventoryScopeFields
              idPrefix="af-template-scope"
              draft={saveForm}
              tags={tagsQuery.data ?? []}
              onChange={(patch) => setSaveForm((prev) => ({ ...prev, ...patch }))}
            />

            <JobSchedulePicker
              enabled={saveForm.isScheduled}
              config={saveForm.scheduleConfig}
              onEnabledChange={(enabled) => setSaveForm((prev) => ({ ...prev, isScheduled: enabled }))}
              onConfigChange={(config) => setSaveForm((prev) => ({ ...prev, scheduleConfig: config }))}
            />
            {saveForm.isScheduled ? (
              <p className="pf-audit-flow-templates__cron-preview">{cronPreview}</p>
            ) : null}

            <label className="pf-notify-switch">
              <input
                type="checkbox"
                checked={saveForm.isActive}
                onChange={(e) => setSaveForm((prev) => ({ ...prev, isActive: e.target.checked }))}
              />
              <span className="pf-notify-switch__track" aria-hidden />
              <span className="pf-notify-switch__label">{t("auditFlow.templateActive")}</span>
            </label>
          </div>

          <div className="pf-audit-flow-templates__composer-foot">
            <Button type="button" variant="secondary" className="pf-btn--sm" onClick={cancelSave}>
              {t("common.cancel")}
            </Button>
            <Button
              type="button"
              className="pf-btn--sm"
              disabled={!saveForm.name.trim() || !canSave || createMutation.isPending}
              title={!canSave ? t("auditFlow.templatesNeedTargets") : undefined}
              onClick={submitSave}
            >
              {t("auditFlow.saveTemplate")}
            </Button>
          </div>
        </div>
      ) : (
        <>
          {canManage && hasTemplates ? (
            <div className="pf-audit-flow-templates__toolbar">
              <span className="pf-audit-flow-templates__toolbar-label">{t("auditFlow.templatesList")}</span>
              <Button
                type="button"
                className="pf-btn--sm"
                onClick={openSave}
              >
                {t("auditFlow.saveAsTemplate")}
              </Button>
            </div>
          ) : null}

          {templates.isLoading ? (
            <div className="pf-audit-flow-templates__loading">
              <Spinner />
            </div>
          ) : !hasTemplates ? (
            <div className="pf-audit-flow-templates__empty">
              <EmptyState
                title={t("auditFlow.templatesEmpty")}
                description={t("auditFlow.templatesEmptyHint")}
              />
              {canManage ? (
                <div className="pf-audit-flow-templates__empty-action">
                  <Button type="button" onClick={openSave}>
                    {t("auditFlow.saveAsTemplate")}
                  </Button>
                </div>
              ) : null}
            </div>
          ) : (
            <ul className="pf-audit-flow-templates__list">
              {items.map((template) => {
                const scheduleLabel = template.is_scheduled
                  ? formatScheduleLabel(template.cron_expression, scheduleLabels)
                  : t("auditFlow.templateManual");
                const isEditing = editingId === template.id;
                return (
                  <li
                    key={template.id}
                    className={`pf-audit-flow-templates__row${isEditing ? " is-editing" : ""}`}
                  >
                    <div className="pf-audit-flow-templates__row-main">
                      <div className="pf-audit-flow-templates__meta">
                        <div className="pf-audit-flow-templates__name-row">
                          <strong className="pf-audit-flow-templates__name">{template.name}</strong>
                          {canSeeObjectOwners ? (
                            <ObjectOwnerCell ownerSub={template.owner_sub} />
                          ) : null}
                        </div>
                        {template.description ? (
                          <p className="pf-audit-flow-templates__description">{template.description}</p>
                        ) : null}
                        <p className="pf-audit-flow-templates__targets">
                          {(template.targets || []).join(", ") || t("auditFlow.inventoryScopeOnly")}
                        </p>
                        {template.inventory_scope ? (
                          <p className="pf-audit-flow-templates__targets">
                            {t("auditFlow.inventoryScopeSummary", {
                              tags: template.inventory_scope.tags.length
                                ? template.inventory_scope.tags.join(", ")
                                : t("auditFlow.inventoryScopeAnyTag"),
                              site: template.inventory_scope.site || t("auditFlow.inventoryScopeAnySite"),
                            })}
                          </p>
                        ) : null}
                        <div className="pf-audit-flow-templates__badges">
                          <Badge variant={template.is_active ? "success" : "neutral"}>
                            {template.is_active ? t("common.active") : t("common.inactive")}
                          </Badge>
                          <Badge variant={template.is_scheduled ? "info" : "neutral"}>
                            {scheduleLabel}
                          </Badge>
                          <Badge variant="neutral">
                            {t("auditFlow.templateCreds", {
                              count: template.credentials?.length ?? 0,
                            })}
                          </Badge>
                          {template.save_to_inventory ? (
                            <Badge variant="info">{t("auditFlow.saveToInventory")}</Badge>
                          ) : null}
                        </div>
                      </div>
                      <div className="pf-audit-flow-templates__row-actions">
                        <Button
                          type="button"
                          className="pf-btn--sm"
                          disabled={!canManage || !template.is_active || runMutation.isPending}
                          onClick={() => runMutation.mutate(template.id)}
                        >
                          {t("auditFlow.runNow")}
                        </Button>
                        {canManage ? (
                          <>
                            <Button
                              type="button"
                              variant="secondary"
                              className="pf-btn--sm"
                              onClick={() => startEdit(template)}
                            >
                              {t("common.edit")}
                            </Button>
                            <Button
                              type="button"
                              variant="danger-secondary"
                              className="pf-btn--sm"
                              onClick={() => deleteMutation.mutate(template.id)}
                            >
                              {t("common.delete")}
                            </Button>
                          </>
                        ) : null}
                      </div>
                    </div>

                    {isEditing ? (
                      <div className="pf-audit-flow-templates__inline-edit pf-form pf-form--wide">
                        <div className="pf-form__row">
                          <div className="pf-form__group">
                            <label htmlFor={`af-template-edit-name-${template.id}`}>
                              {t("auditFlow.templateName")}
                            </label>
                            <input
                              id={`af-template-edit-name-${template.id}`}
                              className="pf-input"
                              value={editForm.name}
                              onChange={(e) =>
                                setEditForm((prev) => ({ ...prev, name: e.target.value }))
                              }
                            />
                          </div>
                          <div className="pf-form__group">
                            <label htmlFor={`af-template-edit-desc-${template.id}`}>
                              {t("auditFlow.templateDescription")}
                            </label>
                            <input
                              id={`af-template-edit-desc-${template.id}`}
                              className="pf-input"
                              value={editForm.description}
                              onChange={(e) =>
                                setEditForm((prev) => ({ ...prev, description: e.target.value }))
                              }
                            />
                          </div>
                        </div>
                        <InventoryScopeFields
                          idPrefix={`af-template-scope-${template.id}`}
                          draft={editForm}
                          tags={tagsQuery.data ?? []}
                          onChange={(patch) => setEditForm((prev) => ({ ...prev, ...patch }))}
                        />
                        <JobSchedulePicker
                          enabled={editForm.isScheduled}
                          config={editForm.scheduleConfig}
                          onEnabledChange={(enabled) =>
                            setEditForm((prev) => ({ ...prev, isScheduled: enabled }))
                          }
                          onConfigChange={(config) =>
                            setEditForm((prev) => ({ ...prev, scheduleConfig: config }))
                          }
                        />
                        {editForm.isScheduled ? (
                          <p className="pf-audit-flow-templates__cron-preview">{editCronPreview}</p>
                        ) : null}
                        <label className="pf-notify-switch">
                          <input
                            type="checkbox"
                            checked={editForm.isActive}
                            onChange={(e) =>
                              setEditForm((prev) => ({ ...prev, isActive: e.target.checked }))
                            }
                          />
                          <span className="pf-notify-switch__track" aria-hidden />
                          <span className="pf-notify-switch__label">{t("auditFlow.templateActive")}</span>
                        </label>
                        <div className="pf-audit-flow-templates__actions">
                          <Button type="button" variant="secondary" className="pf-btn--sm" onClick={cancelEdit}>
                            {t("common.cancel")}
                          </Button>
                          <Button
                            type="button"
                            className="pf-btn--sm"
                            disabled={
                              !editForm.name.trim() ||
                              updateMutation.isPending ||
                              ((template.targets || []).length === 0 && editScope == null)
                            }
                            onClick={submitEdit}
                          >
                            {t("common.save")}
                          </Button>
                        </div>
                      </div>
                    ) : null}
                  </li>
                );
              })}
            </ul>
          )}
        </>
      )}
    </div>
  );
}
