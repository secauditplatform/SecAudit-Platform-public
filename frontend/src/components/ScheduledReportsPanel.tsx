import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import {
  api,
  type ScheduledReport,
  type ScheduledReportFormat,
} from "../api/client";
import { JobSchedulePicker, useScheduleLabels } from "./JobSchedulePicker";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { EmptyState } from "./ui/EmptyState";
import { PasswordInput } from "./ui/PasswordInput";
import { Spinner } from "./ui/Spinner";
import { useToast } from "./ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";
import {
  buildCronExpression,
  DEFAULT_SCHEDULE,
  formatScheduleLabel,
  parseCronExpression,
  type ScheduleConfig,
} from "../utils/jobSchedule";

type ScheduleForm = {
  name: string;
  job_id: number | null;
  is_active: boolean;
  schedule: ScheduleConfig;
  report_format: ScheduledReportFormat;
  to_addresses: string;
  smtp_host: string;
  smtp_port: string;
  smtp_from: string;
  smtp_user: string;
  use_tls: boolean;
  secret: string;
};

const FORMATS: ScheduledReportFormat[] = ["pdf", "html", "both"];

const emptyForm = (): ScheduleForm => ({
  name: "",
  job_id: null,
  is_active: true,
  schedule: { ...DEFAULT_SCHEDULE },
  report_format: "pdf",
  to_addresses: "",
  smtp_host: "",
  smtp_port: "",
  smtp_from: "",
  smtp_user: "",
  use_tls: false,
  secret: "",
});

function formFromSchedule(schedule: ScheduledReport): ScheduleForm {
  const config = schedule.config_json ?? {};
  const recipients = Array.isArray(config.to_addresses)
    ? config.to_addresses.join(", ")
    : String(config.to_addresses ?? "");
  return {
    name: schedule.name,
    job_id: schedule.job_id,
    is_active: schedule.is_active,
    schedule: parseCronExpression(schedule.cron_expression),
    report_format: schedule.report_format,
    to_addresses: recipients,
    smtp_host: String(config.smtp_host ?? ""),
    smtp_port: config.smtp_port != null ? String(config.smtp_port) : "",
    smtp_from: String(config.from_address ?? ""),
    smtp_user: String(config.smtp_user ?? ""),
    use_tls: Boolean(config.use_tls ?? false),
    secret: "",
  };
}

function buildPayload(form: ScheduleForm, locale: string) {
  const config_json: Record<string, unknown> = {
    to_addresses: form.to_addresses
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean),
    use_tls: form.use_tls,
    locale,
  };
  if (form.smtp_host.trim()) config_json.smtp_host = form.smtp_host.trim();
  if (form.smtp_port.trim()) config_json.smtp_port = Number(form.smtp_port.trim());
  if (form.smtp_from.trim()) config_json.from_address = form.smtp_from.trim();
  if (form.smtp_user.trim()) config_json.smtp_user = form.smtp_user.trim();

  return {
    name: form.name,
    job_id: form.job_id!,
    cron_expression: buildCronExpression(form.schedule),
    is_active: form.is_active,
    report_format: form.report_format,
    delivery_type: "email" as const,
    config_json,
    secret: form.secret || undefined,
  };
}

type ScheduledReportsPanelProps = {
  canManage: boolean;
};

export function ScheduledReportsPanel({ canManage }: ScheduledReportsPanelProps) {
  const { t, locale } = useTranslation();
  const toast = useToast();
  const queryClient = useQueryClient();
  const scheduleLabels = useScheduleLabels();
  const [form, setForm] = useState<ScheduleForm>(emptyForm());
  const [editingId, setEditingId] = useState<number | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [showSmtpAdvanced, setShowSmtpAdvanced] = useState(false);

  const formatLabels = useMemo(
    () =>
      ({
        pdf: t("scheduledReports.formatPdf"),
        html: t("scheduledReports.formatHtml"),
        both: t("scheduledReports.formatBoth"),
      }) satisfies Record<ScheduledReportFormat, string>,
    [t]
  );

  const schedules = useQuery({
    queryKey: ["scheduled-reports"],
    queryFn: api.scheduledReports,
  });
  const jobs = useQuery({ queryKey: ["jobs"], queryFn: () => api.jobs() });

  const jobNameById = useMemo(() => {
    const map = new Map<number, string>();
    jobs.data?.forEach((job) => map.set(job.id, job.name));
    return map;
  }, [jobs.data]);

  const createMutation = useMutation({
    mutationFn: api.createScheduledReport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scheduled-reports"] });
      setForm(emptyForm());
      setShowSmtpAdvanced(false);
      setShowForm(false);
      toast.success(t("toast.scheduledReportCreated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: ReturnType<typeof buildPayload> }) =>
      api.updateScheduledReport(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scheduled-reports"] });
      setEditingId(null);
      setForm(emptyForm());
      setShowSmtpAdvanced(false);
      setShowForm(false);
      toast.success(t("toast.scheduledReportUpdated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteScheduledReport,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["scheduled-reports"] });
      if (editingId != null) {
        setEditingId(null);
        setForm(emptyForm());
        setShowSmtpAdvanced(false);
        setShowForm(false);
      }
      toast.success(t("toast.scheduledReportDeleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deliverMutation = useMutation({
    mutationFn: (id: number) => api.deliverScheduledReport(id),
    onSuccess: (result) => {
      queryClient.invalidateQueries({ queryKey: ["scheduled-reports"] });
      if (!result.delivered) {
        const reason = result.reason ?? "unknown";
        const reasonKey = `scheduledReports.reason.${reason}` as const;
        const translated = t(reasonKey);
        toast.error(translated !== reasonKey ? translated : (result.reason ?? t("scheduledReports.deliverFailed")));
        return;
      }
      toast.success(t("toast.scheduledReportDelivered"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const isEditing = editingId !== null;
  const hasSchedules = Boolean(schedules.data?.length);
  const isSaving = createMutation.isPending || updateMutation.isPending;

  const cancelForm = () => {
    setEditingId(null);
    setForm(emptyForm());
    setShowSmtpAdvanced(false);
    setShowForm(false);
  };

  const startCreate = () => {
    setEditingId(null);
    setForm(emptyForm());
    setShowSmtpAdvanced(false);
    setShowForm(true);
  };

  const startEdit = (schedule: ScheduledReport) => {
    const next = formFromSchedule(schedule);
    setEditingId(schedule.id);
    setForm(next);
    setShowSmtpAdvanced(
      Boolean(
        next.smtp_host.trim() ||
          next.smtp_port.trim() ||
          next.smtp_from.trim() ||
          next.smtp_user.trim() ||
          next.use_tls
      )
    );
    setShowForm(true);
  };

  const submit = () => {
    if (!form.name.trim() || form.job_id == null) return;
    if (!form.to_addresses.trim() && !isEditing) {
      toast.error(t("scheduledReports.recipientsRequired"));
      return;
    }
    const payload = buildPayload(form, locale);
    if (isEditing && editingId != null) {
      updateMutation.mutate({ id: editingId, data: payload });
      return;
    }
    createMutation.mutate(payload);
  };

  if (!canManage && !hasSchedules) {
    return null;
  }

  return (
    <div className="pf-scheduled-reports">
      {showForm && canManage ? (
        <div className="pf-scheduled-reports__composer">
          <div className="pf-scheduled-reports__composer-head">
            <h4 className="pf-scheduled-reports__composer-title">
              {isEditing ? t("scheduledReports.editTitle", { name: form.name }) : t("scheduledReports.add")}
            </h4>
          </div>

          <div className="pf-scheduled-reports__composer-body">
            <section className="pf-scheduled-reports__section" aria-labelledby="schedule-basics-heading">
              <div className="pf-scheduled-reports__section-head">
                <h5 id="schedule-basics-heading" className="pf-scheduled-reports__section-title">
                  {t("scheduledReports.basicsSection")}
                </h5>
              </div>
              <div className="pf-form__row">
                <div className="pf-form__group">
                  <label htmlFor="schedule-name">{t("common.name")}</label>
                  <input
                    id="schedule-name"
                    className="pf-input"
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    placeholder="weekly-compliance"
                    disabled={isSaving}
                  />
                </div>
                <div className="pf-form__group">
                  <label htmlFor="schedule-job">{t("scheduledReports.job")}</label>
                  <select
                    id="schedule-job"
                    className="pf-select"
                    value={form.job_id ?? ""}
                    onChange={(e) =>
                      setForm({ ...form, job_id: e.target.value ? Number(e.target.value) : null })
                    }
                    disabled={isSaving}
                  >
                    <option value="">{t("scheduledReports.selectJob")}</option>
                    {jobs.data?.map((job) => (
                      <option key={job.id} value={job.id}>
                        {job.name}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
            </section>

            <section className="pf-scheduled-reports__section" aria-labelledby="schedule-timing-heading">
              <div className="pf-scheduled-reports__section-head">
                <h5 id="schedule-timing-heading" className="pf-scheduled-reports__section-title">
                  {t("scheduledReports.schedule")}
                </h5>
              </div>
              <JobSchedulePicker
                enabled
                onEnabledChange={() => undefined}
                config={form.schedule}
                onConfigChange={(schedule) => setForm({ ...form, schedule })}
              />
            </section>

            <section className="pf-scheduled-reports__section" aria-labelledby="schedule-format-heading">
              <div className="pf-scheduled-reports__section-head">
                <h5 id="schedule-format-heading" className="pf-scheduled-reports__section-title">
                  {t("scheduledReports.format")}
                </h5>
              </div>
              <div className="pf-scheduled-reports__format-grid" role="group" aria-label={t("scheduledReports.format")}>
                {FORMATS.map((format) => (
                  <button
                    key={format}
                    type="button"
                    className={`pf-scheduled-reports__chip${form.report_format === format ? " is-active" : ""}`}
                    aria-pressed={form.report_format === format}
                    onClick={() => setForm({ ...form, report_format: format })}
                    disabled={isSaving}
                  >
                    {formatLabels[format]}
                  </button>
                ))}
              </div>
            </section>

            <section className="pf-scheduled-reports__section pf-scheduled-reports__section--email" aria-labelledby="schedule-email-heading">
              <div className="pf-scheduled-reports__section-head">
                <h5 id="schedule-email-heading" className="pf-scheduled-reports__section-title">
                  {t("scheduledReports.emailSection")}
                </h5>
                <p className="pf-scheduled-reports__section-desc">{t("scheduledReports.smtpHint")}</p>
              </div>

              <div className="pf-form__group">
                <label htmlFor="schedule-recipients">{t("scheduledReports.recipients")}</label>
                <input
                  id="schedule-recipients"
                  className="pf-input"
                  value={form.to_addresses}
                  onChange={(e) => setForm({ ...form, to_addresses: e.target.value })}
                  placeholder="soc@company.com, ciso@company.com"
                  disabled={isSaving}
                />
              </div>

              <Button
                type="button"
                variant="link"
                className="pf-btn--sm pf-notify-form__advanced-toggle"
                aria-expanded={showSmtpAdvanced}
                onClick={() => setShowSmtpAdvanced((value) => !value)}
              >
                {showSmtpAdvanced ? t("notifications.hideSmtp") : t("notifications.showSmtp")}
              </Button>

              {showSmtpAdvanced ? (
                <div className="pf-scheduled-reports__smtp">
                  <div className="pf-form__row">
                    <div className="pf-form__group">
                      <label htmlFor="schedule-smtp-host">{t("scheduledReports.smtpHost")}</label>
                      <input
                        id="schedule-smtp-host"
                        className="pf-input"
                        value={form.smtp_host}
                        onChange={(e) => setForm({ ...form, smtp_host: e.target.value })}
                        placeholder={t("scheduledReports.smtpHostPlaceholder")}
                        disabled={isSaving}
                      />
                    </div>
                    <div className="pf-form__group">
                      <label htmlFor="schedule-smtp-port">{t("scheduledReports.smtpPort")}</label>
                      <input
                        id="schedule-smtp-port"
                        className="pf-input"
                        value={form.smtp_port}
                        onChange={(e) => setForm({ ...form, smtp_port: e.target.value })}
                        placeholder="1025"
                        disabled={isSaving}
                      />
                    </div>
                  </div>
                  <div className="pf-form__row">
                    <div className="pf-form__group">
                      <label htmlFor="schedule-smtp-from">{t("scheduledReports.smtpFrom")}</label>
                      <input
                        id="schedule-smtp-from"
                        className="pf-input"
                        value={form.smtp_from}
                        onChange={(e) => setForm({ ...form, smtp_from: e.target.value })}
                        placeholder="secaudit@localhost"
                        disabled={isSaving}
                      />
                    </div>
                    <div className="pf-form__group">
                      <label htmlFor="schedule-smtp-user">{t("scheduledReports.smtpUser")}</label>
                      <input
                        id="schedule-smtp-user"
                        className="pf-input"
                        value={form.smtp_user}
                        onChange={(e) => setForm({ ...form, smtp_user: e.target.value })}
                        placeholder={t("scheduledReports.smtpUserPlaceholder")}
                        disabled={isSaving}
                      />
                    </div>
                  </div>
                  <div className="pf-form__group">
                    <label htmlFor="schedule-secret">{t("scheduledReports.smtpPassword")}</label>
                    <PasswordInput
                      id="schedule-secret"
                      value={form.secret}
                      onChange={(e) => setForm({ ...form, secret: e.target.value })}
                      placeholder={isEditing ? t("scheduledReports.keepSecretEmpty") : ""}
                      disabled={isSaving}
                    />
                  </div>
                  <label className="pf-form__checkbox-label" htmlFor="schedule-smtp-tls">
                    <input
                      id="schedule-smtp-tls"
                      type="checkbox"
                      checked={form.use_tls}
                      onChange={(e) => setForm({ ...form, use_tls: e.target.checked })}
                      disabled={isSaving}
                    />
                    {t("scheduledReports.smtpTls")}
                  </label>
                </div>
              ) : null}
            </section>

            <div className="pf-scheduled-reports__status-row">
              <label className="pf-notify-switch">
                <input
                  type="checkbox"
                  checked={form.is_active}
                  onChange={(e) => setForm({ ...form, is_active: e.target.checked })}
                  disabled={isSaving}
                />
                <span className="pf-notify-switch__track" aria-hidden />
                <span className="pf-notify-switch__label">{t("scheduledReports.active")}</span>
              </label>
            </div>
          </div>

          <div className="pf-scheduled-reports__composer-foot">
            <div className="pf-form__actions">
              <Button onClick={submit} loading={isSaving} disabled={isSaving}>
                {isEditing ? t("scheduledReports.saveChanges") : t("common.create")}
              </Button>
              <Button variant="secondary" onClick={cancelForm} disabled={isSaving}>
                {t("common.cancel")}
              </Button>
            </div>
          </div>
        </div>
      ) : (
        <>
          {canManage && hasSchedules ? (
            <div className="pf-scheduled-reports__toolbar">
              <span className="pf-scheduled-reports__toolbar-label">{t("scheduledReports.list")}</span>
              <Button onClick={startCreate}>{t("scheduledReports.add")}</Button>
            </div>
          ) : null}

          <div className="pf-scheduled-reports__list">
            {schedules.isLoading ? (
              <Spinner />
            ) : !hasSchedules ? (
              canManage ? (
                <div className="pf-scheduled-reports__empty">
                  <EmptyState title={t("scheduledReports.empty")} />
                  <div className="pf-scheduled-reports__empty-action">
                    <Button onClick={startCreate}>{t("scheduledReports.add")}</Button>
                  </div>
                </div>
              ) : (
                <EmptyState title={t("scheduledReports.empty")} />
              )
            ) : (
              <div className="pf-table-wrap">
                <table className="pf-table pf-table--compact">
                  <thead>
                    <tr>
                      <th>{t("common.name")}</th>
                      <th>{t("scheduledReports.job")}</th>
                      <th>{t("scheduledReports.schedule")}</th>
                      <th>{t("common.status")}</th>
                      <th className="pf-table__col-actions">{t("common.actions")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {schedules.data?.map((schedule) => (
                      <tr key={schedule.id}>
                        <td>
                          <div className="pf-scheduled-reports__name">{schedule.name}</div>
                          <div className="pf-scheduled-reports__meta">
                            <Badge variant="info">{formatLabels[schedule.report_format]}</Badge>
                            <Badge variant="neutral">{t("scheduledReports.deliveryEmail")}</Badge>
                          </div>
                        </td>
                        <td>{jobNameById.get(schedule.job_id) ?? `#${schedule.job_id}`}</td>
                        <td>{formatScheduleLabel(schedule.cron_expression, scheduleLabels)}</td>
                        <td>
                          <Badge variant={schedule.is_active ? "success" : "neutral"}>
                            {schedule.is_active ? t("common.active") : t("common.inactive")}
                          </Badge>
                        </td>
                        <td className="pf-table__col-actions">
                          {canManage ? (
                            <div className="pf-table__actions">
                              <Button
                                variant="primary"
                                className="pf-btn--sm"
                                onClick={() => deliverMutation.mutate(schedule.id)}
                              >
                                {t("scheduledReports.sendNow")}
                              </Button>
                              <Button variant="secondary" className="pf-btn--sm" onClick={() => startEdit(schedule)}>
                                {t("common.edit")}
                              </Button>
                              <Button
                                variant="danger-secondary"
                                className="pf-btn--sm"
                                onClick={() => deleteMutation.mutate(schedule.id)}
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
