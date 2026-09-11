import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import {
  api,
  type NotificationChannel,
  type NotificationChannelType,
  type NotificationEventType,
} from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { ObjectOwnerCell } from "./ObjectOwnerCell";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { EmptyState } from "./ui/EmptyState";
import { PasswordInput } from "./ui/PasswordInput";
import { Spinner } from "./ui/Spinner";
import { useToast } from "./ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";

type ChannelForm = {
  name: string;
  channel_type: "email" | "slack";
  is_active: boolean;
  events: NotificationEventType[];
  to_addresses: string;
  smtp_host: string;
  smtp_port: string;
  from_address: string;
  secret: string;
};

const CHANNEL_TYPES: Array<"email" | "slack"> = ["email", "slack"];

const RUN_EVENTS: NotificationEventType[] = [
  "run_failed",
  "run_completed",
  "run_stale",
  "dispatch_failed",
  "worker_heartbeat_stale",
  "worker_heartbeat_recovered",
];

const emptyForm = (): ChannelForm => ({
  name: "",
  channel_type: "email",
  is_active: true,
  events: ["run_failed", "run_stale", "dispatch_failed", "worker_heartbeat_stale"],
  to_addresses: "",
  smtp_host: "",
  smtp_port: "",
  from_address: "",
  secret: "",
});

function asUiChannelType(type: NotificationChannelType): "email" | "slack" {
  return type === "slack" ? "slack" : "email";
}

function formFromChannel(channel: NotificationChannel): ChannelForm {
  const config = channel.config_json ?? {};
  const recipients = Array.isArray(config.to_addresses) ? config.to_addresses.join(", ") : "";
  return {
    name: channel.name,
    channel_type: asUiChannelType(channel.channel_type),
    is_active: channel.is_active,
    events: channel.events.length ? channel.events : ["run_failed"],
    to_addresses: recipients,
    smtp_host: String(config.smtp_host ?? ""),
    smtp_port: config.smtp_port != null && config.smtp_port !== "" ? String(config.smtp_port) : "",
    from_address: String(config.from_address ?? ""),
    secret: "",
  };
}

function buildPayload(form: ChannelForm) {
  const config_json: Record<string, unknown> = {};
  if (form.channel_type === "email") {
    config_json.to_addresses = form.to_addresses
      .split(",")
      .map((item) => item.trim())
      .filter(Boolean);
    if (form.smtp_host.trim()) config_json.smtp_host = form.smtp_host.trim();
    if (form.smtp_port.trim()) config_json.smtp_port = Number(form.smtp_port.trim());
    if (form.from_address.trim()) config_json.from_address = form.from_address.trim();
  }
  return {
    name: form.name.trim(),
    channel_type: form.channel_type as NotificationChannelType,
    is_active: form.is_active,
    events: form.events,
    config_json: Object.keys(config_json).length ? config_json : null,
    secret: form.secret || undefined,
  };
}

function eventLabelKey(event: NotificationEventType) {
  return `notifications.eventNames.${event}` as const;
}

export function NotificationsSettings() {
  const { t } = useTranslation();
  const { canSeeObjectOwners } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<ChannelForm>(emptyForm());
  const [editingId, setEditingId] = useState<number | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [showSmtpAdvanced, setShowSmtpAdvanced] = useState(false);

  const channelTypeLabels = useMemo(
    () =>
      ({
        email: t("notifications.typeEmail"),
        slack: t("notifications.typeSlack"),
      }) satisfies Record<"email" | "slack", string>,
    [t]
  );

  const channels = useQuery({ queryKey: ["notification-channels"], queryFn: api.notificationChannels });

  const createMutation = useMutation({
    mutationFn: api.createNotificationChannel,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notification-channels"] });
      setForm(emptyForm());
      setShowForm(false);
      setShowSmtpAdvanced(false);
      toast.success(t("toast.notificationChannelCreated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: ReturnType<typeof buildPayload> }) =>
      api.updateNotificationChannel(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notification-channels"] });
      setEditingId(null);
      setForm(emptyForm());
      setShowForm(false);
      setShowSmtpAdvanced(false);
      toast.success(t("toast.notificationChannelUpdated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteNotificationChannel,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notification-channels"] });
      if (editingId != null) {
        setEditingId(null);
        setForm(emptyForm());
        setShowForm(false);
        setShowSmtpAdvanced(false);
      }
      toast.success(t("toast.notificationChannelDeleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const testMutation = useMutation({
    mutationFn: api.testNotificationChannel,
    onSuccess: (result) => {
      if (result.errors.length) {
        toast.error(result.errors.join("; "));
        return;
      }
      toast.success(t("toast.notificationTestSent"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const isEditing = editingId !== null;
  const needsWebhookSecret = form.channel_type === "slack";
  const hasChannels = Boolean(channels.data?.length);
  const isSaving = createMutation.isPending || updateMutation.isPending;
  const selectedEventsCount = form.events.length;

  const selectChannelType = (type: "email" | "slack") => {
    setForm({
      ...form,
      channel_type: type,
      secret: "",
      events: ["run_failed", "run_stale", "dispatch_failed", "worker_heartbeat_stale"],
    });
    if (type !== "email") setShowSmtpAdvanced(false);
  };

  const toggleEvent = (event: NotificationEventType) => {
    setForm((current) => ({
      ...current,
      events: current.events.includes(event)
        ? current.events.filter((item) => item !== event)
        : [...current.events, event],
    }));
  };

  const cancelForm = () => {
    setEditingId(null);
    setForm(emptyForm());
    setShowForm(false);
    setShowSmtpAdvanced(false);
  };

  const startCreate = () => {
    setEditingId(null);
    setForm(emptyForm());
    setShowSmtpAdvanced(false);
    setShowForm(true);
  };

  const startEdit = (channel: NotificationChannel) => {
    const next = formFromChannel(channel);
    setEditingId(channel.id);
    setForm(next);
    setShowSmtpAdvanced(Boolean(next.smtp_host || next.smtp_port || next.from_address));
    setShowForm(true);
  };

  const submit = () => {
    const payload = buildPayload(form);
    if (!payload.name) return;
    if (!payload.events.length) {
      toast.error(t("notifications.eventsRequired"));
      return;
    }
    if (needsWebhookSecret && !payload.secret && !isEditing) {
      toast.error(t("notifications.secretRequired"));
      return;
    }
    if (form.channel_type === "email" && !form.to_addresses.trim()) {
      toast.error(t("notifications.recipientsRequired"));
      return;
    }
    if (isEditing && editingId != null) {
      updateMutation.mutate({ id: editingId, data: payload });
      return;
    }
    createMutation.mutate(payload);
  };

  const typeLabel = (type: NotificationChannelType) => {
    if (type === "email") return channelTypeLabels.email;
    if (type === "slack") return channelTypeLabels.slack;
    return type;
  };

  return (
    <div className="pf-notifications-settings">
      {showForm ? (
        <div className="pf-notifications-settings__composer">
          <div className="pf-notifications-settings__composer-head">
            <div className="pf-notifications-settings__composer-head-copy">
              <h4 className="pf-notifications-settings__composer-title">
                {isEditing ? t("notifications.editTitle", { name: form.name }) : t("notifications.add")}
              </h4>
              <p className="pf-notifications-settings__composer-hint">{t("notifications.formHint")}</p>
            </div>
          </div>

          <div className="pf-notifications-settings__composer-body">
            <div className="pf-notifications-settings__form-grid">
              <section className="pf-notify-block pf-notify-block--type">
                <div className="pf-notify-block__head">
                  <h5 className="pf-notify-block__title">{t("notifications.type")}</h5>
                </div>
                <div className="pf-notify-type-tiles" role="group" aria-label={t("notifications.type")}>
                  {CHANNEL_TYPES.map((type) => (
                    <button
                      key={type}
                      type="button"
                      className={`pf-notify-type-tile${form.channel_type === type ? " is-active" : ""}`}
                      onClick={() => selectChannelType(type)}
                      aria-pressed={form.channel_type === type}
                      disabled={isSaving}
                    >
                      {channelTypeLabels[type]}
                    </button>
                  ))}
                </div>

                <div className="pf-form__group">
                  <label htmlFor="settings-channel-name">{t("common.name")}</label>
                  <input
                    id="settings-channel-name"
                    className="pf-input"
                    value={form.name}
                    onChange={(e) => setForm({ ...form, name: e.target.value })}
                    placeholder={form.channel_type === "slack" ? "ops-slack" : "ops-email"}
                    disabled={isSaving}
                  />
                </div>
              </section>

              <section className="pf-notify-block pf-notify-block--events">
                <div className="pf-notify-block__head">
                  <h5 className="pf-notify-block__title">
                    {t("notifications.events")}
                    <span className="pf-notify-block__meta">
                      {selectedEventsCount}/{RUN_EVENTS.length}
                    </span>
                  </h5>
                </div>
                <div className="pf-notify-event-grid">
                  {RUN_EVENTS.map((event) => {
                    const active = form.events.includes(event);
                    return (
                      <button
                        key={event}
                        type="button"
                        className={`pf-notify-event-chip${active ? " is-active" : ""}`}
                        onClick={() => toggleEvent(event)}
                        aria-pressed={active}
                        disabled={isSaving}
                      >
                        <span className="pf-notify-event-chip__mark" aria-hidden />
                        <span className="pf-notify-event-chip__text">{t(eventLabelKey(event))}</span>
                      </button>
                    );
                  })}
                </div>
              </section>

              <section className="pf-notify-block pf-notify-block--delivery">
              <div className="pf-notify-block__head">
                <h5 className="pf-notify-block__title">
                  {form.channel_type === "email"
                    ? t("notifications.typeEmail")
                    : t("notifications.typeSlack")}
                </h5>
                {form.channel_type === "email" ? (
                  <p className="pf-notify-block__desc">{t("notifications.smtpHint")}</p>
                ) : null}
              </div>

              {form.channel_type === "email" ? (
                <>
                  <div className="pf-form__group">
                    <label htmlFor="settings-channel-recipients">{t("notifications.recipients")}</label>
                    <input
                      id="settings-channel-recipients"
                      className="pf-input"
                      value={form.to_addresses}
                      onChange={(e) => setForm({ ...form, to_addresses: e.target.value })}
                      placeholder="soc@company.com, admin@company.com"
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
                    <div className="pf-notify-smtp">
                      <div className="pf-form__row">
                        <div className="pf-form__group">
                          <label htmlFor="settings-channel-from">{t("notifications.fromAddress")}</label>
                          <input
                            id="settings-channel-from"
                            className="pf-input"
                            value={form.from_address}
                            onChange={(e) => setForm({ ...form, from_address: e.target.value })}
                            placeholder="secaudit@localhost"
                            disabled={isSaving}
                          />
                        </div>
                        <div className="pf-form__group">
                          <label htmlFor="settings-channel-smtp-host">{t("notifications.smtpHost")}</label>
                          <input
                            id="settings-channel-smtp-host"
                            className="pf-input"
                            value={form.smtp_host}
                            onChange={(e) => setForm({ ...form, smtp_host: e.target.value })}
                            placeholder="mailpit"
                            disabled={isSaving}
                          />
                        </div>
                      </div>
                      <div className="pf-form__row">
                        <div className="pf-form__group">
                          <label htmlFor="settings-channel-smtp-port">{t("notifications.smtpPort")}</label>
                          <input
                            id="settings-channel-smtp-port"
                            className="pf-input"
                            value={form.smtp_port}
                            onChange={(e) => setForm({ ...form, smtp_port: e.target.value })}
                            placeholder="1025"
                            disabled={isSaving}
                          />
                        </div>
                        <div className="pf-form__group">
                          <label htmlFor="settings-channel-secret">{t("notifications.smtpPassword")}</label>
                          <PasswordInput
                            id="settings-channel-secret"
                            value={form.secret}
                            onChange={(e) => setForm({ ...form, secret: e.target.value })}
                            placeholder={isEditing ? t("notifications.keepSecretEmpty") : t("common.optional")}
                            disabled={isSaving}
                          />
                        </div>
                      </div>
                    </div>
                  ) : null}
                </>
              ) : (
                <div className="pf-form__group">
                  <label htmlFor="settings-channel-secret">{t("notifications.webhookUrl")}</label>
                  <PasswordInput
                    id="settings-channel-secret"
                    value={form.secret}
                    onChange={(e) => setForm({ ...form, secret: e.target.value })}
                    placeholder={isEditing ? t("notifications.keepSecretEmpty") : "https://hooks.slack.com/services/..."}
                    disabled={isSaving}
                  />
                  <p className="pf-form__hint">{t("notifications.slackHint")}</p>
                </div>
              )}
            </section>
            </div>
          </div>

          <div className="pf-notifications-settings__composer-foot">
            <label className="pf-notify-switch">
              <input
                type="checkbox"
                checked={form.is_active}
                onChange={(e) => setForm({ ...form, is_active: e.target.checked })}
                disabled={isSaving}
              />
              <span className="pf-notify-switch__track" aria-hidden />
              <span className="pf-notify-switch__label">{t("notifications.active")}</span>
            </label>
            <div className="pf-form__actions">
              <Button onClick={submit} loading={isSaving} disabled={isSaving}>
                {isEditing ? t("notifications.saveChanges") : t("common.create")}
              </Button>
              <Button variant="secondary" onClick={cancelForm} disabled={isSaving}>
                {t("common.cancel")}
              </Button>
            </div>
          </div>
        </div>
      ) : (
        <>
          <div className="pf-notifications-settings__toolbar">
            <div className="pf-notifications-settings__toolbar-copy">
              <span className="pf-notifications-settings__toolbar-label">{t("notifications.list")}</span>
              {hasChannels ? (
                <span className="pf-notifications-settings__toolbar-meta">
                  {channels.data?.length ?? 0}
                </span>
              ) : null}
            </div>
            <Button className="pf-btn--sm" onClick={startCreate}>
              {t("notifications.add")}
            </Button>
          </div>

          <div className="pf-notifications-settings__list">
            {channels.isLoading ? (
              <Spinner />
            ) : !hasChannels ? (
              <div className="pf-notifications-settings__empty">
                <EmptyState title={t("notifications.empty")} description={t("notifications.emptyDesc")} />
                <div className="pf-notifications-settings__empty-action">
                  <Button onClick={startCreate}>{t("notifications.add")}</Button>
                </div>
              </div>
            ) : (
              <div className="pf-notify-channel-cards">
                {channels.data?.map((channel) => (
                  <article key={channel.id} className="pf-notify-channel-card">
                    <div className="pf-notify-channel-card__main">
                      <div className="pf-notify-channel-card__title-row">
                        <h5 className="pf-notify-channel-card__name">{channel.name}</h5>
                        <Badge variant={channel.is_active ? "success" : "neutral"}>
                          {channel.is_active ? t("common.active") : t("common.inactive")}
                        </Badge>
                      </div>
                      <div className="pf-notify-channel-card__meta">
                        <span className="pf-notify-channel-card__type">{typeLabel(channel.channel_type)}</span>
                        {canSeeObjectOwners ? <ObjectOwnerCell ownerSub={channel.owner_sub} /> : null}
                      </div>
                      <div className="pf-notify-channel-card__events">
                        {channel.events.map((event) => (
                          <Badge key={event} variant="info">
                            {t(eventLabelKey(event))}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <div className="pf-notify-channel-card__actions">
                      <Button
                        variant="secondary"
                        className="pf-btn--sm"
                        onClick={() => testMutation.mutate(channel.id)}
                      >
                        {t("notifications.test")}
                      </Button>
                      <Button variant="secondary" className="pf-btn--sm" onClick={() => startEdit(channel)}>
                        {t("common.edit")}
                      </Button>
                      <Button
                        variant="danger-secondary"
                        className="pf-btn--sm"
                        onClick={() => deleteMutation.mutate(channel.id)}
                      >
                        {t("common.delete")}
                      </Button>
                    </div>
                  </article>
                ))}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
