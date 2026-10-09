import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { api, type DirectorySource, type DirectorySourceInput } from "../api/client";
import { useTranslation } from "../i18n/I18nProvider";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { useConfirm } from "./ui/ConfirmDialog";
import { Panel } from "./ui/Panel";
import { PasswordInput } from "./ui/PasswordInput";
import { useToast } from "./ui/Toast";

type DirectoryForm = DirectorySourceInput & { bind_password: string };

const EMPTY_FORM: DirectoryForm = {
  name: "",
  server: "",
  port: 389,
  use_ssl: false,
  start_tls: true,
  verify_tls: false,
  base_dn: "",
  bind_dn: "",
  bind_password: "",
  enabled_only: true,
  map_ou_to_site: true,
  is_active: true,
};

function statusVariant(status: string): "success" | "danger" | "warning" | "info" | "neutral" {
  switch (status) {
    case "completed":
      return "success";
    case "failed":
    case "cancelled":
      return "danger";
    case "running":
      return "info";
    case "pending":
      return "warning";
    default:
      return "neutral";
  }
}

export function DirectoryDiscoveryPanel({ canExecute }: { canExecute: boolean }) {
  const { t, dateLocale } = useTranslation();
  const toast = useToast();
  const { confirm } = useConfirm();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<DirectoryForm>(EMPTY_FORM);
  const [editingId, setEditingId] = useState<number | null>(null);
  const syncStatus = useRef(new Map<number, string>());

  const sources = useQuery({
    queryKey: ["directory-sources"],
    queryFn: api.directorySources,
  });
  const syncs = useQuery({
    queryKey: ["directory-syncs"],
    queryFn: api.directorySyncs,
    refetchInterval: (query) => {
      const live = query.state.data?.some((item) => item.status === "pending" || item.status === "running");
      return live ? 3000 : false;
    },
  });

  const sourceName = useMemo(() => {
    const map = new Map<number, string>();
    for (const source of sources.data ?? []) map.set(source.id, source.name);
    return map;
  }, [sources.data]);

  useEffect(() => {
    let refreshHosts = false;
    for (const sync of syncs.data ?? []) {
      const previous = syncStatus.current.get(sync.id);
      if (
        previous &&
        previous !== sync.status &&
        (sync.status === "completed" || sync.status === "failed")
      ) {
        refreshHosts = true;
      }
      syncStatus.current.set(sync.id, sync.status);
    }
    if (refreshHosts) {
      void queryClient.invalidateQueries({ queryKey: ["hosts"] });
    }
  }, [syncs.data, queryClient]);

  const payload = (): DirectorySourceInput => {
    const body: DirectorySourceInput = {
      name: form.name.trim(),
      server: form.server.trim(),
      port: form.port,
      use_ssl: form.use_ssl,
      start_tls: form.use_ssl ? false : form.start_tls,
      verify_tls: form.verify_tls,
      base_dn: form.base_dn.trim(),
      bind_dn: form.bind_dn.trim(),
      enabled_only: form.enabled_only,
      map_ou_to_site: form.map_ou_to_site,
      is_active: form.is_active,
    };
    if (form.bind_password.trim()) body.bind_password = form.bind_password;
    return body;
  };

  const invalidate = async () => {
    await queryClient.invalidateQueries({ queryKey: ["directory-sources"] });
    await queryClient.invalidateQueries({ queryKey: ["directory-syncs"] });
    await queryClient.invalidateQueries({ queryKey: ["hosts"] });
  };

  const saveMutation = useMutation({
    mutationFn: async () => {
      const body = payload();
      if (editingId == null) {
        if (!body.bind_password) throw new Error(t("hosts.directoryPassword"));
        return api.createDirectorySource(body);
      }
      return api.updateDirectorySource(editingId, body);
    },
    onSuccess: async () => {
      toast.success(t("hosts.directorySaved"));
      setForm(EMPTY_FORM);
      setEditingId(null);
      await invalidate();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const testMutation = useMutation({
    mutationFn: () => {
      const body = payload();
      return api.testDirectorySource({
        server: body.server,
        port: body.port,
        use_ssl: body.use_ssl,
        start_tls: body.start_tls,
        verify_tls: body.verify_tls,
        base_dn: body.base_dn,
        bind_dn: body.bind_dn,
        enabled_only: body.enabled_only,
        ...(body.bind_password ? { bind_password: body.bind_password } : {}),
        ...(editingId != null ? { source_id: editingId } : {}),
      });
    },
    onSuccess: (result) => {
      const summary =
        result.computers === 0
          ? t("hosts.directoryTestEmpty")
          : t("hosts.directoryTestOk", { count: result.computers });
      const sample = result.sample.length
        ? ` ${t("hosts.directoryTestSample", { sample: result.sample.join(", ") })}`
        : "";
      toast.success(`${summary}${sample}`);
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const syncMutation = useMutation({
    mutationFn: (sourceId: number) => api.startDirectorySync(sourceId),
    onSuccess: async () => {
      toast.success(t("hosts.directorySyncStarted"));
      await queryClient.invalidateQueries({ queryKey: ["directory-syncs"] });
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteMutation = useMutation({
    mutationFn: (sourceId: number) => api.deleteDirectorySource(sourceId),
    onSuccess: async () => {
      toast.success(t("hosts.directoryDeleted"));
      if (editingId != null) {
        setEditingId(null);
        setForm(EMPTY_FORM);
      }
      await invalidate();
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const editSource = (source: DirectorySource) => {
    setEditingId(source.id);
    setForm({
      name: source.name,
      server: source.server,
      port: source.port,
      use_ssl: source.use_ssl,
      start_tls: source.start_tls,
      verify_tls: source.verify_tls,
      base_dn: source.base_dn,
      bind_dn: source.bind_dn,
      bind_password: "",
      enabled_only: source.enabled_only,
      map_ou_to_site: source.map_ou_to_site,
      is_active: source.is_active,
    });
  };

  const setSsl = (useSsl: boolean) => {
    setForm((current) => ({
      ...current,
      use_ssl: useSsl,
      start_tls: useSsl ? false : current.port === 636 ? true : current.start_tls || true,
      port: useSsl && current.port === 389 ? 636 : !useSsl && current.port === 636 ? 389 : current.port,
    }));
  };

  const formReady = Boolean(form.name.trim() && form.server.trim() && form.base_dn.trim() && form.bind_dn.trim());
  const busy = saveMutation.isPending || testMutation.isPending;

  return (
    <Panel title={t("hosts.directoryTitle")}>
      <div className="pf-directory">
        {sources.isError ? (
          <div className="pf-alert pf-alert--error">
            {sources.error instanceof Error ? sources.error.message : t("toast.genericError")}
          </div>
        ) : null}
        <div className="pf-form pf-form--wide">
          <div className="pf-form__row pf-directory__endpoint">
            <div className="pf-form__group">
              <label htmlFor="directory-name">{t("hosts.directoryName")}</label>
              <input
                id="directory-name"
                className="pf-input"
                value={form.name}
                onChange={(event) => setForm({ ...form, name: event.target.value })}
              />
            </div>
            <div className="pf-form__group">
              <label htmlFor="directory-server">{t("hosts.directoryServer")}</label>
              <input
                id="directory-server"
                className="pf-input"
                value={form.server}
                placeholder="dc.corp.local"
                onChange={(event) => setForm({ ...form, server: event.target.value })}
              />
            </div>
            <div className="pf-form__group">
              <label htmlFor="directory-port">{t("hosts.directoryPort")}</label>
              <input
                id="directory-port"
                className="pf-input"
                type="number"
                min={1}
                max={65535}
                value={form.port}
                onChange={(event) => setForm({ ...form, port: Number(event.target.value) || 389 })}
              />
            </div>
          </div>
          <div className="pf-form__row pf-directory__identity">
            <div className="pf-form__group">
              <label htmlFor="directory-base-dn">{t("hosts.directoryBaseDn")}</label>
              <input
                id="directory-base-dn"
                className="pf-input"
                value={form.base_dn}
                placeholder="DC=corp,DC=local"
                onChange={(event) => setForm({ ...form, base_dn: event.target.value })}
              />
            </div>
            <div className="pf-form__group">
              <label htmlFor="directory-bind-dn">{t("hosts.directoryBindDn")}</label>
              <input
                id="directory-bind-dn"
                className="pf-input"
                value={form.bind_dn}
                placeholder="CN=secaudit,OU=Service,DC=corp,DC=local"
                onChange={(event) => setForm({ ...form, bind_dn: event.target.value })}
              />
            </div>
            <div className="pf-form__group">
              <label htmlFor="directory-password">{t("hosts.directoryPassword")}</label>
              <PasswordInput
                id="directory-password"
                autoComplete="new-password"
                value={form.bind_password}
                onChange={(event) => setForm({ ...form, bind_password: event.target.value })}
              />
              {editingId != null ? <p className="pf-form__hint">{t("hosts.directoryPasswordKeep")}</p> : null}
            </div>
          </div>
          <div className="pf-directory__options">
            <div className="pf-directory__option-group">
              <p className="pf-directory__option-label">{t("hosts.directoryConnection")}</p>
              <label className="pf-directory__option" htmlFor="directory-ssl">
                <input
                  id="directory-ssl"
                  type="checkbox"
                  className="pf-checkbox-control"
                  checked={form.use_ssl}
                  onChange={(event) => setSsl(event.target.checked)}
                />
                <span className="pf-directory__option-text">{t("hosts.directoryUseSsl")}</span>
              </label>
              <label className="pf-directory__option" htmlFor="directory-starttls">
                <input
                  id="directory-starttls"
                  type="checkbox"
                  className="pf-checkbox-control"
                  checked={form.start_tls && !form.use_ssl}
                  disabled={form.use_ssl}
                  onChange={(event) => setForm({ ...form, start_tls: event.target.checked })}
                />
                <span className="pf-directory__option-text">{t("hosts.directoryStartTls")}</span>
              </label>
              <label className="pf-directory__option" htmlFor="directory-verify">
                <input
                  id="directory-verify"
                  type="checkbox"
                  className="pf-checkbox-control"
                  checked={form.verify_tls}
                  onChange={(event) => setForm({ ...form, verify_tls: event.target.checked })}
                />
                <span className="pf-directory__option-text">{t("hosts.directoryVerifyTls")}</span>
              </label>
            </div>
            <div className="pf-directory__option-group">
              <p className="pf-directory__option-label">{t("hosts.directoryImportOptions")}</p>
              <label className="pf-directory__option" htmlFor="directory-enabled">
                <input
                  id="directory-enabled"
                  type="checkbox"
                  className="pf-checkbox-control"
                  checked={form.enabled_only}
                  onChange={(event) => setForm({ ...form, enabled_only: event.target.checked })}
                />
                <span className="pf-directory__option-text">{t("hosts.directoryEnabledOnly")}</span>
              </label>
              <label className="pf-directory__option" htmlFor="directory-ou">
                <input
                  id="directory-ou"
                  type="checkbox"
                  className="pf-checkbox-control"
                  checked={form.map_ou_to_site}
                  onChange={(event) => setForm({ ...form, map_ou_to_site: event.target.checked })}
                />
                <span className="pf-directory__option-text">{t("hosts.directoryMapOu")}</span>
              </label>
              <label className="pf-directory__option" htmlFor="directory-active">
                <input
                  id="directory-active"
                  type="checkbox"
                  className="pf-checkbox-control"
                  checked={form.is_active}
                  onChange={(event) => setForm({ ...form, is_active: event.target.checked })}
                />
                <span className="pf-directory__option-text">{t("hosts.directoryActive")}</span>
              </label>
            </div>
          </div>
          <div className="pf-directory__actions">
            {editingId != null ? (
              <Button
                variant="secondary"
                onClick={() => {
                  setEditingId(null);
                  setForm(EMPTY_FORM);
                }}
              >
                {t("common.cancel")}
              </Button>
            ) : null}
            <Button
              variant="secondary"
              onClick={() => testMutation.mutate()}
              disabled={!canExecute || !formReady || (editingId == null && !form.bind_password.trim()) || busy}
            >
              {t("hosts.directoryTest")}
            </Button>
            <Button
              onClick={() => saveMutation.mutate()}
              disabled={!canExecute || !formReady || (editingId == null && !form.bind_password.trim()) || busy}
              title={!canExecute ? t("common.demoActionDisabled") : undefined}
            >
              {editingId == null ? t("hosts.directorySave") : t("hosts.saveChanges")}
            </Button>
          </div>
        </div>

        {(sources.data?.length ?? 0) > 0 ? (
          <div className="pf-directory__list">
            {sources.data?.map((source) => (
              <div key={source.id} className="pf-directory__source">
                <div className="pf-directory__source-main">
                  <span className="pf-directory__source-title">
                    {source.name}
                    {!source.is_active ? (
                      <>
                        {" "}
                        <Badge variant="neutral">{t("hosts.listStatusInactive")}</Badge>
                      </>
                    ) : null}
                  </span>
                  <div className="pf-directory__source-meta">
                    <code>
                      {source.server}:{source.port}
                    </code>
                    <span>{source.base_dn}</span>
                    <span>{source.bind_dn}</span>
                  </div>
                </div>
                <div className="pf-directory__source-actions">
                  <Button variant="secondary" className="pf-btn--sm" onClick={() => editSource(source)}>
                    {t("common.edit")}
                  </Button>
                  <Button
                    className="pf-btn--sm"
                    onClick={() => syncMutation.mutate(source.id)}
                    disabled={!canExecute || !source.is_active || syncMutation.isPending}
                  >
                    {t("hosts.directorySync")}
                  </Button>
                  <Button
                    variant="danger-secondary"
                    className="pf-btn--sm"
                    disabled={!canExecute || deleteMutation.isPending}
                    onClick={async () => {
                      const ok = await confirm({
                        title: t("common.delete"),
                        message: t("hosts.directoryDeleteConfirm", { name: source.name }),
                        variant: "danger",
                      });
                      if (ok) deleteMutation.mutate(source.id);
                    }}
                  >
                    {t("common.delete")}
                  </Button>
                </div>
              </div>
            ))}
          </div>
        ) : null}

        {(syncs.data?.length ?? 0) > 0 ? (
          <div className="pf-directory__list">
            <p className="pf-form__hint pf-directory__list-title">{t("hosts.directoryHistory")}</p>
            {syncs.data?.map((sync) => (
              <div key={sync.id} className="pf-directory__source">
                <div className="pf-directory__source-main">
                  <span className="pf-directory__source-title">
                    #{sync.id} · {sourceName.get(sync.source_id) ?? sync.source_id}
                  </span>
                  <div className="pf-directory__source-meta">
                    <Badge variant={statusVariant(sync.status)} literal>
                      {sync.status}
                    </Badge>
                    <span>
                      {t("hosts.directoryFound")}: <strong>{sync.hosts_found}</strong>
                    </span>
                    <span>
                      {t("hosts.directoryCreated")}: <strong>{sync.hosts_created}</strong>
                    </span>
                    <span>
                      {t("hosts.directoryUpdated")}: <strong>{sync.hosts_updated}</strong>
                    </span>
                    <span>
                      {t("hosts.directoryMatched")}: <strong>{sync.hosts_matched}</strong>
                    </span>
                    <span>{new Date(sync.created_at).toLocaleString(dateLocale)}</span>
                    {sync.error_message ? <span>{sync.error_message}</span> : null}
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : null}
      </div>
    </Panel>
  );
}
