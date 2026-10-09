import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import {
  api,
  type ApiKey,
  type ApiKeyCreated,
  type ApiKeyScope,
} from "../api/client";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { DateInput } from "./ui/DateInput";
import { IconCredentials } from "./ui/Icons";
import { Panel } from "./ui/Panel";
import { Spinner } from "./ui/Spinner";
import { useConfirm } from "./ui/ConfirmDialog";
import { useToast } from "./ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";

const ALL_SCOPES: ApiKeyScope[] = ["jobs:run", "reports:read", "inventory:scan"];

type KeyForm = {
  name: string;
  scopes: ApiKeyScope[];
  expires_at: string;
};

const emptyForm = (): KeyForm => ({
  name: "",
  scopes: ["jobs:run"],
  expires_at: "",
});

function statusVariant(key: ApiKey): "success" | "warning" | "danger" | "neutral" {
  if (key.revoked_at || !key.is_active) return "danger";
  if (key.expires_at && new Date(key.expires_at).getTime() <= Date.now()) return "warning";
  return "success";
}

function statusLabel(
  key: ApiKey,
  t: (key: string, params?: Record<string, string | number>) => string
): string {
  if (key.revoked_at) return t("users.apiKeys.statusRevoked");
  if (!key.is_active) return t("users.apiKeys.statusInactive");
  if (key.expires_at && new Date(key.expires_at).getTime() <= Date.now()) {
    return t("users.apiKeys.statusExpired");
  }
  return t("users.apiKeys.statusActive");
}

export function ApiKeysPanel() {
  const { t, dateLocale } = useTranslation();
  const toast = useToast();
  const { confirm } = useConfirm();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<KeyForm>(emptyForm());
  const [showForm, setShowForm] = useState(false);
  const [revealedSecret, setRevealedSecret] = useState<string | null>(null);

  const keys = useQuery({
    queryKey: ["api-keys"],
    queryFn: api.apiKeys,
  });

  const keyList = keys.data ?? [];
  const hasKeys = keyList.length > 0;

  const scopeMeta = useMemo(
    () =>
      ALL_SCOPES.map((scope) => ({
        scope,
        label: t(`users.apiKeys.scopes.${scope}`),
        desc: t(`users.apiKeys.scopeDesc.${scope}`),
      })),
    [t]
  );

  const createMutation = useMutation({
    mutationFn: api.createApiKey,
    onSuccess: (created: ApiKeyCreated) => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
      setForm(emptyForm());
      setShowForm(false);
      setRevealedSecret(created.secret);
      toast.success(t("users.apiKeys.created"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const rotateMutation = useMutation({
    mutationFn: api.rotateApiKey,
    onSuccess: (created: ApiKeyCreated) => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
      setRevealedSecret(created.secret);
      toast.success(t("users.apiKeys.rotated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const revokeMutation = useMutation({
    mutationFn: api.revokeApiKey,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
      toast.success(t("users.apiKeys.revoked"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteApiKey,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-keys"] });
      toast.success(t("users.apiKeys.deleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const openCreate = () => {
    setForm(emptyForm());
    setShowForm(true);
  };

  const closeComposer = () => {
    setShowForm(false);
    setForm(emptyForm());
  };

  const toggleScope = (scope: ApiKeyScope) => {
    setForm((prev) => {
      const has = prev.scopes.includes(scope);
      const scopes = has ? prev.scopes.filter((s) => s !== scope) : [...prev.scopes, scope];
      return { ...prev, scopes };
    });
  };

  const handleCreate = () => {
    if (!form.name.trim() || form.scopes.length === 0) {
      toast.error(t("users.apiKeys.validation"));
      return;
    }
    createMutation.mutate({
      name: form.name.trim(),
      scopes: form.scopes,
      expires_at: form.expires_at ? `${form.expires_at}T23:59:59.000Z` : null,
    });
  };

  const handleRotate = async (key: ApiKey) => {
    const ok = await confirm({
      title: t("users.apiKeys.rotateTitle"),
      message: t("users.apiKeys.rotateConfirm", { name: key.name }),
      confirmLabel: t("users.apiKeys.rotate"),
      variant: "danger",
    });
    if (ok) rotateMutation.mutate(key.id);
  };

  const handleRevoke = async (key: ApiKey) => {
    const ok = await confirm({
      title: t("users.apiKeys.revokeTitle"),
      message: t("users.apiKeys.revokeConfirm", { name: key.name }),
      confirmLabel: t("users.apiKeys.revoke"),
      variant: "danger",
    });
    if (ok) revokeMutation.mutate(key.id);
  };

  const handleDelete = async (key: ApiKey) => {
    const ok = await confirm({
      title: t("users.apiKeys.deleteTitle"),
      message: t("users.apiKeys.deleteConfirm", { name: key.name }),
      confirmLabel: t("common.delete"),
      variant: "danger",
    });
    if (ok) deleteMutation.mutate(key.id);
  };

  const copySecret = async () => {
    if (!revealedSecret) return;
    try {
      await navigator.clipboard.writeText(revealedSecret);
      toast.success(t("users.apiKeys.copied"));
    } catch {
      toast.error(t("toast.genericError"));
    }
  };

  const toolbar = showForm ? (
    <Button variant="secondary" className="pf-btn--sm" onClick={closeComposer}>
      {t("common.cancel")}
    </Button>
  ) : hasKeys ? (
    <Button className="pf-btn--sm" onClick={openCreate}>
      {t("users.apiKeys.add")}
    </Button>
  ) : null;

  return (
    <Panel
      title={t("users.apiKeys.title")}
      toolbar={toolbar}
      noPadding
      className="pf-api-keys-panel"
    >
      <div className="pf-api-keys">
        {revealedSecret ? (
          <div className="pf-api-keys__secret" role="status">
            <div className="pf-api-keys__secret-intro">
              <strong className="pf-api-keys__secret-title">{t("users.apiKeys.secretTitle")}</strong>
              <p className="pf-api-keys__secret-hint">{t("users.apiKeys.secretHint")}</p>
            </div>
            <div className="pf-api-keys__secret-body">
              <code className="pf-api-keys__secret-value">{revealedSecret}</code>
              <div className="pf-api-keys__secret-actions">
                <Button variant="primary" className="pf-btn--sm" onClick={() => void copySecret()}>
                  {t("users.apiKeys.copy")}
                </Button>
                <Button variant="secondary" className="pf-btn--sm" onClick={() => setRevealedSecret(null)}>
                  {t("common.close")}
                </Button>
              </div>
            </div>
          </div>
        ) : null}

        {showForm ? (
          <form
            className="pf-api-keys__form"
            onSubmit={(e) => {
              e.preventDefault();
              handleCreate();
            }}
          >
            <div className="pf-api-keys__grid">
              <div className="pf-form__group pf-api-keys__field-name">
                <label htmlFor="api-key-name">{t("users.apiKeys.name")}</label>
                <input
                  id="api-key-name"
                  className="pf-input"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder={t("users.apiKeys.namePlaceholder")}
                  autoComplete="off"
                  autoFocus
                />
              </div>
              <div className="pf-form__group pf-api-keys__field-expires">
                <label htmlFor="api-key-expires">{t("users.apiKeys.expires")}</label>
                <DateInput
                  id="api-key-expires"
                  className="pf-input"
                  value={form.expires_at}
                  onChange={(e) => setForm({ ...form, expires_at: e.target.value })}
                />
                <p className="pf-form__hint">{t("users.apiKeys.expiresHint")}</p>
              </div>
            </div>

            <div className="pf-form__group">
              <span className="pf-api-keys__scopes-label" id="api-keys-scopes-label">
                {t("users.apiKeys.scopesLabel")}
              </span>
              <div className="pf-table-wrap pf-api-keys__scopes-wrap">
                <table
                  className="pf-table pf-table--compact pf-api-keys__scopes-table"
                  aria-labelledby="api-keys-scopes-label"
                >
                  <thead>
                    <tr>
                      <th
                        scope="col"
                        className="pf-api-keys__scopes-check"
                        aria-label={t("users.apiKeys.scopesLabel")}
                      />
                      <th scope="col">{t("users.apiKeys.scopeColumn")}</th>
                      <th scope="col">{t("users.apiKeys.descriptionColumn")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scopeMeta.map(({ scope, label, desc }) => {
                      const selected = form.scopes.includes(scope);
                      const inputId = `api-key-scope-${scope.replace(":", "-")}`;
                      return (
                        <tr
                          key={scope}
                          className={selected ? "pf-table__row--selected" : undefined}
                        >
                          <td className="pf-api-keys__scopes-check">
                            <input
                              id={inputId}
                              type="checkbox"
                              className="pf-checkbox-control"
                              checked={selected}
                              onChange={() => toggleScope(scope)}
                              aria-label={label}
                            />
                          </td>
                          <td>
                            <label htmlFor={inputId} className="pf-api-keys__scope-code">
                              {label}
                            </label>
                          </td>
                          <td>
                            <label htmlFor={inputId} className="pf-api-keys__scope-desc">
                              {desc}
                            </label>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            <div className="pf-api-keys__actions">
              <Button
                type="submit"
                disabled={!form.name.trim() || form.scopes.length === 0 || createMutation.isPending}
              >
                {t("users.apiKeys.create")}
              </Button>
            </div>
          </form>
        ) : null}

        {keys.isLoading ? (
          <div className="pf-api-keys__loading">
            <Spinner />
          </div>
        ) : keys.isError ? (
          <div className="pf-api-keys__empty">
            <p className="pf-api-keys__empty-desc">
              {keys.error instanceof Error ? keys.error.message : t("toast.genericError")}
            </p>
          </div>
        ) : !hasKeys && !showForm ? (
          <div className="pf-api-keys__empty">
            <div className="pf-api-keys__empty-icon" aria-hidden>
              <IconCredentials />
            </div>
            <div className="pf-api-keys__empty-copy">
              <h3 className="pf-api-keys__empty-title">{t("users.apiKeys.empty")}</h3>
              <p className="pf-api-keys__empty-desc">{t("users.apiKeys.emptyDesc")}</p>
            </div>
            <Button onClick={openCreate}>{t("users.apiKeys.emptyAction")}</Button>
          </div>
        ) : hasKeys ? (
          <div className="pf-table-wrap pf-api-keys__table">
            <table className="pf-table pf-table--compact">
              <thead>
                <tr>
                  <th>{t("users.apiKeys.name")}</th>
                  <th>{t("users.apiKeys.prefix")}</th>
                  <th>{t("users.apiKeys.scopesLabel")}</th>
                  <th>{t("users.apiKeys.lastUsed")}</th>
                  <th>{t("users.apiKeys.expires")}</th>
                  <th>{t("common.status")}</th>
                  <th className="pf-table__col-actions">{t("common.actions")}</th>
                </tr>
              </thead>
              <tbody>
                {keyList.map((key) => (
                  <tr key={key.id}>
                    <td>
                      <div className="pf-api-keys__name">{key.name}</div>
                    </td>
                    <td>
                      <code className="pf-api-keys__prefix">sa_{key.key_prefix}_…</code>
                    </td>
                    <td>
                      <div className="pf-api-keys__scope-badges">
                        {key.scopes.map((scope) => (
                          <Badge key={scope} variant="info" literal>
                            {scope}
                          </Badge>
                        ))}
                      </div>
                    </td>
                    <td className="pf-table__muted">
                      {key.last_used_at
                        ? new Date(key.last_used_at).toLocaleString(dateLocale)
                        : t("users.apiKeys.never")}
                    </td>
                    <td className="pf-table__muted">
                      {key.expires_at
                        ? new Date(key.expires_at).toLocaleString(dateLocale)
                        : t("users.apiKeys.noExpiry")}
                    </td>
                    <td>
                      <Badge variant={statusVariant(key)}>{statusLabel(key, t)}</Badge>
                    </td>
                    <td className="pf-table__col-actions">
                      <div className="pf-table__actions">
                        <Button
                          variant="secondary"
                          className="pf-btn--sm"
                          onClick={() => void handleRotate(key)}
                          disabled={Boolean(key.revoked_at) || rotateMutation.isPending}
                        >
                          {t("users.apiKeys.rotate")}
                        </Button>
                        <Button
                          variant="secondary"
                          className="pf-btn--sm"
                          onClick={() => void handleRevoke(key)}
                          disabled={Boolean(key.revoked_at) || revokeMutation.isPending}
                        >
                          {t("users.apiKeys.revoke")}
                        </Button>
                        <Button
                          variant="danger-secondary"
                          className="pf-btn--sm"
                          onClick={() => void handleDelete(key)}
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
        ) : null}
      </div>
    </Panel>
  );
}
