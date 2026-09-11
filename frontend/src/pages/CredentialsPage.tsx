import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useCallback, useMemo, useRef, useState } from "react";
import { api, type Credential } from "../api/client";
import { OpsListExpandFooter } from "../components/OpsListExpandFooter";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { EmptyState } from "../components/ui/EmptyState";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { PasswordInput, SecretTextarea } from "../components/ui/PasswordInput";
import { Spinner } from "../components/ui/Spinner";
import { useToast } from "../components/ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";
import { sliceOpsList } from "../utils/opsListLimit";

type CredentialForm = {
  name: string;
  credential_type: string;
  username: string;
  secret: string;
  key_passphrase: string;
  service_username: string;
  service_secret: string;
  description: string;
};

const emptyForm = (): CredentialForm => ({
  name: "",
  credential_type: "ssh_password",
  username: "",
  secret: "",
  key_passphrase: "",
  service_username: "",
  service_secret: "",
  description: "",
});

export function CredentialsPage() {
  const { t, dateLocale } = useTranslation();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<CredentialForm>(emptyForm());
  const [editingId, setEditingId] = useState<number | null>(null);
  const [listSearch, setListSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [listExpanded, setListExpanded] = useState(false);
  const credentialFormPanelRef = useRef<HTMLDivElement | null>(null);

  const scrollToCredentialForm = useCallback(() => {
    requestAnimationFrame(() => {
      credentialFormPanelRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
      document.getElementById("cred-name")?.focus();
    });
  }, []);

  const credentialTypes = [
    { value: "ssh_password", label: t("credentials.typeSshPassword") },
    { value: "ssh_key", label: t("credentials.typeSshKey") },
    { value: "winrm", label: t("credentials.typeWinrm") },
  ];

  const credentials = useQuery({ queryKey: ["credentials"], queryFn: api.credentials });
  const createMutation = useMutation({
    mutationFn: api.createCredential,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["credentials"] });
      setForm(emptyForm());
      toast.success(t("toast.credentialCreated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Partial<CredentialForm> }) => api.updateCredential(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["credentials"] });
      setEditingId(null);
      setForm(emptyForm());
      toast.success(t("toast.credentialUpdated"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteCredential,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["credentials"] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      if (editingId != null) {
        setEditingId(null);
        setForm(emptyForm());
      }
      toast.success(t("toast.credentialDeleted"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const startEdit = (cred: Credential) => {
    setEditingId(cred.id);
    setForm({
      name: cred.name,
      credential_type: cred.credential_type,
      username: cred.username ?? "",
      secret: "",
      key_passphrase: "",
      service_username: cred.service_username ?? "",
      service_secret: "",
      description: cred.description ?? "",
    });
    scrollToCredentialForm();
  };

  const cancelEdit = () => {
    setEditingId(null);
    setForm(emptyForm());
  };

  const isEditing = editingId !== null;
  const editingCredential = credentials.data?.find((item) => item.id === editingId);
  const credentialRows = credentials.data ?? [];

  const filteredCredentials = useMemo(() => {
    const query = listSearch.trim().toLowerCase();
    return credentialRows.filter((cred) => {
      if (typeFilter !== "all" && cred.credential_type !== typeFilter) return false;
      if (!query) return true;
      return (
        cred.name.toLowerCase().includes(query) ||
        (cred.username ?? "").toLowerCase().includes(query) ||
        (cred.service_username ?? "").toLowerCase().includes(query) ||
        (cred.description ?? "").toLowerCase().includes(query) ||
        cred.credential_type.toLowerCase().includes(query)
      );
    });
  }, [credentialRows, listSearch, typeFilter]);

  const visibleCredentials = useMemo(
    () => sliceOpsList(filteredCredentials, listExpanded),
    [filteredCredentials, listExpanded]
  );

  const hasActiveFilters = listSearch.trim() !== "" || typeFilter !== "all";

  const clearFilters = () => {
    setListSearch("");
    setTypeFilter("all");
    setListExpanded(false);
  };

  return (
    <>
      <PageHeader title={t("credentials.title")} description={t("credentials.description")} />

      <div ref={credentialFormPanelRef}>
      <Panel title={isEditing ? t("credentials.editTitle", { name: form.name }) : t("credentials.add")}>
        <div className="pf-form pf-form--wide">
          <div className="pf-form__row">
            <div className="pf-form__group">
              <label htmlFor="cred-name">{t("hosts.name")}</label>
              <input
                id="cred-name"
                className="pf-input"
                value={form.name}
                onChange={(e) => setForm({ ...form, name: e.target.value })}
                placeholder="prod-ssh-key"
              />
            </div>
            <div className="pf-form__group">
              <label htmlFor="cred-type">{t("credentials.type")}</label>
              <select
                id="cred-type"
                className="pf-select"
                value={form.credential_type}
                onChange={(e) => setForm({ ...form, credential_type: e.target.value })}
              >
                {credentialTypes.map((type) => (
                  <option key={type.value} value={type.value}>
                    {type.label}
                  </option>
                ))}
              </select>
            </div>
            <div className="pf-form__group">
              <label htmlFor="cred-user">{t("credentials.user")}</label>
              <input
                id="cred-user"
                className="pf-input"
                value={form.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
                placeholder="root"
              />
            </div>
          </div>
          <div className="pf-form__group">
            <label htmlFor="cred-secret">
              {form.credential_type === "ssh_key" ? t("credentials.privateKey") : t("credentials.passwordSecret")}
            </label>
            {form.credential_type === "ssh_key" ? (
              <SecretTextarea
                id="cred-secret"
                rows={6}
                value={form.secret}
                onChange={(e) => setForm({ ...form, secret: e.target.value })}
                placeholder={
                  isEditing ? t("credentials.keepKeyEmpty") : "-----BEGIN OPENSSH PRIVATE KEY-----"
                }
                style={{ fontFamily: "monospace", resize: "vertical" }}
              />
            ) : (
              <PasswordInput
                id="cred-secret"
                value={form.secret}
                onChange={(e) => setForm({ ...form, secret: e.target.value })}
                placeholder={isEditing ? t("credentials.keepPasswordEmpty") : "••••••••"}
              />
            )}
          </div>
          {form.credential_type === "ssh_key" ? (
            <div className="pf-form__group">
              <label htmlFor="cred-key-passphrase">{t("credentials.keyPassphrase")}</label>
              <PasswordInput
                id="cred-key-passphrase"
                value={form.key_passphrase}
                onChange={(e) => setForm({ ...form, key_passphrase: e.target.value })}
                placeholder={isEditing ? t("credentials.keepKeyPassphraseEmpty") : t("common.optional")}
              />
            </div>
          ) : null}
          <div className="pf-form__group pf-form__group--divider">
            <div className="pf-form__hint">{t("credentials.serviceSection")}</div>
          </div>
          <div className="pf-form__row">
            <div className="pf-form__group">
              <label htmlFor="cred-service-user">{t("credentials.serviceUser")}</label>
              <input
                id="cred-service-user"
                className="pf-input"
                value={form.service_username}
                onChange={(e) => setForm({ ...form, service_username: e.target.value })}
                placeholder="postgres"
              />
            </div>
            <div className="pf-form__group">
              <label htmlFor="cred-service-secret">{t("credentials.serviceSecret")}</label>
              <PasswordInput
                id="cred-service-secret"
                value={form.service_secret}
                onChange={(e) => setForm({ ...form, service_secret: e.target.value })}
                placeholder={
                  isEditing && editingCredential?.has_service_secret
                    ? t("credentials.keepServiceSecretEmpty")
                    : t("common.optional")
                }
              />
            </div>
          </div>
          <div className="pf-form__group">
            <label htmlFor="cred-desc">{t("credentials.descriptionField")}</label>
            <input
              id="cred-desc"
              className="pf-input"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
              placeholder={t("common.optional")}
            />
          </div>
          <div className="pf-form__actions">
            {isEditing ? (
              <>
                <Button
                  onClick={() =>
                    updateMutation.mutate({
                      id: editingId,
                      data: {
                        name: form.name,
                        credential_type: form.credential_type,
                        username: form.username || undefined,
                        description: form.description || undefined,
                        ...(form.secret ? { secret: form.secret } : {}),
                        ...(form.key_passphrase ? { key_passphrase: form.key_passphrase } : {}),
                        ...(form.service_username ? { service_username: form.service_username } : {}),
                        ...(form.service_secret ? { service_secret: form.service_secret } : {}),
                      },
                    })
                  }
                  disabled={!form.name || updateMutation.isPending}
                >
                  {t("credentials.saveChanges")}
                </Button>
                <Button variant="secondary" onClick={cancelEdit}>
                  {t("common.cancel")}
                </Button>
              </>
            ) : (
              <Button
                onClick={() =>
                  createMutation.mutate({
                    ...form,
                    ...(form.key_passphrase ? { key_passphrase: form.key_passphrase } : {}),
                    ...(form.service_username ? { service_username: form.service_username } : {}),
                    ...(form.service_secret ? { service_secret: form.service_secret } : {}),
                  })
                }
                disabled={!form.name || !form.secret || createMutation.isPending}
              >
                {t("common.save")}
              </Button>
            )}
          </div>
          {(createMutation.isError || updateMutation.isError) && (
            <div className="pf-alert pf-alert--error">
              {((createMutation.error || updateMutation.error) as Error).message}
            </div>
          )}
        </div>
      </Panel>
      </div>

      <Panel title={t("credentials.list")} noPadding>
        {credentials.isLoading ? (
          <Spinner />
        ) : credentialRows.length === 0 ? (
          <EmptyState title={t("credentials.empty")} description={t("credentials.emptyDesc")} />
        ) : (
          <>
            <div className="pf-filters">
              <div className="pf-filters__grid pf-filters__grid--credentials">
                <div className="pf-filters__group">
                  <label htmlFor="credentials-filter-search">{t("credentials.listSearchLabel")}</label>
                  <input
                    id="credentials-filter-search"
                    className="pf-input"
                    value={listSearch}
                    onChange={(e) => setListSearch(e.target.value)}
                    placeholder={t("credentials.listSearch")}
                  />
                </div>
                <div className="pf-filters__group">
                  <label htmlFor="credentials-filter-type">{t("credentials.type")}</label>
                  <select
                    id="credentials-filter-type"
                    className="pf-select"
                    value={typeFilter}
                    onChange={(e) => setTypeFilter(e.target.value)}
                  >
                    <option value="all">{t("credentials.listTypeAll")}</option>
                    {credentialTypes.map((type) => (
                      <option key={type.value} value={type.value}>
                        {type.label}
                      </option>
                    ))}
                  </select>
                </div>
              </div>
              <div className="pf-filters__footer">
                <p className="pf-filters__summary">
                  {hasActiveFilters
                    ? t("profiles.filterResultsActive", {
                        count: filteredCredentials.length,
                        total: credentialRows.length,
                      })
                    : t("profiles.filterShown", {
                        count: filteredCredentials.length,
                        total: credentialRows.length,
                      })}
                </p>
                {hasActiveFilters ? (
                  <Button variant="secondary" className="pf-btn--sm" type="button" onClick={clearFilters}>
                    {t("profiles.clearFilters")}
                  </Button>
                ) : null}
              </div>
            </div>
            {filteredCredentials.length === 0 ? (
              <EmptyState title={t("jobs.noFilterResults")} description={t("jobs.noFilterResultsDesc")} />
            ) : (
              <>
                <div className="pf-table-wrap">
                  <table className="pf-table">
                    <thead>
                      <tr>
                        <th>{t("hosts.name")}</th>
                        <th>{t("credentials.type")}</th>
                        <th>{t("credentials.user")}</th>
                        <th>{t("credentials.serviceUser")}</th>
                        <th>{t("credentials.created")}</th>
                        <th className="pf-table__col-actions">{t("common.actions")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {visibleCredentials.map((cred) => (
                        <tr key={cred.id} className={editingId === cred.id ? "pf-table__row--selected" : undefined}>
                          <td>{cred.name}</td>
                          <td>
                            <Badge variant="info" literal>
                              {cred.credential_type}
                            </Badge>
                          </td>
                          <td>{cred.username || t("common.dash")}</td>
                          <td>
                            {cred.service_username || cred.has_service_secret ? (
                              <span title={cred.has_service_secret ? t("credentials.serviceSecretSet") : undefined}>
                                {cred.service_username || t("credentials.serviceSecretSet")}
                              </span>
                            ) : (
                              t("common.dash")
                            )}
                          </td>
                          <td>{new Date(cred.created_at).toLocaleString(dateLocale)}</td>
                          <td className="pf-table__col-actions">
                            <div className="pf-table__actions">
                              <Button variant="secondary" className="pf-btn--sm" onClick={() => startEdit(cred)}>
                                {t("common.edit")}
                              </Button>
                              <Button
                                variant="danger-secondary"
                                className="pf-btn--sm"
                                onClick={() => deleteMutation.mutate(cred.id)}
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
                <OpsListExpandFooter
                  shown={visibleCredentials.length}
                  total={filteredCredentials.length}
                  expanded={listExpanded}
                  onToggle={() => setListExpanded((value) => !value)}
                />
              </>
            )}
          </>
        )}
        {deleteMutation.isError && (
          <div className="pf-alert pf-alert--error" style={{ margin: "1rem" }}>
            {(deleteMutation.error as Error).message}
          </div>
        )}
      </Panel>
    </>
  );
}
