import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useEffect, useLayoutEffect, useMemo, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { api, type Credential, type Host, type HostLinkedCredential } from "../api/client";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { PasswordInput, SecretTextarea } from "./ui/PasswordInput";
import { useTranslation } from "../i18n/I18nProvider";

type CredentialForm = {
  name: string;
  credential_type: string;
  username: string;
  secret: string;
  key_passphrase: string;
  service_username: string;
  service_secret: string;
};

const emptyCredentialForm = (credentialType = "ssh_password"): CredentialForm => ({
  name: "",
  credential_type: credentialType,
  username: "",
  secret: "",
  key_passphrase: "",
  service_username: "",
  service_secret: "",
});

type HostCredentialPopoverProps = {
  host: Host;
  credentials: Credential[];
};

const PANEL_WIDTH_PX = 352;
const VIEWPORT_MARGIN_PX = 8;
const PANEL_GAP_PX = 6;

function hostCredentialTypes(osType?: string | null): string[] {
  const os = (osType ?? "linux").toLowerCase();
  return os === "windows" ? ["winrm"] : ["ssh_password", "ssh_key"];
}

function linkedCredentialsForHost(host: Host, credentials: Credential[]): HostLinkedCredential[] {
  if (host.linked_credentials?.length) {
    return host.linked_credentials;
  }
  if (host.credential_id == null) {
    return [];
  }
  const assigned = credentials.find((item) => item.id === host.credential_id);
  if (!assigned) {
    return [];
  }
  return [
    {
      id: assigned.id,
      name: assigned.name,
      credential_type: assigned.credential_type,
      username: assigned.username,
    },
  ];
}

function availableCredentialsForHost(host: Host, credentials: Credential[]): Credential[] {
  const allowed = new Set(hostCredentialTypes(host.os_type));
  const linkedIds = new Set(linkedCredentialsForHost(host, credentials).map((item) => item.id));
  return credentials.filter(
    (cred) => allowed.has(cred.credential_type) && !linkedIds.has(cred.id)
  );
}

function positionPanel(trigger: DOMRect, panel: HTMLElement) {
  const panelWidth = Math.min(PANEL_WIDTH_PX, window.innerWidth - VIEWPORT_MARGIN_PX * 2);
  panel.style.width = `${panelWidth}px`;

  const panelHeight = panel.getBoundingClientRect().height;
  const viewportHeight = window.innerHeight;
  const viewportWidth = window.innerWidth;
  const spaceBelow = viewportHeight - VIEWPORT_MARGIN_PX - (trigger.bottom + PANEL_GAP_PX);
  const spaceAbove = trigger.top - PANEL_GAP_PX - VIEWPORT_MARGIN_PX;

  let top = trigger.bottom + PANEL_GAP_PX;
  if (panelHeight > spaceBelow && spaceAbove > spaceBelow) {
    top = trigger.top - PANEL_GAP_PX - panelHeight;
  } else if (panelHeight > spaceBelow) {
    top = Math.max(VIEWPORT_MARGIN_PX, viewportHeight - VIEWPORT_MARGIN_PX - panelHeight);
  }
  top = Math.max(
    VIEWPORT_MARGIN_PX,
    Math.min(top, viewportHeight - VIEWPORT_MARGIN_PX - panelHeight)
  );

  let left = trigger.left;
  if (left + panelWidth > viewportWidth - VIEWPORT_MARGIN_PX) {
    left = viewportWidth - VIEWPORT_MARGIN_PX - panelWidth;
  }
  left = Math.max(VIEWPORT_MARGIN_PX, left);

  panel.style.top = `${top}px`;
  panel.style.left = `${left}px`;
  panel.style.maxHeight = `${viewportHeight - VIEWPORT_MARGIN_PX * 2}px`;
}

export function HostCredentialPopover({ host, credentials }: HostCredentialPopoverProps) {
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const rootRef = useRef<HTMLDivElement>(null);
  const triggerRef = useRef<HTMLSpanElement>(null);
  const panelRef = useRef<HTMLDivElement>(null);
  const [open, setOpen] = useState(false);
  const [mode, setMode] = useState<"link" | "create">("link");
  const [selectedCredentialId, setSelectedCredentialId] = useState<number | "">("");
  const allowedTypes = useMemo(() => hostCredentialTypes(host.os_type), [host.os_type]);
  const [createForm, setCreateForm] = useState<CredentialForm>(() =>
    emptyCredentialForm(allowedTypes[0] ?? "ssh_password")
  );

  const linked = linkedCredentialsForHost(host, credentials);
  const available = availableCredentialsForHost(host, credentials);

  useEffect(() => {
    if (!open) return;
    setMode(linked.length > 0 || available.length > 0 ? "link" : "create");
    setSelectedCredentialId("");
    setCreateForm(emptyCredentialForm(allowedTypes[0] ?? "ssh_password"));
  }, [open, linked.length, available.length, allowedTypes]);

  useLayoutEffect(() => {
    if (!open || !triggerRef.current || !panelRef.current) return;

    const panel = panelRef.current;
    const updatePosition = () => {
      if (!triggerRef.current || !panelRef.current) return;
      positionPanel(triggerRef.current.getBoundingClientRect(), panelRef.current);
    };

    updatePosition();
    const resizeObserver = new ResizeObserver(updatePosition);
    resizeObserver.observe(panel);
    window.addEventListener("scroll", updatePosition, true);
    window.addEventListener("resize", updatePosition);
    return () => {
      resizeObserver.disconnect();
      window.removeEventListener("scroll", updatePosition, true);
      window.removeEventListener("resize", updatePosition);
    };
  }, [open, mode, linked.length, available.length]);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: MouseEvent) => {
      const target = event.target as Node;
      if (rootRef.current?.contains(target) || panelRef.current?.contains(target)) {
        return;
      }
      const active = document.activeElement;
      if (active instanceof HTMLSelectElement && panelRef.current?.contains(active)) {
        return;
      }
      setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  const linkMutation = useMutation({
    mutationFn: (credentialId: number) => api.linkHostCredential(host.id, credentialId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      setSelectedCredentialId("");
    },
  });

  const unlinkMutation = useMutation({
    mutationFn: (credentialId: number) => api.unlinkHostCredential(host.id, credentialId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
    },
  });

  const createAndLinkMutation = useMutation({
    mutationFn: async (form: CredentialForm) => {
      const credential = await api.createCredential({
        name: form.name,
        credential_type: form.credential_type,
        username: form.username || undefined,
        secret: form.secret,
        ...(form.key_passphrase ? { key_passphrase: form.key_passphrase } : {}),
        ...(form.service_username ? { service_username: form.service_username } : {}),
        ...(form.service_secret ? { service_secret: form.service_secret } : {}),
      });
      return api.linkHostCredential(host.id, credential.id);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      queryClient.invalidateQueries({ queryKey: ["credentials"] });
      setOpen(false);
    },
  });

  const credentialTypes = [
    { value: "ssh_password", label: t("credentials.typeSshPassword") },
    { value: "ssh_key", label: t("credentials.typeSshKey") },
    { value: "winrm", label: t("credentials.typeWinrm") },
  ].filter((type) => allowedTypes.includes(type.value));

  const pending = linkMutation.isPending || unlinkMutation.isPending || createAndLinkMutation.isPending;
  const error = linkMutation.error ?? unlinkMutation.error ?? createAndLinkMutation.error;

  const panel = open ? (
    <div
      ref={panelRef}
      className="pf-host-cred__panel"
      role="dialog"
      aria-label={t("hosts.credentialPanelTitle", { name: host.name })}
    >
      <h4 className="pf-host-cred__title">
        {t("hosts.credentialPanelTitle", { name: host.name })}
      </h4>

      {linked.length > 0 ? (
        <div className="pf-host-cred__current">
          <span className="pf-host-cred__current-label">{t("hosts.credentialCurrent")}</span>
          <ul className="pf-host-cred__linked-list">
            {linked.map((item) => (
              <li key={item.id} className="pf-host-cred__linked-item">
                <div className="pf-host-cred__current-row">
                  <span>{item.name}</span>
                  <Badge variant="info" literal>
                    {item.credential_type}
                  </Badge>
                  {item.username ? (
                    <span className="pf-table__muted">{item.username}</span>
                  ) : null}
                </div>
                <Button
                  variant="danger-secondary"
                  className="pf-btn--sm"
                  onClick={() => unlinkMutation.mutate(item.id)}
                  disabled={pending}
                >
                  {t("hosts.credentialUnlink")}
                </Button>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      <div className="pf-host-cred__mode" role="tablist" aria-label={t("hosts.credentialMode")}>
        <button
          type="button"
          role="tab"
          className={`pf-host-cred__mode-btn${mode === "link" ? " active" : ""}`}
          aria-selected={mode === "link"}
          onClick={() => setMode("link")}
        >
          {t("hosts.credentialLinkExisting")}
        </button>
        <button
          type="button"
          role="tab"
          className={`pf-host-cred__mode-btn${mode === "create" ? " active" : ""}`}
          aria-selected={mode === "create"}
          onClick={() => setMode("create")}
        >
          {t("hosts.credentialCreateNew")}
        </button>
      </div>

      {mode === "link" ? (
        <div className="pf-host-cred__section">
          <label htmlFor={`host-cred-link-${host.id}`}>{t("hosts.credential")}</label>
          <select
            id={`host-cred-link-${host.id}`}
            className="pf-select"
            value={selectedCredentialId}
            onChange={(e) =>
              setSelectedCredentialId(e.target.value ? Number(e.target.value) : "")
            }
          >
            <option value="">{t("hosts.notSelected")}</option>
            {available.map((cred) => (
              <option key={cred.id} value={cred.id}>
                {cred.name}
                {cred.username ? ` (${cred.username})` : ""} · {cred.credential_type}
              </option>
            ))}
          </select>
          <div className="pf-host-cred__actions">
            <Button
              onClick={() => selectedCredentialId !== "" && linkMutation.mutate(selectedCredentialId)}
              disabled={selectedCredentialId === "" || pending}
            >
              {linked.length > 0 ? t("hosts.credentialAddAnother") : t("hosts.credentialAssign")}
            </Button>
            <Button variant="secondary" onClick={() => setOpen(false)}>
              {t("common.cancel")}
            </Button>
          </div>
        </div>
      ) : (
        <div className="pf-host-cred__section">
          <div className="pf-form__group">
            <label htmlFor={`host-cred-name-${host.id}`}>{t("hosts.name")}</label>
            <input
              id={`host-cred-name-${host.id}`}
              className="pf-input"
              value={createForm.name}
              onChange={(e) => setCreateForm({ ...createForm, name: e.target.value })}
              placeholder="prod-ssh-key"
            />
          </div>
          <div className="pf-form__group">
            <label htmlFor={`host-cred-type-${host.id}`}>{t("credentials.type")}</label>
            <select
              id={`host-cred-type-${host.id}`}
              className="pf-select"
              value={createForm.credential_type}
              onChange={(e) => setCreateForm({ ...createForm, credential_type: e.target.value })}
            >
              {credentialTypes.map((type) => (
                <option key={type.value} value={type.value}>
                  {type.label}
                </option>
              ))}
            </select>
          </div>
          <div className="pf-form__group">
            <label htmlFor={`host-cred-user-${host.id}`}>{t("credentials.user")}</label>
            <input
              id={`host-cred-user-${host.id}`}
              className="pf-input"
              value={createForm.username}
              onChange={(e) => setCreateForm({ ...createForm, username: e.target.value })}
              placeholder="root"
            />
          </div>
          <div className="pf-form__group">
            <label htmlFor={`host-cred-secret-${host.id}`}>
              {createForm.credential_type === "ssh_key"
                ? t("credentials.privateKey")
                : t("credentials.passwordSecret")}
            </label>
            {createForm.credential_type === "ssh_key" ? (
              <SecretTextarea
                id={`host-cred-secret-${host.id}`}
                rows={4}
                value={createForm.secret}
                onChange={(e) => setCreateForm({ ...createForm, secret: e.target.value })}
                placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
                style={{ fontFamily: "monospace", resize: "vertical" }}
              />
            ) : (
              <PasswordInput
                id={`host-cred-secret-${host.id}`}
                value={createForm.secret}
                onChange={(e) => setCreateForm({ ...createForm, secret: e.target.value })}
                placeholder="••••••••"
              />
            )}
          </div>
          {createForm.credential_type === "ssh_key" ? (
            <div className="pf-form__group">
              <label htmlFor={`host-cred-key-passphrase-${host.id}`}>{t("credentials.keyPassphrase")}</label>
              <PasswordInput
                id={`host-cred-key-passphrase-${host.id}`}
                value={createForm.key_passphrase}
                onChange={(e) => setCreateForm({ ...createForm, key_passphrase: e.target.value })}
                placeholder={t("common.optional")}
              />
            </div>
          ) : null}
          <div className="pf-form__group pf-form__group--divider">
            <div className="pf-form__hint">{t("credentials.serviceSection")}</div>
          </div>
          <div className="pf-form__group">
            <label htmlFor={`host-cred-service-user-${host.id}`}>{t("credentials.serviceUser")}</label>
            <input
              id={`host-cred-service-user-${host.id}`}
              className="pf-input"
              value={createForm.service_username}
              onChange={(e) => setCreateForm({ ...createForm, service_username: e.target.value })}
              placeholder="postgres"
            />
          </div>
          <div className="pf-form__group">
            <label htmlFor={`host-cred-service-secret-${host.id}`}>{t("credentials.serviceSecret")}</label>
            <PasswordInput
              id={`host-cred-service-secret-${host.id}`}
              value={createForm.service_secret}
              onChange={(e) => setCreateForm({ ...createForm, service_secret: e.target.value })}
              placeholder={t("common.optional")}
            />
          </div>
          <div className="pf-host-cred__actions">
            <Button
              onClick={() => createAndLinkMutation.mutate(createForm)}
              disabled={!createForm.name || !createForm.secret || pending}
            >
              {t("hosts.credentialCreateAssign")}
            </Button>
            <Button variant="secondary" onClick={() => setOpen(false)}>
              {t("common.cancel")}
            </Button>
          </div>
        </div>
      )}

      {error && <div className="pf-alert pf-alert--error">{(error as Error).message}</div>}
    </div>
  ) : null;

  return (
    <div className="pf-host-cred" ref={rootRef}>
      <div className="pf-host-cred__cell">
        <div className="pf-host-cred__summary">
          {linked.length > 0 ? (
            linked.map((item) => (
              <span key={item.id} className="pf-host-cred__chip" title={item.name}>
                {item.name}
              </span>
            ))
          ) : (
            <span className="pf-table__muted">{t("common.dash")}</span>
          )}
        </div>
        <span ref={triggerRef} className="pf-host-cred__trigger">
          <Button
            variant="link"
            className="pf-btn--sm pf-host-cred__action"
            onClick={() => setOpen((value) => !value)}
            aria-expanded={open}
            aria-haspopup="dialog"
          >
            {linked.length > 0 ? t("hosts.credentialManage") : t("hosts.credentialAdd")}
          </Button>
        </span>
      </div>

      {panel && createPortal(panel, document.body)}
    </div>
  );
}
