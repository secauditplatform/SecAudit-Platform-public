import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useMemo, useState } from "react";
import { Navigate } from "react-router-dom";
import { api, type PlatformUser, type UserRole } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { IconUserRound } from "../components/ui/Icons";
import { PasswordInput } from "../components/ui/PasswordInput";
import { Spinner } from "../components/ui/Spinner";
import { useConfirm } from "../components/ui/ConfirmDialog";
import { useToast } from "../components/ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";

type UserForm = {
  username: string;
  email: string;
  full_name: string;
  role: UserRole;
  password: string;
  is_active: boolean;
};

const ROLES: UserRole[] = ["admin", "operator", "auditor"];
const MIN_PASSWORD_LENGTH = 8;

const emptyForm = (): UserForm => ({
  username: "",
  email: "",
  full_name: "",
  role: "operator",
  password: "",
  is_active: true,
});

function isPasswordTooShort(password: string, required: boolean): boolean {
  if (!password) return required;
  return password.length < MIN_PASSWORD_LENGTH;
}

function formatUserMutationError(
  err: unknown,
  t: (key: string, params?: Record<string, string | number>) => string
): string {
  const message = err instanceof Error ? err.message : "";
  const lowered = message.toLowerCase();
  if (
    lowered.includes("password") &&
    (lowered.includes("at least 8") ||
      lowered.includes("string_too_short") ||
      lowered.includes("too short") ||
      lowered.includes("min_length"))
  ) {
    return t("users.passwordTooShortSimple", { min: MIN_PASSWORD_LENGTH });
  }
  return message || t("toast.genericError");
}

function roleVariant(role: UserRole): "success" | "info" | "warning" | "neutral" {
  switch (role) {
    case "admin":
      return "success";
    case "operator":
      return "info";
    case "auditor":
      return "warning";
    default:
      return "neutral";
  }
}

export function UsersPage() {
  const { t, dateLocale } = useTranslation();
  const { isAdmin, username: currentUsername } = useAuth();
  const toast = useToast();
  const { confirm } = useConfirm();
  const queryClient = useQueryClient();
  const [form, setForm] = useState<UserForm>(emptyForm());
  const [editingId, setEditingId] = useState<number | null>(null);
  const [showForm, setShowForm] = useState(false);

  const users = useQuery({
    queryKey: ["users"],
    queryFn: api.users,
    enabled: isAdmin,
  });

  const roleOptions = useMemo(
    () => ROLES.map((role) => ({ value: role, label: t(`users.roles.${role}`) })),
    [t]
  );

  const createMutation = useMutation({
    mutationFn: api.createUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      setForm(emptyForm());
      setShowForm(false);
      toast.success(t("toast.userCreated"));
    },
    onError: (err) => toast.error(formatUserMutationError(err, t)),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: Parameters<typeof api.updateUser>[1] }) =>
      api.updateUser(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      setEditingId(null);
      setForm(emptyForm());
      setShowForm(false);
      toast.success(t("toast.userUpdated"));
    },
    onError: (err) => toast.error(formatUserMutationError(err, t)),
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteUser,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["users"] });
      if (editingId != null) {
        setEditingId(null);
        setForm(emptyForm());
        setShowForm(false);
      }
      toast.success(t("toast.userDeleted"));
    },
    onError: (err) => toast.error(formatUserMutationError(err, t)),
  });

  if (!isAdmin) {
    return <Navigate to="/" replace />;
  }

  const userList = users.data ?? [];
  const hasUsers = userList.length > 0;
  const isEditing = editingId !== null;
  const isSelf = isEditing && form.username === currentUsername;
  const composerOpen = showForm || isEditing;
  const passwordRequired = !isEditing;
  const passwordInvalid = isPasswordTooShort(form.password, passwordRequired);
  const passwordTouched = form.password.length > 0;
  const showPasswordFieldError = passwordTouched && form.password.length < MIN_PASSWORD_LENGTH;
  const canSubmitAccount =
    Boolean(form.username.trim()) &&
    Boolean(form.email.trim()) &&
    !passwordInvalid &&
    !(isEditing ? updateMutation.isPending : createMutation.isPending);

  const startCreate = () => {
    setEditingId(null);
    setForm(emptyForm());
    setShowForm(true);
  };

  const startEdit = (user: PlatformUser) => {
    setEditingId(user.id);
    setShowForm(true);
    setForm({
      username: user.username,
      email: user.email,
      full_name: user.full_name ?? "",
      role: user.role,
      password: "",
      is_active: user.is_active,
    });
  };

  const closeComposer = () => {
    setEditingId(null);
    setForm(emptyForm());
    setShowForm(false);
  };

  const handleDelete = async (user: PlatformUser) => {
    const ok = await confirm({
      title: t("users.deleteTitle"),
      message: t("users.deleteConfirm", { name: user.username }),
      confirmLabel: t("common.delete"),
      variant: "danger",
    });
    if (ok) deleteMutation.mutate(user.id);
  };

  return (
    <>
      <PageHeader title={t("users.title")} description={t("users.description")} />

      <Panel title={t("users.list")} noPadding>
        <div className="pf-users">
          {composerOpen ? (
            <div className="pf-users__composer">
              <div className="pf-users__composer-head">
                <div>
                  <h3 className="pf-users__composer-title">
                    {isEditing ? t("users.editTitle", { name: form.username }) : t("users.add")}
                  </h3>
                  <p className="pf-users__composer-subtitle">
                    {isEditing ? t("users.editSubtitle") : t("users.createSubtitle")}
                  </p>
                </div>
                <button type="button" className="pf-users__composer-close" onClick={closeComposer}>
                  {t("common.cancel")}
                </button>
              </div>

              <div className="pf-users__composer-body">
                <section className="pf-users__section" aria-labelledby="users-section-account">
                  <h4 id="users-section-account" className="pf-users__section-title">
                    {t("users.sectionAccount")}
                  </h4>
                  <div className="pf-users__fields pf-users__fields--3">
                    <div className="pf-form__group">
                      <label htmlFor="user-username">{t("users.username")}</label>
                      <input
                        id="user-username"
                        className="pf-input"
                        value={form.username}
                        onChange={(e) => setForm({ ...form, username: e.target.value })}
                        placeholder={t("users.usernamePlaceholder")}
                        autoComplete="off"
                      />
                    </div>
                    <div className="pf-form__group">
                      <label htmlFor="user-email">{t("users.email")}</label>
                      <input
                        id="user-email"
                        type="email"
                        className="pf-input"
                        value={form.email}
                        onChange={(e) => setForm({ ...form, email: e.target.value })}
                        placeholder={t("users.emailPlaceholder")}
                        autoComplete="off"
                      />
                    </div>
                    <div className="pf-form__group">
                      <label htmlFor="user-full-name">{t("users.fullName")}</label>
                      <input
                        id="user-full-name"
                        className="pf-input"
                        value={form.full_name}
                        onChange={(e) => setForm({ ...form, full_name: e.target.value })}
                        placeholder={t("common.optional")}
                      />
                    </div>
                  </div>
                </section>

                <section className="pf-users__section" aria-labelledby="users-section-access">
                  <h4 id="users-section-access" className="pf-users__section-title">
                    {t("users.sectionAccess")}
                  </h4>
                  <div className={`pf-users__fields${isEditing ? " pf-users__fields--3" : " pf-users__fields--2"}`}>
                    <div className="pf-form__group">
                      <label htmlFor="user-role">{t("users.role")}</label>
                      <select
                        id="user-role"
                        className="pf-select"
                        value={form.role}
                        onChange={(e) => setForm({ ...form, role: e.target.value as UserRole })}
                        disabled={isSelf}
                      >
                        {roleOptions.map((option) => (
                          <option key={option.value} value={option.value}>
                            {option.label}
                          </option>
                        ))}
                      </select>
                      <p className="pf-form__hint">{t(`users.roleHints.${form.role}`)}</p>
                    </div>
                    <div className="pf-form__group">
                      <div className="pf-users__password-label-row">
                        <label htmlFor="user-password">{t("users.password")}</label>
                        {passwordTouched ? (
                          <span
                            className={`pf-users__password-meter${
                              showPasswordFieldError
                                ? " pf-users__password-meter--error"
                                : " pf-users__password-meter--ok"
                            }`}
                          >
                            {t("users.passwordLength", {
                              count: form.password.length,
                              min: MIN_PASSWORD_LENGTH,
                            })}
                          </span>
                        ) : null}
                      </div>
                      <PasswordInput
                        id="user-password"
                        value={form.password}
                        onChange={(e) => setForm({ ...form, password: e.target.value })}
                        placeholder={isEditing ? t("users.keepPasswordEmpty") : "••••••••"}
                        autoComplete="new-password"
                        aria-invalid={showPasswordFieldError}
                        aria-describedby="user-password-hint"
                        className={showPasswordFieldError ? "pf-input--invalid" : ""}
                      />
                      <div className="pf-users__password-progress" aria-hidden>
                        <span
                          className={`pf-users__password-progress-bar${
                            showPasswordFieldError
                              ? " pf-users__password-progress-bar--error"
                              : passwordTouched
                                ? " pf-users__password-progress-bar--ok"
                                : ""
                          }`}
                          style={{
                            width: `${Math.min(
                              100,
                              Math.round((form.password.length / MIN_PASSWORD_LENGTH) * 100)
                            )}%`,
                          }}
                        />
                      </div>
                      <p
                        id="user-password-hint"
                        className={`pf-form__hint${showPasswordFieldError ? " pf-form__hint--error" : passwordTouched ? " pf-form__hint--success" : ""}`}
                        role={showPasswordFieldError ? "alert" : undefined}
                      >
                        {showPasswordFieldError
                          ? t("users.passwordTooShort", {
                              count: form.password.length,
                              min: MIN_PASSWORD_LENGTH,
                            })
                          : passwordTouched
                            ? t("users.passwordReady")
                            : isEditing
                              ? t("users.passwordEditHint")
                              : t("users.passwordHint")}
                      </p>
                    </div>
                    {isEditing ? (
                      <div className="pf-form__group">
                        <label htmlFor="user-active">{t("common.status")}</label>
                        <select
                          id="user-active"
                          className="pf-select"
                          value={form.is_active ? "active" : "inactive"}
                          onChange={(e) => setForm({ ...form, is_active: e.target.value === "active" })}
                          disabled={isSelf}
                        >
                          <option value="active">{t("common.active")}</option>
                          <option value="inactive">{t("common.inactive")}</option>
                        </select>
                        {isSelf ? <p className="pf-form__hint">{t("users.selfEditHint")}</p> : null}
                      </div>
                    ) : null}
                  </div>
                </section>
              </div>

              <div className="pf-users__composer-foot">
                {isEditing ? (
                  <>
                    <Button
                      onClick={() => {
                        if (passwordInvalid) return;
                        updateMutation.mutate({
                          id: editingId,
                          data: {
                            username: form.username,
                            email: form.email,
                            full_name: form.full_name || null,
                            role: form.role,
                            is_active: form.is_active,
                            ...(form.password ? { password: form.password } : {}),
                          },
                        });
                      }}
                      disabled={!canSubmitAccount}
                    >
                      {t("users.saveChanges")}
                    </Button>
                    <Button variant="secondary" onClick={closeComposer}>
                      {t("common.cancel")}
                    </Button>
                  </>
                ) : (
                  <Button
                    onClick={() => {
                      if (passwordInvalid) return;
                      createMutation.mutate({
                        username: form.username,
                        email: form.email,
                        full_name: form.full_name || undefined,
                        role: form.role,
                        password: form.password,
                      });
                    }}
                    disabled={!canSubmitAccount}
                  >
                    {t("users.createAction")}
                  </Button>
                )}
              </div>
            </div>
          ) : hasUsers ? (
            <div className="pf-users__toolbar">
              <span className="pf-users__toolbar-label">{t("users.listCount", { count: userList.length })}</span>
              <Button className="pf-btn--sm" onClick={startCreate}>{t("users.add")}</Button>
            </div>
          ) : null}

          <div className="pf-users__list">
            {users.isLoading ? (
              <Spinner />
            ) : !hasUsers && !composerOpen ? (
              <div className="pf-users__empty">
                <div className="pf-users__empty-card">
                  <div className="pf-users__empty-icon" aria-hidden>
                    <IconUserRound />
                  </div>
                  <h3 className="pf-users__empty-title">{t("users.empty")}</h3>
                  <p className="pf-users__empty-desc">{t("users.emptyDesc")}</p>
                  <Button onClick={startCreate}>{t("users.emptyAction")}</Button>
                </div>
              </div>
            ) : hasUsers ? (
              <div className="pf-table-wrap">
                <table className="pf-table pf-table--compact">
                  <thead>
                    <tr>
                      <th>{t("users.username")}</th>
                      <th>{t("users.email")}</th>
                      <th>{t("users.fullName")}</th>
                      <th>{t("users.role")}</th>
                      <th>{t("common.status")}</th>
                      <th>{t("users.created")}</th>
                      <th className="pf-table__col-actions">{t("common.actions")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {userList.map((user) => (
                      <tr
                        key={user.id}
                        className={editingId === user.id ? "pf-table__row--selected" : undefined}
                      >
                        <td>
                          <div className="pf-users__name">{user.username}</div>
                          {user.username === currentUsername ? (
                            <span className="pf-users__you-badge">{t("users.you")}</span>
                          ) : null}
                        </td>
                        <td>{user.email}</td>
                        <td>{user.full_name || t("common.dash")}</td>
                        <td>
                          <Badge variant={roleVariant(user.role)} literal>
                            {t(`users.roles.${user.role}`)}
                          </Badge>
                        </td>
                        <td>
                          <Badge variant={user.is_active ? "success" : "danger"}>
                            {user.is_active ? t("common.active") : t("common.inactive")}
                          </Badge>
                        </td>
                        <td className="pf-table__muted">
                          {new Date(user.created_at).toLocaleString(dateLocale)}
                        </td>
                        <td className="pf-table__col-actions">
                          <div className="pf-table__actions">
                            <Button variant="secondary" className="pf-btn--sm" onClick={() => startEdit(user)}>
                              {t("common.edit")}
                            </Button>
                            <Button
                              variant="danger-secondary"
                              className="pf-btn--sm"
                              onClick={() => void handleDelete(user)}
                              disabled={deleteMutation.isPending || user.username === currentUsername}
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
        </div>
      </Panel>
    </>
  );
}
