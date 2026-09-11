import { useEffect, useRef, type FormEvent } from "react";
import { useTranslation } from "../i18n/I18nProvider";
import { PasswordInput } from "../components/ui/PasswordInput";
import { IconKeyRound, IconLoginLocal, IconUserRound } from "../components/ui/Icons";

type LoginLocalFormProps = {
  username: string;
  password: string;
  error: string | null;
  pending: boolean;
  onUsernameChange: (value: string) => void;
  onPasswordChange: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onCancel: () => void;
};

export function LoginLocalForm({
  username,
  password,
  error,
  pending,
  onUsernameChange,
  onPasswordChange,
  onSubmit,
  onCancel,
}: LoginLocalFormProps) {
  const { t } = useTranslation();
  const usernameRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    usernameRef.current?.focus();
  }, []);

  return (
    <div className="pf-login-local">
      <div className="pf-login-local__header">
        <span className="pf-login-local__badge" aria-hidden>
          <IconLoginLocal />
        </span>
        <div className="pf-login-local__heading">
          <p className="pf-login-local__title">{t("auth.localLogin")}</p>
          <p className="pf-login-local__hint">{t("auth.loginLocalHint")}</p>
        </div>
      </div>

      <form className="pf-login-local__form" onSubmit={onSubmit}>
        <div className="pf-login-local__fields">
          <label className="pf-login-control" htmlFor="local-username">
            <span className="pf-login-control__icon" aria-hidden>
              <IconUserRound />
            </span>
            <span className="pf-login-control__body">
              <span className="pf-login-control__label">{t("auth.username")}</span>
              <input
                ref={usernameRef}
                id="local-username"
                className="pf-login-control__input"
                value={username}
                onChange={(event) => onUsernameChange(event.target.value)}
                placeholder={t("auth.usernamePlaceholder")}
                autoComplete="username"
                disabled={pending}
              />
            </span>
          </label>

          <label className="pf-login-control" htmlFor="local-password">
            <span className="pf-login-control__icon" aria-hidden>
              <IconKeyRound />
            </span>
            <span className="pf-login-control__body">
              <span className="pf-login-control__label">{t("auth.password")}</span>
              <PasswordInput
                id="local-password"
                className="pf-login-control__password"
                value={password}
                onChange={(event) => onPasswordChange(event.target.value)}
                placeholder={t("auth.passwordPlaceholder")}
                autoComplete="current-password"
                disabled={pending}
              />
            </span>
          </label>
        </div>

        {error && <div className="pf-alert pf-alert--error pf-login-local__alert">{error}</div>}

        <div className="pf-login-local__actions">
          <button
            type="submit"
            className="pf-login-local__submit"
            disabled={pending || !username || !password}
          >
            {pending ? t("auth.loggingIn") : t("auth.signIn")}
          </button>
          <button
            type="button"
            className="pf-login-local__back"
            onClick={onCancel}
            disabled={pending}
          >
            {t("common.cancel")}
          </button>
        </div>
      </form>
    </div>
  );
}
