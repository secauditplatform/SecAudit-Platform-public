import { useEffect, useRef, type FormEvent } from "react";
import { useTranslation } from "../i18n/I18nProvider";
import { IconKeyRound } from "../components/ui/Icons";

type LoginMfaFormProps = {
  username: string;
  code: string;
  error: string | null;
  pending: boolean;
  onCodeChange: (value: string) => void;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onBack: () => void;
};

export function LoginMfaForm({
  username,
  code,
  error,
  pending,
  onCodeChange,
  onSubmit,
  onBack,
}: LoginMfaFormProps) {
  const { t } = useTranslation();
  const codeRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    codeRef.current?.focus();
  }, []);

  return (
    <div className="pf-login-local">
      <div className="pf-login-local__header">
        <span className="pf-login-local__badge" aria-hidden>
          <IconKeyRound />
        </span>
        <div className="pf-login-local__heading">
          <p className="pf-login-local__title">{t("auth.mfaTitle")}</p>
          <p className="pf-login-local__hint">{t("auth.mfaHint", { username })}</p>
        </div>
      </div>

      <form className="pf-login-local__form" onSubmit={onSubmit}>
        <div className="pf-login-local__fields">
          <label className="pf-login-control" htmlFor="local-mfa-code">
            <span className="pf-login-control__icon" aria-hidden>
              <IconKeyRound />
            </span>
            <span className="pf-login-control__body">
              <span className="pf-login-control__label">{t("auth.mfaCode")}</span>
              <input
                ref={codeRef}
                id="local-mfa-code"
                className="pf-login-control__input"
                value={code}
                onChange={(event) => onCodeChange(event.target.value)}
                placeholder={t("auth.mfaCodePlaceholder")}
                autoComplete="one-time-code"
                inputMode="text"
                disabled={pending}
              />
            </span>
          </label>
        </div>

        {error && <div className="pf-alert pf-alert--error pf-login-local__alert">{error}</div>}

        <div className="pf-login-local__actions">
          <button type="submit" className="pf-login-local__submit" disabled={pending || !code.trim()}>
            {pending ? t("auth.loggingIn") : t("auth.mfaVerify")}
          </button>
          <button type="button" className="pf-login-local__back" onClick={onBack} disabled={pending}>
            {t("auth.mfaBack")}
          </button>
        </div>
      </form>
    </div>
  );
}
