import { useState, type FormEvent } from "react";
import { useTranslation } from "../i18n/I18nProvider";
import { Spinner } from "../components/ui/Spinner";
import { LoginMethodButton } from "./LoginMethodButton";
import { LoginLocalForm } from "./LoginLocalForm";

type LoginPageProps = {
  showKeycloak: boolean;
  keycloakDisabled?: boolean;
  showLocal: boolean;
  demoStand?: boolean;
  onKeycloakLogin: () => void;
  onLocalLogin: (username: string, password: string) => Promise<void>;
};

export function LoginLoading() {
  const { t } = useTranslation();

  return (
    <div className="pf-login-page">
      <div className="pf-login-shell pf-login-shell--loading" aria-live="polite" aria-busy="true">
        <div className="pf-login-brand">
          <div className="pf-login-brand__mark" aria-hidden />
          <div>
            <h1 className="pf-login-brand__title">SecAudit</h1>
            <p className="pf-login-brand__subtitle">{t("auth.loginSubtitle")}</p>
          </div>
        </div>
        <div className="pf-login-body pf-login-body--centered">
          <Spinner />
          <p className="pf-login-loading__text">{t("auth.authenticating")}</p>
        </div>
      </div>
    </div>
  );
}

export function LoginPage({
  showKeycloak,
  keycloakDisabled = false,
  showLocal,
  demoStand = false,
  onKeycloakLogin,
  onLocalLogin,
}: LoginPageProps) {
  const { t } = useTranslation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [localFormOpen, setLocalFormOpen] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setPending(true);
    try {
      await onLocalLogin(username, password);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("auth.loginError"));
    } finally {
      setPending(false);
    }
  };

  return (
    <div className="pf-login-page">
      <div className="pf-login-shell">
        <header className="pf-login-brand">
          <div className="pf-login-brand__mark" aria-hidden />
          <div>
            <h1 className="pf-login-brand__title">SecAudit</h1>
            <p className="pf-login-brand__subtitle">{t("auth.loginSubtitle")}</p>
          </div>
        </header>

        <div className="pf-login-body">
          {demoStand ? (
            <aside className="pf-login-demo-notice" role="note">
              <strong className="pf-login-demo-notice__title">{t("auth.demoStandTitle")}</strong>
              <p className="pf-login-demo-notice__text">{t("auth.demoStandNotice")}</p>
            </aside>
          ) : null}

          <p className="pf-login-intro">{t("auth.loginRequired")}</p>

          <div className="pf-login-methods">
            {showKeycloak && (
              <LoginMethodButton
                variant="sso"
                label={t("auth.loginKeycloak")}
                onClick={onKeycloakLogin}
                disabled={keycloakDisabled}
                disabledHint={keycloakDisabled ? t("auth.ssoUnavailable") : undefined}
              />
            )}

            {showLocal && !localFormOpen && (
              <LoginMethodButton
                variant="local"
                label={t("auth.localLogin")}
                onClick={() => setLocalFormOpen(true)}
              />
            )}

            {showLocal && localFormOpen && (
              <div className="pf-login-methods__expand">
                <LoginLocalForm
                  username={username}
                  password={password}
                  error={error}
                  pending={pending}
                  onUsernameChange={setUsername}
                  onPasswordChange={setPassword}
                  onSubmit={handleSubmit}
                  onCancel={() => {
                    setLocalFormOpen(false);
                    setError(null);
                  }}
                />
              </div>
            )}
          </div>
        </div>

        <footer className="pf-login-footer">
          <span>{demoStand ? t("auth.demoStandFooter") : "SecAudit Platform"}</span>
        </footer>
      </div>
    </div>
  );
}
