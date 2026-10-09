import { useState, type FormEvent } from "react";
import { useTranslation } from "../i18n/I18nProvider";
import { Spinner } from "../components/ui/Spinner";
import { LoginMethodButton } from "./LoginMethodButton";
import { LoginLocalForm } from "./LoginLocalForm";
import { LoginMfaForm } from "./LoginMfaForm";
import { MfaRequiredError } from "./mfaErrors";

const DEMO_STAND_REPO_URL = "https://github.com/secauditplatform/SecAudit-Platform-public";
const LICENSE_URL = "https://polyformproject.org/licenses/noncommercial/1.0.0";

type LoginPageProps = {
  showKeycloak: boolean;
  keycloakDisabled?: boolean;
  showLocal: boolean;
  localDisabled?: boolean;
  demoStand?: boolean;
  onKeycloakLogin: () => void;
  onLocalLogin: (username: string, password: string) => Promise<void>;
  onMfaVerify: (mfaToken: string, code: string) => Promise<void>;
  onDemoLogin?: () => Promise<void>;
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
  localDisabled = false,
  demoStand = false,
  onKeycloakLogin,
  onLocalLogin,
  onMfaVerify,
  onDemoLogin,
}: LoginPageProps) {
  const { t } = useTranslation();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaToken, setMfaToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [pending, setPending] = useState(false);
  const [demoPending, setDemoPending] = useState(false);
  const [localFormOpen, setLocalFormOpen] = useState(false);

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError(null);
    setPending(true);
    try {
      await onLocalLogin(username, password);
    } catch (err) {
      if (err instanceof MfaRequiredError) {
        setMfaToken(err.mfaToken);
        setMfaCode("");
        setError(null);
      } else {
        setError(err instanceof Error ? err.message : t("auth.loginError"));
      }
    } finally {
      setPending(false);
    }
  };

  const handleMfaSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!mfaToken) return;
    setError(null);
    setPending(true);
    try {
      await onMfaVerify(mfaToken, mfaCode);
    } catch (err) {
      setError(err instanceof Error ? err.message : t("auth.mfaError"));
    } finally {
      setPending(false);
    }
  };

  const handleDemoLogin = async () => {
    if (!onDemoLogin) return;
    setError(null);
    setDemoPending(true);
    try {
      await onDemoLogin();
    } catch (err) {
      setError(err instanceof Error ? err.message : t("auth.loginError"));
    } finally {
      setDemoPending(false);
    }
  };

  const operatorEntry =
    demoStand && new URLSearchParams(window.location.search).has("operator");
  const localFrozen = localDisabled && !operatorEntry;
  const mfaStep = Boolean(mfaToken);

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
              <p className="pf-login-demo-notice__text">
                {t("auth.demoStandLocalHint")}{" "}
                <a
                  className="pf-login-demo-notice__link"
                  href={DEMO_STAND_REPO_URL}
                  target="_blank"
                  rel="noopener noreferrer"
                >
                  {DEMO_STAND_REPO_URL}
                </a>
              </p>
            </aside>
          ) : null}

          <p className="pf-login-intro">{t("auth.loginRequired")}</p>

          {error && demoStand && onDemoLogin && !mfaStep ? (
            <p className="pf-login-error" role="alert">
              {error}
            </p>
          ) : null}

          <div className="pf-login-methods">
            {mfaStep ? (
              <div className="pf-login-methods__expand">
                <LoginMfaForm
                  username={username}
                  code={mfaCode}
                  error={error}
                  pending={pending}
                  onCodeChange={setMfaCode}
                  onSubmit={handleMfaSubmit}
                  onBack={() => {
                    setMfaToken(null);
                    setMfaCode("");
                    setError(null);
                  }}
                />
              </div>
            ) : (
              <>
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
                    disabled={localFrozen}
                    disabledHint={localFrozen ? t("auth.localLoginDisabled") : undefined}
                  />
                )}

                {showLocal && localFormOpen && !localFrozen && (
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

                {demoStand && onDemoLogin ? (
                  <button
                    type="button"
                    className="pf-login-demo-signin"
                    onClick={() => void handleDemoLogin()}
                    disabled={demoPending}
                  >
                    {demoPending ? t("auth.loggingIn") : t("auth.signIn")}
                  </button>
                ) : null}
              </>
            )}
          </div>
        </div>

        <footer className="pf-login-footer">
          <div className="pf-login-footer__stack">
            <span>{demoStand ? t("auth.demoStandFooter") : "SecAudit Platform"}</span>
            {demoStand ? (
              <span className="pf-login-footer__license">
                {t("auth.demoStandLicense")}{" "}
                <a href={LICENSE_URL} target="_blank" rel="noopener noreferrer">
                  PolyForm Noncommercial 1.0.0
                </a>
              </span>
            ) : null}
          </div>
        </footer>
      </div>
    </div>
  );
}
