import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import QRCode from "qrcode";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { useTranslation } from "../i18n/I18nProvider";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { PasswordInput } from "./ui/PasswordInput";
import { Spinner } from "./ui/Spinner";
import { useToast } from "./ui/Toast";

export function MfaSettings() {
  const { t } = useTranslation();
  const { authMode } = useAuth();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [setupSecret, setSetupSecret] = useState<string | null>(null);
  const [otpauthUri, setOtpauthUri] = useState<string | null>(null);
  const [qrDataUrl, setQrDataUrl] = useState<string | null>(null);
  const [confirmCode, setConfirmCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [disablePassword, setDisablePassword] = useState("");
  const [disableCode, setDisableCode] = useState("");
  const [showManualSecret, setShowManualSecret] = useState(false);
  const [secretCopied, setSecretCopied] = useState(false);

  const enabled = authMode === "local";
  const status = useQuery({
    queryKey: ["mfa-status"],
    queryFn: () => api.mfaStatus(),
    enabled,
    retry: false,
  });

  useEffect(() => {
    let cancelled = false;
    if (!otpauthUri) {
      setQrDataUrl(null);
      return;
    }
    void QRCode.toDataURL(otpauthUri, {
      errorCorrectionLevel: "M",
      margin: 1,
      width: 160,
      color: { dark: "#111827", light: "#ffffff" },
    })
      .then((url) => {
        if (!cancelled) setQrDataUrl(url);
      })
      .catch(() => {
        if (!cancelled) setQrDataUrl(null);
      });
    return () => {
      cancelled = true;
    };
  }, [otpauthUri]);

  const resetEnrollment = () => {
    setSetupSecret(null);
    setOtpauthUri(null);
    setQrDataUrl(null);
    setConfirmCode("");
    setShowManualSecret(false);
    setSecretCopied(false);
  };

  const setupMutation = useMutation({
    mutationFn: () => api.mfaSetup(),
    onSuccess: (data) => {
      setSetupSecret(data.secret);
      setOtpauthUri(data.otpauth_uri);
      setRecoveryCodes(null);
      setConfirmCode("");
      setShowManualSecret(false);
      setSecretCopied(false);
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const confirmMutation = useMutation({
    mutationFn: () => api.mfaConfirm(confirmCode),
    onSuccess: (data) => {
      setRecoveryCodes(data.recovery_codes);
      resetEnrollment();
      void queryClient.invalidateQueries({ queryKey: ["mfa-status"] });
      toast.success(t("settings.mfaEnabled"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const disableMutation = useMutation({
    mutationFn: () => api.mfaDisable(disablePassword, disableCode),
    onSuccess: () => {
      setDisablePassword("");
      setDisableCode("");
      setRecoveryCodes(null);
      void queryClient.invalidateQueries({ queryKey: ["mfa-status"] });
      toast.success(t("settings.mfaDisabled"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const copySecret = async () => {
    if (!setupSecret) return;
    try {
      await navigator.clipboard.writeText(setupSecret);
      setSecretCopied(true);
      window.setTimeout(() => setSecretCopied(false), 2000);
    } catch {
      toast.error(t("toast.genericError"));
    }
  };

  if (!enabled) {
    return (
      <section className="pf-settings-block" aria-labelledby="settings-mfa-heading">
        <div className="pf-settings-block__head">
          <h3 id="settings-mfa-heading" className="pf-settings-block__title">
            {t("settings.mfaTitle")}
          </h3>
          <p className="pf-settings-block__desc">{t("settings.mfaSsoOnly")}</p>
        </div>
      </section>
    );
  }

  const mfaOn = Boolean(status.data?.enabled);
  const enrolling = Boolean(setupSecret);

  return (
    <section className="pf-settings-block pf-settings-block--mfa" aria-labelledby="settings-mfa-heading">
      <div className="pf-settings-mfa__header">
        <div className="pf-settings-block__head">
          <h3 id="settings-mfa-heading" className="pf-settings-block__title">
            {t("settings.mfaTitle")}
          </h3>
          {!enrolling ? <p className="pf-settings-block__desc">{t("settings.mfaDesc")}</p> : null}
        </div>
        {!status.isLoading && !enrolling ? (
          <Badge variant={mfaOn ? "success" : "neutral"} literal>
            {mfaOn ? t("common.on") : t("common.off")}
          </Badge>
        ) : null}
      </div>

      {status.isLoading ? (
        <div className="pf-settings-mfa__loading">
          <Spinner />
        </div>
      ) : null}

      {!status.isLoading && mfaOn && !enrolling ? (
        <div className="pf-settings-mfa">
          <p className="pf-settings-mfa__status">
            {t("settings.mfaStatusOn", { count: status.data?.recovery_codes_remaining ?? 0 })}
          </p>
          <div className="pf-settings-mfa__disable">
            <label className="pf-settings-mfa__field">
              <span className="pf-settings-mfa__label">{t("auth.password")}</span>
              <PasswordInput
                value={disablePassword}
                onChange={(e) => setDisablePassword(e.target.value)}
                autoComplete="current-password"
              />
            </label>
            <label className="pf-settings-mfa__field">
              <span className="pf-settings-mfa__label">{t("auth.mfaCode")}</span>
              <input
                className="pf-input"
                value={disableCode}
                onChange={(e) => setDisableCode(e.target.value)}
                autoComplete="one-time-code"
                inputMode="numeric"
                placeholder={t("auth.mfaCodePlaceholder")}
              />
            </label>
            <div className="pf-settings-mfa__actions">
              <Button
                variant="danger-secondary"
                className="pf-btn--sm"
                onClick={() => disableMutation.mutate()}
                disabled={disableMutation.isPending || !disablePassword || !disableCode.trim()}
              >
                {t("settings.mfaDisable")}
              </Button>
            </div>
          </div>
        </div>
      ) : null}

      {!status.isLoading && !mfaOn && !enrolling ? (
        <div className="pf-settings-mfa pf-settings-mfa--idle">
          <Button
            variant="secondary"
            className="pf-btn--sm pf-settings-mfa__setup-btn"
            onClick={() => setupMutation.mutate()}
            disabled={setupMutation.isPending}
            loading={setupMutation.isPending}
          >
            {t("settings.mfaEnable")}
          </Button>
        </div>
      ) : null}

      {enrolling ? (
        <div className="pf-settings-mfa pf-settings-mfa--enroll">
          <div className="pf-settings-mfa__scan">
            <p className="pf-settings-mfa__step">{t("settings.mfaScanHint")}</p>
            <div className="pf-settings-mfa__qr-block">
              <div className="pf-settings-mfa__qr-card">
                <div className="pf-settings-mfa__qr-frame">
                  {qrDataUrl ? (
                    <img className="pf-settings-mfa__qr" src={qrDataUrl} alt={t("settings.mfaQrAlt")} width={160} height={160} />
                  ) : (
                    <div className="pf-settings-mfa__qr-placeholder">
                      <Spinner />
                    </div>
                  )}
                </div>
              </div>
              <div className="pf-settings-mfa__qr-actions">
                {otpauthUri ? (
                  <a className="pf-settings-mfa__link" href={otpauthUri}>
                    {t("settings.mfaOpenApp")}
                  </a>
                ) : null}
                <button
                  type="button"
                  className="pf-settings-mfa__link-btn"
                  onClick={() => setShowManualSecret((v) => !v)}
                >
                  {showManualSecret ? t("settings.mfaHideSecret") : t("settings.mfaCantScan")}
                </button>
              </div>
            </div>
            {showManualSecret && setupSecret ? (
              <div className="pf-settings-mfa__manual">
                <p className="pf-settings-mfa__manual-hint">{t("settings.mfaManualHint")}</p>
                <div className="pf-settings-mfa__secret-row">
                  <code className="pf-settings-mfa__secret">{setupSecret}</code>
                  <Button variant="secondary" className="pf-btn--sm" type="button" onClick={() => void copySecret()}>
                    {secretCopied ? t("settings.mfaCopied") : t("settings.mfaCopySecret")}
                  </Button>
                </div>
              </div>
            ) : null}
          </div>

          <form
            className="pf-settings-mfa__confirm"
            onSubmit={(event) => {
              event.preventDefault();
              if (confirmCode.trim()) confirmMutation.mutate();
            }}
          >
            <p className="pf-settings-mfa__step">{t("settings.mfaConfirmHint")}</p>
            <label className="pf-settings-mfa__field pf-settings-mfa__field--code">
              <span className="pf-settings-mfa__label">{t("auth.mfaCode")}</span>
              <input
                className="pf-input pf-settings-mfa__code-input"
                value={confirmCode}
                onChange={(e) => setConfirmCode(e.target.value.replace(/\s/g, "").slice(0, 32))}
                autoComplete="one-time-code"
                inputMode="numeric"
                placeholder="000000"
                autoFocus
              />
            </label>
            <div className="pf-settings-mfa__actions">
              <Button
                type="submit"
                className="pf-btn--sm"
                disabled={confirmMutation.isPending || confirmCode.trim().length < 6}
                loading={confirmMutation.isPending}
              >
                {t("settings.mfaConfirm")}
              </Button>
              <Button
                type="button"
                variant="secondary"
                className="pf-btn--sm"
                onClick={resetEnrollment}
                disabled={confirmMutation.isPending}
              >
                {t("common.cancel")}
              </Button>
            </div>
          </form>
        </div>
      ) : null}

      {recoveryCodes && recoveryCodes.length > 0 ? (
        <div className="pf-settings-mfa__recovery" role="status">
          <p className="pf-settings-mfa__recovery-title">{t("settings.mfaRecoveryHint")}</p>
          <ul className="pf-settings-mfa__recovery-grid">
            {recoveryCodes.map((code) => (
              <li key={code}>
                <code>{code}</code>
              </li>
            ))}
          </ul>
          <Button variant="secondary" className="pf-btn--sm" type="button" onClick={() => setRecoveryCodes(null)}>
            {t("settings.mfaRecoveryDismiss")}
          </Button>
        </div>
      ) : null}
    </section>
  );
}
