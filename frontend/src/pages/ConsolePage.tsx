import { useState } from "react";
import { Navigate } from "react-router-dom";
import { ConsoleTerminal } from "../components/ConsoleTerminal";
import { useAuth } from "../auth/AuthProvider";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { Button } from "../components/ui/Button";
import { useTranslation } from "../i18n/I18nProvider";

type ConsoleStatus = "connecting" | "connected" | "disconnected" | "error";

export function ConsolePage() {
  const { t } = useTranslation();
  const { canOperate, isDemoMode } = useAuth();
  const [status, setStatus] = useState<ConsoleStatus>("connecting");
  const [sessionKey, setSessionKey] = useState(0);

  if (!canOperate) {
    return <Navigate to="/" replace />;
  }

  const statusLabel =
    status === "connected"
      ? t("console.connected")
      : status === "connecting"
        ? t("console.connecting")
        : status === "error"
          ? t("console.error")
          : t("console.disconnected");

  const examples = isDemoMode
    ? [{ cmd: "ping -c 4 8.8.8.8", desc: t("console.examplePing") }]
    : [
        { cmd: "ping -c 4 8.8.8.8", desc: t("console.examplePing") },
        { cmd: "traceroute google.com", desc: t("console.exampleTraceroute") },
        { cmd: "dig secaudit.local ANY", desc: t("console.exampleDig") },
        { cmd: "nslookup example.com", desc: t("console.exampleNslookup") },
        { cmd: "ss -tuln", desc: t("console.exampleSs") },
      ];

  return (
    <div className="pf-console">
      <PageHeader
        title={t("console.title")}
        description={isDemoMode ? t("console.demoDescription") : t("console.description")}
      />

      <div className="pf-console__workspace">
        <section className="pf-console__main" aria-label={t("console.terminal")}>
          <div className="pf-console-toolbar">
            <div className="pf-console-toolbar__status">
              <span
                className={`pf-console-toolbar__dot pf-console-toolbar__dot--${status}`}
                aria-hidden
              />
              <span className="pf-console-toolbar__label">{t("console.status")}</span>
              <span className="pf-console-toolbar__value">{statusLabel}</span>
            </div>
            <p className="pf-console-toolbar__hint">{t("console.focusHint")}</p>
            <div className="pf-console-toolbar__actions">
              <Button
                variant="secondary"
                className="pf-btn--sm"
                onClick={() => setSessionKey((key) => key + 1)}
              >
                {t("console.newSession")}
              </Button>
            </div>
          </div>

          <div className="pf-console-frame">
            <div className="pf-console-frame__inner">
              <ConsoleTerminal sessionKey={sessionKey} onStatusChange={setStatus} />
            </div>
          </div>
        </section>

        <aside className="pf-console__sidebar">
          <Panel title={t("console.help")} className="pf-console-help-panel" collapsible={false}>
            <p className="pf-console-help__text">
              {isDemoMode ? t("console.demoHelpText") : t("console.helpText")}
            </p>
            <ul className="pf-console-examples">
              {examples.map(({ cmd, desc }) => (
                <li key={cmd} className="pf-console-examples__item">
                  <code className="pf-console-examples__cmd">{cmd}</code>
                  <span className="pf-console-examples__desc">{desc}</span>
                </li>
              ))}
            </ul>
          </Panel>
        </aside>
      </div>
    </div>
  );
}
