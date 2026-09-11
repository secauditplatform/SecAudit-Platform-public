import { useEffect, useRef, useState } from "react";
import { useAuth } from "../auth/AuthProvider";
import { useTranslation } from "../i18n/I18nProvider";
import { resolveWsBaseUrl } from "../utils/wsUrl";
import { authenticateWebSocket } from "../utils/wsAuth";
import { Panel } from "./ui/Panel";

type LogEntry = {
  level: string;
  message: string;
  timestamp: string;
};

type RemediationRunLogsProps = {
  runId: number | null;
};

export function RemediationRunLogs({ runId }: RemediationRunLogsProps) {
  const { t } = useTranslation();
  const { token, ready } = useAuth();
  const authEnabled = import.meta.env.VITE_AUTH_ENABLED === "true";
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setLogs([]);
  }, [runId]);

  useEffect(() => {
    if (!runId || !ready || (authEnabled && !token)) return;

    const wsBase = resolveWsBaseUrl();
    const ws = new WebSocket(`${wsBase}/api/v1/ws/remediation-runs/${runId}`);

    ws.onopen = () => {
      authenticateWebSocket(ws, token, authEnabled);
    };

    ws.onmessage = (event) => {
      try {
        const entry = JSON.parse(event.data) as LogEntry;
        setLogs((prev) => [...prev, entry]);
      } catch {
        /* ignore */
      }
    };

    return () => ws.close();
  }, [runId, token, ready, authEnabled]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    container.scrollTop = container.scrollHeight;
  }, [logs]);

  if (!runId) return null;

  return (
    <Panel title={t("remediation.liveLogs", { id: runId })}>
      <div
        ref={containerRef}
        style={{
          fontFamily: "Consolas, monospace",
          fontSize: "0.8125rem",
          background: "#1b1d22",
          color: "#d2d2d2",
          padding: "1rem",
          maxHeight: "16rem",
          overflowY: "auto",
        }}
      >
        {logs.length === 0 ? (
          <div style={{ color: "#8a8d90" }}>{t("remediation.waitingLogs")}</div>
        ) : (
          logs.map((log, i) => (
            <div key={`${log.timestamp}-${i}`} style={{ marginBottom: "0.25rem" }}>
              <span style={{ color: "#8a8d90", marginRight: "0.5rem" }}>
                {new Date(log.timestamp).toLocaleTimeString()}
              </span>
              {log.message}
            </div>
          ))
        )}
      </div>
    </Panel>
  );
}
