import { useQuery } from "@tanstack/react-query";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, type AuditFlowLogEntry } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { useTranslation } from "../i18n/I18nProvider";
import { authenticateWebSocket } from "../utils/wsAuth";
import { resolveWsBaseUrl } from "../utils/wsUrl";

type AuditFlowLogsProps = {
  runId: number;
  runStatus?: string | null;
};

function logKey(entry: AuditFlowLogEntry): string {
  return `${entry.timestamp}|${entry.level}|${entry.message}`;
}

function isActiveStatus(status: string | null | undefined): boolean {
  return status === "pending" || status === "scanning" || status === "running";
}

export function AuditFlowLogs({ runId, runStatus }: AuditFlowLogsProps) {
  const { t } = useTranslation();
  const { token, ready, authenticated } = useAuth();
  const authEnabled = import.meta.env.VITE_AUTH_ENABLED === "true";
  const canLoad = Boolean(ready && (!authEnabled || (authenticated && token)));

  const [liveEntries, setLiveEntries] = useState<AuditFlowLogEntry[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [wsError, setWsError] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const seenKeysRef = useRef<Set<string>>(new Set());
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | null>(null);

  const appendEntries = useCallback((entries: AuditFlowLogEntry[]) => {
    if (entries.length === 0) return;
    setLiveEntries((prev) => {
      const next = [...prev];
      for (const entry of entries) {
        const key = logKey(entry);
        if (seenKeysRef.current.has(key)) continue;
        seenKeysRef.current.add(key);
        next.push(entry);
      }
      return next;
    });
  }, []);

  useEffect(() => {
    setLiveEntries([]);
    seenKeysRef.current.clear();
    setWsConnected(false);
    setWsError(null);
  }, [runId]);

  const logsQuery = useQuery({
    queryKey: ["audit-flow-logs", runId],
    queryFn: () => api.getAuditFlowLogs(runId),
    enabled: canLoad,
    refetchInterval: isActiveStatus(runStatus) ? 1500 : 5000,
    staleTime: 0,
  });

  useEffect(() => {
    if (logsQuery.data) appendEntries(logsQuery.data);
  }, [appendEntries, logsQuery.data]);

  useEffect(() => {
    if (!canLoad) return;

    let cancelled = false;
    let reconnectAttempt = 0;

    const clearReconnectTimer = () => {
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
    };

    const connect = () => {
      if (cancelled) return;
      clearReconnectTimer();
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }

      const ws = new WebSocket(`${resolveWsBaseUrl()}/api/v1/ws/audit-flow/${runId}`);
      wsRef.current = ws;

      ws.onopen = () => {
        reconnectAttempt = 0;
        setWsConnected(true);
        setWsError(null);
        authenticateWebSocket(ws, token, authEnabled);
      };

      ws.onmessage = (event) => {
        try {
          appendEntries([JSON.parse(event.data) as AuditFlowLogEntry]);
        } catch {
          /* ignore malformed frames */
        }
      };

      ws.onerror = () => {
        setWsConnected(false);
        setWsError(t("jobs.logsWsError"));
      };

      ws.onclose = () => {
        setWsConnected(false);
        wsRef.current = null;
        if (!cancelled && isActiveStatus(runStatus)) {
          const delay = Math.min(10_000, 1000 * 2 ** reconnectAttempt);
          reconnectTimerRef.current = window.setTimeout(() => {
            reconnectAttempt += 1;
            connect();
          }, delay);
        }
      };
    };

    connect();

    return () => {
      cancelled = true;
      clearReconnectTimer();
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [appendEntries, authEnabled, canLoad, runId, runStatus, t, token]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    container.scrollTop = container.scrollHeight;
  }, [liveEntries]);

  const sortedLogs = [...liveEntries].sort(
    (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  );
  const waiting = sortedLogs.length === 0;
  const active = isActiveStatus(runStatus);

  return (
    <div className="pf-audit-flow-logs">
      <div className="pf-job-run-logs__toolbar">
        <span className={`pf-job-run-logs__badge${wsConnected ? " pf-job-run-logs__badge--live" : ""}`}>
          {wsConnected ? t("jobs.logsLive") : t("jobs.logsPolling")}
        </span>
        {active && waiting && !logsQuery.isError && (
          <span className="pf-job-run-logs__hint">{t("jobs.logsRunningHint")}</span>
        )}
        {logsQuery.isError && (
          <span className="pf-job-run-logs__error">{(logsQuery.error as Error).message}</span>
        )}
        {wsError && !logsQuery.isError && <span className="pf-job-run-logs__error">{wsError}</span>}
      </div>
      <div ref={containerRef} className="pf-job-run-logs__console pf-audit-flow-logs__console">
        {logsQuery.isLoading && waiting ? (
          <div className="pf-job-run-logs__placeholder">{t("common.loading")}</div>
        ) : waiting ? (
          <div className="pf-job-run-logs__placeholder">
            {active ? t("jobs.waitingLogs") : t("jobs.noLogsYet")}
          </div>
        ) : (
          sortedLogs.map((log, index) => (
            <div key={`${log.timestamp}-${index}`} className="pf-job-run-logs__line">
              <span className="pf-job-run-logs__time">{new Date(log.timestamp).toLocaleTimeString()}</span>
              <span className={`pf-job-run-logs__level pf-job-run-logs__level--${log.level.toLowerCase()}`}>
                [{log.level}]
              </span>
              <span className="pf-job-run-logs__message">{log.message}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
