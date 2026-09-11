import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "xterm";
import { useEffect, useRef } from "react";
import { useAuth } from "../auth/AuthProvider";
import { useTranslation } from "../i18n/I18nProvider";
import { resolveWsBaseUrl } from "../utils/wsUrl";
import { authenticateWebSocket } from "../utils/wsAuth";
import "xterm/css/xterm.css";

const authEnabled = import.meta.env.VITE_AUTH_ENABLED === "true";

type ConsoleTerminalProps = {
  sessionKey: number;
  onStatusChange?: (status: "connecting" | "connected" | "disconnected" | "error") => void;
};

export function ConsoleTerminal({ sessionKey, onStatusChange }: ConsoleTerminalProps) {
  const { t } = useTranslation();
  const containerRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const onStatusChangeRef = useRef(onStatusChange);
  const { token, ready } = useAuth();

  useEffect(() => {
    onStatusChangeRef.current = onStatusChange;
  }, [onStatusChange]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container || !ready || (authEnabled && !token)) return;

    let disposed = false;
    onStatusChangeRef.current?.("connecting");

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 14,
      fontFamily: "Consolas, 'Courier New', monospace",
      theme: {
        background: "#15171c",
        foreground: "#d2d2d2",
        cursor: "#2b9af3",
        selectionBackground: "rgba(43, 154, 243, 0.35)",
      },
      convertEol: true,
    });
    const fitAddon = new FitAddon();
    term.loadAddon(fitAddon);
    term.open(container);
    fitAddon.fit();
    term.focus();

    terminalRef.current = term;
    fitAddonRef.current = fitAddon;

    const wsBase = resolveWsBaseUrl();
    const ws = new WebSocket(`${wsBase}/api/v1/ws/console`);
    ws.binaryType = "arraybuffer";
    wsRef.current = ws;

    ws.onopen = () => {
      if (disposed) return;
      authenticateWebSocket(ws, token, authEnabled);
      onStatusChangeRef.current?.("connected");
      sendResize();
      term.focus();
    };

    const sendResize = () => {
      if (disposed || ws.readyState !== WebSocket.OPEN) return;
      fitAddon.fit();
      ws.send(
        JSON.stringify({
          type: "resize",
          cols: term.cols,
          rows: term.rows,
        })
      );
    };

    ws.onmessage = (event) => {
      if (disposed) return;
      if (typeof event.data === "string") {
        term.write(event.data);
      } else {
        term.write(new Uint8Array(event.data));
      }
    };

    ws.onerror = () => {
      if (disposed) return;
      onStatusChangeRef.current?.("error");
      term.writeln("\r\n\x1b[31mОшибка подключения к консоли.\x1b[0m");
    };

    ws.onclose = () => {
      if (disposed) return;
      onStatusChangeRef.current?.("disconnected");
      term.writeln("\r\n\x1b[33mСессия завершена.\x1b[0m");
    };

    const dataDisposable = term.onData((data) => {
      if (!disposed && ws.readyState === WebSocket.OPEN) {
        ws.send(new TextEncoder().encode(data));
      }
    });

    const focusTerminal = () => term.focus();
    container.addEventListener("click", focusTerminal);

    const resizeObserver = new ResizeObserver(() => sendResize());
    resizeObserver.observe(container);
    window.addEventListener("resize", sendResize);

    return () => {
      disposed = true;
      dataDisposable.dispose();
      container.removeEventListener("click", focusTerminal);
      resizeObserver.disconnect();
      window.removeEventListener("resize", sendResize);
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close();
      }
      wsRef.current = null;
      if (!term.element) return;
      term.dispose();
      terminalRef.current = null;
      fitAddonRef.current = null;
    };
  }, [token, ready, sessionKey]);

  return (
    <div className="pf-console-terminal">
      <div className="pf-console-terminal__titlebar">
        <span className="pf-console-terminal__title">{t("console.windowTitle")}</span>
      </div>
      <div ref={containerRef} className="pf-console-terminal__screen" />
    </div>
  );
}
