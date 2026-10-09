import Editor from "@monaco-editor/react";
import { useSyncExternalStore } from "react";

const MOBILE_MQ = "(max-width: 768px)";

function subscribeMobile(onChange: () => void) {
  const mq = window.matchMedia(MOBILE_MQ);
  mq.addEventListener("change", onChange);
  return () => mq.removeEventListener("change", onChange);
}

function getMobileSnapshot() {
  return window.matchMedia(MOBILE_MQ).matches;
}

function getServerSnapshot() {
  return false;
}

/** True when viewport is phone-width (shared Monaco / layout helpers). */
export function useIsMobileViewport() {
  return useSyncExternalStore(subscribeMobile, getMobileSnapshot, getServerSnapshot);
}

export const PLAYBOOK_EDITOR_OPTIONS = {
  minimap: { enabled: true },
  fontSize: 14,
  lineHeight: 22,
  wordWrap: "on" as const,
  scrollBeyondLastLine: false,
  automaticLayout: true,
  padding: { top: 12, bottom: 12 },
  renderLineHighlight: "line" as const,
  scrollbar: {
    verticalScrollbarSize: 10,
    horizontalScrollbarSize: 10,
  },
};

export function monacoEditorOptionsForViewport(isMobile: boolean) {
  return {
    ...PLAYBOOK_EDITOR_OPTIONS,
    wordWrap: (isMobile ? "off" : "on") as "off" | "on",
    minimap: { enabled: !isMobile },
  };
}

type PlaybookYamlEditorProps = {
  value: string;
  onChange: (value: string) => void;
  height: string;
};

export function PlaybookYamlEditor({ value, onChange, height }: PlaybookYamlEditorProps) {
  const isMobile = useIsMobileViewport();
  return (
    <Editor
      height={height}
      defaultLanguage="yaml"
      theme="vs-dark"
      value={value}
      onChange={(next) => onChange(next ?? "")}
      options={monacoEditorOptionsForViewport(isMobile)}
    />
  );
}
