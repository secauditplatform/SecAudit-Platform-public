import Editor from "@monaco-editor/react";

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

type PlaybookYamlEditorProps = {
  value: string;
  onChange: (value: string) => void;
  height: string;
};

export function PlaybookYamlEditor({ value, onChange, height }: PlaybookYamlEditorProps) {
  return (
    <Editor
      height={height}
      defaultLanguage="yaml"
      theme="vs-dark"
      value={value}
      onChange={(next) => onChange(next ?? "")}
      options={PLAYBOOK_EDITOR_OPTIONS}
    />
  );
}
