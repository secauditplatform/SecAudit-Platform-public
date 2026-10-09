import Editor from "@monaco-editor/react";
import { monacoEditorOptionsForViewport, useIsMobileViewport } from "./PlaybookYamlEditor";

export function scriptEditorLanguage(executionType: string): string {
  switch (executionType.toUpperCase()) {
    case "WINRM":
    case "POWERSHELL":
      return "powershell";
    case "PYTHON":
      return "python";
    case "ANSIBLE":
      return "yaml";
    default:
      return "shell";
  }
}

type ScriptCodeEditorProps = {
  value: string;
  onChange: (value: string) => void;
  executionType: string;
  height?: string;
  readOnly?: boolean;
};

export function ScriptCodeEditor({
  value,
  onChange,
  executionType,
  height = "420px",
  readOnly = false,
}: ScriptCodeEditorProps) {
  const isMobile = useIsMobileViewport();
  return (
    <Editor
      height={height}
      language={scriptEditorLanguage(executionType)}
      theme="vs-dark"
      value={value}
      onChange={(next) => onChange(next ?? "")}
      options={{
        ...monacoEditorOptionsForViewport(isMobile),
        readOnly,
      }}
    />
  );
}
