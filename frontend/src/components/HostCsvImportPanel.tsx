import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { api, type HostCsvImportResult } from "../api/client";
import { useTranslation } from "../i18n/I18nProvider";
import { Button } from "./ui/Button";
import { FileUploadZone } from "./ui/FileUploadZone";
import { Panel } from "./ui/Panel";
import { useToast } from "./ui/Toast";

export function HostCsvImportPanel({ canExecute }: { canExecute: boolean }) {
  const { t } = useTranslation();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<HostCsvImportResult | null>(null);
  const [pending, setPending] = useState<"preview" | "apply" | null>(null);

  async function run(apply: boolean) {
    if (!file) return;
    setPending(apply ? "apply" : "preview");
    try {
      const result = await api.importHostsCsv(file, apply);
      if (apply) {
        toast.success(t("hosts.csvApplied", { created: result.created, updated: result.updated }));
        setPreview(null);
        setFile(null);
        await queryClient.invalidateQueries({ queryKey: ["hosts"] });
      } else {
        setPreview(result);
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("toast.genericError"));
    } finally {
      setPending(null);
    }
  }

  const blocked = !canExecute;
  const canWrite = preview != null && (preview.created > 0 || preview.updated > 0);

  return (
    <Panel title={t("hosts.csvTitle")}>
      <div className="pf-host-csv">
        <FileUploadZone
          id="host-csv-file"
          label={t("hosts.csvTitle")}
          accept=".csv,text/csv"
          formatLabels={[".csv"]}
          multiple={false}
          variant="profiles"
          files={file ? [file] : []}
          onFilesChange={(next) => {
            setFile(next[0] ?? null);
            setPreview(null);
          }}
          disabled={blocked || pending != null}
          hint={t("hosts.csvColumns")}
        />
        <div className="pf-host-csv__actions">
          <Button
            type="button"
            variant="secondary"
            disabled={blocked || !file || pending != null}
            loading={pending === "preview"}
            title={blocked ? t("common.demoActionDisabled") : undefined}
            onClick={() => void run(false)}
          >
            {t("hosts.csvPreview")}
          </Button>
          <Button
            type="button"
            disabled={blocked || !canWrite || pending != null}
            loading={pending === "apply"}
            title={blocked ? t("common.demoActionDisabled") : undefined}
            onClick={() => void run(true)}
          >
            {t("hosts.csvApply")}
          </Button>
        </div>
        {preview ? (
          <div className="pf-host-csv__summary">
            <span>{t("hosts.csvCreated", { count: preview.created })}</span>
            <span>{t("hosts.csvUpdated", { count: preview.updated })}</span>
            <span>{t("hosts.csvUnchanged", { count: preview.unchanged })}</span>
            <span>{t("hosts.csvRejected", { count: preview.rejected.length })}</span>
            {preview.truncated ? <span>{t("hosts.csvTruncated")}</span> : null}
            {preview.rejected.length > 0 ? (
              <ul className="pf-host-csv__rejected">
                {preview.rejected.slice(0, 30).map((item) => (
                  <li key={`${item.row}-${item.reason}`}>
                    {item.row}: {t(`hosts.csvReason_${item.reason}`)}
                  </li>
                ))}
              </ul>
            ) : null}
            {!canWrite ? <span>{t("hosts.csvNoChanges")}</span> : null}
          </div>
        ) : null}
      </div>
    </Panel>
  );
}
