import { useMutation } from "@tanstack/react-query";
import { useState } from "react";
import { api, type NetworkVendor } from "../api/client";
import { Button } from "./ui/Button";
import { Panel } from "./ui/Panel";
import { useToast } from "./ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";

export function NetworkRemediationConfigPanel({
  runId,
  hostId,
  vendor = "cisco_ios",
}: {
  runId: number | null;
  hostId?: number | null;
  vendor?: NetworkVendor;
}) {
  const { t } = useTranslation();
  const toast = useToast();
  const [hostname, setHostname] = useState("");
  const [commands, setCommands] = useState("");
  const [content, setContent] = useState("");

  const generate = useMutation({
    mutationFn: () => {
      if (!runId) throw new Error("No run selected");
      return api.generateNetworkRemediationConfig(runId, {
        vendor,
        host_id: hostId ?? undefined,
        hostname: hostname.trim() || undefined,
        commands: commands
          .split("\n")
          .map((line) => line.trim())
          .filter(Boolean),
        content,
      });
    },
    onSuccess: async (row) => {
      toast.success(t("network.configGenerated"));
      if (runId) {
        await api.downloadNetworkRemediationConfig(runId, row.id, row.filename);
      }
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  if (runId == null) return null;

  return (
    <Panel title={t("network.remediationConfigTitle")}>
      <p className="pf-table__muted">{t("network.remediationConfigDesc")}</p>
      <div className="pf-form-grid" style={{ marginTop: "1rem" }}>
        <label>
          {t("network.hostnameOptional")}
          <input className="pf-input" value={hostname} onChange={(e) => setHostname(e.target.value)} />
        </label>
        <label style={{ gridColumn: "1 / -1" }}>
          {t("network.commandsOptional")}
          <textarea
            className="pf-input"
            rows={4}
            value={commands}
            onChange={(e) => setCommands(e.target.value)}
            placeholder="aaa new-model&#10;ip ssh version 2"
          />
        </label>
        <label style={{ gridColumn: "1 / -1" }}>
          {t("network.fullConfigOptional")}
          <textarea
            className="pf-input"
            rows={8}
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder={t("network.fullConfigPlaceholder")}
          />
        </label>
      </div>
      <Button
        style={{ marginTop: "0.75rem" }}
        onClick={() => generate.mutate()}
        disabled={generate.isPending}
      >
        {t("network.generateAndDownload")}
      </Button>
    </Panel>
  );
}
