import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { api, type NetworkVendor } from "../api/client";
import { Button } from "./ui/Button";
import { FileInputField } from "./ui/FileInputField";
import { Panel } from "./ui/Panel";
import { useToast } from "./ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";

const VENDORS: NetworkVendor[] = [
  "cisco_ios",
  "cisco_nxos",
  "cisco_asa",
  "juniper_junos",
  "arista_eos",
  "huawei",
  "h3c",
  "fortinet",
  "palo_alto",
  "check_point",
  "generic",
];

type JobOption = { id: number; name: string };
type HostOption = { id: number; name: string };

export function NetworkConfigUploadPanel({
  jobId,
  jobs,
  onJobChange,
  hostOptions,
}: {
  jobId: number | null;
  jobs?: JobOption[];
  onJobChange?: (id: number) => void;
  hostOptions?: HostOption[];
}) {
  const { t } = useTranslation();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [vendor, setVendor] = useState<NetworkVendor>("cisco_ios");
  const [file, setFile] = useState<File | null>(null);
  const [hostId, setHostId] = useState<number | "">("");

  const configs = useQuery({
    queryKey: ["network-configs", jobId],
    queryFn: () => api.listNetworkConfigs(jobId!),
    enabled: jobId != null,
  });

  const upload = useMutation({
    mutationFn: () => {
      if (!jobId || !file) throw new Error("Missing job or file");
      return api.uploadNetworkConfig(jobId, file, {
        hostId: hostId !== "" ? hostId : undefined,
        vendor,
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["network-configs", jobId] });
      setFile(null);
      toast.success(t("network.configUploaded"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const canUpload = jobId != null && file != null;

  return (
    <Panel title={t("network.configUploadTitle")} className="pf-network-config-panel">

      {jobs && jobs.length > 0 && onJobChange ? (
        <div className="pf-form__row pf-network-config-panel__job-row">
          <div className="pf-form__group">
            <label htmlFor="network-config-job">{t("network.configJob")}</label>
            <select
              id="network-config-job"
              className="pf-select"
              value={jobId ?? ""}
              onChange={(e) => onJobChange(Number(e.target.value))}
            >
              {jobs.map((job) => (
                <option key={job.id} value={job.id}>
                  {job.name}
                </option>
              ))}
            </select>
          </div>
        </div>
      ) : null}

      {jobId == null ? (
        <p className="pf-network-config-panel__hint">{t("network.configUploadHint")}</p>
      ) : (
        <>
          <div className="pf-form pf-form--wide pf-network-config-panel__form">
            <div className="pf-form__row">
              {hostOptions && hostOptions.length > 0 ? (
                <div className="pf-form__group">
                  <label htmlFor="network-config-host">{t("network.configHostOptional")}</label>
                  <select
                    id="network-config-host"
                    className="pf-select"
                    value={hostId}
                    onChange={(e) => setHostId(e.target.value ? Number(e.target.value) : "")}
                  >
                    <option value="">{t("network.configHostAny")}</option>
                    {hostOptions.map((host) => (
                      <option key={host.id} value={host.id}>
                        {host.name}
                      </option>
                    ))}
                  </select>
                </div>
              ) : null}
              <div className="pf-form__group">
                <label htmlFor="network-config-vendor">{t("network.vendor")}</label>
                <select
                  id="network-config-vendor"
                  className="pf-select"
                  value={vendor}
                  onChange={(e) => setVendor(e.target.value as NetworkVendor)}
                >
                  {VENDORS.map((v) => (
                    <option key={v} value={v}>
                      {t(`network.vendors.${v}`, { defaultValue: v })}
                    </option>
                  ))}
                </select>
              </div>
              <div className="pf-form__group">
                <label htmlFor="network-config-file">{t("network.configFile")}</label>
                <FileInputField
                  id="network-config-file"
                  accept=".txt,.cfg,.conf,.config,.log"
                  file={file}
                  onFileChange={setFile}
                  disabled={upload.isPending}
                />
              </div>
            </div>
            <div className="pf-form__actions">
              <Button onClick={() => upload.mutate()} disabled={!canUpload || upload.isPending}>
                {t("network.uploadConfig")}
              </Button>
            </div>
          </div>

          {configs.data && configs.data.length > 0 ? (
            <ul className="pf-network-config-panel__list">
              {configs.data.map((cfg) => (
                <li key={cfg.id} className="pf-network-config-panel__item">
                  <span className="pf-network-config-panel__filename">{cfg.filename}</span>
                  <span className="pf-network-config-panel__meta">
                    {cfg.vendor} · {new Date(cfg.created_at).toLocaleString()}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="pf-network-config-panel__empty">{t("network.configUploadEmpty")}</p>
          )}
        </>
      )}
    </Panel>
  );
}
