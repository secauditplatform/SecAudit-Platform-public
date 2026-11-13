import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import { api, type SystemHealth } from "../api/client";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Spinner } from "./ui/Spinner";
import { useToast } from "./ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";

const COMPONENT_ORDER = ["postgres", "redis", "worker", "beat"] as const;
const QUEUE_ORDER = ["compliance", "remediation", "inventory", "aag", "maintenance"] as const;

function statusVariant(status: string): "success" | "danger" | "neutral" {
  if (status === "ok") return "success";
  if (status === "error") return "danger";
  return "neutral";
}

function componentLabel(t: (key: string) => string, key: string): string {
  const map: Record<string, string> = {
    postgres: t("settings.healthPostgres"),
    redis: t("settings.healthRedis"),
    worker: t("settings.healthWorker"),
    beat: t("settings.healthBeat"),
  };
  return map[key] ?? key;
}

export function SystemHealthSettings() {
  const { t } = useTranslation();
  const toast = useToast();
  const queryClient = useQueryClient();
  const [retentionDays, setRetentionDays] = useState("0");

  const health = useQuery({
    queryKey: ["system-health"],
    queryFn: api.systemHealth,
    refetchInterval: 10_000,
  });

  useEffect(() => {
    if (health.data) {
      setRetentionDays(String(health.data.retention_days));
    }
  }, [health.data]);

  const saveRetention = useMutation({
    mutationFn: (days: number) => api.updateSystemHealthSettings({ retention_days: days }),
    onSuccess: (result) => {
      setRetentionDays(String(result.retention_days));
      queryClient.setQueryData<SystemHealth>(["system-health"], (prev) =>
        prev ? { ...prev, retention_days: result.retention_days } : prev
      );
      toast.success(t("settings.healthRetentionSaved"));
    },
    onError: (err) => toast.error(err instanceof Error ? err.message : t("toast.genericError")),
  });

  const onExport = async (format: "csv" | "json") => {
    try {
      await api.exportAuditLogs(format);
      toast.success(t("settings.healthExportStarted"));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : t("toast.genericError"));
    }
  };

  const onApplyRetention = () => {
    const parsed = Number.parseInt(retentionDays, 10);
    if (!Number.isFinite(parsed) || parsed < 0 || parsed > 3650) {
      toast.error(t("settings.healthRetentionInvalid"));
      return;
    }
    saveRetention.mutate(parsed);
  };

  if (health.isLoading) {
    return (
      <div className="pf-settings-health pf-settings-health--loading">
        <Spinner />
      </div>
    );
  }

  if (health.isError || !health.data) {
    return (
      <div className="pf-settings-health">
        <p className="pf-settings-block__desc">{t("settings.healthLoadError")}</p>
        <Button variant="secondary" onClick={() => void health.refetch()}>
          {t("common.retry")}
        </Button>
      </div>
    );
  }

  const data: SystemHealth = health.data;
  const dirty = Number.parseInt(retentionDays, 10) !== data.retention_days;

  return (
    <div className="pf-settings-health">
      <section className="pf-settings-block" aria-labelledby="settings-health-status">
        <div className="pf-settings-block__head">
          <h3 id="settings-health-status" className="pf-settings-block__title">
            {t("settings.healthComponents")}
          </h3>
          <p className="pf-settings-block__desc">{t("settings.healthComponentsDesc")}</p>
        </div>
        <ul className="pf-settings-health__list">
          {COMPONENT_ORDER.map((key) => {
            const item = data.components[key];
            if (!item) return null;
            return (
              <li key={key} className="pf-settings-health__row">
                <span className="pf-settings-health__name">{componentLabel(t, key)}</span>
                <Badge variant={statusVariant(item.status)}>{item.status}</Badge>
                <span className="pf-settings-health__detail">{item.detail || "—"}</span>
              </li>
            );
          })}
        </ul>
      </section>

      <section className="pf-settings-block" aria-labelledby="settings-health-queues">
        <div className="pf-settings-block__head">
          <h3 id="settings-health-queues" className="pf-settings-block__title">
            {t("settings.healthQueues")}
          </h3>
          <p className="pf-settings-block__desc">{t("settings.healthQueuesDesc")}</p>
        </div>
        <ul className="pf-settings-health__list">
          {QUEUE_ORDER.map((queue) => (
            <li key={queue} className="pf-settings-health__row">
              <span className="pf-settings-health__name">{queue}</span>
              <span className="pf-settings-health__depth">{data.queues[queue] ?? 0}</span>
            </li>
          ))}
        </ul>
      </section>

      <section
        className="pf-settings-block pf-settings-block--retention"
        aria-labelledby="settings-health-retention"
      >
        <div className="pf-settings-health__retention-head">
          <div className="pf-settings-block__head">
            <h3 id="settings-health-retention" className="pf-settings-block__title">
              {t("settings.healthRetention")}
            </h3>
            <p className="pf-settings-block__desc">{t("settings.healthRetentionEditDesc")}</p>
          </div>
          <Badge variant={data.retention_days > 0 ? "success" : "neutral"}>
            {data.retention_days > 0
              ? t("settings.healthRetentionActive", { days: data.retention_days })
              : t("settings.healthRetentionIdle")}
          </Badge>
        </div>
        <div className="pf-settings-health__retention-card">
          <label className="pf-settings-health__retention-label" htmlFor="health-retention-days">
            {t("settings.healthRetentionLabel")}
          </label>
          <div className="pf-settings-health__retention-controls">
            <div className="pf-settings-health__retention-field">
              <input
                id="health-retention-days"
                className="pf-input pf-settings-health__retention-input"
                type="number"
                min={0}
                max={3650}
                step={1}
                value={retentionDays}
                onChange={(event) => setRetentionDays(event.target.value)}
                aria-describedby="health-retention-hint"
              />
              <span className="pf-settings-health__retention-unit" aria-hidden>
                {t("settings.healthRetentionUnit")}
              </span>
            </div>
            <Button
              variant="primary"
              onClick={onApplyRetention}
              disabled={!dirty || saveRetention.isPending}
              loading={saveRetention.isPending}
            >
              {t("settings.healthRetentionApply")}
            </Button>
          </div>
          <p id="health-retention-hint" className="pf-settings-health__retention-hint">
            {data.retention_days > 0
              ? t("settings.healthRetentionDays", { days: data.retention_days })
              : t("settings.healthRetentionOff")}
          </p>
        </div>
      </section>

      <section className="pf-settings-block" aria-labelledby="settings-health-export">
        <div className="pf-settings-block__head">
          <h3 id="settings-health-export" className="pf-settings-block__title">
            {t("settings.healthExport")}
          </h3>
          <p className="pf-settings-block__desc">{t("settings.healthExportDesc")}</p>
        </div>
        <div className="pf-settings-health__actions">
          <Button variant="secondary" onClick={() => void onExport("csv")}>
            {t("settings.healthExportCsv")}
          </Button>
          <Button variant="secondary" onClick={() => void onExport("json")}>
            {t("settings.healthExportJson")}
          </Button>
        </div>
      </section>
    </div>
  );
}
