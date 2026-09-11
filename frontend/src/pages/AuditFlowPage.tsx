import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Fragment, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api, type AuditFlowHost, type AuditFlowRun, type Profile } from "../api/client";
import { AuditFlowLogs } from "../components/AuditFlowLogs";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { useConfirm } from "../components/ui/ConfirmDialog";
import { EmptyState } from "../components/ui/EmptyState";
import { IconCredentials, IconHosts, IconNetwork, IconReports, IconTrash } from "../components/ui/Icons";
import { PageHeader } from "../components/ui/PageHeader";
import { Panel } from "../components/ui/Panel";
import { useToast } from "../components/ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";
import { useAuth } from "../auth/AuthProvider";
import { applyAuditFlowHostPatch, hostReviewReason } from "../utils/auditFlowHostState";
import { buildAuditFlowReportHref } from "../utils/reportDeepLink";

type CredType = "ssh_password" | "ssh_key" | "winrm";

type CredDraft = {
  label: string;
  credential_type: CredType;
  username: string;
  secret: string;
  key_passphrase: string;
  service_username: string;
  service_secret: string;
};

const ACTIVE = new Set(["pending", "scanning", "running"]);
const emptyCred = (): CredDraft => ({
  label: "",
  credential_type: "ssh_password",
  username: "",
  secret: "",
  key_passphrase: "",
  service_username: "",
  service_secret: "",
});

function profilePlatform(profile: Profile): "linux" | "windows" | "network" | "services" | null {
  const category = (profile.category_name || "").toLowerCase();
  if (category.includes("windows")) return "windows";
  if (category.includes("network")) return "network";
  if (category.includes("service")) return "services";
  if (category.includes("linux")) return "linux";
  return null;
}

function checkScoreText(
  summary:
    | AuditFlowHost["check_summary"]
    | NonNullable<AuditFlowHost["extra_checks"]>[number]
    | null
    | undefined
) {
  if (!summary) return null;
  if (!summary.total_checks) return null;
  const percent = summary.compliance_percent ?? 0;
  return Number.isInteger(percent) ? String(percent) : percent.toFixed(1);
}

function hostJobStatus(host: AuditFlowHost): string | null {
  return host.check_summary?.job_status ?? null;
}

function hostReportReady(host: AuditFlowHost): boolean {
  return Boolean(host.job_run_id && hostJobStatus(host) === "completed");
}

function shortenSkipDetail(detail: string | null | undefined): string | null {
  if (!detail) return null;
  let text = detail.replace(/\s+/g, " ").trim();
  const password = text.match(/Invalid\/incorrect password:[^.]*/i);
  if (password) text = password[0].trim();
  else {
    const facts = text.split(/Gathering Facts:\s*/i);
    if (facts.length > 1) text = facts[facts.length - 1].trim();
    text = text
      .replace(/^FAILED\s+\[[^\]]+\]\s*/i, "")
      .replace(/^[\w.-]+:\s*/i, "")
      .trim();
  }
  if (text.length > 120) return `${text.slice(0, 117)}…`;
  return text || null;
}

function localizeSkipDetail(
  detail: string | null | undefined,
  t: (key: string) => string
): string | null {
  const short = shortenSkipDetail(detail);
  if (!short) return null;
  const hay = `${detail}\n${short}`;
  if (/Invalid\/incorrect password|Permission denied, please try again/i.test(hay)) {
    return t("auditFlow.detailBadPassword");
  }
  if (/No working credential pair/i.test(hay)) {
    return t("auditFlow.skip_auth_failed");
  }
  if (/No SSH\/WinRM management port responded/i.test(hay)) {
    return t("auditFlow.detailNoMgmtPort");
  }
  return short;
}

function hostProfileGroups(host: AuditFlowHost, profiles: Profile[]) {
  const suggested: Array<{ profile_id: number; profile_name: string; confidence?: number }> = [];
  if (host.profile_id && host.profile_name) {
    suggested.push({
      profile_id: host.profile_id,
      profile_name: host.profile_name,
      confidence: host.confidence,
    });
  }
  for (const alt of host.alternatives || []) {
    if (alt.profile_id && alt.profile_id !== host.profile_id) {
      suggested.push(alt);
    }
  }
  const suggestedIds = new Set(suggested.map((item) => item.profile_id));
  const rest = profiles.filter((profile) => !suggestedIds.has(profile.id));
  const samePlatform = rest.filter((profile) => {
    const platform = profilePlatform(profile);
    if (platform === "services") return false;
    return !host.platform || platform === host.platform || platform == null;
  });
  const applications = rest.filter((profile) => profilePlatform(profile) === "services");
  const otherOs = rest.filter((profile) => {
    const platform = profilePlatform(profile);
    return Boolean(host.platform && platform && platform !== "services" && platform !== host.platform);
  });
  return { suggested, samePlatform, applications, otherOs };
}

function platformTone(platform: string | null | undefined): string {
  const value = (platform || "").toLowerCase();
  if (value === "windows") return "windows";
  if (value === "network") return "network";
  if (value === "linux") return "linux";
  return "unknown";
}

function detectTargetType(raw: string): "cidr" | "ip" | "range" | "hostname" | "invalid" | null {
  const v = raw.trim();
  if (!v) return null;
  if (v.includes("/")) {
    const parts = v.split("/");
    if (parts.length === 2 && /^\d+$/.test(parts[1])) {
      const prefix = parseInt(parts[1], 10);
      if (prefix >= 0 && prefix <= 32) return "cidr";
    }
    return "invalid";
  }
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) {
    const octets = v.split(".").map(Number);
    if (octets.every((o) => o >= 0 && o <= 255)) return "ip";
    return "invalid";
  }
  if (/^[\d.-]+$/.test(v) && v.includes("-")) {
    return "range";
  }
  if (/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(v)) {
    return "hostname";
  }
  return "invalid";
}

function getTargetTypeLabel(type: ReturnType<typeof detectTargetType>, t: (key: string) => string): string | null {
  switch (type) {
    case "cidr":
      return t("auditFlow.targetTypeCidr");
    case "ip":
      return t("auditFlow.targetTypeIp");
    case "range":
      return t("auditFlow.targetTypeRange");
    case "hostname":
      return t("auditFlow.targetTypeHost");
    case "invalid":
      return t("auditFlow.targetTypeInvalid");
    default:
      return null;
  }
}

export function AuditFlowPage() {
  const { t } = useTranslation();
  const { canExecute } = useAuth();
  const toast = useToast();
  const { confirm } = useConfirm();
  const queryClient = useQueryClient();
  const [targets, setTargets] = useState<string[]>(["192.168.1.0/24"]);
  const [targetMode, setTargetMode] = useState<"list" | "text">("list");
  const [creds, setCreds] = useState<CredDraft[]>([]);
  const [saveToInventory, setSaveToInventory] = useState(false);
  const [viewedStep, setViewedStep] = useState<"setup" | "scan" | null>(null);
  const [activeId, setActiveId] = useState<number | null>(null);
  const [addingCredHostId, setAddingCredHostId] = useState<number | null>(null);
  const [hostCred, setHostCred] = useState<CredDraft>(emptyCred);

  const runsQuery = useQuery({
    queryKey: ["audit-flow-runs"],
    queryFn: () => api.listAuditFlowRuns(),
    refetchInterval: (query) => {
      const items = query.state.data ?? [];
      return items.some((item) => ACTIVE.has(item.status)) ? 2500 : false;
    },
  });
  const runQuery = useQuery({
    queryKey: ["audit-flow-run", activeId],
    queryFn: () => api.getAuditFlowRun(activeId!),
    enabled: activeId != null,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status && ACTIVE.has(status) ? 1500 : false;
    },
  });
  const profilesQuery = useQuery({
    queryKey: ["profiles"],
    queryFn: () => api.profiles(),
  });

  const run = runQuery.data;
  useEffect(() => {
    setViewedStep(null);
  }, [activeId, run?.status]);
  useEffect(() => {
    setAddingCredHostId(null);
    setHostCred(emptyCred());
  }, [activeId]);
  useEffect(() => {
    if (addingCredHostId == null) return;
    const field = document.getElementById(`af-host-label-${addingCredHostId}`);
    field?.focus();
  }, [addingCredHostId]);
  useEffect(() => {
    if (run?.status === "failed" && run.error_message) {
      toast.error(run.error_message);
    }
  }, [run?.status, run?.error_message, toast]);

  const startMutation = useMutation({
    mutationFn: () => {
      const cleanedTargets = targets
        .flatMap((item) => item.split(/[\s,;\r\n]+/))
        .map((line) => line.trim())
        .filter(Boolean);
      return api.startAuditFlow({
        targets: cleanedTargets,
        credentials: creds
          .filter((c) => c.username.trim() && c.secret.trim())
          .map((c) => ({
            label: c.label.trim() || undefined,
            credential_type: c.credential_type,
            username: c.username.trim(),
            secret: c.secret,
            ...(c.key_passphrase.trim() ? { key_passphrase: c.key_passphrase.trim() } : {}),
            ...(c.service_username.trim() ? { service_username: c.service_username.trim() } : {}),
            ...(c.service_secret.trim() ? { service_secret: c.service_secret.trim() } : {}),
          })),
        save_to_inventory: saveToInventory,
      });
    },
    onSuccess: (created) => {
      setViewedStep(null);
      setActiveId(created.id);
      queryClient.invalidateQueries({ queryKey: ["audit-flow-runs"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const cancelMutation = useMutation({
    mutationFn: (id: number) => api.cancelAuditFlowRun(id),
    onSuccess: (updated) => {
      queryClient.setQueryData(["audit-flow-run", updated.id], updated);
      queryClient.invalidateQueries({ queryKey: ["audit-flow-runs"] });
    },
  });

  const patchMutation = useMutation({
    mutationFn: (payload: {
      id: number;
      selected?: boolean;
      profile_id?: number;
      credential_id?: number;
      extra_profiles?: Array<{ profile_id: number; selected: boolean }>;
    }) => api.patchAuditFlowHosts(activeId!, [payload]),
    onMutate: async (payload) => {
      if (activeId == null) return {};
      await queryClient.cancelQueries({ queryKey: ["audit-flow-run", activeId] });
      const previous = queryClient.getQueryData<AuditFlowRun>(["audit-flow-run", activeId]);
      if (previous) {
        const patch = { ...payload };
        if (payload.profile_id) {
          const profile = profilesQuery.data?.find((item) => item.id === payload.profile_id);
          if (profile) {
            patch.profile_name = profile.profile_name;
          }
        }
        queryClient.setQueryData(["audit-flow-run", activeId], applyAuditFlowHostPatch(previous, patch));
      }
      return { previous };
    },
    onSuccess: (updated) => {
      queryClient.setQueryData(["audit-flow-run", updated.id], updated);
      queryClient.invalidateQueries({ queryKey: ["audit-flow-runs"] });
    },
    onError: (err: Error, _payload, context) => {
      if (activeId != null && context?.previous) {
        queryClient.setQueryData(["audit-flow-run", activeId], context.previous);
      }
      toast.error(err.message);
    },
  });

  const addHostCredMutation = useMutation({
    mutationFn: ({ hostId, draft }: { hostId: number; draft: CredDraft }) =>
      api.addAuditFlowCredential(activeId!, {
        label: draft.label.trim() || undefined,
        credential_type: draft.credential_type,
        username: draft.username.trim(),
        secret: draft.secret,
        ...(draft.key_passphrase.trim() ? { key_passphrase: draft.key_passphrase.trim() } : {}),
        ...(draft.service_username.trim() ? { service_username: draft.service_username.trim() } : {}),
        ...(draft.service_secret.trim() ? { service_secret: draft.service_secret.trim() } : {}),
        host_id: hostId,
      }),
    onSuccess: (updated) => {
      queryClient.setQueryData(["audit-flow-run", updated.id], updated);
      queryClient.invalidateQueries({ queryKey: ["audit-flow-runs"] });
      setAddingCredHostId(null);
      setHostCred(emptyCred());
      toast.success(t("auditFlow.credSaved"));
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const executeMutation = useMutation({
    mutationFn: () => api.executeAuditFlow(activeId!),
    onSuccess: (updated) => {
      queryClient.setQueryData(["audit-flow-run", updated.id], updated);
      queryClient.invalidateQueries({ queryKey: ["audit-flow-runs"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: number) => api.deleteAuditFlowRun(id),
    onSuccess: (_void, id) => {
      if (activeId === id) setActiveId(null);
      queryClient.removeQueries({ queryKey: ["audit-flow-run", id] });
      queryClient.invalidateQueries({ queryKey: ["audit-flow-runs"] });
    },
    onError: (err: Error) => toast.error(err.message),
  });

  const runStep = useMemo(() => {
    if (!run) return "setup";
    if (run.status === "pending" || run.status === "scanning") return "scan";
    if (run.status === "ready") return "review";
    if (run.status === "running") return "checks";
    return "results";
  }, [run]);
  const canJumpBack = run?.status === "ready";
  const step = canJumpBack && viewedStep ? viewedStep : runStep;

  const steps = [
    { id: "setup", label: t("auditFlow.stepSetup") },
    { id: "scan", label: t("auditFlow.stepScan") },
    { id: "review", label: t("auditFlow.stepReview") },
    { id: "checks", label: t("auditFlow.stepChecks") },
    { id: "results", label: t("auditFlow.stepResults") },
  ] as const;
  const stepIndex = steps.findIndex((item) => item.id === step);
  const runStepIndex = steps.findIndex((item) => item.id === runStep);

  const handleTargetItemChange = (index: number, val: string) => {
    const tokens = val.split(/[\s,;\r\n]+/).filter(Boolean);
    if (tokens.length > 1) {
      setTargets((prev) => {
        const copy = [...prev];
        copy.splice(index, 1, ...tokens);
        return copy.slice(0, 16);
      });
    } else {
      setTargets((prev) => {
        const copy = [...prev];
        copy[index] = val;
        return copy;
      });
    }
  };

  const handleTargetItemPaste = (index: number, e: React.ClipboardEvent<HTMLInputElement>) => {
    const pasteData = e.clipboardData.getData("text");
    const tokens = pasteData.split(/[\s,;\r\n]+/).filter(Boolean);
    if (tokens.length > 1) {
      e.preventDefault();
      setTargets((prev) => {
        const copy = [...prev];
        copy.splice(index, 1, ...tokens);
        return copy.slice(0, 16);
      });
    }
  };

  const handleAddTargetRow = (val = "") => {
    setTargets((prev) => (prev.length < 16 ? [...prev, val] : prev));
  };

  const handleRemoveTargetRow = (index: number) => {
    setTargets((prev) => {
      if (prev.length <= 1) return [""];
      return prev.filter((_, i) => i !== index);
    });
  };

  const handleAddExample = (example: string) => {
    setTargets((prev) => {
      if (prev.length === 1 && !prev[0].trim()) {
        return [example];
      }
      if (prev.includes(example)) return prev;
      if (prev.length < 16) return [...prev, example];
      return prev;
    });
  };

  const prefillSetupFromRun = () => {
    if (!run) return;
    if (run.targets?.length) setTargets([...run.targets]);
    setSaveToInventory(Boolean(run.save_to_inventory));
    setCreds((prev) => {
      if (prev.some((item) => item.secret.trim())) return prev;
      if (!run.credentials.length) return prev;
      return run.credentials.map((cred) => ({
        label: cred.label || "",
        credential_type: cred.credential_type,
        username: cred.username,
        secret: "",
      }));
    });
  };

  const goToStep = (id: (typeof steps)[number]["id"]) => {
    if (!canJumpBack) return;
    if (id === "review") {
      setViewedStep(null);
      return;
    }
    if (id === "setup") {
      prefillSetupFromRun();
      setViewedStep("setup");
      return;
    }
    if (id === "scan") setViewedStep("scan");
  };

  const reviewSkipReason = hostReviewReason;

  const skipLabel = (host: AuditFlowHost) => {
    if (step === "review" && canContinue && !host.selected) {
      return t("auditFlow.skip_skipped_by_user");
    }
    const status = hostJobStatus(host);
    if (status === "failed" || status === "cancelled") {
      return t("auditFlow.skip_playbook_failed");
    }
    if (hostReportReady(host)) {
      return t("auditFlow.completed");
    }
    if (host.job_run_id || reviewSkipReason(host) === "checking") {
      return t("auditFlow.running");
    }
    const reason = reviewSkipReason(host);
    if (!reason) return t("auditFlow.ready");
    const key = `auditFlow.skip_${reason}`;
    const translated = t(key);
    return translated === key ? reason : translated;
  };

  const skipVariant = (host: AuditFlowHost): "success" | "warning" | "info" | "danger" => {
    if (step === "review" && canContinue && !host.selected) {
      return "warning";
    }
    const reason = reviewSkipReason(host);
    const status = hostJobStatus(host);
    if (status === "failed" || status === "cancelled" || reason === "playbook_failed" || reason === "auth_failed") {
      return "danger";
    }
    if (
      reason === "scanning" ||
      reason === "checking" ||
      reason === "missing_credential" ||
      (host.job_run_id && !hostReportReady(host))
    ) {
      return "info";
    }
    if (reason) return "warning";
    return "success";
  };

  const renderHostStatus = (host: AuditFlowHost) => {
    const detail = localizeSkipDetail(host.skip_detail, t);
    const showDetail =
      Boolean(detail) &&
      (host.skip_reason === "playbook_failed" ||
        host.skip_reason === "low_confidence" ||
        host.skip_reason === "ambiguous_profile");
    const score = hostReportReady(host) ? checkScoreText(host.check_summary) : null;
    return (
      <div className="pf-audit-flow-status">
        <Badge variant={skipVariant(host)}>{skipLabel(host)}</Badge>
        {score ? (
          <span className="pf-audit-flow-status__score">
            {t("auditFlow.complianceScore", { percent: score })}
          </span>
        ) : null}
        {showDetail ? (
          <p className="pf-audit-flow-status__note" title={host.skip_detail || undefined}>
            {detail}
          </p>
        ) : null}
      </div>
    );
  };

  const renderHostReport = (host: AuditFlowHost) => {
    if (!hostReportReady(host)) {
      return <span className="pf-audit-flow-muted">—</span>;
    }
    const href = buildAuditFlowReportHref(host);
    if (!href) {
      return <span className="pf-audit-flow-muted">—</span>;
    }
    return (
      <Link
        className="pf-btn pf-btn--secondary pf-btn--sm pf-audit-flow-status__report"
        to={href}
      >
        {t("auditFlow.jobRun")}
      </Link>
    );
  };

  const canContinue = Boolean(
    run && run.status === "ready" && run.hosts.some((host) => !host.job_run_id)
  );
  const hostEditable = (host: AuditFlowHost) => canContinue && !host.job_run_id;
  const hostsReadyToExecute = Boolean(
    run?.hosts.some(
      (host) => host.selected && host.credential_id && !host.job_run_id && host.profile_id
    )
  );
  const orderedHosts = useMemo(
    () => [...(run?.hosts ?? [])].sort((left, right) => left.id - right.id),
    [run?.hosts]
  );
  const reviewStats = useMemo(() => {
    const hosts = run?.hosts ?? [];
    let ready = 0;
    let needsAction = 0;
    let selected = 0;
    let reports = 0;
    for (const host of hosts) {
      if (host.selected) selected += 1;
      if (hostReportReady(host)) reports += 1;
      if (!host.selected) continue;
      const reason = hostReviewReason(host);
      if (!reason) ready += 1;
      else if (
        reason === "no_matching_profile" ||
        reason === "auth_failed" ||
        reason === "low_confidence" ||
        reason === "ambiguous_profile" ||
        reason === "missing_credential"
      ) {
        needsAction += 1;
      }
    }
    return { total: hosts.length, ready, needsAction, selected, reports };
  }, [run?.hosts]);
  const runCredentials = run?.credentials ?? [];
  const cancelToolbar =
    run && (runStep === "scan" || runStep === "checks") ? (
      <Button
        type="button"
        variant="secondary"
        className="pf-btn--sm"
        onClick={() => cancelMutation.mutate(run.id)}
        disabled={cancelMutation.isPending}
      >
        {t("auditFlow.cancel")}
      </Button>
    ) : null;
  const stageToolbar =
    runStep === "results" ? (
      <Button type="button" variant="secondary" className="pf-btn--sm" onClick={() => setActiveId(null)}>
        {t("auditFlow.newRun")}
      </Button>
    ) : (
      cancelToolbar
    );

  const deleteRun = async (id: number) => {
    const ok = await confirm({
      title: t("auditFlow.deleteRun"),
      message: t("auditFlow.deleteRunConfirm", { id }),
      variant: "danger",
      confirmLabel: t("common.delete"),
    });
    if (ok) deleteMutation.mutate(id);
  };

  const runStatusLabel = (status: string) => {
    const key = `auditFlow.status${status.charAt(0).toUpperCase()}${status.slice(1)}`;
    const translated = t(key);
    return translated === key ? status : translated;
  };

  const runStatusVariant = (status: string): "success" | "warning" | "info" | "danger" | "neutral" => {
    if (status === "completed" || status === "ready") return "success";
    if (status === "failed") return "danger";
    if (status === "cancelled") return "warning";
    if (ACTIVE.has(status)) return "info";
    return "neutral";
  };

  return (
    <div className="pf-audit-flow">
      <PageHeader title={t("auditFlow.title")} description={t("auditFlow.description")} />

      <ol className="pf-audit-flow-steps" aria-label={t("auditFlow.title")}>
        {steps.map((item, index) => {
          const jumpable = canJumpBack && (item.id === "setup" || item.id === "scan" || item.id === "review");
          return (
            <li
              key={item.id}
              className={`pf-audit-flow-steps__item${
                index === stepIndex ? " pf-audit-flow-steps__item--active" : ""
              }${index < runStepIndex && index !== stepIndex ? " pf-audit-flow-steps__item--done" : ""}${
                jumpable ? " pf-audit-flow-steps__item--clickable" : ""
              }`}
              aria-current={index === stepIndex ? "step" : undefined}
            >
              {jumpable ? (
                <button type="button" className="pf-audit-flow-steps__btn" onClick={() => goToStep(item.id)}>
                  <span className="pf-audit-flow-steps__num">{index + 1}</span>
                  <span className="pf-audit-flow-steps__label">{item.label}</span>
                </button>
              ) : (
                <>
                  <span className="pf-audit-flow-steps__num">{index + 1}</span>
                  <span className="pf-audit-flow-steps__label">{item.label}</span>
                </>
              )}
            </li>
          );
        })}
      </ol>

      {step === "setup" && (
        <Panel
          title={t("auditFlow.stepSetup")}
          description={t("auditFlow.setupHint")}
          collapsible={false}
          className="pf-audit-flow-stage"
          noPadding
        >
          <div className="pf-audit-flow-stage__body pf-audit-flow-stage__content pf-audit-flow-stage__content--setup">
              <section className="pf-audit-flow-block">
                <header className="pf-audit-flow-block__head">
                  <span className="pf-audit-flow-block__icon" aria-hidden="true">
                    <IconNetwork />
                  </span>
                  <div className="pf-audit-flow-block__copy">
                    <div className="pf-audit-flow-block__title-row">
                      <h3 className="pf-audit-flow-block__title">{t("auditFlow.targets")}</h3>
                      <span className="pf-audit-flow-target-counter">
                        {t("auditFlow.targetCount", {
                          count: targets.filter((item) => item.trim()).length || targets.length,
                        })}
                      </span>
                    </div>
                    <p className="pf-audit-flow-block__hint">{t("auditFlow.targetsHint")}</p>
                  </div>
                  <div className="pf-audit-flow-targets-toolbar">
                    <div className="pf-audit-flow-targets-toolbar__modes" role="group">
                      <button
                        type="button"
                        className={`pf-audit-flow-targets-toolbar__mode-btn${
                          targetMode === "list" ? " is-active" : ""
                        }`}
                        onClick={() => setTargetMode("list")}
                      >
                        {t("auditFlow.targetModeList")}
                      </button>
                      <button
                        type="button"
                        className={`pf-audit-flow-targets-toolbar__mode-btn${
                          targetMode === "text" ? " is-active" : ""
                        }`}
                        onClick={() => setTargetMode("text")}
                      >
                        {t("auditFlow.targetModeText")}
                      </button>
                    </div>
                    {targetMode === "list" && (
                      <Button
                        type="button"
                        variant="secondary"
                        className="pf-btn--sm pf-audit-flow-block__add"
                        onClick={() => handleAddTargetRow()}
                        disabled={targets.length >= 16}
                      >
                        {t("auditFlow.addTarget")}
                      </Button>
                    )}
                  </div>
                </header>

                {targetMode === "list" ? (
                  <div className="pf-audit-flow-targets-list">
                    {targets.length === 0 ? (
                      <div className="pf-audit-flow-block__empty">
                        <p className="pf-audit-flow-block__empty-text">{t("auditFlow.targetEmptyList")}</p>
                      </div>
                    ) : (
                      targets.map((target, index) => {
                        const detected = detectTargetType(target);
                        const badgeLabel = getTargetTypeLabel(detected, t);
                        return (
                          <div key={index} className="pf-audit-flow-target-row">
                            <span className="pf-audit-flow-target-row__index">{index + 1}</span>
                            <div className="pf-audit-flow-target-row__input-wrap">
                              <input
                                type="text"
                                className={`pf-input pf-audit-flow-target-row__input${
                                  detected === "invalid" ? " is-invalid" : ""
                                }`}
                                placeholder={t("auditFlow.targetPlaceholder")}
                                value={target}
                                autoComplete="off"
                                spellCheck={false}
                                onChange={(e) => handleTargetItemChange(index, e.target.value)}
                                onPaste={(e) => handleTargetItemPaste(index, e)}
                              />
                              {badgeLabel && (
                                <span
                                  className={`pf-audit-flow-target-row__badge${
                                    detected === "invalid" ? " pf-audit-flow-target-row__badge--invalid" : ""
                                  }`}
                                >
                                  {badgeLabel}
                                </span>
                              )}
                            </div>
                            <button
                              type="button"
                              className="pf-audit-flow-target-row__remove"
                              aria-label={t("auditFlow.removeTarget")}
                              title={t("auditFlow.removeTarget")}
                              onClick={() => handleRemoveTargetRow(index)}
                              disabled={targets.length <= 1 && !target.trim()}
                            >
                              <IconTrash />
                            </button>
                          </div>
                        );
                      })
                    )}

                    {targets.length < 16 && (
                      <button
                        type="button"
                        className="pf-audit-flow-targets-add-btn"
                        onClick={() => handleAddTargetRow()}
                      >
                        + {t("auditFlow.addTarget")}
                      </button>
                    )}
                  </div>
                ) : (
                  <div className="pf-audit-flow-targets-text-mode">
                    <textarea
                      id="audit-flow-targets-text"
                      className="pf-input pf-audit-flow-setup__targets"
                      rows={5}
                      placeholder={t("auditFlow.targetTextPlaceholder")}
                      value={targets.join("\n")}
                      onChange={(e) => setTargets(e.target.value.split("\n"))}
                      spellCheck={false}
                    />
                  </div>
                )}

                <div className="pf-audit-flow-targets-examples">
                  <span className="pf-audit-flow-targets-examples__label">
                    {t("auditFlow.targetExamplesLabel")}
                  </span>
                  <button
                    type="button"
                    className="pf-audit-flow-targets-examples__chip"
                    onClick={() => handleAddExample("192.168.1.0/24")}
                    title={t("auditFlow.targetExampleSubnetLabel")}
                  >
                    <span className="pf-audit-flow-targets-examples__chip-value">192.168.1.0/24</span>
                    <span className="pf-audit-flow-targets-examples__chip-type">
                      ({t("auditFlow.targetExampleSubnetLabel")})
                    </span>
                  </button>
                  <button
                    type="button"
                    className="pf-audit-flow-targets-examples__chip"
                    onClick={() => handleAddExample("10.0.0.1")}
                    title={t("auditFlow.targetExampleIpLabel")}
                  >
                    <span className="pf-audit-flow-targets-examples__chip-value">10.0.0.1</span>
                    <span className="pf-audit-flow-targets-examples__chip-type">
                      ({t("auditFlow.targetExampleIpLabel")})
                    </span>
                  </button>
                  <button
                    type="button"
                    className="pf-audit-flow-targets-examples__chip"
                    onClick={() => handleAddExample("192.168.1.10-50")}
                    title={t("auditFlow.targetExampleRangeLabel")}
                  >
                    <span className="pf-audit-flow-targets-examples__chip-value">192.168.1.10-50</span>
                    <span className="pf-audit-flow-targets-examples__chip-type">
                      ({t("auditFlow.targetExampleRangeLabel")})
                    </span>
                  </button>
                  <button
                    type="button"
                    className="pf-audit-flow-targets-examples__chip"
                    onClick={() => handleAddExample("host.domain.local")}
                    title={t("auditFlow.targetExampleHostLabel")}
                  >
                    <span className="pf-audit-flow-targets-examples__chip-value">host.domain.local</span>
                    <span className="pf-audit-flow-targets-examples__chip-type">
                      ({t("auditFlow.targetExampleHostLabel")})
                    </span>
                  </button>
                </div>
              </section>

              <section className="pf-audit-flow-block">
                <header className="pf-audit-flow-block__head">
                  <span className="pf-audit-flow-block__icon" aria-hidden="true">
                    <IconCredentials />
                  </span>
                  <div className="pf-audit-flow-block__copy">
                    <h3 className="pf-audit-flow-block__title">{t("auditFlow.credentials")}</h3>
                    <p className="pf-audit-flow-block__hint">{t("auditFlow.credHint")}</p>
                  </div>
                  <Button
                    type="button"
                    variant="secondary"
                    className="pf-btn--sm pf-audit-flow-block__add"
                    onClick={() => setCreds((prev) => [...prev, emptyCred()])}
                  >
                    {t("auditFlow.addCredentialShort")}
                  </Button>
                </header>
                <div className="pf-audit-flow-list">
                  {creds.length === 0 ? (
                    <div className="pf-audit-flow-block__empty">
                      <p className="pf-audit-flow-block__empty-text">{t("auditFlow.credEmpty")}</p>
                    </div>
                  ) : (
                    creds.map((cred, index) => (
                    <div key={index} className="pf-audit-flow-cred">
                      <div className="pf-audit-flow-cred__bar">
                        <span className="pf-audit-flow-cred__index">{t("auditFlow.credPair", { n: index + 1 })}</span>
                        <button
                          type="button"
                          className="pf-audit-flow-cred__remove"
                          aria-label={t("auditFlow.removeCredential")}
                          title={t("auditFlow.removeCredential")}
                          onClick={() => setCreds((prev) => prev.filter((_, i) => i !== index))}
                        >
                          <IconTrash />
                        </button>
                      </div>
                      <div
                        className={`pf-audit-flow-cred__fields${
                          cred.credential_type === "ssh_key" ? " pf-audit-flow-cred__fields--key" : ""
                        }`}
                      >
                        <div className="pf-form__group">
                          <label htmlFor={`af-label-${index}`}>{t("auditFlow.credLabel")}</label>
                          <input
                            id={`af-label-${index}`}
                            className="pf-input"
                            value={cred.label}
                            onChange={(e) =>
                              setCreds((prev) => prev.map((c, i) => (i === index ? { ...c, label: e.target.value } : c)))
                            }
                          />
                        </div>
                        <div className="pf-form__group">
                          <label htmlFor={`af-type-${index}`}>{t("auditFlow.credType")}</label>
                          <select
                            id={`af-type-${index}`}
                            className="pf-select"
                            value={cred.credential_type}
                            onChange={(e) =>
                              setCreds((prev) =>
                                prev.map((c, i) =>
                                  i === index ? { ...c, credential_type: e.target.value as CredType } : c
                                )
                              )
                            }
                          >
                            <option value="ssh_password">{t("auditFlow.credTypeSshPassword")}</option>
                            <option value="ssh_key">{t("auditFlow.credTypeSshKey")}</option>
                            <option value="winrm">{t("auditFlow.credTypeWinrm")}</option>
                          </select>
                        </div>
                        <div className="pf-form__group">
                          <label htmlFor={`af-user-${index}`}>{t("auditFlow.credUser")}</label>
                          <input
                            id={`af-user-${index}`}
                            className="pf-input"
                            autoComplete="username"
                            value={cred.username}
                            onChange={(e) =>
                              setCreds((prev) => prev.map((c, i) => (i === index ? { ...c, username: e.target.value } : c)))
                            }
                          />
                        </div>
                        <div className="pf-form__group pf-audit-flow-cred__secret">
                          <label htmlFor={`af-secret-${index}`}>{t("auditFlow.credSecret")}</label>
                          {cred.credential_type === "ssh_key" ? (
                            <textarea
                              id={`af-secret-${index}`}
                              className="pf-input"
                              rows={4}
                              value={cred.secret}
                              onChange={(e) =>
                                setCreds((prev) => prev.map((c, i) => (i === index ? { ...c, secret: e.target.value } : c)))
                              }
                            />
                          ) : (
                            <input
                              id={`af-secret-${index}`}
                              className="pf-input"
                              type="password"
                              autoComplete="current-password"
                              value={cred.secret}
                              onChange={(e) =>
                                setCreds((prev) => prev.map((c, i) => (i === index ? { ...c, secret: e.target.value } : c)))
                              }
                            />
                          )}
                        </div>
                        {cred.credential_type === "ssh_key" ? (
                          <div className="pf-form__group">
                            <label htmlFor={`af-key-passphrase-${index}`}>{t("credentials.keyPassphrase")}</label>
                            <input
                              id={`af-key-passphrase-${index}`}
                              className="pf-input"
                              type="password"
                              autoComplete="off"
                              value={cred.key_passphrase}
                              onChange={(e) =>
                                setCreds((prev) =>
                                  prev.map((c, i) => (i === index ? { ...c, key_passphrase: e.target.value } : c))
                                )
                              }
                            />
                          </div>
                        ) : null}
                        <div className="pf-form__group pf-form__group--divider">
                          <div className="pf-form__hint">{t("credentials.serviceSection")}</div>
                        </div>
                        <div className="pf-form__group">
                          <label htmlFor={`af-service-user-${index}`}>{t("credentials.serviceUser")}</label>
                          <input
                            id={`af-service-user-${index}`}
                            className="pf-input"
                            value={cred.service_username}
                            onChange={(e) =>
                              setCreds((prev) =>
                                prev.map((c, i) => (i === index ? { ...c, service_username: e.target.value } : c))
                              )
                            }
                            placeholder="postgres"
                          />
                        </div>
                        <div className="pf-form__group pf-audit-flow-cred__secret">
                          <label htmlFor={`af-service-secret-${index}`}>{t("credentials.serviceSecret")}</label>
                          <input
                            id={`af-service-secret-${index}`}
                            className="pf-input"
                            type="password"
                            autoComplete="off"
                            value={cred.service_secret}
                            onChange={(e) =>
                              setCreds((prev) =>
                                prev.map((c, i) => (i === index ? { ...c, service_secret: e.target.value } : c))
                              )
                            }
                          />
                        </div>
                      </div>
                    </div>
                    ))
                  )}
                </div>
              </section>

              <label className="pf-audit-flow-option" htmlFor="audit-flow-save-inventory">
                <input
                  id="audit-flow-save-inventory"
                  type="checkbox"
                  className="pf-checkbox-control"
                  checked={saveToInventory}
                  onChange={(e) => setSaveToInventory(e.target.checked)}
                />
                <span className="pf-audit-flow-option__copy">
                  <span className="pf-audit-flow-option__title">{t("auditFlow.saveToInventory")}</span>
                  <span className="pf-audit-flow-option__hint">{t("auditFlow.saveToInventoryHint")}</span>
                </span>
              </label>
              {run?.status === "ready" ? (
                <p className="pf-form__hint pf-audit-flow-setup__reenter">{t("auditFlow.reenterSecrets")}</p>
              ) : null}
          </div>
          <div className="pf-audit-flow-footer">
            {run?.status === "ready" ? (
              <Button type="button" variant="secondary" onClick={() => setViewedStep(null)}>
                {t("auditFlow.backToReview")}
              </Button>
            ) : (
              <span className="pf-audit-flow-footer__spacer" />
            )}
            <div className="pf-audit-flow-footer__actions">
              <Button
                onClick={() => startMutation.mutate()}
                disabled={
                  !canExecute ||
                  startMutation.isPending ||
                  targets.flatMap((item) => item.split(/[\s,;\r\n]+/)).filter((t) => t.trim()).length === 0
                }
                title={!canExecute ? t("common.demoActionDisabled") : undefined}
              >
                {t("auditFlow.startScan")}
              </Button>
            </div>
          </div>
        </Panel>
      )}

      {step === "scan" && run && (
        <Panel
          title={t("auditFlow.scanning")}
          description={t("auditFlow.scanHint")}
          toolbar={cancelToolbar}
          collapsible={false}
          className="pf-audit-flow-stage"
          noPadding
        >
          <div className="pf-audit-flow-stage__body pf-audit-flow-stage__content">
            <div className={`pf-audit-flow-live${run.status === "ready" ? " is-done" : " is-active"}`}>
              <span className="pf-audit-flow-live__dot" aria-hidden="true" />
              <div className="pf-audit-flow-live__copy">
                <strong>
                  {run.status === "ready"
                    ? t("auditFlow.scanDone")
                    : run.progress?.address
                      ? t("auditFlow.scanLive")
                      : t("auditFlow.scanIdle")}
                </strong>
                {run.progress?.address ? (
                  <span>
                    {t("auditFlow.checkingNow")}: <code>{run.progress.address}</code>
                  </span>
                ) : null}
              </div>
              <span className="pf-audit-flow-live__count">
                {t("auditFlow.hostsFoundCount", { count: orderedHosts.length })}
              </span>
            </div>

            {(run.targets ?? []).length > 0 && (
              <section className="pf-audit-flow-block">
                <header className="pf-audit-flow-block__head">
                  <span className="pf-audit-flow-block__icon" aria-hidden="true">
                    <IconNetwork />
                  </span>
                  <div className="pf-audit-flow-block__copy">
                    <h3 className="pf-audit-flow-block__title">{t("auditFlow.scanTargets")}</h3>
                    <p className="pf-audit-flow-block__hint">{t("auditFlow.targetsHint")}</p>
                  </div>
                </header>
                <ul className="pf-audit-flow-targets">
                  {run.targets.map((target) => {
                    const current = run.progress?.target === target;
                    return (
                      <li
                        key={target}
                        className={`pf-audit-flow-targets__item${current ? " is-current" : ""}`}
                      >
                        <code>{target}</code>
                        {run.status !== "ready" ? (
                          <Badge variant={current ? "info" : "neutral"}>
                            {current ? t("auditFlow.skip_checking") : t("auditFlow.skip_scanning")}
                          </Badge>
                        ) : null}
                      </li>
                    );
                  })}
                </ul>
              </section>
            )}

            <section className="pf-audit-flow-block">
              <header className="pf-audit-flow-block__head">
                <span className="pf-audit-flow-block__icon" aria-hidden="true">
                  <IconHosts />
                </span>
                <div className="pf-audit-flow-block__copy">
                  <h3 className="pf-audit-flow-block__title">{t("auditFlow.discoveredHosts")}</h3>
                  <p className="pf-audit-flow-block__hint">{t("auditFlow.scanHint")}</p>
                </div>
              </header>
              {orderedHosts.length === 0 ? (
                <div className="pf-audit-flow-block__empty">
                  <p className="pf-audit-flow-block__empty-title">{t("auditFlow.noHostsYet")}</p>
                  <p className="pf-audit-flow-block__empty-text">{t("auditFlow.scanHint")}</p>
                </div>
              ) : (
                <div className="pf-table-wrap pf-audit-flow-scan__table">
                  <table className="pf-table pf-audit-flow-table">
                    <thead>
                      <tr>
                        <th>{t("auditFlow.ip")}</th>
                        <th className="pf-audit-flow-table__os">{t("auditFlow.os")}</th>
                        <th>{t("auditFlow.reason")}</th>
                      </tr>
                    </thead>
                    <tbody>
                      {orderedHosts.map((host) => {
                        const current = run.progress?.address === host.ip_address;
                        return (
                          <tr
                            key={host.id}
                            className={current ? "pf-audit-flow-scan__row--current" : undefined}
                          >
                            <td>
                              <span className="pf-audit-flow-scan__ip">{host.ip_address}</span>
                              {host.hostname ? (
                                <span className="pf-audit-flow-scan__host">{host.hostname}</span>
                              ) : null}
                            </td>
                            <td className="pf-audit-flow-table__os">
                              <div className="pf-audit-flow-oscell">
                                {host.platform || host.os_guess ? (
                                  <div className="pf-audit-flow-oscell__main">
                                    {host.platform ? (
                                      <span
                                        className={`pf-audit-flow-plat pf-audit-flow-plat--${platformTone(host.platform)}`}
                                      >
                                        {host.platform}
                                      </span>
                                    ) : null}
                                    <span className="pf-audit-flow-oscell__guess">
                                      {host.os_guess || t("common.dash")}
                                    </span>
                                  </div>
                                ) : (
                                  <span className="pf-audit-flow-oscell__empty">{t("common.dash")}</span>
                                )}
                              </div>
                            </td>
                            <td>
                              <Badge variant={current ? "info" : skipVariant(host)}>
                                {current ? t("auditFlow.skip_checking") : skipLabel(host)}
                              </Badge>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          </div>
          <div className="pf-audit-flow-footer">
            {run.status === "ready" ? (
              <>
                <Button type="button" variant="secondary" onClick={() => goToStep("setup")}>
                  {t("auditFlow.changeSettings")}
                </Button>
                <div className="pf-audit-flow-footer__actions">
                  <Button type="button" variant="secondary" onClick={() => setViewedStep(null)}>
                    {t("auditFlow.backToReview")}
                  </Button>
                </div>
              </>
            ) : (
              <span className="pf-audit-flow-footer__note pf-audit-flow-footer__live">
                <span className="pf-audit-flow-live__dot" aria-hidden="true" />
                {t("auditFlow.scanLive")}
              </span>
            )}
          </div>
        </Panel>
      )}

      {(step === "review" || step === "checks" || step === "results") && run && (
        <Panel
          title={
            step === "review"
              ? t("auditFlow.stepReview")
              : step === "checks"
                ? t("auditFlow.stepChecks")
                : t("auditFlow.stepResults")
          }
          description={
            step === "review"
              ? t("auditFlow.reviewHint")
              : step === "checks"
                ? t("auditFlow.checksHint")
                : t("auditFlow.resultsHint")
          }
          collapsible={step === "results"}
          toolbar={stageToolbar}
          className="pf-audit-flow-stage"
          noPadding
        >
          <div className="pf-audit-flow-stage__body pf-audit-flow-stage__content">
            {orderedHosts.length === 0 ? (
              <EmptyState title={t("auditFlow.noHosts")} description={t("auditFlow.noHostsDesc")} />
            ) : (
              <>
                <div
                  className={`pf-audit-flow-live${
                    step === "checks" ? " is-active" : step === "results" ? " is-done" : " is-idle"
                  }`}
                >
                  <span className="pf-audit-flow-live__dot" aria-hidden="true" />
                  <div className="pf-audit-flow-live__copy">
                    <strong>
                      {step === "checks"
                        ? t("auditFlow.running")
                        : step === "results"
                          ? t("auditFlow.stepResults")
                          : t("auditFlow.reviewLive")}
                    </strong>
                    <span>
                      {[
                        t("auditFlow.hostsFoundCount", { count: reviewStats.total }),
                        step === "results"
                          ? t("auditFlow.reviewReports", { count: reviewStats.reports })
                          : t("auditFlow.reviewReady", { count: reviewStats.ready }),
                        reviewStats.needsAction
                          ? t("auditFlow.reviewNeedsAction", { count: reviewStats.needsAction })
                          : null,
                      ]
                        .filter(Boolean)
                        .join(" · ")}
                    </span>
                  </div>
                  {step === "review" ? (
                    <span className="pf-audit-flow-live__count">
                      {t("auditFlow.reviewSelected", { count: reviewStats.selected })}
                    </span>
                  ) : null}
                </div>

                <section className="pf-audit-flow-block">
                  <header className="pf-audit-flow-block__head">
                    <span className="pf-audit-flow-block__icon" aria-hidden="true">
                      {step === "results" ? <IconReports /> : <IconHosts />}
                    </span>
                    <div className="pf-audit-flow-block__copy">
                      <h3 className="pf-audit-flow-block__title">
                        {step === "results" ? t("auditFlow.stepResults") : t("auditFlow.reviewHostsTitle")}
                      </h3>
                      <p className="pf-audit-flow-block__hint">
                        {step === "results" ? t("auditFlow.resultsHint") : t("auditFlow.continueHint")}
                      </p>
                    </div>
                  </header>
                  <div
                    className={`pf-table-wrap pf-audit-flow-review__table${
                      addingCredHostId != null ? " pf-audit-flow-review__table--editing" : ""
                    }`}
                  >
                    <table className="pf-table pf-audit-flow-table">
                      <thead>
                        <tr>
                          {canContinue && <th className="pf-audit-flow-table__check">{t("auditFlow.select")}</th>}
                          <th>{t("auditFlow.ip")}</th>
                          <th className="pf-audit-flow-table__os">{t("auditFlow.os")}</th>
                          <th className="pf-audit-flow-table__profile">{t("auditFlow.profile")}</th>
                          <th>{t("auditFlow.credential")}</th>
                          <th>{t("auditFlow.reason")}</th>
                          {(step === "checks" || step === "results") && (
                            <th className="pf-audit-flow-table__report">{t("auditFlow.jobRun")}</th>
                          )}
                        </tr>
                      </thead>
                      <tbody>
                        {orderedHosts.map((host) => {
                          const credFormOpen = addingCredHostId === host.id && hostEditable(host);
                          const reviewColSpan =
                            5 + (canContinue ? 1 : 0) + (step === "checks" || step === "results" ? 1 : 0);
                          return (
                          <Fragment key={host.id}>
                          <tr className={credFormOpen ? "pf-audit-flow-table__row--cred-open" : undefined}>
                            {canContinue && (
                              <td className="pf-audit-flow-table__check">
                                <input
                                  type="checkbox"
                                  className="pf-checkbox-control"
                                  checked={host.selected}
                                  disabled={!hostEditable(host)}
                                  onChange={(e) =>
                                    patchMutation.mutate({ id: host.id, selected: e.target.checked })
                                  }
                                />
                              </td>
                            )}
                            <td>
                              <div className="pf-audit-flow-hostcell">
                                <span className="pf-audit-flow-scan__ip">{host.ip_address}</span>
                                {host.hostname ? (
                                  <span className="pf-audit-flow-scan__host">{host.hostname}</span>
                                ) : null}
                                {host.inventory_reused ? (
                                  <span className="pf-audit-flow-scan__host">{t("auditFlow.inventoryReused")}</span>
                                ) : null}
                              </div>
                            </td>
                            <td className="pf-audit-flow-table__os">
                              <div className="pf-audit-flow-oscell">
                                {host.platform || host.os_guess ? (
                                  <div className="pf-audit-flow-oscell__main">
                                    {host.platform ? (
                                      <span
                                        className={`pf-audit-flow-plat pf-audit-flow-plat--${platformTone(host.platform)}`}
                                      >
                                        {host.platform}
                                      </span>
                                    ) : null}
                                    <span className="pf-audit-flow-oscell__guess">{host.os_guess || "—"}</span>
                                  </div>
                                ) : (
                                  <span className="pf-audit-flow-oscell__empty">{t("common.dash")}</span>
                                )}
                              </div>
                            </td>
                            <td className="pf-audit-flow-table__profile">
                              <div className="pf-audit-flow-bind pf-audit-flow-bind--profile">
                                <div className="pf-audit-flow-bind__field">
                                {hostEditable(host) ? (
                                  <select
                                    className="pf-select"
                                    value={host.profile_id ?? ""}
                                    onChange={(e) => {
                                      const profileId = Number(e.target.value);
                                      if (!profileId) return;
                                      patchMutation.mutate({ id: host.id, profile_id: profileId });
                                    }}
                                  >
                                    <option value="">{t("hosts.notSelected")}</option>
                                    {(() => {
                                      const groups = hostProfileGroups(host, profilesQuery.data ?? []);
                                      return (
                                        <>
                                          {groups.suggested.length > 0 && (
                                            <optgroup label={t("auditFlow.suggestedProfiles")}>
                                              {groups.suggested.map((item) => (
                                                <option key={item.profile_id} value={item.profile_id}>
                                                  {item.confidence
                                                    ? `${item.profile_name} (${item.confidence}%)`
                                                    : item.profile_name}
                                                </option>
                                              ))}
                                            </optgroup>
                                          )}
                                          {groups.samePlatform.length > 0 && (
                                            <optgroup label={t("auditFlow.otherProfiles")}>
                                              {groups.samePlatform.map((profile) => (
                                                <option key={profile.id} value={profile.id}>
                                                  {profile.profile_name}
                                                </option>
                                              ))}
                                            </optgroup>
                                          )}
                                          {groups.otherOs.length > 0 && (
                                            <optgroup label={t("auditFlow.otherOsProfiles")}>
                                              {groups.otherOs.map((profile) => (
                                                <option key={profile.id} value={profile.id}>
                                                  {profile.profile_name}
                                                </option>
                                              ))}
                                            </optgroup>
                                          )}
                                          {groups.applications.length > 0 && (
                                            <optgroup label={t("auditFlow.applicationProfiles")}>
                                              {groups.applications.map((profile) => (
                                                <option key={profile.id} value={profile.id}>
                                                  {profile.profile_name}
                                                </option>
                                              ))}
                                            </optgroup>
                                          )}
                                        </>
                                      );
                                    })()}
                                  </select>
                                ) : (
                                  <span className="pf-audit-flow-bind__name">{host.profile_name || "—"}</span>
                                )}
                                </div>
                                {host.confidence && !host.profile_id ? (
                                  <span
                                    className={`pf-audit-flow-match${
                                      host.confidence < 70 ? " pf-audit-flow-match--low" : ""
                                    }`}
                                  >
                                    {t("auditFlow.matchValue", { percent: host.confidence })}
                                  </span>
                                ) : null}
                              </div>
                            </td>
                            <td>
                              <div className="pf-audit-flow-bind pf-audit-flow-bind--cred">
                                {hostEditable(host) ? (
                                  <>
                                    <div className="pf-audit-flow-bind__field">
                                      <select
                                        className="pf-select"
                                        value={host.credential_id ?? ""}
                                        disabled={runCredentials.length === 0}
                                        onChange={(e) => {
                                          const credentialId = Number(e.target.value);
                                          if (!credentialId) return;
                                          patchMutation.mutate({ id: host.id, credential_id: credentialId });
                                        }}
                                      >
                                        <option value="">{host.credential_label || t("hosts.notSelected")}</option>
                                        {runCredentials.map((cred) => (
                                          <option key={cred.id} value={cred.id}>
                                            {cred.label ? `${cred.label} (${cred.username})` : cred.username}
                                          </option>
                                        ))}
                                      </select>
                                    </div>
                                    {credFormOpen ? (
                                      <span className="pf-audit-flow-hostcred__open is-active">
                                        {t("auditFlow.hostCredentialEditing")}
                                      </span>
                                    ) : (
                                      <button
                                        type="button"
                                        className="pf-audit-flow-hostcred__open"
                                        onClick={() => {
                                          setAddingCredHostId(host.id);
                                          setHostCred(emptyCred());
                                        }}
                                      >
                                        {t("auditFlow.addCredentialHost")}
                                      </button>
                                    )}
                                  </>
                                ) : (
                                  <span>{host.credential_label || "—"}</span>
                                )}
                              </div>
                            </td>
                            <td className="pf-audit-flow-table__status">{renderHostStatus(host)}</td>
                            {(step === "checks" || step === "results") && (
                              <td className="pf-audit-flow-table__report">{renderHostReport(host)}</td>
                            )}
                          </tr>
                          {credFormOpen ? (
                            <tr className="pf-audit-flow-hostcred-row">
                              <td colSpan={reviewColSpan}>
                                <form
                                  className="pf-audit-flow-cred pf-audit-flow-hostcred"
                                  onSubmit={(event) => {
                                    event.preventDefault();
                                    if (!hostCred.username.trim() || !hostCred.secret.trim()) return;
                                    addHostCredMutation.mutate({ hostId: host.id, draft: hostCred });
                                  }}
                                >
                                  <div className="pf-audit-flow-hostcred__head">
                                    <p className="pf-audit-flow-hostcred__title">
                                      {t("auditFlow.hostCredentialTitle", { ip: host.ip_address })}
                                    </p>
                                  </div>
                                  <div
                                    className={`pf-audit-flow-cred__fields${
                                      hostCred.credential_type === "ssh_key"
                                        ? " pf-audit-flow-cred__fields--key"
                                        : ""
                                    }`}
                                  >
                                    <div className="pf-form__group">
                                      <label htmlFor={`af-host-label-${host.id}`}>{t("auditFlow.credLabel")}</label>
                                      <input
                                        id={`af-host-label-${host.id}`}
                                        className="pf-input"
                                        value={hostCred.label}
                                        onChange={(e) =>
                                          setHostCred((prev) => ({ ...prev, label: e.target.value }))
                                        }
                                      />
                                    </div>
                                    <div className="pf-form__group">
                                      <label htmlFor={`af-host-type-${host.id}`}>{t("auditFlow.credType")}</label>
                                      <select
                                        id={`af-host-type-${host.id}`}
                                        className="pf-select"
                                        value={hostCred.credential_type}
                                        onChange={(e) =>
                                          setHostCred((prev) => ({
                                            ...prev,
                                            credential_type: e.target.value as CredType,
                                          }))
                                        }
                                      >
                                        <option value="ssh_password">{t("auditFlow.credTypeSshPassword")}</option>
                                        <option value="ssh_key">{t("auditFlow.credTypeSshKey")}</option>
                                        <option value="winrm">{t("auditFlow.credTypeWinrm")}</option>
                                      </select>
                                    </div>
                                    <div className="pf-form__group">
                                      <label htmlFor={`af-host-user-${host.id}`}>{t("auditFlow.credUser")}</label>
                                      <input
                                        id={`af-host-user-${host.id}`}
                                        className="pf-input"
                                        autoComplete="username"
                                        value={hostCred.username}
                                        onChange={(e) =>
                                          setHostCred((prev) => ({ ...prev, username: e.target.value }))
                                        }
                                      />
                                    </div>
                                    <div className="pf-form__group pf-audit-flow-cred__secret">
                                      <label htmlFor={`af-host-secret-${host.id}`}>{t("auditFlow.credSecret")}</label>
                                      {hostCred.credential_type === "ssh_key" ? (
                                        <textarea
                                          id={`af-host-secret-${host.id}`}
                                          className="pf-input"
                                          rows={3}
                                          value={hostCred.secret}
                                          onChange={(e) =>
                                            setHostCred((prev) => ({ ...prev, secret: e.target.value }))
                                          }
                                        />
                                      ) : (
                                        <input
                                          id={`af-host-secret-${host.id}`}
                                          className="pf-input"
                                          type="password"
                                          autoComplete="current-password"
                                          value={hostCred.secret}
                                          onChange={(e) =>
                                            setHostCred((prev) => ({ ...prev, secret: e.target.value }))
                                          }
                                        />
                                      )}
                                    </div>
                                    {hostCred.credential_type === "ssh_key" ? (
                                      <div className="pf-form__group">
                                        <label htmlFor={`af-host-key-passphrase-${host.id}`}>
                                          {t("credentials.keyPassphrase")}
                                        </label>
                                        <input
                                          id={`af-host-key-passphrase-${host.id}`}
                                          className="pf-input"
                                          type="password"
                                          autoComplete="off"
                                          value={hostCred.key_passphrase}
                                          onChange={(e) =>
                                            setHostCred((prev) => ({ ...prev, key_passphrase: e.target.value }))
                                          }
                                        />
                                      </div>
                                    ) : null}
                                    <div className="pf-form__group pf-form__group--divider">
                                      <div className="pf-form__hint">{t("credentials.serviceSection")}</div>
                                    </div>
                                    <div className="pf-form__group">
                                      <label htmlFor={`af-host-service-user-${host.id}`}>
                                        {t("credentials.serviceUser")}
                                      </label>
                                      <input
                                        id={`af-host-service-user-${host.id}`}
                                        className="pf-input"
                                        value={hostCred.service_username}
                                        onChange={(e) =>
                                          setHostCred((prev) => ({ ...prev, service_username: e.target.value }))
                                        }
                                        placeholder="postgres"
                                      />
                                    </div>
                                    <div className="pf-form__group">
                                      <label htmlFor={`af-host-service-secret-${host.id}`}>
                                        {t("credentials.serviceSecret")}
                                      </label>
                                      <input
                                        id={`af-host-service-secret-${host.id}`}
                                        className="pf-input"
                                        type="password"
                                        autoComplete="off"
                                        value={hostCred.service_secret}
                                        onChange={(e) =>
                                          setHostCred((prev) => ({ ...prev, service_secret: e.target.value }))
                                        }
                                      />
                                    </div>
                                  </div>
                                  <div className="pf-audit-flow-hostcred__actions">
                                    <Button
                                      type="button"
                                      variant="secondary"
                                      className="pf-btn--sm"
                                      onClick={() => {
                                        setAddingCredHostId(null);
                                        setHostCred(emptyCred());
                                      }}
                                    >
                                      {t("common.cancel")}
                                    </Button>
                                    <Button
                                      type="submit"
                                      className="pf-btn--sm"
                                      disabled={
                                        !hostCred.username.trim() ||
                                        !hostCred.secret.trim() ||
                                        addHostCredMutation.isPending
                                      }
                                    >
                                      {t("auditFlow.addCredentialHost")}
                                    </Button>
                                  </div>
                                </form>
                              </td>
                            </tr>
                          ) : null}
                          </Fragment>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                </section>
              </>
            )}
          </div>
          {(step === "review" || step === "checks") && (
            <div className="pf-audit-flow-footer">
              {step === "checks" ? (
                <span className="pf-audit-flow-footer__note pf-audit-flow-footer__live">
                  <span className="pf-audit-flow-live__dot" aria-hidden="true" />
                  {t("auditFlow.running")}
                </span>
              ) : (
                <>
                  <span className="pf-audit-flow-footer__note">
                    {t("auditFlow.reviewSelected", { count: reviewStats.selected })}
                  </span>
                  <div className="pf-audit-flow-footer__actions">
                    <Button type="button" variant="secondary" onClick={() => goToStep("setup")}>
                      {t("auditFlow.changeSettings")}
                    </Button>
                    <Button
                      onClick={() => executeMutation.mutate()}
                      disabled={executeMutation.isPending || !canExecute || !hostsReadyToExecute}
                      title={!canExecute ? t("common.demoActionDisabled") : undefined}
                    >
                      {t("auditFlow.execute")}
                    </Button>
                  </div>
                </>
              )}
            </div>
          )}
        </Panel>
      )}

      {run && step !== "setup" && (
        <Panel title={t("auditFlow.liveLogs")}>
          <AuditFlowLogs runId={run.id} runStatus={run.status} />
        </Panel>
      )}

      <Panel title={t("auditFlow.recent")} className="pf-panel--muted">
        {(runsQuery.data ?? []).length === 0 ? (
          <p className="pf-form__hint">{t("auditFlow.noRuns")}</p>
        ) : (
          <ul className="pf-audit-flow-recent">
            {(runsQuery.data ?? []).map((item: AuditFlowRun) => (
              <li key={item.id} className="pf-audit-flow-recent__row">
                <button
                  type="button"
                  className={`pf-audit-flow-recent__item${item.id === activeId ? " is-active" : ""}`}
                  onClick={() => {
                    setViewedStep(null);
                    setActiveId(item.id);
                  }}
                >
                  <span className="pf-audit-flow-recent__id">#{item.id}</span>
                  <Badge variant={runStatusVariant(item.status)}>{runStatusLabel(item.status)}</Badge>
                  <span className="pf-audit-flow-recent__meta">
                    {t("auditFlow.hostsFoundCount", { count: item.hosts_found })}
                  </span>
                </button>
                <button
                  type="button"
                  className="pf-audit-flow-recent__delete"
                  aria-label={t("auditFlow.deleteRun")}
                  title={t("auditFlow.deleteRun")}
                  disabled={ACTIVE.has(item.status) || deleteMutation.isPending}
                  onClick={(event) => {
                    event.stopPropagation();
                    void deleteRun(item.id);
                  }}
                >
                  <IconTrash />
                </button>
              </li>
            ))}
          </ul>
        )}
      </Panel>
    </div>
  );
}
