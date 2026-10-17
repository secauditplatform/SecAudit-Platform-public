import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "react-router-dom";
import {
  api,
  type AagArtifact,
  type AagConnection,
  type AagConnectionInput,
  type AagPackageDraft,
  type AagProvider,
  type AagStatus,
  type AagExplainCandidate,
  type AagExplainSection,
  type AagTaskKind,
  type JobRun,
} from "../../api/client";
import { useAuth } from "../../auth/AuthProvider";
import { Badge } from "../../components/ui/Badge";
import { Button } from "../../components/ui/Button";
import { useConfirm } from "../../components/ui/ConfirmDialog";
import { EmptyState } from "../../components/ui/EmptyState";
import { PageHeader } from "../../components/ui/PageHeader";
import { Panel } from "../../components/ui/Panel";
import { Pagination } from "../../components/ui/Pagination";
import { QueryErrorState } from "../../components/ui/QueryErrorState";
import { Spinner } from "../../components/ui/Spinner";
import { useToast } from "../../components/ui/Toast";
import { useTranslation } from "../../i18n/I18nProvider";
import { checkStatusVariant, runStatusLabel, runStatusVariant } from "../../utils/statusVariant";

const demoMode = import.meta.env.VITE_DEMO_MODE === "true";

function useAagStatus() {
  return useQuery({
    queryKey: ["aagStatus"],
    queryFn: api.aagStatus,
    retry: false,
  });
}

function providerSignature(status: AagStatus, t: (key: string) => string): string {
  if (!status.enabled || status.provider === "none") return t("aag.providerNone");
  const model = status.model_name ? `, ${status.model_name}` : "";
  if (status.provider === "internal") return `${t("aag.providerInternal")}${model}`;
  return `${t("aag.providerExternal")}${model}`;
}

/** Closed-task notice: contour off, or enabled but the task screen lands later (AAG-1+). */
export function AagDisabledNotice({ status }: { status: AagStatus }) {
  const { t } = useTranslation();
  if (!status.enabled) {
    return (
      <EmptyState
        title={t("aag.disabledTitle")}
        description={t("aag.disabledBody")}
      />
    );
  }
  return (
    <EmptyState
      title={t("aag.comingSoonTitle")}
      description={`${t("aag.comingSoonBody")} · ${providerSignature(status, t)}`}
    />
  );
}

function destinationHost(url: string | null | undefined): string | null {
  const trimmed = (url ?? "").trim();
  if (!trimmed) return null;
  try {
    return new URL(trimmed).hostname || null;
  } catch {
    return null;
  }
}

function taskStatusLabel(status: string, t: (key: string) => string): string {
  if (status === "completed") return t("aag.taskStatusCompleted");
  if (status === "failed") return t("aag.taskStatusFailed");
  return t("aag.taskStatusPending");
}

function aagErrorText(message: string, t: (key: string) => string): string {
  if (/CIS|STIG|FSTEK|ФСТЭК/i.test(message)) return t("aag.officialPackage");
  if (/profile name is required/i.test(message)) return t("aag.profileNameRequired");
  if (/os or software name/i.test(message)) return t("aag.targetNameRequired");
  if (/did not describe any checks/i.test(message)) return t("aag.generateInvalid");
  return message;
}

function leadKey(kind: AagTaskKind): string {
  if (kind === "explain") return "aag.explainLead";
  return "aag.generateLead";
}

function callKindLabel(kind: string | null | undefined, t: (key: string) => string): string {
  if (kind === "test") return t("aag.callKindTest");
  if (kind === "explain") return t("nav.aagExplain");
  if (kind === "brief") return t("nav.aagBrief");
  if (kind === "search") return t("nav.aagSearch");
  if (kind === "draft") return t("nav.aagDrafts");
  if (kind === "generate") return t("nav.aagGenerate");
  return t("common.dash");
}

function callDraftLabel(draft: string | null | undefined, t: (key: string) => string): string {
  if (draft === "waiver") return t("aag.draftWaiver");
  if (draft === "remediation_plan") return t("aag.draftPlan");
  if (draft === "audit_flow") return t("aag.draftAuditFlow");
  if (draft === "network") return t("aag.draftNetwork");
  if (draft === "playbook") return t("aag.draftPlaybook");
  if (draft === "mapping") return t("aag.draftMapping");
  return t("common.dash");
}

function callErrorLabel(code: string | null | undefined, t: (key: string) => string): string {
  if (!code) return t("common.dash");
  if (/^http_\d{3}$/.test(code)) return `HTTP ${code.slice(5)}`;
  const key = `aag.callError_${code}`;
  const label = t(key);
  return label === key ? code : label;
}

function callDurationLabel(ms: number | null | undefined, t: (key: string) => string): string {
  if (ms == null) return t("common.dash");
  const seconds = ms / 1000;
  const text = seconds >= 10 ? String(Math.round(seconds)) : seconds.toFixed(1);
  return `${text} ${t("common.secondsShort")}`;
}

function taskStatusVariant(status: string): "success" | "danger" | "warning" {
  if (status === "completed") return "success";
  if (status === "failed") return "danger";
  return "warning";
}

function packageFromArtifact(item: AagArtifact): {
  description: Record<string, unknown>;
  rules: Record<string, unknown>;
  scriptName: string;
  script: string;
} | null {
  const stored = item.meta_json?.files;
  const storedView =
    stored && stored.description && typeof stored.description === "object"
      ? {
          description: stored.description,
          rules: stored.rules ?? {},
          scriptName: stored.script_name ?? "",
          script: stored.script ?? "",
        }
      : null;
  if (storedView && packageRuleRows(storedView.rules).length > 0) return storedView;
  if (!item.response_text) return storedView;
  const parsed = parsePackageObject(item.response_text);
  if (!parsed) return storedView;
  const description =
    parsed.description && typeof parsed.description === "object" && !Array.isArray(parsed.description)
      ? (parsed.description as Record<string, unknown>)
      : null;
  if (!description) return storedView;
  const rulesRaw = parsed.rules;
  const rules =
    rulesRaw && typeof rulesRaw === "object" && !Array.isArray(rulesRaw)
      ? (rulesRaw as Record<string, unknown>)
      : Array.isArray(rulesRaw)
        ? { rules: rulesRaw }
        : {};
  return {
    description,
    rules,
    scriptName: typeof parsed.script_name === "string" ? parsed.script_name : "",
    script: typeof parsed.script === "string" ? parsed.script : "",
  };
}

function packageSpec(description: Record<string, unknown> | null) {
  const text = (value: unknown) => (typeof value === "string" ? value.trim() : "");
  const block = (key: "os" | "software") => {
    const value = description?.[key];
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    return value as Record<string, unknown>;
  };
  const osBlock = description ? block("os") : null;
  const softwareBlock = description ? block("software") : null;
  const target = osBlock ?? softwareBlock;
  return {
    profileName: text(description?.profile_name),
    version: text(description?.version),
    overview: text(description?.overview),
    purpose: text(description?.purpose),
    targetKind: osBlock ? "os" : softwareBlock ? "software" : "",
    targetName: text(target?.name),
    targetVendor: text(target?.vendor),
    targetVersion: text(target?.version),
  };
}

function PackageMetaChips({
  target,
  version,
  ruleCount,
  scriptName,
}: {
  target: string;
  version: string;
  ruleCount: number;
  scriptName: string;
}) {
  const { t } = useTranslation();
  const chips = [target, version, t("aag.packageRulesCount", { count: ruleCount }), scriptName].filter(Boolean);
  if (chips.length === 0) return null;
  return (
    <div className="pf-aag-result__chips">
      {chips.map((chip, index) => (
        <span key={`${chip}-${index}`}>{chip}</span>
      ))}
    </div>
  );
}

function PackageTabs({
  fileTab,
  onChange,
  ruleCount,
}: {
  fileTab: "description" | "rules" | "script";
  onChange: (tab: "description" | "rules" | "script") => void;
  ruleCount: number;
}) {
  const { t } = useTranslation();
  const tabs = [
    { id: "description" as const, label: t("aag.packageTabDescription") },
    { id: "rules" as const, label: t("aag.packageRules"), count: ruleCount },
    { id: "script" as const, label: t("aag.profileScript") },
  ];
  return (
    <div className="pf-aag-package__tabs" role="tablist">
      {tabs.map((tab) => (
        <button
          key={tab.id}
          type="button"
          role="tab"
          className={`pf-aag-package__tab${fileTab === tab.id ? " is-active" : ""}`}
          aria-selected={fileTab === tab.id}
          onClick={() => onChange(tab.id)}
        >
          {tab.label}
          {tab.count != null ? <span className="pf-aag-package__tab-count">{tab.count}</span> : null}
        </button>
      ))}
    </div>
  );
}

function PackageDescriptionView({
  description,
  showName,
}: {
  description: Record<string, unknown> | null;
  showName?: boolean;
}) {
  const { t } = useTranslation();
  const spec = packageSpec(description);
  const facts: { label: string; value: string }[] = [];
  if (showName) {
    facts.push({ label: t("aag.profileName"), value: spec.profileName || t("common.dash") });
  }
  facts.push({ label: t("aag.profileVersion"), value: spec.version || t("common.dash") });
  if (spec.targetKind) {
    facts.push({
      label: spec.targetKind === "os" ? t("aag.profileTargetOs") : t("aag.profileTargetSoftware"),
      value: spec.targetName || t("common.dash"),
    });
  }
  if (spec.targetVendor) facts.push({ label: t("aag.profileTargetVendor"), value: spec.targetVendor });
  if (spec.targetVersion) facts.push({ label: t("aag.profileTargetVersion"), value: spec.targetVersion });
  return (
    <div className="pf-aag-package__sheet">
      <dl className="pf-aag-package__facts">
        {facts.map((fact) => (
          <div key={fact.label} className="pf-aag-package__fact">
            <dt>{fact.label}</dt>
            <dd>{fact.value}</dd>
          </div>
        ))}
      </dl>
      {spec.overview ? (
        <div className="pf-aag-package__prose">
          <span>{t("aag.profileOverview")}</span>
          <p>{spec.overview}</p>
        </div>
      ) : null}
      {spec.purpose ? (
        <div className="pf-aag-package__prose">
          <span>{t("aag.profilePurpose")}</span>
          <p>{spec.purpose}</p>
        </div>
      ) : null}
    </div>
  );
}

function PackageRulesView({ rules }: { rules: Record<string, unknown> | null }) {
  const { t } = useTranslation();
  const ruleRows = packageRuleRows(rules);
  if (ruleRows.length === 0) return <p className="pf-table__muted">{t("aag.packageNoRules")}</p>;
  return (
    <div className="pf-aag-package__rules">
      {ruleRows.map((rule) => (
        <article key={rule.id || rule.title} className="pf-aag-package__rule">
          <header className="pf-aag-package__rule-head">
            <span className="pf-aag-package__rule-id">{rule.id || t("common.dash")}</span>
            {rule.criticality ? (
              <Badge variant={packageCriticalityVariant(rule.criticality)} literal>
                {rule.criticality}
              </Badge>
            ) : null}
          </header>
          <p className="pf-aag-package__rule-title">{rule.title || t("common.dash")}</p>
          {rule.explanation ? <p className="pf-aag-package__rule-text">{rule.explanation}</p> : null}
        </article>
      ))}
    </div>
  );
}

function PackageScriptView({ scriptName, script }: { scriptName: string; script: string }) {
  return (
    <div className="pf-aag-package__codeblock">
      {scriptName ? <div className="pf-aag-package__codebar">{scriptName}</div> : null}
      <pre className="pf-aag-package__code">{script}</pre>
    </div>
  );
}

function PackageFileView({
  description,
  rules,
  scriptName,
  script,
}: {
  description: Record<string, unknown> | null;
  rules: Record<string, unknown> | null;
  scriptName: string;
  script: string;
}) {
  const [fileTab, setFileTab] = useState<"description" | "rules" | "script">("description");
  const ruleCount = packageRuleRows(rules).length;
  return (
    <div className="pf-aag-package__stage">
      <PackageTabs fileTab={fileTab} onChange={setFileTab} ruleCount={ruleCount} />
      <div className="pf-aag-package__stage-body">
        {fileTab === "description" ? <PackageDescriptionView description={description} showName /> : null}
        {fileTab === "rules" ? <PackageRulesView rules={rules} /> : null}
        {fileTab === "script" ? <PackageScriptView scriptName={scriptName} script={script} /> : null}
      </div>
    </div>
  );
}

function explainTone(status: string): string {
  const tone = status.trim().toLowerCase();
  if (tone === "pass" || tone === "fail" || tone === "error" || tone === "skip") return tone;
  return "neutral";
}

function ExplainRecorded({ text, confirmed }: { text: string; confirmed: boolean }) {
  const { t } = useTranslation();
  const parts = text.split(/(run_id=\d+|rule=RULE\d+)/g);
  return (
    <p className="pf-aag-explain__text">
      {parts.map((part, index) =>
        /^(?:run_id=\d+|rule=RULE\d+)$/.test(part) ? (
          <code key={`${part}-${index}`} className="pf-aag-explain__cite">
            {part}
          </code>
        ) : (
          <span key={`${part}-${index}`}>{part}</span>
        ),
      )}
      {!confirmed ? <span className="pf-aag-result__mark"> {t("aag.uncited")}</span> : null}
    </p>
  );
}

function ExplainCheck({ section }: { section: AagExplainSection }) {
  const { t } = useTranslation();
  const status = section.status.trim();
  const tone = explainTone(status);
  return (
    <section className={`pf-aag-explain__check pf-aag-explain__check--${tone}`}>
      <header className="pf-aag-explain__head">
        <div className="pf-aag-explain__identity">
          <p className="pf-aag-explain__rule">{section.rule || t("common.dash")}</p>
          {section.host ? <p className="pf-aag-explain__host">{section.host}</p> : null}
        </div>
        {status ? (
          <Badge variant={checkStatusVariant(tone)} literal>
            {status.toUpperCase()}
          </Badge>
        ) : null}
      </header>
      {section.what ? (
        <div className="pf-aag-explain__lead">
          <p className="pf-aag-explain__label">{t("aag.explainWhat")}</p>
          <p className="pf-aag-explain__text">{section.what}</p>
        </div>
      ) : null}
      {section.checked || section.did ? (
        <div className="pf-aag-explain__grid">
          {section.checked ? (
            <div className={`pf-aag-explain__fact${section.did ? "" : " pf-aag-explain__fact--wide"}`}>
              <p className="pf-aag-explain__label">{t("aag.explainChecked")}</p>
              <p className="pf-aag-explain__text">{section.checked}</p>
            </div>
          ) : null}
          {section.did ? (
            <div className={`pf-aag-explain__fact${section.checked ? "" : " pf-aag-explain__fact--wide"}`}>
              <p className="pf-aag-explain__label">{t("aag.explainDid")}</p>
              <ExplainRecorded text={section.did} confirmed={section.confirmed} />
            </div>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}

function AagResultCard({
  item,
  startCollapsed,
  onDelete,
  deletingId,
  onRetry,
  retryingId,
}: {
  item: AagArtifact;
  startCollapsed: boolean;
  onDelete?: (item: AagArtifact) => void;
  deletingId?: number;
  onRetry?: (item: AagArtifact) => void;
  retryingId?: number;
}) {
  const { t } = useTranslation();
  const signature =
    item.provider === "internal"
      ? [t("aag.providerInternal"), item.model_name].filter(Boolean).join(" · ")
      : [t("aag.providerExternal"), item.target_host, item.model_name].filter(Boolean).join(" · ");
  const filterEntries = Object.entries(item.host_filter ?? {}).filter(
    ([, value]) => value !== undefined && value !== null && value !== "",
  );
  const paragraphs = item.paragraphs ?? [];
  const sections = item.explain_sections ?? [];
  const packageView = item.kind === "generate" ? packageFromArtifact(item) : null;
  const packageMeta = packageView ? packageSpec(packageView.description) : null;
  const profileTitle = packageMeta?.profileName ?? "";
  const hasBody =
    sections.length > 0 ||
    paragraphs.length > 0 ||
    Boolean(packageView) ||
    Boolean(item.response_text) ||
    filterEntries.length > 0 ||
    Boolean(item.error_message);
  const canCollapse = item.status === "completed" && hasBody;
  const [collapsed, setCollapsed] = useState(startCollapsed && canCollapse);
  const hidden = canCollapse && collapsed;

  return (
    <article
      className={`pf-aag-result${item.status === "failed" ? " pf-aag-result--failed" : ""}${
        hidden ? " pf-aag-result--collapsed" : ""
      }`}
    >
      <header className="pf-aag-result__head">
        {canCollapse ? (
          <button
            type="button"
            className="pf-aag-result__toggle"
            aria-expanded={!hidden}
            aria-label={hidden ? t("common.expandPanel") : t("common.collapsePanel")}
            onClick={() => setCollapsed((current) => !current)}
          >
            <span className="pf-aag-result__chevron" aria-hidden />
          </button>
        ) : null}
        <div className="pf-aag-result__meta">
          <p className="pf-aag-result__title">
            {profileTitle || signature}
            {!profileTitle && item.target_host && item.provider === "internal" ? ` · ${item.target_host}` : ""}
          </p>
          <p className="pf-aag-result__aside">
            {profileTitle ? `${signature} · ` : ""}
            {item.in_perimeter ? t("aag.perimeter") : t("aag.outsidePerimeter")}
          </p>
          {packageView && packageMeta ? (
            <PackageMetaChips
              target={[packageMeta.targetName, packageMeta.targetVersion].filter(Boolean).join(" ")}
              version={packageMeta.version}
              ruleCount={packageRuleRows(packageView.rules).length}
              scriptName={packageView.scriptName}
            />
          ) : null}
        </div>
        <div className="pf-aag-result__tools">
          <Badge variant={taskStatusVariant(item.status)} literal>
            {taskStatusLabel(item.status, t)}
          </Badge>
          {onRetry && (item.kind === "explain" || item.kind === "generate") && item.status === "failed" ? (
            <Button
              variant="secondary"
              className="pf-btn--sm"
              loading={retryingId === item.id}
              onClick={() => onRetry(item)}
            >
              {t("aag.retryTask")}
            </Button>
          ) : null}
          {onDelete ? (
            <Button
              variant="danger-secondary"
              className="pf-btn--sm"
              loading={deletingId === item.id}
              onClick={() => onDelete(item)}
            >
              {t("common.delete")}
            </Button>
          ) : null}
        </div>
      </header>
      {!hidden && hasBody ? (
              <div className="pf-aag-result__body">
                {packageView ? (
                  <PackageFileView
                    description={packageView.description}
                    rules={packageView.rules}
                    scriptName={packageView.scriptName}
                    script={packageView.script}
                  />
                ) : null}
                {!packageView && sections.length > 0 ? (
                  <div className="pf-aag-explain">
                    {sections.map((section, index) => (
                      <ExplainCheck key={`${item.id}-${section.rule}-${index}`} section={section} />
                    ))}
                  </div>
                ) : null}
                {!packageView && sections.length === 0
                  ? paragraphs.map((paragraph, index) => (
                      <p key={`${item.id}-${index}`}>
                        {paragraph.text}{" "}
                        {!paragraph.confirmed && item.kind === "explain" ? (
                          <span className="pf-aag-result__mark">{t("aag.uncited")}</span>
                        ) : null}
                      </p>
                    ))
                  : null}
                {!packageView && sections.length === 0 && paragraphs.length === 0 && item.response_text ? (
                  <p>{item.response_text}</p>
                ) : null}
                {filterEntries.length > 0 ? (
                  <dl className="pf-aag-result__filter">
                    <dt>{t("aag.filterTitle")}</dt>
                    {filterEntries.map(([key, value]) => (
                      <dd key={key}>
                        <span>{key}</span> {String(value)}
                      </dd>
                    ))}
                  </dl>
                ) : null}
                {item.error_message ? (
                  <p className="pf-aag-result__error">{aagErrorText(item.error_message, t)}</p>
                ) : null}
              </div>
      ) : null}
    </article>
  );
}

function AagArtifactList({
  items,
  onDelete,
  deletingId,
  onRetry,
  retryingId,
}: {
  items: AagArtifact[];
  onDelete?: (item: AagArtifact) => void;
  deletingId?: number;
  onRetry?: (item: AagArtifact) => void;
  retryingId?: number;
}) {
  let seenCompleted = false;
  return (
    <div className="pf-aag-results">
      {items.map((item) => {
        const startCollapsed = item.status === "completed" && seenCompleted;
        if (item.status === "completed") seenCompleted = true;
        return (
          <AagResultCard
            key={item.id}
            item={item}
            startCollapsed={startCollapsed}
            onDelete={onDelete}
            deletingId={deletingId}
            onRetry={onRetry}
            retryingId={retryingId}
          />
        );
      })}
    </div>
  );
}

const EXPLAIN_LIMIT = 25;
const AAG_PAGE_SIZE = 25;

function explainLoadError(message: string, t: (key: string) => string): string {
  if (/not completed/i.test(message)) return t("aag.explainRunNotCompleted");
  if (/not found/i.test(message)) return t("aag.explainRunMissing");
  return message || t("aag.taskFailed");
}

function ExplainRequest({
  runInput,
  onRunInput,
  selectedChecks,
  onSelectedChecks,
  candidates,
  fetching,
  errorMessage,
  ready,
  runId,
}: {
  runInput: string;
  onRunInput: (value: string) => void;
  selectedChecks: number[];
  onSelectedChecks: (next: number[] | ((current: number[]) => number[])) => void;
  candidates: AagExplainCandidate[];
  fetching: boolean;
  errorMessage: string | null;
  ready: boolean;
  runId: number | null;
}) {
  const { t, dateLocale } = useTranslation();
  const [jobSearch, setJobSearch] = useState("");
  const [profileId, setProfileId] = useState("");
  const [runStatus, setRunStatus] = useState("completed");
  const [checkQuery, setCheckQuery] = useState("");
  const [checkStatus, setCheckStatus] = useState("all");
  const [hostFilter, setHostFilter] = useState("");
  const [runsPage, setRunsPage] = useState(1);
  const [findingsPage, setFindingsPage] = useState(1);
  useEffect(() => {
    setHostFilter("");
    setFindingsPage(1);
  }, [runId]);
  useEffect(() => {
    setRunsPage(1);
  }, [jobSearch, profileId, runStatus]);
  useEffect(() => {
    setFindingsPage(1);
  }, [checkQuery, checkStatus, hostFilter]);
  const jobsQuery = useQuery({
    queryKey: ["jobs", "aag-explain"],
    queryFn: () => api.jobs(),
    enabled: ready,
    retry: false,
  });
  const profilesQuery = useQuery({
    queryKey: ["profiles", "aag-explain"],
    queryFn: () => api.profiles(),
    enabled: ready,
    retry: false,
  });
  const runsQuery = useQuery({
    queryKey: ["jobRuns", "aag-explain"],
    queryFn: () => api.jobRuns({ limit: 200 }),
    enabled: ready,
    retry: false,
  });
  const jobs = jobsQuery.data ?? [];
  const profiles = profilesQuery.data ?? [];
  const jobById = useMemo(() => new Map(jobs.map((job) => [job.id, job])), [jobs]);
  const profileById = useMemo(() => new Map(profiles.map((profile) => [profile.id, profile])), [profiles]);
  const filteredRuns = useMemo(() => {
    const query = jobSearch.trim().toLowerCase();
    const wantedProfile = profileId ? Number(profileId) : null;
    return (runsQuery.data?.items ?? []).filter((run) => {
      const job = jobById.get(run.job_id);
      if (runStatus !== "all" && run.status !== runStatus) return false;
      if (wantedProfile != null && job?.profile_id !== wantedProfile) return false;
      if (!query) return true;
      const profileName =
        job?.profile_id != null ? (profileById.get(job.profile_id)?.profile_name ?? "") : "";
      return (
        (job?.name ?? "").toLowerCase().includes(query) ||
        profileName.toLowerCase().includes(query) ||
        String(run.id).includes(query)
      );
    });
  }, [jobById, jobSearch, profileById, profileId, runStatus, runsQuery.data?.items]);
  const runsPageCount = Math.max(1, Math.ceil(filteredRuns.length / AAG_PAGE_SIZE));
  const safeRunsPage = Math.min(runsPage, runsPageCount);
  const pagedRuns = filteredRuns.slice((safeRunsPage - 1) * AAG_PAGE_SIZE, safeRunsPage * AAG_PAGE_SIZE);
  const hosts = useMemo(() => {
    const names = new Set<string>();
    for (const row of candidates) {
      const name = row.host_name || String(row.host_id);
      if (name) names.add(name);
    }
    return [...names].sort((left, right) => left.localeCompare(right));
  }, [candidates]);
  const visible = useMemo(() => {
    const query = checkQuery.trim().toLowerCase();
    return candidates.filter((row) => {
      if (checkStatus !== "all" && row.status.toLowerCase() !== checkStatus) return false;
      const hostName = row.host_name || String(row.host_id);
      if (hostFilter && hostName !== hostFilter) return false;
      if (!query) return true;
      return [row.rule_tech_name, row.rule_title, row.host_name, row.message].some((value) =>
        (value ?? "").toLowerCase().includes(query),
      );
    });
  }, [candidates, checkQuery, checkStatus, hostFilter]);
  const findingsPageCount = Math.max(1, Math.ceil(visible.length / AAG_PAGE_SIZE));
  const safeFindingsPage = Math.min(findingsPage, findingsPageCount);
  const pagedFindings = visible.slice((safeFindingsPage - 1) * AAG_PAGE_SIZE, safeFindingsPage * AAG_PAGE_SIZE);
  const pageIds = pagedFindings.map((row) => row.id);
  const pickedPage = pagedFindings.filter((row) => selectedChecks.includes(row.id)).length;
  const visibleIds = visible.map((row) => row.id);
  const pickedVisible = visible.filter((row) => selectedChecks.includes(row.id)).length;

  function chooseRun(run: JobRun) {
    if (String(run.id) !== runInput.trim()) onSelectedChecks([]);
    onRunInput(String(run.id));
  }

  return (
    <>
      <div className="pf-aag-filters">
        <div className="pf-form__group">
          <label htmlFor="aag-job-search">{t("aag.explainJobSearch")}</label>
          <input
            id="aag-job-search"
            className="pf-input"
            value={jobSearch}
            placeholder={t("aag.explainJobPlaceholder")}
            onChange={(event) => setJobSearch(event.target.value)}
          />
        </div>
        <div className="pf-form__group">
          <label htmlFor="aag-profile-filter">{t("reports.profile")}</label>
          <select
            id="aag-profile-filter"
            className="pf-select"
            value={profileId}
            onChange={(event) => setProfileId(event.target.value)}
          >
            <option value="">{t("reports.allProfiles")}</option>
            {[...profiles]
              .sort((left, right) => left.profile_name.localeCompare(right.profile_name))
              .map((profile) => (
                <option key={profile.id} value={profile.id}>
                  {profile.profile_name}
                </option>
              ))}
          </select>
        </div>
        <div className="pf-form__group">
          <label htmlFor="aag-run-status">{t("aag.explainRunStatus")}</label>
          <select
            id="aag-run-status"
            className="pf-select"
            value={runStatus}
            onChange={(event) => setRunStatus(event.target.value)}
          >
            <option value="all">{t("aag.explainRunAny")}</option>
            {(["completed", "failed", "running", "pending", "cancelled"] as const).map((status) => (
              <option key={status} value={status}>
                {runStatusLabel(t, status)}
              </option>
            ))}
          </select>
        </div>
        <div className="pf-form__group pf-aag-run">
          <label htmlFor="aag-run-explain">{t("jobs.runId")}</label>
          <input
            id="aag-run-explain"
            className="pf-input"
            value={runInput}
            onChange={(event) => {
              if (event.target.value.trim() !== runInput.trim()) onSelectedChecks([]);
              onRunInput(event.target.value);
            }}
          />
        </div>
      </div>
      <div className="pf-form__group">
        <div className="pf-aag-findings__toolbar">
          <span className="pf-aag-findings__heading">{t("aag.explainPickRun")}</span>
        </div>
        {runsQuery.isPending ? (
          <div className="pf-aag-findings pf-aag-findings--state">
            <Spinner />
          </div>
        ) : pagedRuns.length > 0 ? (
          <div className="pf-aag-runs" role="listbox" aria-label={t("aag.explainPickRun")}>
            <div className="pf-aag-runs__head" aria-hidden>
              <span>{t("jobs.runId")}</span>
              <span>{t("aag.explainJobSearch")}</span>
              <span>{t("reports.profile")}</span>
              <span>{t("common.status")}</span>
              <span className="pf-aag-runs__time">{t("jobs.finished")}</span>
            </div>
            {pagedRuns.map((run) => {
              const job = jobById.get(run.job_id);
              const profileName =
                job?.profile_id != null ? profileById.get(job.profile_id)?.profile_name : "";
              const stamp = run.finished_at || run.started_at || run.created_at;
              const when = stamp
                ? new Date(stamp).toLocaleString(dateLocale, {
                    year: "numeric",
                    month: "short",
                    day: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                  })
                : "";
              const selected = runInput.trim() === String(run.id);
              const jobName = job?.name || t("common.dash");
              return (
                <button
                  key={run.id}
                  type="button"
                  role="option"
                  aria-selected={selected}
                  className={`pf-aag-runs__row${selected ? " is-selected" : ""}`}
                  onClick={() => chooseRun(run)}
                >
                  <span className="pf-aag-runs__id">#{run.id}</span>
                  <span className="pf-aag-runs__name" title={jobName}>
                    {jobName}
                  </span>
                  <span className="pf-aag-runs__profile" title={profileName || undefined}>
                    {profileName || t("common.dash")}
                  </span>
                  <span className="pf-aag-runs__status">
                    <Badge variant={runStatusVariant(run.status)} literal>
                      {runStatusLabel(t, run.status)}
                    </Badge>
                  </span>
                  <span className="pf-aag-runs__time">{when || t("common.dash")}</span>
                </button>
              );
            })}
          </div>
        ) : (
          <p className="pf-table__muted">{t("aag.explainNoRuns")}</p>
        )}
        <Pagination
          page={safeRunsPage}
          pageSize={AAG_PAGE_SIZE}
          total={filteredRuns.length}
          onPageChange={setRunsPage}
        />
      </div>
      <div className="pf-form__group">
        <div className="pf-aag-findings__toolbar">
          <span className="pf-aag-findings__heading">{t("aag.selectFindings")}</span>
          <span className="pf-aag-findings__count">
            {selectedChecks.length > 0 ? (
              <span className="pf-form__hint">
                {t("hostSelection.selected", { count: selectedChecks.length })}
                {selectedChecks.length >= EXPLAIN_LIMIT
                  ? ` · ${t("aag.explainSelectionLimit", { count: EXPLAIN_LIMIT })}`
                  : ""}
              </span>
            ) : null}
            {visible.length > 0 ? (
              <span className="pf-aag-findings__links">
                <Button
                  variant="link"
                  className="pf-btn--sm"
                  type="button"
                  onClick={() =>
                    onSelectedChecks((current) => {
                      const kept = current.filter((id) => !visibleIds.includes(id));
                      const room = EXPLAIN_LIMIT - kept.length;
                      return [...kept, ...visibleIds.filter((id) => !kept.includes(id)).slice(0, Math.max(0, room))];
                    })
                  }
                >
                  {t("hostSelection.selectAll")}
                </Button>
                <Button
                  variant="link"
                  className="pf-btn--sm"
                  type="button"
                  disabled={pickedVisible === 0}
                  onClick={() => onSelectedChecks((current) => current.filter((id) => !visibleIds.includes(id)))}
                >
                  {t("hostSelection.clear")}
                </Button>
              </span>
            ) : null}
          </span>
        </div>
        <div className="pf-aag-check-filters">
          <div className="pf-form__group">
            <label htmlFor="aag-check-search">{t("aag.explainCheckSearch")}</label>
            <input
              id="aag-check-search"
              className="pf-input"
              value={checkQuery}
              placeholder={t("aag.explainCheckPlaceholder")}
              onChange={(event) => setCheckQuery(event.target.value)}
            />
          </div>
          <div className="pf-form__group">
            <label htmlFor="aag-check-status">{t("aag.explainCheckStatus")}</label>
            <select
              id="aag-check-status"
              className="pf-select"
              value={checkStatus}
              onChange={(event) => setCheckStatus(event.target.value)}
            >
              <option value="all">{t("aag.explainStatusAll")}</option>
              {(["pass", "fail", "error", "skip"] as const).map((status) => (
                <option key={status} value={status}>
                  {runStatusLabel(t, status)}
                </option>
              ))}
            </select>
          </div>
          <div className="pf-form__group">
            <label htmlFor="aag-check-host">{t("aag.explainHost")}</label>
            <select
              id="aag-check-host"
              className="pf-select"
              value={hostFilter}
              onChange={(event) => setHostFilter(event.target.value)}
            >
              <option value="">{t("aag.explainHostAll")}</option>
              {hosts.map((host) => (
                <option key={host} value={host}>
                  {host}
                </option>
              ))}
            </select>
          </div>
        </div>
        {fetching ? (
          <div className="pf-aag-findings pf-aag-findings--state">
            <Spinner />
          </div>
        ) : visible.length > 0 ? (
          <div className="pf-aag-findings" role="group" aria-label={t("aag.selectFindings")}>
            <div className="pf-aag-findings__head">
              <input
                type="checkbox"
                className="pf-checkbox-control"
                aria-label={t("hostSelection.selectAll")}
                checked={pagedFindings.length > 0 && pickedPage === pagedFindings.length}
                ref={(node) => {
                  if (!node) return;
                  node.indeterminate = pickedPage > 0 && pickedPage < pagedFindings.length;
                }}
                onChange={(event) => {
                  if (event.target.checked) {
                    onSelectedChecks((current) => {
                      const kept = current.filter((id) => !pageIds.includes(id));
                      const room = EXPLAIN_LIMIT - kept.length;
                      return [...kept, ...pageIds.filter((id) => !kept.includes(id)).slice(0, Math.max(0, room))];
                    });
                    return;
                  }
                  onSelectedChecks((current) => current.filter((id) => !pageIds.includes(id)));
                }}
              />
              <span className="pf-aag-findings__head-title">
                {t("reports.rule")} · {t("reports.host")}
              </span>
              <span className="pf-aag-findings__head-status">{t("common.status")}</span>
            </div>
            {pagedFindings.map((row) => {
              const selected = selectedChecks.includes(row.id);
              const blocked = !selected && selectedChecks.length >= EXPLAIN_LIMIT;
              return (
                <label
                  key={row.id}
                  className={`pf-aag-findings__row${selected ? " pf-aag-findings__row--selected" : ""}`}
                >
                  <input
                    type="checkbox"
                    className="pf-checkbox-control pf-aag-findings__check"
                    checked={selected}
                    disabled={blocked}
                    onChange={(event) =>
                      onSelectedChecks((current) => {
                        if (!event.target.checked) return current.filter((id) => id !== row.id);
                        if (current.includes(row.id) || current.length >= EXPLAIN_LIMIT) return current;
                        return [...current, row.id];
                      })
                    }
                  />
                  <span className="pf-aag-findings__main">
                    <span className="pf-aag-findings__rule">{row.rule_tech_name}</span>
                    {row.rule_title ? (
                      <span className="pf-aag-findings__name" title={row.rule_title}>
                        {row.rule_title}
                      </span>
                    ) : null}
                    <span className="pf-aag-findings__host">{row.host_name ?? row.host_id}</span>
                    {row.has_remediation ? (
                      <span className="pf-aag-findings__note">{t("aag.hasRemediation")}</span>
                    ) : null}
                  </span>
                  <span className="pf-aag-findings__status">
                    <Badge variant={checkStatusVariant(row.status)} literal>
                      {row.status}
                    </Badge>
                  </span>
                </label>
              );
            })}
          </div>
        ) : null}
        <Pagination
          page={safeFindingsPage}
          pageSize={AAG_PAGE_SIZE}
          total={visible.length}
          onPageChange={setFindingsPage}
        />
        {errorMessage ? <p className="pf-table__muted">{errorMessage}</p> : null}
        {!fetching && !errorMessage && runId != null && candidates.length === 0 ? (
          <p className="pf-table__muted">{t("aag.noFindings")}</p>
        ) : null}
        {!fetching && !errorMessage && candidates.length > 0 && visible.length === 0 ? (
          <p className="pf-table__muted">{t("aag.noChecksMatch")}</p>
        ) : null}
      </div>
    </>
  );
}

function AagTaskPage({
  kind,
  labelKey,
  withRunHint,
}: {
  kind: AagTaskKind;
  labelKey: string;
  withRunHint?: boolean;
}) {
  const { t } = useTranslation();
  const { canOperate } = useAuth();
  const { confirm } = useConfirm();
  const toast = useToast();
  const queryClient = useQueryClient();
  const statusQuery = useAagStatus();
  const [params] = useSearchParams();
  const runIdRaw = params.get("runId");
  const [runInput, setRunInput] = useState(runIdRaw ?? "");
  const runId = /^\d+$/.test(runInput.trim()) ? Number(runInput.trim()) : null;
  const presetChecks = (params.get("checks") ?? "")
    .split(",")
    .map((item) => Number(item))
    .filter((item) => Number.isInteger(item) && item > 0);
  const [prompt, setPrompt] = useState("");
  const [profileName, setProfileName] = useState("");
  const [profileVersion, setProfileVersion] = useState("");
  const [targetKind, setTargetKind] = useState<"" | "os" | "software">("");
  const [scriptKind, setScriptKind] = useState<"" | "sh" | "ps1" | "py">("");
  const [selectedChecks, setSelectedChecks] = useState<number[]>(presetChecks);
  const [page, setPage] = useState(1);
  const pageSize = AAG_PAGE_SIZE;
  const statusData = statusQuery.data;
  const tasksQuery = useQuery({
    queryKey: ["aagTasks", kind, page],
    queryFn: () => api.aagTasks({ kind, offset: (page - 1) * pageSize, limit: pageSize }),
    enabled: Boolean(statusData?.enabled),
    retry: false,
    refetchInterval: (query) =>
      query.state.data?.items.some((item) => item.status === "pending") ? 2000 : false,
  });
  const candidatesQuery = useQuery({
    queryKey: ["aagCandidates", runId],
    queryFn: () => api.aagExplainCandidates(runId!),
    enabled: kind === "explain" && Boolean(statusData?.enabled) && runId != null,
    retry: false,
  });
  const submit = useMutation({
    mutationFn: () =>
      api.createAagTask({
        kind,
        prompt: kind === "explain" ? null : prompt,
        run_id: runId,
        check_ids: kind === "explain" ? selectedChecks : undefined,
        profile_name: kind === "generate" ? profileName.trim() : null,
        profile_version: kind === "generate" ? profileVersion.trim() || null : null,
        target_kind: kind === "generate" && targetKind ? targetKind : undefined,
        script_kind: kind === "generate" && scriptKind ? scriptKind : undefined,
      }),
    onSuccess: async () => {
      setPrompt("");
      toast.success(t("aag.taskQueued"));
      await queryClient.invalidateQueries({ queryKey: ["aagTasks", kind] });
    },
    onError: (error: unknown) => {
      const message = error instanceof Error ? error.message : "";
      toast.error(message ? aagErrorText(message, t) : t("aag.taskFailed"));
    },
  });
  const deleteResult = useMutation({
    mutationFn: api.deleteAagTask,
    onSuccess: async () => {
      toast.success(t("aag.resultDeleted"));
      if ((tasksQuery.data?.items.length ?? 0) <= 1 && page > 1) {
        setPage(page - 1);
      }
      await queryClient.invalidateQueries({ queryKey: ["aagTasks", kind] });
    },
    onError: (error: unknown) => {
      toast.error(error instanceof Error ? error.message : t("aag.taskFailed"));
    },
  });
  const retryResult = useMutation({
    mutationFn: api.retryAagTask,
    onSuccess: async () => {
      toast.success(t("aag.taskRetried"));
      await queryClient.invalidateQueries({ queryKey: ["aagTasks", kind] });
    },
    onError: (error: unknown) => {
      toast.error(error instanceof Error ? error.message : t("aag.taskFailed"));
    },
  });

  return (
    <>
      <PageHeader title={t(labelKey)} description={t(leadKey(kind))} />
      {statusQuery.isPending ? (
        <Spinner />
      ) : statusQuery.isError || !statusData ? (
        <QueryErrorState
          title={t("aag.statusError")}
          message={statusQuery.error instanceof Error ? statusQuery.error.message : undefined}
          onRetry={() => void statusQuery.refetch()}
        />
      ) : (
        <>
          {withRunHint && runIdRaw ? (
            <Panel title={t("aag.runHintTitle")} collapsible={false}>
              <p className="pf-table__muted">{t("aag.runHintBody", { runId: runIdRaw })}</p>
            </Panel>
          ) : null}
          {!statusData.enabled ? (
            <AagDisabledNotice status={statusData} />
          ) : (
            <>
              {statusData.reachable === false ? (
                <Panel title={t("aag.providerUnreachable")} collapsible={false} />
              ) : null}
              {canOperate ? (
                <Panel title={t(labelKey)}>
                  <div className="pf-form pf-form--wide">
                    {kind === "explain" ? (
                      <ExplainRequest
                        runInput={runInput}
                        onRunInput={setRunInput}
                        selectedChecks={selectedChecks}
                        onSelectedChecks={setSelectedChecks}
                        candidates={candidatesQuery.data ?? []}
                        fetching={candidatesQuery.isFetching}
                        errorMessage={
                          candidatesQuery.isError
                            ? explainLoadError(
                                candidatesQuery.error instanceof Error ? candidatesQuery.error.message : "",
                                t,
                              )
                            : null
                        }
                        ready={Boolean(statusData.enabled)}
                        runId={runId}
                      />
                    ) : null}
                    {kind === "generate" ? (
                      <div className="pf-aag-generate">
                        <div className="pf-aag-generate__identity">
                          <div className="pf-form__group">
                            <label htmlFor="aag-profile-name">{t("aag.profileName")}</label>
                            <input
                              id="aag-profile-name"
                              className="pf-input"
                              value={profileName}
                              maxLength={128}
                              onChange={(event) => setProfileName(event.target.value)}
                            />
                          </div>
                          <div className="pf-form__group">
                            <label htmlFor="aag-profile-version">{t("aag.profileVersion")}</label>
                            <input
                              id="aag-profile-version"
                              className="pf-input"
                              value={profileVersion}
                              maxLength={32}
                              placeholder={t("aag.fromPrompt")}
                              onChange={(event) => setProfileVersion(event.target.value)}
                            />
                          </div>
                        </div>
                        <div className="pf-aag-generate__options">
                          <div className="pf-form__group">
                            <label htmlFor="aag-target-kind">{t("aag.profileTarget")}</label>
                            <select
                              id="aag-target-kind"
                              className="pf-select"
                              value={targetKind}
                              onChange={(event) =>
                                setTargetKind(event.target.value === "software" || event.target.value === "os" ? event.target.value : "")
                              }
                            >
                              <option value="">{t("aag.fromPrompt")}</option>
                              <option value="os">{t("aag.profileTargetOs")}</option>
                              <option value="software">{t("aag.profileTargetSoftware")}</option>
                            </select>
                          </div>
                          <div className="pf-form__group">
                            <label htmlFor="aag-script-kind">{t("aag.profileScript")}</label>
                            <select
                              id="aag-script-kind"
                              className="pf-select"
                              value={scriptKind}
                              onChange={(event) => {
                                const value = event.target.value;
                                setScriptKind(value === "sh" || value === "ps1" || value === "py" ? value : "");
                              }}
                            >
                              <option value="">{t("aag.fromPrompt")}</option>
                              <option value="sh">{t("aag.profileScriptSh")}</option>
                              <option value="ps1">{t("aag.profileScriptPs1")}</option>
                              <option value="py">{t("aag.profileScriptPy")}</option>
                            </select>
                          </div>
                        </div>
                        <div className="pf-form__group pf-aag-generate__prompt">
                          <label htmlFor="aag-prompt-generate">{t("aag.prompt")}</label>
                          <textarea
                            id="aag-prompt-generate"
                            className="pf-textarea"
                            rows={8}
                            value={prompt}
                            onChange={(event) => setPrompt(event.target.value)}
                          />
                        </div>
                      </div>
                    ) : null}
                    <div className="pf-aag-form__foot">
                      <Button
                        variant="primary"
                        loading={submit.isPending}
                        disabled={
                          statusData.reachable === false ||
                          (kind === "explain" && selectedChecks.length === 0) ||
                          (kind === "generate" && (!profileName.trim() || !prompt.trim()))
                        }
                        onClick={() => submit.mutate()}
                      >
                        {t("aag.submitTask")}
                      </Button>
                    </div>
                  </div>
                </Panel>
              ) : null}
              {kind === "generate" ? (
                <AagPackageLibrary
                  items={tasksQuery.data?.items ?? []}
                  pending={tasksQuery.isPending}
                  errorMessage={
                    tasksQuery.isError
                      ? tasksQuery.error instanceof Error
                        ? tasksQuery.error.message
                        : t("aag.taskFailed")
                      : null
                  }
                  onReload={() => void tasksQuery.refetch()}
                  page={page}
                  pageSize={pageSize}
                  total={tasksQuery.data?.total ?? 0}
                  onPageChange={setPage}
                  deletingId={deleteResult.isPending ? deleteResult.variables : undefined}
                  retryingId={retryResult.isPending ? retryResult.variables : undefined}
                  onRetry={canOperate ? (item) => retryResult.mutate(item.id) : undefined}
                  onDelete={
                    canOperate
                      ? (item) => {
                          void confirm({
                            title: t("aag.deleteResultTitle"),
                            message: t("aag.deleteResultMessage"),
                            variant: "danger",
                            confirmLabel: t("common.delete"),
                          }).then((accepted) => {
                            if (accepted) deleteResult.mutate(item.id);
                          });
                        }
                      : undefined
                  }
                />
              ) : (
              <Panel title={t("aag.artifactsTitle")}>
                {tasksQuery.isPending ? (
                  <Spinner />
                ) : tasksQuery.isError ? (
                  <QueryErrorState
                    title={t("aag.taskFailed")}
                    message={tasksQuery.error instanceof Error ? tasksQuery.error.message : undefined}
                    onRetry={() => void tasksQuery.refetch()}
                  />
                ) : (tasksQuery.data?.items.length ?? 0) === 0 ? (
                  <EmptyState title={t("aag.artifactsEmpty")} description={t("aag.artifactsEmpty")} />
                ) : (
                  <>
                    <AagArtifactList
                      items={tasksQuery.data?.items ?? []}
                      deletingId={deleteResult.isPending ? deleteResult.variables : undefined}
                      retryingId={retryResult.isPending ? retryResult.variables : undefined}
                      onRetry={canOperate ? (item) => retryResult.mutate(item.id) : undefined}
                      onDelete={
                        canOperate
                          ? (item) => {
                              void confirm({
                                title: t("aag.deleteResultTitle"),
                                message: t("aag.deleteResultMessage"),
                                variant: "danger",
                                confirmLabel: t("common.delete"),
                              }).then((accepted) => {
                                if (accepted) deleteResult.mutate(item.id);
                              });
                            }
                          : undefined
                      }
                    />
                    <Pagination
                      page={page}
                      pageSize={pageSize}
                      total={tasksQuery.data?.total ?? 0}
                      onPageChange={setPage}
                    />
                  </>
                )}
              </Panel>
              )}
            </>
          )}
        </>
      )}
    </>
  );
}

function AagStubPage({ labelKey, withRunHint }: { labelKey: string; withRunHint?: boolean }) {
  const { t } = useTranslation();
  const statusQuery = useAagStatus();
  const [params] = useSearchParams();
  const runId = params.get("runId");
  const statusData = statusQuery.data;

  return (
    <>
      <PageHeader title={t(labelKey)} description={t("aag.subtitle")} />
      {statusQuery.isPending ? (
        <Spinner />
      ) : statusQuery.isError || !statusData ? (
        <QueryErrorState
          title={t("aag.statusError")}
          message={statusQuery.error instanceof Error ? statusQuery.error.message : undefined}
          onRetry={() => void statusQuery.refetch()}
        />
      ) : (
        <>
          {withRunHint && runId ? (
            <Panel title={t("aag.runHintTitle")} collapsible={false}>
              <p className="pf-table__muted">{t("aag.runHintBody", { runId })}</p>
            </Panel>
          ) : null}
          <AagDisabledNotice status={statusData} />
        </>
      )}
    </>
  );
}

export function AagExplainPage() {
  return <AagTaskPage kind="explain" labelKey="nav.aagExplain" withRunHint />;
}

function profileNameFromDescription(raw: string): string {
  try {
    const parsed = JSON.parse(raw) as { profile_name?: unknown };
    return typeof parsed.profile_name === "string" ? parsed.profile_name : "";
  } catch {
    return "";
  }
}

function parsePackageObject(raw: string): Record<string, unknown> | null {
  try {
    const parsed = JSON.parse(raw) as unknown;
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : null;
  } catch {
    return null;
  }
}

function packageRuleRows(rules: Record<string, unknown> | null): { id: string; title: string; criticality: string; explanation: string }[] {
  const list = rules && Array.isArray(rules.rules) ? rules.rules : rules && Array.isArray(rules.items) ? rules.items : [];
  return list.flatMap((item) => {
    if (!item || typeof item !== "object") return [];
    const rule = item as Record<string, unknown>;
    const id = String(rule.requirement_id ?? "");
    const title = String(rule.title ?? id);
    const explanation = String(rule.explanation ?? "");
    return [
      {
        id,
        title,
        criticality: String(rule.criticality ?? ""),
        explanation: explanation && explanation !== title ? explanation : "",
      },
    ];
  });
}

function packageCriticalityVariant(value: string): "success" | "danger" | "warning" | "info" | "neutral" {
  const normalized = value.trim().toLowerCase();
  if (normalized === "critical" || normalized === "high") return "danger";
  if (normalized === "medium") return "warning";
  if (normalized === "low") return "info";
  return "neutral";
}

function AagPackageLibrary({
  items,
  pending,
  errorMessage,
  onReload,
  page,
  pageSize,
  total,
  onPageChange,
  onDelete,
  onRetry,
  deletingId,
  retryingId,
}: {
  items: AagArtifact[];
  pending: boolean;
  errorMessage: string | null;
  onReload: () => void;
  page: number;
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
  onDelete?: (item: AagArtifact) => void;
  onRetry?: (item: AagArtifact) => void;
  deletingId?: number;
  retryingId?: number;
}) {
  const { t } = useTranslation();
  const signature = items.map((item) => item.id).join(",");
  const [openId, setOpenId] = useState<number | null>(items.find((item) => item.meta_json?.files)?.id ?? items[0]?.id ?? null);
  useEffect(() => {
    const ids = signature ? signature.split(",").map(Number) : [];
    setOpenId((current) => (current != null && ids.includes(current) ? current : (ids[0] ?? null)));
  }, [signature]);
  return (
    <Panel title={t("aag.packagesTitle")}>
      {pending ? (
        <Spinner />
      ) : errorMessage ? (
        <QueryErrorState title={t("aag.taskFailed")} message={errorMessage} onRetry={onReload} />
      ) : items.length === 0 ? (
        <EmptyState title={t("aag.artifactsEmpty")} description={t("aag.artifactsEmpty")} />
      ) : (
        <>
          <div className="pf-aag-results">
            {items.map((item) =>
              item.meta_json?.files ? (
                <AagPackageEditor
                  key={item.id}
                  item={item}
                  open={openId === item.id}
                  onOpen={() => setOpenId((current) => (current === item.id ? null : item.id))}
                  onDelete={onDelete}
                  onRetry={onRetry}
                  deletingId={deletingId}
                  retryingId={retryingId}
                />
              ) : (
                <AagGenerateStatusCard
                  key={item.id}
                  item={item}
                  onDelete={onDelete}
                  onRetry={onRetry}
                  deletingId={deletingId}
                  retryingId={retryingId}
                />
              ),
            )}
          </div>
          <Pagination page={page} pageSize={pageSize} total={total} onPageChange={onPageChange} />
        </>
      )}
    </Panel>
  );
}

function AagGenerateActions({
  item,
  onDelete,
  onRetry,
  deletingId,
  retryingId,
}: {
  item: AagArtifact;
  onDelete?: (item: AagArtifact) => void;
  onRetry?: (item: AagArtifact) => void;
  deletingId?: number;
  retryingId?: number;
}) {
  const { t } = useTranslation();
  return (
    <>
      <Badge variant={taskStatusVariant(item.status)} literal>
        {taskStatusLabel(item.status, t)}
      </Badge>
      {onRetry && item.status === "failed" ? (
        <Button
          variant="secondary"
          className="pf-btn--sm"
          loading={retryingId === item.id}
          onClick={() => onRetry(item)}
        >
          {t("aag.retryTask")}
        </Button>
      ) : null}
      {onDelete ? (
        <Button
          variant="danger-secondary"
          className="pf-btn--sm"
          loading={deletingId === item.id}
          onClick={() => onDelete(item)}
        >
          {t("common.delete")}
        </Button>
      ) : null}
    </>
  );
}

function AagGenerateStatusCard({
  item,
  onDelete,
  onRetry,
  deletingId,
  retryingId,
}: {
  item: AagArtifact;
  onDelete?: (item: AagArtifact) => void;
  onRetry?: (item: AagArtifact) => void;
  deletingId?: number;
  retryingId?: number;
}) {
  const { t } = useTranslation();
  const signature =
    item.provider === "internal"
      ? [t("aag.providerInternal"), item.model_name].filter(Boolean).join(" · ")
      : [t("aag.providerExternal"), item.target_host, item.model_name].filter(Boolean).join(" · ");
  const title = String(item.meta_json?.profile_name || signature || t("common.dash"));
  return (
    <article className={`pf-aag-result${item.status === "failed" ? " pf-aag-result--failed" : ""}`}>
      <header className="pf-aag-result__head">
        <div className="pf-aag-result__meta">
          <p className="pf-aag-result__title">{title}</p>
          <p className="pf-aag-result__aside">
            {item.in_perimeter ? t("aag.perimeter") : t("aag.outsidePerimeter")}
          </p>
        </div>
        <div className="pf-aag-result__tools">
          <AagGenerateActions
            item={item}
            onDelete={onDelete}
            onRetry={onRetry}
            deletingId={deletingId}
            retryingId={retryingId}
          />
        </div>
      </header>
      {item.error_message ? (
        <div className="pf-aag-result__body">
          <p className="pf-aag-result__error">{aagErrorText(item.error_message, t)}</p>
        </div>
      ) : null}
    </article>
  );
}

function AagPackageEditor({
  item,
  open,
  onOpen,
  onDelete,
  onRetry,
  deletingId,
  retryingId,
}: {
  item: AagArtifact;
  open: boolean;
  onOpen: () => void;
  onDelete?: (item: AagArtifact) => void;
  onRetry?: (item: AagArtifact) => void;
  deletingId?: number;
  retryingId?: number;
}) {
  const { t } = useTranslation();
  const toast = useToast();
  const queryClient = useQueryClient();
  const files = item.meta_json?.files;
  const [description, setDescription] = useState(JSON.stringify(files?.description ?? {}, null, 2));
  const [rules, setRules] = useState(JSON.stringify(files?.rules ?? {}, null, 2));
  const [scriptName, setScriptName] = useState(files?.script_name ?? "check.sh");
  const [script, setScript] = useState(files?.script ?? "");
  const [profileName, setProfileName] = useState(profileNameFromDescription(JSON.stringify(files?.description ?? {})));
  const [dirty, setDirty] = useState(false);
  const [editing, setEditing] = useState(false);
  const [fileTab, setFileTab] = useState<"description" | "rules" | "script">("description");
  const errors = item.meta_json?.validation_errors ?? [];
  const imported = Boolean(item.meta_json?.imported_profile_name);

  const save = useMutation({
    mutationFn: () => {
      let parsedDescription: Record<string, unknown>;
      let parsedRules: Record<string, unknown>;
      try {
        parsedDescription = JSON.parse(description) as Record<string, unknown>;
        parsedRules = JSON.parse(rules) as Record<string, unknown>;
      } catch {
        throw new Error(t("aag.packageJsonInvalid"));
      }
      const draft: AagPackageDraft = {
        description: { ...parsedDescription, profile_name: profileName.trim() },
        rules: parsedRules,
        script_name: scriptName.trim() || "check.sh",
        script,
      };
      return api.saveAagPackage(item.id, draft);
    },
    onSuccess: async (saved) => {
      const next = saved.meta_json?.files;
      if (next) {
        setDescription(JSON.stringify(next.description ?? {}, null, 2));
        setRules(JSON.stringify(next.rules ?? {}, null, 2));
        setScriptName(next.script_name ?? "check.sh");
        setScript(next.script ?? "");
        setProfileName(typeof next.description?.profile_name === "string" ? next.description.profile_name : profileName);
      }
      setDirty(false);
      const nextErrors = saved.meta_json?.validation_errors ?? [];
      if (nextErrors.length > 0) {
        toast.error(aagErrorText(nextErrors[0], t));
      } else {
        toast.success(t("aag.packageSaved"));
      }
      await queryClient.invalidateQueries({ queryKey: ["aagTasks", "generate"] });
    },
    onError: (error: unknown) => {
      const message = error instanceof Error ? error.message : "";
      toast.error(message ? aagErrorText(message, t) : t("aag.taskFailed"));
    },
  });
  const accept = useMutation({
    mutationFn: () => api.acceptAagPackage(item.id),
    onSuccess: async () => {
      toast.success(t("aag.savedProfile"));
      await queryClient.invalidateQueries({ queryKey: ["aagTasks", "generate"] });
    },
    onError: (error: unknown) => {
      const message = error instanceof Error ? error.message : t("aag.taskFailed");
      toast.error(message.includes("already") ? t("aag.nameCollision") : aagErrorText(message, t));
    },
  });

  if (!files) return null;
  const descriptionObject = parsePackageObject(description);
  const rulesObject = parsePackageObject(rules);
  const spec = packageSpec(descriptionObject);
  const target = [spec.targetName, spec.targetVersion].filter(Boolean).join(" ");
  const ruleRows = packageRuleRows(rulesObject);
  const hidden = !open;
  return (
    <article className={`pf-aag-result${hidden ? " pf-aag-result--collapsed" : ""}`}>
      <header className="pf-aag-result__head">
        <button
          type="button"
          className="pf-aag-result__toggle"
          aria-expanded={open}
          aria-label={hidden ? t("common.expandPanel") : t("common.collapsePanel")}
          onClick={onOpen}
        >
          <span className="pf-aag-result__chevron" aria-hidden />
        </button>
        <div className="pf-aag-result__meta">
          <p className="pf-aag-result__title">{profileName || t("common.dash")}</p>
          <PackageMetaChips
            target={target}
            version={spec.version}
            ruleCount={ruleRows.length}
            scriptName={scriptName}
          />
        </div>
        <div className="pf-aag-result__tools">
          {imported ? (
            <Badge variant="success" literal>
              {t("aag.packageInList")}
            </Badge>
          ) : null}
          <AagGenerateActions
            item={item}
            onDelete={onDelete}
            onRetry={onRetry}
            deletingId={deletingId}
            retryingId={retryingId}
          />
        </div>
      </header>
      {open ? (
        <>
        <div className="pf-aag-result__body">
          <div className="pf-aag-package__identity">
            <div className="pf-form__group">
              <label htmlFor={`aag-package-name-${item.id}`}>{t("aag.profileName")}</label>
              <input
                id={`aag-package-name-${item.id}`}
                className="pf-input"
                value={profileName}
                maxLength={128}
                disabled={imported}
                onChange={(event) => {
                  setProfileName(event.target.value);
                  setDirty(true);
                }}
              />
            </div>
            <Button
              variant="secondary"
              className="pf-btn--sm"
              disabled={imported}
              onClick={() => setEditing((current) => !current)}
            >
              {editing ? t("aag.packageViewFiles") : t("aag.packageEditFiles")}
            </Button>
          </div>
          <div className="pf-aag-package__stage">
            <PackageTabs fileTab={fileTab} onChange={setFileTab} ruleCount={ruleRows.length} />
            <div className="pf-aag-package__stage-body">
              {fileTab === "description" ? (
                editing ? (
                  <textarea
                    id={`aag-desc-${item.id}`}
                    className="pf-textarea pf-aag-package__editor"
                    rows={14}
                    value={description}
                    disabled={imported}
                    onChange={(event) => {
                      setDescription(event.target.value);
                      setDirty(true);
                    }}
                  />
                ) : descriptionObject ? (
                  <PackageDescriptionView description={descriptionObject} />
                ) : (
                  <p className="pf-aag-result__error">{t("aag.packageJsonInvalid")}</p>
                )
              ) : null}
              {fileTab === "rules" ? (
                editing ? (
                  <textarea
                    id={`aag-rules-${item.id}`}
                    className="pf-textarea pf-aag-package__editor"
                    rows={14}
                    value={rules}
                    disabled={imported}
                    onChange={(event) => {
                      setRules(event.target.value);
                      setDirty(true);
                    }}
                  />
                ) : rulesObject ? (
                  <PackageRulesView rules={rulesObject} />
                ) : (
                  <p className="pf-aag-result__error">{t("aag.packageJsonInvalid")}</p>
                )
              ) : null}
              {fileTab === "script" ? (
                editing ? (
                  <div className="pf-aag-package__script">
                    <input
                      id={`aag-script-name-${item.id}`}
                      className="pf-input"
                      value={scriptName}
                      disabled={imported}
                      onChange={(event) => {
                        setScriptName(event.target.value);
                        setDirty(true);
                      }}
                    />
                    <textarea
                      className="pf-textarea pf-aag-package__editor"
                      rows={14}
                      value={script}
                      disabled={imported}
                      onChange={(event) => {
                        setScript(event.target.value);
                        setDirty(true);
                      }}
                    />
                  </div>
                ) : (
                  <PackageScriptView scriptName={scriptName} script={script} />
                )
              ) : null}
            </div>
          </div>
          {errors.length > 0 ? (
            <ul className="pf-aag-package__errors">
              {errors.map((error) => (
                <li key={error}>{aagErrorText(error, t)}</li>
              ))}
            </ul>
          ) : null}
        </div>
        <footer className="pf-aag-result__foot">
          <Button
            variant="secondary"
            loading={save.isPending}
            disabled={imported || !profileName.trim()}
            onClick={() => save.mutate()}
          >
            {t("aag.savePackage")}
          </Button>
          <Button
            variant="primary"
            loading={accept.isPending}
            disabled={imported || dirty || errors.length > 0 || !profileName.trim()}
            onClick={() => accept.mutate()}
          >
            {t("aag.acceptPackage")}
          </Button>
        </footer>
        </>
      ) : null}
    </article>
  );
}

export function AagGeneratePage() {
  return <AagTaskPage kind="generate" labelKey="nav.aagGenerate" />;
}

const PROVIDERS: AagProvider[] = ["none", "internal", "external"];

function connectionForm(data: AagConnection): AagConnectionInput {
  return {
    id: data.id ?? undefined,
    provider: data.provider,
    enabled: Boolean(data.enabled),
    internal_base_url: data.internal_base_url ?? "",
    external_base_url: data.external_base_url ?? "",
    model_name: data.model_name ?? "",
    external_api_key: "",
    timeout_seconds: data.timeout_seconds,
    max_tokens: data.max_tokens,
  };
}

function blankProvider(): AagConnectionInput {
  return {
    provider: "none",
    enabled: false,
    model_name: "",
    internal_base_url: "",
    external_base_url: "",
    external_api_key: "",
  };
}

export function AagConnectionPage() {
  const { t } = useTranslation();
  const { isAdmin } = useAuth();
  const toast = useToast();
  const { confirm } = useConfirm();
  const queryClient = useQueryClient();
  const providerFormRef = useRef<HTMLElement>(null);
  const statusQuery = useAagStatus();
  const connectionQuery = useQuery({
    queryKey: ["aagConnection"],
    queryFn: api.aagConnection,
    enabled: isAdmin,
    retry: false,
  });
  const providersQuery = useQuery({
    queryKey: ["aagProviders"],
    queryFn: api.aagProviders,
    enabled: isAdmin,
    retry: false,
  });
  const [callsPage, setCallsPage] = useState(1);
  const callsPageSize = AAG_PAGE_SIZE;
  const callsQuery = useQuery({
    queryKey: ["aagCalls", callsPage],
    queryFn: () => api.aagCalls({ offset: (callsPage - 1) * callsPageSize, limit: callsPageSize }),
    enabled: isAdmin,
    retry: false,
  });

  const [editingId, setEditingId] = useState<number | null>(null);
  const [formMode, setFormMode] = useState<"closed" | "create" | "edit">("closed");
  const [form, setForm] = useState<AagConnectionInput>(blankProvider());
  const [testResult, setTestResult] = useState<string | null>(null);

  useEffect(() => {
    if (formMode === "closed") return;
    providerFormRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
  }, [formMode, editingId]);

  const refreshProviders = async () => {
    await queryClient.invalidateQueries({ queryKey: ["aagStatus"] });
    await queryClient.invalidateQueries({ queryKey: ["aagConnection"] });
    await queryClient.invalidateQueries({ queryKey: ["aagProviders"] });
  };

  const saveMutation = useMutation({
    mutationFn: api.saveAagConnection,
    onSuccess: async (saved) => {
      toast.success(t("aag.saved"));
      setTestResult(null);
      if (saved.id) {
        setEditingId(saved.id);
        setFormMode("edit");
        setForm(connectionForm(saved));
      }
      await refreshProviders();
    },
    onError: (error: unknown) => {
      toast.error(error instanceof Error ? error.message : t("aag.saveFailed"));
    },
  });

  const contourMutation = useMutation({
    mutationFn: () => {
      const current = connectionQuery.data;
      if (!current?.id) throw new Error(t("aag.saveFailed"));
      return api.saveAagConnection({
        ...connectionForm(current),
        enabled: !current.enabled,
      });
    },
    onSuccess: async (saved) => {
      toast.success(t("aag.saved"));
      if (saved.id && saved.id === editingId) setForm(connectionForm(saved));
      await refreshProviders();
    },
    onError: (error: unknown) => {
      toast.error(error instanceof Error ? error.message : t("aag.saveFailed"));
    },
  });

  const selectMutation = useMutation({
    mutationFn: api.selectAagProvider,
    onSuccess: async (saved) => {
      toast.success(t("aag.providerNowOnline"));
      if (saved.id && saved.id === editingId) setForm(connectionForm(saved));
      await refreshProviders();
    },
    onError: (error: unknown) => {
      toast.error(error instanceof Error ? error.message : t("aag.saveFailed"));
    },
  });

  const deleteMutation = useMutation({
    mutationFn: api.deleteAagProvider,
    onSuccess: async (_void, id) => {
      toast.success(t("aag.providerDeleted"));
      if (editingId === id) {
        setEditingId(null);
        setFormMode("closed");
        setForm(blankProvider());
        setTestResult(null);
      }
      await refreshProviders();
    },
    onError: (error: unknown) => {
      toast.error(error instanceof Error ? error.message : t("aag.saveFailed"));
    },
  });

  const deleteCallMutation = useMutation({
    mutationFn: api.deleteAagCall,
    onSuccess: async () => {
      toast.success(t("aag.callDeleted"));
      if ((callsQuery.data?.items.length ?? 0) <= 1 && callsPage > 1) {
        setCallsPage(callsPage - 1);
      }
      await queryClient.invalidateQueries({ queryKey: ["aagCalls"] });
    },
    onError: (error: unknown) => {
      toast.error(error instanceof Error ? error.message : t("aag.callsError"));
    },
  });

  const testMutation = useMutation({
    mutationFn: api.testAagConnection,
    onSuccess: async (result) => {
      setTestResult(
        result.ok
          ? `${t("aag.testOk")} · ${result.host ?? ""} · ${result.model_name ?? ""}`.trim()
          : `${t("aag.testFail")}: ${result.message}`
      );
      await queryClient.invalidateQueries({ queryKey: ["aagCalls"] });
      await queryClient.invalidateQueries({ queryKey: ["aagStatus"] });
    },
    onError: (error: unknown) => {
      setTestResult(`${t("aag.testFail")}: ${error instanceof Error ? error.message : ""}`);
    },
  });

  if (!isAdmin) {
    return (
      <>
        <PageHeader title={t("nav.aagConnection")} description={t("aag.connectionLead")} />
        <EmptyState title={t("aag.adminOnlyTitle")} description={t("aag.adminOnlyBody")} />
      </>
    );
  }

  if (statusQuery.isPending || connectionQuery.isPending || providersQuery.isPending) {
    return (
      <>
        <PageHeader title={t("nav.aagConnection")} description={t("aag.connectionLead")} />
        <Spinner />
      </>
    );
  }

  const status = statusQuery.data;
  const stored = connectionQuery.data;
  const providers = providersQuery.data ?? [];
  if (statusQuery.isError || connectionQuery.isError || providersQuery.isError || !status || !stored) {
    const message =
      (statusQuery.error instanceof Error ? statusQuery.error.message : undefined) ??
      (connectionQuery.error instanceof Error ? connectionQuery.error.message : undefined) ??
      (providersQuery.error instanceof Error ? providersQuery.error.message : undefined);
    return (
      <>
        <PageHeader title={t("nav.aagConnection")} description={t("aag.connectionLead")} />
        <QueryErrorState
          title={t("aag.statusError")}
          message={message}
          onRetry={() => {
            void statusQuery.refetch();
            void connectionQuery.refetch();
            void providersQuery.refetch();
          }}
        />
      </>
    );
  }
  const editing = providers.find((item) => item.id === editingId);

  const externalBlocked = status.demo_mode || demoMode;

  return (
    <>
      <PageHeader title={t("nav.aagConnection")} description={t("aag.connectionLead")} />

      <Panel title={t("aag.providerStatus")}>
        <div className="pf-form pf-form--wide">
          <div className={`pf-aag-contour${status.enabled ? " is-on" : " is-off"}`}>
            <div className="pf-aag-contour__status">
              <span className="pf-aag-contour__mark">
                <span className="pf-aag-contour__dot" aria-hidden />
                {status.enabled ? t("aag.contourOn") : t("aag.contourOff")}
              </span>
              <span className="pf-aag-contour__hint">
                {status.enabled ? t("aag.contourOnHint") : t("aag.disabledBody")}
              </span>
            </div>
            <Button
              variant={status.enabled ? "secondary" : "primary"}
              loading={contourMutation.isPending}
              disabled={!status.enabled && stored.provider === "none"}
              onClick={() => contourMutation.mutate()}
            >
              {status.enabled ? t("aag.contourDisable") : t("aag.contourEnabled")}
            </Button>
          </div>
          {!status.enabled && stored.provider === "none" ? (
            <p className="pf-form__hint">{t("aag.contourEnabledHint")}</p>
          ) : null}
        </div>
      </Panel>

      {formMode !== "closed" ? (
      <Panel
        ref={providerFormRef}
        title={formMode === "create" ? t("aag.createProviderTitle") : t("aag.editProviderTitle")}
      >
        <div className="pf-form pf-form--wide">
          <div className="pf-form__row">
            <div className="pf-form__group">
              <label htmlFor="aag-provider">{t("aag.provider")}</label>
              <select
                id="aag-provider"
                className="pf-select"
                value={form.provider}
                onChange={(e) => setForm({ ...form, provider: e.target.value as AagProvider })}
              >
                {PROVIDERS.map((provider) => (
                  <option
                    key={provider}
                    value={provider}
                    disabled={provider === "external" && externalBlocked}
                  >
                    {t(`aag.provider${provider[0].toUpperCase()}${provider.slice(1)}`)}
                  </option>
                ))}
              </select>
              {externalBlocked ? (
                <div className="pf-form__hint">{t("aag.demoExternalBlocked")}</div>
              ) : null}
            </div>
            <div className="pf-form__group">
              <label htmlFor="aag-model">{t("aag.modelName")}</label>
              <input
                id="aag-model"
                className="pf-input"
                value={form.model_name ?? ""}
                onChange={(e) => setForm({ ...form, model_name: e.target.value })}
                placeholder="qwen2.5:14b"
                disabled={form.provider === "none"}
              />
            </div>
          </div>
          {form.provider === "internal" ? (
            <div className="pf-form__group">
              <label htmlFor="aag-internal-url">{t("aag.internalUrl")}</label>
              <input
                id="aag-internal-url"
                className="pf-input"
                value={form.internal_base_url ?? ""}
                onChange={(e) => setForm({ ...form, internal_base_url: e.target.value })}
                placeholder="http://ollama:11434"
              />
              {destinationHost(form.internal_base_url) ? (
                <div className="pf-form__hint">
                  {t("aag.destinationHost")}: {destinationHost(form.internal_base_url)}
                </div>
              ) : null}
            </div>
          ) : null}
          {form.provider === "external" ? (
            <>
              <div className="pf-form__group">
                <label htmlFor="aag-external-url">{t("aag.externalUrl")}</label>
                <input
                  id="aag-external-url"
                  className="pf-input"
                  value={form.external_base_url ?? ""}
                  onChange={(e) => setForm({ ...form, external_base_url: e.target.value })}
                  placeholder="https://api.example.com"
                />
                {destinationHost(form.external_base_url) ? (
                  <div className="pf-form__hint">
                    {t("aag.destinationHost")}: {destinationHost(form.external_base_url)}
                  </div>
                ) : null}
              </div>
              <div className="pf-form__group">
                <label htmlFor="aag-key">{t("aag.apiKey")}</label>
                <input
                  id="aag-key"
                  type="password"
                  className="pf-input"
                  value={form.external_api_key ?? ""}
                  onChange={(e) => setForm({ ...form, external_api_key: e.target.value })}
                  placeholder={editing?.has_external_key ? t("aag.keyConfigured") : t("aag.keyNotConfigured")}
                  autoComplete="new-password"
                />
                <div className="pf-form__hint">{t("aag.apiKeyHint")}</div>
              </div>
            </>
          ) : null}
          <div className="pf-form__row">
            <div className="pf-form__group">
              <label htmlFor="aag-timeout">{t("aag.timeout")}</label>
              <input
                id="aag-timeout"
                type="number"
                className="pf-input"
                value={form.timeout_seconds != null ? Math.round(form.timeout_seconds / 60) : ""}
                onChange={(e) =>
                  setForm({
                    ...form,
                    timeout_seconds: e.target.value ? Math.round(Number(e.target.value) * 60) : undefined,
                  })
                }
                min={1}
                max={120}
              />
            </div>
            <div className="pf-form__group">
              <label htmlFor="aag-tokens">{t("aag.maxTokens")}</label>
              <input
                id="aag-tokens"
                type="number"
                className="pf-input"
                value={form.max_tokens ?? ""}
                onChange={(e) =>
                  setForm({ ...form, max_tokens: e.target.value ? Number(e.target.value) : undefined })
                }
                min={1}
                max={1000000}
              />
            </div>
          </div>
          {testResult ? <div className="pf-form__hint">{testResult}</div> : null}
          <div className="pf-form__actions">
            <Button
              variant="primary"
              loading={saveMutation.isPending}
              disabled={form.provider === "none"}
              onClick={() => saveMutation.mutate({ ...form, id: formMode === "edit" ? editingId ?? undefined : undefined })}
            >
              {t("common.save")}
            </Button>
            {formMode === "edit" ? (
            <Button
              variant="secondary"
              loading={testMutation.isPending}
              disabled={form.provider === "none" || editingId == null}
              onClick={() => {
                if (editingId != null) testMutation.mutate(editingId);
              }}
            >
              {t("aag.testConnection")}
            </Button>
            ) : null}
          </div>
        </div>
      </Panel>
      ) : null}

      <Panel
        title={t("aag.providersTitle")}
        toolbar={
          <Button
            variant="secondary"
            className="pf-btn--sm"
            onClick={() => {
              setFormMode("create");
              setEditingId(null);
              setForm(blankProvider());
              setTestResult(null);
              providerFormRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
            }}
          >
            {t("aag.addProvider")}
          </Button>
        }
      >
        {providers.length === 0 ? (
          <EmptyState title={t("aag.providersEmpty")} description={t("aag.providersEmptyHint")} />
        ) : (
          <div className="pf-table-wrap">
            <table className="pf-table pf-table--compact">
              <thead>
                <tr>
                  <th className="pf-aag-provider-pick" />
                  <th>{t("aag.provider")}</th>
                  <th>{t("aag.modelName")}</th>
                  <th>{t("aag.callHost")}</th>
                  <th>{t("aag.timeout")}</th>
                  <th>{t("aag.maxTokens")}</th>
                  <th>{t("aag.providerStatus")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {providers.map((item) => {
                  const selected = Boolean(item.selected);
                  const online = selected && status.enabled;
                  const kind = item.provider;
                  return (
                    <tr key={item.id} className={online ? "is-online" : undefined}>
                      <td>
                        <input
                          type="radio"
                          name="aag-working-provider"
                          className="pf-aag-provider-radio"
                          checked={selected}
                          aria-label={t(`aag.provider${kind[0].toUpperCase()}${kind.slice(1)}`)}
                          disabled={selectMutation.isPending || item.id == null}
                          onChange={() => {
                            if (!selected && item.id != null) selectMutation.mutate(item.id);
                          }}
                        />
                      </td>
                      <td>{t(`aag.provider${kind[0].toUpperCase()}${kind.slice(1)}`)}</td>
                      <td>{item.model_name || t("common.dash")}</td>
                      <td>
                        {destinationHost(
                          item.provider === "external" ? item.external_base_url : item.internal_base_url,
                        ) ?? t("common.dash")}
                      </td>
                      <td>{Math.round(item.timeout_seconds / 60)}</td>
                      <td>{item.max_tokens}</td>
                      <td>
                        <span className={`pf-aag-contour__mark${online ? " is-on" : " is-off"}`}>
                          <span className="pf-aag-contour__dot" aria-hidden />
                          {online ? t("aag.providerOnline") : t("aag.providerOffline")}
                        </span>
                      </td>
                      <td className="pf-table__col-actions">
                        <div className="pf-table__actions">
                          <Button
                            variant="secondary"
                            className="pf-btn--sm"
                            onClick={() => {
                              if (item.id == null) return;
                              setFormMode("edit");
                              setEditingId(item.id);
                              setForm(connectionForm(item));
                              setTestResult(null);
                              providerFormRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
                            }}
                          >
                            {t("common.edit")}
                          </Button>
                          <Button
                            variant="danger-secondary"
                            className="pf-btn--sm"
                            loading={deleteMutation.isPending}
                            onClick={() => {
                              if (item.id == null) return;
                              const id = item.id;
                              void confirm({
                                title: t("aag.deleteProviderTitle"),
                                message: t("aag.deleteProviderMessage"),
                                variant: "danger",
                                confirmLabel: t("common.delete"),
                              }).then((accepted) => {
                                if (accepted) deleteMutation.mutate(id);
                              });
                            }}
                          >
                            {t("common.delete")}
                          </Button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Panel>

      <Panel title={t("aag.callsTitle")} description={t("aag.callsDesc")}>
        {callsQuery.isPending ? (
          <Spinner />
        ) : callsQuery.isError ? (
          <QueryErrorState
            title={t("aag.callsError")}
            message={callsQuery.error instanceof Error ? callsQuery.error.message : undefined}
            onRetry={() => void callsQuery.refetch()}
          />
        ) : (callsQuery.data?.items.length ?? 0) === 0 ? (
          <EmptyState title={t("aag.callsEmptyTitle")} description={t("aag.callsEmpty")} />
        ) : (
          <div className="pf-table-wrap">
            <table className="pf-table pf-table--compact">
              <thead>
                <tr>
                  <th>{t("aag.callTime")}</th>
                  <th>{t("aag.callKind")}</th>
                  <th>{t("aag.callDraft")}</th>
                  <th>{t("aag.callOutcome")}</th>
                  <th>{t("aag.callError")}</th>
                  <th>{t("aag.callDuration")}</th>
                  <th>{t("aag.callRun")}</th>
                  <th>{t("aag.callPerimeter")}</th>
                  <th>{t("aag.callProvider")}</th>
                  <th>{t("aag.callHost")}</th>
                  <th>{t("aag.callModel")}</th>
                  <th>{t("aag.callTokens")}</th>
                  <th>{t("aag.callInputHash")}</th>
                  <th>{t("aag.callBy")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {callsQuery.data?.items.map((entry) => (
                  <tr key={entry.id}>
                    <td className="pf-table__muted">{entry.created_at}</td>
                    <td>{callKindLabel(entry.kind, t)}</td>
                    <td>{callDraftLabel(entry.draft_type, t)}</td>
                    <td>
                      <Badge variant={entry.outcome === "failed" ? "danger" : "success"} literal>
                        {entry.outcome === "failed" ? t("aag.callOutcomeFailed") : t("aag.callOutcomeOk")}
                      </Badge>
                    </td>
                    <td>{callErrorLabel(entry.error_code, t)}</td>
                    <td className="pf-table__muted">{callDurationLabel(entry.duration_ms, t)}</td>
                    <td>{entry.run_id ?? t("common.dash")}</td>
                    <td>{entry.in_perimeter ? t("aag.perimeter") : t("aag.outsidePerimeter")}</td>
                    <td>{entry.provider}</td>
                    <td>{entry.target_host ?? t("common.dash")}</td>
                    <td>{entry.model_name ?? t("common.dash")}</td>
                    <td>{entry.token_count ?? t("common.dash")}</td>
                    <td className="pf-table__muted">{entry.input_hash.slice(0, 16)}…</td>
                    <td>{entry.created_by ?? t("common.dash")}</td>
                    <td className="pf-table__col-actions">
                      <div className="pf-table__actions">
                        <Button
                          variant="danger-secondary"
                          className="pf-btn--sm"
                          loading={deleteCallMutation.isPending && deleteCallMutation.variables === entry.id}
                          onClick={() => {
                            void confirm({
                              title: t("aag.deleteCallTitle"),
                              message: t("aag.deleteCallMessage"),
                              variant: "danger",
                              confirmLabel: t("common.delete"),
                            }).then((accepted) => {
                              if (accepted) deleteCallMutation.mutate(entry.id);
                            });
                          }}
                        >
                          {t("common.delete")}
                        </Button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            <Pagination
              page={callsPage}
              pageSize={callsPageSize}
              total={callsQuery.data?.total ?? 0}
              onPageChange={setCallsPage}
            />
          </div>
        )}
      </Panel>
    </>
  );
}
