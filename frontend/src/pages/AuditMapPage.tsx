import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api, type AuditMapNode, type AuditMapViewName } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { operationsPath, type OperationsPlatform, type OperationsTask } from "../components/OperationsTabs";
import { Button } from "../components/ui/Button";
import { EmptyState } from "../components/ui/EmptyState";
import { IconLinux, IconNetwork, IconWindows } from "../components/ui/Icons";
import { PageHeader } from "../components/ui/PageHeader";
import { Spinner } from "../components/ui/Spinner";
import { useToast } from "../components/ui/Toast";
import { useTranslation } from "../i18n/I18nProvider";
import {
  AUDIT_MAP_DEFAULT_ZOOM,
  AUDIT_MAP_MAX_ZOOM,
  AUDIT_MAP_MIN_ZOOM,
  fitAuditMapCamera,
  packAuditMap,
} from "./auditMapLayout";
import { existingAuditJob, readyAuditJob, readyAuditTemplate, reusableAuditJob } from "./auditMapRun";

const UNASSIGNED = "__none__";
const STATUS_ORDER = ["pass", "fail", "error", "unchecked"] as const;
const VIEWS: AuditMapViewName[] = ["network", "service", "platform", "profile"];

type DisplayMode = "map" | "list" | "donut";
const DISPLAY_MODES: DisplayMode[] = ["map", "list", "donut"];
const DISPLAY_LABEL: Record<DisplayMode, string> = {
  map: "auditMap.displayMap",
  list: "auditMap.displayList",
  donut: "auditMap.displayDonut",
};

function displayParam(value: string | null): DisplayMode {
  if (value === "list" || value === "donut") return value;
  return "map";
}

const DONUT_STROKE: Record<string, string> = {
  pass: "var(--pf-green-500)",
  fail: "var(--pf-red-600)",
  error: "var(--pf-gold-400)",
  unchecked: "var(--pf-black-400)",
};

function statusCounts(items: { status: string }[]): Record<string, number> {
  const counts: Record<string, number> = { pass: 0, fail: 0, error: 0, unchecked: 0 };
  for (const item of items) {
    const key = item.status in counts ? item.status : "unchecked";
    counts[key] += 1;
  }
  return counts;
}

function StatusDonut({ counts, total, label }: { counts: Record<string, number>; total: number; label: string }) {
  const radius = 34;
  const circle = 2 * Math.PI * radius;
  let taken = 0;
  return (
    <div className="pf-audit-map__donut" role="img" aria-label={label}>
      <svg viewBox="0 0 88 88" width="88" height="88" aria-hidden="true">
        <circle
          cx="44"
          cy="44"
          r={radius}
          fill="none"
          strokeWidth="12"
          style={{ stroke: "color-mix(in srgb, var(--text-secondary) 14%, transparent)" }}
        />
        <g transform="rotate(-90 44 44)">
          {STATUS_ORDER.map((status) => {
            const value = counts[status] ?? 0;
            if (!value || !total) return null;
            const length = (value / total) * circle;
            const offset = -(taken / total) * circle;
            taken += value;
            return (
              <circle
                key={status}
                cx="44"
                cy="44"
                r={radius}
                fill="none"
                strokeWidth="12"
                style={{ stroke: DONUT_STROKE[status] }}
                strokeDasharray={`${length} ${circle - length}`}
                strokeDashoffset={offset}
              />
            );
          })}
        </g>
      </svg>
      <span className="pf-audit-map__donut-total" aria-hidden="true">
        {total}
      </span>
    </div>
  );
}

type Point = { x: number; y: number };

function siteParam(value: string): string | undefined {
  return value || undefined;
}

function viewParam(value: string | null): AuditMapViewName {
  if (value === "service" || value === "platform" || value === "profile") return value;
  return "network";
}

function repeatsHost(view: AuditMapViewName): boolean {
  return view === "service" || view === "profile";
}

function nodeLabel(node: AuditMapNode, mode: "ip" | "dns"): string {
  if (mode === "ip") return node.ip || node.hostname || node.name;
  return node.dns || node.name || node.hostname;
}

function countHostResults(results: { host_id: number; status: string }[], hostId: number) {
  const counts = { pass: 0, fail: 0, error: 0 };
  for (const row of results) {
    if (row.host_id !== hostId) continue;
    const status = row.status.toLowerCase();
    if (status === "pass" || status === "fail" || status === "error") counts[status] += 1;
  }
  return counts;
}

function platformOf(osType: string | null): OperationsPlatform {
  const normalized = (osType ?? "linux").toLowerCase();
  if (normalized === "network") return "network";
  if (normalized === "windows") return "windows";
  return "linux";
}

function launchPath(node: AuditMapNode, task: OperationsTask): string {
  const path = operationsPath(platformOf(node.os_type), task);
  const joiner = path.includes("?") ? "&" : "?";
  return `${path}${joiner}hosts=${node.host_id}`;
}

function PlatformGlyph({ osType }: { osType: string | null }) {
  const kind = (osType ?? "").toLowerCase();
  if (kind === "windows") return <IconWindows />;
  if (kind === "network") return <IconNetwork />;
  return <IconLinux />;
}

export function AuditMapPage() {
  const { t } = useTranslation();
  const { canExecute, canOperate } = useAuth();
  const toast = useToast();
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [params, setParams] = useSearchParams();
  const site = params.get("site") ?? "";
  const environment = params.get("environment") ?? "";
  const criticality = params.get("criticality") ?? "";
  const profile = params.get("profile") ?? "";
  const tag = params.get("tag") ?? "";
  const view = viewParam(params.get("view"));
  const labelMode = params.get("label") === "dns" ? "dns" : "ip";
  const display = displayParam(params.get("display"));
  const [draft, setDraft] = useState<Record<string, Point>>({});
  const [activeId, setActiveId] = useState<number | null>(null);
  const [activeGroup, setActiveGroup] = useState<string | null>(null);
  const [donutGroup, setDonutGroup] = useState<string | null>(null);
  const [focus, setFocus] = useState<string | null>(null);
  const [trackedRun, setTrackedRun] = useState<{ hostId: number; runId: number } | null>(null);
  const refreshedRun = useRef<number | null>(null);
  const [zoom, setZoom] = useState(AUDIT_MAP_DEFAULT_ZOOM);
  const [pan, setPan] = useState<Point>({ x: 0, y: 0 });
  const camera = useRef({ zoom: AUDIT_MAP_DEFAULT_ZOOM, pan: { x: 0, y: 0 } });
  const userAdjusted = useRef(false);
  const layoutRef = useRef<{ placed: Map<string, Point> }>({ placed: new Map() });
  const viewportRef = useRef<HTMLDivElement | null>(null);
  const detailRef = useRef<HTMLElement | null>(null);
  const panDrag = useRef<{ startX: number; startY: number; originX: number; originY: number } | null>(null);
  const suppressClick = useRef(false);

  function applyCamera(nextZoom: number, nextPan: Point) {
    camera.current = { zoom: nextZoom, pan: nextPan };
    setZoom(nextZoom);
    setPan(nextPan);
  }

  function fitCamera() {
    const el = viewportRef.current;
    if (!el) return;
    const rect = el.getBoundingClientRect();
    const next = fitAuditMapCamera([...layoutRef.current.placed.values()], {
      width: rect.width,
      height: rect.height,
    });
    userAdjusted.current = false;
    applyCamera(next.zoom, next.pan);
  }

  function resetCamera() {
    fitCamera();
  }

  function zoomBy(factor: number, centerX?: number, centerY?: number) {
    const el = viewportRef.current;
    const { zoom: current, pan: currentPan } = camera.current;
    const next = Math.min(AUDIT_MAP_MAX_ZOOM, Math.max(AUDIT_MAP_MIN_ZOOM, current * factor));
    if (next === current) return;
    userAdjusted.current = true;
    const scale = next / current;
    let anchor = { x: 0, y: 0 };
    if (el && centerX != null && centerY != null) {
      const rect = el.getBoundingClientRect();
      anchor = { x: centerX - rect.left, y: centerY - rect.top };
    } else if (el) {
      const rect = el.getBoundingClientRect();
      anchor = { x: rect.width / 2, y: rect.height / 2 };
    }
    applyCamera(next, {
      x: anchor.x - (anchor.x - currentPan.x) * scale,
      y: anchor.y - (anchor.y - currentPan.y) * scale,
    });
  }

  useEffect(() => {
    const el = viewportRef.current;
    if (!el) return;
    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      zoomBy(event.deltaY < 0 ? 1.12 : 1 / 1.12, event.clientX, event.clientY);
    };
    el.addEventListener("wheel", onWheel, { passive: false });
    return () => el.removeEventListener("wheel", onWheel);
  }, []);

  useEffect(() => {
    const panel = detailRef.current;
    if (!panel || activeId == null || (display !== "map" && display !== "donut")) return;
    const fit = () => {
      const scroller = panel.closest(".pf-main");
      if (!(scroller instanceof HTMLElement)) return;
      panel.style.maxHeight = `${Math.max(280, scroller.clientHeight - 16)}px`;
    };
    fit();
    panel.scrollIntoView({ block: "nearest" });
    window.addEventListener("resize", fit);
    return () => {
      window.removeEventListener("resize", fit);
      panel.style.maxHeight = "";
    };
  }, [activeId, display]);

  const filters = {
    site: siteParam(site),
    environment: environment || undefined,
    criticality: criticality || undefined,
    tag: tag || undefined,
    profile: profile || undefined,
  };

  const mapQuery = useQuery({
    queryKey: ["audit-map", filters],
    queryFn: () => api.auditMap(filters),
  });

  const runQuery = useQuery({
    queryKey: ["audit-map-run", trackedRun?.runId],
    queryFn: () => api.getJobRun(trackedRun!.runId),
    enabled: trackedRun != null,
    refetchInterval: (query) => {
      const status = query.state.data?.status;
      return status === "pending" || status === "running" || !status ? 2000 : false;
    },
  });

  useEffect(() => {
    const next = runQuery.data;
    if (!next || !trackedRun || next.id !== trackedRun.runId) return;
    if (next.status === "pending" || next.status === "running") return;
    if (refreshedRun.current === next.id) return;
    refreshedRun.current = next.id;
    void queryClient.invalidateQueries({ queryKey: ["audit-map"] });
  }, [runQuery.data, trackedRun, queryClient]);

  const startAudit = useMutation({
    mutationFn: async (node: AuditMapNode) => {
      const platform = platformOf(node.os_type);
      const scope = platform === "network" ? "network" : "standard";
      const [templates, jobs, host] = await Promise.all([
        api.jobTemplates(),
        api.jobs(scope),
        api.getHost(node.host_id),
      ]);
      const readyJob = readyAuditJob(jobs, node, profile, host);
      if (readyJob) {
        const run = await api.runJob(readyJob.id);
        return { started: true as const, hostId: node.host_id, runId: run.id };
      }
      const template = readyAuditTemplate(templates, node, profile, host);
      if (!template) {
        return { started: false as const, jobId: existingAuditJob(jobs, node.host_id, profile)?.id ?? null };
      }
      const existing = reusableAuditJob(jobs, template, node.host_id);
      const run = existing
        ? await api.runJob(existing.id)
        : await api.runJob(
            (
              await api.createJob({
                name: template.name,
                profile_id: template.profile_id ?? undefined,
                playbook_id: template.playbook_id ?? undefined,
                execution_type: template.execution_type ?? undefined,
                host_ids: [node.host_id],
                scope,
                is_scheduled: false,
              })
            ).id,
          );
      return { started: true as const, hostId: node.host_id, runId: run.id };
    },
    onSuccess: async (result, node) => {
      if (result.started) {
        setTrackedRun({ hostId: result.hostId, runId: result.runId });
        toast.success(t("auditMap.auditStarted"));
        return;
      }
      const path = launchPath(node, "compliance");
      const joiner = path.includes("?") ? "&" : "?";
      navigate(result.jobId ? `${path}${joiner}job=${result.jobId}` : path);
    },
    onError: (error: Error) => toast.error(error.message || t("auditMap.auditStartFailed")),
  });

  const data = mapQuery.data;
  const groups = useMemo(() => data?.views?.[view] ?? [], [data, view]);
  const visibleGroups = useMemo(
    () => (focus == null ? groups : groups.filter((group) => (group.key ?? "") === focus)),
    [groups, focus]
  );
  const nodes = useMemo(() => {
    const seen = new Map<number, AuditMapNode>();
    for (const group of groups) {
      for (const node of group.nodes) seen.set(node.host_id, node);
    }
    return [...seen.values()];
  }, [groups]);

  const layout = useMemo(
    () => packAuditMap(visibleGroups, new Map(), draft, false),
    [visibleGroups, draft],
  );
  layoutRef.current = layout;

  const active = useMemo(() => {
    if (activeId == null) return null;
    if (view === "profile" && activeGroup != null) {
      const group = groups.find((item) => (item.key ?? "") === activeGroup);
      const match = group?.nodes.find((node) => node.host_id === activeId);
      if (match) return match;
    }
    for (const group of groups) {
      const match = group.nodes.find((node) => node.host_id === activeId);
      if (match) return match;
    }
    return null;
  }, [activeGroup, activeId, groups, view]);

  const canvasNodes = useMemo(() => {
    const list: { groupKey: string; node: AuditMapNode }[] = [];
    for (const group of visibleGroups) {
      for (const node of group.nodes) {
        list.push({ groupKey: group.key ?? "", node });
      }
    }
    return list;
  }, [visibleGroups]);

  const liveRun = trackedRun && active && trackedRun.hostId === active.host_id ? runQuery.data : undefined;
  const liveStatus = liveRun?.status;
  const checkInFlight =
    trackedRun?.hostId === active?.host_id &&
    !runQuery.isError &&
    (liveStatus === "pending" || liveStatus === "running" || !liveRun);
  const serviceCounts = useMemo(() => {
    if (!active) return null;
    if (liveRun && (checkInFlight || active.last_job_run_id !== liveRun.id)) {
      const counts = countHostResults(liveRun.check_results, active.host_id);
      return { ...counts, unchecked: 0 };
    }
    if (active.checks) {
      return {
        pass: active.checks.pass ?? 0,
        fail: active.checks.fail ?? 0,
        error: active.checks.error ?? 0,
        unchecked: 0,
      };
    }
    return statusCounts(active.services);
  }, [active, liveRun, checkInFlight]);

  function setFilter(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next);
    setActiveId(null);
    setActiveGroup(null);
    setDonutGroup(null);
    setFocus(null);
    setDraft({});
  }

  function setView(nextView: AuditMapViewName) {
    const next = new URLSearchParams(params);
    next.set("view", nextView);
    setParams(next);
    setActiveGroup(null);
    setDraft({});
    setDonutGroup(null);
    setFocus(null);
  }

  function setLabel(mode: "ip" | "dns") {
    const next = new URLSearchParams(params);
    next.set("label", mode);
    setParams(next);
  }

  function setDisplay(mode: DisplayMode) {
    const next = new URLSearchParams(params);
    next.set("display", mode);
    setParams(next);
  }

  function platformLabel(osType: string | null): string {
    const key = (osType ?? "").toLowerCase();
    if (key === "linux") return t("hosts.osLinux");
    if (key === "windows") return t("hosts.osWindows");
    if (key === "network") return t("hosts.osNetwork");
    if (!key || key === "other") return t("auditMap.otherPlatform");
    return osType ?? t("auditMap.otherPlatform");
  }

  function groupTitle(key: string | null): string {
    if (view === "network") return key || t("auditMap.otherAddresses");
    if (view === "service") return key || t("auditMap.noService");
    if (view === "profile") return key || t("auditMap.noProfile");
    return platformLabel(key);
  }

  function viewLabel(item: AuditMapViewName): string {
    if (item === "network") return t("auditMap.viewNetwork");
    if (item === "service") return t("auditMap.viewService");
    if (item === "profile") return t("auditMap.viewProfile");
    return t("auditMap.viewPlatform");
  }

  function hostSelected(hostId: number, groupKey = ""): boolean {
    if (activeId !== hostId) return false;
    if (view !== "profile") return true;
    return (activeGroup ?? "") === groupKey;
  }

  function openHost(hostId: number, groupKey = "") {
    if (hostSelected(hostId, groupKey)) {
      setActiveId(null);
      setActiveGroup(null);
      return;
    }
    setActiveId(hostId);
    setActiveGroup(view === "profile" ? groupKey : null);
  }

  function closeHost() {
    setActiveId(null);
    setActiveGroup(null);
  }

  function startDrag(event: React.PointerEvent, placeId: string) {
    if (!canExecute || repeatsHost(view)) return;
    if (event.button !== 0) return;
    const zoomNow = camera.current.zoom;
    const origin = layout.placed.get(placeId) ?? { x: 0, y: 0 };
    const startX = event.clientX;
    const startY = event.clientY;
    let moved = false;
    const move = (ev: PointerEvent) => {
      if (Math.abs(ev.clientX - startX) + Math.abs(ev.clientY - startY) > 5) moved = true;
      setDraft((current) => ({
        ...current,
        [placeId]: {
          x: origin.x + (ev.clientX - startX) / zoomNow,
          y: origin.y + (ev.clientY - startY) / zoomNow,
        },
      }));
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      if (moved) {
        suppressClick.current = true;
        window.setTimeout(() => {
          suppressClick.current = false;
        }, 0);
      }
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }

  function startPan(event: React.PointerEvent) {
    if (event.button !== 0) return;
    if ((event.target as HTMLElement).closest(".pf-audit-map__object, button, a, input, label, select")) return;
    const startX = event.clientX;
    const startY = event.clientY;
    const origin = { ...camera.current.pan };
    panDrag.current = { startX, startY, originX: origin.x, originY: origin.y };
    const move = (ev: PointerEvent) => {
      const drag = panDrag.current;
      if (!drag) return;
      if (Math.abs(ev.clientX - drag.startX) + Math.abs(ev.clientY - drag.startY) > 4) {
        userAdjusted.current = true;
      }
      applyCamera(camera.current.zoom, {
        x: drag.originX + (ev.clientX - drag.startX),
        y: drag.originY + (ev.clientY - drag.startY),
      });
    };
    const up = () => {
      panDrag.current = null;
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }

  const hostCard = active ? (
            <aside ref={detailRef} className="pf-audit-map__detail" aria-label={active.name}>
              <div className={`pf-audit-map__detail-head pf-audit-map__detail-head--${active.status}`}>
                <span className="pf-audit-map__detail-glyph" aria-hidden>
                  <PlatformGlyph osType={active.os_type} />
                </span>
                <div className="pf-audit-map__detail-title">
                  <h2>{active.name}</h2>
                  <p className="pf-audit-map__detail-addr">
                    {active.ip || active.dns || active.hostname || "—"}:{active.port}
                  </p>
                </div>
                <span className={`pf-audit-map__pill pf-audit-map__pill--${active.status}`}>
                  {t(`auditMap.legend.${active.status}`)}
                </span>
                <button
                  type="button"
                  className="pf-audit-map__detail-close"
                  aria-label={t("common.close")}
                  onClick={closeHost}
                >
                  ×
                </button>
              </div>

              <div className="pf-audit-map__detail-body">
                {canExecute ? (
                  <div className="pf-audit-map__detail-run">
                    <Button
                      type="button"
                      loading={startAudit.isPending}
                      disabled={checkInFlight}
                      onClick={() => startAudit.mutate(active)}
                    >
                      {t("auditMap.openAudit")}
                    </Button>
                    <Link className="pf-btn pf-btn--secondary" to={launchPath(active, "remediation")}>
                      {t("auditMap.openRemediation")}
                    </Link>
                  </div>
                ) : null}
                <div className="pf-audit-map__detail-links">
                  {canOperate ? <Link to={`/hosts?edit=${active.host_id}`}>{t("auditMap.openHost")}</Link> : null}
                  {active.last_job_run_id ? (
                    <Link to={`/reports?run=${active.last_job_run_id}`}>{t("auditMap.openReport")}</Link>
                  ) : null}
                </div>

                <div className="pf-audit-map__stats">
                  <p className="pf-audit-map__detail-subtitle">
                    {checkInFlight ? t("auditMap.checkProgress") : t("auditMap.lastCheckStats")}
                  </p>
                  {active.profile_name ? (
                    <p className="pf-audit-map__check-profile">
                      <span>{t("auditMap.filterProfile")}</span>
                      {active.profile_id != null && (data?.profiles ?? []).some((item) => item.id === active.profile_id) ? (
                        <Link to={`/profiles?id=${active.profile_id}`}>{active.profile_name}</Link>
                      ) : (
                        <strong>{active.profile_name}</strong>
                      )}
                    </p>
                  ) : null}
                  {liveRun && (checkInFlight || liveRun.status === "failed" || active.last_job_run_id !== liveRun.id) ? (
                    <p className={`pf-audit-map__run pf-audit-map__run--${liveRun.status}`}>
                      {checkInFlight ? <span className="pf-audit-map__run-dot" aria-hidden /> : null}
                      {t(`dashboard.status_${liveRun.status}`)}
                      {liveRun.status === "failed" && liveRun.error_message ? ` · ${liveRun.error_message}` : ""}
                    </p>
                  ) : null}
                  <div className="pf-audit-map__meter" role="img" aria-label={t("auditMap.lastCheckStats")}>
                    {STATUS_ORDER.map((status) => {
                      const count = serviceCounts?.[status] ?? 0;
                      const totalServices = active.checks
                        ? (active.checks.pass ?? 0) + (active.checks.fail ?? 0) + (active.checks.error ?? 0)
                        : active.services.length;
                      if (!count || !totalServices) return null;
                      return (
                        <i
                          key={status}
                          className={`pf-audit-map__meter-seg pf-audit-map__meter-seg--${status}`}
                          style={{ width: `${(count / totalServices) * 100}%` }}
                        />
                      );
                    })}
                  </div>
                  <ul className="pf-audit-map__stats-list">
                    {STATUS_ORDER.filter((status) => !(active.checks && status === "unchecked")).map((status) => (
                      <li key={status}>
                        <span className={`pf-audit-map__dot pf-audit-map__dot--${status}`} aria-hidden />
                        <span>{t(`auditMap.legend.${status}`)}</span>
                        <strong>{serviceCounts?.[status] ?? 0}</strong>
                      </li>
                    ))}
                  </ul>
                </div>

                <dl className="pf-audit-map__facts">
                  <div>
                    <dt>{t("auditMap.labelIp")}</dt>
                    <dd className="pf-audit-map__mono">{active.ip || t("common.dash")}</dd>
                  </div>
                  <div>
                    <dt>{t("auditMap.labelDns")}</dt>
                    <dd className="pf-audit-map__mono">{active.dns || t("common.dash")}</dd>
                  </div>
                  <div>
                    <dt>{t("auditMap.port")}</dt>
                    <dd>{active.port}</dd>
                  </div>
                  <div>
                    <dt>{t("hosts.osType")}</dt>
                    <dd>{platformLabel(active.os_type)}</dd>
                  </div>
                  <div>
                    <dt>{t("hosts.site")}</dt>
                    <dd>{active.site || t("auditMap.unassignedSite")}</dd>
                  </div>
                  <div>
                    <dt>{t("hosts.environment")}</dt>
                    <dd>{active.environment || t("common.dash")}</dd>
                  </div>
                  <div>
                    <dt>{t("hosts.criticality")}</dt>
                    <dd>
                      {active.criticality
                        ? t(`hosts.criticalityLabel.${active.criticality}`)
                        : t("hosts.criticalityUnset")}
                    </dd>
                  </div>
                  <div>
                    <dt>{t("auditMap.filterTag")}</dt>
                    <dd>{active.tags.length ? active.tags.join(", ") : t("common.dash")}</dd>
                  </div>
                </dl>

                <p className="pf-audit-map__detail-subtitle">{t("auditMap.viewService")}</p>
                <div className="pf-audit-map__services">
                  {active.services.map((service) => (
                    <span key={service.port} className="pf-audit-map__service" title={
                      service.source === "connection"
                        ? t("auditMap.serviceConnection")
                        : service.confirmed
                          ? t("auditMap.serviceManual")
                          : t("auditMap.serviceScan")
                    }>
                      {service.port}/{service.protocol}
                    </span>
                  ))}
                </div>
              </div>
            </aside>
  ) : null;

  return (
    <section className="pf-page pf-audit-map">
      <PageHeader title={t("auditMap.title")} description={t("auditMap.subtitle")} />

      <div className="pf-audit-map__panel">
        <div className="pf-audit-map__bar">
          <div className="pf-audit-map__control">
            <span className="pf-audit-map__label-caption" id="audit-map-display-mode">
              {t("auditMap.displayAria")}
            </span>
            <div className="pf-segmented pf-audit-map__segmented" role="tablist" aria-labelledby="audit-map-display-mode">
              {DISPLAY_MODES.map((mode) => (
                <button
                  key={mode}
                  type="button"
                  role="tab"
                  aria-selected={mode === display}
                  className={`pf-segmented__option${mode === display ? " is-active" : ""}`}
                  onClick={() => setDisplay(mode)}
                >
                  <span className="pf-segmented__label">{t(DISPLAY_LABEL[mode])}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="pf-audit-map__control">
            <span className="pf-audit-map__label-caption" id="audit-map-view-mode">
              {t("auditMap.viewsAria")}
            </span>
            <div className="pf-segmented pf-audit-map__segmented" role="tablist" aria-labelledby="audit-map-view-mode">
              {VIEWS.map((item) => (
                <button
                  key={item}
                  type="button"
                  role="tab"
                  aria-selected={item === view}
                  className={`pf-segmented__option${item === view ? " is-active" : ""}`}
                  onClick={() => setView(item)}
                >
                  <span className="pf-segmented__label">
                    {viewLabel(item)}
                  </span>
                </button>
              ))}
            </div>
          </div>
          {view === "network" ? (
            <div className="pf-audit-map__control">
              <span className="pf-audit-map__label-caption" id="audit-map-label-mode">
                {t("auditMap.nodeLabel")}
              </span>
              <div className="pf-segmented pf-audit-map__segmented" role="tablist" aria-labelledby="audit-map-label-mode">
                <button
                  type="button"
                  role="tab"
                  aria-selected={labelMode === "ip"}
                  className={`pf-segmented__option${labelMode === "ip" ? " is-active" : ""}`}
                  onClick={() => setLabel("ip")}
                >
                  <span className="pf-segmented__label">{t("auditMap.labelIp")}</span>
                </button>
                <button
                  type="button"
                  role="tab"
                  aria-selected={labelMode === "dns"}
                  className={`pf-segmented__option${labelMode === "dns" ? " is-active" : ""}`}
                  onClick={() => setLabel("dns")}
                >
                  <span className="pf-segmented__label">{t("auditMap.labelDns")}</span>
                </button>
              </div>
            </div>
          ) : null}
        </div>

        <div className="pf-filters pf-audit-map__filters">
          <div className="pf-filters__grid pf-filters__grid--audit-map">
            <div className="pf-filters__group">
              <label htmlFor="audit-map-site">{t("hosts.site")}</label>
              <select
                id="audit-map-site"
                className="pf-select"
                value={site || (data ? data.site || UNASSIGNED : "")}
                onChange={(event) => setFilter("site", event.target.value)}
              >
                {(data?.sites ?? []).map((item) => (
                  <option key={item} value={item}>
                    {item}
                  </option>
                ))}
                {data?.has_unassigned ? <option value={UNASSIGNED}>{t("auditMap.unassignedSite")}</option> : null}
              </select>
            </div>
            <div className="pf-filters__group">
              <label htmlFor="audit-map-environment">{t("hosts.environment")}</label>
              <input
                id="audit-map-environment"
                className="pf-input"
                value={environment}
                onChange={(event) => setFilter("environment", event.target.value)}
              />
            </div>
            <div className="pf-filters__group">
              <label htmlFor="audit-map-criticality">{t("hosts.criticality")}</label>
              <select
                id="audit-map-criticality"
                className="pf-select"
                value={criticality}
                onChange={(event) => setFilter("criticality", event.target.value)}
              >
                <option value="">{t("hosts.criticalityUnset")}</option>
                {(["low", "medium", "high", "critical"] as const).map((level) => (
                  <option key={level} value={level}>
                    {t(`hosts.criticalityLabel.${level}`)}
                  </option>
                ))}
              </select>
            </div>
            <div className="pf-filters__group">
              <label htmlFor="audit-map-profile">{t("auditMap.filterProfile")}</label>
              <select
                id="audit-map-profile"
                className="pf-select"
                value={profile}
                onChange={(event) => setFilter("profile", event.target.value)}
              >
                <option value="">{t("auditMap.allProfiles")}</option>
                {(data?.profiles ?? []).map((item) => (
                  <option key={item.id} value={String(item.id)}>
                    {item.name}
                  </option>
                ))}
              </select>
            </div>
            <div className="pf-filters__group">
              <label htmlFor="audit-map-tag">{t("auditMap.filterTag")}</label>
              <input
                id="audit-map-tag"
                className="pf-input"
                value={tag}
                onChange={(event) => setFilter("tag", event.target.value)}
              />
            </div>
          </div>
        </div>

      </div>

      {focus != null ? (
        <p className="pf-audit-map__crumb">
          <button type="button" onClick={() => setFocus(null)}>
            {t("auditMap.allGroups")}
          </button>
          <span>{groupTitle(focus)}</span>
        </p>
      ) : null}

      {mapQuery.isLoading ? <Spinner /> : null}
      {mapQuery.isError ? <EmptyState title={(mapQuery.error as Error).message} /> : null}
      {data && nodes.length === 0 ? <EmptyState title={t("auditMap.empty")} /> : null}
      {data?.truncated ? <p className="pf-audit-map__truncated">{t("auditMap.truncated", { count: 200 })}</p> : null}

      {data && nodes.length > 0 && display === "list" ? (
        <div className="pf-audit-map__groups">
          {groups.map((group) => {
            const key = group.key ?? "";
            const stats: Record<string, number> = { pass: 0, fail: 0, error: 0, unchecked: 0 };
            for (const node of group.nodes) stats[node.status] = (stats[node.status] ?? 0) + 1;
            return (
              <section
                key={key || "other"}
                className={`pf-audit-map__zone pf-audit-map__zone--${group.status}`}
                aria-label={`${groupTitle(group.key)} · ${group.nodes.length}`}
              >
                <header className="pf-audit-map__zone-head">
                  <span className="pf-audit-map__dot" aria-hidden />
                  <h3>{groupTitle(group.key)}</h3>
                  <span className="pf-audit-map__group-count">{group.nodes.length}</span>
                  {(["error", "fail"] as const)
                    .filter((item) => (stats[item] ?? 0) > 0)
                    .map((item) => (
                      <span key={item} className={`pf-audit-map__mini pf-audit-map__mini--${item}`}>
                        {t(`auditMap.legend.${item}`)} {stats[item]}
                      </span>
                    ))}
                </header>
                <table className="pf-table">
                  <thead>
                    <tr>
                      <th>{t("hosts.name")}</th>
                      <th>{t("auditMap.labelIp")}</th>
                      <th>{t("auditMap.labelDns")}</th>
                      <th>{t("auditMap.port")}</th>
                      <th>{t("hosts.osType")}</th>
                      <th>{t("auditMap.legendTitle")}</th>
                      <th>{t("auditMap.viewService")}</th>
                      <th>{t("common.actions")}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {group.nodes.map((node) => (
                      <tr key={node.host_id}>
                        <td>
                          <span className="pf-audit-map__row-name">{node.name}</span>
                          <span className="pf-audit-map__host-address">{node.hostname}</span>
                        </td>
                        <td className="pf-audit-map__mono">{node.ip || t("common.dash")}</td>
                        <td className="pf-audit-map__mono">{node.dns || t("common.dash")}</td>
                        <td>{node.port}</td>
                        <td>{platformLabel(node.os_type)}</td>
                        <td>
                          <span className={`pf-audit-map__pill pf-audit-map__pill--${node.status}`}>
                            {t(`auditMap.legend.${node.status}`)}
                          </span>
                        </td>
                        <td>
                          <span className="pf-audit-map__services">
                            {node.services.map((service) => (
                              <span key={service.port} className="pf-audit-map__service">
                                {service.port}/{service.protocol}
                              </span>
                            ))}
                          </span>
                        </td>
                        <td>
                          <span className="pf-audit-map__row-actions">
                            {canOperate ? <Link to={`/hosts?edit=${node.host_id}`}>{t("auditMap.openHost")}</Link> : null}
                            {node.last_job_run_id ? (
                              <Link to={`/reports?run=${node.last_job_run_id}`}>{t("auditMap.openReport")}</Link>
                            ) : null}
                            {canExecute ? (
                              <button
                                type="button"
                                className="pf-audit-map__text-btn"
                                disabled={startAudit.isPending}
                                onClick={() => startAudit.mutate(node)}
                              >
                                {t("auditMap.openAudit")}
                              </button>
                            ) : null}
                            {canExecute ? (
                              <Link to={launchPath(node, "remediation")}>{t("auditMap.openRemediation")}</Link>
                            ) : null}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </section>
            );
          })}
        </div>
      ) : null}

      {data && nodes.length > 0 && display === "donut" ? (
        <div className={donutGroup || active ? "pf-audit-map__stage pf-audit-map__stage--open" : "pf-audit-map__stage"}>
          <div className="pf-audit-map__donuts">
          {visibleGroups.map((group) => {
            const key = group.key ?? "";
            const counts = statusCounts(group.nodes);
            const total = group.nodes.length;
            return (
              <section
                key={key || "other"}
                className={`pf-audit-map__donut-card pf-audit-map__zone--${group.status}${donutGroup === key ? " is-selected" : ""}`}
                aria-label={`${groupTitle(group.key)} · ${total}`}
              >
                <button
                  type="button"
                  className="pf-audit-map__donut-head"
                  aria-expanded={donutGroup === key}
                  onClick={() => {
                    setDonutGroup(donutGroup === key ? null : key);
                    setActiveId(null);
                    setActiveGroup(null);
                  }}
                >
                  <span className="pf-audit-map__dot" aria-hidden />
                  <h3>{groupTitle(group.key)}</h3>
                  <span className="pf-audit-map__group-count">{total}</span>
                </button>
                <div className="pf-audit-map__donut-wrap">
                  <StatusDonut counts={counts} total={total} label={`${groupTitle(group.key)} · ${total}`} />
                  <ul className="pf-audit-map__donut-legend">
                    {STATUS_ORDER.map((status) => (
                      <li key={status}>
                        <span className={`pf-audit-map__dot pf-audit-map__dot--${status}`} aria-hidden />
                        <span>{t(`auditMap.legend.${status}`)}</span>
                        <strong>{counts[status] ?? 0}</strong>
                      </li>
                    ))}
                  </ul>
                </div>
              </section>
            );
          })}
          </div>
          {active
            ? hostCard
            : donutGroup
            ? (() => {
                const group = visibleGroups.find((item) => (item.key ?? "") === donutGroup);
                if (!group) return null;
                const groupKey = group.key ?? "";
                const counts = statusCounts(group.nodes);
                const total = group.nodes.length;
                return (
                  <aside className="pf-audit-map__detail" aria-label={groupTitle(group.key)}>
                    <div className={`pf-audit-map__detail-head pf-audit-map__detail-head--${group.status}`}>
                      <span className="pf-audit-map__dot" aria-hidden />
                      <div className="pf-audit-map__detail-title">
                        <h2>{groupTitle(group.key)}</h2>
                      </div>
                      <button
                        type="button"
                        className="pf-audit-map__detail-close"
                        aria-label={t("common.close")}
                        onClick={() => setDonutGroup(null)}
                      >
                        ×
                      </button>
                    </div>
                    <div className="pf-audit-map__detail-body">
                      <div className="pf-audit-map__stats">
                        <p className="pf-audit-map__detail-subtitle">{t("auditMap.lastCheckStats")}</p>
                        <div className="pf-audit-map__meter" role="img" aria-label={t("auditMap.lastCheckStats")}>
                          {STATUS_ORDER.map((status) => {
                            const count = counts[status] ?? 0;
                            if (!count || !total) return null;
                            return (
                              <i
                                key={status}
                                className={`pf-audit-map__meter-seg pf-audit-map__meter-seg--${status}`}
                                style={{ width: `${(count / total) * 100}%` }}
                              />
                            );
                          })}
                        </div>
                        <ul className="pf-audit-map__stats-list">
                          {STATUS_ORDER.map((status) => (
                            <li key={status}>
                              <span className={`pf-audit-map__dot pf-audit-map__dot--${status}`} aria-hidden />
                              <span>{t(`auditMap.legend.${status}`)}</span>
                              <strong>{counts[status] ?? 0}</strong>
                            </li>
                          ))}
                        </ul>
                      </div>
                      <ul className="pf-audit-map__host-list">
                        {group.nodes.map((node) => (
                          <li key={node.host_id}>
                            <button
                              type="button"
                              className="pf-audit-map__host-row"
                              aria-pressed={hostSelected(node.host_id, groupKey)}
                              onClick={() => openHost(node.host_id, groupKey)}
                            >
                              <span className={`pf-audit-map__dot pf-audit-map__dot--${node.status}`} aria-hidden />
                              <span className="pf-audit-map__host-row-name">{node.name}</span>
                              <span className="pf-audit-map__host-row-addr">
                                {node.ip || node.dns || node.hostname || "—"}
                              </span>
                              <span className={`pf-audit-map__pill pf-audit-map__pill--${node.status}`}>
                                {t(`auditMap.legend.${node.status}`)}
                              </span>
                            </button>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </aside>
                );
              })()
            : null}
        </div>
      ) : null}

      {data && nodes.length > 0 && display === "map" ? (
        <div className={active ? "pf-audit-map__stage pf-audit-map__stage--open" : "pf-audit-map__stage"}>
          <div className="pf-audit-map__map">
            <div className="pf-audit-map__maphead">
              <p className="pf-audit-map__hint">{t("auditMap.canvasHint")}</p>
              <div className="pf-audit-map__zoombar">
                <button type="button" aria-label={t("auditMap.zoomOut")} onClick={() => zoomBy(1 / 1.25)}>
                  −
                </button>
                <span aria-hidden>{Math.round(zoom * 100)}%</span>
                <button type="button" aria-label={t("auditMap.zoomIn")} onClick={() => zoomBy(1.25)}>
                  +
                </button>
                <button type="button" aria-label={t("auditMap.zoomReset")} onClick={resetCamera}>
                  {t("auditMap.zoomFit")}
                </button>
              </div>
            </div>
            <div
              ref={viewportRef}
              className="pf-audit-map__canvas"
              style={{ height: Math.max(480, Math.min(layout.height, 700)) }}
              onPointerDown={startPan}
            >
            <div
              className="pf-audit-map__world"
              style={{
                width: layout.width,
                height: layout.height,
                transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
              }}
            >
              {layout.frames.map((frame) => (
                <div
                  key={frame.key || "other"}
                  className={`pf-audit-map__group pf-audit-map__group--${frame.status}`}
                  style={{ top: frame.top, left: frame.left, width: frame.width, height: frame.height }}
                />
              ))}
              {layout.frames.map((frame) => (
                <button
                  key={`title-${frame.key || "other"}`}
                  type="button"
                  className={`pf-audit-map__group-title pf-audit-map__group-title--${frame.status}`}
                  style={{ top: frame.top + 12, left: frame.left + 14, maxWidth: frame.width - 28 }}
                  aria-label={`${groupTitle(frame.key)} · ${frame.count}`}
                  onClick={() => {
                    setFocus(focus === frame.key ? null : frame.key);
                  }}
                >
                  <span className="pf-audit-map__group-name">{groupTitle(frame.key)}</span>
                  <span className="pf-audit-map__group-count">{frame.count}</span>
                  {(["error", "fail"] as const)
                    .filter((key) => (frame.stats[key] ?? 0) > 0)
                    .map((key) => (
                      <span key={key} className={`pf-audit-map__mini pf-audit-map__mini--${key}`}>
                        {t(`auditMap.legend.${key}`)} {frame.stats[key]}
                      </span>
                    ))}
                </button>
              ))}
              {canvasNodes.map(({ groupKey, node }) => {
                  const placeId = `${groupKey}:${node.host_id}`;
                  const point = layout.placed.get(placeId) ?? { x: 0, y: 0 };
                  const label = view === "network" ? nodeLabel(node, labelMode) : node.name;
                  const sub = node.ip || node.dns || node.hostname || "";
                  const hint = `${node.name} · ${sub} · ${t(`auditMap.legend.${node.status}`)}`;
                  const extra = node.services.length > 1 ? ` +${node.services.length - 1}` : "";
                  return (
                    <button
                      key={placeId}
                      type="button"
                      className={`pf-audit-map__object pf-audit-map__object--${node.status}${
                        point.y < 130 ? " pf-audit-map__object--tip-below" : ""
                      }${hostSelected(node.host_id, groupKey) ? " pf-audit-map__object--active" : ""}${
                        trackedRun?.hostId === node.host_id &&
                        (runQuery.data?.status === "pending" || runQuery.data?.status === "running" || !runQuery.data)
                          ? " pf-audit-map__object--running"
                          : ""
                      }`}
                      style={{ left: point.x, top: point.y }}
                      aria-label={hint}
                      aria-pressed={hostSelected(node.host_id, groupKey)}
                      onClick={() => {
                        if (suppressClick.current) return;
                        openHost(node.host_id, groupKey);
                      }}
                      onPointerDown={(event) => startDrag(event, placeId)}
                    >
                      <span className="pf-audit-map__object-head">
                        <span className="pf-audit-map__glyph" aria-hidden>
                          <PlatformGlyph osType={node.os_type} />
                        </span>
                        <span className="pf-audit-map__object-name">{label}</span>
                        <span className={`pf-audit-map__dot pf-audit-map__dot--${node.status}`} aria-hidden />
                      </span>
                      <span className="pf-audit-map__object-sub">{sub || "—"}</span>
                      <span className="pf-audit-map__object-meta">
                        <span className="pf-audit-map__port">
                          {node.port}
                          {extra}
                        </span>
                      </span>
                      <span className="pf-audit-map__object-stats">
                        {node.checks && node.checks.pass + node.checks.fail + node.checks.error > 0
                          ? (["pass", "fail", "error"] as const)
                              .filter((status) => (node.checks?.[status] ?? 0) > 0)
                              .map((status) => (
                                <span key={status} className={`pf-audit-map__mini pf-audit-map__mini--${status}`}>
                                  {t(`auditMap.legend.${status}`)} {node.checks?.[status]}
                                </span>
                              ))
                          : null}
                      </span>
                      <span className="pf-audit-map__tip" aria-hidden>
                        <strong>{node.name}</strong>
                        <span>{sub || "—"}</span>
                        <span>
                          {t(`auditMap.legend.${node.status}`)} · {t("auditMap.port")} {node.port}
                          {extra}
                        </span>
                      </span>
                    </button>
                  );
              })}
            </div>
            </div>
          </div>

          {hostCard}
        </div>
      ) : null}
    </section>
  );
}
