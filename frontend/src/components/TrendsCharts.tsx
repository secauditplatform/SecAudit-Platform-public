import { useEffect, useId, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import { type ComplianceTimelinePoint } from "../api/client";
import { complianceColor } from "./InsightSummary";
import { useTranslation } from "../i18n/I18nProvider";

const TIMELINE_ASPECT = 320 / 720;
const MIN_VIEW_RATIO = 0.14;
const ZOOM_FACTOR = 1.16;
const TARGET_COMPLIANCE = 80;
const COMPLIANCE_BAND_MID = 50;
const DEFAULT_Y_MAX = 100;
const Y_GUTTER = 52;
const PLOT_Y_INSET = 14;
const DOT_RADIUS = 6.5;

type PlotView = { x: number; w: number };
type ChartCoord = { x: number; y: number; point: ComplianceTimelinePoint };

function computeChartYMax(values: number[]): number {
  const peak = values.length === 0 ? 0 : Math.max(...values);
  if (peak <= DEFAULT_Y_MAX) return DEFAULT_Y_MAX;

  const withHeadroom = peak * 1.06 + 2;
  if (withHeadroom <= 105) return 105;
  if (withHeadroom <= 110) return 110;
  if (withHeadroom <= 115) return 115;
  if (withHeadroom <= 120) return 120;
  if (withHeadroom <= 125) return 125;
  if (withHeadroom <= 130) return 130;
  if (withHeadroom <= 150) return 150;
  if (withHeadroom <= 175) return 175;
  if (withHeadroom <= 200) return 200;
  return Math.ceil(withHeadroom / 25) * 25;
}

function percentToY(percent: number, yMax: number, padTop: number, chartH: number): number {
  const innerH = Math.max(1, chartH - PLOT_Y_INSET * 2);
  return padTop + PLOT_Y_INSET + innerH - (percent / yMax) * innerH;
}

function buildYTicks(yMax: number): number[] {
  if (yMax <= DEFAULT_Y_MAX) return [0, 25, 50, 75, 100];

  const ticks = new Set<number>([0, COMPLIANCE_BAND_MID, TARGET_COMPLIANCE, 100, yMax]);
  const step = yMax <= 120 ? 10 : yMax <= 150 ? 25 : 50;
  for (let value = step; value < yMax; value += step) {
    ticks.add(value);
  }
  return [...ticks].sort((a, b) => a - b);
}

function formatYTick(value: number): string {
  return Number.isInteger(value) ? `${value}%` : `${value.toFixed(1)}%`;
}

function complianceBarClass(percent: number): string {
  if (percent >= 80) return "pf-trends-bar--good";
  if (percent >= 50) return "pf-trends-bar--warn";
  return "pf-trends-bar--bad";
}

function fullPlotView(chartW: number): PlotView {
  return { x: 0, w: chartW };
}

function clampPlotView(view: PlotView, chartW: number): PlotView {
  const minW = chartW * MIN_VIEW_RATIO;
  const w = Math.min(chartW, Math.max(minW, view.w));
  const x = Math.min(chartW - w, Math.max(0, view.x));
  return { x, w };
}

function isFullPlotView(view: PlotView, chartW: number): boolean {
  return view.x <= 0.5 && Math.abs(view.w - chartW) < 1;
}

function zoomPlotView(view: PlotView, chartW: number, factor: number, focalX: number): PlotView {
  const nextW = view.w / factor;
  const ratioX = (focalX - view.x) / view.w;
  return clampPlotView({ x: focalX - ratioX * nextW, w: nextW }, chartW);
}

function clientToPlotX(clientX: number, rect: DOMRect, view: PlotView): number {
  return view.x + ((clientX - rect.left) / rect.width) * view.w;
}

function smoothLinePath(coords: { x: number; y: number }[]): string {
  if (coords.length === 0) return "";
  if (coords.length === 1) return `M ${coords[0].x} ${coords[0].y}`;
  if (coords.length === 2) {
    return `M ${coords[0].x} ${coords[0].y} L ${coords[1].x} ${coords[1].y}`;
  }

  let path = `M ${coords[0].x} ${coords[0].y}`;
  for (let i = 0; i < coords.length - 1; i++) {
    const p0 = coords[Math.max(0, i - 1)];
    const p1 = coords[i];
    const p2 = coords[i + 1];
    const p3 = coords[Math.min(coords.length - 1, i + 2)];

    const cp1x = p1.x + (p2.x - p0.x) / 6;
    const cp1y = p1.y + (p2.y - p0.y) / 6;
    const cp2x = p2.x - (p3.x - p1.x) / 6;
    const cp2y = p2.y - (p3.y - p1.y) / 6;

    path += ` C ${cp1x} ${cp1y}, ${cp2x} ${cp2y}, ${p2.x} ${p2.y}`;
  }
  return path;
}

function smoothAreaPath(coords: { x: number; y: number }[], baseY: number): string {
  if (coords.length === 0) return "";
  const line = smoothLinePath(coords);
  return `${line} L ${coords[coords.length - 1].x} ${baseY} L ${coords[0].x} ${baseY} Z`;
}

function pickXLabelIndices(
  coords: ChartCoord[],
  plotView: PlotView,
  maxLabels: number
): number[] {
  if (coords.length === 0) return [];
  const visible = coords
    .map((coord, index) => ({ index, coord }))
    .filter(({ coord }) => coord.x >= plotView.x - 1 && coord.x <= plotView.x + plotView.w + 1);

  if (visible.length === 0) {
    return coords.length <= maxLabels
      ? coords.map((_, index) => index)
      : [0, Math.floor((coords.length - 1) / 2), coords.length - 1];
  }

  const target = Math.min(maxLabels, visible.length);
  if (target === 1) return [visible[0].index];
  if (visible.length <= target) return visible.map(({ index }) => index);

  const picked: number[] = [];
  for (let i = 0; i < target; i++) {
    const slot = visible[Math.round((i / (target - 1)) * (visible.length - 1))];
    if (!picked.includes(slot.index)) picked.push(slot.index);
  }
  return picked;
}

export type HorizontalBarItem = {
  key: string | number;
  label: string;
  value: number;
};

export function HorizontalBarChart({
  items,
  ariaLabel,
}: {
  items: HorizontalBarItem[];
  ariaLabel: string;
}) {
  const max = Math.max(...items.map((item) => item.value), 1);

  return (
    <div className="pf-trends-chart pf-trends-chart--horizontal" role="img" aria-label={ariaLabel}>
      {items.map((item) => {
        const widthPct = (item.value / max) * 100;
        const showInlineLabel = widthPct >= 22;

        return (
          <div key={item.key} className="pf-trends-bar-row">
            <span className="pf-trends-bar-row__label" title={item.label}>
              {item.label}
            </span>
            <div className="pf-trends-bar-row__track">
              <span
                className={`pf-trends-bar ${complianceBarClass(item.value)}`}
                style={{ width: `${widthPct}%` }}
              >
                {showInlineLabel && <span className="pf-trends-bar__label">{item.value}%</span>}
              </span>
            </div>
            <span className="pf-trends-bar-row__value">{item.value}%</span>
          </div>
        );
      })}
    </div>
  );
}

export function TimelineChart({
  points,
  ariaLabel,
  dateLocale,
  enableZoom = true,
  avgCompliance,
}: {
  points: ComplianceTimelinePoint[];
  ariaLabel: string;
  dateLocale: string;
  enableZoom?: boolean;
  avgCompliance?: number;
}) {
  const { t } = useTranslation();
  const shellRef = useRef<HTMLDivElement>(null);
  const plotWrapRef = useRef<HTMLDivElement>(null);
  const plotSvgRef = useRef<SVGSVGElement>(null);
  const panRef = useRef<{
    pointerId: number;
    startX: number;
    plotView: PlotView;
  } | null>(null);
  const gradientUid = useId().replace(/:/g, "");
  const clipUid = useId().replace(/:/g, "");
  const lineGradientId = `pf-trends-line-gradient-${gradientUid}`;
  const areaGradientId = `pf-trends-area-gradient-${gradientUid}`;
  const clipId = `pf-trends-clip-${clipUid}`;
  const userZoomedRef = useRef(false);

  const [hoveredRunId, setHoveredRunId] = useState<number | null>(null);
  const [plotWidth, setPlotWidth] = useState(668);
  const [plotView, setPlotView] = useState<PlotView>(() => fullPlotView(668));
  const [isPanning, setIsPanning] = useState(false);

  const height = Math.max(260, Math.round(plotWidth * TIMELINE_ASPECT));
  const padTop = 22;
  const padBottom = 38;
  const chartH = height - padTop - padBottom;
  const plotRadius = 6;

  useEffect(() => {
    const element = plotWrapRef.current;
    if (!element) return;

    const updateWidth = () => {
      const nextWidth = Math.max(240, Math.round(element.clientWidth));
      setPlotWidth((current) => (current === nextWidth ? current : nextWidth));
    };

    updateWidth();
    const observer = new ResizeObserver(updateWidth);
    observer.observe(element);
    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    userZoomedRef.current = false;
    setPlotView(fullPlotView(plotWidth));
  }, [points]);

  useEffect(() => {
    if (userZoomedRef.current) {
      setPlotView((current) => clampPlotView(current, plotWidth));
      return;
    }
    setPlotView(fullPlotView(plotWidth));
  }, [plotWidth]);

  useEffect(() => {
    const element = plotWrapRef.current;
    if (!element || !enableZoom) return;

    const onWheel = (event: WheelEvent) => {
      event.preventDefault();
      userZoomedRef.current = true;
      const rect = element.getBoundingClientRect();
      setPlotView((current) => {
        const focalX = clientToPlotX(event.clientX, rect, current);
        const factor = event.deltaY < 0 ? ZOOM_FACTOR : 1 / ZOOM_FACTOR;
        return zoomPlotView(current, plotWidth, factor, focalX);
      });
    };

    element.addEventListener("wheel", onWheel, { passive: false });
    return () => element.removeEventListener("wheel", onWheel);
  }, [enableZoom, plotWidth]);

  if (points.length === 0) return null;

  const sortedPoints = [...points].sort(
    (a, b) => new Date(a.finished_at).getTime() - new Date(b.finished_at).getTime()
  );

  const complianceValues = sortedPoints.map((point) => point.compliance_percent);
  const yMax = computeChartYMax(complianceValues);
  const yTicks = buildYTicks(yMax);
  const exceedsCap = yMax > DEFAULT_Y_MAX;
  const isZoomed = enableZoom && !isFullPlotView(plotView, plotWidth);

  const yAt = (percent: number) => percentToY(percent, yMax, padTop, chartH);
  const plotBottomY = yAt(0);

  const coords: ChartCoord[] = sortedPoints.map((point, index) => {
    const x =
      sortedPoints.length === 1 ? plotWidth / 2 : (index / (sortedPoints.length - 1)) * plotWidth;
    const y = yAt(point.compliance_percent);
    return { x, y, point };
  });

  const linePath = smoothLinePath(coords);
  const areaPath = smoothAreaPath(coords, plotBottomY);

  const maxLabels = plotView.w < plotWidth * 0.35 ? 8 : plotView.w < plotWidth * 0.65 ? 6 : 5;
  const xLabelIndices = pickXLabelIndices(coords, plotView, maxLabels);

  const hovered = coords.find((c) => c.point.run_id === hoveredRunId);
  const avgY = avgCompliance != null ? yAt(avgCompliance) : null;
  const targetY = yAt(TARGET_COMPLIANCE);
  const capY = yAt(Math.min(100, yMax));
  const zoneY80 = yAt(TARGET_COMPLIANCE);
  const zoneY50 = yAt(COMPLIANCE_BAND_MID);
  const zoneTopY = yAt(yMax);

  const resetZoom = () => {
    userZoomedRef.current = false;
    setPlotView(fullPlotView(plotWidth));
  };

  const handlePointerDown = (event: ReactPointerEvent<SVGSVGElement>) => {
    if (!enableZoom || !isZoomed) return;
    if ((event.target as HTMLElement).closest('[role="button"]')) return;

    userZoomedRef.current = true;
    panRef.current = {
      pointerId: event.pointerId,
      startX: event.clientX,
      plotView: { ...plotView },
    };
    setIsPanning(true);
    event.currentTarget.setPointerCapture(event.pointerId);
  };

  const handlePointerMove = (event: ReactPointerEvent<SVGSVGElement>) => {
    const pan = panRef.current;
    if (!pan || pan.pointerId !== event.pointerId) return;

    const rect = plotWrapRef.current?.getBoundingClientRect();
    if (!rect) return;

    const deltaPlotX = (event.clientX - pan.startX) * (pan.plotView.w / rect.width);

    setPlotView(
      clampPlotView(
        {
          ...pan.plotView,
          x: pan.plotView.x - deltaPlotX,
        },
        plotWidth
      )
    );
  };

  const endPan = (event: ReactPointerEvent<SVGSVGElement>) => {
    const pan = panRef.current;
    if (!pan || pan.pointerId !== event.pointerId) return;

    panRef.current = null;
    setIsPanning(false);
    if (event.currentTarget.hasPointerCapture(event.pointerId)) {
      event.currentTarget.releasePointerCapture(event.pointerId);
    }
  };

  const tooltipAbove = hovered ? hovered.y > padTop + chartH * 0.35 : true;

  return (
    <div
      ref={shellRef}
      className={`pf-trends-chart pf-trends-chart--timeline pf-trends-timeline__shell${enableZoom ? " pf-trends-chart--zoomable" : ""}`}
    >
      {isZoomed ? (
        <button type="button" className="pf-trends-timeline__reset" onClick={resetZoom}>
          {t("trends.resetZoom")}
        </button>
      ) : null}

      <div className="pf-trends-timeline__frame">
        <svg
          className="pf-trends-timeline__y-axis"
          viewBox={`0 0 ${Y_GUTTER} ${height}`}
          width={Y_GUTTER}
          height={height}
          aria-hidden
        >
          <rect x={0} y={padTop} width={Y_GUTTER} height={chartH} className="pf-trends-timeline__y-bg" />
          {yTicks.map((tick) => {
            const y = yAt(tick);
            const emphasize = tick === yMax || (tick === 100 && exceedsCap) || tick === TARGET_COMPLIANCE;
            return (
              <g key={`y-${tick}`}>
                <line x1={Y_GUTTER - 6} y1={y} x2={Y_GUTTER} y2={y} className="pf-trends-timeline__y-tick-mark" />
                <text
                  x={Y_GUTTER - 10}
                  y={y + 4}
                  textAnchor="end"
                  className={`pf-trends-timeline__tick${emphasize ? " pf-trends-timeline__tick--emphasis" : ""}`}
                >
                  {formatYTick(tick)}
                </text>
              </g>
            );
          })}
        </svg>

        <div ref={plotWrapRef} className="pf-trends-timeline__plot-wrap">
          <svg
            ref={plotSvgRef}
            viewBox={`${plotView.x} 0 ${plotView.w} ${height}`}
            className={`pf-trends-timeline pf-trends-timeline__plot${isPanning ? " is-panning" : ""}${isZoomed ? " is-zoomed" : ""}`}
            role="img"
            aria-label={ariaLabel}
            preserveAspectRatio="none"
            onPointerDown={handlePointerDown}
            onPointerMove={handlePointerMove}
            onPointerUp={endPan}
            onPointerCancel={endPan}
            onDoubleClick={enableZoom ? resetZoom : undefined}
          >
            <defs>
              <clipPath id={clipId}>
                <rect
                  x={0}
                  y={padTop - DOT_RADIUS}
                  width={plotWidth}
                  height={chartH + DOT_RADIUS * 2}
                  rx={plotRadius}
                  ry={plotRadius}
                />
              </clipPath>
              <linearGradient id={lineGradientId} x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor="var(--pf-blue-400)" />
                <stop offset="100%" stopColor="var(--pf-cyan-400)" />
              </linearGradient>
              <linearGradient id={areaGradientId} x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="var(--timeline-area-top)" />
                <stop offset="100%" stopColor="var(--timeline-area-bottom)" />
              </linearGradient>
              <linearGradient id={`${gradientUid}-zone-overflow`} x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="var(--timeline-zone-overflow-a)" />
                <stop offset="100%" stopColor="var(--timeline-zone-overflow-b)" />
              </linearGradient>
              <linearGradient id={`${gradientUid}-zone-high`} x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="var(--timeline-zone-high-a)" />
                <stop offset="100%" stopColor="var(--timeline-zone-high-b)" />
              </linearGradient>
              <linearGradient id={`${gradientUid}-zone-mid`} x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="var(--timeline-zone-mid-a)" />
                <stop offset="100%" stopColor="var(--timeline-zone-mid-b)" />
              </linearGradient>
              <linearGradient id={`${gradientUid}-zone-low`} x1="0%" y1="0%" x2="0%" y2="100%">
                <stop offset="0%" stopColor="var(--timeline-zone-low-a)" />
                <stop offset="100%" stopColor="var(--timeline-zone-low-b)" />
              </linearGradient>
            </defs>

            <rect
              x={0}
              y={padTop}
              width={plotWidth}
              height={chartH}
              rx={plotRadius}
              ry={plotRadius}
              className="pf-trends-timeline__plot-bg"
            />

            <g clipPath={`url(#${clipId})`}>
              {exceedsCap ? (
                <rect
                  x={0}
                  y={zoneTopY}
                  width={plotWidth}
                  height={Math.max(0, capY - zoneTopY)}
                  fill={`url(#${gradientUid}-zone-overflow)`}
                />
              ) : null}
              <rect
                x={0}
                y={capY}
                width={plotWidth}
                height={Math.max(0, zoneY80 - capY)}
                fill={`url(#${gradientUid}-zone-high)`}
              />
              <rect
                x={0}
                y={zoneY80}
                width={plotWidth}
                height={Math.max(0, zoneY80 - zoneY50)}
                fill={`url(#${gradientUid}-zone-mid)`}
              />
              <rect
                x={0}
                y={zoneY50}
                width={plotWidth}
                height={Math.max(0, plotBottomY - zoneY50)}
                fill={`url(#${gradientUid}-zone-low)`}
              />

              {exceedsCap && capY > padTop ? (
                <line x1={0} y1={capY} x2={plotWidth} y2={capY} className="pf-trends-timeline__zone-line pf-trends-timeline__zone-line--cap" />
              ) : null}
              <line x1={0} y1={zoneY80} x2={plotWidth} y2={zoneY80} className="pf-trends-timeline__zone-line pf-trends-timeline__zone-line--high" />
              <line x1={0} y1={zoneY50} x2={plotWidth} y2={zoneY50} className="pf-trends-timeline__zone-line pf-trends-timeline__zone-line--mid" />

              {yTicks.map((tick) => {
                const y = yAt(tick);
                const isCap = tick === 100 && exceedsCap;
                const isTarget = tick === TARGET_COMPLIANCE;
                return (
                  <line
                    key={tick}
                    x1={0}
                    y1={y}
                    x2={plotWidth}
                    y2={y}
                    className={`pf-trends-timeline__grid${
                      isCap ? " pf-trends-timeline__grid--cap" : isTarget ? " pf-trends-timeline__grid--target" : ""
                    }`}
                  />
                );
              })}

              {avgY != null ? (
                <g className="pf-trends-timeline__avg">
                  <line x1={0} y1={avgY} x2={plotWidth} y2={avgY} className="pf-trends-timeline__avg-line" />
                  <text x={plotWidth - 6} y={avgY - 5} textAnchor="end" className="pf-trends-timeline__avg-label">
                    {t("trends.chartAvgShort", { value: Math.round(avgCompliance!) })}
                  </text>
                </g>
              ) : null}

              {exceedsCap ? (
                <line x1={0} y1={capY} x2={plotWidth} y2={capY} className="pf-trends-timeline__cap-line" />
              ) : null}

              <line x1={0} y1={targetY} x2={plotWidth} y2={targetY} className="pf-trends-timeline__target" />

              {areaPath && <path d={areaPath} className="pf-trends-timeline__area" fill={`url(#${areaGradientId})`} />}
              <path d={linePath} className="pf-trends-timeline__line" fill="none" stroke={`url(#${lineGradientId})`} />
            </g>

            <line x1={0} y1={plotBottomY} x2={plotWidth} y2={plotBottomY} className="pf-trends-timeline__axis" />

            <text x={plotWidth - 4} y={targetY - 5} textAnchor="end" className="pf-trends-timeline__target-label">
              {t("trends.chartTarget")}
            </text>

            {exceedsCap ? (
              <text x={plotWidth - 4} y={capY - 5} textAnchor="end" className="pf-trends-timeline__cap-label">
                100%
              </text>
            ) : null}

            {xLabelIndices.map((index) => {
              const { x, point } = coords[index];
              return (
                <text key={point.run_id} x={x} y={height - 10} textAnchor="middle" className="pf-trends-timeline__x-label">
                  {new Date(point.finished_at).toLocaleDateString(dateLocale, {
                    day: "2-digit",
                    month: "short",
                  })}
                </text>
              );
            })}

            {hovered ? (
              <line
                x1={hovered.x}
                y1={yAt(yMax)}
                x2={hovered.x}
                y2={plotBottomY}
                className="pf-trends-timeline__crosshair"
              />
            ) : null}

            {coords.map(({ x, y, point }) => {
              const active = hoveredRunId === point.run_id;
              return (
                <g
                  key={point.run_id}
                  onMouseEnter={() => setHoveredRunId(point.run_id)}
                  onMouseLeave={() => setHoveredRunId(null)}
                  onFocus={() => setHoveredRunId(point.run_id)}
                  onBlur={() => setHoveredRunId(null)}
                  tabIndex={0}
                  role="button"
                  aria-label={`#${point.run_id} ${point.compliance_percent}%`}
                >
                  {active && <circle cx={x} cy={y} r={12} className="pf-trends-timeline__dot-halo" />}
                  <circle
                    cx={x}
                    cy={y}
                    r={active ? DOT_RADIUS : 4.5}
                    fill={complianceColor(point.compliance_percent)}
                    className={`pf-trends-timeline__dot${active ? " pf-trends-timeline__dot--active" : ""}`}
                  />
                </g>
              );
            })}
          </svg>

          {hovered && (
            <div
              className={`pf-trends-timeline__tooltip${tooltipAbove ? "" : " pf-trends-timeline__tooltip--below"}`}
              style={{
                left: `${((hovered.x - plotView.x) / plotView.w) * 100}%`,
                top: `${(hovered.y / height) * 100}%`,
              }}
            >
              <span className="pf-trends-timeline__tooltip-run">#{hovered.point.run_id}</span>
              <span
                className="pf-trends-timeline__tooltip-value"
                style={{ color: complianceColor(hovered.point.compliance_percent) }}
              >
                {hovered.point.compliance_percent}%
              </span>
              <span className="pf-trends-timeline__tooltip-meta">
                {t("trends.passFailShort")}: {hovered.point.passed} / {hovered.point.failed}
              </span>
              <span className="pf-trends-timeline__tooltip-date">
                {new Date(hovered.point.finished_at).toLocaleString(dateLocale)}
              </span>
              <span className="pf-trends-timeline__tooltip-job">{hovered.point.job_name}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
