import type { DynamicHostFilter, HostCriticality } from "../api/client";
import { useTranslation } from "../i18n/I18nProvider";

export const EMPTY_DYNAMIC_FILTER: DynamicHostFilter = { tags: [], active_only: true };

export type TargetMode = "hosts" | "dynamic";

export function TargetModeToggle({
  mode,
  onChange,
  hostsLabel,
  dynamicLabel,
}: {
  mode: TargetMode;
  onChange: (mode: TargetMode) => void;
  hostsLabel: string;
  dynamicLabel: string;
}) {
  return (
    <div className="pf-segmented pf-segmented--job-target" role="tablist">
      {(["hosts", "dynamic"] as const).map((item) => (
        <button
          key={item}
          type="button"
          role="tab"
          aria-selected={mode === item}
          className={`pf-segmented__option${mode === item ? " is-active" : ""}`}
          onClick={() => onChange(item)}
        >
          <span className="pf-segmented__label">{item === "hosts" ? hostsLabel : dynamicLabel}</span>
        </button>
      ))}
    </div>
  );
}

type DynamicHostFilterFieldsProps = {
  value: DynamicHostFilter;
  onChange: (value: DynamicHostFilter) => void;
  idPrefix?: string;
};

export function DynamicHostFilterFields({
  value,
  onChange,
  idPrefix = "dynamic-filter",
}: DynamicHostFilterFieldsProps) {
  const { t } = useTranslation();
  const patch = (next: Partial<DynamicHostFilter>) => onChange({ ...value, ...next });
  const text = (v: string | null | undefined) => v ?? "";

  return (
    <div className="pf-host-picker__filters">
      <div className="pf-form__group">
        <label htmlFor={`${idPrefix}-tags`}>{t("jobs.dynamicTags")}</label>
        <input
          id={`${idPrefix}-tags`}
          className="pf-input"
          value={value.tags.join(", ")}
          onChange={(e) =>
            patch({
              tags: e.target.value
                .split(",")
                .map((tag) => tag.trim())
                .filter(Boolean),
            })
          }
        />
      </div>
      <div className="pf-form__group">
        <label htmlFor={`${idPrefix}-search`}>{t("jobs.dynamicSearch")}</label>
        <input
          id={`${idPrefix}-search`}
          className="pf-input"
          value={text(value.search)}
          onChange={(e) => patch({ search: e.target.value || null })}
        />
      </div>
      <div className="pf-form__group">
        <label htmlFor={`${idPrefix}-site`}>{t("hosts.site")}</label>
        <input
          id={`${idPrefix}-site`}
          className="pf-input"
          value={text(value.site)}
          onChange={(e) => patch({ site: e.target.value || null })}
        />
      </div>
      <div className="pf-form__group">
        <label htmlFor={`${idPrefix}-environment`}>{t("hosts.environment")}</label>
        <input
          id={`${idPrefix}-environment`}
          className="pf-input"
          value={text(value.environment)}
          onChange={(e) => patch({ environment: e.target.value || null })}
        />
      </div>
      <div className="pf-form__group">
        <label htmlFor={`${idPrefix}-criticality`}>{t("hosts.criticality")}</label>
        <select
          id={`${idPrefix}-criticality`}
          className="pf-select"
          value={value.criticality ?? "all"}
          onChange={(e) =>
            patch({
              criticality: e.target.value === "all" ? null : (e.target.value as HostCriticality),
            })
          }
        >
          <option value="all">{t("hosts.listCriticalityAll")}</option>
          <option value="low">{t("hosts.criticalityLow")}</option>
          <option value="medium">{t("hosts.criticalityMedium")}</option>
          <option value="high">{t("hosts.criticalityHigh")}</option>
        </select>
      </div>
      <div className="pf-form__group pf-form__group--check">
        <span className="pf-form__group-check-label" aria-hidden="true">
          &nbsp;
        </span>
        <label className="pf-checkbox">
          <input
            type="checkbox"
            className="pf-checkbox-control"
            checked={value.active_only}
            onChange={(e) => patch({ active_only: e.target.checked })}
          />
          {t("jobs.dynamicActiveOnly")}
        </label>
      </div>
    </div>
  );
}
