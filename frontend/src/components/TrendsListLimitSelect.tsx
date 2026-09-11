import { useTranslation } from "../i18n/I18nProvider";
import { TRENDS_LIST_LIMIT_OPTIONS, type TrendsListLimit } from "../utils/trendsListLimit";

export function TrendsListLimitSelect({
  value,
  onChange,
  className,
}: {
  value: TrendsListLimit;
  onChange: (next: TrendsListLimit) => void;
  className?: string;
}) {
  const { t } = useTranslation();

  return (
    <label className={`pf-trends-list-limit${className ? ` ${className}` : ""}`}>
      <span className="pf-trends-list-limit__label">
        {t("platformOverview.timelineInfographic.recentLimitLabel")}
      </span>
      <select
        className="pf-select pf-trends-list-limit__select"
        value={value}
        onChange={(event) => {
          const next = Number(event.target.value) as TrendsListLimit;
          onChange(next);
        }}
        aria-label={t("platformOverview.timelineInfographic.recentLimitAria")}
      >
        {TRENDS_LIST_LIMIT_OPTIONS.map((option) => (
          <option key={option} value={option}>
            {t("platformOverview.timelineInfographic.recentMeta", { count: option })}
          </option>
        ))}
      </select>
    </label>
  );
}
