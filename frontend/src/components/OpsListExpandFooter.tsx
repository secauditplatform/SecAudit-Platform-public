import { Button } from "./ui/Button";
import { useTranslation } from "../i18n/I18nProvider";
import { OPS_LIST_INITIAL, OPS_LIST_MAX } from "../utils/opsListLimit";

type OpsListExpandFooterProps = {
  shown: number;
  total: number;
  expanded: boolean;
  onToggle: () => void;
};

export function OpsListExpandFooter({ shown, total, expanded, onToggle }: OpsListExpandFooterProps) {
  const { t } = useTranslation();
  const cappedTotal = Math.min(total, OPS_LIST_MAX);
  const canExpand = cappedTotal > OPS_LIST_INITIAL;

  if (total === 0) return null;

  const moreCount = cappedTotal - OPS_LIST_INITIAL;

  return (
    <div className="pf-ops-list-footer">
      <p className="pf-filters__summary">
        {total > OPS_LIST_MAX
          ? t("jobs.listShowingCapped", { shown, total, max: OPS_LIST_MAX })
          : t("jobs.listShowing", { shown, total })}
      </p>
      {canExpand ? (
        <Button variant="link" className="pf-btn--sm" type="button" onClick={onToggle}>
          {expanded
            ? t("jobs.showLessRows")
            : t("jobs.showMoreRows", { count: moreCount })}
        </Button>
      ) : null}
    </div>
  );
}
