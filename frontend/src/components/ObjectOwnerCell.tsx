import { useTranslation } from "../i18n/I18nProvider";
import { formatOwnerSub } from "../utils/objectOwner";

type ObjectOwnerCellProps = {
  ownerSub?: string | null;
};

export function ObjectOwnerCell({ ownerSub }: ObjectOwnerCellProps) {
  const { t } = useTranslation();

  if (!ownerSub) {
    return (
      <span className="pf-table__muted" title={t("objectRbac.sharedHint")}>
        {t("objectRbac.shared")}
      </span>
    );
  }

  const label = formatOwnerSub(ownerSub);
  return (
    <span className="pf-table__mono pf-object-owner" title={ownerSub}>
      {label || ownerSub}
    </span>
  );
}
