import { useTranslation } from "../../i18n/I18nProvider";

export function Spinner() {
  const { t } = useTranslation();
  return (
    <div className="pf-spinner" role="status" aria-label={t("common.loading")}>
      <span className="pf-spinner__icon" />
    </div>
  );
}
