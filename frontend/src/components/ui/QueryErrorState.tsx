import { useTranslation } from "../../i18n/I18nProvider";
import { Button } from "./Button";

type QueryErrorStateProps = {
  title: string;
  message?: string;
  onRetry?: () => void;
};

export function QueryErrorState({ title, message, onRetry }: QueryErrorStateProps) {
  const { t } = useTranslation();

  return (
    <div className="pf-empty-state pf-empty-state--error">
      <div className="pf-empty-state__icon">
        <svg viewBox="0 0 512 512" fill="currentColor" aria-hidden>
          <path d="M256 8C119 8 8 119 8 256s111 248 248 248 248-111 248-248S393 8 256 8zm0 448c-110.5 0-200-89.5-200-200S145.5 56 256 56s200 89.5 200 200-89.5 200-200 200zm32-132a16 16 0 00-16 16v48a16 16 0 0016 16h32a16 16 0 0016-16v-48a16 16 0 00-16-16h-32zM256 96c-17.7 0-32 14.3-32 32v160c0 17.7 14.3 32 32 32s32-14.3 32-32V128c0-17.7-14.3-32-32-32z" />
        </svg>
      </div>
      <h3 className="pf-empty-state__title">{title}</h3>
      {message && <p className="pf-empty-state__description">{message}</p>}
      {onRetry && (
        <div className="pf-empty-state__actions">
          <Button variant="secondary" className="pf-btn--sm" onClick={onRetry}>
            {t("common.retry")}
          </Button>
        </div>
      )}
    </div>
  );
}
