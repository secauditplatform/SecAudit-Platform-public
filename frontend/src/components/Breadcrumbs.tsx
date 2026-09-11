import { Link, useLocation } from "react-router-dom";
import { ROUTE_BREADCRUMBS } from "../navigation/appNavigation";
import { useTranslation } from "../i18n/I18nProvider";
import { scrollAppToTop } from "./ScrollToTop";

export function Breadcrumbs() {
  const { pathname } = useLocation();
  const { t } = useTranslation();
  const config = ROUTE_BREADCRUMBS[pathname];

  if (!config) return null;

  return (
    <nav className="pf-breadcrumbs" aria-label={t("nav.breadcrumbsAria")}>
      <ol className="pf-breadcrumbs__list">
        <li className="pf-breadcrumbs__item">
          <Link to="/" className="pf-breadcrumbs__link" onClick={() => scrollAppToTop()}>
            SecAudit
          </Link>
        </li>
        {config.groupKey ? (
          <li className="pf-breadcrumbs__item">
            <span className="pf-breadcrumbs__sep" aria-hidden>
              /
            </span>
            <span className="pf-breadcrumbs__group">{t(config.groupKey)}</span>
          </li>
        ) : null}
        <li className="pf-breadcrumbs__item">
          <span className="pf-breadcrumbs__sep" aria-hidden>
            /
          </span>
          <span className="pf-breadcrumbs__current" aria-current="page">
            {t(config.pageKey)}
          </span>
        </li>
      </ol>
    </nav>
  );
}
