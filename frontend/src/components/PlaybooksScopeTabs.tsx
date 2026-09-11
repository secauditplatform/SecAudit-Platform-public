import { IconLinux, IconNetwork, IconWindows } from "./ui/Icons";
import { useTranslation } from "../i18n/I18nProvider";

export type PlaybookPlatformScope = "linux" | "windows" | "network";
export type PlaybookPageView = "catalog" | "jobs";

const PLATFORMS: PlaybookPlatformScope[] = ["linux", "windows", "network"];

const PLATFORM_LABEL: Record<PlaybookPlatformScope, string> = {
  linux: "playbooks.scopeLinux",
  windows: "playbooks.scopeWindows",
  network: "playbooks.scopeNetwork",
};

const PLATFORM_DESCRIPTION: Record<PlaybookPlatformScope, string> = {
  linux: "playbooks.scopeLinuxDescription",
  windows: "playbooks.scopeWindowsDescription",
  network: "playbooks.scopeNetworkDescription",
};

const PLATFORM_ICON: Record<PlaybookPlatformScope, typeof IconLinux> = {
  linux: IconLinux,
  windows: IconWindows,
  network: IconNetwork,
};

type PlaybooksPageHeaderProps = {
  platform: PlaybookPlatformScope;
  onPlatformChange: (platform: PlaybookPlatformScope) => void;
  pageView: PlaybookPageView;
  onPageViewChange: (view: PlaybookPageView) => void;
};

export function PlaybooksPageHeader({
  platform,
  onPlatformChange,
  pageView,
  onPageViewChange,
}: PlaybooksPageHeaderProps) {
  const { t } = useTranslation();

  const viewTabs: { id: PlaybookPageView; labelKey: string }[] = [
    { id: "catalog", labelKey: "playbooks.list" },
    { id: "jobs", labelKey: "playbooks.jobsList" },
  ];

  return (
    <div className="pf-playbooks-header">
      <header className="pf-page-header">
        <div className="pf-page-header__main">
          <h1 className="pf-page-header__title">{t("playbooks.title")}</h1>
          <p className="pf-page-header__description">{t(PLATFORM_DESCRIPTION[platform])}</p>
        </div>
      </header>

      <nav className="pf-playbooks-platform-tabs" aria-label={t("playbooks.scopeTabsAria")}>
        <div className="pf-segmented pf-segmented--platform" role="tablist">
          {PLATFORMS.map((item) => {
            const Icon = PLATFORM_ICON[item];
            const isActive = platform === item;
            return (
              <button
                key={item}
                type="button"
                role="tab"
                aria-selected={isActive}
                data-platform={item}
                className={`pf-segmented__option${isActive ? " is-active" : ""}`}
                onClick={() => onPlatformChange(item)}
              >
                <span className="pf-segmented__icon" aria-hidden>
                  <Icon />
                </span>
                <span className="pf-segmented__label">{t(PLATFORM_LABEL[item])}</span>
              </button>
            );
          })}
        </div>
      </nav>

      <nav className="pf-playbooks-view-tabs" aria-label={t("playbooks.viewTabsAria")}>
        <div className="pf-segmented pf-segmented--scope" role="tablist">
          {viewTabs.map((tab) => {
            const isActive = pageView === tab.id;
            return (
              <button
                key={tab.id}
                type="button"
                role="tab"
                aria-selected={isActive}
                className={`pf-segmented__option${isActive ? " is-active" : ""}`}
                onClick={() => onPageViewChange(tab.id)}
              >
                <span className="pf-segmented__label">{t(tab.labelKey)}</span>
              </button>
            );
          })}
        </div>
      </nav>
    </div>
  );
}
