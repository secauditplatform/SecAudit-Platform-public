import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useAuth } from "../auth/AuthProvider";
import { useTranslation } from "../i18n/I18nProvider";
import { useTheme, type ThemePreference } from "../theme/ThemeProvider";
import { LanguagePicker } from "./LanguagePicker";
import { NotificationsSettings } from "./NotificationsSettings";
import {
  IconBell,
  IconCheck,
  IconDisplay,
  IconMoon,
  IconSettings,
  IconSun,
} from "./ui/Icons";

const THEME_OPTIONS: Array<{
  id: ThemePreference;
  icon: ReactNode;
  labelKey: "settings.themeLight" | "settings.themeDark" | "settings.themeSystem";
  hintKey: "settings.themeLightHint" | "settings.themeDarkHint" | "settings.themeSystemHint";
}> = [
  {
    id: "light",
    icon: <IconSun />,
    labelKey: "settings.themeLight",
    hintKey: "settings.themeLightHint",
  },
  {
    id: "dark",
    icon: <IconMoon />,
    labelKey: "settings.themeDark",
    hintKey: "settings.themeDarkHint",
  },
  {
    id: "system",
    icon: <IconDisplay />,
    labelKey: "settings.themeSystem",
    hintKey: "settings.themeSystemHint",
  },
];

type TabId = "general" | "notifications";

export function SettingsPanel() {
  const { isAuditorPortal } = useAuth();
  const { preference, setPreference } = useTheme();
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [tab, setTab] = useState<TabId>("general");
  const dialogRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const showNotifications = !isAuditorPortal;

  useEffect(() => {
    if (!open) return;
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("keydown", onKeyDown);
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = "";
    };
  }, [open]);

  useEffect(() => {
    if (!open) return;
    if (!showNotifications && tab === "notifications") {
      setTab("general");
    }
  }, [open, showNotifications, tab]);

  const openSettings = () => {
    setTab("general");
    setOpen(true);
  };

  return (
    <div className="pf-settings">
      <button
        type="button"
        className="pf-settings__trigger"
        onClick={openSettings}
        aria-label={t("settings.openAria")}
        aria-haspopup="dialog"
        aria-expanded={open}
      >
        <IconSettings />
      </button>

      {open
        ? createPortal(
            <div className="pf-modal pf-modal--settings" role="presentation">
              <button
                type="button"
                className="pf-modal__backdrop"
                aria-label={t("settings.close")}
                onClick={() => setOpen(false)}
              />
              <div
                ref={dialogRef}
                className="pf-modal__panel pf-modal__panel--settings"
                role="dialog"
                aria-modal="true"
                aria-labelledby={titleId}
              >
              <div className="pf-settings-modal__chrome">
                <header className="pf-settings-modal__hero">
                  <div className="pf-settings-modal__hero-main">
                    <span className="pf-settings-modal__hero-icon" aria-hidden>
                      <IconSettings />
                    </span>
                    <div className="pf-settings-modal__hero-copy">
                      <h2 id={titleId} className="pf-settings-modal__title">
                        {t("settings.title")}
                      </h2>
                      <p className="pf-settings-modal__subtitle">{t("settings.subtitle")}</p>
                    </div>
                  </div>
                  <button
                    type="button"
                    className="pf-settings-modal__close"
                    onClick={() => setOpen(false)}
                    aria-label={t("settings.close")}
                  >
                    <span aria-hidden>×</span>
                  </button>
                </header>

                {showNotifications ? (
                  <div className="pf-settings-modal__nav">
                    <nav className="pf-settings-modal__tabs" aria-label={t("settings.title")}>
                      <div className="pf-segmented pf-settings-modal__segmented" role="tablist">
                        <button
                          type="button"
                          role="tab"
                          className={`pf-segmented__option pf-settings-modal__tab${tab === "general" ? " is-active" : ""}`}
                          aria-selected={tab === "general"}
                          onClick={() => setTab("general")}
                        >
                          <span className="pf-segmented__label">{t("settings.general")}</span>
                        </button>
                        <button
                          type="button"
                          role="tab"
                          className={`pf-segmented__option pf-settings-modal__tab${tab === "notifications" ? " is-active" : ""}`}
                          aria-selected={tab === "notifications"}
                          onClick={() => setTab("notifications")}
                        >
                          <IconBell className="pf-settings-modal__tab-icon" aria-hidden />
                          <span className="pf-segmented__label">{t("settings.notifications")}</span>
                        </button>
                      </div>
                    </nav>
                    <p className="pf-settings-modal__pane-desc">
                      {tab === "general" ? t("settings.generalDesc") : t("notifications.description")}
                    </p>
                  </div>
                ) : null}
              </div>

                <div className="pf-settings-modal__body">
                  <div
                    className={`pf-settings-modal__pane${tab === "general" || !showNotifications ? " is-active" : ""}`}
                    role="tabpanel"
                    aria-hidden={showNotifications && tab !== "general"}
                  >
                    <div className="pf-settings-general">
                      <section className="pf-settings-block" aria-labelledby="settings-language-heading">
                        <div className="pf-settings-block__head">
                          <h3 id="settings-language-heading" className="pf-settings-block__title">
                            {t("settings.language")}
                          </h3>
                          <p className="pf-settings-block__desc">{t("settings.languageDesc")}</p>
                        </div>
                        <LanguagePicker />
                      </section>

                      <section className="pf-settings-block" aria-labelledby="settings-theme-heading">
                        <div className="pf-settings-block__head">
                          <h3 id="settings-theme-heading" className="pf-settings-block__title">
                            {t("settings.theme")}
                          </h3>
                          <p className="pf-settings-block__desc">{t("settings.themeDesc")}</p>
                        </div>
                        <div
                          className="pf-theme-tiles"
                          role="radiogroup"
                          aria-label={t("settings.theme")}
                        >
                          {THEME_OPTIONS.map((option) => {
                            const active = preference === option.id;
                            return (
                              <button
                                key={option.id}
                                type="button"
                                role="radio"
                                aria-checked={active}
                                className={`pf-theme-tile${active ? " is-active" : ""}`}
                                onClick={() => setPreference(option.id)}
                              >
                                <span className="pf-theme-tile__icon" aria-hidden>
                                  {option.icon}
                                </span>
                                <span className="pf-theme-tile__copy">
                                  <span className="pf-theme-tile__label">{t(option.labelKey)}</span>
                                  <span className="pf-theme-tile__hint">{t(option.hintKey)}</span>
                                </span>
                                <span className="pf-theme-tile__check" aria-hidden>
                                  {active ? <IconCheck /> : null}
                                </span>
                              </button>
                            );
                          })}
                        </div>
                      </section>
                    </div>
                  </div>

                  {showNotifications ? (
                    <div
                      className={`pf-settings-modal__pane pf-settings-modal__pane--notifications${tab === "notifications" ? " is-active" : ""}`}
                      role="tabpanel"
                      aria-hidden={tab !== "notifications"}
                    >
                      <NotificationsSettings />
                    </div>
                  ) : null}
                </div>
              </div>
            </div>,
            document.body
          )
        : null}
    </div>
  );
}
