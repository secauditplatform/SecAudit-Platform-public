import { useId, useMemo, useState } from "react";
import { LOCALES, type Locale } from "../i18n/locales";
import { useTranslation } from "../i18n/I18nProvider";
import { IconCheck, IconSearch } from "./ui/Icons";

type LanguagePickerProps = {
  defaultExpanded?: boolean;
};

export function LanguagePicker({ defaultExpanded = false }: LanguagePickerProps) {
  const { t, locale, setLocale } = useTranslation();
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState(defaultExpanded);
  const panelId = useId();

  const current = useMemo(
    () => LOCALES.find((item) => item.code === locale) ?? LOCALES[0],
    [locale]
  );

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return LOCALES;
    return LOCALES.filter(
      (item) =>
        item.nativeName.toLowerCase().includes(q) ||
        item.englishName.toLowerCase().includes(q) ||
        item.code.includes(q)
    );
  }, [query]);

  const selectLocale = (code: Locale) => {
    setLocale(code);
    setQuery("");
    if (!defaultExpanded) setExpanded(false);
  };

  return (
    <div
      className={`pf-lang-picker${expanded ? " is-expanded" : ""}`}
      role="group"
      aria-label={t("settings.language")}
    >
      <button
        type="button"
        className="pf-lang-picker__current"
        aria-expanded={expanded}
        aria-controls={panelId}
        onClick={() => setExpanded((value) => !value)}
      >
        <span className="pf-lang-picker__current-mark" aria-hidden>
          <IconCheck />
        </span>
        <span className="pf-lang-picker__current-text">
          <span className="pf-lang-picker__current-native" dir="auto">
            {current.nativeName}
          </span>
          <span className="pf-lang-picker__current-meta">{current.englishName}</span>
        </span>
        <span className="pf-lang-picker__badge">{current.code.toUpperCase()}</span>
        <span className={`pf-lang-picker__chevron${expanded ? " is-open" : ""}`} aria-hidden>
          <svg viewBox="0 0 16 16" width="14" height="14" fill="none">
            <path
              d="M4 6l4 4 4-4"
              stroke="currentColor"
              strokeWidth="1.75"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </svg>
        </span>
      </button>

      <div id={panelId} className="pf-lang-picker__panel" hidden={!expanded}>
        <label className="pf-lang-picker__search">
          <IconSearch className="pf-lang-picker__search-icon" />
          <input
            type="search"
            className="pf-lang-picker__search-input"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder={t("settings.languageSearch")}
            aria-label={t("settings.languageSearch")}
            autoComplete="off"
          />
        </label>

        <div className="pf-lang-picker__grid" role="listbox" aria-label={t("settings.language")}>
          {filtered.length === 0 ? (
            <p className="pf-lang-picker__empty">{t("settings.languageEmpty")}</p>
          ) : (
            filtered.map((item) => {
              const active = item.code === locale;
              return (
                <button
                  key={item.code}
                  type="button"
                  role="option"
                  aria-selected={active}
                  title={`${item.nativeName} · ${item.englishName}`}
                  className={`pf-lang-picker__chip${active ? " is-active" : ""}`}
                  onClick={() => selectLocale(item.code as Locale)}
                >
                  <span className="pf-lang-picker__chip-copy">
                    <span className="pf-lang-picker__chip-name" dir="auto">
                      {item.nativeName}
                    </span>
                    <span className="pf-lang-picker__chip-meta">{item.englishName}</span>
                  </span>
                  <span className="pf-lang-picker__chip-code">{item.code.toUpperCase()}</span>
                  {active ? (
                    <span className="pf-lang-picker__chip-check" aria-hidden>
                      <IconCheck />
                    </span>
                  ) : null}
                </button>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
}
