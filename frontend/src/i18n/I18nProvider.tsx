import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { getLocaleMeta, isLocale, type Locale } from "./locales";
import { ar } from "./locales/ar";
import { bn } from "./locales/bn";
import { de } from "./locales/de";
import { en } from "./locales/en";
import { es } from "./locales/es";
import { fr } from "./locales/fr";
import { hi } from "./locales/hi";
import { ja } from "./locales/ja";
import { ko } from "./locales/ko";
import { pt } from "./locales/pt";
import { ru, type TranslationDict } from "./locales/ru";
import { zh } from "./locales/zh";

export type { Locale };

const STORAGE_KEY = "secaudit_locale";

const dictionaries: Record<Locale, TranslationDict> = {
  ru,
  en,
  zh,
  es,
  hi,
  ar,
  bn,
  pt,
  ja,
  fr,
  de,
  ko,
};

function detectLocale(): Locale {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (isLocale(stored)) return stored;
  // Platform default is English; users can switch via the language picker.
  return "en";
}

type Params = Record<string, string | number>;

type I18nContextValue = {
  locale: Locale;
  setLocale: (locale: Locale) => void;
  t: (key: string, params?: Params) => string;
  dateLocale: string;
};

const I18nContext = createContext<I18nContextValue | null>(null);

function getNested(dict: TranslationDict, path: string): string | undefined {
  const parts = path.split(".");
  let current: string | TranslationDict | undefined = dict;
  for (const part of parts) {
    if (typeof current !== "object" || current == null) return undefined;
    current = current[part] as string | TranslationDict | undefined;
  }
  return typeof current === "string" ? current : undefined;
}

function interpolate(text: string, params?: Params): string {
  if (!params) return text;
  return Object.entries(params).reduce(
    (result, [key, value]) => result.replaceAll(`{{${key}}}`, String(value)),
    text
  );
}

function applyDocumentLocale(locale: Locale) {
  const meta = getLocaleMeta(locale);
  document.documentElement.lang = meta?.dateLocale ?? locale;
  document.documentElement.dir = meta?.dir ?? "ltr";
}

export function I18nProvider({ children }: { children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(detectLocale);

  useEffect(() => {
    applyDocumentLocale(locale);
  }, [locale]);

  const setLocale = useCallback((next: Locale) => {
    localStorage.setItem(STORAGE_KEY, next);
    setLocaleState(next);
    applyDocumentLocale(next);
  }, []);

  const value = useMemo<I18nContextValue>(() => {
    const dict = dictionaries[locale];
    const meta = getLocaleMeta(locale);
    return {
      locale,
      setLocale,
      dateLocale: meta?.dateLocale ?? "en-US",
      t: (key: string, params?: Params) => {
        const text =
          getNested(dict, key) ?? getNested(en, key) ?? getNested(ru, key) ?? key;
        return interpolate(text, params);
      },
    };
  }, [locale, setLocale]);

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>;
}

export function useTranslation() {
  const ctx = useContext(I18nContext);
  if (!ctx) throw new Error("useTranslation must be used within I18nProvider");
  return ctx;
}
