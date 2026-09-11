export type Locale =
  | "ru"
  | "en"
  | "zh"
  | "es"
  | "hi"
  | "ar"
  | "bn"
  | "pt"
  | "ja"
  | "fr"
  | "de"
  | "ko";

export type LocaleMeta = {
  code: Locale;
  /** BCP 47 tag for date/number formatting */
  dateLocale: string;
  /** Native endonym shown in the language picker */
  nativeName: string;
  /** English name for search */
  englishName: string;
  dir?: "ltr" | "rtl";
};

const LOCALE_META: LocaleMeta[] = [
  { code: "en", dateLocale: "en-US", nativeName: "English", englishName: "English" },
  { code: "ru", dateLocale: "ru-RU", nativeName: "Русский", englishName: "Russian" },
  { code: "ar", dateLocale: "ar-SA", nativeName: "العربية", englishName: "Arabic", dir: "rtl" },
  { code: "bn", dateLocale: "bn-BD", nativeName: "বাংলা", englishName: "Bengali" },
  { code: "zh", dateLocale: "zh-CN", nativeName: "中文", englishName: "Chinese" },
  { code: "fr", dateLocale: "fr-FR", nativeName: "Français", englishName: "French" },
  { code: "de", dateLocale: "de-DE", nativeName: "Deutsch", englishName: "German" },
  { code: "hi", dateLocale: "hi-IN", nativeName: "हिन्दी", englishName: "Hindi" },
  { code: "ja", dateLocale: "ja-JP", nativeName: "日本語", englishName: "Japanese" },
  { code: "ko", dateLocale: "ko-KR", nativeName: "한국어", englishName: "Korean" },
  { code: "pt", dateLocale: "pt-BR", nativeName: "Português", englishName: "Portuguese" },
  { code: "es", dateLocale: "es-ES", nativeName: "Español", englishName: "Spanish" },
];

/** UI languages: RU/EN first, then top-10 by speakers (excl. RU/EN), A–Z by English name. */
export const LOCALES: LocaleMeta[] = LOCALE_META;

export const LOCALE_CODES = LOCALES.map((l) => l.code);

const byCode = Object.fromEntries(LOCALES.map((l) => [l.code, l])) as Record<Locale, LocaleMeta>;

export function getLocaleMeta(code: string): LocaleMeta | undefined {
  return byCode[code as Locale];
}

export function isLocale(value: string | null | undefined): value is Locale {
  return Boolean(value && value in byCode);
}
