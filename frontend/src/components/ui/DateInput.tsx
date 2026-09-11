import type { InputHTMLAttributes } from "react";
import { useTranslation } from "../../i18n/I18nProvider";

type DateInputProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type" | "lang">;

/** Native date input with locale aligned to the active UI language. */
export function DateInput({ className, ...props }: DateInputProps) {
  const { dateLocale } = useTranslation();
  return <input type="date" lang={dateLocale} className={className} {...props} />;
}
