import type { InputHTMLAttributes, TextareaHTMLAttributes } from "react";
import { useState } from "react";
import { useTranslation } from "../../i18n/I18nProvider";
import { IconEye, IconEyeSlash } from "./Icons";

type PasswordInputProps = Omit<InputHTMLAttributes<HTMLInputElement>, "type">;

export function PasswordInput({ className = "", ...props }: PasswordInputProps) {
  const { t } = useTranslation();
  const [visible, setVisible] = useState(false);

  return (
    <div className="pf-password-field">
      <input
        {...props}
        type={visible ? "text" : "password"}
        className={`pf-input pf-password-field__input ${className}`.trim()}
      />
      <button
        type="button"
        className="pf-password-field__toggle"
        onClick={() => setVisible((value) => !value)}
        aria-label={visible ? t("common.hidePassword") : t("common.showPassword")}
      >
        {visible ? <IconEyeSlash /> : <IconEye />}
      </button>
    </div>
  );
}

type SecretTextareaProps = TextareaHTMLAttributes<HTMLTextAreaElement>;

export function SecretTextarea({ className = "", ...props }: SecretTextareaProps) {
  const { t } = useTranslation();
  const [visible, setVisible] = useState(false);

  return (
    <div className="pf-password-field pf-password-field--textarea">
      <textarea
        {...props}
        className={`pf-textarea pf-password-field__input ${visible ? "" : "pf-textarea--masked"} ${className}`.trim()}
      />
      <button
        type="button"
        className="pf-password-field__toggle"
        onClick={() => setVisible((value) => !value)}
        aria-label={visible ? t("common.hideSecret") : t("common.showSecret")}
      >
        {visible ? <IconEyeSlash /> : <IconEye />}
      </button>
    </div>
  );
}
