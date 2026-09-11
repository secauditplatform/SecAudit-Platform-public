import type { ReactNode } from "react";
import { IconLoginLocal, IconLoginSso } from "../components/ui/Icons";

type LoginMethodButtonProps = {
  label: string;
  variant: "sso" | "local";
  onClick: () => void;
  icon?: ReactNode;
  disabled?: boolean;
  disabledHint?: string;
};

export function LoginMethodButton({
  label,
  variant,
  onClick,
  icon,
  disabled = false,
  disabledHint,
}: LoginMethodButtonProps) {
  const defaultIcon = variant === "sso" ? <IconLoginSso /> : <IconLoginLocal />;

  return (
    <button
      type="button"
      className={`pf-login-method pf-login-method--${variant}${disabled ? " pf-login-method--disabled" : ""}`}
      onClick={onClick}
      disabled={disabled}
      title={disabled ? disabledHint : undefined}
      aria-disabled={disabled}
    >
      <span className="pf-login-method__icon" aria-hidden>
        {icon ?? defaultIcon}
      </span>
      <span className="pf-login-method__label">{label}</span>
      <span className="pf-login-method__chevron" aria-hidden />
    </button>
  );
}
