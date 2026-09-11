import type { ButtonHTMLAttributes, ReactNode } from "react";

/**
 * Button variants by context:
 * - Table row actions: edit/open/view → secondary + pf-btn--sm; run → primary + pf-btn--sm; delete → danger-secondary + pf-btn--sm; stop → secondary + pf-btn--sm
 * - Form actions: submit → primary; cancel → secondary; destructive (delete) → danger-secondary + pf-btn--sm
 * - Panel toolbar (secondary): secondary or secondary + pf-btn--sm
 * - Bulk/destructive toolbar CTA: danger-secondary + pf-btn--sm
 */
type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: "primary" | "secondary" | "link" | "link-danger" | "danger" | "danger-secondary";
  /** Blocks repeat clicks without disabling the button (avoids stuck :active after save). */
  loading?: boolean;
  children: ReactNode;
};

export function Button({
  variant = "primary",
  className = "",
  loading = false,
  disabled,
  onClick,
  children,
  ...props
}: ButtonProps) {
  const handleClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    if (loading) return;
    onClick?.(event);
    event.currentTarget.blur();
  };

  return (
    <button
      className={`pf-btn pf-btn--${variant}${loading ? " pf-btn--busy" : ""} ${className}`.trim()}
      disabled={disabled}
      aria-busy={loading || undefined}
      onClick={handleClick}
      {...props}
    >
      {children}
    </button>
  );
}
