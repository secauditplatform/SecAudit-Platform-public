type BadgeVariant = "success" | "danger" | "warning" | "info" | "neutral";

type BadgeProps = {
  variant?: BadgeVariant;
  /** Preserve literal casing (no capitalize transform) for snake_case values */
  literal?: boolean;
  children: React.ReactNode;
};

export function Badge({ variant = "neutral", literal = false, children }: BadgeProps) {
  return (
    <span className={`pf-label pf-label--${variant}${literal ? " pf-label--literal" : ""}`}>
      {children}
    </span>
  );
}
