import { useId, type ReactNode } from "react";

type SettingsSectionProps = {
  title: string;
  description?: string;
  summary?: ReactNode;
  open: boolean;
  onToggle: () => void;
  children: ReactNode;
};

export function SettingsSection({
  title,
  description,
  summary,
  open,
  onToggle,
  children,
}: SettingsSectionProps) {
  const panelId = useId();
  const headerId = useId();

  return (
    <section className={`pf-settings-acc${open ? " is-open" : ""}`}>
      <h3 className="pf-settings-acc__heading">
        <button
          type="button"
          id={headerId}
          className="pf-settings-acc__trigger"
          aria-expanded={open}
          aria-controls={panelId}
          onClick={onToggle}
        >
          <span className="pf-settings-acc__trigger-main">
            <span className="pf-settings-acc__title">{title}</span>
            {description ? (
              <span className="pf-settings-acc__description">{description}</span>
            ) : null}
            {!open && summary ? (
              <span className="pf-settings-acc__summary">{summary}</span>
            ) : null}
          </span>
          <span className={`pf-settings-acc__chevron${open ? " is-open" : ""}`} aria-hidden>
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
      </h3>
      <div
        id={panelId}
        role="region"
        aria-labelledby={headerId}
        className="pf-settings-acc__panel"
        hidden={!open}
      >
        <div className="pf-settings-acc__panel-inner">{children}</div>
      </div>
    </section>
  );
}
