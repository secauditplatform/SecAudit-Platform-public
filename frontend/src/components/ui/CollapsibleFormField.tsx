import { useState, type ReactNode } from "react";
import { useTranslation } from "../../i18n/I18nProvider";

type CollapsibleFormFieldProps = {
  id: string;
  label: string;
  summary?: string;
  defaultCollapsed?: boolean;
  children: ReactNode;
};

export function CollapsibleFormField({
  id,
  label,
  summary,
  defaultCollapsed = false,
  children,
}: CollapsibleFormFieldProps) {
  const { t } = useTranslation();
  const [collapsed, setCollapsed] = useState(defaultCollapsed);

  const toggle = () => setCollapsed((open) => !open);

  return (
    <div
      className={`pf-form-field pf-form-field--collapsible${collapsed ? " pf-form-field--collapsed" : ""}`}
    >
      <div className="pf-form-field__header">
        <button
          type="button"
          className="pf-form-field__toggle"
          onClick={toggle}
          aria-expanded={!collapsed}
          aria-controls={id}
          aria-label={collapsed ? t("common.expandField") : t("common.collapseField")}
        >
          <span className="pf-form-field__chevron" aria-hidden />
        </button>
        <button
          type="button"
          className="pf-form-field__title"
          onClick={toggle}
          aria-expanded={!collapsed}
          aria-controls={id}
        >
          {label}
          {summary && <span className="pf-form-field__summary">{summary}</span>}
        </button>
      </div>
      {!collapsed && (
        <div id={id} className="pf-form-field__body">
          {children}
        </div>
      )}
    </div>
  );
}
