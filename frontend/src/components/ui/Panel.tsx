import { forwardRef, useState, type ReactNode } from "react";
import { useTranslation } from "../../i18n/I18nProvider";

type PanelProps = {
  title?: string;
  description?: string;
  toolbar?: ReactNode;
  children: ReactNode;
  className?: string;
  noPadding?: boolean;
  collapsible?: boolean;
  defaultCollapsed?: boolean;
  collapsed?: boolean;
  onCollapsedChange?: (collapsed: boolean) => void;
};

export const Panel = forwardRef<HTMLElement, PanelProps>(function Panel(
  {
    title,
    description,
    toolbar,
    children,
    className = "",
    noPadding,
    collapsible = true,
    defaultCollapsed = false,
    collapsed: collapsedProp,
    onCollapsedChange,
  },
  ref
) {
  const { t } = useTranslation();
  const [uncontrolledCollapsed, setUncontrolledCollapsed] = useState(defaultCollapsed);
  const isControlled = collapsedProp !== undefined;
  const collapsed = isControlled ? collapsedProp : uncontrolledCollapsed;
  const canCollapse = collapsible && Boolean(title);

  const toggleCollapsed = () => {
    if (!canCollapse) return;
    const next = !collapsed;
    if (!isControlled) setUncontrolledCollapsed(next);
    onCollapsedChange?.(next);
  };

  return (
    <section ref={ref} className={`pf-panel${collapsed ? " pf-panel--collapsed" : ""} ${className}`}>
      {(title || toolbar) && (
        <div className={`pf-panel__header${canCollapse ? " pf-panel__header--collapsible" : ""}`}>
          <div className="pf-panel__header-main">
            {canCollapse && (
              <button
                type="button"
                className="pf-panel__toggle"
                onClick={toggleCollapsed}
                aria-expanded={!collapsed}
                aria-label={collapsed ? t("common.expandPanel") : t("common.collapsePanel")}
              >
                <span className="pf-panel__chevron" aria-hidden />
              </button>
            )}
            {title && (
              <h2
                className="pf-panel__title"
                onClick={canCollapse ? toggleCollapsed : undefined}
                onKeyDown={
                  canCollapse
                    ? (event) => {
                        if (event.key === "Enter" || event.key === " ") {
                          event.preventDefault();
                          toggleCollapsed();
                        }
                      }
                    : undefined
                }
                role={canCollapse ? "button" : undefined}
                tabIndex={canCollapse ? 0 : undefined}
              >
                {title}
              </h2>
            )}
            {description && <p className="pf-panel__description">{description}</p>}
          </div>
          {toolbar && <div className="pf-panel__toolbar">{toolbar}</div>}
        </div>
      )}
      {!collapsed && (
        <div className={noPadding ? "pf-panel__body pf-panel__body--flush" : "pf-panel__body"}>
          {children}
        </div>
      )}
    </section>
  );
});
