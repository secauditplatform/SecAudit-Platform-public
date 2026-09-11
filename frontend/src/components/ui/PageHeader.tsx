import type { ReactNode } from "react";

type PageHeaderProps = {
  title: string;
  description?: string;
  actions?: ReactNode;
};

export function PageHeader({ title, description, actions }: PageHeaderProps) {
  return (
    <div className="pf-page-header">
      <div className="pf-page-header__main">
        <h1 className="pf-page-header__title">{title}</h1>
        {description && <p className="pf-page-header__description">{description}</p>}
      </div>
      {actions && <div className="pf-page-header__actions">{actions}</div>}
    </div>
  );
}
