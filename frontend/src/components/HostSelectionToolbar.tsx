import type { ReactNode } from "react";
import { useTranslation } from "../i18n/I18nProvider";
import { Button } from "./ui/Button";

type HostSelectionToolbarProps = {
  selectedCount: number;
  onSelectAll: () => void;
  onClear: () => void;
  clearDisabled?: boolean;
  emptyHintKey?: "hostSelection.jobHint" | "hostSelection.listHint";
  customHint?: string;
  extraActions?: ReactNode;
  variant?: "embedded" | "panel";
};

export function HostSelectionToolbar({
  selectedCount,
  onSelectAll,
  onClear,
  clearDisabled,
  emptyHintKey = "hostSelection.jobHint",
  customHint,
  extraActions,
  variant = "embedded",
}: HostSelectionToolbarProps) {
  const { t } = useTranslation();

  const emptyHint = customHint ?? t(emptyHintKey);

  return (
    <div
      className={`pf-host-selection-toolbar${variant === "panel" ? " pf-host-selection-toolbar--panel" : ""}`}
    >
      <p className="pf-host-selection-toolbar__hint">
        {selectedCount > 0 ? t("hostSelection.selected", { count: selectedCount }) : emptyHint}
      </p>
      <div className="pf-host-selection-toolbar__actions">
        <Button variant="link" className="pf-btn--sm" type="button" onClick={onSelectAll}>
          {t("hostSelection.selectAll")}
        </Button>
        <Button
          variant="link"
          className="pf-btn--sm"
          type="button"
          onClick={onClear}
          disabled={clearDisabled ?? selectedCount === 0}
        >
          {t("hostSelection.clear")}
        </Button>
        {extraActions}
      </div>
    </div>
  );
}
