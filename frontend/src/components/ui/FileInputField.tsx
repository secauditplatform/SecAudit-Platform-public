import { useRef, type ChangeEvent } from "react";
import { useTranslation } from "../../i18n/I18nProvider";
import { Button } from "./Button";

type FileInputFieldProps = {
  id: string;
  accept?: string;
  file: File | null;
  onFileChange: (file: File | null) => void;
  disabled?: boolean;
};

export function FileInputField({
  id,
  accept,
  file,
  onFileChange,
  disabled = false,
}: FileInputFieldProps) {
  const { t } = useTranslation();
  const inputRef = useRef<HTMLInputElement>(null);

  const openFileDialog = () => {
    if (disabled) return;
    inputRef.current?.click();
  };

  const handleInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    onFileChange(event.target.files?.[0] ?? null);
    event.target.value = "";
  };

  return (
    <div className={`pf-file-input${disabled ? " pf-file-input--disabled" : ""}`}>
      <input
        ref={inputRef}
        id={id}
        className="pf-file-input__native"
        type="file"
        accept={accept}
        disabled={disabled}
        onChange={handleInputChange}
      />
      <div className="pf-file-input__display">
        <span
          className={`pf-file-input__name${file ? "" : " pf-file-input__name--empty"}`}
          title={file?.name}
        >
          {file?.name ?? t("network.configFileEmpty")}
        </span>
        {file ? (
          <button
            type="button"
            className="pf-file-input__clear"
            onClick={() => onFileChange(null)}
            disabled={disabled}
            aria-label={t("profiles.uploadClearFile")}
          >
            ×
          </button>
        ) : null}
        <Button
          type="button"
          variant="secondary"
          className="pf-btn--sm pf-file-input__browse"
          onClick={openFileDialog}
          disabled={disabled}
        >
          {file ? t("profiles.uploadReplaceFile") : t("network.configFileBrowse")}
        </Button>
      </div>
    </div>
  );
}
