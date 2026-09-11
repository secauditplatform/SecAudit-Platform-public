import { useRef, useState, type ChangeEvent, type DragEvent } from "react";
import { useTranslation } from "../../i18n/I18nProvider";
import { Button } from "./Button";
import { IconUpload } from "./Icons";

type FileUploadZoneProps = {
  id: string;
  label: string;
  hint?: string;
  accept?: string;
  /** Override extension chips (e.g. grouped labels for profiles import). */
  formatLabels?: string[];
  multiple?: boolean;
  files: File[];
  onFilesChange: (files: File[]) => void;
  disabled?: boolean;
  variant?: "default" | "profiles" | "compact";
};

function fileKey(file: File): string {
  return `${file.name}:${file.size}:${file.lastModified}`;
}

function mergeFiles(current: File[], incoming: File[]): File[] {
  const map = new Map(current.map((file) => [fileKey(file), file]));
  incoming.forEach((file) => map.set(fileKey(file), file));
  return Array.from(map.values());
}

export function formatUploadFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatExtensions(accept?: string): string[] {
  if (!accept) return [];
  const seen = new Set<string>();
  return accept
    .split(",")
    .map((value) => value.trim().replace(/^\./, "").toLowerCase())
    .filter((value) => {
      if (!value || seen.has(value)) return false;
      seen.add(value);
      return true;
    });
}

export function FileUploadZone({
  id,
  label,
  hint,
  accept,
  formatLabels,
  multiple = true,
  files,
  onFilesChange,
  disabled = false,
  variant = "default",
}: FileUploadZoneProps) {
  const { t } = useTranslation();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const formatExtensionsList = formatLabels?.length ? formatLabels : formatExtensions(accept);

  const openFileDialog = () => {
    if (disabled) return;
    inputRef.current?.click();
  };

  const handleInputChange = (event: ChangeEvent<HTMLInputElement>) => {
    const selected = event.target.files ? Array.from(event.target.files) : [];
    onFilesChange(multiple ? selected : selected.slice(0, 1));
    event.target.value = "";
  };

  const handleDrop = (event: DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setDragOver(false);
    if (disabled) return;

    const dropped = Array.from(event.dataTransfer.files);
    if (!dropped.length) return;
    onFilesChange(multiple ? mergeFiles(files, dropped) : dropped.slice(0, 1));
  };

  const removeFile = (target: File) => {
    onFilesChange(files.filter((file) => fileKey(file) !== fileKey(target)));
  };

  return (
    <div
      className={`pf-file-upload${
        variant === "profiles" ? " pf-file-upload--profiles" : ""
      }${variant === "compact" ? " pf-file-upload--compact" : ""}`}
    >
      <label className="pf-file-upload__label" htmlFor={id}>
        {label}
      </label>

      <div
        className={`pf-file-upload__dropzone${dragOver ? " pf-file-upload__dropzone--active" : ""}${disabled ? " pf-file-upload__dropzone--disabled" : ""}${files.length > 0 ? " pf-file-upload__dropzone--filled" : ""}`}
        onDragEnter={(event) => {
          event.preventDefault();
          if (!disabled) setDragOver(true);
        }}
        onDragOver={(event) => {
          event.preventDefault();
          if (!disabled) setDragOver(true);
        }}
        onDragLeave={(event) => {
          event.preventDefault();
          const related = event.relatedTarget as Node | null;
          if (!event.currentTarget.contains(related)) {
            setDragOver(false);
          }
        }}
        onDrop={handleDrop}
        onClick={openFileDialog}
        onKeyDown={(event) => {
          if (disabled) return;
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            openFileDialog();
          }
        }}
        role="button"
        tabIndex={disabled ? -1 : 0}
        aria-disabled={disabled}
        aria-label={label}
      >
        <input
          ref={inputRef}
          id={id}
          className="pf-file-upload__input"
          type="file"
          multiple={multiple}
          accept={accept}
          disabled={disabled}
          onChange={handleInputChange}
          onClick={(event) => event.stopPropagation()}
        />

        <div className="pf-file-upload__dropzone-inner">
          <span className="pf-file-upload__icon" aria-hidden>
            <IconUpload />
          </span>
          <div className="pf-file-upload__copy">
            <p className="pf-file-upload__title">
              {variant === "compact" && files[0]
                ? files[0].name
                : t("profiles.uploadDropTitle")}
            </p>
            <p className="pf-file-upload__subtitle">
              {variant === "compact" && files[0]
                ? formatUploadFileSize(files[0].size)
                : t("profiles.uploadDropSubtitle")}
            </p>
          </div>
          <Button
            type="button"
            variant="secondary"
            className="pf-btn--sm pf-file-upload__browse"
            onClick={(event) => {
              event.stopPropagation();
              openFileDialog();
            }}
            disabled={disabled}
          >
            {variant === "compact" && files.length > 0
              ? t("profiles.uploadReplaceFile")
              : t("profiles.uploadBrowse")}
          </Button>
          {formatExtensionsList.length > 0 && !(variant === "compact" && files.length > 0) && (
            <div className="pf-file-upload__formats" aria-label={t("profiles.uploadFormatsLabel")}>
              {formatExtensionsList.map((extension) => (
                <span key={extension} className="pf-file-upload__format">
                  {extension.startsWith(".") || formatLabels?.length ? extension : `.${extension}`}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>

      {hint && <p className="pf-form__hint pf-file-upload__hint">{hint}</p>}

      {files.length > 0 && variant !== "compact" && (
        <div className="pf-file-upload__list-wrap">
          <div className="pf-file-upload__list-header">
            <span className="pf-file-upload__list-title">
              {t("profiles.selectedFiles", { count: files.length })}
            </span>
            <Button
              type="button"
              variant="link"
              className="pf-btn--sm"
              onClick={() => onFilesChange([])}
              disabled={disabled}
            >
              {t("profiles.uploadClearAll")}
            </Button>
          </div>
          <ul className="pf-file-upload__list">
            {files.map((file) => (
              <li key={fileKey(file)} className="pf-file-upload__item">
                <div className="pf-file-upload__item-main">
                  <span className="pf-file-upload__item-name pf-table__mono">{file.name}</span>
                  <span className="pf-file-upload__item-size">{formatUploadFileSize(file.size)}</span>
                </div>
                <Button
                  type="button"
                  variant="link-danger"
                  className="pf-btn--sm"
                  onClick={() => removeFile(file)}
                  disabled={disabled}
                  aria-label={t("profiles.uploadRemoveFile", { name: file.name })}
                >
                  {t("common.delete")}
                </Button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {files.length > 0 && variant === "compact" && (
        <div className="pf-file-upload__compact-actions">
          <Button
            type="button"
            variant="link-danger"
            className="pf-btn--sm"
            onClick={() => onFilesChange([])}
            disabled={disabled}
          >
            {t("profiles.uploadClearFile")}
          </Button>
        </div>
      )}
    </div>
  );
}
