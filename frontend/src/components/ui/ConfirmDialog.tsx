import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useId,
  useRef,
  useState,
  type FormEvent,
  type ReactNode,
} from "react";
import { useTranslation } from "../../i18n/I18nProvider";
import { Button } from "./Button";

export type ConfirmVariant = "default" | "warning" | "danger";

export type ConfirmOptions = {
  title: string;
  message: string;
  subtitle?: string;
  variant?: ConfirmVariant;
  confirmLabel?: string;
  cancelLabel?: string;
  icon?: ReactNode;
};

export type ConfirmChoice = {
  id: string;
  label: string;
  hint?: string;
  defaultChecked?: boolean;
  disabled?: boolean;
};

export type ConfirmChoicesOptions = ConfirmOptions & {
  choices: ConfirmChoice[];
};

export type PromptOptions = {
  title: string;
  message?: string;
  subtitle?: string;
  label: string;
  placeholder?: string;
  defaultValue?: string;
  confirmLabel?: string;
  cancelLabel?: string;
  required?: boolean;
  icon?: ReactNode;
};

type ConfirmRequest = ConfirmOptions & {
  kind: "confirm";
  resolve: (value: boolean) => void;
};

type ConfirmChoicesRequest = ConfirmChoicesOptions & {
  kind: "confirm-choices";
  resolve: (value: Record<string, boolean> | null) => void;
};

type PromptRequest = PromptOptions & {
  kind: "prompt";
  resolve: (value: string | null) => void;
};

type DialogRequest = ConfirmRequest | ConfirmChoicesRequest | PromptRequest;

type ConfirmContextValue = {
  confirm: (options: ConfirmOptions) => Promise<boolean>;
  confirmChoices: (options: ConfirmChoicesOptions) => Promise<Record<string, boolean> | null>;
  prompt: (options: PromptOptions) => Promise<string | null>;
};

const ConfirmContext = createContext<ConfirmContextValue | null>(null);

function alertClass(variant: ConfirmVariant): string {
  if (variant === "warning") return "pf-alert pf-alert--warning pf-confirm-message";
  if (variant === "danger") return "pf-alert pf-alert--error pf-confirm-message";
  return "pf-alert pf-alert--info pf-confirm-message";
}

function ConfirmDialogView({
  request,
  onClose,
}: {
  request: ConfirmRequest;
  onClose: (confirmed: boolean) => void;
}) {
  const { t } = useTranslation();
  const variant = request.variant ?? "default";

  return (
    <div
      className="pf-modal pf-modal--auth"
      role="presentation"
      onClick={() => onClose(false)}
    >
      <div
        className="pf-login-shell pf-confirm-shell"
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-dialog-title"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="pf-login-brand">
          {request.icon ? (
            <div className="pf-login-brand__mark pf-login-brand__mark--icon" aria-hidden>
              {request.icon}
            </div>
          ) : null}
          <div>
            <h3 className="pf-login-brand__title" id="confirm-dialog-title">
              {request.title}
            </h3>
            {request.subtitle ? (
              <p className="pf-login-brand__subtitle">{request.subtitle}</p>
            ) : null}
          </div>
        </header>
        <div className="pf-login-body pf-login-body--confirm">
          <div className={alertClass(variant)}>{request.message}</div>
          <div className="pf-confirm-actions">
            <Button
              variant={variant === "danger" ? "link-danger" : "primary"}
              onClick={() => onClose(true)}
              className="pf-btn--block"
            >
              {request.confirmLabel ?? t("common.confirm")}
            </Button>
            <Button variant="secondary" onClick={() => onClose(false)} className="pf-btn--block">
              {request.cancelLabel ?? t("common.cancel")}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

function ConfirmChoicesDialogView({
  request,
  onClose,
}: {
  request: ConfirmChoicesRequest;
  onClose: (value: Record<string, boolean> | null) => void;
}) {
  const { t } = useTranslation();
  const variant = request.variant ?? "default";
  const [checked, setChecked] = useState<Record<string, boolean>>(() =>
    Object.fromEntries(
      request.choices.map((choice) => [choice.id, Boolean(choice.defaultChecked)])
    )
  );

  const jobsOn = Boolean(checked.jobs);
  const toggle = (id: string, disabled?: boolean) => {
    if (disabled) return;
    setChecked((prev) => {
      const nextValue = !prev[id];
      const next = { ...prev, [id]: nextValue };
      // Deleting jobs always removes their runs/reports.
      if (id === "jobs" && nextValue && "reports" in prev) {
        next.reports = true;
      }
      return next;
    });
  };

  return (
    <div
      className="pf-modal pf-modal--auth"
      role="presentation"
      onClick={() => onClose(null)}
    >
      <div
        className="pf-login-shell pf-confirm-shell"
        role="dialog"
        aria-modal="true"
        aria-labelledby="confirm-choices-title"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="pf-login-brand">
          {request.icon ? (
            <div className="pf-login-brand__mark pf-login-brand__mark--icon" aria-hidden>
              {request.icon}
            </div>
          ) : null}
          <div>
            <h3 className="pf-login-brand__title" id="confirm-choices-title">
              {request.title}
            </h3>
            {request.subtitle ? (
              <p className="pf-login-brand__subtitle">{request.subtitle}</p>
            ) : null}
          </div>
        </header>
        <div className="pf-login-body pf-login-body--confirm">
          <div className={alertClass(variant)}>{request.message}</div>
          <div className="pf-confirm-choices" role="group" aria-label={request.title}>
            {request.choices.map((choice) => {
              const forcedByJobs = choice.id === "reports" && jobsOn;
              const isDisabled = Boolean(choice.disabled || forcedByJobs);
              const isChecked = forcedByJobs ? true : Boolean(checked[choice.id]);
              return (
                <label
                  key={choice.id}
                  className={`pf-confirm-choice${isDisabled ? " pf-confirm-choice--disabled" : ""}`}
                >
                  <input
                    type="checkbox"
                    className="pf-checkbox-control"
                    checked={isChecked}
                    disabled={isDisabled}
                    onChange={() => toggle(choice.id, isDisabled)}
                  />
                  <span className="pf-confirm-choice__copy">
                    <span className="pf-confirm-choice__label">{choice.label}</span>
                    {choice.hint ? (
                      <span className="pf-confirm-choice__hint">{choice.hint}</span>
                    ) : null}
                  </span>
                </label>
              );
            })}
          </div>
          <div className="pf-confirm-actions">
            <Button
              variant={variant === "danger" ? "link-danger" : "primary"}
              onClick={() =>
                onClose(jobsOn && "reports" in checked ? { ...checked, reports: true } : checked)
              }
              className="pf-btn--block"
            >
              {request.confirmLabel ?? t("common.confirm")}
            </Button>
            <Button variant="secondary" onClick={() => onClose(null)} className="pf-btn--block">
              {request.cancelLabel ?? t("common.cancel")}
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

function PromptDialogView({
  request,
  onClose,
}: {
  request: PromptRequest;
  onClose: (value: string | null) => void;
}) {
  const { t } = useTranslation();
  const fieldId = useId();
  const inputRef = useRef<HTMLTextAreaElement>(null);
  const [value, setValue] = useState(request.defaultValue ?? "");
  const required = request.required !== false;
  const trimmed = value.trim();
  const canSubmit = !required || trimmed.length > 0;

  useEffect(() => {
    inputRef.current?.focus();
  }, []);

  const submit = (event: FormEvent) => {
    event.preventDefault();
    if (!canSubmit) return;
    onClose(trimmed);
  };

  return (
    <div
      className="pf-modal pf-modal--auth"
      role="presentation"
      onClick={() => onClose(null)}
    >
      <div
        className="pf-login-shell pf-confirm-shell"
        role="dialog"
        aria-modal="true"
        aria-labelledby="prompt-dialog-title"
        onClick={(event) => event.stopPropagation()}
      >
        <header className="pf-login-brand">
          {request.icon ? (
            <div className="pf-login-brand__mark pf-login-brand__mark--icon" aria-hidden>
              {request.icon}
            </div>
          ) : null}
          <div>
            <h3 className="pf-login-brand__title" id="prompt-dialog-title">
              {request.title}
            </h3>
            {request.subtitle ? (
              <p className="pf-login-brand__subtitle">{request.subtitle}</p>
            ) : null}
          </div>
        </header>
        <form className="pf-login-body pf-login-body--confirm" onSubmit={submit}>
          {request.message ? (
            <div className="pf-alert pf-alert--info pf-confirm-message">{request.message}</div>
          ) : null}
          <div className="pf-form__group">
            <label htmlFor={fieldId}>{request.label}</label>
            <textarea
              id={fieldId}
              ref={inputRef}
              className="pf-textarea pf-confirm-prompt"
              rows={4}
              value={value}
              placeholder={request.placeholder}
              onChange={(event) => setValue(event.target.value)}
              onKeyDown={(event) => {
                if (event.key === "Escape") {
                  event.preventDefault();
                  onClose(null);
                }
              }}
            />
          </div>
          <div className="pf-confirm-actions">
            <Button type="submit" variant="primary" className="pf-btn--block" disabled={!canSubmit}>
              {request.confirmLabel ?? t("common.confirm")}
            </Button>
            <Button
              type="button"
              variant="secondary"
              onClick={() => onClose(null)}
              className="pf-btn--block"
            >
              {request.cancelLabel ?? t("common.cancel")}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}

export function ConfirmProvider({ children }: { children: ReactNode }) {
  const [request, setRequest] = useState<DialogRequest | null>(null);
  const requestRef = useRef<DialogRequest | null>(null);

  const confirm = useCallback((options: ConfirmOptions) => {
    return new Promise<boolean>((resolve) => {
      const next: ConfirmRequest = { ...options, kind: "confirm", resolve };
      requestRef.current = next;
      setRequest(next);
    });
  }, []);

  const confirmChoices = useCallback((options: ConfirmChoicesOptions) => {
    return new Promise<Record<string, boolean> | null>((resolve) => {
      const next: ConfirmChoicesRequest = { ...options, kind: "confirm-choices", resolve };
      requestRef.current = next;
      setRequest(next);
    });
  }, []);

  const prompt = useCallback((options: PromptOptions) => {
    return new Promise<string | null>((resolve) => {
      const next: PromptRequest = { ...options, kind: "prompt", resolve };
      requestRef.current = next;
      setRequest(next);
    });
  }, []);

  const closeConfirm = useCallback((confirmed: boolean) => {
    const current = requestRef.current;
    if (!current || current.kind !== "confirm") return;
    requestRef.current = null;
    setRequest(null);
    current.resolve(confirmed);
  }, []);

  const closeConfirmChoices = useCallback((value: Record<string, boolean> | null) => {
    const current = requestRef.current;
    if (!current || current.kind !== "confirm-choices") return;
    requestRef.current = null;
    setRequest(null);
    current.resolve(value);
  }, []);

  const closePrompt = useCallback((value: string | null) => {
    const current = requestRef.current;
    if (!current || current.kind !== "prompt") return;
    requestRef.current = null;
    setRequest(null);
    current.resolve(value);
  }, []);

  return (
    <ConfirmContext.Provider value={{ confirm, confirmChoices, prompt }}>
      {children}
      {request?.kind === "confirm" ? (
        <ConfirmDialogView request={request} onClose={closeConfirm} />
      ) : null}
      {request?.kind === "confirm-choices" ? (
        <ConfirmChoicesDialogView request={request} onClose={closeConfirmChoices} />
      ) : null}
      {request?.kind === "prompt" ? (
        <PromptDialogView request={request} onClose={closePrompt} />
      ) : null}
    </ConfirmContext.Provider>
  );
}

export function useConfirm() {
  const ctx = useContext(ConfirmContext);
  if (!ctx) throw new Error("useConfirm must be used within ConfirmProvider");
  return ctx;
}
