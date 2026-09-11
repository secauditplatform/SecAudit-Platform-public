import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";

export type ToastVariant = "success" | "error" | "info";

type ToastItem = {
  id: number;
  message: string;
  variant: ToastVariant;
  isExiting?: boolean;
};

type ToastContextValue = {
  toast: (message: string, variant?: ToastVariant) => void;
  success: (message: string) => void;
  error: (message: string) => void;
};

const ToastContext = createContext<ToastContextValue | null>(null);

const TOAST_DURATION_MS = 4000;
const TOAST_EXIT_MS = 180;

const TOAST_META = {
  success: { title: "Success", icon: "check" },
  error: { title: "Error", icon: "error" },
  info: { title: "Info", icon: "info" },
} as const satisfies Record<ToastVariant, { title: string; icon: "check" | "error" | "info" }>;

function ToastIcon({ icon }: { icon: "check" | "error" | "info" }) {
  if (icon === "check") {
    return (
      <svg viewBox="0 0 16 16" aria-hidden="true">
        <path d="M6.6 11.6 3.4 8.4l-1 1L6.6 13.6l7-7-1-1z" />
      </svg>
    );
  }
  if (icon === "error") {
    return (
      <svg viewBox="0 0 16 16" aria-hidden="true">
        <path d="m8 6.6-2.8-2.8-1 1L7 7.6 4.2 10.4l1 1L8 8.6l2.8 2.8 1-1L9 7.6l2.8-2.8-1-1z" />
      </svg>
    );
  }
  return (
    <svg viewBox="0 0 16 16" aria-hidden="true">
      <path d="M7.25 6.5h1.5V12h-1.5zM8 3a1 1 0 1 0 .001 2.001A1 1 0 0 0 8 3z" />
    </svg>
  );
}

function ToastView({ item, onDismiss }: { item: ToastItem; onDismiss: (id: number) => void }) {
  const meta = TOAST_META[item.variant];

  useEffect(() => {
    const timer = window.setTimeout(() => onDismiss(item.id), TOAST_DURATION_MS);
    return () => window.clearTimeout(timer);
  }, [item.id, onDismiss]);

  return (
    <div
      className={`pf-toast pf-toast--${item.variant}${item.isExiting ? " pf-toast--exiting" : ""}`}
      role={item.variant === "error" ? "alert" : "status"}
      aria-live={item.variant === "error" ? "assertive" : "polite"}
      aria-atomic="true"
    >
      <span className="pf-toast__icon" aria-hidden="true">
        <ToastIcon icon={meta.icon} />
      </span>
      <div className="pf-toast__content">
        <p className="pf-toast__title">{meta.title}</p>
        <p className="pf-toast__message">{item.message}</p>
      </div>
    </div>
  );
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([]);
  const nextId = useRef(0);
  const exitTimers = useRef<Map<number, number>>(new Map());

  const dismiss = useCallback((id: number) => {
    setToasts((prev) =>
      prev.map((toast) => (toast.id === id ? { ...toast, isExiting: true } : toast)),
    );

    if (exitTimers.current.has(id)) return;

    const timer = window.setTimeout(() => {
      setToasts((prev) => prev.filter((toast) => toast.id !== id));
      exitTimers.current.delete(id);
    }, TOAST_EXIT_MS);
    exitTimers.current.set(id, timer);
  }, []);

  const toast = useCallback((message: string, variant: ToastVariant = "info") => {
    const id = ++nextId.current;
    setToasts((prev) => [...prev, { id, message, variant }]);
  }, []);

  useEffect(
    () => () => {
      exitTimers.current.forEach((timer) => window.clearTimeout(timer));
      exitTimers.current.clear();
    },
    [],
  );

  const value: ToastContextValue = {
    toast,
    success: (message) => toast(message, "success"),
    error: (message) => toast(message, "error"),
  };

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div className="pf-toast-container" aria-live="polite" aria-atomic="true">
        {toasts.map((item) => (
          <ToastView key={item.id} item={item} onDismiss={dismiss} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast() {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error("useToast must be used within ToastProvider");
  return ctx;
}
