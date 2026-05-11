import {
  createContext,
  useCallback,
  useContext,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';

export type ToastTone = 'info' | 'success' | 'warning' | 'error';

export interface Toast {
  id: number;
  tone: ToastTone;
  title?: string;
  message: string;
  durationMs: number;
}

interface ToastContextValue {
  toasts: Toast[];
  push: (
    t: Omit<Toast, 'id' | 'durationMs'> & { durationMs?: number },
  ) => number;
  dismiss: (id: number) => void;
  /** Convenience helpers so call sites read naturally as toast.error('...'). */
  info: (message: string, title?: string) => number;
  success: (message: string, title?: string) => number;
  warning: (message: string, title?: string) => number;
  error: (message: string, title?: string) => number;
}

const ToastContext = createContext<ToastContextValue | null>(null);

const DEFAULT_DURATION: Record<ToastTone, number> = {
  info: 4000,
  success: 4000,
  warning: 6000,
  // Error toasts stick longer because failures usually need a deliberate read.
  error: 8000,
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);
  const timers = useRef(new Map<number, number>());

  const dismiss = useCallback((id: number) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
    const handle = timers.current.get(id);
    if (handle !== undefined) {
      window.clearTimeout(handle);
      timers.current.delete(id);
    }
  }, []);

  const push = useCallback<ToastContextValue['push']>(
    ({ tone, title, message, durationMs }) => {
      const id = nextId.current++;
      const duration = durationMs ?? DEFAULT_DURATION[tone];
      setToasts((prev) => [
        ...prev,
        { id, tone, title, message, durationMs: duration },
      ]);
      if (duration > 0) {
        const handle = window.setTimeout(() => dismiss(id), duration);
        timers.current.set(id, handle);
      }
      return id;
    },
    [dismiss],
  );

  const value = useMemo<ToastContextValue>(
    () => ({
      toasts,
      push,
      dismiss,
      info: (message, title) => push({ tone: 'info', message, title }),
      success: (message, title) => push({ tone: 'success', message, title }),
      warning: (message, title) => push({ tone: 'warning', message, title }),
      error: (message, title) => push({ tone: 'error', message, title }),
    }),
    [toasts, push, dismiss],
  );

  return (
    <ToastContext.Provider value={value}>{children}</ToastContext.Provider>
  );
}

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used inside <ToastProvider>');
  return ctx;
}
