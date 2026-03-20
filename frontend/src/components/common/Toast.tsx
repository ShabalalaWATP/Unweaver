import { createContext, useContext, useState, useCallback, useRef } from 'react';
import { CheckCircle, XCircle, Info, AlertTriangle, X } from 'lucide-react';

// ════════════════════════════════════════════════════════════════════════
//  Types
// ════════════════════════════════════════════════════════════════════════

type ToastType = 'success' | 'error' | 'info' | 'warning';

interface Toast {
  id: number;
  message: string;
  type: ToastType;
  exiting?: boolean;
}

interface ToastContextValue {
  addToast: (message: string, type?: ToastType) => void;
  success: (message: string) => void;
  error: (message: string) => void;
  info: (message: string) => void;
  warning: (message: string) => void;
}

// ════════════════════════════════════════════════════════════════════════
//  Context
// ════════════════════════════════════════════════════════════════════════

const ToastContext = createContext<ToastContextValue | null>(null);

export function useToast(): ToastContextValue {
  const ctx = useContext(ToastContext);
  if (!ctx) throw new Error('useToast must be used within <ToastProvider>');
  return ctx;
}

// ════════════════════════════════════════════════════════════════════════
//  Config
// ════════════════════════════════════════════════════════════════════════

const TOAST_DURATION = 4000;
const EXIT_ANIMATION = 300;

const TYPE_CONFIG: Record<ToastType, {
  icon: React.ReactNode;
  color: string;
  bg: string;
  border: string;
}> = {
  success: {
    icon: <CheckCircle size={14} />,
    color: 'var(--success)',
    bg: 'rgba(63,185,80,0.1)',
    border: 'rgba(63,185,80,0.25)',
  },
  error: {
    icon: <XCircle size={14} />,
    color: 'var(--danger)',
    bg: 'rgba(248,81,73,0.1)',
    border: 'rgba(248,81,73,0.25)',
  },
  info: {
    icon: <Info size={14} />,
    color: 'var(--accent)',
    bg: 'rgba(88,166,255,0.1)',
    border: 'rgba(88,166,255,0.25)',
  },
  warning: {
    icon: <AlertTriangle size={14} />,
    color: 'var(--warning)',
    bg: 'rgba(210,153,34,0.1)',
    border: 'rgba(210,153,34,0.25)',
  },
};

// ════════════════════════════════════════════════════════════════════════
//  Styles
// ════════════════════════════════════════════════════════════════════════

const s = {
  container: {
    position: 'fixed',
    bottom: '16px',
    right: '16px',
    display: 'flex',
    flexDirection: 'column',
    gap: '8px',
    zIndex: 10000,
    pointerEvents: 'none',
  } as React.CSSProperties,
  toast: {
    display: 'flex',
    alignItems: 'center',
    gap: '10px',
    padding: '10px 14px',
    borderRadius: 'var(--radius-lg, 10px)',
    border: '1px solid',
    fontSize: '12px',
    fontWeight: 500,
    minWidth: '260px',
    maxWidth: '400px',
    backdropFilter: 'blur(12px)',
    boxShadow: 'var(--shadow-lg)',
    pointerEvents: 'auto',
    transition: 'all 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
  } as React.CSSProperties,
  toastEnter: {
    animation: 'toast-slide-in 0.3s cubic-bezier(0.4, 0, 0.2, 1)',
  } as React.CSSProperties,
  toastExit: {
    opacity: 0,
    transform: 'translateX(100%)',
  } as React.CSSProperties,
  message: {
    flex: 1,
    lineHeight: '1.4',
  } as React.CSSProperties,
  closeBtn: {
    padding: '2px',
    borderRadius: 'var(--radius-sm, 4px)',
    color: 'var(--text-muted)',
    cursor: 'pointer',
    display: 'flex',
    alignItems: 'center',
    transition: 'color 0.15s',
    flexShrink: 0,
  } as React.CSSProperties,
};

// ════════════════════════════════════════════════════════════════════════
//  Provider
// ════════════════════════════════════════════════════════════════════════

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const idCounter = useRef(0);

  const removeToast = useCallback((id: number) => {
    setToasts((prev) => prev.map((t) => (t.id === id ? { ...t, exiting: true } : t)));
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, EXIT_ANIMATION);
  }, []);

  const addToast = useCallback(
    (message: string, type: ToastType = 'info') => {
      const id = ++idCounter.current;
      setToasts((prev) => [...prev.slice(-4), { id, message, type }]); // keep max 5
      setTimeout(() => removeToast(id), TOAST_DURATION);
    },
    [removeToast],
  );

  const contextValue: ToastContextValue = {
    addToast,
    success: useCallback((msg: string) => addToast(msg, 'success'), [addToast]),
    error: useCallback((msg: string) => addToast(msg, 'error'), [addToast]),
    info: useCallback((msg: string) => addToast(msg, 'info'), [addToast]),
    warning: useCallback((msg: string) => addToast(msg, 'warning'), [addToast]),
  };

  return (
    <ToastContext.Provider value={contextValue}>
      {children}
      <div style={s.container}>
        {toasts.map((toast) => {
          const cfg = TYPE_CONFIG[toast.type];
          return (
            <div
              key={toast.id}
              style={{
                ...s.toast,
                color: cfg.color,
                background: cfg.bg,
                borderColor: cfg.border,
                ...(toast.exiting ? s.toastExit : s.toastEnter),
              }}
            >
              {cfg.icon}
              <span style={s.message}>{toast.message}</span>
              <button
                style={s.closeBtn}
                onClick={() => removeToast(toast.id)}
                onMouseEnter={(e) => { e.currentTarget.style.color = 'var(--text-primary)'; }}
                onMouseLeave={(e) => { e.currentTarget.style.color = 'var(--text-muted)'; }}
              >
                <X size={12} />
              </button>
            </div>
          );
        })}
      </div>
    </ToastContext.Provider>
  );
}

// ════════════════════════════════════════════════════════════════════════
//  Inject keyframes (toast-slide-in)
// ════════════════════════════════════════════════════════════════════════

const KEYFRAMES = `
@keyframes toast-slide-in {
  from {
    opacity: 0;
    transform: translateX(100%) scale(0.95);
  }
  to {
    opacity: 1;
    transform: translateX(0) scale(1);
  }
}`;

// Inject once
if (typeof document !== 'undefined') {
  const existing = document.getElementById('unweaver-toast-keyframes');
  if (!existing) {
    const style = document.createElement('style');
    style.id = 'unweaver-toast-keyframes';
    style.textContent = KEYFRAMES;
    document.head.appendChild(style);
  }
}
