import React, { createContext, useContext, useState, useCallback } from 'react'

interface Toast {
  id: string
  type: 'success' | 'error' | 'warning' | 'info'
  message: string
  duration?: number
}

interface ToastContextType {
  toasts: Toast[]
  addToast: (toast: Omit<Toast, 'id'>) => void
  removeToast: (id: string) => void
}

const ToastContext = createContext<ToastContextType | undefined>(undefined)

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([])

  const addToast = useCallback(({ type, message, duration = 3000 }: Omit<Toast, 'id'>) => {
    const id = Math.random().toString(36).substring(2, 9)
    const toast: Toast = { id, type, message, duration }

    setToasts((prev) => [...prev, toast])

    if (duration > 0) {
      setTimeout(() => {
        setToasts((prev) => prev.filter((t) => t.id !== id))
      }, duration)
    }
  }, [])

  const removeToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id))
  }, [])

  return (
    <ToastContext.Provider value={{ toasts, addToast, removeToast }}>
      {children}
      <ToastContainer toasts={toasts} removeToast={removeToast} />
    </ToastContext.Provider>
  )
}

function ToastContainer({ toasts, removeToast }: { toasts: Toast[]; removeToast: (id: string) => void }) {
  const typeStyles = {
    success: 'border-[var(--success)] bg-[var(--success-subtle)]',
    error: 'border-[var(--danger)] bg-[var(--danger-subtle)]',
    warning: 'border-[var(--warning)] bg-[var(--warning-subtle)]',
    info: 'border-[var(--info)] bg-[var(--info-subtle)]',
  }

  return (
    <div className="fixed bottom-4 right-4 z-50 space-y-2">
      {toasts.map((toast) => (
        <div
          key={toast.id}
          className={`card p-4 min-w-[300px] max-w-[400px] border-l-4 ${typeStyles[toast.type]}`}
        >
          <div className="flex items-center justify-between">
            <span className="text-sm">{toast.message}</span>
            <button
              onClick={() => removeToast(toast.id)}
              className="text-[var(--text-dim)] hover:text-[var(--text-primary)]"
            >
              ✕
            </button>
          </div>
        </div>
      ))}
    </div>
  )
}

export function useToast() {
  const context = useContext(ToastContext)
  if (!context) {
    throw new Error('useToast must be used within ToastProvider')
  }
  return context
}
