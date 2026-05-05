import React, { createContext, useContext, useState, useCallback, useRef, useEffect } from 'react'

const ToastContext = createContext(null)

let toastIdCounter = 0

const TOAST_ICONS = {
  success: '✓',
  error: '✕',
  warning: '!',
  info: 'i',
}

const TOAST_COLORS = {
  success: { bg: 'var(--success-subtle)', border: 'var(--success)', color: 'var(--success)' },
  error: { bg: 'var(--danger-subtle)', border: 'var(--danger)', color: 'var(--danger)' },
  warning: { bg: 'var(--warning-subtle)', border: 'var(--warning)', color: 'var(--warning)' },
  info: { bg: 'var(--info-subtle)', border: 'var(--info)', color: 'var(--info)' },
}

function ToastItem({ toast, onDismiss }) {
  const [exiting, setExiting] = useState(false)
  const timerRef = useRef(null)

  useEffect(() => {
    if (toast.duration > 0) {
      timerRef.current = setTimeout(() => {
        setExiting(true)
        setTimeout(() => onDismiss(toast.id), 300)
      }, toast.duration)
    }
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [toast.duration, toast.id, onDismiss])

  const handleDismiss = () => {
    if (timerRef.current) clearTimeout(timerRef.current)
    setExiting(true)
    setTimeout(() => onDismiss(toast.id), 300)
  }

  const colors = TOAST_COLORS[toast.type] || TOAST_COLORS.info

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'flex-start',
        gap: '10px',
        padding: '12px 16px',
        background: 'var(--bg-card)',
        border: `1px solid ${colors.border}`,
        borderLeft: `3px solid ${colors.border}`,
        borderRadius: '8px',
        boxShadow: '0 4px 16px var(--shadow-color)',
        minWidth: '300px',
        maxWidth: '420px',
        animation: exiting ? 'toast-exit 0.3s ease forwards' : 'toast-enter 0.3s ease',
        pointerEvents: 'auto',
      }}
    >
      <span style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        width: '22px',
        height: '22px',
        borderRadius: '50%',
        background: colors.bg,
        color: colors.color,
        fontSize: '12px',
        fontWeight: 700,
        flexShrink: 0,
        fontFamily: 'var(--font-title)',
      }}>
        {TOAST_ICONS[toast.type]}
      </span>
      <div style={{ flex: 1, minWidth: 0 }}>
        {toast.title && (
          <div style={{
            fontSize: '13px',
            fontWeight: 600,
            color: 'var(--text-bright)',
            marginBottom: '2px',
          }}>
            {toast.title}
          </div>
        )}
        <div style={{
          fontSize: '12px',
          color: 'var(--text-secondary)',
          lineHeight: '1.5',
          wordBreak: 'break-word',
        }}>
          {toast.message}
        </div>
      </div>
      <button
        onClick={handleDismiss}
        style={{
          background: 'none',
          border: 'none',
          color: 'var(--text-dim)',
          cursor: 'pointer',
          fontSize: '14px',
          padding: '2px',
          lineHeight: 1,
          flexShrink: 0,
        }}
        aria-label="关闭通知"
      >
        ✕
      </button>
    </div>
  )
}

export function ToastProvider({ children }) {
  const [toasts, setToasts] = useState([])

  const addToast = useCallback((toast) => {
    const id = ++toastIdCounter
    const newToast = {
      id,
      type: toast.type || 'info',
      title: toast.title || '',
      message: toast.message || '',
      duration: toast.duration ?? 4000,
    }
    setToasts(prev => [...prev, newToast])
    return id
  }, [])

  const dismissToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  const toast = useCallback((message, type = 'info', options = {}) => {
    return addToast({ message, type, ...options })
  }, [addToast])

  const toastSuccess = useCallback((message, options = {}) => {
    return addToast({ message, type: 'success', ...options })
  }, [addToast])

  const toastError = useCallback((message, options = {}) => {
    return addToast({ message, type: 'error', duration: 6000, ...options })
  }, [addToast])

  const toastWarning = useCallback((message, options = {}) => {
    return addToast({ message, type: 'warning', ...options })
  }, [addToast])

  const toastInfo = useCallback((message, options = {}) => {
    return addToast({ message, type: 'info', ...options })
  }, [addToast])

  const value = {
    toasts,
    toast,
    toastSuccess,
    toastError,
    toastWarning,
    toastInfo,
    dismissToast,
  }

  return (
    <ToastContext.Provider value={value}>
      {children}
      <div
        style={{
          position: 'fixed',
          top: '16px',
          right: '16px',
          zIndex: 10000,
          display: 'flex',
          flexDirection: 'column',
          gap: '8px',
          pointerEvents: 'none',
        }}
      >
        {toasts.map((t) => (
          <ToastItem key={t.id} toast={t} onDismiss={dismissToast} />
        ))}
      </div>
      <style>{`
        @keyframes toast-enter {
          from {
            opacity: 0;
            transform: translateX(100%) scale(0.95);
          }
          to {
            opacity: 1;
            transform: translateX(0) scale(1);
          }
        }
        @keyframes toast-exit {
          from {
            opacity: 1;
            transform: translateX(0) scale(1);
          }
          to {
            opacity: 0;
            transform: translateX(100%) scale(0.95);
          }
        }
      `}</style>
    </ToastContext.Provider>
  )
}

export function useToast() {
  const ctx = useContext(ToastContext)
  if (!ctx) throw new Error('useToast must be used within ToastProvider')
  return ctx
}
