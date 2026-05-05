import React from 'react'

export default function LoadingFallback() {
  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      height: '60vh',
      gap: '16px',
    }}>
      <div style={{
        width: '36px',
        height: '36px',
        border: '3px solid var(--border-color)',
        borderTopColor: 'var(--accent)',
        borderRadius: '50%',
        animation: 'spin 0.8s linear infinite',
      }} />
      <span style={{
        fontSize: '13px',
        color: 'var(--text-secondary)',
        fontFamily: 'var(--font-body)',
      }}>
        加载中...
      </span>
      <style>{`
        @keyframes spin {
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  )
}
