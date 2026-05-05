import React, { useState, useRef, useEffect } from 'react'

const themes = [
  { id: 'matrix', name: '矩阵 Matrix', color: '#58a6ff' },
  { id: 'amber', name: '琥珀 Amber', color: '#e0a840' },
  { id: 'cyberpunk', name: '赛博 Cyberpunk', color: '#a855f7' },
  { id: 'retro', name: '复古 Retro', color: '#999999' },
  { id: 'ocean', name: '海洋 Ocean', color: '#3b82f6' },
  { id: 'nord', name: 'Nord', color: '#88c0d0' },
  { id: 'dracula', name: 'Dracula', color: '#bd93f9' },
  { id: 'monokai', name: 'Monokai', color: '#a6e22e' },
  { id: 'solarized', name: 'Solarized', color: '#2aa198' },
  { id: 'midnight', name: '午夜 Midnight', color: '#6366f1' },
]

export default function ThemeSwitcher({ current, onChange }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)

  useEffect(() => {
    function handleClick(e) {
      if (ref.current && !ref.current.contains(e.target)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClick)
    return () => document.removeEventListener('mousedown', handleClick)
  }, [])

  const currentTheme = themes.find(t => t.id === current) || themes[0]

  return (
    <div ref={ref} style={{ position: 'relative' }}>
      <button
        onClick={() => setOpen(!open)}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: '8px',
          width: '100%',
          padding: '8px 12px',
          background: 'var(--bg-tertiary)',
          border: '1px solid var(--border-color)',
          borderRadius: '6px',
          cursor: 'pointer',
          color: 'var(--text-primary)',
          fontSize: '12px',
          fontFamily: 'var(--font-body)',
          fontWeight: 600,
          transition: 'all 0.15s ease',
        }}
      >
        <span style={{
          width: '14px',
          height: '14px',
          borderRadius: '50%',
          background: currentTheme.color,
          flexShrink: 0,
        }} />
        <span style={{ flex: 1, textAlign: 'left' }}>{currentTheme.name}</span>
        <span style={{
          fontSize: '10px',
          color: 'var(--text-dim)',
          transform: open ? 'rotate(180deg)' : 'rotate(0)',
          transition: 'transform 0.2s ease',
        }}>
          ▼
        </span>
      </button>

      {open && (
        <div style={{
          position: 'absolute',
          top: '100%',
          left: 0,
          right: 0,
          marginTop: '4px',
          background: 'var(--bg-card)',
          border: '1px solid var(--border-color)',
          borderRadius: '6px',
          overflow: 'hidden',
          zIndex: 1001,
          boxShadow: '0 8px 24px var(--shadow-color)',
          maxHeight: '240px',
          overflowY: 'auto',
        }}>
          {themes.map((t) => (
            <div
              key={t.id}
              onClick={() => {
                onChange(t.id)
                setOpen(false)
              }}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '8px 12px',
                cursor: 'pointer',
                background: current === t.id ? 'var(--sidebar-active)' : 'transparent',
                color: current === t.id ? 'var(--text-bright)' : 'var(--text-secondary)',
                fontSize: '12px',
                fontFamily: 'var(--font-body)',
                fontWeight: current === t.id ? 600 : 400,
                transition: 'all 0.1s ease',
              }}
              onMouseEnter={(e) => {
                if (current !== t.id) e.target.style.background = 'var(--bg-hover)'
              }}
              onMouseLeave={(e) => {
                if (current !== t.id) e.target.style.background = 'transparent'
              }}
            >
              <span style={{
                width: '14px',
                height: '14px',
                borderRadius: '50%',
                background: t.color,
                flexShrink: 0,
              }} />
              {t.name}
              {current === t.id && (
                <span style={{ marginLeft: 'auto', color: 'var(--accent)', fontSize: '11px' }}>✓</span>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
