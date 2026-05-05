import { useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'

const SHORTCUTS = {
  'g d': { label: '仪表盘', path: '/', category: '导航' },
  'g t': { label: '扫描任务', path: '/tasks', category: '导航' },
  'g n': { label: '新建扫描', path: '/tasks/new', category: '导航' },
  'g v': { label: '漏洞列表', path: '/vulnerabilities', category: '导航' },
  'g r': { label: '扫描报告', path: '/reports', category: '导航' },
  'g i': { label: '信息收集', path: '/recon', category: '导航' },
  'g a': { label: '攻击引擎', path: '/attack', category: '导航' },
  'g p': { label: 'POC管理', path: '/pocs', category: '导航' },
  'g s': { label: '系统设置', path: '/settings', category: '导航' },
  '?': { label: '显示快捷键帮助', action: 'help', category: '通用' },
  'Escape': { label: '关闭弹窗/侧栏', action: 'escape', category: '通用' },
}

export function useKeyboardShortcuts({ onHelp, onEscape } = {}) {
  const navigate = useNavigate()
  const keysPressed = {}

  const handleKeyDown = useCallback((e) => {
    if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') {
      if (e.key === 'Escape') {
        e.target.blur()
        onEscape?.()
      }
      return
    }

    keysPressed[e.key.toLowerCase()] = true

    if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault()
      onHelp?.()
      return
    }

    if (e.key === 'Escape') {
      onEscape?.()
      return
    }

    if (e.key === 'g' && !e.ctrlKey && !e.metaKey) {
      return
    }

    if (keysPressed['g']) {
      const combo = `g ${e.key.toLowerCase()}`
      const shortcut = SHORTCUTS[combo]
      if (shortcut?.path) {
        e.preventDefault()
        navigate(shortcut.path)
      }
    }
  }, [navigate, onHelp, onEscape])

  const handleKeyUp = useCallback((e) => {
    delete keysPressed[e.key.toLowerCase()]
  }, [])

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown)
    window.addEventListener('keyup', handleKeyUp)
    return () => {
      window.removeEventListener('keydown', handleKeyDown)
      window.removeEventListener('keyup', handleKeyUp)
    }
  }, [handleKeyDown, handleKeyUp])

  return { shortcuts: SHORTCUTS }
}

export function KeyboardHelpModal({ open, onClose }) {
  if (!open) return null

  const categories = {}
  Object.entries(SHORTCUTS).forEach(([key, info]) => {
    if (!categories[info.category]) categories[info.category] = []
    categories[info.category].push({ key, ...info })
  })

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 10001,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
      }}
      onClick={onClose}
    >
      <div
        style={{
          position: 'absolute',
          inset: 0,
          background: 'rgba(0,0,0,0.6)',
        }}
      />
      <div
        style={{
          position: 'relative',
          background: 'var(--bg-card)',
          border: '1px solid var(--border-color)',
          borderRadius: '12px',
          padding: '24px',
          maxWidth: '560px',
          width: '90%',
          maxHeight: '80vh',
          overflowY: 'auto',
          boxShadow: '0 16px 48px var(--shadow-color)',
        }}
        onClick={(e) => e.stopPropagation()}
        role="dialog"
        aria-label="键盘快捷键帮助"
      >
        <div style={{
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          marginBottom: '20px',
        }}>
          <h2 style={{
            fontSize: '16px',
            fontWeight: 700,
            color: 'var(--text-bright)',
            fontFamily: 'var(--font-title)',
          }}>
            键盘快捷键
          </h2>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--text-dim)',
              cursor: 'pointer',
              fontSize: '18px',
              padding: '4px',
            }}
            aria-label="关闭"
          >
            ✕
          </button>
        </div>

        {Object.entries(categories).map(([category, items]) => (
          <div key={category} style={{ marginBottom: '20px' }}>
            <div style={{
              fontSize: '11px',
              fontWeight: 600,
              color: 'var(--text-dim)',
              textTransform: 'uppercase',
              letterSpacing: '1px',
              marginBottom: '8px',
            }}>
              {category}
            </div>
            {items.map((item) => (
              <div
                key={item.key}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '6px 0',
                  borderBottom: '1px solid var(--border-color)',
                }}
              >
                <span style={{ fontSize: '13px', color: 'var(--text-primary)' }}>
                  {item.label}
                </span>
                <kbd style={{
                  display: 'inline-block',
                  padding: '2px 8px',
                  background: 'var(--bg-tertiary)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '4px',
                  fontSize: '11px',
                  fontFamily: 'var(--font-title)',
                  color: 'var(--accent)',
                  fontWeight: 600,
                }}>
                  {item.key.replace('g ', 'g + ')}
                </kbd>
              </div>
            ))}
          </div>
        ))}

        <div style={{
          marginTop: '16px',
          padding: '10px',
          background: 'var(--bg-tertiary)',
          borderRadius: '6px',
          fontSize: '11px',
          color: 'var(--text-dim)',
          textAlign: 'center',
        }}>
          按 <kbd style={{
            padding: '1px 6px',
            background: 'var(--bg-primary)',
            border: '1px solid var(--border-color)',
            borderRadius: '3px',
            fontSize: '11px',
            fontFamily: 'var(--font-title)',
            color: 'var(--accent)',
          }}>?</kbd> 随时查看快捷键帮助
        </div>
      </div>
    </div>
  )
}

export { SHORTCUTS }
