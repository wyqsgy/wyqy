import React, { createContext, useContext, useState, useEffect, useCallback } from 'react'

const ThemeContext = createContext(null)

const THEME_KEY = 'wyqyan-theme'
const THEME_META_COLOR = '#0e1525'

const THEMES = [
  { id: 'matrix', name: '矩阵', color: '#58a6ff', category: 'dark' },
  { id: 'amber', name: '琥珀', color: '#e0a840', category: 'dark' },
  { id: 'cyberpunk', name: '赛博', color: '#a855f7', category: 'dark' },
  { id: 'retro', name: '复古', color: '#999999', category: 'dark' },
  { id: 'ocean', name: '海洋', color: '#3b82f6', category: 'dark' },
  { id: 'nord', name: 'Nord', color: '#88c0d0', category: 'dark' },
  { id: 'dracula', name: 'Dracula', color: '#bd93f9', category: 'dark' },
  { id: 'monokai', name: 'Monokai', color: '#a6e22e', category: 'dark' },
  { id: 'solarized', name: 'Solarized', color: '#2aa198', category: 'dark' },
  { id: 'midnight', name: '午夜', color: '#6366f1', category: 'dark' },
]

function getSystemTheme() {
  if (typeof window === 'undefined') return 'matrix'
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'matrix' : 'matrix'
}

function getStoredTheme() {
  try {
    const stored = localStorage.getItem(THEME_KEY)
    if (stored && THEMES.find(t => t.id === stored)) return stored
  } catch {}
  return null
}

export function ThemeProvider({ children }) {
  const [theme, setThemeState] = useState(() => {
    return getStoredTheme() || getSystemTheme()
  })
  const [transitioning, setTransitioning] = useState(false)

  const setTheme = useCallback((newTheme) => {
    if (newTheme === theme) return
    setTransitioning(true)
    setThemeState(newTheme)
    try {
      localStorage.setItem(THEME_KEY, newTheme)
    } catch {}
    setTimeout(() => setTransitioning(false), 400)
  }, [theme])

  useEffect(() => {
    document.body.className = `theme-${theme}${transitioning ? ' theme-transitioning' : ''}`
    const meta = document.querySelector('meta[name="theme-color"]')
    if (meta) {
      const themeInfo = THEMES.find(t => t.id === theme)
      meta.setAttribute('content', themeInfo?.color || THEME_META_COLOR)
    }
  }, [theme, transitioning])

  useEffect(() => {
    const mq = window.matchMedia('(prefers-color-scheme: dark)')
    const handler = () => {
      if (!getStoredTheme()) {
        setThemeState(getSystemTheme())
      }
    }
    mq.addEventListener('change', handler)
    return () => mq.removeEventListener('change', handler)
  }, [])

  const value = {
    theme,
    setTheme,
    themes: THEMES,
    currentTheme: THEMES.find(t => t.id === theme),
    transitioning,
  }

  return (
    <ThemeContext.Provider value={value}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  const ctx = useContext(ThemeContext)
  if (!ctx) throw new Error('useTheme must be used within ThemeProvider')
  return ctx
}

export { THEMES }
