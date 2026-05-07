import React, { createContext, useContext, useState, useEffect } from 'react'

type Theme = 'matrix' | 'amber' | 'cyberpunk' | 'nord' | 'dracula' | 'monokai' | 'solarized' | 'midnight' | 'retro' | 'ocean'

interface ThemeContextType {
  theme: Theme
  setTheme: (theme: Theme) => void
  themes: Theme[]
}

const ThemeContext = createContext<ThemeContextType | undefined>(undefined)

const themes: Theme[] = ['matrix', 'amber', 'cyberpunk', 'nord', 'dracula', 'monokai', 'solarized', 'midnight', 'retro', 'ocean']

export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const [theme, setThemeState] = useState<Theme>(() => {
    const saved = localStorage.getItem('theme') as Theme
    return saved || 'cyberpunk'
  })

  const setTheme = (newTheme: Theme) => {
    setThemeState(newTheme)
    localStorage.setItem('theme', newTheme)
  }

  useEffect(() => {
    document.body.className = `theme-${theme}`
  }, [theme])

  return (
    <ThemeContext.Provider value={{ theme, setTheme, themes }}>
      {children}
    </ThemeContext.Provider>
  )
}

export function useTheme() {
  const context = useContext(ThemeContext)
  if (!context) {
    throw new Error('useTheme must be used within ThemeProvider')
  }
  return context
}
