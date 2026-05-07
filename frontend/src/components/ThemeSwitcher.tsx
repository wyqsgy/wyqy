import React from 'react'
import { useTheme } from '../contexts/ThemeContext'

const themes = [
  { id: 'matrix', name: 'Matrix', class: 'theme-dot-matrix' },
  { id: 'amber', name: 'Amber', class: 'theme-dot-amber' },
  { id: 'cyberpunk', name: 'Cyberpunk', class: 'theme-dot-cyberpunk' },
  { id: 'nord', name: 'Nord', class: 'theme-dot-nord' },
  { id: 'dracula', name: 'Dracula', class: 'theme-dot-dracula' },
  { id: 'ocean', name: 'Ocean', class: 'theme-dot-ocean' },
]

export default function ThemeSwitcher() {
  const { theme, setTheme } = useTheme()

  return (
    <div className="theme-switcher">
      {themes.map((t) => (
        <button
          key={t.id}
          className={`theme-dot ${t.class} ${theme === t.id ? 'active' : ''}`}
          onClick={() => setTheme(t.id as any)}
          title={t.name}
        />
      ))}
    </div>
  )
}
