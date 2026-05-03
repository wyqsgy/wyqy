import React from 'react'

const themes = [
  { id: 'matrix', name: 'MATRIX', class: 'theme-dot-matrix' },
  { id: 'amber', name: 'AMBER', class: 'theme-dot-amber' },
  { id: 'cyberpunk', name: 'CYBER', class: 'theme-dot-cyberpunk' },
  { id: 'retro', name: 'RETRO', class: 'theme-dot-retro' },
  { id: 'ocean', name: 'OCEAN', class: 'theme-dot-ocean' },
]

export default function ThemeSwitcher({ current, onChange }) {
  return (
    <div className="theme-switcher">
      {themes.map((t) => (
        <div
          key={t.id}
          className={`theme-dot ${t.class} ${current === t.id ? 'active' : ''}`}
          onClick={() => onChange(t.id)}
          data-tooltip={t.name}
          title={t.name}
        />
      ))}
    </div>
  )
}
