import React from 'react'
import { useTheme } from '../contexts/ThemeContext'
import { useI18n } from '../contexts/I18nContext'

export default function Settings() {
  const { theme, setTheme, themes } = useTheme()
  const { locale, setLocale, locales } = useI18n()

  return (
    <div className="space-y-6 page-enter max-w-2xl">
      <h1 className="sec-title text-2xl">Settings</h1>

      <div className="card p-6 space-y-6">
        <div>
          <label className="label-text mb-3 block">Theme</label>
          <div className="flex flex-wrap gap-3">
            {themes.map((t) => (
              <button
                key={t}
                onClick={() => setTheme(t)}
                className={`btn ${theme === t ? 'btn-accent' : ''}`}
              >
                {t}
              </button>
            ))}
          </div>
        </div>

        <div>
          <label className="label-text mb-3 block">Language</label>
          <select
            className="pixel-select"
            value={locale}
            onChange={(e) => setLocale(e.target.value as any)}
          >
            {locales.map((l) => (
              <option key={l} value={l}>{l}</option>
            ))}
          </select>
        </div>
      </div>
    </div>
  )
}
