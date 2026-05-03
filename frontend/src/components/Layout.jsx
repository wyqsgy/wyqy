import React, { useState, useEffect } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import ThemeSwitcher from './ThemeSwitcher'

const navItems = [
  { to: '/', icon: '[~]', label: 'DASHBOARD' },
  { to: '/tasks', icon: '[>]', label: 'TASKS' },
  { to: '/tasks/new', icon: '[+]', label: 'NEW SCAN' },
  { to: '/vulnerabilities', icon: '[!]', label: 'VULNS' },
  { to: '/reports', icon: '[#]', label: 'REPORTS' },
  { to: '/recon', icon: '[@]', label: 'RECON' },
  { to: '/attack', icon: '[*]', label: 'ATTACK' },
]

const THEME_KEY = 'wyqyan-theme'

export default function Layout() {
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem(THEME_KEY) || 'matrix'
  })

  useEffect(() => {
    localStorage.setItem(THEME_KEY, theme)
    document.body.className = `theme-${theme}`
  }, [theme])

  return (
    <div className={`flex h-screen theme-${theme}`} style={{ background: 'var(--bg-primary)' }}>
      <div className="crt-overlay" />
      <div className="scan-line-moving" />

      <aside style={{
        width: '220px',
        background: 'var(--bg-secondary)',
        borderRight: '2px solid var(--border-color)',
        display: 'flex',
        flexDirection: 'column',
        boxShadow: '2px 0 15px var(--shadow-color)',
      }}>
        <div style={{
          padding: '16px',
          borderBottom: '2px solid var(--border-color)',
          textAlign: 'center',
        }}>
          <div className="pixel-text" style={{
            fontSize: '12px',
            color: 'var(--text-bright)',
            textShadow: '0 0 10px var(--accent-glow)',
            animation: 'textGlow 2s ease-in-out infinite',
          }}>
            [ WyqYan ]
          </div>
          <div className="pixel-text-sm" style={{
            color: 'var(--text-dim)',
            marginTop: '6px',
          }}>
            DDDD2 BLUEPRINT
          </div>
          <div style={{ marginTop: '8px' }}>
            <ThemeSwitcher current={theme} onChange={setTheme} />
          </div>
        </div>

        <nav style={{ flex: 1, padding: '8px', overflowY: 'auto' }}>
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              style={({ isActive }) => ({
                display: 'flex',
                alignItems: 'center',
                padding: '10px 12px',
                marginBottom: '2px',
                fontFamily: 'var(--pixel-font)',
                fontSize: '8px',
                color: isActive ? 'var(--text-bright)' : 'var(--text-dim)',
                background: isActive ? 'var(--bg-tertiary)' : 'transparent',
                border: isActive ? '2px solid var(--border-glow)' : '2px solid transparent',
                textDecoration: 'none',
                textTransform: 'uppercase',
                transition: 'all 0.2s ease',
                boxShadow: isActive ? '0 0 10px var(--shadow-color)' : 'none',
              })}
            >
              <span style={{
                marginRight: '8px',
                color: 'var(--accent)',
                fontFamily: 'var(--mono-font)',
                fontSize: '14px',
              }}>
                {item.icon}
              </span>
              {item.label}
            </NavLink>
          ))}
        </nav>

        <div style={{
          padding: '12px',
          borderTop: '2px solid var(--border-color)',
          fontFamily: 'var(--pixel-font)',
          fontSize: '7px',
          color: 'var(--text-dim)',
          textAlign: 'center',
        }}>
          <div>v2.0.0</div>
          <div style={{ marginTop: '4px', color: 'var(--accent)' }}>
            CLI-FIRST
          </div>
        </div>
      </aside>

      <main style={{
        flex: 1,
        overflow: 'auto',
        background: 'var(--bg-primary)',
      }}>
        <div style={{ padding: '24px' }}>
          <Outlet />
        </div>
      </main>
    </div>
  )
}
