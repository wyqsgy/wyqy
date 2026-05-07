import React, { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import ThemeSwitcher from './ThemeSwitcher'

const menuItems = [
  { path: '/', label: 'Dashboard', icon: '◈' },
  { path: '/tasks', label: 'Tasks', icon: '◇' },
  { path: '/vulnerabilities', label: 'Vulns', icon: '◆' },
  { path: '/reports', label: 'Reports', icon: '▣' },
  { path: '/recon', label: 'Recon', icon: '◎' },
  { path: '/attack', label: 'Attack', icon: '◉' },
  { path: '/pocs', label: 'POCs', icon: '○' },
  { path: '/verify', label: 'Verify', icon: '◐' },
  { path: '/templates', label: 'Templates', icon: '□' },
  { path: '/settings', label: 'Settings', icon: '▢' },
]

export default function Layout() {
  const [sidebarOpen, setSidebarOpen] = useState(false)

  return (
    <div className="flex h-screen">
      <aside
        className={`sidebar-desktop w-56 bg-[var(--sidebar-bg)] border-r border-[var(--border-color)] flex flex-col ${
          sidebarOpen ? 'block' : 'hidden md:flex'
        }`}
      >
        <div className="p-4 border-b border-[var(--border-color)]">
          <h1 className="sec-title text-[var(--accent)]">SUPERPOWERS</h1>
          <p className="text-xs text-[var(--text-dim)] mt-1">Security Scanner v2.0</p>
        </div>
        <nav className="flex-1 p-2 overflow-y-auto">
          {menuItems.map((item) => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                  isActive
                    ? 'bg-[var(--sidebar-active)] text-[var(--accent)]'
                    : 'text-[var(--text-secondary)] hover:bg-[var(--bg-hover)] hover:text-[var(--text-primary)]'
                }`
              }
            >
              <span className="text-base">{item.icon}</span>
              <span>{item.label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="p-4 border-t border-[var(--border-color)]">
          <ThemeSwitcher />
        </div>
      </aside>

      <div className="flex-1 flex flex-col overflow-hidden">
        <header className="mobile-header hidden h-14 bg-[var(--bg-secondary)] border-b border-[var(--border-color)] items-center px-4">
          <button
            onClick={() => setSidebarOpen(!sidebarOpen)}
            className="hamburger-btn mr-4"
          >
            <span />
            <span />
            <span />
          </button>
          <span className="sec-title text-[var(--accent)]">SUPERPOWERS</span>
        </header>

        <main className="flex-1 overflow-y-auto p-6 bg-[var(--bg-primary)]">
          <Outlet />
        </main>
      </div>

      {sidebarOpen && (
        <div className="sidebar-overlay md:hidden" onClick={() => setSidebarOpen(false)} />
      )}
    </div>
  )
}
