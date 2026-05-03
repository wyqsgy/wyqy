import React, { useState, useEffect } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import ThemeSwitcher from './ThemeSwitcher'

const navItems = [
  { to: '/', icon: '~', label: '仪表盘' },
  { to: '/tasks', icon: '>', label: '扫描任务' },
  { to: '/tasks/new', icon: '+', label: '新建扫描' },
  { to: '/vulnerabilities', icon: '!', label: '漏洞列表' },
  { to: '/reports', icon: '#', label: '扫描报告' },
  { to: '/recon', icon: '@', label: '信息收集' },
  { to: '/attack', icon: '*', label: '攻击引擎' },
  { to: '/pocs', icon: '$', label: 'POC管理' },
  { to: '/verify', icon: '?', label: 'AI验证' },
  { to: '/settings', icon: '%', label: '系统设置' },
]

const THEME_KEY = 'wyqyan-theme'

export default function Layout() {
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem(THEME_KEY) || 'matrix'
  })
  const [sidebarOpen, setSidebarOpen] = useState(false)

  useEffect(() => {
    localStorage.setItem(THEME_KEY, theme)
    document.body.className = `theme-${theme}`
  }, [theme])

  const closeSidebar = () => setSidebarOpen(false)

  const sidebarContent = (
    <>
      <div style={{
        padding: '20px 16px',
        borderBottom: '1px solid var(--border-color)',
      }}>
        <div style={{
          fontSize: '18px',
          fontWeight: 700,
          color: 'var(--text-bright)',
          fontFamily: 'var(--font-title)',
          letterSpacing: '0.5px',
        }}>
          WyqYan
        </div>
        <div style={{
          fontSize: '11px',
          color: 'var(--text-dim)',
          marginTop: '4px',
          letterSpacing: '0.5px',
        }}>
          WyqYan 漏洞扫描平台
        </div>
        <div style={{ marginTop: '10px' }}>
          <ThemeSwitcher current={theme} onChange={setTheme} />
        </div>
      </div>

      <nav style={{ flex: 1, padding: '8px', overflowY: 'auto' }}>
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.to === '/'}
            onClick={closeSidebar}
            style={({ isActive }) => ({
              display: 'flex',
              alignItems: 'center',
              padding: '10px 14px',
              marginBottom: '2px',
              fontSize: '13px',
              fontWeight: isActive ? 600 : 400,
              color: isActive ? 'var(--text-bright)' : 'var(--text-secondary)',
              background: isActive ? 'var(--sidebar-active)' : 'transparent',
              borderLeft: isActive ? '3px solid var(--accent)' : '3px solid transparent',
              textDecoration: 'none',
              borderRadius: '4px',
              transition: 'all 0.15s ease',
            })}
          >
            <span style={{
              marginRight: '10px',
              fontFamily: 'var(--font-title)',
              fontSize: '14px',
              width: '16px',
              textAlign: 'center',
            }}>
              {item.icon}
            </span>
            {item.label}
          </NavLink>
        ))}
      </nav>

      <div style={{
        padding: '12px 16px',
        borderTop: '1px solid var(--border-color)',
        fontSize: '11px',
        color: 'var(--text-dim)',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}>
        <span>v2.0.0</span>
        <span style={{ color: 'var(--accent)', fontSize: '10px', fontWeight: 600 }}>CLI-FIRST</span>
      </div>
    </>
  )

  return (
    <div className={`flex h-screen theme-${theme}`} style={{ background: 'var(--bg-primary)' }}>
      <aside className="sidebar-desktop" style={{
        width: '240px',
        background: 'var(--sidebar-bg)',
        borderRight: '1px solid var(--border-color)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
      }}>
        {sidebarContent}
      </aside>

      {sidebarOpen && (
        <div className="sidebar-overlay" onClick={closeSidebar} />
      )}

      <aside className={`sidebar-mobile ${sidebarOpen ? 'sidebar-mobile-open' : ''}`} style={{
        position: 'fixed',
        top: 0,
        left: 0,
        bottom: 0,
        width: '260px',
        background: 'var(--sidebar-bg)',
        borderRight: '1px solid var(--border-color)',
        display: 'flex',
        flexDirection: 'column',
        zIndex: 1000,
        transform: sidebarOpen ? 'translateX(0)' : 'translateX(-100%)',
        transition: 'transform 0.25s ease',
        boxShadow: sidebarOpen ? '4px 0 24px rgba(0,0,0,0.5)' : 'none',
      }}>
        {sidebarContent}
      </aside>

      <main style={{
        flex: 1,
        overflow: 'auto',
        background: 'var(--bg-primary)',
        minWidth: 0,
      }}>
        <div className="mobile-header" style={{
          display: 'none',
          padding: '12px 16px',
          borderBottom: '1px solid var(--border-color)',
          background: 'var(--sidebar-bg)',
          alignItems: 'center',
          gap: '12px',
          position: 'sticky',
          top: 0,
          zIndex: 100,
        }}>
          <button
            className="hamburger-btn"
            onClick={() => setSidebarOpen(true)}
            aria-label="打开菜单"
          >
            <span />
            <span />
            <span />
          </button>
          <span style={{
            fontWeight: 700,
            color: 'var(--text-bright)',
            fontFamily: 'var(--font-title)',
            fontSize: '16px',
          }}>
            WyqYan
          </span>
        </div>

        <div style={{ padding: '24px' }}>
          <Outlet />
        </div>
      </main>
    </div>
  )
}
