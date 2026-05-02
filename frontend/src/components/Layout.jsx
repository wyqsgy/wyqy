import React from 'react'
import { NavLink, Outlet } from 'react-router-dom'

const navItems = [
  { to: '/', icon: '📊', label: '仪表板' },
  { to: '/tasks', icon: '🔍', label: '扫描任务' },
  { to: '/tasks/new', icon: '➕', label: '新建扫描' },
  { to: '/vulnerabilities', icon: '🐛', label: '漏洞列表' },
  { to: '/reports', icon: '📄', label: '报告中心' },
  { to: '/recon', icon: '🔭', label: '信息收集' },
  { to: '/attack', icon: '⚔️', label: '攻击引擎' },
]

export default function Layout() {
  return (
    <div className="flex h-screen bg-gray-100">
      <aside className="w-64 bg-dark-900 text-white flex flex-col">
        <div className="p-6 border-b border-dark-700">
          <h1 className="text-xl font-bold text-primary-300">🛡️ WyqYan</h1>
          <p className="text-xs text-dark-400 mt-1">AI漏洞验证平台</p>
        </div>
        <nav className="flex-1 p-4 space-y-1">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              className={({ isActive }) =>
                `flex items-center px-4 py-3 rounded-lg text-sm transition-all ${
                  isActive
                    ? 'bg-primary-700 text-white font-medium'
                    : 'text-dark-300 hover:bg-dark-800 hover:text-white'
                }`
              }
            >
              <span className="mr-3">{item.icon}</span>
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="p-4 border-t border-dark-700 text-xs text-dark-500">
          WyqYan v1.0.0 | AI-Powered
        </div>
      </aside>

      <main className="flex-1 overflow-auto">
        <div className="p-8">
          <Outlet />
        </div>
      </main>
    </div>
  )
}
