import React from 'react'
import { useTasks } from '../hooks/useTasks'
import StatCard from '../components/ui/StatCard'
import ScanProgress from '../components/ui/ScanProgress'
import NeonCard from '../components/ui/NeonCard'
import { useTheme } from '../contexts/ThemeContext'

export default function Dashboard() {
  const { data, isLoading } = useTasks()
  const { theme } = useTheme()

  if (isLoading) {
    return <div className="text-center py-12">Loading...</div>
  }

  const tasks = data?.tasks || []
  const runningTasks = tasks.filter((t) => t.status === 'running').length
  const completedTasks = tasks.filter((t) => t.status === 'completed').length
  const totalVulns = tasks.reduce((acc, t) => acc + (t.vulnerability_count || 0), 0)

  return (
    <div className="space-y-6 page-enter">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="sec-title text-2xl">Dashboard</h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1">
            Welcome back. Current theme: {theme}
          </p>
        </div>
        <div className="flex gap-2">
          <span className="pulse-dot" style={{ '--pulse-color': 'var(--success)' } as React.CSSProperties} />
          <span className="text-sm text-[var(--text-secondary)]">System Online</span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Tasks" value={tasks.length} color="accent" />
        <StatCard label="Running" value={runningTasks} color="warning" />
        <StatCard label="Completed" value={completedTasks} color="success" />
        <StatCard label="Vulnerabilities" value={totalVulns} color="danger" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <NeonCard title="Recent Tasks" glow>
          {tasks.slice(0, 5).map((task) => (
            <div key={task.id} className="flex items-center justify-between py-2 border-b border-[var(--border-color)]">
              <div>
                <p className="text-sm font-medium">{task.name}</p>
                <p className="text-xs text-[var(--text-dim)]">{task.target}</p>
              </div>
              <ScanProgress progress={task.progress} size="sm" />
            </div>
          ))}
          {tasks.length === 0 && <p className="text-sm text-[var(--text-dim)]">No tasks yet</p>}
        </NeonCard>

        <NeonCard title="Quick Actions" color="success">
          <div className="grid grid-cols-2 gap-3">
            <a href="/tasks/new" className="btn text-center">+ New Task</a>
            <a href="/recon" className="btn text-center">Recon</a>
            <a href="/vulnerabilities" className="btn text-center">Vulns</a>
            <a href="/reports" className="btn text-center">Reports</a>
          </div>
        </NeonCard>
      </div>
    </div>
  )
}
