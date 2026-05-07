import React from 'react'

interface StatCardProps {
  label: string
  value: string | number
  icon?: React.ReactNode
  trend?: { value: number; direction: 'up' | 'down' }
  color?: 'accent' | 'danger' | 'success' | 'warning'
}

export default function StatCard({ label, value, icon, trend, color = 'accent' }: StatCardProps) {
  const colorStyles = {
    accent: 'text-[var(--accent)]',
    danger: 'text-[var(--danger)]',
    success: 'text-[var(--success)]',
    warning: 'text-[var(--warning)]',
  }

  return (
    <div className="card p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="label-text">{label}</span>
        {icon && <span className={colorStyles[color]}>{icon}</span>}
      </div>
      <div className="flex items-end gap-2">
        <span className={`big-number ${colorStyles[color]}`}>{value}</span>
        {trend && (
          <span className={`text-sm ${trend.direction === 'up' ? 'text-[var(--success)]' : 'text-[var(--danger)]'}`}>
            {trend.direction === 'up' ? '↑' : '↓'} {Math.abs(trend.value)}%
          </span>
        )}
      </div>
    </div>
  )
}
