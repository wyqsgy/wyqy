import React from 'react'
import type { RiskLevel } from '../../types'

interface RiskBadgeProps {
  level: RiskLevel
  size?: 'sm' | 'md'
  showLabel?: boolean
}

export default function RiskBadge({ level, size = 'md', showLabel = true }: RiskBadgeProps) {
  const styles: Record<RiskLevel, { class: string; label: string }> = {
    critical: { class: 'badge-critical', label: 'CRITICAL' },
    high: { class: 'badge-high', label: 'HIGH' },
    medium: { class: 'badge-medium', label: 'MEDIUM' },
    low: { class: 'badge-low', label: 'LOW' },
    info: { class: 'badge-info', label: 'INFO' },
  }

  const sizeStyles = {
    sm: 'text-[10px] px-1.5 py-0.5',
    md: 'text-[11px] px-2.5 py-1',
  }

  const { class: badgeClass, label } = styles[level]

  return (
    <span className={`badge ${badgeClass} ${sizeStyles[size]}`}>
      {showLabel ? label : level.toUpperCase()}
    </span>
  )
}
