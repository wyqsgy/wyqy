import React from 'react'

interface ScanProgressProps {
  progress: number
  label?: string
  showPercentage?: boolean
  size?: 'sm' | 'md' | 'lg'
  animated?: boolean
}

export default function ScanProgress({
  progress,
  label,
  showPercentage = true,
  size = 'md',
  animated = true,
}: ScanProgressProps) {
  const sizeStyles = {
    sm: 'h-1',
    md: 'h-2',
    lg: 'h-3',
  }

  const clampedProgress = Math.min(100, Math.max(0, progress))

  return (
    <div className="w-full">
      {(label || showPercentage) && (
        <div className="flex justify-between mb-1 text-xs text-[var(--text-secondary)]">
          {label && <span>{label}</span>}
          {showPercentage && <span>{Math.round(clampedProgress)}%</span>}
        </div>
      )}
      <div className={`pixel-progress ${sizeStyles[size]}`}>
        <div
          className={`pixel-progress-bar ${animated ? 'transition-all duration-300' : ''}`}
          style={{ width: `${clampedProgress}%` }}
        />
      </div>
    </div>
  )
}
