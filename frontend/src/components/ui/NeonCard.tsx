import React from 'react'

interface NeonCardProps {
  children: React.ReactNode
  title?: string
  glow?: boolean
  color?: 'accent' | 'danger' | 'success' | 'warning'
  className?: string
}

export default function NeonCard({ children, title, glow = false, color = 'accent', className = '' }: NeonCardProps) {
  const glowStyles: Record<string, string> = {
    accent: 'shadow-[0_0_20px_rgba(168,85,247,0.3)] border-[var(--accent)]',
    danger: 'shadow-[0_0_20px_rgba(239,68,68,0.3)] border-[var(--danger)]',
    success: 'shadow-[0_0_20px_rgba(34,197,94,0.3)] border-[var(--success)]',
    warning: 'shadow-[0_0_20px_rgba(245,158,11,0.3)] border-[var(--warning)]',
  }

  return (
    <div className={`card p-4 ${glow ? glowStyles[color] : ''} ${className}`}>
      {title && <div className="sec-title mb-4">{title}</div>}
      {children}
    </div>
  )
}
