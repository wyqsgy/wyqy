import React from 'react'

interface NeonButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'accent' | 'danger' | 'ghost'
  size?: 'sm' | 'md' | 'lg'
  glow?: boolean
}

export default function NeonButton({
  children,
  variant = 'primary',
  size = 'md',
  glow = false,
  className = '',
  ...props
}: NeonButtonProps) {
  const sizeStyles = {
    sm: 'px-3 py-1.5 text-xs',
    md: 'px-4 py-2 text-sm',
    lg: 'px-6 py-3 text-base',
  }

  const variantStyles = {
    primary: 'btn',
    accent: 'btn btn-accent',
    danger: 'btn btn-danger',
    ghost: 'bg-transparent border-transparent hover:bg-[var(--bg-hover)]',
  }

  const glowStyle = glow ? 'shadow-[0_0_15px_rgba(168,85,247,0.4)] hover:shadow-[0_0_25px_rgba(168,85,247,0.5)]' : ''

  return (
    <button
      className={`${variantStyles[variant]} ${sizeStyles[size]} ${glowStyle} ${className}`}
      {...props}
    >
      {children}
    </button>
  )
}
