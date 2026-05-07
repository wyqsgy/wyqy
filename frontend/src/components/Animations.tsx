import React, { useEffect, useState } from 'react'

interface AnimationsProps {
  type?: 'fade' | 'slide' | 'scale'
  duration?: number
  children: React.ReactNode
  className?: string
  onAnimationEnd?: () => void
}

export default function Animations({
  type = 'fade',
  duration = 300,
  children,
  className = '',
  onAnimationEnd,
}: AnimationsProps) {
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    const timer = setTimeout(() => setVisible(true), 50)
    return () => clearTimeout(timer)
  }, [])

  const animations = {
    fade: visible ? 'opacity-100' : 'opacity-0',
    slide: visible ? 'translate-y-0 opacity-100' : 'translate-y-4 opacity-0',
    scale: visible ? 'scale-100 opacity-100' : 'scale-95 opacity-0',
  }

  const transitionStyle = {
    transitionDuration: `${duration}ms`,
    transitionTimingFunction: 'ease-out',
  }

  return (
    <div
      className={`${animations[type]} ${className}`}
      style={transitionStyle}
      onTransitionEnd={onAnimationEnd}
    >
      {children}
    </div>
  )
}

export function useAnimation(type: 'enter' | 'exit' = 'enter') {
  const [phase, setPhase] = useState<'entering' | 'entered' | 'exiting' | 'exited'>(
    type === 'enter' ? 'exited' : 'entered'
  )

  const enter = () => setPhase('entering')
  const entered = () => setPhase('entered')
  const exit = () => setPhase('exiting')
  const exited = () => setPhase('exited')

  return { phase, enter, entered, exit, exited }
}
