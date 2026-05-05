import React, { useState, useEffect, useRef } from 'react'

function AnimatedPresence({ children, show, animation = 'fade', duration = 300 }) {
  const [shouldRender, setShouldRender] = useState(show)
  const [animState, setAnimState] = useState(show ? 'enter' : 'exit')
  const timerRef = useRef(null)

  useEffect(() => {
    if (show) {
      setShouldRender(true)
      requestAnimationFrame(() => {
        requestAnimationFrame(() => {
          setAnimState('enter')
        })
      })
    } else {
      setAnimState('exit')
      timerRef.current = setTimeout(() => {
        setShouldRender(false)
      }, duration)
    }
    return () => {
      if (timerRef.current) clearTimeout(timerRef.current)
    }
  }, [show, duration])

  if (!shouldRender) return null

  const animClass = `anim-${animation}-${animState}`

  return (
    <div className={animClass} style={{ '--anim-duration': `${duration}ms` }}>
      {children}
    </div>
  )
}

function FadeIn({ children, delay = 0, duration = 400, className = '', style = {} }) {
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    const timer = setTimeout(() => setVisible(true), delay)
    return () => clearTimeout(timer)
  }, [delay])

  return (
    <div
      className={`anim-fade ${visible ? 'anim-fade-enter' : 'anim-fade-exit'} ${className}`}
      style={{ '--anim-duration': `${duration}ms`, '--anim-delay': `${delay}ms`, ...style }}
    >
      {children}
    </div>
  )
}

function SlideIn({ children, direction = 'up', delay = 0, duration = 400, className = '', style = {} }) {
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    const timer = setTimeout(() => setVisible(true), delay)
    return () => clearTimeout(timer)
  }, [delay])

  const dirClass = `anim-slide-${direction}`

  return (
    <div
      className={`${dirClass} ${visible ? 'anim-slide-enter' : 'anim-slide-exit'} ${className}`}
      style={{ '--anim-duration': `${duration}ms`, '--anim-delay': `${delay}ms`, ...style }}
    >
      {children}
    </div>
  )
}

function ScaleIn({ children, delay = 0, duration = 400, className = '', style = {} }) {
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    const timer = setTimeout(() => setVisible(true), delay)
    return () => clearTimeout(timer)
  }, [delay])

  return (
    <div
      className={`anim-scale ${visible ? 'anim-scale-enter' : 'anim-scale-exit'} ${className}`}
      style={{ '--anim-duration': `${duration}ms`, '--anim-delay': `${delay}ms`, ...style }}
    >
      {children}
    </div>
  )
}

function StaggerList({ children, baseDelay = 50, duration = 400, className = '', style = {} }) {
  return (
    <div className={className} style={style}>
      {React.Children.map(children, (child, index) => (
        <FadeIn key={index} delay={index * baseDelay} duration={duration}>
          {child}
        </FadeIn>
      ))}
    </div>
  )
}

function PulseDot({ color = 'var(--success)', size = 8 }) {
  return (
    <span
      className="pulse-dot"
      style={{
        '--pulse-color': color,
        '--pulse-size': `${size}px`,
      }}
    />
  )
}

function SkeletonLine({ width = '100%', height = '16px', style = {} }) {
  return (
    <div
      className="skeleton-line"
      style={{ width, height, ...style }}
    />
  )
}

function SkeletonCard({ lines = 3, style = {} }) {
  return (
    <div className="skeleton-card" style={style}>
      <SkeletonLine width="60%" height="18px" style={{ marginBottom: '12px' }} />
      {Array.from({ length: lines }).map((_, i) => (
        <SkeletonLine
          key={i}
          width={`${70 + Math.random() * 30}%`}
          height="14px"
          style={{ marginBottom: '8px' }}
        />
      ))}
    </div>
  )
}

export {
  AnimatedPresence,
  FadeIn,
  SlideIn,
  ScaleIn,
  StaggerList,
  PulseDot,
  SkeletonLine,
  SkeletonCard,
}
