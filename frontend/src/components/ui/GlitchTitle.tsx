import React, { useEffect, useState } from 'react'

interface GlitchTitleProps {
  text: string
  className?: string
  glitchInterval?: number
}

export default function GlitchTitle({
  text,
  className = '',
  glitchInterval = 3000,
}: GlitchTitleProps) {
  const [isGlitching, setIsGlitching] = useState(false)

  useEffect(() => {
    const interval = setInterval(() => {
      setIsGlitching(true)
      setTimeout(() => setIsGlitching(false), 150)
    }, glitchInterval)

    return () => clearInterval(interval)
  }, [glitchInterval])

  const glitchChars = '!<>-_\\/[]{}—=+*^?#@$%&0123456789'

  const getGlitchText = () => {
    return text
      .split('')
      .map((char, i) => {
        if (char === ' ') return char
        if (Math.random() > 0.7) {
          return glitchChars[Math.floor(Math.random() * glitchChars.length)]
        }
        return char
      })
      .join('')
  }

  return (
    <h1
      className={`font-bold ${className} ${isGlitching ? 'animate-pulse' : ''}`}
      data-text={text}
      style={{
        position: 'relative',
        textShadow: isGlitching
          ? '2px 0 #ef4444, -2px 0 #22c55e'
          : 'none',
      }}
    >
      {isGlitching ? getGlitchText() : text}
    </h1>
  )
}
