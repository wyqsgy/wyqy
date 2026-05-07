import React, { useEffect, useRef } from 'react'

interface TerminalOutputProps {
  lines: string[]
  className?: string
  autoScroll?: boolean
}

export default function TerminalOutput({ lines, className = '', autoScroll = true }: TerminalOutputProps) {
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (autoScroll && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight
    }
  }, [lines, autoScroll])

  const getLineClass = (line: string) => {
    if (line.includes('[ERROR]') || line.includes('error') || line.includes('failed')) return 'error'
    if (line.includes('[WARN]') || line.includes('warning')) return 'warning'
    if (line.includes('[SUCCESS]') || line.includes('completed') || line.includes('success')) return 'success'
    if (line.includes('[INFO]') || line.includes('info')) return 'info'
    return 'output'
  }

  return (
    <div ref={containerRef} className={`terminal ${className}`}>
      {lines.map((line, index) => (
        <div key={index} className={`line ${getLineClass(line)}`}>
          <span className="prompt">&gt;</span> {line}
        </div>
      ))}
    </div>
  )
}
