import React, { useState, useRef, useEffect, useCallback, useMemo } from 'react'

const DEFAULT_ITEM_HEIGHT = 80
const DEFAULT_OVERSCAN = 5

export default function VirtualList({
  items = [],
  renderItem,
  itemHeight = DEFAULT_ITEM_HEIGHT,
  overscan = DEFAULT_OVERSCAN,
  className,
  style,
  getItemKey,
  onEndReached,
  endThreshold = 200,
}) {
  const containerRef = useRef(null)
  const [scrollTop, setScrollTop] = useState(0)
  const [containerHeight, setContainerHeight] = useState(0)
  const rafRef = useRef(null)

  const totalHeight = items.length * itemHeight

  const visibleRange = useMemo(() => {
    if (containerHeight === 0) return { start: 0, end: 0 }
    const start = Math.max(0, Math.floor(scrollTop / itemHeight) - overscan)
    const end = Math.min(
      items.length,
      Math.ceil((scrollTop + containerHeight) / itemHeight) + overscan
    )
    return { start, end }
  }, [scrollTop, containerHeight, itemHeight, items.length, overscan])

  const visibleItems = useMemo(() => {
    return items.slice(visibleRange.start, visibleRange.end)
  }, [items, visibleRange])

  useEffect(() => {
    const el = containerRef.current
    if (!el) return

    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        setContainerHeight(entry.contentRect.height)
      }
    })
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  const handleScroll = useCallback((e) => {
    if (rafRef.current) cancelAnimationFrame(rafRef.current)
    rafRef.current = requestAnimationFrame(() => {
      const st = e.target.scrollTop
      setScrollTop(st)

      if (onEndReached && e.target.scrollHeight - st - e.target.clientHeight < endThreshold) {
        onEndReached()
      }
    })
  }, [onEndReached, endThreshold])

  useEffect(() => {
    return () => {
      if (rafRef.current) cancelAnimationFrame(rafRef.current)
    }
  }, [])

  const containerStyle = {
    overflow: 'auto',
    position: 'relative',
    ...style,
  }

  const innerStyle = {
    height: `${totalHeight}px`,
    position: 'relative',
  }

  return (
    <div
      ref={containerRef}
      className={className}
      style={containerStyle}
      onScroll={handleScroll}
    >
      <div style={innerStyle}>
        {visibleItems.map((item, index) => {
          const actualIndex = visibleRange.start + index
          const key = getItemKey ? getItemKey(item, actualIndex) : actualIndex
          return (
            <div
              key={key}
              style={{
                position: 'absolute',
                top: `${actualIndex * itemHeight}px`,
                left: 0,
                right: 0,
                height: `${itemHeight}px`,
              }}
            >
              {renderItem(item, actualIndex)}
            </div>
          )
        })}
      </div>
    </div>
  )
}
