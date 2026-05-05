import { useState, useEffect, useRef, useCallback } from 'react'

export function useDebounce(value, delay = 300) {
  const [debounced, setDebounced] = useState(value)

  useEffect(() => {
    const timer = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(timer)
  }, [value, delay])

  return debounced
}

export function useThrottle(fn, delay = 300) {
  const lastRef = useRef(0)
  const timerRef = useRef(null)

  return useCallback((...args) => {
    const now = Date.now()
    if (now - lastRef.current >= delay) {
      lastRef.current = now
      fn(...args)
    } else {
      if (timerRef.current) clearTimeout(timerRef.current)
      timerRef.current = setTimeout(() => {
        lastRef.current = Date.now()
        fn(...args)
      }, delay - (now - lastRef.current))
    }
  }, [fn, delay])
}

export function useLocalStorage(key, initialValue) {
  const [value, setValue] = useState(() => {
    try {
      const stored = localStorage.getItem(key)
      return stored !== null ? JSON.parse(stored) : initialValue
    } catch {
      return initialValue
    }
  })

  useEffect(() => {
    try {
      localStorage.setItem(key, JSON.stringify(value))
    } catch {
      console.warn(`Failed to save ${key} to localStorage`)
    }
  }, [key, value])

  return [value, setValue]
}

export function usePrevious(value) {
  const ref = useRef()
  useEffect(() => {
    ref.current = value
  })
  return ref.current
}

export function useIsMounted() {
  const mounted = useRef(true)
  useEffect(() => {
    return () => { mounted.current = false }
  }, [])
  return useCallback(() => mounted.current, [])
}

export function useInterval(callback, delay) {
  const savedCallback = useRef(callback)

  useEffect(() => {
    savedCallback.current = callback
  }, [callback])

  useEffect(() => {
    if (delay === null) return
    const id = setInterval(() => savedCallback.current(), delay)
    return () => clearInterval(id)
  }, [delay])
}
