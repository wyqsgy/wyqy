const METRICS_KEY = 'wyqyan-perf-metrics'

const metrics = {
  lcp: 0,
  fid: 0,
  cls: 0,
  inp: 0,
  ttfb: 0,
  fcp: 0,
  collected: false,
}

function logMetric(name, value, rating) {
  if (process.env.NODE_ENV === 'development') {
    const emoji = rating === 'good' ? '✓' : rating === 'needs-improvement' ? '!' : '✕'
    console.log(`[Perf] ${emoji} ${name}: ${Math.round(value * 100) / 100}ms (${rating})`)
  }
}

function getRating(name, value) {
  const thresholds = {
    lcp: [2500, 4000],
    fid: [100, 300],
    cls: [0.1, 0.25],
    inp: [200, 500],
    ttfb: [800, 1800],
    fcp: [1800, 3000],
  }
  const [good, poor] = thresholds[name] || [0, 0]
  if (value <= good) return 'good'
  if (value <= poor) return 'needs-improvement'
  return 'poor'
}

export function initPerfMonitoring() {
  if (typeof window === 'undefined') return

  try {
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.entryType === 'largest-contentful-paint') {
          metrics.lcp = entry.startTime
          logMetric('LCP', entry.startTime, getRating('lcp', entry.startTime))
        }
        if (entry.entryType === 'first-input') {
          metrics.fid = entry.processingStart - entry.startTime
          logMetric('FID', metrics.fid, getRating('fid', metrics.fid))
        }
      }
    }).observe({ type: 'largest-contentful-paint', buffered: true })

    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (entry.entryType === 'first-input') {
          metrics.fid = entry.processingStart - entry.startTime
          logMetric('FID', metrics.fid, getRating('fid', metrics.fid))
        }
      }
    }).observe({ type: 'first-input', buffered: true })

    let clsValue = 0
    new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) {
        if (!entry.hadRecentInput) {
          clsValue += entry.value
          metrics.cls = clsValue
          logMetric('CLS', clsValue, getRating('cls', clsValue))
        }
      }
    }).observe({ type: 'layout-shift', buffered: true })

    const navEntry = performance.getEntriesByType('navigation')[0]
    if (navEntry) {
      metrics.ttfb = navEntry.responseStart - navEntry.requestStart
      logMetric('TTFB', metrics.ttfb, getRating('ttfb', metrics.ttfb))
    }

    const paintEntries = performance.getEntriesByType('paint')
    for (const entry of paintEntries) {
      if (entry.name === 'first-contentful-paint') {
        metrics.fcp = entry.startTime
        logMetric('FCP', entry.startTime, getRating('fcp', entry.startTime))
      }
    }

    metrics.collected = true
  } catch (e) {
    console.warn('[Perf] Monitoring init failed:', e)
  }
}

export function getPerfMetrics() {
  return { ...metrics }
}

export function measureRender(componentName, fn) {
  const start = performance.now()
  const result = fn()
  const duration = performance.now() - start
  if (duration > 16 && process.env.NODE_ENV === 'development') {
    console.warn(`[Perf] Slow render: ${componentName} took ${Math.round(duration)}ms`)
  }
  return result
}

export function createPerfMark(name) {
  if (typeof performance === 'undefined') return { end: () => {} }
  performance.mark(`${name}-start`)
  return {
    end: () => {
      performance.mark(`${name}-end`)
      try {
        performance.measure(name, `${name}-start`, `${name}-end`)
      } catch {}
    },
  }
}

export function reportWebVitals() {
  if (typeof window === 'undefined') return

  import('web-vitals').then(({ onCLS, onFID, onLCP, onFCP, onTTFB, onINP }) => {
    onCLS((v) => {
      metrics.cls = v.value
      logMetric('CLS', v.value, v.rating)
    })
    onFID((v) => {
      metrics.fid = v.value
      logMetric('FID', v.value, v.rating)
    })
    onLCP((v) => {
      metrics.lcp = v.value
      logMetric('LCP', v.value, v.rating)
    })
    onFCP((v) => {
      metrics.fcp = v.value
      logMetric('FCP', v.value, v.rating)
    })
    onTTFB((v) => {
      metrics.ttfb = v.value
      logMetric('TTFB', v.value, v.rating)
    })
    onINP((v) => {
      metrics.inp = v.value
      logMetric('INP', v.value, v.rating)
    })
  }).catch(() => {})
}
