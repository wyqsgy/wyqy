import React, { useState, useEffect } from 'react'
import { getVulnerabilities } from '../api'

const RISK_STYLES = {
  critical: { color: 'var(--danger)', glow: 'var(--danger-glow)', label: 'CRIT' },
  high: { color: '#ff6600', glow: '#ff660080', label: 'HIGH' },
  medium: { color: 'var(--warning)', glow: 'var(--warning-glow)', label: 'MED' },
  low: { color: 'var(--info)', glow: 'rgba(0,204,255,0.5)', label: 'LOW' },
  info: { color: 'var(--text-dim)', glow: 'transparent', label: 'INFO' },
}

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)
  const [filter, setFilter] = useState('all')

  useEffect(() => { loadVulns() }, [page, filter])

  const loadVulns = async () => {
    setLoading(true)
    try {
      const params = { page, limit: 20 }
      if (filter !== 'all') params.risk_level = filter
      const res = await getVulnerabilities(params)
      setVulns(res.data.data?.items || [])
      setTotal(res.data.data?.total || 0)
    } catch (e) {
      console.error('Vulns load error:', e)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <div className="pixel-text" style={{
        fontSize: '14px',
        color: 'var(--text-bright)',
        textShadow: '0 0 10px var(--accent-glow)',
        marginBottom: '24px',
      }}>
        // VULNERABILITIES
      </div>

      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap' }}>
        {['all', 'critical', 'high', 'medium', 'low', 'info'].map((level) => {
          const st = RISK_STYLES[level] || { color: 'var(--text-dim)', label: level.toUpperCase() }
          return (
            <button
              key={level}
              className="pixel-btn"
              onClick={() => { setFilter(level); setPage(1) }}
              style={{
                borderColor: filter === level ? st.color : 'var(--border-color)',
                color: filter === level ? st.color : 'var(--text-dim)',
                boxShadow: filter === level ? `0 0 8px ${st.glow || 'transparent'}` : 'none',
              }}
            >
              {st.label || level.toUpperCase()}
            </button>
          )
        })}
      </div>

      <div className="pixel-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div className="pixel-table">
          <table>
            <thead>
              <tr>
                <th>RISK</th>
                <th>TYPE</th>
                <th>TARGET</th>
                <th>DETAIL</th>
                <th>TIME</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: '40px' }}>
                    <span className="mono-text" style={{ color: 'var(--text-dim)' }}>LOADING...</span>
                  </td>
                </tr>
              ) : vulns.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: 'center', padding: '40px' }}>
                    <span className="mono-text" style={{ color: 'var(--text-dim)' }}>NO VULNERABILITIES</span>
                  </td>
                </tr>
              ) : (
                vulns.map((v) => {
                  const st = RISK_STYLES[v.risk_level] || RISK_STYLES.info
                  return (
                    <tr key={v.id || v.vuln_id}>
                      <td>
                        <span className="pixel-badge" style={{
                          borderColor: st.color,
                          color: st.color,
                          boxShadow: `0 0 6px ${st.glow}`,
                        }}>
                          {st.label}
                        </span>
                      </td>
                      <td className="pixel-text-sm" style={{ color: 'var(--text-primary)' }}>
                        {v.vuln_type || 'UNKNOWN'}
                      </td>
                      <td className="mono-text" style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>
                        {v.target?.substring(0, 40) || 'N/A'}
                      </td>
                      <td className="mono-text" style={{ color: 'var(--text-dim)', fontSize: '11px', maxWidth: '300px' }}>
                        {v.detail?.substring(0, 80) || v.description?.substring(0, 80) || 'N/A'}
                      </td>
                      <td className="mono-text" style={{ color: 'var(--text-dim)', fontSize: '10px' }}>
                        {v.found_at ? new Date(v.found_at).toLocaleString() : 'N/A'}
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>

        {total > 20 && (
          <div style={{
            padding: '12px',
            borderTop: '2px solid var(--border-color)',
            display: 'flex',
            justifyContent: 'center',
            gap: '8px',
          }}>
            <button className="pixel-btn" disabled={page <= 1} onClick={() => setPage(page - 1)}>
              &lt; PREV
            </button>
            <span className="pixel-text-sm" style={{ color: 'var(--text-dim)', padding: '8px 12px' }}>
              PAGE {page} / {Math.ceil(total / 20)}
            </span>
            <button className="pixel-btn" disabled={page >= Math.ceil(total / 20)} onClick={() => setPage(page + 1)}>
              NEXT &gt;
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
