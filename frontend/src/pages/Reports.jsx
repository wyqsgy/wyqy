import React, { useState, useEffect } from 'react'
import { listReports } from '../api'

export default function Reports() {
  const [reports, setReports] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => { loadReports() }, [])

  const loadReports = async () => {
    setLoading(true)
    try {
      const res = await listReports()
      setReports(res.data.data?.items || res.data.data || [])
    } catch (e) {
      console.error('Reports load error:', e)
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
        // REPORTS
      </div>

      <div className="pixel-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div className="pixel-table">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>TITLE</th>
                <th>TARGET</th>
                <th>VULNS</th>
                <th>FORMAT</th>
                <th>CREATED</th>
                <th>ACTION</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '40px' }}>
                    <span className="mono-text" style={{ color: 'var(--text-dim)' }}>LOADING...</span>
                  </td>
                </tr>
              ) : reports.length === 0 ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: 'center', padding: '40px' }}>
                    <span className="mono-text" style={{ color: 'var(--text-dim)' }}>NO REPORTS</span>
                  </td>
                </tr>
              ) : (
                reports.map((r) => (
                  <tr key={r.id || r.report_id}>
                    <td className="mono-text" style={{ color: 'var(--accent)', fontSize: '12px' }}>
                      {r.id?.substring(0, 8) || r.report_id?.substring(0, 8) || 'N/A'}
                    </td>
                    <td className="pixel-text-sm" style={{ color: 'var(--text-primary)' }}>
                      {r.title || 'REPORT'}
                    </td>
                    <td className="mono-text" style={{ color: 'var(--text-secondary)', fontSize: '12px' }}>
                      {r.target?.substring(0, 40) || 'N/A'}
                    </td>
                    <td className="mono-text" style={{ color: 'var(--danger)', fontSize: '13px' }}>
                      {r.vuln_count || 0}
                    </td>
                    <td>
                      <span className="pixel-badge" style={{ borderColor: 'var(--info)', color: 'var(--info)' }}>
                        {r.format || 'JSON'}
                      </span>
                    </td>
                    <td className="mono-text" style={{ color: 'var(--text-dim)', fontSize: '10px' }}>
                      {r.created_at ? new Date(r.created_at).toLocaleDateString() : 'N/A'}
                    </td>
                    <td>
                      <button className="pixel-btn" style={{ fontSize: '7px', padding: '4px 8px' }}>
                        [DL]
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
