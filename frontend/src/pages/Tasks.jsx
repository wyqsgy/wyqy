import React, { useState, useEffect } from 'react'
import { getTasks } from '../api'

const STATUS_STYLES = {
  pending: { bg: 'var(--bg-tertiary)', color: 'var(--text-dim)', label: 'PEND' },
  running: { bg: 'rgba(0,136,255,0.1)', color: 'var(--info)', label: 'RUN' },
  completed: { bg: 'rgba(0,255,65,0.1)', color: 'var(--success)', label: 'DONE' },
  failed: { bg: 'rgba(255,51,51,0.1)', color: 'var(--danger)', label: 'FAIL' },
  stopped: { bg: 'rgba(255,170,0,0.1)', color: 'var(--warning)', label: 'STOP' },
}

export default function Tasks() {
  const [tasks, setTasks] = useState([])
  const [loading, setLoading] = useState(true)
  const [page, setPage] = useState(1)
  const [total, setTotal] = useState(0)

  useEffect(() => { loadTasks() }, [page])

  const loadTasks = async () => {
    setLoading(true)
    try {
      const res = await getTasks({ page, limit: 20 })
      setTasks(res.data.data?.items || [])
      setTotal(res.data.data?.total || 0)
    } catch (e) {
      console.error('Tasks load error:', e)
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
        // TASKS
      </div>

      <div className="pixel-card" style={{ padding: '0', overflow: 'hidden' }}>
        <div className="pixel-table">
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>TARGET</th>
                <th>TYPE</th>
                <th>STATUS</th>
                <th>VULNS</th>
                <th>CREATED</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '40px' }}>
                    <span className="mono-text" style={{ color: 'var(--text-dim)' }}>LOADING...</span>
                  </td>
                </tr>
              ) : tasks.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ textAlign: 'center', padding: '40px' }}>
                    <span className="mono-text" style={{ color: 'var(--text-dim)' }}>NO TASKS</span>
                  </td>
                </tr>
              ) : (
                tasks.map((t) => {
                  const st = STATUS_STYLES[t.status] || STATUS_STYLES.pending
                  return (
                    <tr key={t.task_id}>
                      <td className="mono-text" style={{ color: 'var(--accent)', fontSize: '12px' }}>
                        {t.task_id?.substring(0, 8)}
                      </td>
                      <td className="mono-text" style={{ color: 'var(--text-primary)', fontSize: '13px' }}>
                        {t.target?.substring(0, 50) || 'N/A'}
                      </td>
                      <td>
                        <span className="pixel-badge" style={{ borderColor: 'var(--info)', color: 'var(--info)' }}>
                          {t.scan_type || 'FULL'}
                        </span>
                      </td>
                      <td>
                        <span className="pixel-badge" style={{
                          borderColor: st.color,
                          color: st.color,
                          background: st.bg,
                        }}>
                          {st.label}
                        </span>
                      </td>
                      <td className="mono-text" style={{ color: 'var(--danger)', fontSize: '13px' }}>
                        {t.vuln_count || 0}
                      </td>
                      <td className="mono-text" style={{ color: 'var(--text-dim)', fontSize: '11px' }}>
                        {t.created_at ? new Date(t.created_at).toLocaleDateString() : 'N/A'}
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
            <button
              className="pixel-btn"
              disabled={page <= 1}
              onClick={() => setPage(page - 1)}
            >
              &lt; PREV
            </button>
            <span className="pixel-text-sm" style={{ color: 'var(--text-dim)', padding: '8px 12px' }}>
              PAGE {page} / {Math.ceil(total / 20)}
            </span>
            <button
              className="pixel-btn"
              disabled={page >= Math.ceil(total / 20)}
              onClick={() => setPage(page + 1)}
            >
              NEXT &gt;
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
