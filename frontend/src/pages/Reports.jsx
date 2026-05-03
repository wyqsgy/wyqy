import React, { useState, useEffect } from 'react'
import { getTasks } from '../api'

export default function Reports() {
  const [tasks, setTasks] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => { loadTasks() }, [])

  const loadTasks = async () => {
    try {
      const res = await getTasks({ limit: 100 })
      setTasks((res.data.data?.items || []).filter((t) => t.status === 'completed'))
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="terminal" style={{ height: '300px' }}>
        <div className="line prompt">$ 正在加载报告...</div>
        <div className="line cursor">_</div>
      </div>
    )
  }

  return (
    <div>
      <div className="sec-title" style={{ marginBottom: '24px' }}>扫描报告</div>

      {tasks.length === 0 ? (
        <div className="terminal" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <div style={{ color: 'var(--text-dim)', fontSize: '14px' }}>
            暂无已完成任务的报告
          </div>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: '12px' }}>
          {tasks.map((t) => (
            <div key={t.task_id} className="card" style={{ padding: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                <div>
                  <div style={{ fontWeight: 600, fontSize: '14px', color: 'var(--text-bright)', marginBottom: '4px' }}>
                    {t.target?.substring(0, 30) || '未知目标'}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-dim)' }}>
                    任务: {t.task_id}
                  </div>
                </div>
                <span className="badge" style={{ background: 'var(--success-subtle)', color: 'var(--success)' }}>
                  已完成
                </span>
              </div>

              <div style={{ display: 'flex', gap: '16px', marginBottom: '12px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                <span>漏洞: <strong style={{ color: t.vuln_count > 0 ? 'var(--danger)' : 'var(--text-dim)' }}>{t.vuln_count || 0}</strong></span>
                <span>模块: {t.modules?.length || 0}</span>
              </div>

              <div style={{ display: 'flex', gap: '8px' }}>
                <a
                  href={`/api/v1/reports/${t.task_id}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="btn btn-accent"
                  style={{ flex: 1, textAlign: 'center', textDecoration: 'none', fontSize: '12px' }}
                >
                  查看报告
                </a>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
