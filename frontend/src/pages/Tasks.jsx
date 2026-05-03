import React, { useState, useEffect } from 'react'
import { getTasks, deleteTask } from '../api'

const statusStyles = {
  pending: { bg: 'var(--bg-tertiary)', color: 'var(--text-dim)', label: '等待中' },
  running: { bg: 'var(--info-subtle)', color: 'var(--info)', label: '运行中' },
  completed: { bg: 'var(--success-subtle)', color: 'var(--success)', label: '已完成' },
  failed: { bg: 'var(--danger-subtle)', color: 'var(--danger)', label: '失败' },
  stopped: { bg: 'var(--warning-subtle)', color: 'var(--warning)', label: '已停止' },
}

export default function Tasks() {
  const [tasks, setTasks] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => { loadTasks() }, [])

  const loadTasks = async () => {
    try {
      const res = await getTasks({ limit: 100 })
      setTasks(res.data.data?.items || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const handleDelete = async (id) => {
    if (!confirm('确定删除该任务？')) return
    try {
      await deleteTask(id)
      setTasks((prev) => prev.filter((t) => t.task_id !== id))
    } catch (e) {
      console.error(e)
    }
  }

  if (loading) {
    return (
      <div className="terminal" style={{ height: '300px' }}>
        <div className="line prompt">$ 正在加载任务列表...</div>
        <div className="line cursor">_</div>
      </div>
    )
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', flexWrap: 'wrap', gap: '12px' }}>
        <div className="sec-title">扫描任务</div>
        <a href="/tasks/new" className="btn btn-accent">新建扫描</a>
      </div>

      {tasks.length === 0 ? (
        <div className="terminal" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <div style={{ color: 'var(--text-dim)', fontSize: '14px', marginBottom: '12px' }}>
            暂无扫描任务
          </div>
          <a href="/tasks/new" className="btn btn-accent">创建第一个任务</a>
        </div>
      ) : (
        <div className="card" style={{ overflow: 'hidden' }}>
          <table className="pixel-table">
            <thead>
              <tr>
                <th>目标</th>
                <th>类型</th>
                <th>模块</th>
                <th>状态</th>
                <th>漏洞</th>
                <th>创建时间</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {tasks.map((t) => {
                const st = statusStyles[t.status] || statusStyles.pending
                return (
                  <tr key={t.task_id}>
                    <td data-label="目标" style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {t.target}
                    </td>
                    <td data-label="类型">{t.scan_type || 'full'}</td>
                    <td data-label="模块">{t.modules?.length || 0}</td>
                    <td data-label="状态">
                      <span className="badge" style={{ background: st.bg, color: st.color }}>
                        {st.label}
                      </span>
                    </td>
                    <td data-label="漏洞" style={{ color: t.vuln_count > 0 ? 'var(--danger)' : 'var(--text-dim)' }}>
                      {t.vuln_count || 0}
                    </td>
                    <td data-label="创建时间" style={{ color: 'var(--text-dim)', fontSize: '12px' }}>
                      {t.created_at ? new Date(t.created_at).toLocaleString() : '-'}
                    </td>
                    <td data-label="操作">
                      <button className="btn btn-danger" style={{ fontSize: '11px', padding: '4px 10px' }} onClick={() => handleDelete(t.task_id)}>
                        删除
                      </button>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
