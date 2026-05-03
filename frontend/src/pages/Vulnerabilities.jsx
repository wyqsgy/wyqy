import React, { useState, useEffect } from 'react'
import { getVulnerabilities } from '../api'

const RISK_COLORS = {
  critical: 'var(--danger)',
  high: '#ea580c',
  medium: 'var(--warning)',
  low: 'var(--info)',
  info: 'var(--text-dim)',
}

const RISK_LABELS = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')

  useEffect(() => { loadVulns() }, [])

  const loadVulns = async () => {
    try {
      const res = await getVulnerabilities({ limit: 200 })
      setVulns(res.data.data?.items || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const filtered = filter === 'all' ? vulns : vulns.filter((v) => v.risk_level === filter)

  const riskCounts = vulns.reduce((acc, v) => {
    acc[v.risk_level] = (acc[v.risk_level] || 0) + 1
    return acc
  }, {})

  const filterTabs = [
    { id: 'all', label: `全部 (${vulns.length})` },
    { id: 'critical', label: `严重 (${riskCounts.critical || 0})` },
    { id: 'high', label: `高危 (${riskCounts.high || 0})` },
    { id: 'medium', label: `中危 (${riskCounts.medium || 0})` },
    { id: 'low', label: `低危 (${riskCounts.low || 0})` },
  ]

  if (loading) {
    return (
      <div className="terminal" style={{ height: '300px' }}>
        <div className="line prompt">$ 正在加载漏洞列表...</div>
        <div className="line cursor">_</div>
      </div>
    )
  }

  return (
    <div>
      <div className="sec-title" style={{ marginBottom: '16px' }}>漏洞列表</div>

      <div className="pixel-tabs" style={{ marginBottom: '16px' }}>
        {filterTabs.map((tab) => (
          <button
            key={tab.id}
            className={`pixel-tab ${filter === tab.id ? 'active' : ''}`}
            onClick={() => setFilter(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <div className="terminal" style={{ textAlign: 'center', padding: '60px 20px' }}>
          <div style={{ color: 'var(--text-dim)', fontSize: '14px' }}>
            {vulns.length === 0 ? '暂无漏洞' : '当前筛选条件下无漏洞'}
          </div>
        </div>
      ) : (
        <div className="card" style={{ overflow: 'hidden' }}>
          <table className="pixel-table">
            <thead>
              <tr>
                <th>风险等级</th>
                <th>检测模块</th>
                <th>漏洞标题</th>
                <th>目标</th>
                <th>描述</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((v, i) => (
                <tr key={v.id || i}>
                  <td data-label="风险等级">
                    <span className="badge" style={{
                      background: `${RISK_COLORS[v.risk_level] || 'var(--text-dim)'}20`,
                      color: RISK_COLORS[v.risk_level] || 'var(--text-dim)',
                    }}>
                      {RISK_LABELS[v.risk_level] || '信息'}
                    </span>
                  </td>
                  <td data-label="检测模块" style={{ fontSize: '12px', color: 'var(--accent)' }}>{v.module || '-'}</td>
                  <td data-label="漏洞标题" style={{ fontWeight: 600, maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {v.title || v.type || '-'}
                  </td>
                  <td data-label="目标" style={{ maxWidth: '200px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-secondary)', fontSize: '12px' }}>
                    {v.target || '-'}
                  </td>
                  <td data-label="描述" style={{ maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--text-secondary)', fontSize: '12px' }}>
                    {v.description || v.detail || '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
