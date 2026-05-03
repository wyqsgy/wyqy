import React, { useState, useEffect } from 'react'
import api from '../api'

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

const MATCHER_TYPES = [
  { key: 'word', name: '关键词匹配' },
  { key: 'regex', name: '正则匹配' },
  { key: 'status', name: '状态码匹配' },
  { key: 'size', name: '响应大小匹配' },
]

export default function POCManagement() {
  const [tab, setTab] = useState('all')
  const [pocs, setPocs] = useState([])
  const [total, setTotal] = useState(0)
  const [stats, setStats] = useState(null)
  const [loading, setLoading] = useState(false)
  const [keyword, setKeyword] = useState('')
  const [riskFilter, setRiskFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('all')
  const [page, setPage] = useState(0)
  const [showForm, setShowForm] = useState(false)
  const [editingPoc, setEditingPoc] = useState(null)
  const [pocForm, setPocForm] = useState(getEmptyForm())

  const pageSize = 20

  useEffect(() => { loadPocs(); loadStats() }, [tab, sourceFilter])

  function getEmptyForm() {
    return {
      name: '', description: '', risk_level: 'medium', cve_ids: '',
      cnvd_ids: '', cvss_score: '0.0', tags: '', affected_versions: '',
      poc_type: 'http', requests: [{ method: 'GET', path: '/', headers: '{}', body: '' }],
      matchers: [{ type: 'word', value: '', part: 'body', negative: false }],
      references: '', fix_suggestion: '', disclosure_date: '', is_enabled: true,
    }
  }

  const loadPocs = async () => {
    setLoading(true)
    try {
      const params = { skip: page * pageSize, limit: pageSize, source: sourceFilter }
      if (keyword) params.keyword = keyword
      if (riskFilter) params.risk_level = riskFilter
      const res = await api.get('/pocs', { params })
      setPocs(res.data.data?.items || [])
      setTotal(res.data.data?.total || 0)
    } catch (e) { console.error(e) }
    setLoading(false)
  }

  const loadStats = async () => {
    try {
      const res = await api.get('/pocs/stats')
      setStats(res.data.data)
    } catch (e) { console.error(e) }
  }

  const handleSearch = () => {
    setPage(0)
    loadPocs()
  }

  const savePoc = async () => {
    const data = {
      ...pocForm,
      cve_ids: pocForm.cve_ids ? pocForm.cve_ids.split(',').map(s => s.trim()).filter(Boolean) : [],
      cnvd_ids: pocForm.cnvd_ids ? pocForm.cnvd_ids.split(',').map(s => s.trim()).filter(Boolean) : [],
      tags: pocForm.tags ? pocForm.tags.split(',').map(s => s.trim()).filter(Boolean) : [],
      affected_versions: pocForm.affected_versions ? pocForm.affected_versions.split(',').map(s => s.trim()).filter(Boolean) : [],
      references: pocForm.references ? pocForm.references.split('\n').map(s => s.trim()).filter(Boolean) : [],
      requests: pocForm.requests.map(r => ({
        ...r,
        headers: safeJsonParse(r.headers, {}),
      })),
    }

    try {
      if (editingPoc) {
        await api.put(`/pocs/custom/${editingPoc.db_id}`, data)
      } else {
        await api.post('/pocs/custom', data)
      }
      setShowForm(false)
      setEditingPoc(null)
      setPocForm(getEmptyForm())
      loadPocs()
      loadStats()
    } catch (e) {
      alert('保存失败: ' + (e.response?.data?.detail || e.message))
    }
  }

  const deletePoc = async (poc) => {
    if (!confirm(`确定删除POC "${poc.name}"？`)) return
    try {
      await api.delete(`/pocs/custom/${poc.db_id}`)
      loadPocs()
      loadStats()
    } catch (e) { alert('删除失败') }
  }

  const togglePoc = async (poc) => {
    try {
      await api.post(`/pocs/custom/${poc.db_id}/toggle`)
      loadPocs()
      loadStats()
    } catch (e) { alert('操作失败') }
  }

  const editPoc = (poc) => {
    setPocForm({
      name: poc.name,
      description: poc.description || '',
      risk_level: poc.risk_level,
      cve_ids: (poc.cve_ids || []).join(', '),
      cnvd_ids: (poc.cnvd_ids || []).join(', '),
      cvss_score: String(poc.cvss_score || '0.0'),
      tags: (poc.tags || []).join(', '),
      affected_versions: (poc.affected_versions || []).join(', '),
      poc_type: poc.poc_type || 'http',
      requests: (poc.requests || []).length > 0
        ? poc.requests.map(r => ({ ...r, headers: JSON.stringify(r.headers || {}, null, 2) }))
        : [{ method: 'GET', path: '/', headers: '{}', body: '' }],
      matchers: (poc.matchers || []).length > 0
        ? poc.matchers
        : [{ type: 'word', value: '', part: 'body', negative: false }],
      references: (poc.references || []).join('\n'),
      fix_suggestion: poc.fix_suggestion || '',
      disclosure_date: poc.disclosure_date || '',
      is_enabled: poc.is_enabled !== false,
    })
    setEditingPoc(poc)
    setShowForm(true)
  }

  const addRequest = () => {
    setPocForm({
      ...pocForm,
      requests: [...pocForm.requests, { method: 'GET', path: '/', headers: '{}', body: '' }],
    })
  }

  const removeRequest = (idx) => {
    setPocForm({
      ...pocForm,
      requests: pocForm.requests.filter((_, i) => i !== idx),
    })
  }

  const updateRequest = (idx, field, value) => {
    const updated = [...pocForm.requests]
    updated[idx] = { ...updated[idx], [field]: value }
    setPocForm({ ...pocForm, requests: updated })
  }

  const addMatcher = () => {
    setPocForm({
      ...pocForm,
      matchers: [...pocForm.matchers, { type: 'word', value: '', part: 'body', negative: false }],
    })
  }

  const removeMatcher = (idx) => {
    setPocForm({
      ...pocForm,
      matchers: pocForm.matchers.filter((_, i) => i !== idx),
    })
  }

  const updateMatcher = (idx, field, value) => {
    const updated = [...pocForm.matchers]
    updated[idx] = { ...updated[idx], [field]: value }
    setPocForm({ ...pocForm, matchers: updated })
  }

  function safeJsonParse(str, fallback) {
    try { return JSON.parse(str) } catch (e) { return fallback }
  }

  const cardStyle = {
    background: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
    padding: '20px',
    marginBottom: '16px',
  }

  const inputStyle = {
    width: '100%',
    padding: '8px 12px',
    background: 'var(--bg-tertiary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    color: 'var(--text-primary)',
    fontSize: '13px',
    outline: 'none',
    boxSizing: 'border-box',
  }

  const btnPrimary = {
    padding: '8px 16px',
    background: 'var(--accent)',
    color: '#fff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '13px',
    fontWeight: 600,
  }

  const btnDanger = {
    padding: '6px 12px',
    background: 'var(--danger-subtle)',
    color: 'var(--danger)',
    border: '1px solid var(--danger)',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '12px',
  }

  const btnOutline = {
    padding: '6px 12px',
    background: 'transparent',
    color: 'var(--text-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '12px',
  }

  const badgeStyle = (enabled) => ({
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: '10px',
    fontSize: '11px',
    fontWeight: 600,
    background: enabled ? 'var(--success-subtle)' : 'var(--bg-tertiary)',
    color: enabled ? 'var(--success)' : 'var(--text-dim)',
  })

  const totalPages = Math.ceil(total / pageSize)

  return (
    <div>
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-bright)', margin: 0 }}>
          POC 管理
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-dim)', marginTop: '4px' }}>
          管理内置和自定义漏洞检测POC
        </p>
      </div>

      {stats && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: '12px', marginBottom: '20px' }}>
          {[
            { label: 'POC总数', value: stats.total, color: 'var(--accent)' },
            { label: '内置POC', value: stats.builtin, color: 'var(--info)' },
            { label: '自定义POC', value: stats.custom, color: 'var(--success)' },
            { label: '严重', value: stats.risk_distribution?.critical || 0, color: 'var(--danger)' },
            { label: '高危', value: stats.risk_distribution?.high || 0, color: '#ea580c' },
            { label: '中危', value: stats.risk_distribution?.medium || 0, color: 'var(--warning)' },
          ].map(item => (
            <div key={item.label} style={{ ...cardStyle, padding: '16px', marginBottom: 0, textAlign: 'center' }}>
              <div style={{ fontSize: '24px', fontWeight: 700, color: item.color }}>{item.value}</div>
              <div style={{ fontSize: '12px', color: 'var(--text-dim)', marginTop: '4px' }}>{item.label}</div>
            </div>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', gap: '8px', marginBottom: '16px', flexWrap: 'wrap', alignItems: 'center' }}>
        <input
          style={{ ...inputStyle, width: '240px' }}
          placeholder="搜索POC名称或描述..."
          value={keyword}
          onChange={e => setKeyword(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSearch()}
        />
        <select style={{ ...inputStyle, width: '120px' }} value={riskFilter} onChange={e => { setRiskFilter(e.target.value); setPage(0) }}>
          <option value="">全部风险</option>
          <option value="critical">严重</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
          <option value="info">信息</option>
        </select>
        <select style={{ ...inputStyle, width: '120px' }} value={sourceFilter} onChange={e => { setSourceFilter(e.target.value); setPage(0) }}>
          <option value="all">全部来源</option>
          <option value="builtin">内置POC</option>
          <option value="custom">自定义POC</option>
        </select>
        <button style={btnOutline} onClick={handleSearch}>搜索</button>
        <div style={{ flex: 1 }} />
        <button style={btnPrimary} onClick={() => { setPocForm(getEmptyForm()); setEditingPoc(null); setShowForm(true) }}>
          + 添加自定义POC
        </button>
      </div>

      {showForm && (
        <div style={cardStyle}>
          <h3 style={{ fontSize: '15px', color: 'var(--text-bright)', margin: '0 0 16px 0' }}>
            {editingPoc ? '编辑POC' : '添加自定义POC'}
          </h3>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
            <div>
              <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>POC名称 *</label>
              <input style={inputStyle} value={pocForm.name} onChange={e => setPocForm({ ...pocForm, name: e.target.value })} />
            </div>
            <div>
              <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>风险等级</label>
              <select style={inputStyle} value={pocForm.risk_level} onChange={e => setPocForm({ ...pocForm, risk_level: e.target.value })}>
                {Object.entries(RISK_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </div>
            <div style={{ gridColumn: '1 / -1' }}>
              <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>描述</label>
              <textarea style={{ ...inputStyle, minHeight: '60px', resize: 'vertical' }} value={pocForm.description} onChange={e => setPocForm({ ...pocForm, description: e.target.value })} />
            </div>
            <div>
              <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>CVE编号 (逗号分隔)</label>
              <input style={inputStyle} value={pocForm.cve_ids} onChange={e => setPocForm({ ...pocForm, cve_ids: e.target.value })} placeholder="CVE-2024-XXXX" />
            </div>
            <div>
              <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>CNVD编号 (逗号分隔)</label>
              <input style={inputStyle} value={pocForm.cnvd_ids} onChange={e => setPocForm({ ...pocForm, cnvd_ids: e.target.value })} placeholder="CNVD-2024-XXXX" />
            </div>
            <div>
              <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>CVSS评分</label>
              <input style={inputStyle} value={pocForm.cvss_score} onChange={e => setPocForm({ ...pocForm, cvss_score: e.target.value })} />
            </div>
            <div>
              <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>标签 (逗号分隔)</label>
              <input style={inputStyle} value={pocForm.tags} onChange={e => setPocForm({ ...pocForm, tags: e.target.value })} placeholder="rce, cve-2024" />
            </div>
            <div style={{ gridColumn: '1 / -1' }}>
              <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>影响版本 (逗号分隔)</label>
              <input style={inputStyle} value={pocForm.affected_versions} onChange={e => setPocForm({ ...pocForm, affected_versions: e.target.value })} />
            </div>
          </div>

          <div style={{ marginTop: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <label style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-bright)' }}>HTTP请求</label>
              <button style={btnOutline} onClick={addRequest}>+ 添加请求</button>
            </div>
            {pocForm.requests.map((req, idx) => (
              <div key={idx} style={{ ...cardStyle, padding: '12px', marginBottom: '8px', background: 'var(--bg-tertiary)' }}>
                <div style={{ display: 'flex', gap: '8px', marginBottom: '8px', alignItems: 'center' }}>
                  <select style={{ ...inputStyle, width: '100px' }} value={req.method} onChange={e => updateRequest(idx, 'method', e.target.value)}>
                    {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => (
                      <option key={m} value={m}>{m}</option>
                    ))}
                  </select>
                  <input style={{ ...inputStyle, flex: 1 }} value={req.path} onChange={e => updateRequest(idx, 'path', e.target.value)} placeholder="/path" />
                  {pocForm.requests.length > 1 && (
                    <button style={btnDanger} onClick={() => removeRequest(idx)}>删除</button>
                  )}
                </div>
                <div style={{ marginBottom: '8px' }}>
                  <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'block', marginBottom: '2px' }}>Headers (JSON)</label>
                  <textarea style={{ ...inputStyle, minHeight: '40px', resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: '11px' }}
                    value={req.headers} onChange={e => updateRequest(idx, 'headers', e.target.value)} />
                </div>
                <div>
                  <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'block', marginBottom: '2px' }}>Body</label>
                  <textarea style={{ ...inputStyle, minHeight: '40px', resize: 'vertical', fontFamily: 'var(--font-mono)', fontSize: '11px' }}
                    value={req.body} onChange={e => updateRequest(idx, 'body', e.target.value)} />
                </div>
              </div>
            ))}
          </div>

          <div style={{ marginTop: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
              <label style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-bright)' }}>匹配规则</label>
              <button style={btnOutline} onClick={addMatcher}>+ 添加规则</button>
            </div>
            {pocForm.matchers.map((m, idx) => (
              <div key={idx} style={{ display: 'flex', gap: '8px', marginBottom: '8px', alignItems: 'center' }}>
                <select style={{ ...inputStyle, width: '130px' }} value={m.type} onChange={e => updateMatcher(idx, 'type', e.target.value)}>
                  {MATCHER_TYPES.map(t => (
                    <option key={t.key} value={t.key}>{t.name}</option>
                  ))}
                </select>
                <input style={{ ...inputStyle, flex: 1 }} value={m.value} onChange={e => updateMatcher(idx, 'value', e.target.value)} placeholder="匹配值" />
                <select style={{ ...inputStyle, width: '100px' }} value={m.part} onChange={e => updateMatcher(idx, 'part', e.target.value)}>
                  <option value="body">响应体</option>
                  <option value="header">响应头</option>
                </select>
                <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'flex', alignItems: 'center', gap: '4px', whiteSpace: 'nowrap' }}>
                  <input type="checkbox" checked={m.negative} onChange={e => updateMatcher(idx, 'negative', e.target.checked)} />
                  取反
                </label>
                {pocForm.matchers.length > 1 && (
                  <button style={btnDanger} onClick={() => removeMatcher(idx)}>删除</button>
                )}
              </div>
            ))}
          </div>

          <div style={{ marginTop: '16px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>参考链接 (每行一个)</label>
                <textarea style={{ ...inputStyle, minHeight: '60px', resize: 'vertical' }} value={pocForm.references} onChange={e => setPocForm({ ...pocForm, references: e.target.value })} />
              </div>
              <div>
                <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>修复建议</label>
                <textarea style={{ ...inputStyle, minHeight: '60px', resize: 'vertical' }} value={pocForm.fix_suggestion} onChange={e => setPocForm({ ...pocForm, fix_suggestion: e.target.value })} />
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '16px', marginTop: '12px', alignItems: 'center' }}>
            <label style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
              <input type="checkbox" checked={pocForm.is_enabled} onChange={e => setPocForm({ ...pocForm, is_enabled: e.target.checked })} />
              启用
            </label>
          </div>

          <div style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
            <button style={btnPrimary} onClick={savePoc}>保存POC</button>
            <button style={btnOutline} onClick={() => { setShowForm(false); setEditingPoc(null) }}>取消</button>
          </div>
        </div>
      )}

      {loading && (
        <div style={{ textAlign: 'center', padding: '40px', color: 'var(--text-dim)' }}>加载中...</div>
      )}

      {!loading && pocs.length === 0 && (
        <div style={{ ...cardStyle, textAlign: 'center', color: 'var(--text-dim)', padding: '40px' }}>
          暂无POC数据
        </div>
      )}

      {pocs.map(poc => (
        <div key={poc.id} style={cardStyle}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div style={{ flex: 1 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px', flexWrap: 'wrap' }}>
                <span style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-bright)' }}>{poc.name}</span>
                <span style={{
                  display: 'inline-block',
                  padding: '2px 8px',
                  borderRadius: '10px',
                  fontSize: '11px',
                  fontWeight: 600,
                  background: `${RISK_COLORS[poc.risk_level]}20`,
                  color: RISK_COLORS[poc.risk_level],
                }}>
                  {RISK_LABELS[poc.risk_level] || poc.risk_level}
                </span>
                <span style={{
                  display: 'inline-block',
                  padding: '2px 8px',
                  borderRadius: '10px',
                  fontSize: '11px',
                  fontWeight: 600,
                  background: poc.source === 'builtin' ? 'var(--info-subtle)' : 'var(--success-subtle)',
                  color: poc.source === 'builtin' ? 'var(--info)' : 'var(--success)',
                }}>
                  {poc.source === 'builtin' ? '内置' : '自定义'}
                </span>
                {poc.source === 'custom' && (
                  <span style={badgeStyle(poc.is_enabled)}>{poc.is_enabled ? '启用' : '禁用'}</span>
                )}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-dim)', lineHeight: '1.5', marginBottom: '8px' }}>
                {poc.description}
              </div>
              <div style={{ display: 'flex', gap: '16px', flexWrap: 'wrap', fontSize: '11px', color: 'var(--text-dim)' }}>
                {poc.cve_ids?.length > 0 && (
                  <span>CVE: {poc.cve_ids.join(', ')}</span>
                )}
                {poc.cnvd_ids?.length > 0 && (
                  <span>CNVD: {poc.cnvd_ids.join(', ')}</span>
                )}
                {poc.cvss_score > 0 && (
                  <span>CVSS: {poc.cvss_score}</span>
                )}
                {poc.tags?.length > 0 && (
                  <span>标签: {poc.tags.join(', ')}</span>
                )}
              </div>
            </div>
            {poc.source === 'custom' && (
              <div style={{ display: 'flex', gap: '6px', flexShrink: 0, marginLeft: '12px' }}>
                <button style={btnOutline} onClick={() => togglePoc(poc)}>
                  {poc.is_enabled ? '禁用' : '启用'}
                </button>
                <button style={btnOutline} onClick={() => editPoc(poc)}>编辑</button>
                <button style={btnDanger} onClick={() => deletePoc(poc)}>删除</button>
              </div>
            )}
          </div>
        </div>
      ))}

      {totalPages > 1 && (
        <div style={{ display: 'flex', justifyContent: 'center', gap: '8px', marginTop: '20px' }}>
          <button style={btnOutline} disabled={page === 0} onClick={() => setPage(page - 1)}>上一页</button>
          <span style={{ padding: '6px 12px', fontSize: '13px', color: 'var(--text-secondary)' }}>
            {page + 1} / {totalPages}
          </span>
          <button style={btnOutline} disabled={page >= totalPages - 1} onClick={() => setPage(page + 1)}>下一页</button>
        </div>
      )}
    </div>
  )
}
