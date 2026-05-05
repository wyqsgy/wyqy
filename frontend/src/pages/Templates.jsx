import React, { useState, useEffect, useCallback } from 'react'
import api from '../api'

const SEVERITY_COLORS = {
  critical: 'var(--danger)',
  high: '#ea580c',
  medium: 'var(--warning)',
  low: 'var(--info)',
  info: 'var(--text-dim)',
}

const SEVERITY_LABELS = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

const EXAMPLE_TEMPLATE = `id: example-sql-injection
info:
  name: SQL注入检测示例
  severity: high
  description: 检测GET参数中的SQL注入漏洞
  tags:
    - sql-injection
    - sqli

requests:
  - method: GET
    path: /api/users?id=1' OR '1'='1
    headers:
      User-Agent: WyqYan/1.0

    matchers:
      - type: word
        words:
          - "mysql"
          - "syntax error"
        condition: or

      - type: status
        status:
          - 200
          - 500
`

export default function Templates() {
  const [templates, setTemplates] = useState([])
  const [loading, setLoading] = useState(true)
  const [showEditor, setShowEditor] = useState(false)
  const [editingId, setEditingId] = useState(null)
  const [form, setForm] = useState({
    template_id: '',
    name: '',
    description: '',
    severity: 'medium',
    tags: '',
    content: '',
    format: 'yaml',
    enabled: true,
  })
  const [validating, setValidating] = useState(false)
  const [validationResult, setValidationResult] = useState(null)
  const [saving, setSaving] = useState(false)

  const loadTemplates = useCallback(async () => {
    try {
      const res = await api.get('/templates/', { params: { limit: 200 } })
      setTemplates(res.data.data?.items || [])
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { loadTemplates() }, [loadTemplates])

  const resetForm = () => {
    setForm({
      template_id: '',
      name: '',
      description: '',
      severity: 'medium',
      tags: '',
      content: '',
      format: 'yaml',
      enabled: true,
    })
    setEditingId(null)
    setValidationResult(null)
  }

  const openCreate = () => {
    resetForm()
    setShowEditor(true)
  }

  const openEdit = async (templateId) => {
    try {
      const res = await api.get(`/templates/${templateId}`)
      const t = res.data.data
      setForm({
        template_id: t.template_id,
        name: t.name,
        description: t.description || '',
        severity: t.severity,
        tags: (t.tags || []).join(', '),
        content: t.content,
        format: t.format,
        enabled: t.enabled,
      })
      setEditingId(templateId)
      setShowEditor(true)
      setValidationResult(null)
    } catch (e) {
      alert('加载模板失败')
    }
  }

  const handleValidate = async () => {
    if (!form.content.trim()) return
    setValidating(true)
    try {
      const res = await api.post('/templates/validate', {
        content: form.content,
        format: form.format,
      })
      setValidationResult(res.data.data)
    } catch (e) {
      setValidationResult({ valid: false, errors: [e.message] })
    }
    setValidating(false)
  }

  const handleSave = async () => {
    if (!form.template_id.trim() || !form.name.trim() || !form.content.trim()) {
      alert('请填写模板ID、名称和内容')
      return
    }
    setSaving(true)
    try {
      const payload = {
        ...form,
        tags: form.tags ? form.tags.split(',').map(t => t.trim()).filter(Boolean) : [],
      }
      if (editingId) {
        await api.put(`/templates/${editingId}`, payload)
      } else {
        await api.post('/templates/', payload)
      }
      setShowEditor(false)
      resetForm()
      loadTemplates()
    } catch (e) {
      alert('保存失败: ' + (e.response?.data?.detail || e.message))
    }
    setSaving(false)
  }

  const handleToggle = async (templateId) => {
    try {
      await api.post(`/templates/${templateId}/toggle`)
      loadTemplates()
    } catch (e) {
      alert('操作失败')
    }
  }

  const handleDelete = async (templateId) => {
    if (!window.confirm('确定要删除此模板吗？')) return
    try {
      await api.delete(`/templates/${templateId}`)
      loadTemplates()
    } catch (e) {
      alert('删除失败')
    }
  }

  const loadExample = () => {
    setForm(prev => ({ ...prev, content: EXAMPLE_TEMPLATE }))
  }

  const btnStyle = {
    padding: '8px 16px',
    borderRadius: '6px',
    border: '1px solid var(--border-color)',
    background: 'var(--bg-tertiary)',
    color: 'var(--text-primary)',
    cursor: 'pointer',
    fontSize: '13px',
    fontWeight: 600,
  }

  if (loading) {
    return (
      <div className="terminal" style={{ height: '300px' }}>
        <div className="line prompt">$ 正在加载模板...</div>
        <div className="line cursor">_</div>
      </div>
    )
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
        <div className="sec-title">自定义检测模板</div>
        <button
          style={{ ...btnStyle, background: 'var(--accent)', color: '#fff', border: 'none' }}
          onClick={openCreate}
        >
          + 新建模板
        </button>
      </div>

      <div className="card" style={{ padding: '16px', marginBottom: '20px', background: 'var(--info-subtle)', border: '1px solid var(--info)' }}>
        <div style={{ fontSize: '12px', color: 'var(--info)', lineHeight: '1.6' }}>
          💡 自定义检测模板允许你编写 YAML/JSON 格式的漏洞检测规则，对标 Nuclei 模板机制。
          模板会在每次扫描时自动加载执行，帮助你发现内置规则无法覆盖的特定漏洞。
        </div>
      </div>

      {showEditor && (
        <div className="card" style={{ padding: '20px', marginBottom: '20px' }}>
          <div className="sec-subtitle" style={{ marginBottom: '16px', fontWeight: 600, color: 'var(--text-bright)' }}>
            {editingId ? '编辑模板' : '新建模板'}
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '16px' }}>
            <div>
              <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>模板ID *</label>
              <input
                style={{
                  width: '100%', padding: '8px 12px', borderRadius: '6px',
                  border: '1px solid var(--border-color)', background: 'var(--bg-tertiary)',
                  color: 'var(--text-primary)', fontSize: '13px',
                }}
                value={form.template_id}
                onChange={e => setForm({ ...form, template_id: e.target.value })}
                disabled={!!editingId}
                placeholder="my-custom-check"
              />
            </div>
            <div>
              <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>模板名称 *</label>
              <input
                style={{
                  width: '100%', padding: '8px 12px', borderRadius: '6px',
                  border: '1px solid var(--border-color)', background: 'var(--bg-tertiary)',
                  color: 'var(--text-primary)', fontSize: '13px',
                }}
                value={form.name}
                onChange={e => setForm({ ...form, name: e.target.value })}
                placeholder="SQL注入检测"
              />
            </div>
            <div>
              <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>风险等级</label>
              <select
                style={{
                  width: '100%', padding: '8px 12px', borderRadius: '6px',
                  border: '1px solid var(--border-color)', background: 'var(--bg-tertiary)',
                  color: 'var(--text-primary)', fontSize: '13px',
                }}
                value={form.severity}
                onChange={e => setForm({ ...form, severity: e.target.value })}
              >
                {Object.entries(SEVERITY_LABELS).map(([k, v]) => (
                  <option key={k} value={k}>{v}</option>
                ))}
              </select>
            </div>
            <div>
              <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>标签 (逗号分隔)</label>
              <input
                style={{
                  width: '100%', padding: '8px 12px', borderRadius: '6px',
                  border: '1px solid var(--border-color)', background: 'var(--bg-tertiary)',
                  color: 'var(--text-primary)', fontSize: '13px',
                }}
                value={form.tags}
                onChange={e => setForm({ ...form, tags: e.target.value })}
                placeholder="sql-injection, sqli"
              />
            </div>
          </div>

          <div style={{ marginBottom: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
              <label style={{ fontSize: '11px', color: 'var(--text-dim)' }}>模板内容 (YAML) *</label>
              <button
                style={{ fontSize: '11px', color: 'var(--accent)', background: 'none', border: 'none', cursor: 'pointer' }}
                onClick={loadExample}
              >
                加载示例
              </button>
            </div>
            <textarea
              style={{
                width: '100%', minHeight: '300px', padding: '12px', borderRadius: '6px',
                border: '1px solid var(--border-color)', background: 'var(--bg-tertiary)',
                color: 'var(--text-primary)', fontSize: '12px', fontFamily: 'monospace',
                resize: 'vertical',
              }}
              value={form.content}
              onChange={e => setForm({ ...form, content: e.target.value })}
              placeholder="在此编写YAML格式的检测模板..."
            />
          </div>

          {validationResult && (
            <div style={{
              padding: '12px', borderRadius: '6px', marginBottom: '12px',
              background: validationResult.valid ? 'var(--success-subtle)' : 'var(--danger-subtle)',
              border: `1px solid ${validationResult.valid ? 'var(--success)' : 'var(--danger)'}`,
            }}>
              <div style={{ fontSize: '13px', fontWeight: 600, color: validationResult.valid ? 'var(--success)' : 'var(--danger)', marginBottom: '4px' }}>
                {validationResult.valid ? '✓ 模板验证通过' : '✗ 模板验证失败'}
              </div>
              {validationResult.parsed && (
                <div style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>
                  ID: {validationResult.parsed.id} | 名称: {validationResult.parsed.name} | 请求数: {validationResult.parsed.requests_count}
                </div>
              )}
              {validationResult.errors?.map((err, i) => (
                <div key={i} style={{ fontSize: '11px', color: 'var(--danger)', marginTop: '2px' }}>• {err}</div>
              ))}
            </div>
          )}

          <div style={{ display: 'flex', gap: '8px' }}>
            <button style={btnStyle} onClick={handleValidate} disabled={validating}>
              {validating ? '验证中...' : '🔍 验证模板'}
            </button>
            <button style={{ ...btnStyle, background: 'var(--accent)', color: '#fff', border: 'none' }} onClick={handleSave} disabled={saving}>
              {saving ? '保存中...' : '💾 保存模板'}
            </button>
            <button style={btnStyle} onClick={() => { setShowEditor(false); resetForm() }}>
              取消
            </button>
          </div>
        </div>
      )}

      {templates.length === 0 ? (
        <div className="card" style={{ padding: '40px', textAlign: 'center' }}>
          <div style={{ fontSize: '14px', color: 'var(--text-dim)', marginBottom: '12px' }}>
            暂无自定义模板
          </div>
          <button style={{ ...btnStyle, background: 'var(--accent)', color: '#fff', border: 'none' }} onClick={openCreate}>
            创建第一个模板
          </button>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
          {templates.map((t) => (
            <div key={t.template_id} className="card" style={{
              padding: '16px',
              opacity: t.enabled ? 1 : 0.5,
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div style={{ flex: 1 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                    <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-bright)' }}>
                      {t.name}
                    </span>
                    <span style={{
                      display: 'inline-block', padding: '2px 8px', borderRadius: '10px',
                      fontSize: '10px', fontWeight: 600,
                      background: `${SEVERITY_COLORS[t.severity]}20`,
                      color: SEVERITY_COLORS[t.severity],
                    }}>
                      {SEVERITY_LABELS[t.severity] || t.severity}
                    </span>
                    {!t.enabled && (
                      <span style={{
                        display: 'inline-block', padding: '2px 8px', borderRadius: '10px',
                        fontSize: '10px', fontWeight: 600,
                        background: 'var(--bg-tertiary)', color: 'var(--text-dim)',
                      }}>
                        已禁用
                      </span>
                    )}
                  </div>
                  <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginBottom: '4px' }}>
                    ID: {t.template_id}
                    {t.description && ` | ${t.description.substring(0, 60)}`}
                  </div>
                  <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {(t.tags || []).map(tag => (
                      <span key={tag} style={{
                        fontSize: '10px', padding: '1px 6px',
                        background: 'var(--bg-tertiary)', borderRadius: '3px',
                        color: 'var(--text-dim)', border: '1px solid var(--border-color)',
                      }}>
                        {tag}
                      </span>
                    ))}
                    {t.match_count > 0 && (
                      <span style={{ fontSize: '10px', color: 'var(--success)' }}>
                        命中: {t.match_count}次
                      </span>
                    )}
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '6px', flexShrink: 0, marginLeft: '12px' }}>
                  <button
                    style={{ ...btnStyle, padding: '4px 10px', fontSize: '11px' }}
                    onClick={() => openEdit(t.template_id)}
                  >
                    编辑
                  </button>
                  <button
                    style={{ ...btnStyle, padding: '4px 10px', fontSize: '11px' }}
                    onClick={() => handleToggle(t.template_id)}
                  >
                    {t.enabled ? '禁用' : '启用'}
                  </button>
                  <button
                    style={{ ...btnStyle, padding: '4px 10px', fontSize: '11px', color: 'var(--danger)', borderColor: 'var(--danger)' }}
                    onClick={() => handleDelete(t.template_id)}
                  >
                    删除
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
