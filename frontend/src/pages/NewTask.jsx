import React, { useState } from 'react'
import { createTask } from '../api'
import { useNavigate } from 'react-router-dom'

const SCAN_TYPES = [
  { value: 'quick', label: '快速扫描', desc: '使用常用模块进行快速扫描' },
  { value: 'full', label: '全面扫描', desc: '使用全部模块进行全面深度扫描' },
  { value: 'recon', label: '仅侦察', desc: '仅进行端口、子域名、指纹识别' },
  { value: 'stealth', label: '隐蔽扫描', desc: '低速隐蔽扫描，避免触发告警' },
]

export default function NewTask() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('quick')
  const [modules, setModules] = useState('')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async () => {
    if (!target.trim()) { setError('请输入目标地址'); return }
    setLoading(true); setError('')
    try {
      const modList = modules.trim() ? modules.split(',').map((m) => m.trim()).filter(Boolean) : undefined
      await createTask({ target: target.trim(), scan_type: scanType, modules: modList })
      navigate('/tasks')
    } catch (e) {
      setError(e.response?.data?.detail || e.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <div className="sec-title" style={{ marginBottom: '24px' }}>新建扫描</div>

      <div className="card" style={{ padding: '24px', maxWidth: '600px' }}>
        <div style={{ marginBottom: '20px' }}>
          <div className="label-text" style={{ marginBottom: '8px' }}>目标地址</div>
          <input
            className="pixel-input"
            placeholder="https://target.com 或 192.168.1.1"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
          />
        </div>

        <div style={{ marginBottom: '20px' }}>
          <div className="label-text" style={{ marginBottom: '8px' }}>扫描类型</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
            {SCAN_TYPES.map((st) => (
              <div
                key={st.value}
                className="card"
                onClick={() => setScanType(st.value)}
                style={{
                  padding: '12px',
                  cursor: 'pointer',
                  borderColor: scanType === st.value ? 'var(--accent)' : 'var(--border-color)',
                  background: scanType === st.value ? 'var(--accent-subtle)' : 'var(--bg-card)',
                }}
              >
                <div style={{ fontWeight: 600, fontSize: '13px', color: scanType === st.value ? 'var(--text-bright)' : 'var(--text-primary)', marginBottom: '4px' }}>
                  {st.label}
                </div>
                <div style={{ fontSize: '12px', color: 'var(--text-dim)' }}>{st.desc}</div>
              </div>
            ))}
          </div>
        </div>

        <div style={{ marginBottom: '20px' }}>
          <div className="label-text" style={{ marginBottom: '8px' }}>自定义模块 (可选)</div>
          <input
            className="pixel-input"
            placeholder="spring,shiro,log4j (逗号分隔)"
            value={modules}
            onChange={(e) => setModules(e.target.value)}
          />
          <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '4px' }}>
            留空则自动识别模块
          </div>
        </div>

        {error && (
          <div style={{ padding: '10px', background: 'var(--danger-subtle)', color: 'var(--danger)', borderRadius: '6px', marginBottom: '16px', fontSize: '13px' }}>
            {error}
          </div>
        )}

        <button className="btn btn-accent" onClick={handleSubmit} disabled={loading} style={{ width: '100%' }}>
          {loading ? '创建中...' : '开始扫描'}
        </button>
      </div>
    </div>
  )
}
