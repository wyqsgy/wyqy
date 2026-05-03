import React, { useState } from 'react'
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

export default function PacketVerifier() {
  const [mode, setMode] = useState('form')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [useAi, setUseAi] = useState(true)

  const [formData, setFormData] = useState({
    request_method: 'GET',
    request_url: '',
    request_headers: '{}',
    request_body: '',
    response_status: '200',
    response_headers: '{}',
    response_body: '',
  })

  const [rawRequest, setRawRequest] = useState('')
  const [rawResponse, setRawResponse] = useState('')

  const verifyForm = async () => {
    setLoading(true)
    setResult(null)
    try {
      let headers = {}
      let respHeaders = {}
      try { headers = JSON.parse(formData.request_headers) } catch (e) {}
      try { respHeaders = JSON.parse(formData.response_headers) } catch (e) {}

      const res = await api.post('/verify/packet', {
        request_method: formData.request_method,
        request_url: formData.request_url,
        request_headers: headers,
        request_body: formData.request_body || null,
        response_status: parseInt(formData.response_status) || 0,
        response_headers: respHeaders,
        response_body: formData.response_body || null,
        use_ai: useAi,
      })
      setResult(res.data.data)
    } catch (e) {
      alert('验证失败: ' + (e.response?.data?.detail || e.message))
    }
    setLoading(false)
  }

  const verifyRaw = async () => {
    setLoading(true)
    setResult(null)
    try {
      const res = await api.post('/verify/raw', {
        raw_request: rawRequest || null,
        raw_response: rawResponse || null,
        use_ai: useAi,
      })
      setResult(res.data.data)
    } catch (e) {
      alert('验证失败: ' + (e.response?.data?.detail || e.message))
    }
    setLoading(false)
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

  const textareaStyle = {
    ...inputStyle,
    minHeight: '120px',
    resize: 'vertical',
    fontFamily: 'var(--font-mono)',
    fontSize: '12px',
  }

  const btnPrimary = {
    padding: '10px 24px',
    background: 'var(--accent)',
    color: '#fff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '14px',
    fontWeight: 600,
  }

  const btnOutline = {
    padding: '8px 16px',
    background: 'transparent',
    color: 'var(--text-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '13px',
  }

  return (
    <div>
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-bright)', margin: 0 }}>
          AI 报文验证
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-dim)', marginTop: '4px' }}>
          提交HTTP请求/响应报文，AI自动识别和验证漏洞
        </p>
      </div>

      <div style={{ display: 'flex', gap: '4px', marginBottom: '20px', borderBottom: '1px solid var(--border-color)' }}>
        {[
          { key: 'form', label: '📋 表单模式' },
          { key: 'raw', label: '📝 原始报文' },
        ].map(t => (
          <button
            key={t.key}
            onClick={() => { setMode(t.key); setResult(null) }}
            style={{
              padding: '10px 20px',
              background: 'transparent',
              border: 'none',
              borderBottom: mode === t.key ? '2px solid var(--accent)' : '2px solid transparent',
              color: mode === t.key ? 'var(--text-bright)' : 'var(--text-dim)',
              cursor: 'pointer',
              fontSize: '13px',
              fontWeight: mode === t.key ? 600 : 400,
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {mode === 'form' && (
        <div>
          <div style={cardStyle}>
            <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-bright)', margin: '0 0 12px 0' }}>
              请求报文
            </h3>
            <div style={{ display: 'flex', gap: '8px', marginBottom: '8px' }}>
              <select style={{ ...inputStyle, width: '120px' }} value={formData.request_method}
                onChange={e => setFormData({ ...formData, request_method: e.target.value })}>
                {['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'].map(m => (
                  <option key={m} value={m}>{m}</option>
                ))}
              </select>
              <input style={{ ...inputStyle, flex: 1 }} value={formData.request_url}
                onChange={e => setFormData({ ...formData, request_url: e.target.value })}
                placeholder="https://target.com/path?param=value" />
            </div>
            <div style={{ marginBottom: '8px' }}>
              <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'block', marginBottom: '2px' }}>请求头 (JSON)</label>
              <textarea style={{ ...textareaStyle, minHeight: '60px' }} value={formData.request_headers}
                onChange={e => setFormData({ ...formData, request_headers: e.target.value })} />
            </div>
            <div>
              <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'block', marginBottom: '2px' }}>请求体</label>
              <textarea style={{ ...textareaStyle, minHeight: '60px' }} value={formData.request_body}
                onChange={e => setFormData({ ...formData, request_body: e.target.value })} />
            </div>
          </div>

          <div style={cardStyle}>
            <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-bright)', margin: '0 0 12px 0' }}>
              响应报文
            </h3>
            <div style={{ marginBottom: '8px' }}>
              <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'block', marginBottom: '2px' }}>状态码</label>
              <input style={{ ...inputStyle, width: '120px' }} value={formData.response_status}
                onChange={e => setFormData({ ...formData, response_status: e.target.value })} />
            </div>
            <div style={{ marginBottom: '8px' }}>
              <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'block', marginBottom: '2px' }}>响应头 (JSON)</label>
              <textarea style={{ ...textareaStyle, minHeight: '60px' }} value={formData.response_headers}
                onChange={e => setFormData({ ...formData, response_headers: e.target.value })} />
            </div>
            <div>
              <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'block', marginBottom: '2px' }}>响应体</label>
              <textarea style={textareaStyle} value={formData.response_body}
                onChange={e => setFormData({ ...formData, response_body: e.target.value })} />
            </div>
          </div>

          <div style={{ display: 'flex', gap: '16px', alignItems: 'center', marginBottom: '16px' }}>
            <label style={{ fontSize: '13px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
              <input type="checkbox" checked={useAi} onChange={e => setUseAi(e.target.checked)} />
              🤖 使用AI增强分析
            </label>
            <button style={btnPrimary} onClick={verifyForm} disabled={loading}>
              {loading ? '分析中...' : '开始验证'}
            </button>
          </div>
        </div>
      )}

      {mode === 'raw' && (
        <div>
          <div style={cardStyle}>
            <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-bright)', margin: '0 0 12px 0' }}>
              原始HTTP请求
            </h3>
            <textarea
              style={{ ...textareaStyle, minHeight: '150px' }}
              value={rawRequest}
              onChange={e => setRawRequest(e.target.value)}
              placeholder={`GET /path HTTP/1.1\r\nHost: target.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n`}
            />
          </div>

          <div style={cardStyle}>
            <h3 style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-bright)', margin: '0 0 12px 0' }}>
              原始HTTP响应
            </h3>
            <textarea
              style={{ ...textareaStyle, minHeight: '150px' }}
              value={rawResponse}
              onChange={e => setRawResponse(e.target.value)}
              placeholder={`HTTP/1.1 200 OK\r\nServer: nginx\r\nContent-Type: text/html\r\n\r\n<html>...</html>`}
            />
          </div>

          <div style={{ display: 'flex', gap: '16px', alignItems: 'center', marginBottom: '16px' }}>
            <label style={{ fontSize: '13px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '8px', cursor: 'pointer' }}>
              <input type="checkbox" checked={useAi} onChange={e => setUseAi(e.target.checked)} />
              🤖 使用AI增强分析
            </label>
            <button style={btnPrimary} onClick={verifyRaw} disabled={loading}>
              {loading ? '分析中...' : '开始验证'}
            </button>
          </div>
        </div>
      )}

      {result && (
        <div style={{
          ...cardStyle,
          borderLeft: result.is_vulnerable
            ? `4px solid ${RISK_COLORS[result.risk_level] || 'var(--warning)'}`
            : '4px solid var(--success)',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <h3 style={{ fontSize: '16px', fontWeight: 700, margin: 0, color: 'var(--text-bright)' }}>
              验证结果
            </h3>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              {result.ai_enhanced && (
                <span style={{
                  padding: '2px 8px', borderRadius: '10px', fontSize: '11px', fontWeight: 600,
                  background: 'var(--accent-subtle)', color: 'var(--accent)',
                }}>
                  AI增强
                </span>
              )}
              <span style={{
                padding: '4px 12px',
                borderRadius: '12px',
                fontSize: '13px',
                fontWeight: 700,
                background: result.is_vulnerable
                  ? `${RISK_COLORS[result.risk_level]}20`
                  : 'var(--success-subtle)',
                color: result.is_vulnerable
                  ? RISK_COLORS[result.risk_level]
                  : 'var(--success)',
              }}>
                {result.is_vulnerable
                  ? `⚠️ ${RISK_LABELS[result.risk_level] || result.risk_level}风险`
                  : '✅ 未发现漏洞'}
              </span>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginBottom: '12px' }}>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '2px' }}>漏洞类型</div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-bright)' }}>{result.vulnerability_type}</div>
            </div>
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '2px' }}>置信度</div>
              <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--accent)' }}>{result.confidence}%</div>
            </div>
            {result.cvss_score > 0 && (
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '2px' }}>CVSS评分</div>
                <div style={{ fontSize: '14px', fontWeight: 600, color: RISK_COLORS[result.risk_level] }}>
                  {result.cvss_score}
                </div>
              </div>
            )}
            {result.cve_ids?.length > 0 && (
              <div>
                <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '2px' }}>关联CVE</div>
                <div style={{ fontSize: '13px', color: 'var(--info)' }}>{result.cve_ids.join(', ')}</div>
              </div>
            )}
          </div>

          <div style={{ marginBottom: '12px' }}>
            <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '4px' }}>证据摘要</div>
            <div style={{ fontSize: '13px', color: 'var(--text-secondary)', lineHeight: '1.5', padding: '8px 12px', background: 'var(--bg-tertiary)', borderRadius: '6px' }}>
              {result.evidence_summary}
            </div>
          </div>

          {result.matched_patterns?.length > 0 && (
            <div style={{ marginBottom: '12px' }}>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '4px' }}>匹配特征</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                {result.matched_patterns.map((p, i) => (
                  <span key={i} style={{
                    padding: '2px 8px', borderRadius: '10px', fontSize: '11px',
                    background: 'var(--bg-tertiary)', color: 'var(--text-secondary)',
                  }}>
                    {p}
                  </span>
                ))}
              </div>
            </div>
          )}

          {result.remediation && (
            <div>
              <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginBottom: '4px' }}>修复建议</div>
              <div style={{ fontSize: '13px', color: 'var(--success)', lineHeight: '1.5', padding: '8px 12px', background: 'var(--success-subtle)', borderRadius: '6px' }}>
                {result.remediation}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
