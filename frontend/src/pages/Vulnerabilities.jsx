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

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('all')
  const [verifyingIds, setVerifyingIds] = useState({})
  const [verifyResults, setVerifyResults] = useState({})
  const [expandedId, setExpandedId] = useState(null)

  useEffect(() => { loadVulns() }, [])

  const loadVulns = async () => {
    try {
      const res = await api.get('/vulnerabilities', { params: { limit: 200 } })
      const items = res.data.data?.items || []
      setVulns(items)

      const results = {}
      items.forEach(v => {
        const vr = {
          verification_result: v.verification_result || '',
          confidence_score: v.confidence_score || 0,
          false_positive_reason: v.false_positive_reason || '',
          verification_evidences: v.verification_evidences || [],
        }

        if (v.ai_analysis) {
          try {
            const parsed = typeof v.ai_analysis === 'string' ? JSON.parse(v.ai_analysis) : v.ai_analysis
            vr.is_vulnerable = parsed.is_vulnerable ?? (v.ai_confidence >= 70)
            vr.vulnerability_type = parsed.vulnerability_type || ''
            vr.confidence = parsed.confidence !== undefined ? Math.round(parsed.confidence * 100) : v.ai_confidence
            vr.risk_level = parsed.risk_level || v.risk_level
            vr.evidence_summary = parsed.evidence_summary || ''
            vr.matched_patterns = parsed.matched_patterns || []
            vr.cve_ids = parsed.cve_ids || []
            vr.cvss_score = parsed.cvss_score || 0
            vr.remediation = parsed.remediation || ''
            vr.is_confirmed = v.is_confirmed
          } catch (e) {
            vr.is_vulnerable = v.ai_confidence >= 70
            vr.confidence = v.ai_confidence
            vr.is_confirmed = v.is_confirmed
          }
        }
        results[v.vuln_id] = vr
      })
      setVerifyResults(results)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const handleAiVerify = async (vulnId) => {
    setVerifyingIds(prev => ({ ...prev, [vulnId]: true }))
    try {
      const res = await api.post(`/vulnerabilities/${vulnId}/ai-verify`)
      const data = res.data.data
      setVerifyResults(prev => ({
        ...prev,
        [vulnId]: { ...prev[vulnId], ...data },
      }))
      setVulns(prev => prev.map(v =>
        v.vuln_id === vulnId ? { ...v, ai_confidence: data.confidence, is_confirmed: data.is_confirmed } : v
      ))
    } catch (e) {
      alert('AI验证失败: ' + (e.response?.data?.detail || e.message))
    }
    setVerifyingIds(prev => ({ ...prev, [vulnId]: false }))
  }

  const handleDeepVerify = async (vulnId) => {
    setVerifyingIds(prev => ({ ...prev, [vulnId]: true }))
    try {
      const res = await api.post(`/verify/vulnerability/${vulnId}`)
      const data = res.data.data
      setVerifyResults(prev => ({
        ...prev,
        [vulnId]: {
          ...prev[vulnId],
          verification_result: data.result,
          confidence_score: data.confidence_score,
          false_positive_reason: data.false_positive_reason,
          verification_evidences: data.evidences || [],
          recommendations: data.recommendations || [],
        },
      }))
    } catch (e) {
      alert('深度验证失败: ' + (e.response?.data?.detail || e.message))
    }
    setVerifyingIds(prev => ({ ...prev, [vulnId]: false }))
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

  const cardStyle = {
    background: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
    padding: '16px',
    marginBottom: '12px',
  }

  const btnStyle = {
    padding: '5px 12px',
    background: 'var(--accent-subtle)',
    color: 'var(--accent)',
    border: '1px solid var(--accent)',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '12px',
    fontWeight: 600,
    whiteSpace: 'nowrap',
    transition: 'all 0.15s',
  }

  const btnVerifiedStyle = {
    ...btnStyle,
    background: 'var(--success-subtle)',
    color: 'var(--success)',
    border: '1px solid var(--success)',
  }

  const btnDangerStyle = {
    ...btnStyle,
    background: 'var(--danger-subtle)',
    color: 'var(--danger)',
    border: '1px solid var(--danger)',
  }

  if (loading) {
    return (
      <div style={{ textAlign: 'center', padding: '60px 20px', color: 'var(--text-dim)' }}>
        正在加载漏洞列表...
      </div>
    )
  }

  return (
    <div>
      <div style={{ marginBottom: '20px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-bright)', margin: 0 }}>
          漏洞列表
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-dim)', marginTop: '4px' }}>
          点击 AI验证 按钮对漏洞进行智能分析确认
        </p>
      </div>

      <div style={{ display: 'flex', gap: '6px', marginBottom: '16px', flexWrap: 'wrap' }}>
        {filterTabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setFilter(tab.id)}
            style={{
              padding: '6px 14px',
              background: filter === tab.id ? 'var(--sidebar-active)' : 'transparent',
              color: filter === tab.id ? 'var(--text-bright)' : 'var(--text-dim)',
              border: `1px solid ${filter === tab.id ? 'var(--accent)' : 'var(--border-color)'}`,
              borderRadius: '6px',
              cursor: 'pointer',
              fontSize: '12px',
              fontWeight: filter === tab.id ? 600 : 400,
              transition: 'all 0.15s',
            }}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <div style={{ textAlign: 'center', padding: '60px 20px', color: 'var(--text-dim)', fontSize: '14px' }}>
          {vulns.length === 0 ? '暂无漏洞' : '当前筛选条件下无漏洞'}
        </div>
      ) : (
        <div>
          {filtered.map((v) => {
            const vr = verifyResults[v.vuln_id]
            const isVerifying = verifyingIds[v.vuln_id]
            const isExpanded = expandedId === v.vuln_id

            return (
              <div key={v.vuln_id || v.id} style={cardStyle}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '12px' }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px', flexWrap: 'wrap' }}>
                      <span style={{
                        display: 'inline-block',
                        padding: '2px 8px',
                        borderRadius: '10px',
                        fontSize: '11px',
                        fontWeight: 600,
                        background: `${RISK_COLORS[v.risk_level]}20`,
                        color: RISK_COLORS[v.risk_level],
                      }}>
                        {RISK_LABELS[v.risk_level] || '信息'}
                      </span>
                      <span style={{ fontSize: '12px', color: 'var(--accent)', fontWeight: 600 }}>
                        {v.module || '-'}
                      </span>
                      {vr?.verification_result === 'confirmed' && (
                        <span style={{
                          display: 'inline-block',
                          padding: '2px 8px',
                          borderRadius: '10px',
                          fontSize: '11px',
                          fontWeight: 600,
                          background: 'var(--danger-subtle)',
                          color: 'var(--danger)',
                        }}>
                          ⚠ 已确认 ({vr.confidence_score}%)
                        </span>
                      )}
                      {vr?.verification_result === 'likely' && (
                        <span style={{
                          display: 'inline-block',
                          padding: '2px 8px',
                          borderRadius: '10px',
                          fontSize: '11px',
                          fontWeight: 600,
                          background: 'var(--warning-subtle)',
                          color: 'var(--warning)',
                        }}>
                          ~ 疑似漏洞 ({vr.confidence_score}%)
                        </span>
                      )}
                      {vr?.verification_result === 'uncertain' && (
                        <span style={{
                          display: 'inline-block',
                          padding: '2px 8px',
                          borderRadius: '10px',
                          fontSize: '11px',
                          fontWeight: 600,
                          background: 'var(--info-subtle)',
                          color: 'var(--info)',
                        }}>
                          ? 不确定 ({vr.confidence_score}%)
                        </span>
                      )}
                      {vr?.verification_result === 'false_positive' && (
                        <span style={{
                          display: 'inline-block',
                          padding: '2px 8px',
                          borderRadius: '10px',
                          fontSize: '11px',
                          fontWeight: 600,
                          background: 'var(--success-subtle)',
                          color: 'var(--success)',
                        }}>
                          ✓ 误报 ({vr.confidence_score}%)
                        </span>
                      )}
                      {vr?.is_confirmed === 1 && !vr?.verification_result && (
                        <span style={{
                          display: 'inline-block',
                          padding: '2px 8px',
                          borderRadius: '10px',
                          fontSize: '11px',
                          fontWeight: 600,
                          background: 'var(--success-subtle)',
                          color: 'var(--success)',
                        }}>
                          ✓ AI已确认
                        </span>
                      )}
                      {vr?.is_confirmed === 0 && vr?.confidence !== undefined && !vr?.verification_result && (
                        <span style={{
                          display: 'inline-block',
                          padding: '2px 8px',
                          borderRadius: '10px',
                          fontSize: '11px',
                          fontWeight: 600,
                          background: 'var(--warning-subtle)',
                          color: 'var(--warning)',
                        }}>
                          疑似误报
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '14px', fontWeight: 600, color: 'var(--text-bright)', marginBottom: '4px' }}>
                      {v.name || v.title || v.type || '-'}
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-dim)', lineHeight: '1.5' }}>
                      {v.description || v.detail || '-'}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-dim)', marginTop: '4px' }}>
                      目标: {v.target_url || v.target || '-'}
                    </div>
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '6px', flexShrink: 0 }}>
                    {vr ? (
                      <>
                        <button
                          style={vr.is_vulnerable ? btnDangerStyle : btnVerifiedStyle}
                          onClick={() => setExpandedId(isExpanded ? null : v.vuln_id)}
                        >
                          {vr.is_vulnerable ? `⚠ AI确认 ${vr.confidence}%` : `✓ 可信 ${vr.confidence}%`}
                        </button>
                        <button
                          style={{
                            ...btnStyle,
                            background: 'var(--accent)',
                            color: '#fff',
                            border: 'none',
                          }}
                          onClick={() => handleDeepVerify(v.vuln_id)}
                          disabled={isVerifying}
                        >
                          {isVerifying ? '🔄 验证中...' : '🔍 深度验证'}
                        </button>
                      </>
                    ) : (
                      <button
                        style={btnStyle}
                        onClick={() => handleAiVerify(v.vuln_id)}
                        disabled={isVerifying}
                      >
                        {isVerifying ? '🤖 分析中...' : '🤖 AI验证'}
                      </button>
                    )}
                    {vr && (
                      <button
                        style={{
                          padding: '3px 8px',
                          background: 'transparent',
                          color: 'var(--text-dim)',
                          border: 'none',
                          cursor: 'pointer',
                          fontSize: '11px',
                        }}
                        onClick={() => setExpandedId(isExpanded ? null : v.vuln_id)}
                      >
                        {isExpanded ? '收起详情 ▲' : '展开详情 ▼'}
                      </button>
                    )}
                  </div>
                </div>

                {isExpanded && vr && (
                  <div style={{
                    marginTop: '12px',
                    padding: '12px',
                    background: 'var(--bg-tertiary)',
                    borderRadius: '6px',
                    border: '1px solid var(--border-color)',
                  }}>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '10px' }}>
                      <div>
                        <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '2px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>漏洞类型</div>
                        <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-bright)' }}>{vr.vulnerability_type || '-'}</div>
                      </div>
                      <div>
                        <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '2px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>AI置信度</div>
                        <div style={{
                          fontSize: '13px',
                          fontWeight: 600,
                          color: vr.confidence >= 80 ? 'var(--danger)' : vr.confidence >= 50 ? 'var(--warning)' : 'var(--success)',
                        }}>
                          {vr.confidence}%
                        </div>
                      </div>
                      {vr.cvss_score > 0 && (
                        <div>
                          <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '2px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>CVSS评分</div>
                          <div style={{ fontSize: '13px', fontWeight: 600, color: RISK_COLORS[vr.risk_level] }}>{vr.cvss_score}</div>
                        </div>
                      )}
                      {vr.cve_ids?.length > 0 && (
                        <div>
                          <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '2px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>关联CVE</div>
                          <div style={{ fontSize: '12px', color: 'var(--info)' }}>{vr.cve_ids.join(', ')}</div>
                        </div>
                      )}
                    </div>

                    {vr.verification_result && (
                      <div style={{
                        marginBottom: '10px',
                        padding: '10px',
                        background: vr.verification_result === 'confirmed' ? 'var(--danger-subtle)' :
                                     vr.verification_result === 'false_positive' ? 'var(--success-subtle)' :
                                     vr.verification_result === 'likely' ? 'var(--warning-subtle)' : 'var(--bg-card)',
                        borderRadius: '6px',
                        border: '1px solid var(--border-color)',
                      }}>
                        <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                          深度验证结果
                        </div>
                        <div style={{ fontSize: '13px', fontWeight: 600, marginBottom: '4px', color: 'var(--text-bright)' }}>
                          {vr.verification_result === 'confirmed' && `⚠ 已确认为真实漏洞（置信度: ${vr.confidence_score}%）`}
                          {vr.verification_result === 'likely' && `~ 疑似漏洞（置信度: ${vr.confidence_score}%）`}
                          {vr.verification_result === 'uncertain' && `? 无法确定（置信度: ${vr.confidence_score}%）`}
                          {vr.verification_result === 'false_positive' && `✓ 判定为误报（置信度: ${vr.confidence_score}%）`}
                        </div>
                        {vr.false_positive_reason && (
                          <div style={{ fontSize: '11px', color: 'var(--text-secondary)', marginTop: '4px' }}>
                            原因: {vr.false_positive_reason}
                          </div>
                        )}
                        {vr.verification_evidences?.length > 0 && (
                          <div style={{ marginTop: '8px' }}>
                            <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '4px' }}>验证证据:</div>
                            {vr.verification_evidences.map((e, i) => (
                              <div key={i} style={{
                                fontSize: '11px',
                                color: e.supports_finding ? 'var(--danger)' : 'var(--success)',
                                padding: '3px 0',
                                display: 'flex',
                                alignItems: 'center',
                                gap: '4px',
                              }}>
                                <span>{e.supports_finding ? '⚠' : '✓'}</span>
                                <span>{e.description}</span>
                              </div>
                            ))}
                          </div>
                        )}
                        {vr.recommendations?.length > 0 && (
                          <div style={{ marginTop: '8px' }}>
                            {vr.recommendations.map((r, i) => (
                              <div key={i} style={{ fontSize: '11px', color: 'var(--info)', padding: '2px 0' }}>
                                💡 {r}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )}

                    <div style={{ marginBottom: '8px' }}>
                      <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>证据摘要</div>
                      <div style={{ fontSize: '12px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>{vr.evidence_summary || '-'}</div>
                    </div>

                    {vr.matched_patterns?.length > 0 && (
                      <div style={{ marginBottom: '8px' }}>
                        <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>匹配特征</div>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '4px' }}>
                          {vr.matched_patterns.map((p, i) => (
                            <span key={i} style={{
                              padding: '2px 8px',
                              borderRadius: '10px',
                              fontSize: '11px',
                              background: 'var(--bg-card)',
                              color: 'var(--text-secondary)',
                              border: '1px solid var(--border-color)',
                            }}>
                              {p}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {vr.remediation && (
                      <div>
                        <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>修复建议</div>
                        <div style={{ fontSize: '12px', color: 'var(--success)', lineHeight: '1.5', padding: '8px', background: 'var(--success-subtle)', borderRadius: '4px' }}>
                          {vr.remediation}
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
