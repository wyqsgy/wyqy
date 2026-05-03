import React, { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getTask, getVulnerabilities, generateReport } from '../api'

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

const STATUS_STYLES = {
  pending: { bg: 'var(--bg-tertiary)', color: 'var(--text-dim)', label: '等待中' },
  running: { bg: 'var(--info-subtle)', color: 'var(--info)', label: '扫描中' },
  completed: { bg: 'var(--success-subtle)', color: 'var(--success)', label: '已完成' },
  failed: { bg: 'var(--danger-subtle)', color: 'var(--danger)', label: '失败' },
  stopped: { bg: 'var(--warning-subtle)', color: 'var(--warning)', label: '已停止' },
}

export default function TaskDetail() {
  const { taskId } = useParams()
  const [task, setTask] = useState(null)
  const [vulns, setVulns] = useState([])
  const [expanded, setExpanded] = useState(null)
  const [generatingReport, setGeneratingReport] = useState(false)

  useEffect(() => {
    loadData()
    const t = setInterval(loadData, 3000)
    return () => clearInterval(t)
  }, [taskId])

  const loadData = async () => {
    try {
      const [taskRes, vulnRes] = await Promise.all([
        getTask(taskId),
        getVulnerabilities({ task_id: taskId, limit: 200 }),
      ])
      setTask(taskRes.data.data)
      setVulns(vulnRes.data.data?.items || [])
    } catch (e) {
      console.error(e)
    }
  }

  const handleGenerateReport = async () => {
    setGeneratingReport(true)
    try {
      const res = await generateReport(taskId)
      alert('报告生成成功！报告ID: ' + res.data.data.report_id)
    } catch (e) {
      alert('报告生成失败')
    } finally {
      setGeneratingReport(false)
    }
  }

  if (!task) {
    return (
      <div className="terminal" style={{ height: '300px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <div style={{ color: 'var(--text-dim)', fontSize: '14px' }}>加载中...</div>
      </div>
    )
  }

  const st = STATUS_STYLES[task.status] || STATUS_STYLES.pending

  return (
    <div>
      <div style={{
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'flex-start',
        marginBottom: '24px',
        flexWrap: 'wrap',
        gap: '12px',
      }}>
        <div>
          <div className="sec-title" style={{ marginBottom: '4px' }}>任务详情</div>
          <div className="mono-text" style={{ color: 'var(--text-dim)', fontSize: '12px' }}>
            {task.task_id}
          </div>
        </div>
        <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
          <button
            onClick={handleGenerateReport}
            disabled={generatingReport || task.status === 'running'}
            className="btn btn-accent"
          >
            {generatingReport ? '生成中...' : '生成报告'}
          </button>
          <Link to="/tasks" className="btn">返回列表</Link>
        </div>
      </div>

      <div className="card" style={{ padding: '24px', marginBottom: '24px' }}>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
          gap: '20px',
          marginBottom: '20px',
        }}>
          <div>
            <div className="label-text" style={{ fontSize: '11px', marginBottom: '6px' }}>扫描目标</div>
            <div className="mono-text" style={{ color: 'var(--text-bright)', fontWeight: 600, wordBreak: 'break-all' }}>
              {task.target}
            </div>
          </div>
          <div>
            <div className="label-text" style={{ fontSize: '11px', marginBottom: '6px' }}>状态</div>
            <span className="pixel-badge" style={{ borderColor: st.color, color: st.color, background: st.bg }}>
              {st.label}
            </span>
          </div>
          <div>
            <div className="label-text" style={{ fontSize: '11px', marginBottom: '6px' }}>进度</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <div className="pixel-progress" style={{ flex: 1, minWidth: '80px' }}>
                <div className="pixel-progress-bar" style={{ width: `${task.progress || 0}%` }} />
              </div>
              <span className="mono-text" style={{ fontSize: '13px', color: 'var(--text-secondary)' }}>
                {task.progress || 0}%
              </span>
            </div>
          </div>
          <div>
            <div className="label-text" style={{ fontSize: '11px', marginBottom: '6px' }}>漏洞总数</div>
            <div className="big-number" style={{ color: 'var(--danger)', fontSize: '28px' }}>
              {task.vuln_count || 0}
            </div>
          </div>
        </div>

        <div className="pixel-divider" />

        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(4, 1fr)',
          gap: '12px',
        }}>
          {[
            { label: '严重', count: task.critical_count || 0, color: 'var(--danger)' },
            { label: '高危', count: task.high_count || 0, color: '#ea580c' },
            { label: '中危', count: task.medium_count || 0, color: 'var(--warning)' },
            { label: '低危', count: task.low_count || 0, color: 'var(--success)' },
          ].map((item) => (
            <div key={item.label} style={{
              textAlign: 'center',
              padding: '12px',
              background: 'var(--bg-tertiary)',
              borderRadius: '8px',
              border: '1px solid var(--border-color)',
            }}>
              <div className="big-number" style={{ color: item.color, fontSize: '24px', marginBottom: '4px' }}>
                {item.count}
              </div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', fontWeight: 600 }}>
                {item.label}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="sec-subtitle" style={{ marginBottom: '16px', fontWeight: 600, color: 'var(--text-bright)', fontSize: '14px' }}>
        漏洞列表 ({vulns.length})
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
        {vulns.map((v) => {
          const isExpanded = expanded === v.vuln_id
          const riskColor = RISK_COLORS[v.risk_level] || 'var(--text-dim)'
          return (
            <div
              key={v.vuln_id}
              className="card"
              style={{
                borderColor: isExpanded ? riskColor : 'var(--border-color)',
                overflow: 'hidden',
              }}
            >
              <div
                onClick={() => setExpanded(isExpanded ? null : v.vuln_id)}
                style={{
                  padding: '14px 16px',
                  cursor: 'pointer',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  flexWrap: 'wrap',
                  gap: '8px',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
                  <span className="badge" style={{
                    background: `${riskColor}20`,
                    color: riskColor,
                  }}>
                    {RISK_LABELS[v.risk_level] || '信息'}
                  </span>
                  <span style={{ fontWeight: 600, color: 'var(--text-bright)', fontSize: '14px' }}>
                    {v.name || v.title || '未知漏洞'}
                  </span>
                  {v.category && (
                    <span style={{
                      fontSize: '11px',
                      color: 'var(--text-dim)',
                      background: 'var(--bg-tertiary)',
                      padding: '2px 8px',
                      borderRadius: '4px',
                    }}>
                      {v.category}
                    </span>
                  )}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  {v.ai_confidence != null && (
                    <span style={{ fontSize: '12px', color: 'var(--text-dim)' }}>
                      AI: {v.ai_confidence}%
                    </span>
                  )}
                  <span style={{ color: 'var(--text-dim)', fontSize: '12px' }}>
                    {isExpanded ? '收起' : '展开'}
                  </span>
                </div>
              </div>

              {isExpanded && (
                <div style={{
                  padding: '0 16px 16px',
                  borderTop: '1px solid var(--border-color)',
                }}>
                  <div style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
                    gap: '12px',
                    paddingTop: '14px',
                    fontSize: '13px',
                  }}>
                    {v.target_url && (
                      <div>
                        <div style={{ color: 'var(--text-dim)', fontSize: '11px', marginBottom: '4px' }}>目标URL</div>
                        <div className="mono-text" style={{ color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                          {v.target_url}
                        </div>
                      </div>
                    )}
                    {v.module && (
                      <div>
                        <div style={{ color: 'var(--text-dim)', fontSize: '11px', marginBottom: '4px' }}>检测模块</div>
                        <div style={{ color: 'var(--accent)', fontWeight: 600 }}>{v.module}</div>
                      </div>
                    )}
                    {v.cve_ids?.length > 0 && (
                      <div>
                        <div style={{ color: 'var(--text-dim)', fontSize: '11px', marginBottom: '4px' }}>CVE 编号</div>
                        <div style={{ color: 'var(--warning)', fontWeight: 600 }}>
                          {v.cve_ids.join(', ')}
                        </div>
                      </div>
                    )}
                  </div>

                  {v.detail && (
                    <div style={{ marginTop: '12px' }}>
                      <div style={{ color: 'var(--text-dim)', fontSize: '11px', marginBottom: '6px' }}>详细信息</div>
                      <div style={{
                        background: 'var(--bg-tertiary)',
                        padding: '12px',
                        borderRadius: '6px',
                        color: 'var(--text-primary)',
                        fontSize: '13px',
                        lineHeight: '1.6',
                        border: '1px solid var(--border-color)',
                      }}>
                        {v.detail}
                      </div>
                    </div>
                  )}

                  {v.payload && (
                    <div style={{ marginTop: '12px' }}>
                      <div style={{ color: 'var(--text-dim)', fontSize: '11px', marginBottom: '6px' }}>Payload</div>
                      <pre style={{
                        background: 'var(--bg-primary)',
                        padding: '12px',
                        borderRadius: '6px',
                        color: 'var(--success)',
                        fontSize: '12px',
                        overflowX: 'auto',
                        border: '1px solid var(--border-color)',
                        fontFamily: 'var(--font-body)',
                        lineHeight: '1.5',
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-all',
                      }}>
                        {v.payload}
                      </pre>
                    </div>
                  )}

                  {v.evidence && (
                    <div style={{ marginTop: '12px' }}>
                      <div style={{ color: 'var(--text-dim)', fontSize: '11px', marginBottom: '6px' }}>证据</div>
                      <div style={{
                        background: 'var(--success-subtle)',
                        padding: '12px',
                        borderRadius: '6px',
                        color: 'var(--text-primary)',
                        fontSize: '13px',
                        lineHeight: '1.6',
                        border: '1px solid var(--border-color)',
                      }}>
                        {v.evidence}
                      </div>
                    </div>
                  )}

                  {v.fix_suggestion && (
                    <div style={{ marginTop: '12px' }}>
                      <div style={{ color: 'var(--text-dim)', fontSize: '11px', marginBottom: '6px' }}>修复建议</div>
                      <div style={{
                        background: 'var(--info-subtle)',
                        padding: '12px',
                        borderRadius: '6px',
                        color: 'var(--text-primary)',
                        fontSize: '13px',
                        lineHeight: '1.6',
                        border: '1px solid var(--border-color)',
                      }}>
                        {v.fix_suggestion}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>
          )
        })}

        {vulns.length === 0 && task.status !== 'running' && (
          <div className="terminal" style={{
            textAlign: 'center',
            padding: '60px 20px',
          }}>
            <div style={{ color: 'var(--text-dim)', fontSize: '14px' }}>
              未发现漏洞
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
