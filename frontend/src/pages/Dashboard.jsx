import React, { useState, useEffect } from 'react'
import { getTasks, getVulnerabilities } from '../api'
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

export default function Dashboard() {
  const [stats, setStats] = useState({
    totalTasks: 0, totalVulns: 0, riskDist: [], recentTasks: [],
  })
  const [correlation, setCorrelation] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => { loadData() }, [])

  const loadData = async () => {
    try {
      const [taskRes, vulnRes] = await Promise.all([
        getTasks({ limit: 100 }),
        getVulnerabilities({ limit: 100 }),
      ])
      const tasks = taskRes.data.data?.items || []
      const vulns = vulnRes.data.data?.items || []
      const riskMap = {}
      vulns.forEach((v) => {
        riskMap[v.risk_level] = (riskMap[v.risk_level] || 0) + 1
      })
      const riskDist = Object.entries(riskMap)
        .sort((a, b) => {
          const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
          return (order[a[0]] || 99) - (order[b[0]] || 99)
        })
        .map(([name, value]) => ({ name, value }))
      setStats({
        totalTasks: tasks.length,
        totalVulns: vulns.length,
        riskDist,
        recentTasks: tasks.slice(0, 5),
      })

      const completedTasks = tasks.filter(t => t.status === 'completed')
      if (completedTasks.length > 0) {
        const latestTask = completedTasks[0]
        try {
          const corrRes = await api.get(`/correlation/task/${latestTask.task_id}`)
          if (corrRes.data.data?.chains_found > 0) {
            setCorrelation(corrRes.data.data)
          }
        } catch (e) {
          console.error('关联分析加载失败:', e)
        }
      }
    } catch (e) {
      console.error('仪表盘加载失败:', e)
    } finally {
      setLoading(false)
    }
  }

  const statusStyles = {
    pending: { bg: 'var(--bg-tertiary)', color: 'var(--text-dim)', label: '等待中' },
    running: { bg: 'var(--info-subtle)', color: 'var(--info)', label: '运行中' },
    completed: { bg: 'var(--success-subtle)', color: 'var(--success)', label: '已完成' },
    failed: { bg: 'var(--danger-subtle)', color: 'var(--danger)', label: '失败' },
    stopped: { bg: 'var(--warning-subtle)', color: 'var(--warning)', label: '已停止' },
  }

  if (loading) {
    return (
      <div className="terminal" style={{ height: '300px' }}>
        <div className="line prompt">$ 正在加载仪表盘...</div>
        <div className="line cursor">_</div>
      </div>
    )
  }

  return (
    <div>
      <div className="sec-title" style={{ marginBottom: '24px' }}>仪表盘</div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '16px',
        marginBottom: '24px',
      }}>
        {[
          { label: '扫描任务', value: stats.totalTasks, color: 'var(--accent)' },
          { label: '漏洞总数', value: stats.totalVulns, color: 'var(--danger)' },
          { label: '检测模块', value: '27+', color: 'var(--info)' },
          { label: '攻击引擎', value: '8', color: 'var(--warning)' },
        ].map((item) => (
          <div key={item.label} className="card" style={{ padding: '20px', textAlign: 'center' }}>
            <div className="label-text" style={{ marginBottom: '8px', fontSize: '11px' }}>
              {item.label}
            </div>
            <div className="big-number" style={{ color: item.color }}>
              {item.value}
            </div>
          </div>
        ))}
      </div>

      <div className="dashboard-grid" style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
        gap: '16px',
        marginBottom: '24px',
      }}>
        <div className="card" style={{ padding: '20px' }}>
          <div className="sec-subtitle" style={{ marginBottom: '16px', fontWeight: 600, color: 'var(--text-bright)' }}>
            Risk 分布
          </div>
          {stats.riskDist.length > 0 ? (
            <div>
              {stats.riskDist.map((item) => {
                const maxVal = Math.max(...stats.riskDist.map((i) => i.value), 1)
                const pct = (item.value / maxVal) * 100
                return (
                  <div key={item.name} style={{ marginBottom: '12px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                      <span style={{ fontSize: '13px', fontWeight: 600, color: RISK_COLORS[item.name] || 'var(--text-dim)', textTransform: 'uppercase' }}>
                        {RISK_LABELS[item.name] || item.name}
                      </span>
                      <span className="mono-text" style={{ color: 'var(--text-secondary)' }}>
                        {item.value}
                      </span>
                    </div>
                    <div className="pixel-progress">
                      <div className="pixel-progress-bar" style={{ width: `${pct}%`, background: RISK_COLORS[item.name] || 'var(--accent)' }} />
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="mono-text" style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '40px 0' }}>
              暂无数据
            </div>
          )}
        </div>

        <div className="card" style={{ padding: '20px' }}>
          <div className="sec-subtitle" style={{ marginBottom: '16px', fontWeight: 600, color: 'var(--text-bright)' }}>
            Recent 任务
          </div>
          {stats.recentTasks.length > 0 ? (
            <div>
              {stats.recentTasks.map((t) => {
                const st = statusStyles[t.status] || statusStyles.pending
                return (
                  <div key={t.task_id} style={{
                    padding: '12px',
                    marginBottom: '8px',
                    background: 'var(--bg-tertiary)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '6px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}>
                    <div>
                      <div className="mono-text" style={{ color: 'var(--text-primary)', fontSize: '13px' }}>
                        {t.target?.substring(0, 40) || 'N/A'}
                      </div>
                      <div className="mono-text" style={{ color: 'var(--text-dim)', fontSize: '12px', marginTop: '2px' }}>
                        漏洞数: {t.vuln_count || 0}
                      </div>
                    </div>
                    <span className="pixel-badge" style={{ borderColor: st.color, color: st.color, background: st.bg }}>
                      {st.label}
                    </span>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="mono-text" style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '40px 0' }}>
              暂无任务
            </div>
          )}
        </div>
      </div>

      <div className="card" style={{ padding: '20px' }}>
        <div className="sec-subtitle" style={{ marginBottom: '16px', fontWeight: 600, color: 'var(--text-bright)' }}>
          Supported 支持模块
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(160px, 1fr))', gap: '10px' }}>
          {[
            'Spring 框架', 'Apache Shiro', 'Log4j2 JNDI', 'Fastjson',
            'Nacos', 'Druid', 'Tomcat', 'Struts2 OGNL',
            'ThinkPHP', 'WebLogic', 'Redis', 'Confluence',
            'F5 BIG-IP', 'Jenkins', 'Apache Flink', 'XXL-JOB',
            'Nginx', 'Elasticsearch', 'WAF 绕过', '反序列化',
            'SSRF 链', 'JWT 攻击', '蜜罐识别', 'Linux 提权',
            '智能模糊测试', '指纹识别', '子域名枚举', '端口扫描',
          ].map((mod) => (
            <div key={mod} style={{
              padding: '10px',
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-color)',
              borderRadius: '6px',
              textAlign: 'center',
              fontSize: '12px',
              fontWeight: 600,
              color: 'var(--text-primary)',
            }}>
              {mod}
            </div>
          ))}
        </div>
      </div>

      {correlation && correlation.attack_chains?.length > 0 && (
        <div className="card" style={{ padding: '20px', marginTop: '24px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <div className="sec-subtitle" style={{ fontWeight: 600, color: 'var(--text-bright)' }}>
              ⛓ 攻击链分析 - 发现 {correlation.chains_found} 条组合利用路径
            </div>
            <div style={{ display: 'flex', gap: '8px' }}>
              {correlation.risk_summary?.critical_chains > 0 && (
                <span className="pixel-badge" style={{ borderColor: 'var(--danger)', color: 'var(--danger)', background: 'var(--danger-subtle)' }}>
                  严重: {correlation.risk_summary.critical_chains}
                </span>
              )}
              {correlation.risk_summary?.high_chains > 0 && (
                <span className="pixel-badge" style={{ borderColor: '#ea580c', color: '#ea580c', background: '#ea580c20' }}>
                  高危: {correlation.risk_summary.high_chains}
                </span>
              )}
            </div>
          </div>

          {correlation.recommendations?.length > 0 && (
            <div style={{
              padding: '12px',
              background: 'var(--warning-subtle)',
              border: '1px solid var(--warning)',
              borderRadius: '6px',
              marginBottom: '16px',
            }}>
              {correlation.recommendations.map((r, i) => (
                <div key={i} style={{ fontSize: '12px', color: 'var(--warning)', padding: '2px 0' }}>
                  ⚡ {r}
                </div>
              ))}
            </div>
          )}

          <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {correlation.attack_chains.map((chain) => (
              <div key={chain.chain_id} style={{
                padding: '16px',
                background: 'var(--bg-tertiary)',
                border: `1px solid ${
                  chain.severity === 'critical' ? 'var(--danger)' :
                  chain.severity === 'high' ? '#ea580c' :
                  chain.severity === 'medium' ? 'var(--warning)' : 'var(--border-color)'
                }`,
                borderRadius: '8px',
                borderLeft: `4px solid ${
                  chain.severity === 'critical' ? 'var(--danger)' :
                  chain.severity === 'high' ? '#ea580c' :
                  chain.severity === 'medium' ? 'var(--warning)' : 'var(--info)'
                }`,
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                  <div>
                    <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-bright)', marginBottom: '4px' }}>
                      {chain.name}
                    </div>
                    <div style={{ fontSize: '11px', color: 'var(--text-secondary)', lineHeight: '1.5' }}>
                      {chain.description}
                    </div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px', flexShrink: 0, marginLeft: '12px' }}>
                    <span className="pixel-badge" style={{
                      borderColor: chain.severity === 'critical' ? 'var(--danger)' : chain.severity === 'high' ? '#ea580c' : 'var(--warning)',
                      color: chain.severity === 'critical' ? 'var(--danger)' : chain.severity === 'high' ? '#ea580c' : 'var(--warning)',
                      background: chain.severity === 'critical' ? 'var(--danger-subtle)' : chain.severity === 'high' ? '#ea580c20' : 'var(--warning-subtle)',
                    }}>
                      {chain.severity === 'critical' ? '严重' : chain.severity === 'high' ? '高危' : chain.severity === 'medium' ? '中危' : '低危'}
                    </span>
                    <span style={{ fontSize: '11px', color: 'var(--text-dim)' }}>
                      置信度: {Math.round(chain.confidence * 100)}%
                    </span>
                  </div>
                </div>

                <div style={{ marginBottom: '10px' }}>
                  <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    涉及漏洞节点
                  </div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
                    {chain.nodes.map((node, idx) => (
                      <span key={idx} style={{
                        display: 'inline-flex',
                        alignItems: 'center',
                        gap: '4px',
                        padding: '4px 10px',
                        background: node.role === '核心节点' ? 'var(--danger-subtle)' : 'var(--bg-card)',
                        border: `1px solid ${node.role === '核心节点' ? 'var(--danger)' : 'var(--border-color)'}`,
                        borderRadius: '4px',
                        fontSize: '11px',
                        color: 'var(--text-primary)',
                      }}>
                        <span style={{
                          width: '6px',
                          height: '6px',
                          borderRadius: '50%',
                          background: RISK_COLORS[node.risk_level] || 'var(--text-dim)',
                          display: 'inline-block',
                        }} />
                        {node.vuln_name}
                        <span style={{ fontSize: '9px', color: 'var(--text-dim)' }}>({node.role})</span>
                      </span>
                    ))}
                  </div>
                </div>

                {chain.exploit_path?.length > 0 && (
                  <div style={{ marginBottom: '8px' }}>
                    <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                      攻击路径
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
                      {chain.exploit_path.map((step, idx) => (
                        <div key={idx} style={{
                          fontSize: '11px',
                          color: 'var(--text-secondary)',
                          padding: '4px 8px',
                          background: 'var(--bg-card)',
                          borderRadius: '4px',
                          display: 'flex',
                          alignItems: 'center',
                          gap: '6px',
                        }}>
                          <span style={{ color: 'var(--accent)', fontWeight: 700, flexShrink: 0 }}>▸</span>
                          {step}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                <div style={{
                  padding: '10px',
                  background: 'var(--bg-card)',
                  borderRadius: '6px',
                  border: '1px solid var(--border-color)',
                }}>
                  <div style={{ fontSize: '10px', color: 'var(--text-dim)', marginBottom: '4px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    修复优先级
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-primary)', lineHeight: '1.5' }}>
                    {chain.mitigation_priority}
                  </div>
                </div>

                {chain.attck_techniques?.length > 0 && (
                  <div style={{ marginTop: '8px', display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                    {chain.attck_techniques.map((t) => (
                      <span key={t} style={{
                        fontSize: '10px',
                        padding: '2px 6px',
                        background: 'var(--bg-card)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '3px',
                        color: 'var(--text-dim)',
                        fontFamily: 'monospace',
                      }}>
                        ATT&CK: {t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
