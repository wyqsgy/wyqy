import React, { useState, useEffect } from 'react'
import { getTasks, getVulnerabilities } from '../api'

const RISK_COLORS = {
  critical: 'var(--danger)',
  high: '#ff6600',
  medium: 'var(--warning)',
  low: 'var(--info)',
  info: 'var(--text-dim)',
}

const RISK_LABELS = {
  critical: 'CRIT',
  high: 'HIGH',
  medium: 'MED',
  low: 'LOW',
  info: 'INFO',
}

export default function Dashboard() {
  const [stats, setStats] = useState({
    totalTasks: 0, totalVulns: 0, riskDist: [], recentTasks: [], vulnsByType: [],
  })
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
      const typeMap = {}
      vulns.forEach((v) => {
        riskMap[v.risk_level] = (riskMap[v.risk_level] || 0) + 1
        typeMap[v.vuln_type] = (typeMap[v.vuln_type] || 0) + 1
      })

      const riskDist = Object.entries(riskMap)
        .sort((a, b) => {
          const order = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }
          return (order[a[0]] || 99) - (order[b[0]] || 99)
        })
        .map(([name, value]) => ({ name, value }))

      const vulnsByType = Object.entries(typeMap)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)

      setStats({
        totalTasks: tasks.length,
        totalVulns: vulns.length,
        riskDist,
        recentTasks: tasks.slice(0, 5),
        vulnsByType,
      })
    } catch (e) {
      console.error('Dashboard load error:', e)
    } finally {
      setLoading(false)
    }
  }

  const statusStyles = {
    pending: { bg: 'var(--bg-tertiary)', color: 'var(--text-dim)', label: 'PEND' },
    running: { bg: 'rgba(0,136,255,0.1)', color: 'var(--info)', label: 'RUN' },
    completed: { bg: 'rgba(0,255,65,0.1)', color: 'var(--success)', label: 'DONE' },
    failed: { bg: 'rgba(255,51,51,0.1)', color: 'var(--danger)', label: 'FAIL' },
    stopped: { bg: 'rgba(255,170,0,0.1)', color: 'var(--warning)', label: 'STOP' },
  }

  if (loading) {
    return (
      <div className="pixel-terminal" style={{ height: '400px' }}>
        <div className="line prompt">$ loading dashboard...</div>
        <div className="line cursor">_</div>
      </div>
    )
  }

  return (
    <div>
      <div className="pixel-text" style={{
        fontSize: '14px',
        color: 'var(--text-bright)',
        textShadow: '0 0 10px var(--accent-glow)',
        marginBottom: '24px',
      }}>
        // DASHBOARD
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
        gap: '16px',
        marginBottom: '24px',
      }}>
        {[
          { label: 'TASKS', value: stats.totalTasks, color: 'var(--accent)' },
          { label: 'VULNS', value: stats.totalVulns, color: 'var(--danger)' },
          { label: 'MODULES', value: '27+', color: 'var(--info)' },
          { label: 'ENGINES', value: '8', color: 'var(--warning)' },
        ].map((item) => (
          <div key={item.label} className="pixel-card" style={{ padding: '20px', textAlign: 'center' }}>
            <div className="pixel-text-sm" style={{ color: 'var(--text-dim)', marginBottom: '8px' }}>
              {item.label}
            </div>
            <div className="vt-text" style={{
              fontSize: '36px',
              color: item.color,
              textShadow: `0 0 15px ${item.color}80`,
            }}>
              {item.value}
            </div>
          </div>
        ))}
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: '1fr 1fr',
        gap: '16px',
        marginBottom: '24px',
      }}>
        <div className="pixel-card" style={{ padding: '20px' }}>
          <div className="pixel-text-sm" style={{ color: 'var(--text-bright)', marginBottom: '16px' }}>
            [ RISK DISTRIBUTION ]
          </div>
          {stats.riskDist.length > 0 ? (
            <div>
              {stats.riskDist.map((item) => {
                const maxVal = Math.max(...stats.riskDist.map((i) => i.value), 1)
                const pct = (item.value / maxVal) * 100
                return (
                  <div key={item.name} style={{ marginBottom: '12px' }}>
                    <div style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      marginBottom: '4px',
                    }}>
                      <span className="pixel-text-sm" style={{ color: RISK_COLORS[item.name] || 'var(--text-dim)' }}>
                        {RISK_LABELS[item.name] || item.name.toUpperCase()}
                      </span>
                      <span className="mono-text" style={{ color: 'var(--text-secondary)', fontSize: '13px' }}>
                        {item.value}
                      </span>
                    </div>
                    <div className="pixel-progress" style={{ height: '12px' }}>
                      <div className="pixel-progress-bar" style={{
                        width: `${pct}%`,
                        background: RISK_COLORS[item.name] || 'var(--accent)',
                        boxShadow: `0 0 8px ${RISK_COLORS[item.name] || 'var(--accent-glow)'}80`,
                      }} />
                    </div>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="mono-text" style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '40px 0' }}>
              NO DATA
            </div>
          )}
        </div>

        <div className="pixel-card" style={{ padding: '20px' }}>
          <div className="pixel-text-sm" style={{ color: 'var(--text-bright)', marginBottom: '16px' }}>
            [ RECENT TASKS ]
          </div>
          {stats.recentTasks.length > 0 ? (
            <div>
              {stats.recentTasks.map((t) => {
                const st = statusStyles[t.status] || statusStyles.pending
                return (
                  <div key={t.task_id} style={{
                    padding: '10px 12px',
                    marginBottom: '6px',
                    background: 'var(--bg-tertiary)',
                    border: '1px solid var(--border-color)',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}>
                    <div>
                      <div className="mono-text" style={{ color: 'var(--text-primary)', fontSize: '13px' }}>
                        {t.target?.substring(0, 40) || 'N/A'}
                      </div>
                      <div className="mono-text" style={{ color: 'var(--text-dim)', fontSize: '11px', marginTop: '2px' }}>
                        vulns: {t.vuln_count || 0}
                      </div>
                    </div>
                    <span className="pixel-badge" style={{
                      borderColor: st.color,
                      color: st.color,
                      background: st.bg,
                    }}>
                      {st.label}
                    </span>
                  </div>
                )
              })}
            </div>
          ) : (
            <div className="mono-text" style={{ color: 'var(--text-dim)', textAlign: 'center', padding: '40px 0' }}>
              NO TASKS
            </div>
          )}
        </div>
      </div>

      <div className="pixel-card" style={{ padding: '20px' }}>
        <div className="pixel-text-sm" style={{ color: 'var(--text-bright)', marginBottom: '16px' }}>
          [ SUPPORTED MODULES ]
        </div>
        <div style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fill, minmax(180px, 1fr))',
          gap: '8px',
        }}>
          {[
            { name: 'Spring Framework', count: 7 },
            { name: 'Apache Shiro', count: 2 },
            { name: 'Log4j2 JNDI', count: 1 },
            { name: 'Fastjson', count: 1 },
            { name: 'Nacos', count: 2 },
            { name: 'Druid', count: 1 },
            { name: 'Tomcat', count: 1 },
            { name: 'Struts2 OGNL', count: 1 },
            { name: 'ThinkPHP', count: 1 },
            { name: 'WebLogic', count: 1 },
            { name: 'Redis', count: 1 },
            { name: 'Confluence', count: 1 },
            { name: 'F5 BIG-IP', count: 1 },
            { name: 'Jenkins', count: 1 },
            { name: 'Apache Flink', count: 1 },
            { name: 'XXL-JOB', count: 1 },
            { name: 'Nginx', count: 1 },
            { name: 'Elasticsearch', count: 1 },
            { name: 'WAF BYPASS', count: 15 },
            { name: 'DESERIALIZATION', count: 22 },
            { name: 'SSRF CHAIN', count: 6 },
            { name: 'JWT ATTACK', count: 8 },
            { name: 'HONEYPOT DETECT', count: 13 },
            { name: 'LINUX PRIVESC', count: 11 },
            { name: 'SMART FUZZ', count: 9 },
            { name: 'FINGERPRINT', count: 27 },
            { name: 'SUBDOMAIN', count: 150 },
            { name: 'PORT SCAN', count: 90 },
          ].map((mod) => (
            <div key={mod.name} style={{
              padding: '10px',
              background: 'var(--bg-tertiary)',
              border: '1px solid var(--border-color)',
              textAlign: 'center',
            }}>
              <div className="pixel-text-sm" style={{ color: 'var(--text-primary)' }}>
                {mod.name}
              </div>
              <div className="mono-text" style={{ color: 'var(--text-dim)', fontSize: '11px', marginTop: '4px' }}>
                {mod.count} checks
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
