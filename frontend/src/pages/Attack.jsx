import React, { useState } from 'react'
import { detectWAF, scanDeserialization, scanSSRF, analyzeJWT, smartFuzz, detectHoneypot, scanPrivesc } from '../api'

const ENGINES = [
  {
    id: 'waf',
    name: 'WAF BYPASS',
    icon: '[*]',
    desc: 'WAF detection with 20+ signatures and 25+ evasion techniques',
    params: [{ name: 'target', label: 'TARGET URL', placeholder: 'https://target.com' }],
  },
  {
    id: 'deserial',
    name: 'DESERIALIZATION',
    icon: '[!]',
    desc: 'Java/PHP/Python/.NET deserialization chain detection with 24+ gadget chains',
    params: [{ name: 'target', label: 'TARGET URL', placeholder: 'https://target.com' }],
  },
  {
    id: 'ssrf',
    name: 'SSRF CHAIN',
    icon: '[@]',
    desc: 'Multi-layer SSRF detection with cloud metadata exploitation and protocol chains',
    params: [{ name: 'target', label: 'TARGET URL', placeholder: 'https://target.com' }],
  },
  {
    id: 'jwt',
    name: 'JWT ATTACK',
    icon: '[#]',
    desc: 'Algorithm confusion, key brute-force, header injection, and claim tampering',
    params: [{ name: 'token', label: 'JWT TOKEN', placeholder: 'eyJhbGciOi...' }],
  },
  {
    id: 'fuzz',
    name: 'SMART FUZZ',
    icon: '[~]',
    desc: 'Response diff analysis + WAF adaptive mutation + parameter auto-discovery',
    params: [
      { name: 'target', label: 'TARGET URL', placeholder: 'https://target.com' },
      { name: 'mode', label: 'MODE', type: 'select', options: ['deep', 'quick'] },
    ],
  },
  {
    id: 'honeypot',
    name: 'HONEYPOT DETECT',
    icon: '[?]',
    desc: '30+ honeypot signatures with active deception and latency anomaly detection',
    params: [{ name: 'target', label: 'TARGET URL', placeholder: 'https://target.com' }],
  },
  {
    id: 'privesc',
    name: 'LINUX PRIVESC',
    icon: '[>]',
    desc: 'LinPEAS-style detection with 280+ GTFOBins and 20+ kernel exploit matching',
    params: [],
  },
]

export default function Attack() {
  const [activeEngine, setActiveEngine] = useState(null)
  const [formData, setFormData] = useState({})
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [terminalLines, setTerminalLines] = useState([])

  const addLine = (text, type = 'output') => {
    setTerminalLines((prev) => [...prev, { text, type, time: new Date().toLocaleTimeString() }])
  }

  const handleRun = async () => {
    if (!activeEngine) return
    setLoading(true)
    setResults(null)
    setTerminalLines([])

    const engine = ENGINES.find((e) => e.id === activeEngine)
    addLine(`$ wyqyan attack ${activeEngine} ${Object.entries(formData).map(([k, v]) => `--${k} ${v}`).join(' ')}`, 'prompt')
    addLine(`[INFO] Starting ${engine.name} engine...`, 'info')

    try {
      const apiMap = {
        waf: () => detectWAF({ target: formData.target }),
        deserial: () => scanDeserialization({ target: formData.target }),
        ssrf: () => scanSSRF({ target: formData.target }),
        jwt: () => analyzeJWT({ token: formData.token }),
        fuzz: () => smartFuzz({ target: formData.target, mode: formData.mode || 'deep' }),
        honeypot: () => detectHoneypot({ target: formData.target }),
        privesc: () => scanPrivesc(),
      }
      const apiFn = apiMap[activeEngine]
      if (!apiFn) throw new Error('Unknown engine')
      const res = await apiFn()
      const data = res.data?.data || res.data || {}

      addLine(`[OK] ${engine.name} completed`, 'success')

      if (data.findings?.length) {
        addLine(`[+] Found ${data.findings.length} issue(s)`, 'warning')
        data.findings.forEach((f) => {
          const riskTag = (f.risk_level || f.risk || 'info').toUpperCase()
          addLine(`  [${riskTag}] ${f.type || f.detail || JSON.stringify(f)}`, f.risk_level === 'critical' ? 'error' : 'warning')
        })
      } else if (data.total_findings) {
        addLine(`[+] Found ${data.total_findings} issue(s)`, 'warning')
        if (data.findings) {
          data.findings.forEach((f) => {
            const riskTag = (f.risk_level || f.risk || 'info').toUpperCase()
            addLine(`  [${riskTag}] ${f.type || f.detail || JSON.stringify(f).substring(0, 120)}`, f.risk_level === 'critical' ? 'error' : 'warning')
          })
        }
      } else {
        addLine(`[INFO] No vulnerabilities found`, 'info')
      }

      if (data.stats) {
        addLine(`[STATS] Requests: ${data.stats.requests_sent || 'N/A'} | Duration: ${data.stats.duration || 'N/A'}s`, 'info')
      }

      setResults(data)
    } catch (e) {
      addLine(`[ERROR] ${e.response?.data?.detail || e.message}`, 'error')
    } finally {
      setLoading(false)
      addLine('$ _', 'prompt')
    }
  }

  return (
    <div>
      <div className="pixel-text" style={{
        fontSize: '14px',
        color: 'var(--text-bright)',
        textShadow: '0 0 10px var(--accent-glow)',
        marginBottom: '24px',
      }}>
        // ATTACK ENGINES
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
        gap: '12px',
        marginBottom: '24px',
      }}>
        {ENGINES.map((engine) => (
          <div
            key={engine.id}
            className="pixel-card"
            onClick={() => { setActiveEngine(engine.id); setFormData({}); setResults(null); setTerminalLines([]) }}
            style={{
              padding: '16px',
              cursor: 'pointer',
              borderColor: activeEngine === engine.id ? 'var(--border-glow)' : 'var(--border-color)',
              boxShadow: activeEngine === engine.id ? '0 0 20px var(--shadow-color)' : '0 0 10px var(--shadow-color)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
              <span className="mono-text" style={{ color: 'var(--accent)', fontSize: '16px', marginRight: '8px' }}>
                {engine.icon}
              </span>
              <span className="pixel-text-sm" style={{ color: 'var(--text-bright)' }}>
                {engine.name}
              </span>
            </div>
            <div className="mono-text" style={{ color: 'var(--text-dim)', fontSize: '11px', lineHeight: '1.5' }}>
              {engine.desc}
            </div>
          </div>
        ))}
      </div>

      {activeEngine && (
        <div className="pixel-card" style={{ padding: '20px', marginBottom: '24px' }}>
          <div className="pixel-text-sm" style={{ color: 'var(--text-bright)', marginBottom: '16px' }}>
            [ {ENGINES.find((e) => e.id === activeEngine)?.name} CONFIG ]
          </div>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'flex-end' }}>
            {ENGINES.find((e) => e.id === activeEngine)?.params.map((param) => (
              <div key={param.name} style={{ flex: '1', minWidth: '200px' }}>
                <div className="pixel-text-sm" style={{ color: 'var(--text-dim)', marginBottom: '6px' }}>
                  {param.label}
                </div>
                {param.type === 'select' ? (
                  <select
                    className="pixel-select"
                    value={formData[param.name] || param.options[0]}
                    onChange={(e) => setFormData({ ...formData, [param.name]: e.target.value })}
                    style={{ width: '100%' }}
                  >
                    {param.options.map((o) => (
                      <option key={o} value={o}>{o.toUpperCase()}</option>
                    ))}
                  </select>
                ) : (
                  <input
                    className="pixel-input"
                    placeholder={param.placeholder}
                    value={formData[param.name] || ''}
                    onChange={(e) => setFormData({ ...formData, [param.name]: e.target.value })}
                  />
                )}
              </div>
            ))}
            <button
              className="pixel-btn pixel-btn-accent"
              onClick={handleRun}
              disabled={loading}
              style={{ minWidth: '120px' }}
            >
              {loading ? 'RUNNING...' : '[ EXECUTE ]'}
            </button>
          </div>
        </div>
      )}

      {terminalLines.length > 0 && (
        <div className="pixel-terminal" style={{ maxHeight: '500px', minHeight: '200px' }}>
          {terminalLines.map((line, i) => (
            <div key={i} className={`line ${line.type}`}>
              <span className="mono-text" style={{ color: 'var(--text-dim)', marginRight: '8px', fontSize: '10px' }}>
                [{line.time}]
              </span>
              {line.text}
            </div>
          ))}
        </div>
      )}

      {!activeEngine && !terminalLines.length && (
        <div className="pixel-terminal" style={{ minHeight: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="mono-text" style={{ color: 'var(--text-dim)' }}>
            $ select an attack engine above to begin...
          </div>
        </div>
      )}
    </div>
  )
}
