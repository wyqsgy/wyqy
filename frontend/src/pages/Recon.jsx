import React, { useState } from 'react'
import { enumerateSubdomains, scanPorts, fingerprintTarget } from '../api'

const RECON_MODULES = [
  {
    id: 'subdomain',
    name: 'SUBDOMAIN',
    icon: '[@]',
    desc: 'Multi-source subdomain enumeration with 150+ DNS servers and brute-force',
    params: [{ name: 'domain', label: 'DOMAIN', placeholder: 'example.com' }],
  },
  {
    id: 'port',
    name: 'PORT SCAN',
    icon: '[#]',
    desc: 'Multi-threaded port scanning with service detection for 90+ common ports',
    params: [{ name: 'target', label: 'TARGET', placeholder: '192.168.1.1' }],
  },
  {
    id: 'fingerprint',
    name: 'FINGERPRINT',
    icon: '[~]',
    desc: 'Web technology fingerprinting with 27+ categories and version detection',
    params: [{ name: 'target', label: 'TARGET URL', placeholder: 'https://target.com' }],
  },
]

export default function Recon() {
  const [activeModule, setActiveModule] = useState(null)
  const [formData, setFormData] = useState({})
  const [results, setResults] = useState(null)
  const [loading, setLoading] = useState(false)
  const [terminalLines, setTerminalLines] = useState([])

  const addLine = (text, type = 'output') => {
    setTerminalLines((prev) => [...prev, { text, type, time: new Date().toLocaleTimeString() }])
  }

  const handleRun = async () => {
    if (!activeModule) return
    setLoading(true)
    setResults(null)
    setTerminalLines([])

    const mod = RECON_MODULES.find((m) => m.id === activeModule)
    addLine(`$ wyqyan recon ${activeModule} ${Object.entries(formData).map(([k, v]) => `--${k} ${v}`).join(' ')}`, 'prompt')
    addLine(`[INFO] Starting ${mod.name} reconnaissance...`, 'info')

    try {
      const apiMap = {
        subdomain: () => enumerateSubdomains({ domain: formData.domain }),
        port: () => scanPorts({ target: formData.target }),
        fingerprint: () => fingerprintTarget({ target: formData.target }),
      }
      const apiFn = apiMap[activeModule]
      if (!apiFn) throw new Error('Unknown module')
      const res = await apiFn()
      const data = res.data?.data || res.data || {}

      addLine(`[OK] ${mod.name} completed`, 'success')

      if (data.subdomains?.length) {
        addLine(`[+] Found ${data.subdomains.length} subdomains`, 'warning')
        data.subdomains.slice(0, 20).forEach((s) => {
          const sub = typeof s === 'string' ? s : s.subdomain || s.domain || JSON.stringify(s)
          addLine(`  ${sub}`, 'output')
        })
        if (data.subdomains.length > 20) {
          addLine(`  ... and ${data.subdomains.length - 20} more`, 'info')
        }
      }

      if (data.ports?.length) {
        addLine(`[+] Found ${data.ports.length} open ports`, 'warning')
        data.ports.slice(0, 20).forEach((p) => {
          const port = typeof p === 'object' ? `${p.port}/${p.protocol || 'tcp'} - ${p.service || 'unknown'}` : p
          addLine(`  ${port}`, 'output')
        })
      }

      if (data.fingerprints?.length) {
        addLine(`[+] Identified ${data.fingerprints.length} technologies`, 'warning')
        data.fingerprints.slice(0, 15).forEach((f) => {
          const fp = typeof f === 'string' ? f : `${f.name || f.tech} ${f.version || ''}`
          addLine(`  ${fp}`, 'output')
        })
      }

      if (data.technologies?.length) {
        addLine(`[+] Identified ${data.technologies.length} technologies`, 'warning')
        data.technologies.slice(0, 15).forEach((t) => {
          const tech = typeof t === 'string' ? t : `${t.name || t.tech} ${t.version || ''}`
          addLine(`  ${tech}`, 'output')
        })
      }

      if (!data.subdomains?.length && !data.ports?.length && !data.fingerprints?.length && !data.technologies?.length) {
        addLine(`[INFO] No results returned`, 'info')
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
        // RECONNAISSANCE
      </div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
        gap: '12px',
        marginBottom: '24px',
      }}>
        {RECON_MODULES.map((mod) => (
          <div
            key={mod.id}
            className="pixel-card"
            onClick={() => { setActiveModule(mod.id); setFormData({}); setResults(null); setTerminalLines([]) }}
            style={{
              padding: '16px',
              cursor: 'pointer',
              borderColor: activeModule === mod.id ? 'var(--border-glow)' : 'var(--border-color)',
              boxShadow: activeModule === mod.id ? '0 0 20px var(--shadow-color)' : '0 0 10px var(--shadow-color)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
              <span className="mono-text" style={{ color: 'var(--accent)', fontSize: '16px', marginRight: '8px' }}>
                {mod.icon}
              </span>
              <span className="pixel-text-sm" style={{ color: 'var(--text-bright)' }}>
                {mod.name}
              </span>
            </div>
            <div className="mono-text" style={{ color: 'var(--text-dim)', fontSize: '11px', lineHeight: '1.5' }}>
              {mod.desc}
            </div>
          </div>
        ))}
      </div>

      {activeModule && (
        <div className="pixel-card" style={{ padding: '20px', marginBottom: '24px' }}>
          <div className="pixel-text-sm" style={{ color: 'var(--text-bright)', marginBottom: '16px' }}>
            [ {RECON_MODULES.find((m) => m.id === activeModule)?.name} CONFIG ]
          </div>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'flex-end' }}>
            {RECON_MODULES.find((m) => m.id === activeModule)?.params.map((param) => (
              <div key={param.name} style={{ flex: '1', minWidth: '200px' }}>
                <div className="pixel-text-sm" style={{ color: 'var(--text-dim)', marginBottom: '6px' }}>
                  {param.label}
                </div>
                <input
                  className="pixel-input"
                  placeholder={param.placeholder}
                  value={formData[param.name] || ''}
                  onChange={(e) => setFormData({ ...formData, [param.name]: e.target.value })}
                />
              </div>
            ))}
            <button
              className="pixel-btn pixel-btn-accent"
              onClick={handleRun}
              disabled={loading}
              style={{ minWidth: '120px' }}
            >
              {loading ? 'SCANNING...' : '[ EXECUTE ]'}
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

      {!activeModule && !terminalLines.length && (
        <div className="pixel-terminal" style={{ minHeight: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div className="mono-text" style={{ color: 'var(--text-dim)' }}>
            $ select a recon module above to begin...
          </div>
        </div>
      )}
    </div>
  )
}
