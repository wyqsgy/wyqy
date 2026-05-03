import React, { useState } from 'react'
import { enumerateSubdomains, scanPorts, fingerprintTarget } from '../api'

const MODULES = [
  {
    id: 'subdomain',
    name: '子域名枚举',
    icon: '@',
    desc: '被动信息收集 + DNS 爆破 + crt.sh + rapid7 多源枚举',
    params: [{ name: 'domain', label: '目标域名', placeholder: 'example.com' }],
  },
  {
    id: 'port',
    name: '端口扫描',
    icon: '#',
    desc: 'TCP 连接扫描 + 服务 Banner 抓取 + nmap 风格指纹检测',
    params: [
      { name: 'target', label: '目标主机', placeholder: '192.168.1.1' },
      { name: 'ports', label: '端口范围', placeholder: '1-1000' },
    ],
  },
  {
    id: 'fingerprint',
    name: 'Web 指纹识别',
    icon: '~',
    desc: 'Web 技术检测、框架版本、语言识别、中间件、WAF、CDN 识别',
    params: [{ name: 'target', label: '目标地址', placeholder: 'https://target.com' }],
  },
]

export default function Recon() {
  const [activeModule, setActiveModule] = useState(null)
  const [formData, setFormData] = useState({})
  const [loading, setLoading] = useState(false)
  const [terminalLines, setTerminalLines] = useState([])

  const addLine = (text, type = 'output') => {
    setTerminalLines((prev) => [...prev, { text, type, time: new Date().toLocaleTimeString() }])
  }

  const handleRun = async () => {
    if (!activeModule) return
    setLoading(true)
    setTerminalLines([])

    const mod = MODULES.find((m) => m.id === activeModule)
    addLine(`$ wyqyan recon ${activeModule} ${Object.entries(formData).map(([k, v]) => `--${k} ${v}`).join(' ')}`, 'prompt')
    addLine(`正在启动 ${mod.name}...`, 'info')

    try {
      let res
      if (activeModule === 'subdomain') {
        res = await enumerateSubdomains({ domain: formData.domain })
      } else if (activeModule === 'port') {
        res = await scanPorts({ host: formData.target, ports: formData.ports })
      } else if (activeModule === 'fingerprint') {
        res = await fingerprintTarget({ target_url: formData.target })
      }

      const data = res.data?.data || res.data || {}
      addLine(`${mod.name} 执行完成`, 'success')

      if (activeModule === 'subdomain' && data.subdomains?.length) {
        addLine(`发现 ${data.subdomains.length} 个子域名`, 'warning')
        data.subdomains.forEach((s) => addLine(`  ${s.subdomain} -> ${s.ip || '未知'}`, 'output'))
      } else if (activeModule === 'port' && data.open_ports?.length) {
        addLine(`发现 ${data.open_ports.length} 个开放端口`, 'warning')
        data.open_ports.forEach((p) => addLine(`  ${p.port}/${p.proto} ${p.state} ${p.service || ''}`, 'output'))
      } else if (activeModule === 'fingerprint') {
        const fw = (data.framework || []).map((f) => f.name).join(', ') || '未知'
        const lg = (data.language || []).map((l) => l.name).join(', ') || '未知'
        const mw = (data.middleware || []).map((m) => m.name).join(', ') || '未知'
        addLine(`框架     : ${fw}`, 'output')
        addLine(`语言     : ${lg}`, 'output')
        addLine(`中间件   : ${mw}`, 'output')
        if (data.headers) addLine(`服务器   : ${data.headers.server || '未知'}`, 'output')
      } else {
        addLine('未发现结果', 'info')
      }
    } catch (e) {
      addLine(`ERROR: ${e.response?.data?.detail || e.message}`, 'error')
    } finally {
      setLoading(false)
      addLine('$ _', 'prompt')
    }
  }

  return (
    <div>
      <div className="sec-title" style={{ marginBottom: '24px' }}>信息收集</div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
        gap: '12px',
        marginBottom: '24px',
      }}>
        {MODULES.map((mod) => (
          <div
            key={mod.id}
            className="card"
            onClick={() => { setActiveModule(mod.id); setFormData({}); setTerminalLines([]) }}
            style={{
              padding: '16px',
              cursor: 'pointer',
              borderColor: activeModule === mod.id ? 'var(--accent)' : 'var(--border-color)',
              background: activeModule === mod.id ? 'var(--accent-subtle)' : 'var(--bg-card)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-title)', fontSize: '16px', marginRight: '10px' }}>
                [{mod.icon}]
              </span>
              <span style={{ color: 'var(--text-bright)', fontWeight: 600, fontSize: '14px' }}>
                {mod.name}
              </span>
            </div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: '1.5' }}>
              {mod.desc}
            </div>
          </div>
        ))}
      </div>

      {activeModule && (
        <div className="card" style={{ padding: '20px', marginBottom: '24px' }}>
          <div style={{ color: 'var(--text-bright)', fontWeight: 600, fontSize: '14px', marginBottom: '16px' }}>
            {MODULES.find((m) => m.id === activeModule)?.name} 配置
          </div>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'flex-end' }}>
            {MODULES.find((m) => m.id === activeModule)?.params.map((param) => (
              <div key={param.name} style={{ flex: '1', minWidth: '200px' }}>
                <div className="label-text" style={{ marginBottom: '6px', fontSize: '11px' }}>
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
              className="btn btn-accent"
              onClick={handleRun}
              disabled={loading}
              style={{ minWidth: '120px' }}
            >
              {loading ? '执行中...' : '执行'}
            </button>
          </div>
        </div>
      )}

      {terminalLines.length > 0 && (
        <div className="terminal" style={{ maxHeight: '500px', minHeight: '200px' }}>
          {terminalLines.map((line, i) => (
            <div key={i} className={`line ${line.type}`}>
              <span style={{ color: 'var(--text-dim)', marginRight: '8px', fontSize: '11px' }}>
                [{line.time}]
              </span>
              {line.text}
            </div>
          ))}
        </div>
      )}

      {!activeModule && !terminalLines.length && (
        <div className="terminal" style={{ minHeight: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ color: 'var(--text-dim)', fontSize: '14px' }}>
            选择上方侦察模块开始...
          </div>
        </div>
      )}
    </div>
  )
}
