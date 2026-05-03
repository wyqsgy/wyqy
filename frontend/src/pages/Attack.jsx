import React, { useState } from 'react'
import { detectWAF, scanDeserialization, scanSSRF, analyzeJWT, smartFuzz, detectHoneypot, scanPrivesc } from '../api'

const ENGINES = [
  {
    id: 'waf',
    name: 'WAF 绕过',
    icon: '*',
    desc: 'WAF 检测 20+ 签名 + 25+ 绕过技术，含编码链、分块传输、参数污染',
    params: [{ name: 'target', label: '目标地址', placeholder: 'https://target.com' }],
  },
  {
    id: 'deserial',
    name: '反序列化检测',
    icon: '!',
    desc: 'Java/PHP/Python/.NET 反序列化链检测，24+ Gadget Chain，支持 Shiro/Fastjson',
    params: [{ name: 'target', label: '目标地址', placeholder: 'https://target.com' }],
  },
  {
    id: 'ssrf',
    name: 'SSRF 链利用',
    icon: '@',
    desc: '多层 SSRF 检测 + 云元数据利用 + gopher 协议链 + DNS Rebinding',
    params: [{ name: 'target', label: '目标地址', placeholder: 'https://target.com' }],
  },
  {
    id: 'jwt',
    name: 'JWT 攻击',
    icon: '#',
    desc: '算法混淆、弱密钥爆破、Header 注入、Claim 篡改、JWK/JKU 注入',
    params: [{ name: 'token', label: 'JWT Token', placeholder: 'eyJhbGciOi...' }],
  },
  {
    id: 'fuzz',
    name: '智能模糊测试',
    icon: '~',
    desc: '响应差异分析 + WAF 自适应变异 + 参数自动发现 + 漏洞精准探测',
    params: [
      { name: 'target', label: '目标地址', placeholder: 'https://target.com' },
      { name: 'mode', label: '扫描模式', type: 'select', options: ['deep', 'quick'] },
    ],
  },
  {
    id: 'honeypot',
    name: '蜜罐识别',
    icon: '?',
    desc: '30+ 蜜罐特征签名 + 主动欺骗检测 + 时延异常分析 + SSL 指纹',
    params: [{ name: 'target', label: '目标地址', placeholder: 'https://target.com' }],
  },
  {
    id: 'privesc',
    name: 'Linux 提权扫描',
    icon: '>',
    desc: 'LinPEAS 风格检测 + 280+ GTFOBins + 20+ 内核漏洞匹配 + SUID/Sudo 扫描',
    params: [],
  },
]

export default function Attack() {
  const [activeEngine, setActiveEngine] = useState(null)
  const [formData, setFormData] = useState({})
  const [loading, setLoading] = useState(false)
  const [terminalLines, setTerminalLines] = useState([])

  const addLine = (text, type = 'output') => {
    setTerminalLines((prev) => [...prev, { text, type, time: new Date().toLocaleTimeString() }])
  }

  const handleRun = async () => {
    if (!activeEngine) return
    setLoading(true)
    setTerminalLines([])

    const engine = ENGINES.find((e) => e.id === activeEngine)
    addLine(`$ wyqyan attack ${activeEngine} ${Object.entries(formData).map(([k, v]) => `--${k} ${v}`).join(' ')}`, 'prompt')
    addLine(`正在启动 ${engine.name} 引擎...`, 'info')

    try {
      const apiMap = {
        waf: () => detectWAF({ target_url: formData.target }),
        deserial: () => scanDeserialization({ target_url: formData.target }),
        ssrf: () => scanSSRF({ target_url: formData.target }),
        jwt: () => analyzeJWT({ token: formData.token }),
        fuzz: () => smartFuzz({ target_url: formData.target, timeout: 10 }),
        honeypot: () => detectHoneypot({ target_url: formData.target }),
        privesc: () => scanPrivesc(),
      }
      const apiFn = apiMap[activeEngine]
      if (!apiFn) throw new Error('Unknown engine')
      const res = await apiFn()
      const data = res.data?.data || res.data || {}

      addLine(`${engine.name} 执行完成`, 'success')

      const findings = data.findings || []
      if (findings.length) {
        addLine(`发现 ${findings.length} 个问题`, 'warning')
        findings.forEach((f) => {
          const risk = (f.risk_level || f.risk || 'info').toUpperCase()
          addLine(`  [${risk}] ${f.type || f.detail || JSON.stringify(f)}`, f.risk_level === 'critical' ? 'error' : 'warning')
        })
      } else if (data.total_findings) {
        addLine(`发现 ${data.total_findings} 个问题`, 'warning')
      } else if (data.is_honeypot !== undefined) {
        if (data.is_honeypot) {
          addLine(`检测到蜜罐: ${data.honeypot_type} (${data.confidence}%)`, 'error')
        } else {
          addLine('未检测到蜜罐', 'success')
        }
      } else if (data.waf_detected !== undefined) {
        if (data.waf_detected) {
          addLine(`检测到 WAF: ${data.waf_name} (${data.confidence}%)`, 'warning')
        } else {
          addLine('未检测到 WAF', 'success')
        }
      } else {
        addLine('未发现漏洞', 'info')
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
      <div className="sec-title" style={{ marginBottom: '24px' }}>攻击引擎</div>

      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
        gap: '12px',
        marginBottom: '24px',
      }}>
        {ENGINES.map((engine) => (
          <div
            key={engine.id}
            className="card"
            onClick={() => { setActiveEngine(engine.id); setFormData({}); setTerminalLines([]) }}
            style={{
              padding: '16px',
              cursor: 'pointer',
              borderColor: activeEngine === engine.id ? 'var(--accent)' : 'var(--border-color)',
              background: activeEngine === engine.id ? 'var(--accent-subtle)' : 'var(--bg-card)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', marginBottom: '8px' }}>
              <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-title)', fontSize: '16px', marginRight: '10px' }}>
                [{engine.icon}]
              </span>
              <span style={{ color: 'var(--text-bright)', fontWeight: 600, fontSize: '14px' }}>
                {engine.name}
              </span>
            </div>
            <div style={{ color: 'var(--text-secondary)', fontSize: '13px', lineHeight: '1.5' }}>
              {engine.desc}
            </div>
          </div>
        ))}
      </div>

      {activeEngine && (
        <div className="card" style={{ padding: '20px', marginBottom: '24px' }}>
          <div style={{ color: 'var(--text-bright)', fontWeight: 600, fontSize: '14px', marginBottom: '16px' }}>
            {ENGINES.find((e) => e.id === activeEngine)?.name} 配置
          </div>
          <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'flex-end' }}>
            {ENGINES.find((e) => e.id === activeEngine)?.params.map((param) => (
              <div key={param.name} style={{ flex: '1', minWidth: '200px' }}>
                <div className="label-text" style={{ marginBottom: '6px', fontSize: '11px' }}>
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

      {!activeEngine && !terminalLines.length && (
        <div className="terminal" style={{ minHeight: '200px', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <div style={{ color: 'var(--text-dim)', fontSize: '14px' }}>
            选择上方攻击引擎开始...
          </div>
        </div>
      )}
    </div>
  )
}
