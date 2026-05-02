import React, { useState } from 'react'
import { detectWAF, bypassWAF, detectHoneypot, smartFuzz, analyzeJWT } from '../api'

const TOOLS = [
  { key: 'waf', label: 'WAF检测与绕过', icon: '🛡️', desc: '识别WAF类型并测试绕过技术' },
  { key: 'honeypot', label: '蜜罐识别', icon: '🍯', desc: '检测目标是否为蜜罐诱捕系统' },
  { key: 'fuzz', label: '智能模糊测试', icon: '💉', desc: 'SQL注入/XSS/SSTI/命令注入等自动化Fuzz' },
  { key: 'jwt', label: 'JWT攻击套件', icon: '🔑', desc: '算法混淆/密钥爆破/kid注入/Claims篡改' },
]

export default function Attack() {
  const [tool, setTool] = useState('waf')
  const [target, setTarget] = useState('')
  const [jwtToken, setJwtToken] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const handleRun = async () => {
    if (tool !== 'jwt' && !target.trim()) return
    if (tool === 'jwt' && !jwtToken.trim()) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      let res
      if (tool === 'waf') {
        res = await detectWAF({ target_url: target })
      } else if (tool === 'honeypot') {
        res = await detectHoneypot({ target_url: target })
      } else if (tool === 'fuzz') {
        res = await smartFuzz({ target_url: target })
      } else if (tool === 'jwt') {
        res = await analyzeJWT({ token: jwtToken })
      }
      setResult(res?.data?.data)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message || '操作失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-800">⚔️ 攻击引擎</h1>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {TOOLS.map(t => (
          <button key={t.key} onClick={() => { setTool(t.key); setResult(null); setError(''); }}
            className={`p-4 rounded-lg text-left transition-all border ${
              tool === t.key ? 'border-primary-500 bg-primary-50 shadow-md' : 'border-gray-200 bg-white hover:border-gray-300'
            }`}>
            <div className="text-2xl mb-1">{t.icon}</div>
            <div className="font-medium text-sm">{t.label}</div>
            <div className="text-xs text-gray-500 mt-1">{t.desc}</div>
          </button>
        ))}
      </div>

      <div className="bg-white rounded-lg shadow p-6 space-y-4">
        {tool === 'jwt' ? (
          <div className="space-y-3">
            <label className="block text-sm font-medium text-gray-700">JWT Token</label>
            <textarea value={jwtToken} onChange={e => setJwtToken(e.target.value)}
              placeholder="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.xxx"
              className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 font-mono text-sm"
              rows={3} />
          </div>
        ) : (
          <input type="text" value={target} onChange={e => setTarget(e.target.value)}
            placeholder="输入目标URL (http://...)"
            className="w-full px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
            onKeyDown={e => e.key === 'Enter' && handleRun()} />
        )}
        <button onClick={handleRun} disabled={loading}
          className="px-6 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 disabled:opacity-50">
          {loading ? '执行中...' : '开始执行'}
        </button>

        {error && <div className="p-3 bg-red-50 text-red-700 rounded-lg">{error}</div>}

        {result && tool === 'waf' && (
          <div className="space-y-3">
            <div className={`p-4 rounded-lg ${result.waf_detected ? 'bg-red-50 border border-red-200' : 'bg-green-50 border border-green-200'}`}>
              <div className="font-semibold">
                {result.waf_detected ? `⚠️ WAF检测到: ${result.waf_name} (置信度: ${result.confidence}%)` : '✅ 未检测到WAF'}
              </div>
              {result.details && <div className="text-sm mt-1 text-gray-600">{result.details}</div>}
            </div>
          </div>
        )}

        {result && tool === 'honeypot' && (
          <div className={`p-4 rounded-lg ${result.is_honeypot ? 'bg-red-50 border border-red-200' : 'bg-green-50 border border-green-200'}`}>
            <div className="font-semibold">
              {result.is_honeypot ? `🍯 蜜罐警告: ${result.honeypot_type} (置信度: ${result.confidence}%)` : '✅ 未检测到蜜罐'}
            </div>
            {result.risk_warning && <div className="text-sm mt-1 text-gray-600">{result.risk_warning}</div>}
            {result.indicators?.length > 0 && (
              <div className="mt-2 space-y-1">
                {result.indicators.map((ind, i) => (
                  <div key={i} className="text-xs text-gray-500">• {ind.detail} (评分: {ind.score})</div>
                ))}
              </div>
            )}
          </div>
        )}

        {result && tool === 'fuzz' && (
          <div>
            <p className="text-sm text-gray-500 mb-3">发现 {result.total_findings} 个问题</p>
            <div className="space-y-2">
              {result.findings?.map((f, i) => (
                <div key={i} className={`p-3 rounded-lg border text-sm ${
                  f.risk_level === 'critical' ? 'bg-red-50 border-red-200' :
                  f.risk_level === 'high' ? 'bg-orange-50 border-orange-200' :
                  'bg-yellow-50 border-yellow-200'
                }`}>
                  <div className="font-semibold">[{f.risk_level?.toUpperCase()}] {f.type}</div>
                  <div className="text-gray-600">{f.detail}</div>
                  {f.payload && <div className="font-mono text-xs mt-1 text-gray-500 break-all">Payload: {f.payload}</div>}
                </div>
              ))}
              {result.total_findings === 0 && <div className="text-green-600">✅ 未发现明显漏洞</div>}
            </div>
          </div>
        )}

        {result && tool === 'jwt' && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="bg-gray-50 rounded-lg p-3">
                <h4 className="text-xs font-semibold text-gray-500 mb-1">Header</h4>
                <pre className="text-xs font-mono">{JSON.stringify(result.header, null, 2)}</pre>
              </div>
              <div className="bg-gray-50 rounded-lg p-3">
                <h4 className="text-xs font-semibold text-gray-500 mb-1">Payload</h4>
                <pre className="text-xs font-mono">{JSON.stringify(result.payload, null, 2)}</pre>
              </div>
            </div>
            <div>
              <span className="text-sm font-medium">算法: </span>
              <span className="px-2 py-0.5 bg-blue-100 text-blue-700 rounded text-xs">{result.algorithm}</span>
            </div>
            {result.vulnerabilities?.length > 0 && (
              <div>
                <h4 className="font-semibold text-sm mb-2">发现的漏洞</h4>
                {result.vulnerabilities.map((v, i) => (
                  <div key={i} className="p-2 bg-red-50 rounded mb-1 text-sm">
                    <span className="font-semibold">[{v.risk}]</span> {v.type}: {v.detail}
                  </div>
                ))}
              </div>
            )}
            {result.attack_results?.length > 0 && (
              <div>
                <h4 className="font-semibold text-sm mb-2">攻击测试结果</h4>
                {result.attack_results.map((a, i) => (
                  <div key={i} className="p-2 bg-gray-50 rounded mb-1 text-xs font-mono">
                    <span className="font-semibold text-red-600">{a.attack}</span>: {a.result || a.risk || ''}
                    {a.forged_token && <div className="break-all mt-1 text-gray-500">Token: {a.forged_token}</div>}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
