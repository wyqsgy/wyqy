import React, { useState } from 'react'
import { fingerprintTarget, quickPortScan, enumerateSubdomains } from '../api'

const TABS = [
  { key: 'fingerprint', label: '资产指纹', icon: '🔍' },
  { key: 'ports', label: '端口扫描', icon: '🔌' },
  { key: 'subdomain', label: '子域名枚举', icon: '🌐' },
]

export default function Recon() {
  const [tab, setTab] = useState('fingerprint')
  const [target, setTarget] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [error, setError] = useState('')

  const handleScan = async () => {
    if (!target.trim()) return
    setLoading(true)
    setError('')
    setResult(null)
    try {
      let res
      if (tab === 'fingerprint') {
        res = await fingerprintTarget({ target_url: target })
      } else if (tab === 'ports') {
        res = await quickPortScan(target)
      } else if (tab === 'subdomain') {
        res = await enumerateSubdomains({ domain: target })
      }
      setResult(res?.data?.data)
    } catch (e) {
      setError(e?.response?.data?.detail || e.message || '扫描失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-6">
      <h1 className="text-2xl font-bold text-gray-800">🔭 信息收集</h1>
      <div className="flex space-x-2 border-b pb-2">
        {TABS.map(t => (
          <button key={t.key} onClick={() => { setTab(t.key); setResult(null); setError(''); }}
            className={`px-4 py-2 rounded-t-lg text-sm font-medium transition-all ${
              tab === t.key ? 'bg-primary-600 text-white' : 'bg-gray-100 text-gray-600 hover:bg-gray-200'
            }`}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      <div className="bg-white rounded-lg shadow p-6 space-y-4">
        <div className="flex space-x-3">
          <input
            type="text" value={target} onChange={e => setTarget(e.target.value)}
            placeholder={tab === 'ports' ? '输入IP或域名' : tab === 'subdomain' ? '输入域名 (example.com)' : '输入目标URL (http://...)'}
            className="flex-1 px-4 py-2 border rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500"
            onKeyDown={e => e.key === 'Enter' && handleScan()}
          />
          <button onClick={handleScan} disabled={loading || !target.trim()}
            className="px-6 py-2 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50">
            {loading ? '扫描中...' : '开始扫描'}
          </button>
        </div>

        {error && <div className="p-3 bg-red-50 text-red-700 rounded-lg">{error}</div>}

        {result && tab === 'fingerprint' && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <InfoCard title="Web框架" items={result.framework?.map(f => f.name)} color="blue" />
              <InfoCard title="开发语言" items={result.language?.map(l => l.name)} color="green" />
              <InfoCard title="中间件" items={result.middleware?.map(m => m.name)} color="purple" />
              <InfoCard title="操作系统" items={result.os ? [result.os] : []} color="orange" />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <InfoCard title="CDN" items={result.cdn?.map(c => c.name)} color="cyan" />
              <InfoCard title="WAF" items={result.waf?.map(w => w.name)} color="red" />
            </div>
            {result.security_headers && (
              <div className="bg-gray-50 rounded-lg p-4">
                <h3 className="font-semibold mb-2">安全头检测</h3>
                <div className="grid grid-cols-2 gap-2 text-sm">
                  {Object.entries(result.security_headers).map(([k, v]) => (
                    <div key={k} className="flex items-center space-x-2">
                      <span className={v.present ? 'text-green-600' : 'text-red-500'}>
                        {v.present ? '✅' : '❌'}
                      </span>
                      <span>{v.name}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {result.technologies?.length > 0 && (
              <div className="bg-gray-50 rounded-lg p-4">
                <h3 className="font-semibold mb-2">前端技术</h3>
                <div className="flex flex-wrap gap-2">
                  {result.technologies.map((t, i) => (
                    <span key={i} className="px-2 py-1 bg-blue-100 text-blue-700 rounded text-xs">
                      {t.name}{t.version ? ` v${t.version}` : ''}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {result && tab === 'ports' && (
          <div>
            <p className="mb-2 text-sm text-gray-500">发现 {result.open_ports} 个开放端口</p>
            <div className="overflow-x-auto">
              <table className="min-w-full text-sm">
                <thead className="bg-gray-50">
                  <tr>
                    <th className="px-4 py-2 text-left">端口</th>
                    <th className="px-4 py-2 text-left">服务</th>
                    <th className="px-4 py-2 text-left">Banner</th>
                  </tr>
                </thead>
                <tbody>
                  {result.ports?.map((p, i) => (
                    <tr key={i} className="border-t">
                      <td className="px-4 py-2 font-mono">{p.port}</td>
                      <td className="px-4 py-2">{p.service}{p.is_web ? ' 🌐' : ''}</td>
                      <td className="px-4 py-2 font-mono text-xs text-gray-500 max-w-md truncate">{p.banner || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {result && tab === 'subdomain' && (
          <div>
            <p className="mb-2 text-sm text-gray-500">
              发现 {result.total_found} 个子域名, {result.unique_ips} 个独立IP (耗时 {result.elapsed_seconds}s)
            </p>
            <div className="space-y-1">
              {result.subdomains?.map((s, i) => (
                <div key={i} className="flex items-center space-x-3 text-sm py-1 border-b border-gray-100">
                  <span className="font-mono text-blue-700 w-64">{s.subdomain}</span>
                  <span className="text-gray-500 font-mono">{s.ip}</span>
                  {s.is_cdn && <span className="text-xs px-2 py-0.5 bg-yellow-100 text-yellow-700 rounded">CDN</span>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function InfoCard({ title, items, color }) {
  const colorMap = {
    blue: 'bg-blue-50 border-blue-200 text-blue-700',
    green: 'bg-green-50 border-green-200 text-green-700',
    purple: 'bg-purple-50 border-purple-200 text-purple-700',
    orange: 'bg-orange-50 border-orange-200 text-orange-700',
    red: 'bg-red-50 border-red-200 text-red-700',
    cyan: 'bg-cyan-50 border-cyan-200 text-cyan-700',
  }
  return (
    <div className={`rounded-lg border p-3 ${colorMap[color] || 'bg-gray-50 border-gray-200'}`}>
      <div className="text-xs font-semibold opacity-70 mb-1">{title}</div>
      <div className="text-sm font-medium">
        {items?.length > 0 ? items.join(', ') : '-'}
      </div>
    </div>
  )
}
