import React, { useState, useEffect } from 'react'
import { getVulnerabilities } from '../api'

const riskLabels = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
const riskBadge = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-green-500', info: 'bg-blue-500' }

export default function Vulnerabilities() {
  const [vulns, setVulns] = useState([])
  const [filter, setFilter] = useState({ category: '', risk_level: '' })
  const [expanded, setExpanded] = useState(null)

  useEffect(() => { loadVulns() }, [filter])

  const loadVulns = async () => {
    try {
      const params = { limit: 200 }
      if (filter.category) params.category = filter.category
      if (filter.risk_level) params.risk_level = filter.risk_level
      const res = await getVulnerabilities(params)
      setVulns(res.data.data.items || [])
    } catch (e) { console.error(e) }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-dark-900 mb-6">漏洞列表</h1>

      <div className="flex gap-3 mb-6">
        <select value={filter.category} onChange={(e) => setFilter({ ...filter, category: e.target.value })}
          className="px-3 py-2 border border-gray-300 rounded-lg text-sm">
          <option value="">全部组件</option>
          {['spring', 'shiro', 'log4j2', 'fastjson', 'nacos', 'druid', 'tomcat', 'struts2'].map(c => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        <select value={filter.risk_level} onChange={(e) => setFilter({ ...filter, risk_level: e.target.value })}
          className="px-3 py-2 border border-gray-300 rounded-lg text-sm">
          <option value="">全部等级</option>
          {['critical', 'high', 'medium', 'low', 'info'].map(r => (
            <option key={r} value={r}>{riskLabels[r]}</option>
          ))}
        </select>
      </div>

      <div className="space-y-3">
        {vulns.map((v) => (
          <div key={v.vuln_id} className="bg-white rounded-lg border border-gray-200 overflow-hidden">
            <div className="p-4 cursor-pointer" onClick={() => setExpanded(expanded === v.vuln_id ? null : v.vuln_id)}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-1 rounded text-xs font-bold text-white ${riskBadge[v.risk_level]}`}>{riskLabels[v.risk_level]}</span>
                  <span className="font-medium text-dark-800">{v.name}</span>
                  <span className="text-xs bg-gray-100 px-2 py-0.5 rounded text-dark-500">{v.category}</span>
                </div>
                <div className="flex items-center gap-3 text-xs text-dark-400">
                  <span>AI: {v.ai_confidence}%</span>
                  <span>{expanded === v.vuln_id ? '▼' : '▶'}</span>
                </div>
              </div>
            </div>
            {expanded === v.vuln_id && (
              <div className="px-4 pb-4 border-t border-gray-100 pt-3 text-sm">
                {v.detail && <div className="mb-3"><span className="font-medium text-dark-600">详情:</span><div className="mt-1 bg-gray-50 p-3 rounded">{v.detail}</div></div>}
                {v.payload && <div className="mb-3"><span className="font-medium text-dark-600">Payload:</span><pre className="mt-1 bg-gray-900 text-green-400 p-3 rounded text-xs overflow-x-auto">{v.payload}</pre></div>}
                {v.fix_suggestion && <div className="mb-3"><span className="font-medium text-dark-600">修复建议:</span><div className="mt-1 bg-blue-50 p-3 rounded">{v.fix_suggestion}</div></div>}
                {v.cve_ids?.length > 0 && <div><span className="font-medium text-dark-600">CVE: </span>{v.cve_ids.join(', ')}</div>}
              </div>
            )}
          </div>
        ))}
        {vulns.length === 0 && <div className="bg-white rounded-lg p-12 text-center text-dark-400 border border-gray-100">暂无漏洞数据</div>}
      </div>
    </div>
  )
}
