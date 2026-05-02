import React, { useState, useEffect } from 'react'
import { useParams, Link } from 'react-router-dom'
import { getTask, getVulnerabilities, generateReport } from '../api'

const statusColors = { pending: 'bg-gray-100 text-gray-600', running: 'bg-blue-100 text-blue-700', completed: 'bg-green-100 text-green-700', failed: 'bg-red-100 text-red-700', stopped: 'bg-yellow-100 text-yellow-700' }
const statusLabels = { pending: '等待中', running: '扫描中', completed: '已完成', failed: '失败', stopped: '已停止' }
const riskLabels = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }
const riskBg = { critical: 'bg-red-50 border-red-200', high: 'bg-orange-50 border-orange-200', medium: 'bg-yellow-50 border-yellow-200', low: 'bg-green-50 border-green-200', info: 'bg-blue-50 border-blue-200' }
const riskBadge = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-yellow-500', low: 'bg-green-500', info: 'bg-blue-500' }

export default function TaskDetail() {
  const { taskId } = useParams()
  const [task, setTask] = useState(null)
  const [vulns, setVulns] = useState([])
  const [expanded, setExpanded] = useState(null)
  const [generatingReport, setGeneratingReport] = useState(false)

  useEffect(() => { loadData(); const t = setInterval(loadData, 3000); return () => clearInterval(t) }, [taskId])

  const loadData = async () => {
    try {
      const [taskRes, vulnRes] = await Promise.all([getTask(taskId), getVulnerabilities({ task_id: taskId, limit: 200 })])
      setTask(taskRes.data.data)
      setVulns(vulnRes.data.data.items || [])
    } catch (e) { console.error(e) }
  }

  const handleGenerateReport = async () => {
    setGeneratingReport(true)
    try {
      const res = await generateReport(taskId)
      alert('报告生成成功！报告ID: ' + res.data.data.report_id)
    } catch (e) { alert('报告生成失败') }
    finally { setGeneratingReport(false) }
  }

  if (!task) return <div className="text-center py-12 text-dark-400">加载中...</div>

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-dark-900">任务详情</h1>
          <p className="text-sm text-dark-400 mt-1">{task.task_id}</p>
        </div>
        <div className="flex gap-3">
          <button onClick={handleGenerateReport} disabled={generatingReport || task.status === 'running'}
            className="px-4 py-2 bg-primary-700 text-white rounded-lg text-sm hover:bg-primary-800 disabled:opacity-50">
            {generatingReport ? '生成中...' : '📄 生成报告'}
          </button>
          <Link to="/tasks" className="px-4 py-2 bg-gray-200 text-dark-700 rounded-lg text-sm hover:bg-gray-300">返回列表</Link>
        </div>
      </div>

      <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100 mb-6">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-6">
          <div><div className="text-xs text-dark-400 mb-1">扫描目标</div><div className="font-medium text-dark-900 break-all">{task.target}</div></div>
          <div><div className="text-xs text-dark-400 mb-1">状态</div><span className={`px-2 py-1 rounded text-xs font-medium ${statusColors[task.status]}`}>{statusLabels[task.status]}</span></div>
          <div><div className="text-xs text-dark-400 mb-1">进度</div>
            <div className="flex items-center gap-2"><div className="flex-1 bg-gray-200 rounded-full h-2"><div className="bg-primary-600 h-2 rounded-full" style={{ width: `${task.progress}%` }}></div></div><span className="text-sm">{task.progress}%</span></div>
          </div>
          <div><div className="text-xs text-dark-400 mb-1">漏洞总数</div><div className="text-2xl font-bold text-danger">{task.vuln_count}</div></div>
        </div>
        <div className="grid grid-cols-4 gap-4 mt-4 pt-4 border-t border-gray-100">
          <div className="text-center"><div className="text-lg font-bold text-red-600">{task.critical_count}</div><div className="text-xs text-dark-400">严重</div></div>
          <div className="text-center"><div className="text-lg font-bold text-orange-500">{task.high_count}</div><div className="text-xs text-dark-400">高危</div></div>
          <div className="text-center"><div className="text-lg font-bold text-yellow-500">{task.medium_count}</div><div className="text-xs text-dark-400">中危</div></div>
          <div className="text-center"><div className="text-lg font-bold text-green-600">{task.low_count}</div><div className="text-xs text-dark-400">低危</div></div>
        </div>
      </div>

      <h2 className="text-lg font-semibold text-dark-800 mb-4">漏洞列表 ({vulns.length})</h2>
      <div className="space-y-3">
        {vulns.map((v) => (
          <div key={v.vuln_id} className={`bg-white rounded-lg border ${riskBg[v.risk_level] || 'border-gray-200'} overflow-hidden`}>
            <div className="p-4 cursor-pointer" onClick={() => setExpanded(expanded === v.vuln_id ? null : v.vuln_id)}>
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <span className={`px-2 py-1 rounded text-xs font-bold text-white ${riskBadge[v.risk_level]}`}>{riskLabels[v.risk_level]}</span>
                  <span className="font-medium text-dark-800">{v.name}</span>
                  <span className="text-xs text-dark-400 bg-gray-100 px-2 py-0.5 rounded">{v.category}</span>
                </div>
                <div className="flex items-center gap-3">
                  <span className="text-xs text-dark-400">AI置信度: {v.ai_confidence}%</span>
                  <span className="text-dark-400">{expanded === v.vuln_id ? '▼' : '▶'}</span>
                </div>
              </div>
            </div>
            {expanded === v.vuln_id && (
              <div className="px-4 pb-4 border-t border-gray-100 pt-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
                  <div><span className="font-medium text-dark-600">目标URL:</span><div className="text-dark-800 break-all">{v.target_url}</div></div>
                  <div><span className="font-medium text-dark-600">模块:</span><div className="text-dark-800">{v.module}</div></div>
                  {v.cve_ids?.length > 0 && <div><span className="font-medium text-dark-600">CVE:</span><div className="text-dark-800">{v.cve_ids.join(', ')}</div></div>}
                  {v.detail && <div className="md:col-span-2"><span className="font-medium text-dark-600">详细信息:</span><div className="text-dark-800 bg-gray-50 p-3 rounded mt-1">{v.detail}</div></div>}
                  {v.payload && <div className="md:col-span-2"><span className="font-medium text-dark-600">Payload:</span><pre className="text-xs text-dark-800 bg-gray-900 text-green-400 p-3 rounded mt-1 overflow-x-auto">{v.payload}</pre></div>}
                  {v.evidence && <div className="md:col-span-2"><span className="font-medium text-dark-600">证据:</span><div className="text-dark-800 bg-green-50 p-3 rounded mt-1">{v.evidence}</div></div>}
                  {v.fix_suggestion && <div className="md:col-span-2"><span className="font-medium text-dark-600">修复建议:</span><div className="text-dark-800 bg-blue-50 p-3 rounded mt-1">{v.fix_suggestion}</div></div>}
                </div>
              </div>
            )}
          </div>
        ))}
        {vulns.length === 0 && task.status !== 'running' && (
          <div className="bg-white rounded-lg p-12 text-center text-dark-400 border border-gray-100">未发现漏洞</div>
        )}
      </div>
    </div>
  )
}
