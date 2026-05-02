import React, { useState, useEffect } from 'react'
import { getTasks, listReports, generateReport, getReportHtml } from '../api'

export default function Reports() {
  const [tasks, setTasks] = useState([])
  const [reports, setReports] = useState([])
  const [selectedTask, setSelectedTask] = useState('')
  const [generating, setGenerating] = useState(false)

  useEffect(() => { loadTasks() }, [])

  useEffect(() => { if (selectedTask) loadReports(selectedTask) }, [selectedTask])

  const loadTasks = async () => {
    try {
      const res = await getTasks({ limit: 50, status: 'completed' })
      setTasks(res.data.data.items || [])
    } catch (e) { console.error(e) }
  }

  const loadReports = async (taskId) => {
    try {
      const res = await listReports(taskId)
      setReports(res.data.data.items || [])
    } catch (e) { console.error(e) }
  }

  const handleGenerate = async () => {
    if (!selectedTask) return
    setGenerating(true)
    try {
      await generateReport(selectedTask)
      loadReports(selectedTask)
    } catch (e) { alert('生成失败') }
    finally { setGenerating(false) }
  }

  const handleViewHtml = async (reportId) => {
    try {
      const res = await getReportHtml(reportId)
      const win = window.open('', '_blank')
      win.document.write(res.data)
      win.document.close()
    } catch (e) { alert('获取报告失败') }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-dark-900 mb-6">报告中心</h1>

      <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100 mb-6">
        <div className="flex items-end gap-4">
          <div className="flex-1">
            <label className="block text-sm font-medium text-dark-700 mb-2">选择任务</label>
            <select value={selectedTask} onChange={(e) => setSelectedTask(e.target.value)}
              className="w-full px-3 py-2 border border-gray-300 rounded-lg text-sm">
              <option value="">请选择已完成的扫描任务</option>
              {tasks.map(t => <option key={t.task_id} value={t.task_id}>{t.target} ({t.vuln_count}个漏洞)</option>)}
            </select>
          </div>
          <button onClick={handleGenerate} disabled={!selectedTask || generating}
            className="px-6 py-2 bg-primary-700 text-white rounded-lg text-sm hover:bg-primary-800 disabled:opacity-50">
            {generating ? '生成中...' : '📄 生成报告'}
          </button>
        </div>
      </div>

      <div className="space-y-3">
        {reports.map((r) => (
          <div key={r.report_id} className="bg-white rounded-lg p-4 border border-gray-100 flex items-center justify-between">
            <div>
              <div className="font-medium text-dark-800">{r.title}</div>
              <div className="text-xs text-dark-400 mt-1">共 {r.total_vulns} 个漏洞 | {r.created_at?.slice(0, 19)}</div>
            </div>
            <button onClick={() => handleViewHtml(r.report_id)} className="px-4 py-2 bg-primary-100 text-primary-700 rounded-lg text-sm hover:bg-primary-200">
              查看报告
            </button>
          </div>
        ))}
        {reports.length === 0 && <div className="bg-white rounded-lg p-12 text-center text-dark-400 border border-gray-100">暂无报告</div>}
      </div>
    </div>
  )
}
