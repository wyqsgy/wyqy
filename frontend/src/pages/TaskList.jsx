import React, { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { getTasks, deleteTask, stopTask } from '../api'

const statusColors = { pending: 'bg-gray-100 text-gray-600', running: 'bg-blue-100 text-blue-700', completed: 'bg-green-100 text-green-700', failed: 'bg-red-100 text-red-700', stopped: 'bg-yellow-100 text-yellow-700' }
const statusLabels = { pending: '等待中', running: '扫描中', completed: '已完成', failed: '失败', stopped: '已停止' }
const riskColors = { critical: 'text-red-600', high: 'text-orange-500', medium: 'text-yellow-500', low: 'text-green-600' }

export default function TaskList() {
  const [tasks, setTasks] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => { loadTasks(); const t = setInterval(loadTasks, 5000); return () => clearInterval(t) }, [])

  const loadTasks = async () => {
    try {
      const res = await getTasks({ limit: 50 })
      setTasks(res.data.data.items || [])
    } catch (e) { console.error(e) }
    finally { setLoading(false) }
  }

  const handleStop = async (taskId) => {
    if (!confirm('确认停止该扫描任务？')) return
    await stopTask(taskId)
    loadTasks()
  }

  const handleDelete = async (taskId) => {
    if (!confirm('确认删除该扫描任务？')) return
    await deleteTask(taskId)
    loadTasks()
  }

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-2xl font-bold text-dark-900">扫描任务</h1>
        <Link to="/tasks/new" className="px-4 py-2 bg-primary-700 text-white rounded-lg text-sm hover:bg-primary-800">➕ 新建扫描</Link>
      </div>

      <div className="bg-white rounded-xl shadow-sm border border-gray-100 overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="bg-gray-50 border-b border-gray-100">
              <th className="px-4 py-3 text-left text-xs font-medium text-dark-500 uppercase">目标</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-dark-500 uppercase">状态</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-dark-500 uppercase">进度</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-dark-500 uppercase">漏洞</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-dark-500 uppercase">时间</th>
              <th className="px-4 py-3 text-left text-xs font-medium text-dark-500 uppercase">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-100">
            {tasks.map((t) => (
              <tr key={t.task_id} className="hover:bg-gray-50">
                <td className="px-4 py-3">
                  <Link to={`/tasks/${t.task_id}`} className="text-sm font-medium text-primary-700 hover:underline">{t.target}</Link>
                </td>
                <td className="px-4 py-3">
                  <span className={`px-2 py-1 rounded text-xs font-medium ${statusColors[t.status] || ''}`}>{statusLabels[t.status] || t.status}</span>
                </td>
                <td className="px-4 py-3">
                  <div className="w-24 bg-gray-200 rounded-full h-2">
                    <div className="bg-primary-600 h-2 rounded-full transition-all" style={{ width: `${t.progress}%` }}></div>
                  </div>
                  <span className="text-xs text-dark-400">{t.progress}%</span>
                </td>
                <td className="px-4 py-3">
                  <div className="flex gap-2 text-xs">
                    {t.critical_count > 0 && <span className={riskColors.critical}>严重:{t.critical_count}</span>}
                    {t.high_count > 0 && <span className={riskColors.high}>高:{t.high_count}</span>}
                    {t.medium_count > 0 && <span className={riskColors.medium}>中:{t.medium_count}</span>}
                    {t.low_count > 0 && <span className={riskColors.low}>低:{t.low_count}</span>}
                    {t.vuln_count === 0 && <span className="text-dark-400">0</span>}
                  </div>
                </td>
                <td className="px-4 py-3 text-xs text-dark-400">{t.created_at?.slice(0, 19)}</td>
                <td className="px-4 py-3">
                  <div className="flex gap-2">
                    {t.status === 'running' && (
                      <button onClick={() => handleStop(t.task_id)} className="text-xs text-yellow-600 hover:underline">停止</button>
                    )}
                    <button onClick={() => handleDelete(t.task_id)} className="text-xs text-red-600 hover:underline">删除</button>
                  </div>
                </td>
              </tr>
            ))}
            {tasks.length === 0 && !loading && (
              <tr><td colSpan={6} className="px-4 py-12 text-center text-dark-400">暂无扫描任务</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
