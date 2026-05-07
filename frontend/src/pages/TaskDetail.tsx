import React from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useTask, useTaskLogs, useCancelTask, useDeleteTask } from '../hooks/useTasks'
import { useToast } from '../contexts/ToastContext'
import TerminalOutput from '../components/ui/TerminalOutput'
import ScanProgress from '../components/ui/ScanProgress'
import RiskBadge from '../components/ui/RiskBadge'

export default function TaskDetail() {
  const { taskId } = useParams<{ taskId: string }>()
  const navigate = useNavigate()
  const { data: task, isLoading } = useTask(taskId || '')
  const { data: logs = [] } = useTaskLogs(taskId || '')
  const cancelTask = useCancelTask()
  const deleteTask = useDeleteTask()
  const { addToast } = useToast()

  const handleCancel = async () => {
    if (!taskId) return
    try {
      await cancelTask.mutateAsync(taskId)
      addToast({ type: 'success', message: 'Task cancelled' })
    } catch {
      addToast({ type: 'error', message: 'Failed to cancel task' })
    }
  }

  const handleDelete = async () => {
    if (!taskId) return
    try {
      await deleteTask.mutateAsync(taskId)
      addToast({ type: 'success', message: 'Task deleted' })
      navigate('/tasks')
    } catch {
      addToast({ type: 'error', message: 'Failed to delete task' })
    }
  }

  if (isLoading) {
    return <div className="text-center py-12">Loading...</div>
  }

  if (!task) {
    return <div className="text-center py-12">Task not found</div>
  }

  return (
    <div className="space-y-6 page-enter">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="sec-title text-2xl">{task.name}</h1>
          <p className="text-sm text-[var(--text-secondary)] mt-1">{task.target}</p>
        </div>
        <div className="flex gap-2">
          {task.status === 'running' && (
            <button onClick={handleCancel} className="btn btn-danger" disabled={cancelTask.isPending}>
              Cancel
            </button>
          )}
          <button onClick={handleDelete} className="btn" disabled={deleteTask.isPending}>
            Delete
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="card p-4">
          <div className="label-text mb-2">Status</div>
          <RiskBadge level={task.status === 'failed' ? 'high' : task.status === 'completed' ? 'low' : 'medium'} />
        </div>
        <div className="card p-4">
          <div className="label-text mb-2">Progress</div>
          <ScanProgress progress={task.progress} />
        </div>
        <div className="card p-4">
          <div className="label-text mb-2">Vulnerabilities</div>
          <span className="big-number text-[var(--danger)]">{task.vulnerability_count || 0}</span>
        </div>
      </div>

      <div className="card p-4">
        <div className="label-text mb-4">Task Logs</div>
        <TerminalOutput
          lines={logs.map((log) => `[${log.level}] ${log.message}`)}
          className="h-64"
        />
      </div>
    </div>
  )
}
