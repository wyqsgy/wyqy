import React from 'react'
import { Link } from 'react-router-dom'
import { useTasks } from '../hooks/useTasks'
import RiskBadge from '../components/ui/RiskBadge'
import ScanProgress from '../components/ui/ScanProgress'

export default function Tasks() {
  const { data, isLoading } = useTasks()

  if (isLoading) {
    return <div className="text-center py-12">Loading...</div>
  }

  const tasks = data?.tasks || []

  return (
    <div className="space-y-6 page-enter">
      <div className="flex items-center justify-between">
        <h1 className="sec-title text-2xl">Tasks</h1>
        <Link to="/tasks/new" className="btn btn-accent">+ New Task</Link>
      </div>

      <div className="card overflow-hidden">
        <table className="pixel-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Target</th>
              <th>Status</th>
              <th>Progress</th>
              <th>Created</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {tasks.map((task) => (
              <tr key={task.id}>
                <td data-label="Name">{task.name}</td>
                <td data-label="Target">{task.target}</td>
                <td data-label="Status">
                  <RiskBadge level={task.status === 'failed' ? 'high' : task.status === 'completed' ? 'low' : 'medium'} />
                </td>
                <td data-label="Progress">
                  <ScanProgress progress={task.progress} size="sm" showPercentage={false} />
                </td>
                <td data-label="Created">{new Date(task.created_at).toLocaleDateString()}</td>
                <td data-label="Actions">
                  <div className="flex gap-2">
                    <Link to={`/tasks/${task.id}`} className="btn text-xs py-1 px-2">View</Link>
                  </div>
                </td>
              </tr>
            ))}
            {tasks.length === 0 && (
              <tr>
                <td colSpan={6} className="text-center text-[var(--text-dim)]">No tasks found</td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
