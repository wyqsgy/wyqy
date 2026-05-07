export type TaskStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'

export interface Task {
  id: string
  name: string
  target: string
  status: TaskStatus
  progress: number
  created_at: string
  updated_at: string
  started_at?: string
  completed_at?: string
  vulnerability_count?: number
  scan_type: string
}

export interface TaskCreate {
  name: string
  target: string
  scan_type: string
  options?: Record<string, unknown>
}

export interface TaskLog {
  id: string
  task_id: string
  level: 'info' | 'warning' | 'error' | 'success'
  message: string
  timestamp: string
}
