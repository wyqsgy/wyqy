import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../api'
import type { Task, TaskCreate, TaskLog } from '../types'

export function useTasks(params?: Record<string, unknown>) {
  return useQuery({
    queryKey: ['tasks', params],
    queryFn: async () => {
      const { data } = await api.get<{ tasks: Task[]; total: number }>('/tasks', { params })
      return data
    },
  })
}

export function useTask(taskId: string) {
  return useQuery({
    queryKey: ['tasks', taskId],
    queryFn: async () => {
      const { data } = await api.get<Task>(`/tasks/${taskId}`)
      return data
    },
    enabled: !!taskId,
  })
}

export function useTaskLogs(taskId: string) {
  return useQuery({
    queryKey: ['tasks', taskId, 'logs'],
    queryFn: async () => {
      const { data } = await api.get<TaskLog[]>(`/tasks/${taskId}/logs`)
      return data
    },
    enabled: !!taskId,
    refetchInterval: 5000,
  })
}

export function useCreateTask() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (task: TaskCreate) => {
      const { data } = await api.post<Task>('/tasks', task)
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
  })
}

export function useDeleteTask() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (taskId: string) => {
      await api.delete(`/tasks/${taskId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
  })
}

export function useCancelTask() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (taskId: string) => {
      await api.post(`/tasks/${taskId}/cancel`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
  })
}
