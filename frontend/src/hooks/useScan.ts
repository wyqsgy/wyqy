import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../api'
import type { Scan, ScanModule } from '../types'

export function useScanModules() {
  return useQuery({
    queryKey: ['scan', 'modules'],
    queryFn: async () => {
      const { data } = await api.get<ScanModule[]>('/scans/modules')
      return data
    },
  })
}

export function useScan(scanId: string) {
  const [logs, setLogs] = useState<string[]>([])

  const query = useQuery({
    queryKey: ['scans', scanId],
    queryFn: async () => {
      const { data } = await api.get<Scan>(`/scans/${scanId}`)
      return data
    },
    enabled: !!scanId,
    refetchInterval: (query) => {
      return query.state.data?.status === 'running' ? 2000 : false
    },
  })

  const addLog = useCallback((log: string) => {
    setLogs((prev) => [...prev.slice(-499), `[${new Date().toISOString()}] ${log}`])
  }, [])

  return { ...query, logs, addLog }
}

export function useStartScan() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (params: { target: string; modules: string[]; options?: Record<string, unknown> }) => {
      const { data } = await api.post<Scan>('/scans/start', params)
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })
}

export function useStopScan() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (scanId: string) => {
      await api.post(`/scans/${scanId}/stop`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['scans'] })
    },
  })
}
