import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../api'
import type { Vulnerability, VulnerabilityCreate } from '../types'

export function useVulnerabilities(params?: Record<string, unknown>) {
  return useQuery({
    queryKey: ['vulnerabilities', params],
    queryFn: async () => {
      const { data } = await api.get<{ vulnerabilities: Vulnerability[]; total: number }>('/vulnerabilities', { params })
      return data
    },
  })
}

export function useVulnerability(vulnId: string) {
  return useQuery({
    queryKey: ['vulnerabilities', vulnId],
    queryFn: async () => {
      const { data } = await api.get<Vulnerability>(`/vulnerabilities/${vulnId}`)
      return data
    },
    enabled: !!vulnId,
  })
}

export function useCreateVulnerability() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (vuln: VulnerabilityCreate) => {
      const { data } = await api.post<Vulnerability>('/vulnerabilities', vuln)
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
    },
  })
}

export function useUpdateVulnerability() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async ({ id, ...vuln }: Vulnerability) => {
      const { data } = await api.patch<Vulnerability>(`/vulnerabilities/${id}`, vuln)
      return data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
    },
  })
}

export function useDeleteVulnerability() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: async (vulnId: string) => {
      await api.delete(`/vulnerabilities/${vulnId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['vulnerabilities'] })
    },
  })
}

export function useExportVulnerabilities() {
  return useMutation({
    mutationFn: async (params: { format: 'json' | 'csv' | 'pdf'; ids?: string[] }) => {
      const { data } = await api.post('/vulnerabilities/export', params, { responseType: 'blob' })
      return data
    },
  })
}
