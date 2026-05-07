export type ScanType = 'full' | 'quick' | 'custom' | 'recon' | 'deep'

export interface Scan {
  id: string
  task_id: string
  type: ScanType
  status: 'running' | 'completed' | 'failed'
  progress: number
  modules: string[]
  started_at: string
  completed_at?: string
  results?: ScanResult
}

export interface ScanResult {
  vulnerabilities_found: number
  ports_open: number
  services_identified: number
  endpoints_discovered: number
}

export interface ScanModule {
  name: string
  description: string
  enabled: boolean
  risk_level?: string
}
