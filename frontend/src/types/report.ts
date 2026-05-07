export interface Report {
  id: string
  title: string
  task_id?: string
  type: 'summary' | 'detailed' | 'executive'
  format: 'pdf' | 'html' | 'json' | 'markdown'
  created_at: string
  size?: number
  download_url?: string
}

export interface ReportTemplate {
  id: string
  name: string
  type: 'summary' | 'detailed' | 'executive'
  sections: string[]
  variables: string[]
}
