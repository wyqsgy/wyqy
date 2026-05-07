export * from './task'
export * from './vulnerability'
export * from './scan'
export * from './report'
export * from './api'

export interface PaginationParams {
  page?: number
  page_size?: number
  sort_by?: string
  sort_order?: 'asc' | 'desc'
}

export interface FilterParams extends PaginationParams {
  status?: string
  risk_level?: string
  search?: string
  date_from?: string
  date_to?: string
}
