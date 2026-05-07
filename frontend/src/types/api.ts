export interface ApiResponse<T> {
  data: T
  message?: string
  code?: number
}

export interface ApiError {
  message: string
  code?: number
  details?: Record<string, unknown>
}

export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  page_size: number
}

export interface WebSocketMessage {
  type: string
  payload: unknown
  timestamp: string
}
