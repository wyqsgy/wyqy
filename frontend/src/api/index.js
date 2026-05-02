import axios from 'axios'

const api = axios.create({ baseURL: '/api', timeout: 30000 })

export const createTask = (data) => api.post('/tasks', data)
export const getTasks = (params) => api.get('/tasks', { params })
export const getTask = (taskId) => api.get(`/tasks/${taskId}`)
export const stopTask = (taskId) => api.post(`/tasks/${taskId}/stop`)
export const deleteTask = (taskId) => api.delete(`/tasks/${taskId}`)
export const getCategories = () => api.get('/tasks/categories')

export const getVulnerabilities = (params) => api.get('/vulnerabilities', { params })
export const getVulnerability = (vulnId) => api.get(`/vulnerabilities/${vulnId}`)

export const generateReport = (taskId) => api.post(`/reports/generate/${taskId}`)
export const getReport = (reportId) => api.get(`/reports/${reportId}`)
export const getReportHtml = (reportId) => api.get(`/reports/${reportId}/html`, { responseType: 'text' })
export const listReports = (taskId) => api.get(`/reports/list/${taskId}`)

export default api
