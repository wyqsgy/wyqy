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

export const exportVulnerabilities = (params) => api.get('/export/vulnerabilities', { params })
export const exportTaskReport = (taskId, params) => api.get(`/export/report/${taskId}`, { params })

export const searchCVE = (keyword) => api.get('/cve/search', { params: { keyword } })
export const listCVEs = (params) => api.get('/cve/list', { params })
export const getCVE = (cveId) => api.get(`/cve/${cveId}`)
export const getCVEStats = () => api.get('/cve/stats/summary')

export const detectWAF = (data) => api.post('/attack/waf/detect', data)
export const bypassWAF = (data) => api.post('/attack/waf/bypass', data)
export const scanSSRF = (data) => api.post('/attack/ssrf/scan', data)
export const analyzeJWT = (data) => api.post('/attack/jwt/analyze', data)
export const detectHoneypot = (data) => api.post('/attack/honeypot/detect', data)
export const smartFuzz = (data) => api.post('/attack/fuzz', data)
export const scanDeserialization = (data) => api.post('/attack/deserialization/scan', data)
export const scanPrivesc = () => api.get('/attack/privesc/scan')

export const scanPorts = (data) => api.post('/recon/ports/scan', data)
export const quickPortScan = (host) => api.post(`/recon/ports/quick?host=${host}`)
export const fingerprintTarget = (data) => api.post('/recon/fingerprint', data)
export const enumerateSubdomains = (data) => api.post('/recon/subdomain', data)
export const quickEnumSubdomains = (domain) => api.get(`/recon/subdomain/quick?domain=${domain}`)

export const getPOCs = (params) => api.get('/pocs', { params })
export const getPOCStats = () => api.get('/pocs/stats')
export const createPOC = (data) => api.post('/pocs/custom', data)
export const updatePOC = (id, data) => api.put(`/pocs/custom/${id}`, data)
export const deletePOC = (id) => api.delete(`/pocs/custom/${id}`)
export const togglePOC = (id) => api.post(`/pocs/custom/${id}/toggle`)

export const verifyPacket = (data) => api.post('/verify/packet', data)
export const verifyBatchPackets = (data) => api.post('/verify/batch', data)
export const verifyRawPacket = (data) => api.post('/verify/raw', data)

export const getAIModels = () => api.get('/settings/ai-models')
export const createAIModel = (data) => api.post('/settings/ai-models', data)
export const updateAIModel = (id, data) => api.put(`/settings/ai-models/${id}`, data)
export const deleteAIModel = (id) => api.delete(`/settings/ai-models/${id}`)
export const testAIModel = (id) => api.post(`/settings/ai-models/${id}/test`)
export const getInfoKeys = () => api.get('/settings/info-keys')
export const saveInfoKey = (data) => api.post('/settings/info-keys', data)
export const deleteInfoKey = (id) => api.delete(`/settings/info-keys/${id}`)

export default api
