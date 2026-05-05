import React, { createContext, useContext, useState, useCallback, useEffect } from 'react'

const I18nContext = createContext(null)

const LANG_KEY = 'wyqyan-lang'

const messages = {
  'zh-CN': {
    app: { name: 'WyqYan', subtitle: '漏洞扫描平台', version: 'v2.0.0' },
    nav: {
      dashboard: '仪表盘',
      tasks: '扫描任务',
      newTask: '新建扫描',
      vulnerabilities: '漏洞列表',
      reports: '扫描报告',
      recon: '信息收集',
      attack: '攻击引擎',
      pocManagement: 'POC管理',
      aiVerify: 'AI验证',
      settings: '系统设置',
    },
    common: {
      loading: '加载中...',
      save: '保存',
      cancel: '取消',
      delete: '删除',
      confirm: '确认',
      retry: '重试',
      search: '搜索',
      filter: '筛选',
      all: '全部',
      none: '无',
      back: '返回',
      close: '关闭',
      open: '打开',
      submit: '提交',
      reset: '重置',
      export: '导出',
      import: '导入',
      refresh: '刷新',
      copy: '复制',
      copied: '已复制',
      more: '更多',
      actions: '操作',
      status: '状态',
      type: '类型',
      target: '目标',
      created: '创建时间',
      updated: '更新时间',
      description: '描述',
      detail: '详情',
      result: '结果',
      error: '错误',
      success: '成功',
      warning: '警告',
      info: '信息',
      yes: '是',
      no: '否',
      enabled: '已启用',
      disabled: '已禁用',
    },
    risk: {
      critical: '严重',
      high: '高危',
      medium: '中危',
      low: '低危',
      info: '信息',
    },
    task: {
      pending: '等待中',
      running: '运行中',
      completed: '已完成',
      failed: '失败',
      stopped: '已停止',
      createTask: '创建扫描任务',
      targetUrl: '目标URL',
      targetUrlPlaceholder: 'https://example.com',
      scanType: '扫描类型',
      fullScan: '全面扫描',
      quickScan: '快速扫描',
      customScan: '自定义扫描',
      selectModules: '选择模块',
      startScan: '开始扫描',
      stopScan: '停止扫描',
      noTasks: '暂无扫描任务',
      createFirst: '创建第一个任务',
      vulnCount: '漏洞数量',
      progress: '扫描进度',
    },
    vuln: {
      title: '漏洞列表',
      subtitle: '点击 AI验证 按钮对漏洞进行智能分析确认',
      noVulns: '暂无漏洞',
      noFilteredVulns: '当前筛选条件下无漏洞',
      aiVerify: 'AI验证',
      verifying: '验证中...',
      aiConfirmed: 'AI已确认',
      suspectedFP: '疑似误报',
      expandDetail: '展开详情',
      collapseDetail: '收起详情',
      evidence: '验证证据',
      matchedPatterns: '匹配特征',
      remediation: '修复建议',
      cvssScore: 'CVSS评分',
      confidence: '置信度',
      cveRefs: 'CVE参考',
    },
    settings: {
      title: '系统设置',
      aiModels: 'AI模型管理',
      addModel: '添加模型',
      modelName: '模型名称',
      provider: '服务商',
      apiKey: 'API密钥',
      apiEndpoint: 'API端点',
      modelId: '模型ID',
      testConnection: '测试连接',
      infoKeys: '信息收集密钥',
      addKey: '添加密钥',
      platform: '平台',
      keyValue: '密钥值',
      keyStatus: '状态',
    },
    poc: {
      title: 'POC管理',
      addPoc: '添加POC',
      editPoc: '编辑POC',
      pocName: 'POC名称',
      pocCategory: '分类',
      pocRisk: '风险等级',
      pocContent: 'POC内容',
      importPoc: '导入POC',
      exportPoc: '导出POC',
      testPoc: '测试POC',
    },
    report: {
      title: '扫描报告',
      generate: '生成报告',
      download: '下载报告',
      summary: '扫描摘要',
      overview: '概览',
      vulnDistribution: '漏洞分布',
      riskTrend: '风险趋势',
      recommendations: '修复建议',
    },
    recon: {
      title: '信息收集',
      subdomain: '子域名',
      port: '端口扫描',
      tech: '技术识别',
      whois: 'WHOIS查询',
      dns: 'DNS记录',
    },
    attack: {
      title: '攻击引擎',
      bruteForce: '暴力破解',
      exploit: '漏洞利用',
      wafBypass: 'WAF绕过',
      customPayload: '自定义载荷',
    },
    error: {
      networkError: '网络不可用，请检查连接',
      pageLoadError: '页面加载异常',
      unknownError: '未知错误',
      submitFailed: '提交失败',
      verifyFailed: 'AI验证失败',
    },
    shortcut: {
      title: '键盘快捷键',
      pressQuestion: '按 ? 随时查看快捷键帮助',
      navigation: '导航',
      general: '通用',
    },
  },
  'en': {
    app: { name: 'WyqYan', subtitle: 'Vulnerability Scanner', version: 'v2.0.0' },
    nav: {
      dashboard: 'Dashboard',
      tasks: 'Tasks',
      newTask: 'New Scan',
      vulnerabilities: 'Vulnerabilities',
      reports: 'Reports',
      recon: 'Recon',
      attack: 'Attack',
      pocManagement: 'POC Mgmt',
      aiVerify: 'AI Verify',
      settings: 'Settings',
    },
    common: {
      loading: 'Loading...',
      save: 'Save',
      cancel: 'Cancel',
      delete: 'Delete',
      confirm: 'Confirm',
      retry: 'Retry',
      search: 'Search',
      filter: 'Filter',
      all: 'All',
      none: 'None',
      back: 'Back',
      close: 'Close',
      open: 'Open',
      submit: 'Submit',
      reset: 'Reset',
      export: 'Export',
      import: 'Import',
      refresh: 'Refresh',
      copy: 'Copy',
      copied: 'Copied',
      more: 'More',
      actions: 'Actions',
      status: 'Status',
      type: 'Type',
      target: 'Target',
      created: 'Created',
      updated: 'Updated',
      description: 'Description',
      detail: 'Detail',
      result: 'Result',
      error: 'Error',
      success: 'Success',
      warning: 'Warning',
      info: 'Info',
      yes: 'Yes',
      no: 'No',
      enabled: 'Enabled',
      disabled: 'Disabled',
    },
    risk: {
      critical: 'Critical',
      high: 'High',
      medium: 'Medium',
      low: 'Low',
      info: 'Info',
    },
    task: {
      pending: 'Pending',
      running: 'Running',
      completed: 'Completed',
      failed: 'Failed',
      stopped: 'Stopped',
      createTask: 'Create Scan Task',
      targetUrl: 'Target URL',
      targetUrlPlaceholder: 'https://example.com',
      scanType: 'Scan Type',
      fullScan: 'Full Scan',
      quickScan: 'Quick Scan',
      customScan: 'Custom Scan',
      selectModules: 'Select Modules',
      startScan: 'Start Scan',
      stopScan: 'Stop Scan',
      noTasks: 'No scan tasks',
      createFirst: 'Create first task',
      vulnCount: 'Vulnerabilities',
      progress: 'Progress',
    },
    vuln: {
      title: 'Vulnerabilities',
      subtitle: 'Click AI Verify to intelligently analyze vulnerabilities',
      noVulns: 'No vulnerabilities found',
      noFilteredVulns: 'No vulnerabilities matching current filter',
      aiVerify: 'AI Verify',
      verifying: 'Verifying...',
      aiConfirmed: 'AI Confirmed',
      suspectedFP: 'Suspected FP',
      expandDetail: 'Expand Details',
      collapseDetail: 'Collapse Details',
      evidence: 'Evidence',
      matchedPatterns: 'Matched Patterns',
      remediation: 'Remediation',
      cvssScore: 'CVSS Score',
      confidence: 'Confidence',
      cveRefs: 'CVE References',
    },
    settings: {
      title: 'Settings',
      aiModels: 'AI Models',
      addModel: 'Add Model',
      modelName: 'Model Name',
      provider: 'Provider',
      apiKey: 'API Key',
      apiEndpoint: 'API Endpoint',
      modelId: 'Model ID',
      testConnection: 'Test Connection',
      infoKeys: 'Info Gathering Keys',
      addKey: 'Add Key',
      platform: 'Platform',
      keyValue: 'Key Value',
      keyStatus: 'Status',
    },
    poc: {
      title: 'POC Management',
      addPoc: 'Add POC',
      editPoc: 'Edit POC',
      pocName: 'POC Name',
      pocCategory: 'Category',
      pocRisk: 'Risk Level',
      pocContent: 'POC Content',
      importPoc: 'Import POC',
      exportPoc: 'Export POC',
      testPoc: 'Test POC',
    },
    report: {
      title: 'Reports',
      generate: 'Generate Report',
      download: 'Download Report',
      summary: 'Scan Summary',
      overview: 'Overview',
      vulnDistribution: 'Vulnerability Distribution',
      riskTrend: 'Risk Trend',
      recommendations: 'Recommendations',
    },
    recon: {
      title: 'Reconnaissance',
      subdomain: 'Subdomains',
      port: 'Port Scan',
      tech: 'Tech Detection',
      whois: 'WHOIS Lookup',
      dns: 'DNS Records',
    },
    attack: {
      title: 'Attack Engine',
      bruteForce: 'Brute Force',
      exploit: 'Exploitation',
      wafBypass: 'WAF Bypass',
      customPayload: 'Custom Payload',
    },
    error: {
      networkError: 'Network unavailable, please check connection',
      pageLoadError: 'Page load error',
      unknownError: 'Unknown error',
      submitFailed: 'Submission failed',
      verifyFailed: 'AI verification failed',
    },
    shortcut: {
      title: 'Keyboard Shortcuts',
      pressQuestion: 'Press ? anytime to view shortcuts',
      navigation: 'Navigation',
      general: 'General',
    },
  },
}

const LANGUAGES = [
  { code: 'zh-CN', name: '中文', flag: 'CN' },
  { code: 'en', name: 'English', flag: 'US' },
]

function getStoredLang() {
  try {
    const stored = localStorage.getItem(LANG_KEY)
    if (stored && LANGUAGES.find(l => l.code === stored)) return stored
  } catch {}
  return null
}

function getBrowserLang() {
  if (typeof navigator === 'undefined') return 'zh-CN'
  const lang = navigator.language || 'zh-CN'
  return lang.startsWith('zh') ? 'zh-CN' : 'en'
}

export function I18nProvider({ children }) {
  const [lang, setLangState] = useState(() => {
    return getStoredLang() || getBrowserLang()
  })

  const setLang = useCallback((newLang) => {
    setLangState(newLang)
    try {
      localStorage.setItem(LANG_KEY, newLang)
    } catch {}
    document.documentElement.lang = newLang === 'zh-CN' ? 'zh-CN' : 'en'
  }, [])

  useEffect(() => {
    document.documentElement.lang = lang === 'zh-CN' ? 'zh-CN' : 'en'
  }, [lang])

  const t = useCallback((path, fallback = '') => {
    const keys = path.split('.')
    let value = messages[lang] || messages['zh-CN']
    for (const key of keys) {
      if (value && typeof value === 'object') {
        value = value[key]
      } else {
        return fallback || path
      }
    }
    return value || fallback || path
  }, [lang])

  const value = {
    lang,
    setLang,
    t,
    languages: LANGUAGES,
    currentLang: LANGUAGES.find(l => l.code === lang),
  }

  return (
    <I18nContext.Provider value={value}>
      {children}
    </I18nContext.Provider>
  )
}

export function useI18n() {
  const ctx = useContext(I18nContext)
  if (!ctx) throw new Error('useI18n must be used within I18nProvider')
  return ctx
}

export { LANGUAGES }
