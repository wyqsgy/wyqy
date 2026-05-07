import React, { createContext, useContext, useState, useCallback } from 'react'

type Locale = 'en' | 'zh-CN' | 'zh-TW' | 'ja' | 'ko'

interface I18nContextType {
  locale: Locale
  setLocale: (locale: Locale) => void
  t: (key: string, params?: Record<string, string>) => string
  locales: Locale[]
}

const translations: Record<Locale, Record<string, string>> = {
  'en': {
    'app.title': 'Superpowers Security Scanner',
    'nav.dashboard': 'Dashboard',
    'nav.tasks': 'Tasks',
    'nav.vulnerabilities': 'Vulnerabilities',
    'nav.reports': 'Reports',
    'common.loading': 'Loading...',
    'common.save': 'Save',
    'common.cancel': 'Cancel',
    'common.delete': 'Delete',
    'common.edit': 'Edit',
    'common.search': 'Search',
  },
  'zh-CN': {
    'app.title': '超能安全扫描器',
    'nav.dashboard': '仪表盘',
    'nav.tasks': '任务',
    'nav.vulnerabilities': '漏洞',
    'nav.reports': '报告',
    'common.loading': '加载中...',
    'common.save': '保存',
    'common.cancel': '取消',
    'common.delete': '删除',
    'common.edit': '编辑',
    'common.search': '搜索',
  },
  'zh-TW': {
    'app.title': '超能安全掃描器',
    'nav.dashboard': '儀表板',
    'nav.tasks': '任務',
    'nav.vulnerabilities': '漏洞',
    'nav.reports': '報告',
    'common.loading': '載入中...',
    'common.save': '儲存',
    'common.cancel': '取消',
    'common.delete': '刪除',
    'common.edit': '編輯',
    'common.search': '搜尋',
  },
  'ja': {
    'app.title': 'スーパーパワー セキュリティスキャナー',
    'nav.dashboard': 'ダッシュボード',
    'nav.tasks': 'タスク',
    'nav.vulnerabilities': '脆弱性',
    'nav.reports': 'レポート',
    'common.loading': '読み込み中...',
    'common.save': '保存',
    'common.cancel': 'キャンセル',
    'common.delete': '削除',
    'common.edit': '編集',
    'common.search': '検索',
  },
  'ko': {
    'app.title': '슈퍼파워 보안 스캐너',
    'nav.dashboard': '대시보드',
    'nav.tasks': '작업',
    'nav.vulnerabilities': '취약점',
    'nav.reports': '보고서',
    'common.loading': '로딩 중...',
    'common.save': '저장',
    'common.cancel': '취소',
    'common.delete': '삭제',
    'common.edit': '편집',
    'common.search': '검색',
  },
}

const I18nContext = createContext<I18nContextType | undefined>(undefined)

const locales: Locale[] = ['en', 'zh-CN', 'zh-TW', 'ja', 'ko']

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(() => {
    const saved = localStorage.getItem('locale') as Locale
    return saved || 'en'
  })

  const setLocale = (newLocale: Locale) => {
    setLocaleState(newLocale)
    localStorage.setItem('locale', newLocale)
  }

  const t = useCallback(
    (key: string, params?: Record<string, string>): string => {
      let text = translations[locale][key] || translations['en'][key] || key

      if (params) {
        Object.entries(params).forEach(([k, v]) => {
          text = text.replace(`{${k}}`, v)
        })
      }

      return text
    },
    [locale]
  )

  return (
    <I18nContext.Provider value={{ locale, setLocale, t, locales }}>
      {children}
    </I18nContext.Provider>
  )
}

export function useI18n() {
  const context = useContext(I18nContext)
  if (!context) {
    throw new Error('useI18n must be used within I18nProvider')
  }
  return context
}
