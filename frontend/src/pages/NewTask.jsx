import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { createTask, getCategories } from '../api'

const CATEGORY_LABELS = {
  spring: { name: 'Spring Framework', icon: '🍃', vulns: 'Spring4Shell / SpEL / Actuator / Gateway / Function' },
  shiro: { name: 'Apache Shiro', icon: '🔐', vulns: '反序列化 / 权限绕过' },
  log4j2: { name: 'Log4j2', icon: '📝', vulns: 'JNDI注入 (Log4Shell)' },
  fastjson: { name: 'Fastjson', icon: '⚡', vulns: '反序列化RCE' },
  nacos: { name: 'Nacos', icon: '🌐', vulns: '认证绕过 / Derby RCE / 配置泄露' },
  druid: { name: 'Druid', icon: '🐉', vulns: '监控面板未授权访问' },
  tomcat: { name: 'Tomcat', icon: '🐱', vulns: 'Manager未授权 / 弱口令' },
  struts2: { name: 'Struts2', icon: '🚀', vulns: 'OGNL注入系列' },
}

export default function NewTask() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [selected, setSelected] = useState(new Set(['all']))
  const [loading, setLoading] = useState(false)

  const toggleCategory = (cat) => {
    const next = new Set(selected)
    if (cat === 'all') {
      setSelected(new Set(['all']))
      return
    }
    next.delete('all')
    next.has(cat) ? next.delete(cat) : next.add(cat)
    if (next.size === 0) next.add('all')
    setSelected(next)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!target.trim()) return
    setLoading(true)
    try {
      const res = await createTask({ target: target.trim(), categories: Array.from(selected) })
      navigate(`/tasks/${res.data.data.task_id}`)
    } catch (err) {
      alert('创建任务失败: ' + (err.response?.data?.detail || err.message))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-dark-900 mb-6">新建扫描任务</h1>

      <form onSubmit={handleSubmit} className="max-w-3xl">
        <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100 mb-6">
          <label className="block text-sm font-medium text-dark-700 mb-2">扫描目标</label>
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="输入目标URL，例如: http://192.168.1.100:8080"
            className="w-full px-4 py-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary-500 focus:border-primary-500 outline-none"
          />
        </div>

        <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100 mb-6">
          <label className="block text-sm font-medium text-dark-700 mb-4">选择扫描模块</label>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <button
              type="button"
              onClick={() => toggleCategory('all')}
              className={`p-4 rounded-lg border-2 text-left transition-all ${
                selected.has('all') ? 'border-primary-500 bg-primary-50' : 'border-gray-200 hover:border-gray-300'
              }`}
            >
              <div className="font-medium">🎯 全部模块</div>
              <div className="text-xs text-dark-400 mt-1">检测所有支持的漏洞类型</div>
            </button>
            {Object.entries(CATEGORY_LABELS).map(([key, cat]) => (
              <button
                key={key}
                type="button"
                onClick={() => toggleCategory(key)}
                className={`p-4 rounded-lg border-2 text-left transition-all ${
                  selected.has(key) ? 'border-primary-500 bg-primary-50' : 'border-gray-200 hover:border-gray-300'
                }`}
              >
                <div className="font-medium">{cat.icon} {cat.name}</div>
                <div className="text-xs text-dark-400 mt-1">{cat.vulns}</div>
              </button>
            ))}
          </div>
        </div>

        <button
          type="submit"
          disabled={loading || !target.trim()}
          className="w-full py-3 bg-primary-700 text-white rounded-lg font-medium hover:bg-primary-800 disabled:opacity-50 disabled:cursor-not-allowed transition-all"
        >
          {loading ? '提交中...' : '🚀 开始扫描'}
        </button>
      </form>
    </div>
  )
}
