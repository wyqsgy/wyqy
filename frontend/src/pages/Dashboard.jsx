import React, { useState, useEffect } from 'react'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { getTasks, getVulnerabilities } from '../api'

const COLORS = { critical: '#e94560', high: '#ff6600', medium: '#f59f00', low: '#2b8a3e', info: '#4263eb' }

export default function Dashboard() {
  const [stats, setStats] = useState({ totalTasks: 0, totalVulns: 0, riskDist: [], recentTasks: [] })

  useEffect(() => {
    loadData()
  }, [])

  const loadData = async () => {
    try {
      const [taskRes, vulnRes] = await Promise.all([getTasks({ limit: 100 }), getVulnerabilities({ limit: 100 })])
      const tasks = taskRes.data.data.items || []
      const vulns = vulnRes.data.data.items || []

      const riskMap = {}
      vulns.forEach(v => { riskMap[v.risk_level] = (riskMap[v.risk_level] || 0) + 1 })
      const riskDist = Object.entries(riskMap).map(([name, value]) => ({
        name: { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息' }[name] || name,
        value, fill: COLORS[name] || '#8884d8',
      }))

      setStats({
        totalTasks: tasks.length,
        totalVulns: vulns.length,
        riskDist,
        recentTasks: tasks.slice(0, 5),
      })
    } catch (e) {
      console.error('Failed to load dashboard data:', e)
    }
  }

  const statusColors = { pending: 'bg-gray-200 text-gray-600', running: 'bg-blue-100 text-blue-700', completed: 'bg-green-100 text-green-700', failed: 'bg-red-100 text-red-700', stopped: 'bg-yellow-100 text-yellow-700' }
  const statusLabels = { pending: '等待中', running: '扫描中', completed: '已完成', failed: '失败', stopped: '已停止' }

  return (
    <div>
      <h1 className="text-2xl font-bold text-dark-900 mb-6">仪表板</h1>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
        <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <div className="text-sm text-dark-500 mb-1">扫描任务</div>
          <div className="text-3xl font-bold text-dark-900">{stats.totalTasks}</div>
        </div>
        <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <div className="text-sm text-dark-500 mb-1">发现漏洞</div>
          <div className="text-3xl font-bold text-danger">{stats.totalVulns}</div>
        </div>
        <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <div className="text-sm text-dark-500 mb-1">覆盖组件</div>
          <div className="text-3xl font-bold text-primary-700">18</div>
          <div className="text-xs text-dark-400 mt-1">Spring / Shiro / Log4j2 / Fastjson / Nacos / Druid / Tomcat / Struts2 / ThinkPHP / WebLogic / Redis / Confluence / F5 / Jenkins / Flink / XXL-JOB / Nginx / Elasticsearch</div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
        <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <h3 className="font-semibold text-dark-800 mb-4">漏洞风险分布</h3>
          {stats.riskDist.length > 0 ? (
            <ResponsiveContainer width="100%" height={250}>
              <PieChart>
                <Pie data={stats.riskDist} cx="50%" cy="50%" outerRadius={90} dataKey="value" label={({ name, value }) => `${name}: ${value}`}>
                  {stats.riskDist.map((entry, i) => <Cell key={i} fill={entry.fill} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-[250px] flex items-center justify-center text-dark-400">暂无数据</div>
          )}
        </div>

        <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
          <h3 className="font-semibold text-dark-800 mb-4">最近扫描任务</h3>
          <div className="space-y-3">
            {stats.recentTasks.length > 0 ? stats.recentTasks.map((t) => (
              <div key={t.task_id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div>
                  <div className="font-medium text-sm text-dark-800 truncate max-w-[200px]">{t.target}</div>
                  <div className="text-xs text-dark-400">发现 {t.vuln_count} 个漏洞</div>
                </div>
                <span className={`px-2 py-1 rounded text-xs font-medium ${statusColors[t.status] || ''}`}>
                  {statusLabels[t.status] || t.status}
                </span>
              </div>
            )) : (
              <div className="text-center text-dark-400 py-8">暂无扫描任务</div>
            )}
          </div>
        </div>
      </div>

      <div className="bg-white rounded-xl p-6 shadow-sm border border-gray-100">
        <h3 className="font-semibold text-dark-800 mb-4">支持的漏洞模块</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { name: 'Spring Framework', count: 7, icon: '🍃' },
            { name: 'Apache Shiro', count: 2, icon: '🔐' },
            { name: 'Log4j2', count: 1, icon: '📝' },
            { name: 'Fastjson', count: 1, icon: '⚡' },
            { name: 'Nacos', count: 2, icon: '🌐' },
            { name: 'Druid', count: 1, icon: '🐉' },
            { name: 'Tomcat', count: 1, icon: '🐱' },
            { name: 'Struts2', count: 1, icon: '🚀' },
            { name: 'ThinkPHP', count: 1, icon: '🐘' },
            { name: 'WebLogic', count: 1, icon: '☕' },
            { name: 'Redis', count: 1, icon: '🔴' },
            { name: 'Confluence', count: 1, icon: '📘' },
            { name: 'F5 BIG-IP', count: 1, icon: '🛡️' },
            { name: 'Jenkins', count: 1, icon: '🏗️' },
            { name: 'Apache Flink', count: 1, icon: '🌊' },
            { name: 'XXL-JOB', count: 1, icon: '⏰' },
            { name: 'Nginx', count: 1, icon: '🌐' },
            { name: 'Elasticsearch', count: 1, icon: '🔍' },
          ].map((mod) => (
            <div key={mod.name} className="p-4 bg-gray-50 rounded-lg text-center">
              <div className="text-2xl mb-1">{mod.icon}</div>
              <div className="text-sm font-medium text-dark-800">{mod.name}</div>
              <div className="text-xs text-dark-400">{mod.count} 个检测模块</div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
