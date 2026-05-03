import React, { useState, useEffect } from 'react'
import api from '../api'

const RISK_COLORS = {
  critical: 'var(--danger)',
  high: '#ea580c',
  medium: 'var(--warning)',
  low: 'var(--info)',
  info: 'var(--text-dim)',
}

const SUPPORTED_PLATFORMS = [
  { key: 'fofa', name: 'FOFA', icon: '🌐', desc: '网络空间测绘平台' },
  { key: 'hunter', name: 'Hunter', icon: '🔍', desc: '鹰图平台' },
  { key: 'shodan', name: 'Shodan', icon: '🛰️', desc: '全球设备搜索引擎' },
  { key: 'quake', name: 'Quake', icon: '📡', desc: '360网络空间测绘' },
  { key: 'zoomeye', name: 'ZoomEye', icon: '👁️', desc: '知道创宇网络空间搜索引擎' },
  { key: 'censys', name: 'Censys', icon: '🔬', desc: '互联网资产发现平台' },
  { key: 'virustotal', name: 'VirusTotal', icon: '🛡️', desc: '恶意软件分析平台' },
  { key: 'securitytrails', name: 'SecurityTrails', icon: '🗺️', desc: 'DNS/域名情报平台' },
  { key: 'alienvault', name: 'AlienVault OTX', icon: '👽', desc: '威胁情报共享平台' },
  { key: 'binaryedge', name: 'BinaryEdge', icon: '📊', desc: '互联网扫描数据平台' },
]

const AI_PROVIDERS = [
  { key: 'openai', name: 'OpenAI', defaultBase: 'https://api.openai.com/v1' },
  { key: 'azure', name: 'Azure OpenAI', defaultBase: 'https://YOUR_RESOURCE.openai.azure.com/' },
  { key: 'deepseek', name: 'DeepSeek', defaultBase: 'https://api.deepseek.com/v1' },
  { key: 'zhipu', name: '智谱 GLM', defaultBase: 'https://open.bigmodel.cn/api/paas/v4' },
  { key: 'moonshot', name: 'Moonshot', defaultBase: 'https://api.moonshot.cn/v1' },
  { key: 'qwen', name: '通义千问', defaultBase: 'https://dashscope.aliyuncs.com/compatible-mode/v1' },
  { key: 'baidu', name: '文心一言', defaultBase: 'https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat' },
  { key: 'custom', name: '自定义', defaultBase: 'https://your-api-endpoint/v1' },
]

export default function Settings() {
  const [tab, setTab] = useState('ai')
  const [aiModels, setAiModels] = useState([])
  const [infoKeys, setInfoKeys] = useState([])
  const [loading, setLoading] = useState(false)
  const [showAiForm, setShowAiForm] = useState(false)
  const [editingAi, setEditingAi] = useState(null)
  const [testingId, setTestingId] = useState(null)

  const [aiForm, setAiForm] = useState({
    name: '', provider: 'openai', api_base: 'https://api.openai.com/v1',
    api_key: '', model_name: 'gpt-3.5-turbo', temperature: '0.1',
    max_tokens: '4096', timeout: '60', is_enabled: true, is_default: false,
  })

  const [infoForm, setInfoForm] = useState({})

  useEffect(() => {
    if (tab === 'ai') loadAiModels()
    if (tab === 'info') loadInfoKeys()
  }, [tab])

  const loadAiModels = async () => {
    setLoading(true)
    try {
      const res = await api.get('/settings/ai-models')
      setAiModels(res.data.data || [])
    } catch (e) { console.error(e) }
    setLoading(false)
  }

  const loadInfoKeys = async () => {
    setLoading(true)
    try {
      const res = await api.get('/settings/info-keys')
      setInfoKeys(res.data.data || [])
    } catch (e) { console.error(e) }
    setLoading(false)
  }

  const handleProviderChange = (provider) => {
    const p = AI_PROVIDERS.find(x => x.key === provider)
    setAiForm({ ...aiForm, provider, api_base: p?.defaultBase || '' })
  }

  const saveAiModel = async () => {
    try {
      if (editingAi) {
        await api.put(`/settings/ai-models/${editingAi.id}`, aiForm)
      } else {
        await api.post('/settings/ai-models', aiForm)
      }
      setShowAiForm(false)
      setEditingAi(null)
      resetAiForm()
      loadAiModels()
    } catch (e) {
      alert('保存失败: ' + (e.response?.data?.detail || e.message))
    }
  }

  const deleteAiModel = async (id) => {
    if (!confirm('确定删除此AI模型配置？')) return
    try {
      await api.delete(`/settings/ai-models/${id}`)
      loadAiModels()
    } catch (e) { alert('删除失败') }
  }

  const testAiModel = async (id) => {
    setTestingId(id)
    try {
      const res = await api.post(`/settings/ai-models/${id}/test`)
      alert(res.data.message)
    } catch (e) { alert('测试失败') }
    setTestingId(null)
  }

  const editAiModel = (model) => {
    setAiForm({
      name: model.name, provider: model.provider, api_base: model.api_base,
      api_key: '', model_name: model.model_name, temperature: model.temperature,
      max_tokens: model.max_tokens, timeout: model.timeout,
      is_enabled: model.is_enabled, is_default: model.is_default,
    })
    setEditingAi(model)
    setShowAiForm(true)
  }

  const resetAiForm = () => {
    setAiForm({
      name: '', provider: 'openai', api_base: 'https://api.openai.com/v1',
      api_key: '', model_name: 'gpt-3.5-turbo', temperature: '0.1',
      max_tokens: '4096', timeout: '60', is_enabled: true, is_default: false,
    })
  }

  const saveInfoKey = async (platform) => {
    const data = infoForm[platform] || { platform, api_key: '', email: '', is_enabled: true }
    try {
      await api.post('/settings/info-keys', { ...data, platform })
      loadInfoKeys()
    } catch (e) { alert('保存失败') }
  }

  const deleteInfoKey = async (id) => {
    if (!confirm('确定删除此Key？')) return
    try {
      await api.delete(`/settings/info-keys/${id}`)
      loadInfoKeys()
    } catch (e) { alert('删除失败') }
  }

  const getInfoKeyForPlatform = (platform) => {
    return infoKeys.find(k => k.platform === platform)
  }

  const cardStyle = {
    background: 'var(--bg-card)',
    border: '1px solid var(--border-color)',
    borderRadius: '8px',
    padding: '20px',
    marginBottom: '16px',
  }

  const inputStyle = {
    width: '100%',
    padding: '8px 12px',
    background: 'var(--bg-tertiary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    color: 'var(--text-primary)',
    fontSize: '13px',
    outline: 'none',
    boxSizing: 'border-box',
  }

  const btnPrimary = {
    padding: '8px 16px',
    background: 'var(--accent)',
    color: '#fff',
    border: 'none',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '13px',
    fontWeight: 600,
  }

  const btnDanger = {
    padding: '6px 12px',
    background: 'var(--danger-subtle)',
    color: 'var(--danger)',
    border: '1px solid var(--danger)',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '12px',
  }

  const btnOutline = {
    padding: '6px 12px',
    background: 'transparent',
    color: 'var(--text-secondary)',
    border: '1px solid var(--border-color)',
    borderRadius: '6px',
    cursor: 'pointer',
    fontSize: '12px',
  }

  const badgeStyle = (enabled) => ({
    display: 'inline-block',
    padding: '2px 8px',
    borderRadius: '10px',
    fontSize: '11px',
    fontWeight: 600,
    background: enabled ? 'var(--success-subtle)' : 'var(--bg-tertiary)',
    color: enabled ? 'var(--success)' : 'var(--text-dim)',
  })

  return (
    <div>
      <div style={{ marginBottom: '24px' }}>
        <h2 style={{ fontSize: '20px', fontWeight: 700, color: 'var(--text-bright)', margin: 0 }}>
          系统设置
        </h2>
        <p style={{ fontSize: '13px', color: 'var(--text-dim)', marginTop: '4px' }}>
          管理AI模型、API密钥和信息收集平台Key
        </p>
      </div>

      <div style={{ display: 'flex', gap: '4px', marginBottom: '24px', borderBottom: '1px solid var(--border-color)', paddingBottom: 0 }}>
        {[
          { key: 'ai', label: '🤖 AI模型配置' },
          { key: 'info', label: '🔑 信息收集Key' },
        ].map(t => (
          <button
            key={t.key}
            onClick={() => setTab(t.key)}
            style={{
              padding: '10px 20px',
              background: 'transparent',
              border: 'none',
              borderBottom: tab === t.key ? '2px solid var(--accent)' : '2px solid transparent',
              color: tab === t.key ? 'var(--text-bright)' : 'var(--text-dim)',
              cursor: 'pointer',
              fontSize: '13px',
              fontWeight: tab === t.key ? 600 : 400,
              transition: 'all 0.15s',
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'ai' && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
            <span style={{ fontSize: '14px', color: 'var(--text-secondary)' }}>
              共 {aiModels.length} 个AI模型配置
            </span>
            <button
              style={btnPrimary}
              onClick={() => { resetAiForm(); setEditingAi(null); setShowAiForm(true) }}
            >
              + 添加AI模型
            </button>
          </div>

          {showAiForm && (
            <div style={cardStyle}>
              <h3 style={{ fontSize: '15px', color: 'var(--text-bright)', margin: '0 0 16px 0' }}>
                {editingAi ? '编辑AI模型' : '添加AI模型'}
              </h3>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                <div>
                  <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>配置名称</label>
                  <input style={inputStyle} value={aiForm.name} onChange={e => setAiForm({ ...aiForm, name: e.target.value })} placeholder="例如：我的GPT-4" />
                </div>
                <div>
                  <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>提供商</label>
                  <select style={inputStyle} value={aiForm.provider} onChange={e => handleProviderChange(e.target.value)}>
                    {AI_PROVIDERS.map(p => (
                      <option key={p.key} value={p.key}>{p.name}</option>
                    ))}
                  </select>
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>API Base URL</label>
                  <input style={inputStyle} value={aiForm.api_base} onChange={e => setAiForm({ ...aiForm, api_base: e.target.value })} />
                </div>
                <div style={{ gridColumn: '1 / -1' }}>
                  <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>API Key</label>
                  <input style={inputStyle} type="password" value={aiForm.api_key} onChange={e => setAiForm({ ...aiForm, api_key: e.target.value })} placeholder={editingAi ? '留空则不修改' : '输入API Key'} />
                </div>
                <div>
                  <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>模型名称</label>
                  <input style={inputStyle} value={aiForm.model_name} onChange={e => setAiForm({ ...aiForm, model_name: e.target.value })} />
                </div>
                <div>
                  <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>Temperature</label>
                  <input style={inputStyle} value={aiForm.temperature} onChange={e => setAiForm({ ...aiForm, temperature: e.target.value })} />
                </div>
                <div>
                  <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>Max Tokens</label>
                  <input style={inputStyle} value={aiForm.max_tokens} onChange={e => setAiForm({ ...aiForm, max_tokens: e.target.value })} />
                </div>
                <div>
                  <label style={{ fontSize: '12px', color: 'var(--text-dim)', display: 'block', marginBottom: '4px' }}>超时(秒)</label>
                  <input style={inputStyle} value={aiForm.timeout} onChange={e => setAiForm({ ...aiForm, timeout: e.target.value })} />
                </div>
              </div>
              <div style={{ display: 'flex', gap: '16px', marginTop: '12px', alignItems: 'center' }}>
                <label style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
                  <input type="checkbox" checked={aiForm.is_enabled} onChange={e => setAiForm({ ...aiForm, is_enabled: e.target.checked })} />
                  启用
                </label>
                <label style={{ fontSize: '12px', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '6px', cursor: 'pointer' }}>
                  <input type="checkbox" checked={aiForm.is_default} onChange={e => setAiForm({ ...aiForm, is_default: e.target.checked })} />
                  设为默认
                </label>
              </div>
              <div style={{ display: 'flex', gap: '8px', marginTop: '16px' }}>
                <button style={btnPrimary} onClick={saveAiModel}>保存</button>
                <button style={btnOutline} onClick={() => { setShowAiForm(false); setEditingAi(null) }}>取消</button>
              </div>
            </div>
          )}

          {aiModels.length === 0 && !showAiForm && (
            <div style={{ ...cardStyle, textAlign: 'center', color: 'var(--text-dim)', padding: '40px' }}>
              暂无AI模型配置，点击上方按钮添加
            </div>
          )}

          {aiModels.map(model => (
            <div key={model.id} style={cardStyle}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                    <span style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-bright)' }}>{model.name}</span>
                    <span style={badgeStyle(model.is_enabled)}>{model.is_enabled ? '启用' : '禁用'}</span>
                    {model.is_default && <span style={{ ...badgeStyle(true), background: 'var(--accent-subtle)', color: 'var(--accent)' }}>默认</span>}
                  </div>
                  <div style={{ fontSize: '12px', color: 'var(--text-dim)', lineHeight: '1.6' }}>
                    <div>提供商: {AI_PROVIDERS.find(p => p.key === model.provider)?.name || model.provider}</div>
                    <div>模型: {model.model_name} | API: {model.api_base}</div>
                    <div>Key: {model.api_key}</div>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '6px', flexShrink: 0 }}>
                  <button style={btnOutline} onClick={() => testAiModel(model.id)} disabled={testingId === model.id}>
                    {testingId === model.id ? '测试中...' : '测试连接'}
                  </button>
                  <button style={btnOutline} onClick={() => editAiModel(model)}>编辑</button>
                  <button style={btnDanger} onClick={() => deleteAiModel(model.id)}>删除</button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}

      {tab === 'info' && (
        <div>
          <div style={{ fontSize: '14px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
            配置信息收集平台的API Key，用于子域名枚举、资产发现和威胁情报查询
          </div>

          {SUPPORTED_PLATFORMS.map(platform => {
            const existing = getInfoKeyForPlatform(platform.key)
            const formData = infoForm[platform.key] || { api_key: '', email: '', is_enabled: true }

            return (
              <div key={platform.key} style={cardStyle}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div style={{ flex: 1 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
                      <span style={{ fontSize: '18px' }}>{platform.icon}</span>
                      <span style={{ fontSize: '15px', fontWeight: 600, color: 'var(--text-bright)' }}>{platform.name}</span>
                      {existing && <span style={badgeStyle(existing.is_enabled)}>{existing.is_enabled ? '已配置' : '已禁用'}</span>}
                    </div>
                    <div style={{ fontSize: '12px', color: 'var(--text-dim)', marginBottom: '12px' }}>{platform.desc}</div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
                      <div>
                        <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'block', marginBottom: '2px' }}>API Key</label>
                        <input
                          style={inputStyle}
                          type="password"
                          value={formData.api_key}
                          onChange={e => setInfoForm({ ...infoForm, [platform.key]: { ...formData, api_key: e.target.value } })}
                          placeholder={existing ? '已配置 (留空不修改)' : '输入API Key'}
                        />
                      </div>
                      <div>
                        <label style={{ fontSize: '11px', color: 'var(--text-dim)', display: 'block', marginBottom: '2px' }}>邮箱 (可选)</label>
                        <input
                          style={inputStyle}
                          value={formData.email}
                          onChange={e => setInfoForm({ ...infoForm, [platform.key]: { ...formData, email: e.target.value } })}
                          placeholder="关联邮箱"
                        />
                      </div>
                    </div>
                  </div>
                </div>
                <div style={{ display: 'flex', gap: '8px', marginTop: '12px' }}>
                  <button style={btnPrimary} onClick={() => saveInfoKey(platform.key)}>
                    {existing ? '更新Key' : '保存Key'}
                  </button>
                  {existing && (
                    <button style={btnDanger} onClick={() => deleteInfoKey(existing.id)}>删除</button>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
