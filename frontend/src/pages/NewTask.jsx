import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { createTask } from '../api'

const SCAN_TYPES = [
  { id: 'full', name: 'FULL SCAN', desc: 'Recon + Fingerprint + Attack (all modules)', icon: '[*]' },
  { id: 'recon', name: 'RECON ONLY', desc: 'Subdomain + Port + Fingerprint', icon: '[@]' },
  { id: 'attack', name: 'ATTACK ONLY', desc: 'WAF + Deserial + SSRF + JWT + Fuzz + Honeypot', icon: '[!]' },
  { id: 'quick', name: 'QUICK SCAN', desc: 'Fast fingerprint + top POCs only', icon: '[>]' },
]

export default function NewTask() {
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('full')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!target.trim()) {
      setError('TARGET IS REQUIRED')
      return
    }
    setLoading(true)
    setError('')
    try {
      await createTask({ target: target.trim(), scan_type: scanType })
      navigate('/tasks')
    } catch (e) {
      setError(e.response?.data?.detail || 'CREATE FAILED')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <div className="pixel-text" style={{
        fontSize: '14px',
        color: 'var(--text-bright)',
        textShadow: '0 0 10px var(--accent-glow)',
        marginBottom: '24px',
      }}>
        // NEW SCAN
      </div>

      <div className="pixel-card" style={{ padding: '24px', maxWidth: '700px' }}>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: '20px' }}>
            <div className="pixel-text-sm" style={{ color: 'var(--text-dim)', marginBottom: '8px' }}>
              TARGET
            </div>
            <input
              className="pixel-input"
              placeholder="https://target.com or 192.168.1.1"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              autoFocus
            />
          </div>

          <div style={{ marginBottom: '20px' }}>
            <div className="pixel-text-sm" style={{ color: 'var(--text-dim)', marginBottom: '12px' }}>
              SCAN TYPE
            </div>
            <div style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fill, minmax(150px, 1fr))',
              gap: '8px',
            }}>
              {SCAN_TYPES.map((st) => (
                <div
                  key={st.id}
                  onClick={() => setScanType(st.id)}
                  style={{
                    padding: '12px',
                    background: scanType === st.id ? 'var(--bg-tertiary)' : 'var(--bg-secondary)',
                    border: scanType === st.id ? '2px solid var(--border-glow)' : '2px solid var(--border-color)',
                    cursor: 'pointer',
                    textAlign: 'center',
                    boxShadow: scanType === st.id ? '0 0 10px var(--shadow-color)' : 'none',
                  }}
                >
                  <div className="mono-text" style={{ color: 'var(--accent)', fontSize: '14px', marginBottom: '4px' }}>
                    {st.icon}
                  </div>
                  <div className="pixel-text-sm" style={{ color: 'var(--text-primary)' }}>
                    {st.name}
                  </div>
                  <div className="mono-text" style={{ color: 'var(--text-dim)', fontSize: '9px', marginTop: '4px' }}>
                    {st.desc}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {error && (
            <div className="pixel-text-sm" style={{
              color: 'var(--danger)',
              marginBottom: '16px',
              padding: '8px',
              border: '1px solid var(--danger)',
              background: 'rgba(255,51,51,0.1)',
            }}>
              [ERROR] {error}
            </div>
          )}

          <button
            type="submit"
            className="pixel-btn pixel-btn-accent"
            disabled={loading}
            style={{ width: '100%' }}
          >
            {loading ? 'CREATING...' : '[ START SCAN ]'}
          </button>
        </form>
      </div>
    </div>
  )
}
