import React from 'react'

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, errorInfo) {
    console.error('[ErrorBoundary]', error, errorInfo)
  }

  handleRetry = () => {
    this.setState({ hasError: false, error: null })
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          height: '60vh',
          gap: '16px',
        }}>
          <div style={{
            fontSize: '48px',
            color: 'var(--danger)',
            fontFamily: 'var(--font-title)',
          }}>
            !
          </div>
          <div style={{
            fontSize: '16px',
            color: 'var(--text-bright)',
            fontFamily: 'var(--font-body)',
            fontWeight: 600,
          }}>
            页面加载异常
          </div>
          <div style={{
            fontSize: '12px',
            color: 'var(--text-dim)',
            fontFamily: 'var(--font-body)',
            maxWidth: '400px',
            textAlign: 'center',
          }}>
            {this.state.error?.message || '未知错误'}
          </div>
          <button
            onClick={this.handleRetry}
            style={{
              padding: '8px 20px',
              background: 'var(--accent)',
              color: '#fff',
              border: 'none',
              borderRadius: '6px',
              fontSize: '13px',
              fontFamily: 'var(--font-body)',
              cursor: 'pointer',
              fontWeight: 600,
            }}
          >
            重试
          </button>
        </div>
      )
    }

    return this.props.children
  }
}
