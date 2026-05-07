import React, { Component, ReactNode } from 'react'

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  error?: Error
}

export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props)
    this.state = { hasError: false }
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  componentDidCatch(error: Error, errorInfo: React.ErrorInfo) {
    console.error('ErrorBoundary caught:', error, errorInfo)
  }

  render() {
    if (this.state.hasError) {
      return (
        this.props.fallback || (
          <div className="flex items-center justify-center h-64">
            <div className="card p-6 text-center max-w-md">
              <div className="text-4xl mb-4">⚠</div>
              <h2 className="sec-title text-[var(--danger)] mb-2">Something went wrong</h2>
              <p className="text-sm text-[var(--text-secondary)] mb-4">
                {this.state.error?.message || 'An unexpected error occurred'}
              </p>
              <button
                className="btn"
                onClick={() => this.setState({ hasError: false })}
              >
                Try again
              </button>
            </div>
          </div>
        )
      )
    }

    return this.props.children
  }
}
