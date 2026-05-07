import React from 'react'

export default function LoadingFallback() {
  return (
    <div className="flex items-center justify-center h-64">
      <div className="flex flex-col items-center gap-4">
        <div className="w-8 h-8 border-2 border-[var(--accent)] border-t-transparent rounded-full animate-spin" />
        <span className="text-[var(--text-secondary)] text-sm">Loading...</span>
      </div>
    </div>
  )
}
