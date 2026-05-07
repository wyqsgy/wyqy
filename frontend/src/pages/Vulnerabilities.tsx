import React, { useState } from 'react'
import { useVulnerabilities, useDeleteVulnerability } from '../hooks/useVulnerabilities'
import RiskBadge from '../components/ui/RiskBadge'

export default function Vulnerabilities() {
  const [page, setPage] = useState(1)
  const { data, isLoading } = useVulnerabilities({ page, page_size: 20 })
  const deleteVuln = useDeleteVulnerability()

  if (isLoading) {
    return <div className="text-center py-12">Loading...</div>
  }

  const vulns = data?.vulnerabilities || []

  return (
    <div className="space-y-6 page-enter">
      <div className="flex items-center justify-between">
        <h1 className="sec-title text-2xl">Vulnerabilities</h1>
        <span className="text-sm text-[var(--text-secondary)]">
          Total: {data?.total || 0}
        </span>
      </div>

      <div className="card overflow-hidden">
        <table className="pixel-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Risk</th>
              <th>Target</th>
              <th>CVE</th>
              <th>Status</th>
              <th>Discovered</th>
            </tr>
          </thead>
          <tbody>
            {vulns.map((vuln) => (
              <tr key={vuln.id}>
                <td data-label="Name">{vuln.name}</td>
                <td data-label="Risk">
                  <RiskBadge level={vuln.risk_level} />
                </td>
                <td data-label="Target">{vuln.target}</td>
                <td data-label="CVE">{vuln.cve || '-'}</td>
                <td data-label="Status">
                  <span className="text-xs">{vuln.status}</span>
                </td>
                <td data-label="Discovered">
                  {new Date(vuln.discovered_at).toLocaleDateString()}
                </td>
              </tr>
            ))}
            {vulns.length === 0 && (
              <tr>
                <td colSpan={6} className="text-center text-[var(--text-dim)]">
                  No vulnerabilities found
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {data && data.total > 20 && (
        <div className="flex justify-center gap-2">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            className="btn"
            disabled={page === 1}
          >
            Previous
          </button>
          <span className="px-4 py-2 text-sm text-[var(--text-secondary)]">
            Page {page} of {Math.ceil(data.total / 20)}
          </span>
          <button
            onClick={() => setPage((p) => p + 1)}
            className="btn"
            disabled={page >= Math.ceil(data.total / 20)}
          >
            Next
          </button>
        </div>
      )}
    </div>
  )
}
