import React, { useState } from 'react'

export default function Recon() {
  const [target, setTarget] = useState('')

  return (
    <div className="space-y-6 page-enter">
      <h1 className="sec-title text-2xl">Reconnaissance</h1>
      <div className="card p-6">
        <div className="space-y-4">
          <div>
            <label className="label-text">Target</label>
            <input
              type="text"
              className="input-field mt-2"
              placeholder="example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <button className="btn btn-accent">Start Recon</button>
        </div>
      </div>
    </div>
  )
}
