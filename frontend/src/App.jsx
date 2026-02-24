import { useState } from 'react'
import './App.css'

function App() {
  const [activeTab, setActiveTab] = useState('live')
  const [liveCode, setLiveCode] = useState('')
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)

  const handleUpload = async () => {
    if (!file) return
    setLoading(true)
    const formData = new FormData()
    formData.append("file", file)
    try {
      const resp = await fetch("http://127.0.0.1:8000/api/scan", { method: "POST", body: formData })
      setResults(await resp.json())
    } finally {
      setLoading(false)
    }
  }

  const handleLiveScan = async () => {
    if (!liveCode.trim()) return
    setLoading(true)
    try {
      const resp = await fetch("http://127.0.0.1:8000/api/scan-live", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: liveCode, filename: "live_editor.py" })
      })
      setResults(await resp.json())
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="app-container">

      {/* HEADER SECTION */}
      <header className="global-header">
        <div className="logo-container">
          <h1>SENTINEL<span>.</span>AI</h1>
          <div className="logo-subtitle">Enterprise Security Node</div>
        </div>

        <div className="badge-container">
          <div className="status-badge safe">
             <div className="pulse-dot safe"></div>
             SYSTEM ACTIVE
          </div>
          {results && results.mode !== "LIVE_INFERENCE" && (
             <div className={`status-badge ${results.is_air_gapped ? 'safe' : 'critical'}`}>
               <div className={`pulse-dot ${results.is_air_gapped ? 'safe' : 'critical'}`}></div>
               {results.is_air_gapped ? 'AIR-GAP VERIFIED' : 'AIR-GAP COMPROMISED'}
             </div>
          )}
        </div>
      </header>

      {/* TOP METRICS (BENTO GRID) */}
      <div className="bento-grid">
        <div className="glass-panel" style={{gridColumn: 'span 2'}}>
          <div className="tabs">
            <button className={`tab-btn ${activeTab === 'live' ? 'active' : ''}`} onClick={() => setActiveTab('live')}>LIVE TERMINAL</button>
            <button className={`tab-btn ${activeTab === 'upload' ? 'active' : ''}`} onClick={() => setActiveTab('upload')}>INBOUND BUFFER (.ZIP)</button>
          </div>

          {activeTab === 'live' ? (
            <>
              <textarea
                className="code-editor"
                value={liveCode}
                onChange={(e) => setLiveCode(e.target.value)}
                placeholder="# Paste untrusted code snippet here..."
                spellCheck="false"
              />
              <button onClick={handleLiveScan} className="action-btn" disabled={loading || !liveCode.trim()}>
                {loading ? 'EXECUTING INFERENCE...' : 'RUN SECURITY SCAN'}
              </button>
            </>
          ) : (
            <div style={{textAlign: 'center', padding: '2rem 0'}}>
               <input type="file" onChange={(e) => setFile(e.target.files[0])} style={{display: 'none'}} id="upload" />
               <button onClick={() => document.getElementById('upload').click()} className="tab-btn" style={{border: '1px solid rgba(255,255,255,0.2)', borderRadius: '8px'}}>
                 {file ? file.name : "SELECT PROJECT ZIP"}
               </button>
               <button onClick={handleUpload} className="action-btn" disabled={loading || !file}>
                 {loading ? 'EXTRACTING TO RAM...' : 'ANALYZE PROJECT'}
               </button>
            </div>
          )}
        </div>

        {results && (
          <div className="glass-panel" style={{display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center', border: `1px solid ${results.security_score > 75 ? 'rgba(16, 185, 129, 0.4)' : 'rgba(244, 63, 94, 0.4)'}`}}>
            <div className="metric-label">System Integrity</div>
            <div className="metric-value" style={{color: results.security_score > 75 ? 'var(--accent-emerald)' : 'var(--accent-rose)'}}>
              {results.security_score}%
            </div>
            <div className="metric-label" style={{marginTop: '1rem'}}>Active Threats: {results.issues.length}</div>
          </div>
        )}
      </div>

      {/* THREAT INTELLIGENCE FEED */}
      {results && results.issues.length > 0 && (
        <div className="threat-feed">
          <h3 style={{marginBottom: '1.5rem', fontFamily: 'JetBrains Mono', color: 'var(--text-muted)'}}>// INTELLIGENCE & REMEDIATION LOG</h3>

          {results.issues.map((issue, index) => (
            <div key={index} className="threat-card">
              <div className="threat-header">
                <span className="file-badge">Target: {issue.file}</span>
                <span className="status-badge critical" style={{background: 'transparent', padding: 0}}>{issue.severity} RISK</span>
              </div>

              {/* THE SPLIT DIFF VIEWER */}
              <div className="diff-grid">
                <div className="diff-pane vuln">
                  <div className="diff-title red">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 6L6 18M6 6l12 12"/></svg>
                    VULNERABLE PATH
                  </div>
                  <div className="code-line">
                    <span className="line-num">{issue.line !== "N/A" ? issue.line : '--'}</span>
                    <span className="code-content highlight-red">{issue.code}</span>
                  </div>
                </div>

                {issue.fixed_code && (
                  <div className="diff-pane safe">
                    <div className="diff-title green">
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M20 6L9 17l-5-5"/></svg>
                      SECURE REMEDIATION
                    </div>
                    {issue.fixed_code.split('\n').map((line, i) => (
                      <div className="code-line" key={i}>
                        <span className="line-num">+</span>
                        <span className="code-content highlight-green">{line}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* AI INSIGHTS BENTO */}
              <div className="intelligence-bar">
                <div className="intel-box">
                  <h4>Diagnostic Vector</h4>
                  <p>{issue.explanation}</p>
                </div>
                <div className="intel-box">
                  <h4>Exploit Reality</h4>
                  <p>{issue.teach_back}</p>
                </div>
                <div className="intel-box">
                  <h4 style={{color: 'var(--accent-emerald)'}}>Resolution Protocol</h4>
                  <p>{issue.remediation}</p>
                </div>
              </div>

            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default App