import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  AlertOctagon, Terminal, UploadCloud,
  Cpu, Activity, AlertTriangle, Zap,
  CheckCircle2, Package, Key, Brain
} from 'lucide-react'
import './App.css'

const ScanLine = ({ scanning }) => (
  <motion.div
    className="scan-line"
    animate={scanning ? { top: ['0%', '100%'], opacity: [0, 1, 0] } : { opacity: 0 }}
    transition={{ duration: 1.5, repeat: Infinity, ease: "linear" }}
  />
)

/* ── Sentinel-AI Neural Eye Logo ── */
const SentinelLogo = ({ size = 52 }) => (
  <svg width={size} height={size} viewBox="0 0 120 120" fill="none" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="gold1" x1="20" y1="10" x2="100" y2="110" gradientUnits="userSpaceOnUse">
        <stop offset="0%"   stopColor="#F5E6C0"/>
        <stop offset="40%"  stopColor="#D4A85A"/>
        <stop offset="100%" stopColor="#8A6030"/>
      </linearGradient>
      <linearGradient id="gold2" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0%"   stopColor="#FFF0C8"/>
        <stop offset="100%" stopColor="#C89050"/>
      </linearGradient>
      <filter id="glow" x="-60%" y="-60%" width="220%" height="220%">
        <feGaussianBlur stdDeviation="2.5" result="b"/>
        <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
      <filter id="nodeglow" x="-120%" y="-120%" width="340%" height="340%">
        <feGaussianBlur stdDeviation="2" result="b"/>
        <feMerge><feMergeNode in="b"/><feMergeNode in="SourceGraphic"/></feMerge>
      </filter>
    </defs>

    {/*
      Pentagon shield — wide, cat-ear top corners, tapers to bottom point
      Matches reference: wide body, two protruding top corners
    */}
    <path d="M60 6 L90 20 L104 52 C104 76 82 96 60 105 C38 96 16 76 16 52 L30 20 Z"
      stroke="url(#gold1)" strokeWidth="2" fill="rgba(212,168,90,0.04)" filter="url(#glow)"/>

    {/*
      NODE POSITIONS (matching reference exactly):
      N1  = top-center        (60, 10)
      N2  = top-left ear      (28, 18)
      N3  = top-right ear     (92, 18)
      N4  = mid-left          (14, 42)
      N5  = mid-right         (106, 42)
      N6  = left-orbit        (18, 62)  — on horizontal orbit ring
      N7  = right-orbit       (102, 62) — on horizontal orbit ring
      N8  = lower-left        (30, 82)
      N9  = lower-right       (90, 82)
      N10 = bottom-tip        (60, 98)
      N11 = inner-top         (60, 28)  — where top line meets inner shape
    */}

    {/* ── Network lines (drawn BEFORE nodes so nodes sit on top) ── */}

    {/* Top fan */}
    <line x1="60" y1="10" x2="28" y2="18" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.95"/>
    <line x1="60" y1="10" x2="92" y2="18" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.95"/>
    <line x1="28" y1="18" x2="92" y2="18" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.8"/>

    {/* Ears down to mid */}
    <line x1="28" y1="18" x2="14" y2="42" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>
    <line x1="92" y1="18" x2="106" y2="42" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>

    {/* Top-center down to inner-top node */}
    <line x1="60" y1="10" x2="60" y2="28" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>

    {/* Inner-top connects across and down */}
    <line x1="60" y1="28" x2="28" y2="18" stroke="url(#gold1)" strokeWidth="1" opacity="0.7"/>
    <line x1="60" y1="28" x2="92" y2="18" stroke="url(#gold1)" strokeWidth="1" opacity="0.7"/>
    <line x1="60" y1="28" x2="14" y2="42" stroke="url(#gold1)" strokeWidth="0.8" opacity="0.45"/>
    <line x1="60" y1="28" x2="106" y2="42" stroke="url(#gold1)" strokeWidth="0.8" opacity="0.45"/>

    {/* Mid row horizontal */}
    <line x1="14" y1="42" x2="106" y2="42" stroke="url(#gold1)" strokeWidth="1" opacity="0.65"/>

    {/* Mid to orbit level */}
    <line x1="14" y1="42" x2="18" y2="62" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>
    <line x1="106" y1="42" x2="102" y2="62" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>

    {/* Orbit level horizontal */}
    <line x1="18" y1="62" x2="102" y2="62" stroke="url(#gold1)" strokeWidth="1" opacity="0.6"/>

    {/* Orbit to lower */}
    <line x1="18" y1="62" x2="30" y2="82" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>
    <line x1="102" y1="62" x2="90" y2="82" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>

    {/* Lower V to tip */}
    <line x1="30" y1="82" x2="90" y2="82" stroke="url(#gold1)" strokeWidth="1" opacity="0.7"/>
    <line x1="30" y1="82" x2="60" y2="98" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>
    <line x1="90" y1="82" x2="60" y2="98" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>

    {/* Extra cross-diagonals (visible in reference) */}
    <line x1="28" y1="18" x2="18" y2="62" stroke="url(#gold1)" strokeWidth="0.8" opacity="0.35"/>
    <line x1="92" y1="18" x2="102" y2="62" stroke="url(#gold1)" strokeWidth="0.8" opacity="0.35"/>
    <line x1="14" y1="42" x2="30" y2="82" stroke="url(#gold1)" strokeWidth="0.8" opacity="0.35"/>
    <line x1="106" y1="42" x2="90" y2="82" stroke="url(#gold1)" strokeWidth="0.8" opacity="0.35"/>

    {/* ── Orbit rings (very prominent in reference) ── */}
    {/* Horizontal ellipse */}
    <ellipse cx="60" cy="58" rx="38" ry="17" stroke="url(#gold1)" strokeWidth="1.4" fill="none" opacity="0.75" filter="url(#glow)"/>
    {/* Vertical ellipse */}
    <ellipse cx="60" cy="58" rx="17" ry="36" stroke="url(#gold1)" strokeWidth="1.4" fill="none" opacity="0.5"/>

    {/* ── Nodes (on top of lines) ── */}
    <circle cx="60"  cy="10" r="3.2" fill="url(#gold2)" filter="url(#nodeglow)"/>
    <circle cx="28"  cy="18" r="2.8" fill="url(#gold2)" filter="url(#nodeglow)"/>
    <circle cx="92"  cy="18" r="2.8" fill="url(#gold2)" filter="url(#nodeglow)"/>
    <circle cx="14"  cy="42" r="2.8" fill="url(#gold2)" filter="url(#nodeglow)"/>
    <circle cx="106" cy="42" r="2.8" fill="url(#gold2)" filter="url(#nodeglow)"/>
    <circle cx="18"  cy="62" r="2.8" fill="url(#gold2)" filter="url(#nodeglow)"/>
    <circle cx="102" cy="62" r="2.8" fill="url(#gold2)" filter="url(#nodeglow)"/>
    <circle cx="30"  cy="82" r="2.8" fill="url(#gold2)" filter="url(#nodeglow)"/>
    <circle cx="90"  cy="82" r="2.8" fill="url(#gold2)" filter="url(#nodeglow)"/>
    <circle cx="60"  cy="98" r="3.2" fill="url(#gold2)" filter="url(#nodeglow)"/>
    <circle cx="60"  cy="28" r="2.4" fill="url(#gold2)" filter="url(#nodeglow)"/>

    {/* ── Eye ── */}
    {/* Outer ring */}
    <circle cx="60" cy="58" r="18" stroke="url(#gold1)" strokeWidth="1.5" fill="rgba(212,168,90,0.06)" filter="url(#glow)"/>
    {/* Iris */}
    <circle cx="60" cy="58" r="12" stroke="url(#gold1)" strokeWidth="1.2" fill="rgba(212,168,90,0.1)"/>
    {/* Pupil */}
    <circle cx="60" cy="58" r="6.5" fill="url(#gold1)" filter="url(#nodeglow)"/>
    {/* Crescent shadow (offset to create crescent moon look) */}
    <circle cx="57"  cy="55"  r="4"   fill="rgba(6,10,16,0.78)"/>
    {/* Glint */}
    <circle cx="65"  cy="53"  r="2.2" fill="rgba(255,250,225,0.72)"/>
  </svg>
)

function App() {
  const [activeTab, setActiveTab] = useState('live')
  const [liveCode, setLiveCode] = useState('')
  const [file, setFile] = useState(null)
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState(null)
  const [cursorPos, setCursorPos] = useState({ x: 0, y: 0 })
  const [cursorHovered, setCursorHovered] = useState(false)
  const vantaRef = useRef(null)
  const vantaEffect = useRef(null)

  useEffect(() => {
    const moveCursor = (e) => setCursorPos({ x: e.clientX, y: e.clientY })
    window.addEventListener('mousemove', moveCursor)
    return () => window.removeEventListener('mousemove', moveCursor)
  }, [])

  useEffect(() => {
    const initVanta = () => {
      if (window.VANTA && window.VANTA.GLOBE && vantaRef.current && !vantaEffect.current) {
        vantaEffect.current = window.VANTA.GLOBE({
          el: document.body,
          mouseControls: true,
          touchControls: true,
          gyroControls: false,
          minHeight: window.innerHeight,
          minWidth: window.innerWidth,
          scale: 1.00,
          scaleMobile: 1.00,
          color: 0xC4B49A,
          color2: 0x5A6270,
          backgroundColor: 0x0d1117,
          size: 1.2,
          points: 10,
          maxDistance: 22,
          spacing: 17
        })
      }
    }

    if (window.VANTA && window.VANTA.GLOBE) {
      initVanta()
    } else {
      const threeScript = document.createElement('script')
      threeScript.src = 'https://cdnjs.cloudflare.com/ajax/libs/three.js/r134/three.min.js'
      threeScript.onload = () => {
        const vantaScript = document.createElement('script')
        vantaScript.src = 'https://cdn.jsdelivr.net/npm/vanta@0.5.24/dist/vanta.globe.min.js'
        vantaScript.onload = initVanta
        document.head.appendChild(vantaScript)
      }
      document.head.appendChild(threeScript)
    }

    return () => {
      if (vantaEffect.current) {
        vantaEffect.current.destroy()
        vantaEffect.current = null
      }
    }
  }, [])

const handleUpload = async () => {
    if (!file) return
    setLoading(true)
    const formData = new FormData()
    formData.append("file", file)
    try {
      const baseUrl = import.meta.env.VITE_API_URL || "https://vedansh0110-sentinel-ai-backend.hf.space"
      const resp = await fetch(`${baseUrl}/api/scan`, { method: "POST", body: formData })
      const data = await resp.json()
      setTimeout(() => setResults(data), 1000)
    } catch (error) {
      console.error("Scan failed:", error)
    } finally {
      setTimeout(() => setLoading(false), 1000)
    }
  }

  const handleLiveScan = async () => {
    if (!liveCode.trim()) return
    setLoading(true)
    try {
      const baseUrl = import.meta.env.VITE_API_URL || "https://vedansh0110-sentinel-ai-backend.hf.space"
      const resp = await fetch(`${baseUrl}/api/scan-live`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code: liveCode, filename: "live_editor.py" })
      })
      const data = await resp.json()
      setTimeout(() => setResults(data), 1500)
    } catch (error) {
      console.error("Live scan failed:", error)
    } finally {
      setTimeout(() => setLoading(false), 1500)
    }
  }

  const LinkedInIcon = () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
      <path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-2-2 2 2 0 0 0-2 2v7h-4v-7a6 6 0 0 1 6-6z"/>
      <rect x="2" y="9" width="4" height="12"/>
      <circle cx="4" cy="4" r="2"/>
    </svg>
  )

  const GitHubIcon = () => (
    <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
      <path d="M9 19c-5 1.5-5-2.5-7-3m14 6v-3.87a3.37 3.37 0 0 0-.94-2.61c3.14-.35 6.44-1.54 6.44-7A5.44 5.44 0 0 0 20 4.77 5.07 5.07 0 0 0 19.91 1S18.73.65 16 2.48a13.38 13.38 0 0 0-7 0C6.27.65 5.09 1 5.09 1A5.07 5.07 0 0 0 5 4.77a5.44 5.44 0 0 0-1.5 3.78c0 5.42 3.3 6.61 6.44 7A3.37 3.37 0 0 0 9 18.13V22"/>
    </svg>
  )

  return (
    <div ref={vantaRef} className="app-root">
      <div
        className={`custom-cursor ${cursorHovered ? 'hovered' : ''}`}
        style={{ left: cursorPos.x, top: cursorPos.y }}
      />

      <div className="grid-overlay" />

      <div className="dashboard-layout">

        <aside className="sidebar">
          {/* Logo at top */}
          <div className="sidebar-logo">
            <SentinelLogo size={52} />
          </div>

          {/* Creator links at bottom */}
          <div className="sidebar-bottom">

            {/* Yash Bhatia */}
            <div className="creator-block">
              <div className="creator-avatar">YB</div>
              <div className="creator-popout">
                <div className="creator-name">Yash Bhatia</div>
                <div className="creator-links">
                  <a href="https://www.linkedin.com/in/yash-bhatia-21790b223/" target="_blank" rel="noopener noreferrer" className="creator-link linkedin">
                    <LinkedInIcon /> LinkedIn
                  </a>
                  <a href="https://github.com/atlantis-04" target="_blank" rel="noopener noreferrer" className="creator-link github">
                    <GitHubIcon /> GitHub
                  </a>
                </div>
              </div>
            </div>

            {/* Vedansh Agarwal */}
            <div className="creator-block">
              <div className="creator-avatar">VA</div>
              <div className="creator-popout">
                <div className="creator-name">Vedansh Agarwal</div>
                <div className="creator-links">
                  <a href="https://www.linkedin.com/in/vedanshagarwal9821/" target="_blank" rel="noopener noreferrer" className="creator-link linkedin">
                    <LinkedInIcon /> LinkedIn
                  </a>
                  <a href="https://github.com/Morpheus-xz" target="_blank" rel="noopener noreferrer" className="creator-link github">
                    <GitHubIcon /> GitHub
                  </a>
                </div>
              </div>
            </div>

            {/* Suryansh Raj Singh */}
            <div className="creator-block">
              <div className="creator-avatar">SR</div>
              <div className="creator-popout">
                <div className="creator-name">Suryansh Raj Singh</div>
                <div className="creator-links">
                  <a href="https://www.linkedin.com/in/suryansh-raj-singh-a40b09328/" target="_blank" rel="noopener noreferrer" className="creator-link linkedin">
                    <LinkedInIcon /> LinkedIn
                  </a>
                  <a href="https://github.com/suryanshhh445" target="_blank" rel="noopener noreferrer" className="creator-link github">
                    <GitHubIcon /> GitHub
                  </a>
                </div>
              </div>
            </div>

          </div>
        </aside>

        <main className="main-content">

          <header className="top-header">
            <div>
              <div className="hero-subtitle">
                <Zap size={14} style={{display:'inline', marginBottom:-2}} /> Protect your proprietary code with local AI. SENTINEL detects critical vulnerabilities and instantly writes secure fixes directly on your machine. &nbsp;·&nbsp;
              </div>
              <h1 className="hero-title">Finds Flaws. Writes Fixes.</h1>
            </div>

            <div className="hardware-status">
              <div className="hw-badge">
                <span className="hw-dot pulse-active"></span> NODE: ONLINE
              </div>
              <div className="hw-badge">
                <span className="hw-dot pulse-stable"></span> LATENCY: 12ms
              </div>
            </div>
          </header>

          <div className="bento-grid">

            <motion.div
              className="glass-card main-input"
              initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.1 }}
              onMouseEnter={() => setCursorHovered(true)} onMouseLeave={() => setCursorHovered(false)}
            >
              <div className="tab-switcher">
                {['live', 'upload'].map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`tab-btn ${activeTab === tab ? 'active' : ''}`}
                  >
                    {tab === 'live' ? 'CODE SNIPPET' : 'ZIP FILE'}
                    {activeTab === tab && (
                      <motion.div layoutId="tab-underline" className="tab-underline" />
                    )}
                  </button>
                ))}
              </div>

              <div className="editor-wrapper">
                <ScanLine scanning={loading} />
                <AnimatePresence mode="wait">
                  {activeTab === 'live' ? (
                    <motion.textarea
                      key="editor"
                      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                      className="code-area"
                      value={liveCode}
                      onChange={(e) => setLiveCode(e.target.value)}
                      placeholder="> Paste code snippet, prompt template, or LLM chain logic here..."
                      spellCheck="false"
                    />
                  ) : (
                    <motion.div
                      key="upload"
                      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                      className="upload-area"
                    >
                      <input
                        type="file" id="file-upload"
                        onChange={(e) => setFile(e.target.files[0])} style={{display: 'none'}}
                      />
                      <UploadCloud size={64} color="var(--color-light)" style={{marginBottom: '1rem'}} />
                      <p style={{fontFamily: 'JetBrains Mono', fontSize: '0.75rem', color: 'rgba(250,250,250,0.4)', marginBottom: '1rem', textAlign: 'center'}}>
                        .zip (UPLOAD ONLY ZIP FILES)
                      </p>
                      <button
                        onClick={() => document.getElementById('file-upload').click()}
                        className="upload-btn"
                      >
                        {file ? file.name : "SELECT FILE"}
                      </button>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              <button
                className="cyber-btn"
                onClick={activeTab === 'live' ? handleLiveScan : handleUpload}
                disabled={loading || (activeTab === 'live' ? !liveCode : !file)}
              >
                {loading ? (
                  <span style={{display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '10px'}}>
                    <Activity className="spin" size={18} /> PROCESSING VECTORS
                  </span>
                ) : (
                  'INITIATE DIAGNOSTIC'
                )}
              </button>
            </motion.div>

            <motion.div
              className="glass-card status-panel"
              initial={{ y: 20, opacity: 0 }} animate={{ y: 0, opacity: 1 }} transition={{ delay: 0.2 }}
            >
              <div className="panel-header">
                <Cpu size={18} color="var(--color-light)" />
                <h3>SYSTEM METRICS</h3>
              </div>

              {results ? (
                <div className="results-display">
                  <div className="score-container">
                    {(() => {
                      const score = results.security_score
                      const color = score < 50
                        ? { from: '#E87A7A', to: '#C0392B', glow: 'rgba(232, 122, 122, 0.4)' }
                        : score <= 75
                        ? { from: '#F5C842', to: '#D4A017', glow: 'rgba(245, 200, 66, 0.4)' }
                        : { from: '#6FCF97', to: '#27AE60', glow: 'rgba(111, 207, 151, 0.4)' }
                      return (
                        <motion.div
                          initial={{ scale: 0 }} animate={{ scale: 1 }}
                          style={{
                            fontSize: '6rem', fontWeight: '800', lineHeight: 1,
                            background: `linear-gradient(135deg, ${color.from} 0%, ${color.to} 100%)`,
                            WebkitBackgroundClip: 'text',
                            WebkitTextFillColor: 'transparent',
                            filter: `drop-shadow(0 0 20px ${color.glow})`
                          }}
                        >
                          {score}
                        </motion.div>
                      )
                    })()}
                    <div className="score-label">INTEGRITY SCORE</div>
                  </div>

                  <div className="stats-grid">
                    <div className="stat-box">
                      <div className="stat-val" style={{color: 'var(--color-light)'}}>{results.issues.length}</div>
                      <div className="stat-label">CVEs Detected</div>
                    </div>
                    <div className="stat-box">
                      <div className="stat-val" style={{color: 'var(--color-light)'}}>
                        {results.is_air_gapped
                          ? <AlertTriangle size={28} />
                          : <AlertOctagon size={28} />}
                      </div>
                      <div className="stat-label">Prompt Vulnerabilities</div>
                    </div>
                  </div>

                  <div className="sys-checks">
                    <div className="check-item"><CheckCircle2 size={16} color="var(--color-light)" /> Tracks vulnerable data flows.</div>
                    <div className="check-item"><CheckCircle2 size={16} color="var(--color-light)" /> Local AI detects threats.</div>
                    <div className="check-item"><CheckCircle2 size={16} color="var(--color-light)" /> Auto-writes secure patches.</div>
                  </div>
                </div>
              ) : (
                <div className="empty-state">
                  <Terminal size={56} style={{opacity: 0.1, marginBottom: '1.5rem', color: 'var(--color-light)'}} />
                  <p>AWAITING DATA STREAM</p>
                </div>
              )}
            </motion.div>

          </div>

          <AnimatePresence>
            {results && results.issues.length > 0 && (
              <motion.div className="vuln-feed">
                <div className="panel-header" style={{marginBottom: '1rem'}}>
                  <AlertOctagon size={18} color="var(--color-light)" />
                  <h3>DETECTED ANOMALIES</h3>
                </div>
                {results.issues.map((issue, idx) => {
                  const type = issue.type || issue.category || ''
                  let badgeClass = 'badge-dep-cve'
                  let badgeLabel = 'DEPENDENCY_CVE'
                  let BadgeIcon = Package
                  if (/inject|prompt|sanitiz/i.test(type + issue.explanation)) {
                    badgeClass = 'badge-prompt'; badgeLabel = 'PROMPT_INJECTION'; BadgeIcon = Brain
                  } else if (/secret|key|token|api.?key|leak/i.test(type + issue.explanation)) {
                    badgeClass = 'badge-secret'; badgeLabel = 'SECRET_LEAK'; BadgeIcon = Key
                  } else if (/hallucin|unchecked|llm.?output|generat/i.test(type + issue.explanation)) {
                    badgeClass = 'badge-hallucin'; badgeLabel = 'AI_HALLUCINATION_RISK'; BadgeIcon = Brain
                  }

                  return (
                    <motion.div
                      key={idx} className="vuln-card"
                      initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: idx * 0.1 }}
                    >
                      <div className="vuln-card-header">
                        <div style={{display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap'}}>
                          <span className="badge-critical">CRITICAL</span>
                          <span className={`badge-category ${badgeClass}`}>
                            <BadgeIcon size={11} style={{display:'inline', marginBottom:-1}} /> [{badgeLabel}]
                          </span>
                          <span style={{fontFamily: 'JetBrains Mono'}}>{issue.file}</span>
                        </div>
                        <span style={{color: 'var(--color-light)', opacity: 0.7, fontSize: '0.8rem', fontFamily: 'JetBrains Mono'}}>LN {issue.line}</span>
                      </div>

                      <div className="diff-grid">
                        <div className="diff-pane">
                          <div className="diff-title danger">VULNERABLE SEGMENT</div>
                          <code className="code-block danger">{issue.code}</code>
                        </div>
                        {issue.fixed_code && (
                          <div className="diff-pane safe-pane">
                            <div className="diff-title success">SUGGESTED PATCH</div>
                            <code className="code-block success">{issue.fixed_code}</code>
                          </div>
                        )}
                      </div>

                      <div className="vuln-analysis">
                        <h4>Vector Analysis</h4>
                        <p>{issue.explanation}</p>
                        <div className="remediation-box">
                          <h4>Remediation Protocol</h4>
                          <p>{issue.remediation}</p>
                        </div>
                      </div>
                    </motion.div>
                  )
                })}
              </motion.div>
            )}
          </AnimatePresence>

        </main>
      </div>
    </div>
  )
}

export default App