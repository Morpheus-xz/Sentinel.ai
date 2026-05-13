import { useState, useEffect, useRef } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import {
  AlertOctagon, Terminal, UploadCloud,
  Cpu, Activity, AlertTriangle, Zap,
  CheckCircle2, Package, Key, Brain,
  History, Trash2, ChevronRight
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

    <path d="M60 6 L90 20 L104 52 C104 76 82 96 60 105 C38 96 16 76 16 52 L30 20 Z"
      stroke="url(#gold1)" strokeWidth="2" fill="rgba(212,168,90,0.04)" filter="url(#glow)"/>

    <line x1="60" y1="10" x2="28" y2="18" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.95"/>
    <line x1="60" y1="10" x2="92" y2="18" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.95"/>
    <line x1="28" y1="18" x2="92" y2="18" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.8"/>
    <line x1="28" y1="18" x2="14" y2="42" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>
    <line x1="92" y1="18" x2="106" y2="42" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>
    <line x1="60" y1="10" x2="60" y2="28" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>
    <line x1="60" y1="28" x2="28" y2="18" stroke="url(#gold1)" strokeWidth="1" opacity="0.7"/>
    <line x1="60" y1="28" x2="92" y2="18" stroke="url(#gold1)" strokeWidth="1" opacity="0.7"/>
    <line x1="60" y1="28" x2="14" y2="42" stroke="url(#gold1)" strokeWidth="0.8" opacity="0.45"/>
    <line x1="60" y1="28" x2="106" y2="42" stroke="url(#gold1)" strokeWidth="0.8" opacity="0.45"/>
    <line x1="14" y1="42" x2="106" y2="42" stroke="url(#gold1)" strokeWidth="1" opacity="0.65"/>
    <line x1="14" y1="42" x2="18" y2="62" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>
    <line x1="106" y1="42" x2="102" y2="62" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>
    <line x1="18" y1="62" x2="102" y2="62" stroke="url(#gold1)" strokeWidth="1" opacity="0.6"/>
    <line x1="18" y1="62" x2="30" y2="82" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>
    <line x1="102" y1="62" x2="90" y2="82" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>
    <line x1="30" y1="82" x2="90" y2="82" stroke="url(#gold1)" strokeWidth="1" opacity="0.7"/>
    <line x1="30" y1="82" x2="60" y2="98" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>
    <line x1="90" y1="82" x2="60" y2="98" stroke="url(#gold1)" strokeWidth="1.1" opacity="0.9"/>
    <line x1="28" y1="18" x2="18" y2="62" stroke="url(#gold1)" strokeWidth="0.8" opacity="0.35"/>
    <line x1="92" y1="18" x2="102" y2="62" stroke="url(#gold1)" strokeWidth="0.8" opacity="0.35"/>
    <line x1="14" y1="42" x2="30" y2="82" stroke="url(#gold1)" strokeWidth="0.8" opacity="0.35"/>
    <line x1="106" y1="42" x2="90" y2="82" stroke="url(#gold1)" strokeWidth="0.8" opacity="0.35"/>

    <ellipse cx="60" cy="58" rx="38" ry="17" stroke="url(#gold1)" strokeWidth="1.4" fill="none" opacity="0.75" filter="url(#glow)"/>
    <ellipse cx="60" cy="58" rx="17" ry="36" stroke="url(#gold1)" strokeWidth="1.4" fill="none" opacity="0.5"/>

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

    <circle cx="60" cy="58" r="18" stroke="url(#gold1)" strokeWidth="1.5" fill="rgba(212,168,90,0.06)" filter="url(#glow)"/>
    <circle cx="60" cy="58" r="12" stroke="url(#gold1)" strokeWidth="1.2" fill="rgba(212,168,90,0.1)"/>
    <circle cx="60" cy="58" r="6.5" fill="url(#gold1)" filter="url(#nodeglow)"/>
    <circle cx="57"  cy="55"  r="4"   fill="rgba(6,10,16,0.78)"/>
    <circle cx="65"  cy="53"  r="2.2" fill="rgba(255,250,225,0.72)"/>
  </svg>
)

// ── HISTORY STORAGE KEY ──────────────────────────────────────────────
const HISTORY_KEY = 'sentinel_scan_history'
const MAX_HISTORY = 20   // keep last 20 scans — prevents localStorage bloat

// ── HELPER: score → color (reused in history list + main panel) ──────
const scoreColor = (score) =>
  score < 50
    ? { main: '#E87A7A', glow: 'rgba(232,122,122,0.5)' }
    : score <= 75
    ? { main: '#F5C842', glow: 'rgba(245,200,66,0.5)' }
    : { main: '#6FCF97', glow: 'rgba(111,207,151,0.5)' }

// ── HELPER: compute diff between two issue arrays ────────────────────
const computeDiff = (currentIssues, previousIssues) => {
  const sig = (i) => `${i.file}:${i.line}:${i.type}`
  const currentSigs  = new Set(currentIssues.map(sig))
  const previousSigs = new Set(previousIssues.map(sig))
  return {
    fixed:     previousIssues.filter(i => !currentSigs.has(sig(i))),
    newIssues: currentIssues.filter(i =>  !previousSigs.has(sig(i))),
    unchanged: currentIssues.filter(i =>  previousSigs.has(sig(i))),
  }
}

// ── HISTORY PANEL — module-level: never re-creates on parent render ──
const HistoryPanel = ({ history, selectedHistory, onSelect, onClear }) => {
  if (history.length === 0) {
    return (
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center',
        justifyContent: 'center', height: '100%', gap: '1rem', opacity: 0.4,
        pointerEvents: 'none'
      }}>
        <History size={48} color="var(--color-light)" />
        <p style={{ fontFamily: 'JetBrains Mono', fontSize: '0.75rem', color: 'rgba(250,250,250,0.5)', textAlign: 'center' }}>
          NO SCAN HISTORY YET<br/>RUN A SCAN TO BEGIN TRACKING
        </p>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <div style={{
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
        marginBottom: '0.75rem', flexShrink: 0
      }}>
        <span style={{ fontFamily: 'JetBrains Mono', fontSize: '0.7rem', color: 'rgba(250,250,250,0.4)', letterSpacing: '0.08em' }}>
          {history.length} SCAN{history.length !== 1 ? 'S' : ''} STORED
        </span>
        <button onClick={onClear} style={{
          background: 'transparent', border: 'none', cursor: 'pointer',
          display: 'flex', alignItems: 'center', gap: '4px',
          color: 'rgba(232,122,122,0.7)', fontSize: '0.7rem', fontFamily: 'JetBrains Mono', padding: '2px 6px'
        }}>
          <Trash2 size={11} /> CLEAR ALL
        </button>
      </div>

      <div style={{ overflowY: 'auto', flex: 1, display: 'flex', flexDirection: 'column', gap: '6px' }}>
        {history.map((entry, idx) => {
          const color      = scoreColor(entry.score)
          const isSelected = selectedHistory?.id === entry.id
          const dt         = new Date(entry.timestamp)
          const timeStr    = dt.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
          const dateStr    = dt.toLocaleDateString([], { month: 'short', day: 'numeric' })

          let diffBadge = null
          if (idx < history.length - 1) {
            const prev  = history[idx + 1]
            const diff  = computeDiff(entry.issues, prev.issues)
            const delta = entry.score - prev.score
            diffBadge = (
              <span style={{
                fontSize: '0.6rem', fontFamily: 'JetBrains Mono',
                color: delta >= 0 ? '#6FCF97' : '#E87A7A', marginLeft: '6px'
              }}>
                {delta >= 0 ? '▲' : '▼'}{Math.abs(delta)} · +{diff.newIssues.length} ✓{diff.fixed.length}
              </span>
            )
          }

          return (
            <div
              key={entry.id}
              onClick={() => onSelect(entry)}
              style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '10px 12px',
                background: isSelected ? 'rgba(212,168,90,0.08)' : 'rgba(255,255,255,0.03)',
                border: `1px solid ${isSelected ? 'rgba(212,168,90,0.35)' : 'rgba(255,255,255,0.06)'}`,
                borderRadius: '6px', cursor: 'pointer', flexShrink: 0,
                transition: 'background 0.15s, border-color 0.15s',
              }}
            >
              <div style={{ display: 'flex', flexDirection: 'column', gap: '3px', minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap' }}>
                  <span style={{
                    fontFamily: 'JetBrains Mono', fontSize: '0.72rem', color: 'rgba(250,250,250,0.85)',
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '160px'
                  }}>
                    {entry.label}
                  </span>
                  {diffBadge}
                </div>
                <span style={{ fontFamily: 'JetBrains Mono', fontSize: '0.6rem', color: 'rgba(250,250,250,0.3)' }}>
                  {dateStr} · {timeStr} · {entry.issueCount} issue{entry.issueCount !== 1 ? 's' : ''}
                </span>
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
                <span style={{
                  fontFamily: 'JetBrains Mono', fontWeight: '700', fontSize: '1rem',
                  color: color.main, textShadow: `0 0 12px ${color.glow}`
                }}>
                  {entry.score}
                </span>
                <ChevronRight size={12} color="rgba(250,250,250,0.25)" />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── DIFF SECTION — module-level: stable, no re-creation ─────────────
const DiffSection = ({ current, previous }) => {
  if (!previous) return null
  const diff = computeDiff(current.issues, previous.issues)
  if (diff.fixed.length === 0 && diff.newIssues.length === 0) return null

  return (
    <div className="vuln-feed" style={{ marginTop: '1rem' }}>
      <div className="panel-header" style={{ marginBottom: '1rem' }}>
        <Activity size={18} color="var(--color-light)" />
        <h3>DELTA ANALYSIS vs PREVIOUS SCAN</h3>
      </div>

      {diff.newIssues.length > 0 && (
        <div style={{ marginBottom: '1rem' }}>
          <div style={{ fontFamily: 'JetBrains Mono', fontSize: '0.7rem', color: '#E87A7A', marginBottom: '6px', letterSpacing: '0.08em' }}>
            ▲ {diff.newIssues.length} NEW ISSUE{diff.newIssues.length !== 1 ? 'S' : ''} INTRODUCED
          </div>
          {diff.newIssues.map((issue, idx) => (
            <div key={idx} style={{
              padding: '8px 12px', marginBottom: '4px',
              background: 'rgba(232,122,122,0.06)', border: '1px solid rgba(232,122,122,0.2)',
              borderRadius: '6px', fontFamily: 'JetBrains Mono', fontSize: '0.7rem', color: 'rgba(250,250,250,0.7)'
            }}>
              <span style={{ color: '#E87A7A' }}>+ NEW</span> &nbsp;
              {issue.file} LN {issue.line} — {issue.type}
            </div>
          ))}
        </div>
      )}

      {diff.fixed.length > 0 && (
        <div>
          <div style={{ fontFamily: 'JetBrains Mono', fontSize: '0.7rem', color: '#6FCF97', marginBottom: '6px', letterSpacing: '0.08em' }}>
            ✓ {diff.fixed.length} ISSUE{diff.fixed.length !== 1 ? 'S' : ''} RESOLVED
          </div>
          {diff.fixed.map((issue, idx) => (
            <div key={idx} style={{
              padding: '8px 12px', marginBottom: '4px',
              background: 'rgba(111,207,151,0.06)', border: '1px solid rgba(111,207,151,0.2)',
              borderRadius: '6px', fontFamily: 'JetBrains Mono', fontSize: '0.7rem', color: 'rgba(250,250,250,0.7)'
            }}>
              <span style={{ color: '#6FCF97' }}>✓ FIXED</span> &nbsp;
              {issue.file} LN {issue.line} — {issue.type}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function App() {
  const [activeTab, setActiveTab]     = useState('live')
  const [liveCode, setLiveCode]       = useState('')
  const [file, setFile]               = useState(null)
  const [loading, setLoading]         = useState(false)
  const [results, setResults]         = useState(null)
  const [cursorPos, setCursorPos]     = useState({ x: 0, y: 0 })
  const [cursorHovered, setCursorHovered] = useState(false)

  // ── NEW STATE: history list + which entry is selected ────────────
  const [history, setHistory]               = useState([])
  const [selectedHistory, setSelectedHistory] = useState(null)

  const vantaRef    = useRef(null)
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

  // ── NEW: load history from localStorage on mount ─────────────────
  useEffect(() => {
    try {
      const stored = localStorage.getItem(HISTORY_KEY)
      if (stored) setHistory(JSON.parse(stored))
    } catch (_) {}
  }, [])

  // ── NEW: save a completed scan to history ─────────────────────────
  const saveToHistory = (data, label) => {
    const entry = {
      id:        Date.now(),
      timestamp: new Date().toISOString(),
      label:     label || 'live_editor.py',
      score:     data.security_score,
      issueCount: data.issues.length,
      issues:    data.issues,
      mode:      data.mode || 'LIVE_INFERENCE',
    }
    setHistory(prev => {
      const updated = [entry, ...prev].slice(0, MAX_HISTORY)
      try { localStorage.setItem(HISTORY_KEY, JSON.stringify(updated)) } catch (_) {}
      return updated
    })
  }

  // ── NEW: clear all history ────────────────────────────────────────
  const clearHistory = () => {
    setHistory([])
    setSelectedHistory(null)
    try { localStorage.removeItem(HISTORY_KEY) } catch (_) {}
  }

  const handleUpload = async () => {
    if (!file) return
    setLoading(true)
    const formData = new FormData()
    formData.append("file", file)
    try {
      const baseUrl = import.meta.env.VITE_API_URL || "https://vedansh0110-sentinel-ai-backend.hf.space"
      const resp = await fetch(`${baseUrl}/api/scan`, { method: "POST", body: formData })
      const data = await resp.json()
      setTimeout(() => {
        setResults(data)
        saveToHistory(data, file.name)   // ← NEW: auto-save after upload scan
      }, 1000)
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
      setTimeout(() => {
        setResults(data)
        saveToHistory(data, 'live_editor.py')   // ← NEW: auto-save after live scan
      }, 1500)
    } catch (error) {
      console.error("Live scan failed:", error)
    } finally {
      setTimeout(() => setLoading(false), 1500)
    }
  }

  // ── NEW: load a history entry into the results panel ─────────────
  const loadHistoryEntry = (entry) => {
    setSelectedHistory(entry)
    setResults({ security_score: entry.score, issues: entry.issues, mode: entry.mode })
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
          <div className="sidebar-logo">
            <SentinelLogo size={52} />
          </div>

          <div className="sidebar-bottom">

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

            <div className="creator-block">
              <div className="creator-avatar">VR</div>
              <div className="creator-popout">
                <div className="creator-name">Vinay Rathore</div>
                <div className="creator-links">
                  <a href="https://www.linkedin.com/in/vinay-rathore-14249b328/" target="_blank" rel="noopener noreferrer" className="creator-link linkedin">
                    <LinkedInIcon /> LinkedIn
                  </a>
                  <a href="https://github.com/vinayR-cmd" target="_blank" rel="noopener noreferrer" className="creator-link github">
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
            >
              <div className="tab-switcher">
                {/* ── CHANGE: added 'history' to tab list ── */}
                {['live', 'upload', 'history'].map((tab) => (
                  <button
                    key={tab}
                    onClick={() => setActiveTab(tab)}
                    className={`tab-btn ${activeTab === tab ? 'active' : ''}`}
                  >
                    {tab === 'live' ? 'CODE SNIPPET' : tab === 'upload' ? 'ZIP FILE' : 'HISTORY'}
                    {activeTab === tab && (
                      <motion.div layoutId="tab-underline" className="tab-underline" />
                    )}
                  </button>
                ))}
              </div>

              <div className="editor-wrapper">
                <ScanLine scanning={loading && activeTab !== 'history'} />
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
                  ) : activeTab === 'upload' ? (
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
                  ) : (
                    /* ── NEW: history tab panel ── */
                    <motion.div
                      key="history"
                      initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
                      style={{ height: '100%' }}
                    >
                      <HistoryPanel
                        history={history}
                        selectedHistory={selectedHistory}
                        onSelect={loadHistoryEntry}
                        onClear={clearHistory}
                      />
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>

              {/* Hide the scan button when on history tab */}
              {activeTab !== 'history' && (
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
              )}
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
                      const color = scoreColor(score)   // ← uses extracted helper
                      return (
                        <motion.div
                          initial={{ scale: 0 }} animate={{ scale: 1 }}
                          style={{
                            fontSize: '6rem',
                            fontWeight: '800',
                            lineHeight: 1,
                            color: color.main,
                            textShadow: `0 0 30px ${color.glow}, 0 0 60px ${color.glow}`,
                          }}
                        >
                          {score}
                        </motion.div>
                      )
                    })()}
                    <div className="score-label">INTEGRITY SCORE</div>
                  </div>

                  {/* ── NEW: show "VIEWING HISTORY" badge when replaying a past scan ── */}
                  {selectedHistory && (
                    <div style={{
                      textAlign: 'center', marginBottom: '8px',
                      fontFamily: 'JetBrains Mono', fontSize: '0.6rem',
                      color: 'rgba(212,168,90,0.7)', letterSpacing: '0.08em'
                    }}>
                      ◈ REPLAYING: {new Date(selectedHistory.timestamp).toLocaleString([], {
                        month: 'short', day: 'numeric',
                        hour: '2-digit', minute: '2-digit'
                      })}
                    </div>
                  )}

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
                  if (type === 'DATA_FLOW_EXPLOIT') {
                    badgeClass = 'badge-prompt'; badgeLabel = 'DATA_FLOW_EXPLOIT'; BadgeIcon = AlertOctagon
                  } else if (/inject|prompt|sanitiz/i.test(type + issue.explanation)) {
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

          {/* ── NEW: diff analysis shown below vuln-feed when viewing history ── */}
          {selectedHistory && results && (() => {
            const idx = history.findIndex(h => h.id === selectedHistory.id)
            const previousEntry = history[idx + 1]
            return previousEntry
              ? <DiffSection current={selectedHistory} previous={previousEntry} />
              : null
          })()}

        </main>
      </div>
    </div>
  )
}

export default App