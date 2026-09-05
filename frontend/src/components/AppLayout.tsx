import { BookOpen, ChevronDown, Clock3, Code2, FileDiff, LogOut, Plus, Settings, ShieldCheck } from 'lucide-react'
import { useState } from 'react'
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'

export default function AppLayout() {
  const { user, logout } = useAuth()
  const location = useLocation()
  const navigate = useNavigate()
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const userName = user?.displayName || user?.email || 'User'
  const analysisMatch = location.pathname.match(/^\/analyses\/([^/]+)$/)
  const analysisId = analysisMatch?.[1]

  const onLogout = async () => { await logout(); navigate('/login') }

  if (analysisId) {
    const base = `/analyses/${analysisId}`
    return <div className="app-shell analysis-shell">
      <aside className="analysis-rail" aria-label="Analysis tools">
        <Link className="analysis-rail-brand" to="/"><ShieldCheck size={20} /></Link>
        <nav><Link to="/analyses" title="Library"><BookOpen size={19} /></Link><Link to={`${base}?view=analysis&tab=code`} title="Code and findings"><Code2 size={19} /></Link><Link to={`${base}?view=patch`} title="Patch workspace"><FileDiff size={19} /></Link></nav>
        <Link className="analysis-rail-settings" to="/settings" title="Settings"><Settings size={18} /></Link>
      </aside>
      <main className="main-area"><Outlet /></main>
    </div>
  }

  return <div className="app-shell library-shell">
    <aside className="library-sidebar">
      <Link className="library-brand" to="/" aria-label="LLM Security product home"><span><ShieldCheck size={20} /></span><strong>LLM Security</strong></Link>
      <nav className="library-side-nav" aria-label="Library navigation"><NavLink to="/analyses" end><Clock3 size={17} /> Recent analyses</NavLink><Link to="/analyses?new=1"><Plus size={17} /> New analysis</Link></nav>
      <div className="library-sidebar-bottom"><button className="library-user" onClick={() => setUserMenuOpen((open) => !open)} aria-expanded={userMenuOpen}><span>{userName[0].toUpperCase()}</span><strong>{userName}</strong><ChevronDown size={15} /></button>{userMenuOpen && <div className="library-user-menu"><Link to="/settings"><Settings size={15} /> Settings</Link><button onClick={onLogout}><LogOut size={15} /> Log out</button></div>}</div>
    </aside>
    <main className="main-area"><Outlet /></main>
  </div>
}
