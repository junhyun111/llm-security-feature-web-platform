import {
  ChevronDown,
  FolderKanban,
  Home,
  LogOut,
  Plus,
  Settings,
  ShieldCheck
} from 'lucide-react'
import { useState } from 'react'
import { Link, NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'

export default function AppLayout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const userName = user?.displayName || user?.email || 'User'

  const onLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <div className="app-shell">
      <aside className="workspace-sidebar">
        <Link className="workspace-brand" to="/" aria-label="LLM Security product home">
          <span className="brand-mark"><ShieldCheck size={20} /></span>
          <strong>LLM Security</strong>
        </Link>

        <nav className="workspace-nav" aria-label="Workspace navigation">
          <span className="workspace-nav-label">WORKSPACE</span>
          <NavLink to="/home"><Home size={17} /> Home</NavLink>
          <NavLink to="/analyses" end><FolderKanban size={17} /> All projects</NavLink>
          <Link className="new-analysis-nav" to="/analyses/new"><Plus size={17} /> New analysis</Link>
        </nav>

        <div className="workspace-sidebar-bottom">
          <NavLink className="workspace-settings" to="/settings"><Settings size={17} /> Settings</NavLink>
          <button className="workspace-user" onClick={() => setUserMenuOpen((open) => !open)} aria-expanded={userMenuOpen}>
            <span className="avatar">{userName[0].toUpperCase()}</span>
            <span className="workspace-user-copy"><strong>{userName}</strong><small>{user?.email}</small></span>
            <ChevronDown size={15} />
          </button>
          {userMenuOpen && <div className="workspace-user-menu"><button onClick={onLogout}><LogOut size={15} /> Log out</button></div>}
        </div>
      </aside>
      <main className="main-area"><Outlet /></main>
    </div>
  )
}
