import {
  ChevronDown,
  FolderKanban,
  LayoutDashboard,
  LogOut,
  ScanSearch,
  Settings,
  ShieldCheck
} from 'lucide-react'
import { useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'

export default function AppLayout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [userMenuOpen, setUserMenuOpen] = useState(false)

  const onLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <div className="app-shell">
      <header className="top-navigation">
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={21} /></div>
          <div><strong>LLM Security</strong><span>Code Review Platform</span></div>
        </div>

        <nav className="nav-list" aria-label="Main navigation">
          <NavLink to="/" end><LayoutDashboard size={16} /> Overview</NavLink>
          <NavLink to="/analyses/new"><ScanSearch size={16} /> New Scan</NavLink>
          <NavLink to="/analyses" end><FolderKanban size={16} /> Projects</NavLink>
          <NavLink to="/settings"><Settings size={16} /> Settings</NavLink>
        </nav>

        <div className="top-navigation-user">
          <button className="user-menu-trigger" onClick={() => setUserMenuOpen((open) => !open)} aria-expanded={userMenuOpen}>
            <div className="avatar">{(user?.displayName || user?.email || '?')[0].toUpperCase()}</div>
            <span>{user?.displayName || user?.email}</span><ChevronDown size={14} />
          </button>
          {userMenuOpen && (
            <div className="user-dropdown">
              <strong>{user?.displayName || 'User'}</strong>
              <span>{user?.email}</span>
              <button onClick={onLogout}><LogOut size={15} /> 로그아웃</button>
            </div>
          )}
        </div>
      </header>

      <main className="main-area"><Outlet /></main>
    </div>
  )
}
