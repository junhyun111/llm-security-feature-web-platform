import {
  FolderKanban,
  LayoutDashboard,
  LogOut,
  ScanSearch,
  ShieldCheck
} from 'lucide-react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'

export default function AppLayout() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()

  const onLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark"><ShieldCheck size={21} /></div>
          <div><strong>LLM Security</strong><span>Code Review Platform</span></div>
        </div>

        <nav className="nav-list">
          <span className="nav-section-label">Workspace</span>
          <NavLink to="/" end><LayoutDashboard size={17} /> Overview</NavLink>
          <NavLink to="/analyses/new"><ScanSearch size={17} /> New Scan</NavLink>
          <NavLink to="/analyses"><FolderKanban size={17} /> Projects</NavLink>
        </nav>

        <div className="sidebar-bottom">
          <div className="user-card">
            <div className="avatar">{(user?.displayName || user?.email || '?')[0].toUpperCase()}</div>
            <div className="user-copy"><strong>{user?.displayName}</strong><span>{user?.email}</span></div>
          </div>
          <button className="ghost-button full" onClick={onLogout}><LogOut size={16} /> 로그아웃</button>
        </div>
      </aside>

      <main className="main-area"><Outlet /></main>
    </div>
  )
}
