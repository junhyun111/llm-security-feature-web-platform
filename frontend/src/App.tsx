import { Navigate, Route, Routes } from 'react-router-dom'
import AppLayout from './components/AppLayout'
import ProtectedRoute from './components/ProtectedRoute'
import AnalysisDetailPage from './pages/AnalysisDetailPage'
import DashboardPage from './pages/DashboardPage'
import HistoryPage from './pages/HistoryPage'
import LoginPage from './pages/LoginPage'
import NewAnalysisPage from './pages/NewAnalysisPage'
import RegisterPage from './pages/RegisterPage'
import SettingsPage from './pages/SettingsPage'
import LandingPage from './pages/LandingPage'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<LandingPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />

      <Route element={<ProtectedRoute />}>
        <Route element={<AppLayout />}>
          <Route path="/library" element={<DashboardPage />} />
          <Route path="/analyses" element={<HistoryPage />} />
          <Route path="/analyses/new" element={<NewAnalysisPage />} />
          <Route path="/analyses/:id" element={<AnalysisDetailPage />} />
          <Route path="/settings" element={<SettingsPage />} />
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
