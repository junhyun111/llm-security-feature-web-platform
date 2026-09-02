import { Eye, EyeOff, KeyRound, LockKeyhole, Moon, Sun, UserRound } from 'lucide-react'
import { useState } from 'react'
import { useAuth } from '../auth/AuthContext'
import { useSettings } from '../settings/SettingsContext'
import './SettingsPage.css'

export default function SettingsPage() {
  const { user, updateProfile, changePassword } = useAuth()
  const { theme, setTheme, openRouterApiKey, setOpenRouterApiKey } = useSettings()
  const [email, setEmail] = useState(user?.email || '')
  const [displayName, setDisplayName] = useState(user?.displayName || '')
  const [apiKey, setApiKey] = useState(openRouterApiKey)
  const [showApiKey, setShowApiKey] = useState(false)
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [profileBusy, setProfileBusy] = useState(false)
  const [passwordBusy, setPasswordBusy] = useState(false)
  const [notice, setNotice] = useState('')
  const [error, setError] = useState('')

  const saveProfile = async () => {
    setProfileBusy(true)
    setNotice('')
    setError('')
    try {
      await updateProfile(email.trim(), displayName.trim())
      setNotice('계정 정보가 저장되었습니다.')
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '계정 정보를 저장하지 못했습니다.')
    } finally {
      setProfileBusy(false)
    }
  }

  const saveApiKey = () => {
    setOpenRouterApiKey(apiKey)
    setNotice(apiKey.trim() ? '이 브라우저에 OpenRouter API Key를 저장했습니다.' : '저장된 OpenRouter API Key를 삭제했습니다.')
    setError('')
  }

  const savePassword = async () => {
    if (newPassword !== confirmPassword) {
      setError('새 비밀번호와 확인 비밀번호가 일치하지 않습니다.')
      return
    }
    setPasswordBusy(true)
    setNotice('')
    setError('')
    try {
      await changePassword(currentPassword, newPassword)
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setNotice('비밀번호가 변경되었습니다.')
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '비밀번호를 변경하지 못했습니다.')
    } finally {
      setPasswordBusy(false)
    }
  }

  return (
    <div className="page settings-page narrow-page">
      <header className="page-header">
        <div>
          <span className="eyebrow">SETTINGS</span>
          <h1>설정</h1>
          <p>계정, 화면 테마, OpenRouter 실행 설정을 관리합니다.</p>
        </div>
      </header>

      {error && <div className="error-box">{error}</div>}
      {notice && <div className="settings-notice">{notice}</div>}

      <div className="settings-grid">
        <section className="panel settings-card">
          <div className="settings-card-title"><UserRound size={18} /><div><h2>계정 정보</h2><p>로그인 이메일(ID)과 표시 이름을 변경합니다.</p></div></div>
          <label className="settings-label">표시 이름<input value={displayName} onChange={(event) => setDisplayName(event.target.value)} maxLength={120} /></label>
          <label className="settings-label">로그인 이메일(ID)<input type="email" value={email} onChange={(event) => setEmail(event.target.value)} autoComplete="email" /></label>
          <button className="primary-button compact" disabled={profileBusy || !email.trim() || !displayName.trim()} onClick={saveProfile}>{profileBusy ? '저장 중…' : '계정 정보 저장'}</button>
        </section>

        <section className="panel settings-card">
          <div className="settings-card-title"><LockKeyhole size={18} /><div><h2>비밀번호</h2><p>현재 비밀번호를 확인한 뒤 새 비밀번호로 변경합니다.</p></div></div>
          <label className="settings-label">현재 비밀번호<input type="password" value={currentPassword} onChange={(event) => setCurrentPassword(event.target.value)} autoComplete="current-password" /></label>
          <label className="settings-label">새 비밀번호<input type="password" value={newPassword} onChange={(event) => setNewPassword(event.target.value)} autoComplete="new-password" /></label>
          <label className="settings-label">새 비밀번호 확인<input type="password" value={confirmPassword} onChange={(event) => setConfirmPassword(event.target.value)} autoComplete="new-password" /></label>
          <button className="primary-button compact" disabled={passwordBusy || !currentPassword || !newPassword || !confirmPassword} onClick={savePassword}>{passwordBusy ? '변경 중…' : '비밀번호 변경'}</button>
        </section>

        <section className="panel settings-card">
          <div className="settings-card-title"><Sun size={18} /><div><h2>화면 테마</h2><p>선택한 테마는 이 브라우저에 저장됩니다.</p></div></div>
          <div className="theme-choice" role="radiogroup" aria-label="화면 테마">
            <button className={theme === 'dark' ? 'selected' : ''} onClick={() => setTheme('dark')} role="radio" aria-checked={theme === 'dark'}><Moon size={16} /> 다크 모드</button>
            <button className={theme === 'light' ? 'selected' : ''} onClick={() => setTheme('light')} role="radio" aria-checked={theme === 'light'}><Sun size={16} /> 라이트 모드</button>
          </div>
        </section>

        <section className="panel settings-card settings-card-wide">
          <div className="settings-card-title"><KeyRound size={18} /><div><h2>OpenRouter API Key</h2><p>새 분석과 패치 생성에 자동 사용합니다.</p></div></div>
          <div className="settings-key-row">
            <input type={showApiKey ? 'text' : 'password'} value={apiKey} onChange={(event) => setApiKey(event.target.value)} placeholder="sk-or-v1-..." autoComplete="off" spellCheck={false} aria-label="OpenRouter API Key" />
            <button className="icon-button" type="button" onClick={() => setShowApiKey((value) => !value)} aria-label={showApiKey ? 'API Key 숨기기' : 'API Key 보기'}>{showApiKey ? <EyeOff size={17} /> : <Eye size={17} />}</button>
          </div>
          <p className="settings-help">이 값은 서버, SQLite, 분석 결과에는 저장되지 않습니다. 현재 브라우저의 로컬 저장소에만 보관되므로 공용 PC에서는 저장 후 반드시 삭제하세요.</p>
          <div className="settings-actions"><button className="primary-button compact" onClick={saveApiKey}>API Key 저장</button><button className="ghost-button compact" onClick={() => { setApiKey(''); setOpenRouterApiKey(''); setNotice('저장된 OpenRouter API Key를 삭제했습니다.'); setError('') }}>저장된 키 삭제</button></div>
        </section>
      </div>
    </div>
  )
}
