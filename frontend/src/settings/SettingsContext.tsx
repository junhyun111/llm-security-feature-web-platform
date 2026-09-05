import {
  createContext,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode
} from 'react'
import { useAuth } from '../auth/AuthContext'

export type ThemeMode = 'dark' | 'light'

type SettingsContextValue = {
  theme: ThemeMode
  setTheme: (theme: ThemeMode) => void
  openRouterApiKey: string
  setOpenRouterApiKey: (value: string) => void
}

const THEME_KEY = 'llm-security.theme'
const THEME_DEFAULT_VERSION_KEY = 'llm-security.theme-default-v2'
const SettingsContext = createContext<SettingsContextValue | null>(null)

function readStorage(key: string, fallback = '') {
  try {
    return window.localStorage.getItem(key) ?? fallback
  } catch {
    return fallback
  }
}

function writeStorage(key: string, value: string) {
  try {
    if (value) window.localStorage.setItem(key, value)
    else window.localStorage.removeItem(key)
  } catch {
    // 브라우저 저장소가 제한된 경우에도 현재 탭에서는 설정을 사용한다.
  }
}

function apiKeyStorageKey(userId: string | undefined) {
  return userId ? `llm-security.openrouter-api-key:${userId}` : null
}

export function SettingsProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth()
  const [theme, setThemeState] = useState<ThemeMode>(() => {
    // Version 2 changes the product default from dark to light. The marker also
    // upgrades browsers that stored the old default before a user chose a theme.
    if (readStorage(THEME_DEFAULT_VERSION_KEY) !== '1') {
      writeStorage(THEME_DEFAULT_VERSION_KEY, '1')
      return 'light'
    }
    return readStorage(THEME_KEY) === 'dark' ? 'dark' : 'light'
  })
  const [openRouterApiKey, setOpenRouterApiKeyState] = useState('')

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    document.documentElement.style.colorScheme = theme
    writeStorage(THEME_KEY, theme)
  }, [theme])

  useEffect(() => {
    const key = apiKeyStorageKey(user?.id)
    setOpenRouterApiKeyState(key ? readStorage(key) : '')
  }, [user?.id])

  const value = useMemo<SettingsContextValue>(() => ({
    theme,
    setTheme: setThemeState,
    openRouterApiKey,
    setOpenRouterApiKey: (next) => {
      const normalized = next.trim()
      setOpenRouterApiKeyState(normalized)
      const key = apiKeyStorageKey(user?.id)
      if (key) writeStorage(key, normalized)
    }
  }), [theme, openRouterApiKey, user?.id])

  return <SettingsContext.Provider value={value}>{children}</SettingsContext.Provider>
}

export function useSettings() {
  const context = useContext(SettingsContext)
  if (!context) throw new Error('useSettings must be used inside SettingsProvider')
  return context
}
