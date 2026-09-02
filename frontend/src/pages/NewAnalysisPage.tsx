import {
  Bot,
  Eye,
  EyeOff,
  FileWarning,
  FolderOpen,
  KeyRound,
  ScanSearch,
  ShieldCheck,
  SlidersHorizontal,
  UploadCloud
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { AnalysisJob } from '../types'
import './NewAnalysisPage.css'

const DEFAULT_RUNTIME_MODEL = 'deepseek/deepseek-v4-flash-0731'
const SOURCE_SUFFIXES = new Set(['.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp'])
const IGNORED_DIRECTORIES = new Set([
  '.git', '.venv', 'node_modules', 'build', 'dist', 'out', 'vendor', '__pycache__'
])
const MAX_SOURCE_FILE_BYTES = 5 * 1024 * 1024
const MAX_SOURCE_TOTAL_BYTES = 100 * 1024 * 1024

type RuntimeMetadata = {
  router?: { expert_model_ids?: string[] }
}

type OpenRouterModel = {
  id: string
  name: string
  contextLength?: number | null
  promptPrice?: string | null
  completionPrice?: string | null
  supportsStructuredOutput: boolean
}

type ExcludedFiles = {
  count: number
  bytes: number
  unsupported: number
  ignoredDirectory: number
  tooLarge: number
}

const EMPTY_EXCLUDED: ExcludedFiles = {
  count: 0,
  bytes: 0,
  unsupported: 0,
  ignoredDirectory: 0,
  tooLarge: 0
}

export default function NewAnalysisPage() {
  const navigate = useNavigate()
  const inputRef = useRef<HTMLInputElement>(null)
  const [files, setFiles] = useState<File[]>([])
  const [excluded, setExcluded] = useState<ExcludedFiles>(EMPTY_EXCLUDED)
  const [projectName, setProjectName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  const [sensitivity, setSensitivity] = useState(0.5)
  const [apiKey, setApiKey] = useState('')
  const [showApiKey, setShowApiKey] = useState(false)
  const [modelId, setModelId] = useState(DEFAULT_RUNTIME_MODEL)
  const [trainedModels, setTrainedModels] = useState<string[]>([DEFAULT_RUNTIME_MODEL])
  const [catalogModels, setCatalogModels] = useState<OpenRouterModel[]>([])
  const [catalogBusy, setCatalogBusy] = useState(false)
  const [catalogMessage, setCatalogMessage] = useState('')
  const [runtimeMetadataLoaded, setRuntimeMetadataLoaded] = useState(false)

  useEffect(() => {
    let cancelled = false
    api.get<RuntimeMetadata>('/api/runtime')
      .then((metadata) => {
        if (cancelled) return
        const models = Array.from(new Set(
          (metadata.router?.expert_model_ids || []).map((value) => value.trim()).filter(Boolean)
        ))
        if (models.length) {
          setTrainedModels(models)
          setModelId((current) => models.includes(current) ? current : models[0])
        }
      })
      .catch(() => {
        // Runtime 메타데이터가 없어도 기본 모델을 직접 사용할 수 있습니다.
      })
      .finally(() => {
        if (!cancelled) setRuntimeMetadataLoaded(true)
      })
    return () => { cancelled = true }
  }, [])

  const loadModelCatalog = async () => {
    if (!apiKey.trim()) {
      setError('OpenRouter API Key를 먼저 입력해 주세요.')
      return
    }
    setCatalogBusy(true)
    setCatalogMessage('')
    setError('')
    try {
      const models = await api.post<OpenRouterModel[]>('/api/openrouter/models', {
        apiKey: apiKey.trim()
      })
      setCatalogModels(models)
      setCatalogMessage(`${models.length.toLocaleString()}개 텍스트 모델을 불러왔습니다.`)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'OpenRouter 모델 목록을 불러오지 못했습니다.')
    } finally {
      setCatalogBusy(false)
    }
  }

  const openPicker = () => {
    if (!inputRef.current) return
    inputRef.current.setAttribute('webkitdirectory', '')
    inputRef.current.setAttribute('directory', '')
    inputRef.current.click()
  }

  const onFiles = (selected: FileList | null) => {
    const allFiles = Array.from(selected || [])
    const first = allFiles[0] as File & { webkitRelativePath?: string }
    const root = first?.webkitRelativePath?.split('/')[0] || first?.name || 'project'
    const accepted: File[] = []
    const skipped: ExcludedFiles = { ...EMPTY_EXCLUDED }

    for (const file of allFiles) {
      const typed = file as File & { webkitRelativePath?: string }
      const relativePath = typed.webkitRelativePath || file.name
      const parts = relativePath.replaceAll('\\', '/').split('/')
      const suffixIndex = file.name.lastIndexOf('.')
      const suffix = suffixIndex >= 0 ? file.name.slice(suffixIndex).toLowerCase() : ''
      const insideIgnoredDirectory = parts
        .slice(parts.length > 1 ? 1 : 0, -1)
        .some((part) => IGNORED_DIRECTORIES.has(part.toLowerCase()))

      let reason: keyof Pick<ExcludedFiles, 'unsupported' | 'ignoredDirectory' | 'tooLarge'> | null = null
      if (insideIgnoredDirectory) reason = 'ignoredDirectory'
      else if (!SOURCE_SUFFIXES.has(suffix)) reason = 'unsupported'
      else if (file.size > MAX_SOURCE_FILE_BYTES) reason = 'tooLarge'

      if (reason) {
        skipped.count += 1
        skipped.bytes += file.size
        skipped[reason] += 1
      } else {
        accepted.push(file)
      }
    }

    setFiles(accepted)
    setExcluded(skipped)
    setProjectName(root)
    setError(accepted.length ? '' : '선택한 폴더에 분석 가능한 C/C++ 소스 파일이 없습니다.')
  }

  const totalBytes = files.reduce((sum, file) => sum + file.size, 0)
  const totalTooLarge = totalBytes > MAX_SOURCE_TOTAL_BYTES
  const routerValidated = trainedModels.includes(modelId.trim())
  const sensitivityText = sensitivity < 0.34 ? '낮음' : sensitivity < 0.67 ? '보통' : '높음'

  const start = async () => {
    if (!files.length) return
    if (totalTooLarge) {
      setError(`분석 소스의 합계가 ${formatBytes(MAX_SOURCE_TOTAL_BYTES)} 제한을 초과합니다.`)
      return
    }
    if (!modelId.trim()) {
      setError('사용할 OpenRouter 모델 ID를 입력해 주세요.')
      return
    }
    if (!apiKey.trim()) {
      setError('OpenRouter API Key를 입력해 주세요.')
      return
    }

    setBusy(true)
    setError('')
    const form = new FormData()
    form.append('project_name', projectName || 'project')
    form.append('sensitivity', sensitivity.toString())
    form.append('model', modelId.trim())
    form.append('api_key', apiKey.trim())
    for (const file of files) {
      const typed = file as File & { webkitRelativePath?: string }
      form.append('relative_paths', typed.webkitRelativePath || file.name)
      form.append('files', file, file.name)
    }

    try {
      const job = await api.postForm<AnalysisJob>('/api/analyses', form)
      navigate(`/analyses/${job.id}`)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '프로젝트 업로드에 실패했습니다.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="page analysis-create-page">
      <header className="page-header analysis-create-header">
        <div>
          <span className="eyebrow">NEW SECURITY SCAN</span>
          <h1>프로젝트 분석</h1>
          <p>C/C++ 소스와 분석 민감도, OpenRouter 모델을 선택해 새 보안 검사를 시작합니다.</p>
        </div>
        <div className="frontend-only-badge"><span className="status-dot" /> 사용자 설정 연결됨</div>
      </header>

      <div className="analysis-create-grid">
        <section className="upload-card analysis-upload-card">
          <div className="upload-icon"><UploadCloud size={32} /></div>
          <h2>프로젝트 폴더 선택</h2>
          <p>
            C/C++ 소스만 전송합니다. .git, node_modules, build, dist, vendor 등 개발·빌드 폴더와
            지원하지 않는 파일은 브라우저에서 자동 제외됩니다.
          </p>
          <input ref={inputRef} type="file" multiple hidden onChange={(event) => onFiles(event.target.files)} />
          <button className="secondary-button" onClick={openPicker}><FolderOpen size={17} /> 폴더 선택</button>

          {files.length > 0 ? (
            <div className="selection-card analysis-selection-card">
              <div><span>프로젝트</span><strong>{projectName}</strong></div>
              <div><span>분석 파일</span><strong>{files.length.toLocaleString()}개</strong></div>
              <div><span>소스 용량</span><strong className={totalTooLarge ? 'selection-danger' : ''}>{formatBytes(totalBytes)}</strong></div>
              <div><span>자동 제외</span><strong>{excluded.count.toLocaleString()}개</strong></div>
            </div>
          ) : (
            <div className="analysis-empty-project">아직 선택한 프로젝트가 없습니다.</div>
          )}

          {excluded.count > 0 && (
            <div className="excluded-file-summary">
              <FileWarning size={15} />
              <div>
                <strong>{excluded.count.toLocaleString()}개 파일 ({formatBytes(excluded.bytes)}) 제외</strong>
                <span>비소스 {excluded.unsupported} · 무시 폴더 {excluded.ignoredDirectory} · 5MB 초과 {excluded.tooLarge}</span>
              </div>
            </div>
          )}
          {totalTooLarge && <div className="error-box analysis-error-box">분석 소스 합계는 100MB 이하여야 합니다.</div>}
          {error && <div className="error-box analysis-error-box">{error}</div>}
        </section>

        <section className="panel analysis-settings-panel">
          <div className="analysis-settings-title">
            <div className="analysis-settings-icon"><SlidersHorizontal size={18} /></div>
            <div><h2>분석 설정</h2><p>이번 검사에만 적용할 실행 환경입니다.</p></div>
          </div>

          <div className="analysis-setting-block">
            <div className="analysis-setting-heading">
              <div><span className="analysis-setting-label">탐지 민감도</span><p>높을수록 더 많은 잠재 후보를 검사하며 비용과 오탐 가능성도 늘어날 수 있습니다.</p></div>
              <strong className="sensitivity-value">{sensitivity.toFixed(2)}</strong>
            </div>
            <input className="sensitivity-range" type="range" min="0" max="1" step="0.05" value={sensitivity} onChange={(event) => setSensitivity(Number(event.target.value))} aria-label="분석 민감도" />
            <div className="range-labels"><span>0.0 낮음</span><span className="range-current">{sensitivityText}</span><span>높음 1.0</span></div>
          </div>

          <div className="analysis-setting-block">
            <label className="analysis-field-label" htmlFor="runtime-model"><Bot size={15} /> LLM 모델</label>
            <input id="runtime-model" className="analysis-control" type="text" list="openrouter-models" value={modelId} onChange={(event) => setModelId(event.target.value)} placeholder="provider/model-name" spellCheck={false} />
            <datalist id="openrouter-models">
              {catalogModels.map((model) => <option key={model.id} value={model.id}>{model.name}</option>)}
            </datalist>
            <p className="analysis-field-help">
              {runtimeMetadataLoaded
                ? routerValidated
                  ? 'Router 학습에 사용되어 검증된 권장 모델입니다.'
                  : 'OpenRouter 모델로 실행할 수 있지만 Router 성능은 별도로 검증되지 않았습니다.'
                : 'Runtime 권장 모델 정보를 불러오는 중입니다.'}
            </p>
          </div>

          <div className="analysis-setting-block">
            <label className="analysis-field-label" htmlFor="openrouter-key"><KeyRound size={15} /> OpenRouter API Key</label>
            <div className="api-key-input-wrap">
              <input id="openrouter-key" className="analysis-control" type={showApiKey ? 'text' : 'password'} value={apiKey} onChange={(event) => setApiKey(event.target.value)} placeholder="sk-or-v1-..." autoComplete="off" spellCheck={false} />
              <button className="api-key-visibility" type="button" onClick={() => setShowApiKey((value) => !value)} aria-label={showApiKey ? 'API Key 숨기기' : 'API Key 보기'} title={showApiKey ? 'API Key 숨기기' : 'API Key 보기'}>
                {showApiKey ? <EyeOff size={17} /> : <Eye size={17} />}
              </button>
            </div>
            <p className="analysis-field-help">키는 HTTPS 백엔드를 거쳐 이번 Runtime 작업에만 전달되며 데이터베이스와 프로젝트 파일에 저장되지 않습니다.</p>
            <div className="model-catalog-actions">
              <button className="secondary-button compact" type="button" disabled={catalogBusy || !apiKey.trim()} onClick={loadModelCatalog}>
                <Bot size={15} /> {catalogBusy ? '불러오는 중…' : 'OpenRouter 모델 목록 불러오기'}
              </button>
              {catalogMessage && <span>{catalogMessage}</span>}
            </div>
          </div>

          <div className="analysis-config-preview">
            <div><span>민감도</span><strong>{sensitivity.toFixed(2)}</strong></div>
            <div><span>모델</span><strong title={modelId}>{modelId || '미입력'}</strong></div>
            <div><span>사용자 Key</span><strong>{apiKey ? '입력됨' : '미입력'}</strong></div>
          </div>

          <div className="analysis-ui-notice">
            <ShieldCheck size={17} />
            <p><strong>요청 단위 보안</strong> 모델과 API Key는 분석 요청에만 사용됩니다. 완료 후 Runtime 메모리에서도 제거됩니다.</p>
          </div>
        </section>
      </div>

      <button className="primary-button analysis-start-button" disabled={!files.length || totalTooLarge || busy || !modelId.trim() || !apiKey.trim()} onClick={start}>
        <ScanSearch size={18} /> {busy ? '업로드 중…' : '보안 분석 시작'}
      </button>
      <section className="info-strip analysis-process-strip">
        <strong>분석 과정</strong><span>AST · CFG · Data Flow → Candidate Gate → Utility Router → LLM 검증 → 결과 저장</span>
      </section>
    </div>
  )
}

function formatBytes(value: number) {
  if (!value) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const index = Math.min(Math.floor(Math.log(value) / Math.log(1024)), units.length - 1)
  return `${(value / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`
}
