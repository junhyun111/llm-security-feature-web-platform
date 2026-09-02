import {
  Bot,
  Eye,
  EyeOff,
  FolderOpen,
  KeyRound,
  ScanSearch,
  ShieldCheck,
  SlidersHorizontal,
  UploadCloud,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../api'
import type { AnalysisJob } from '../types'
import './NewAnalysisPage.css'

const DEFAULT_RUNTIME_MODEL = 'deepseek/deepseek-v4-flash-0731'

type RuntimeMetadata = {
  router?: {
    expert_model_ids?: string[]
  }
}

type OpenRouterModel = {
  id: string
  name: string
  contextLength?: number | null
  promptPrice?: string | null
  completionPrice?: string | null
  supportsStructuredOutput: boolean
}

export default function NewAnalysisPage() {
  const navigate = useNavigate()
  const inputRef = useRef<HTMLInputElement>(null)

  const [files, setFiles] = useState<File[]>([])
  const [projectName, setProjectName] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const [sensitivity, setSensitivity] = useState(0.5)
  const [apiKey, setApiKey] = useState('')
  const [showApiKey, setShowApiKey] = useState(false)
  const [modelId, setModelId] = useState(DEFAULT_RUNTIME_MODEL)
  const [trainedModels, setTrainedModels] = useState<string[]>([
    DEFAULT_RUNTIME_MODEL,
  ])
  const [catalogModels, setCatalogModels] = useState<OpenRouterModel[]>([])
  const [catalogBusy, setCatalogBusy] = useState(false)
  const [catalogMessage, setCatalogMessage] = useState('')
  const [runtimeMetadataLoaded, setRuntimeMetadataLoaded] = useState(false)

  useEffect(() => {
    let cancelled = false

    api
      .get<RuntimeMetadata>('/api/runtime')
      .then((metadata) => {
        if (cancelled) return

        const models = Array.from(
          new Set(
            (metadata.router?.expert_model_ids || [])
              .map((value) => value.trim())
              .filter(Boolean)
          )
        )

        if (models.length > 0) {
          setTrainedModels(models)
          setModelId((current) => models.includes(current) ? current : models[0])
        }
      })
      .catch(() => {
        // Runtime metadata 조회 실패 시 기본 모델 표시를 유지한다.
      })
      .finally(() => {
        if (!cancelled) setRuntimeMetadataLoaded(true)
      })

    return () => {
      cancelled = true
    }
  }, [])

  const loadModelCatalog = async () => {
    if (!apiKey.trim()) {
      setError('OpenRouter API Key를 먼저 입력해주세요.')
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
    } catch (e) {
      setError(e instanceof Error ? e.message : 'OpenRouter 모델 목록을 불러오지 못했습니다.')
    } finally {
      setCatalogBusy(false)
    }
  }

  const openPicker = () => {
    if (inputRef.current) {
      inputRef.current.setAttribute('webkitdirectory', '')
      inputRef.current.setAttribute('directory', '')
      inputRef.current.click()
    }
  }

  const onFiles = (selected: FileList | null) => {
    const list = Array.from(selected || [])
    setFiles(list)

    const first = list[0] as File & { webkitRelativePath?: string }
    const root =
      first?.webkitRelativePath?.split('/')[0] ||
      first?.name ||
      'project'

    setProjectName(root)
    setError('')
  }

  const start = async () => {
    if (!files.length) return

    if (!modelId.trim()) {
      setError('사용할 OpenRouter 모델 ID를 입력해주세요.')
      return
    }

    if (!apiKey.trim()) {
      setError('OpenRouter API Key를 입력해주세요.')
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
    } catch (e) {
      setError(e instanceof Error ? e.message : '업로드에 실패했습니다.')
    } finally {
      setBusy(false)
    }
  }

  const totalBytes = files.reduce((sum, file) => sum + file.size, 0)
  const routerValidated = trainedModels.includes(modelId.trim())

  const sensitivityText =
    sensitivity < 0.34 ? '낮음' : sensitivity < 0.67 ? '보통' : '높음'

  return (
    <div className="page analysis-create-page">
      <header className="page-header analysis-create-header">
        <div>
          <span className="eyebrow">NEW SECURITY SCAN</span>
          <h1>프로젝트 분석</h1>
          <p>
            C/C++ 프로젝트를 업로드하고 분석 민감도와 LLM 실행 환경을 설정합니다.
          </p>
        </div>

        <div className="frontend-only-badge">
          <span className="status-dot" />
          사용자 설정 연결됨
        </div>
      </header>

      <div className="analysis-create-grid">
        <section className="upload-card analysis-upload-card">
          <div className="upload-icon">
            <UploadCloud size={34} />
          </div>

          <h2>프로젝트 폴더 선택</h2>
          <p>
            .c, .cc, .cpp, .cxx, .h, .hh, .hpp 파일을 포함한 프로젝트 폴더를
            선택하세요.
          </p>

          <input
            ref={inputRef}
            type="file"
            multiple
            hidden
            onChange={(e) => onFiles(e.target.files)}
          />

          <button className="secondary-button" onClick={openPicker}>
            <FolderOpen size={18} />
            폴더 선택
          </button>

          {files.length > 0 ? (
            <div className="selection-card analysis-selection-card">
              <div>
                <span>선택된 프로젝트</span>
                <strong>{projectName}</strong>
              </div>
              <div>
                <span>파일</span>
                <strong>{files.length.toLocaleString()}개</strong>
              </div>
              <div>
                <span>용량</span>
                <strong>{formatBytes(totalBytes)}</strong>
              </div>
            </div>
          ) : (
            <div className="analysis-empty-project">
              아직 선택된 프로젝트가 없습니다.
            </div>
          )}

          {error && <div className="error-box analysis-error-box">{error}</div>}
        </section>

        <section className="panel analysis-settings-panel">
          <div className="analysis-settings-title">
            <div className="analysis-settings-icon">
              <SlidersHorizontal size={19} />
            </div>
            <div>
              <h2>분석 설정</h2>
              <p>사용자별 분석 환경을 설정합니다.</p>
            </div>
          </div>

          <div className="analysis-setting-block">
            <div className="analysis-setting-heading">
              <div>
                <span className="analysis-setting-label">탐지 민감도</span>
                <p>
                  높을수록 더 많은 잠재 취약점을 탐지하는 방향으로 사용할
                  예정입니다.
                </p>
              </div>
              <strong className="sensitivity-value">
                {sensitivity.toFixed(2)}
              </strong>
            </div>

            <input
              className="sensitivity-range"
              type="range"
              min="0"
              max="1"
              step="0.05"
              value={sensitivity}
              onChange={(e) => setSensitivity(Number(e.target.value))}
              aria-label="분석 민감도"
            />

            <div className="range-labels">
              <span>0.0 낮음</span>
              <span className="range-current">{sensitivityText}</span>
              <span>높음 1.0</span>
            </div>
          </div>

          <div className="analysis-setting-block">
            <label className="analysis-field-label" htmlFor="runtime-model">
              <Bot size={15} />
              LLM 모델
            </label>

            <input
              id="runtime-model"
              className="analysis-control"
              type="text"
              list="openrouter-models"
              value={modelId}
              onChange={(e) => setModelId(e.target.value)}
              placeholder="예: provider/model-name"
              spellCheck={false}
            />
            <datalist id="openrouter-models">
              {catalogModels.map((model) => (
                <option key={model.id} value={model.id}>{model.name}</option>
              ))}
            </datalist>

            <p className="analysis-field-help">
              {runtimeMetadataLoaded
                ? routerValidated
                  ? 'Router 학습에 사용되어 검증된 권장 모델입니다.'
                  : 'OpenRouter 모델로 실행할 수 있지만 Router 성능은 별도로 검증되지 않았습니다.'
                : 'Runtime 호환 모델 정보를 불러오는 중입니다.'}
            </p>
          </div>

          <div className="analysis-setting-block">
            <label className="analysis-field-label" htmlFor="openrouter-key">
              <KeyRound size={15} />
              OpenRouter API Key
            </label>

            <div className="api-key-input-wrap">
              <input
                id="openrouter-key"
                className="analysis-control"
                type={showApiKey ? 'text' : 'password'}
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="sk-or-v1-..."
                autoComplete="off"
                spellCheck={false}
              />
              <button
                className="api-key-visibility"
                type="button"
                onClick={() => setShowApiKey((value) => !value)}
                aria-label={showApiKey ? 'API Key 숨기기' : 'API Key 보기'}
                title={showApiKey ? 'API Key 숨기기' : 'API Key 보기'}
              >
                {showApiKey ? <EyeOff size={17} /> : <Eye size={17} />}
              </button>
            </div>

            <p className="analysis-field-help">
              분석 시작 시 HTTPS 백엔드를 거쳐 내부 Runtime으로만 전달하며
              데이터베이스나 프로젝트 파일에는 저장하지 않습니다.
            </p>
            <div className="model-catalog-actions">
              <button
                className="secondary-button compact"
                type="button"
                disabled={catalogBusy || !apiKey.trim()}
                onClick={loadModelCatalog}
              >
                <Bot size={15} />
                {catalogBusy ? '불러오는 중…' : 'OpenRouter 모델 목록 불러오기'}
              </button>
              {catalogMessage && <span>{catalogMessage}</span>}
            </div>
          </div>

          <div className="analysis-config-preview">
            <div>
              <span>민감도</span>
              <strong>{sensitivity.toFixed(2)}</strong>
            </div>
            <div>
              <span>모델</span>
              <strong title={modelId}>{modelId || '미입력'}</strong>
            </div>
            <div>
              <span>사용자 Key</span>
              <strong>{apiKey ? '입력됨' : '미입력'}</strong>
            </div>
          </div>

          <div className="analysis-ui-notice">
            <ShieldCheck size={17} />
            <p>
              <strong>연결됨:</strong> 민감도 · 모델 · API Key가
              Backend → Runtime으로 전달됩니다. API Key는 분석이 끝나면
              Runtime 메모리에서도 제거됩니다.
            </p>
          </div>
        </section>
      </div>

      <button
        className="primary-button analysis-start-button"
        disabled={!files.length || busy || !modelId.trim() || !apiKey.trim()}
        onClick={start}
      >
        <ScanSearch size={18} />
        {busy ? '업로드 중…' : '보안 분석 시작'}
      </button>

      <section className="info-strip analysis-process-strip">
        <strong>분석 과정</strong>
        <span>
          AST · CFG · Data Flow → Candidate Gate → Utility Router → LLM 검증 →
          결과 저장
        </span>
      </section>
    </div>
  )
}

function formatBytes(value: number) {
  if (!value) return '0 B'

  const units = ['B', 'KB', 'MB', 'GB']
  const index = Math.min(
    Math.floor(Math.log(value) / Math.log(1024)),
    units.length - 1
  )

  return `${(value / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`
}
