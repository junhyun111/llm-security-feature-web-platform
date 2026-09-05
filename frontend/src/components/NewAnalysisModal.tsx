import { Check, ChevronLeft, ChevronRight, FolderOpen, ScanSearch, Settings2, ShieldCheck, UploadCloud, X } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { api } from '../api'
import { useSettings } from '../settings/SettingsContext'
import type { AnalysisJob } from '../types'
import './NewAnalysisModal.css'

const DEFAULT_MODEL = 'deepseek/deepseek-v4-flash-0731'
const SOURCE_SUFFIXES = new Set(['.c', '.cc', '.cpp', '.cxx', '.h', '.hh', '.hpp'])
const IGNORED_DIRECTORIES = new Set(['.git', '.venv', 'node_modules', 'build', 'dist', 'out', 'vendor', '__pycache__'])
const MAX_FILE_BYTES = 5 * 1024 * 1024
const MAX_TOTAL_BYTES = 100 * 1024 * 1024

type ExcludedFiles = { count: number; unsupported: number; ignoredDirectory: number; tooLarge: number }
const EMPTY_EXCLUDED: ExcludedFiles = { count: 0, unsupported: 0, ignoredDirectory: 0, tooLarge: 0 }

type NewAnalysisModalProps = {
  open: boolean
  onClose: () => void
  onCreated?: () => void
}

export default function NewAnalysisModal({ open, onClose, onCreated }: NewAnalysisModalProps) {
  const navigate = useNavigate()
  const { openRouterApiKey: apiKey } = useSettings()
  const inputRef = useRef<HTMLInputElement>(null)
  const [step, setStep] = useState(1)
  const [files, setFiles] = useState<File[]>([])
  const [projectName, setProjectName] = useState('')
  const [excluded, setExcluded] = useState<ExcludedFiles>(EMPTY_EXCLUDED)
  const [sensitivity, setSensitivity] = useState(0.5)
  const [modelId, setModelId] = useState(DEFAULT_MODEL)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')

  const totalBytes = files.reduce((total, file) => total + file.size, 0)
  const tooLarge = totalBytes > MAX_TOTAL_BYTES

  useEffect(() => {
    if (!open) return
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === 'Escape' && !busy) onClose()
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [busy, onClose, open])

  const openPicker = () => {
    const input = inputRef.current
    if (!input) return
    input.setAttribute('webkitdirectory', '')
    input.setAttribute('directory', '')
    input.click()
  }

  const onFiles = (selected: FileList | null) => {
    const selectedFiles = Array.from(selected || [])
    const first = selectedFiles[0] as (File & { webkitRelativePath?: string }) | undefined
    const rootName = first?.webkitRelativePath?.split('/')[0] || first?.name || 'project'
    const accepted: File[] = []
    const skipped: ExcludedFiles = { ...EMPTY_EXCLUDED }

    for (const file of selectedFiles) {
      const typed = file as File & { webkitRelativePath?: string }
      const relativePath = (typed.webkitRelativePath || file.name).replaceAll('\\', '/')
      const parts = relativePath.split('/')
      const extensionIndex = file.name.lastIndexOf('.')
      const extension = extensionIndex < 0 ? '' : file.name.slice(extensionIndex).toLowerCase()
      const ignoredDirectory = parts.slice(parts.length > 1 ? 1 : 0, -1).some((part) => IGNORED_DIRECTORIES.has(part.toLowerCase()))
      if (ignoredDirectory) { skipped.count += 1; skipped.ignoredDirectory += 1 }
      else if (!SOURCE_SUFFIXES.has(extension)) { skipped.count += 1; skipped.unsupported += 1 }
      else if (file.size > MAX_FILE_BYTES) { skipped.count += 1; skipped.tooLarge += 1 }
      else accepted.push(file)
    }

    setFiles(accepted)
    setProjectName(rootName)
    setExcluded(skipped)
    setError(accepted.length ? '' : 'This folder has no supported C or C++ source files.')
  }

  const next = () => {
    if (step === 1 && !files.length) { setError('Choose a project folder before continuing.'); return }
    if (step === 2 && !modelId.trim()) { setError('Enter an LLM model ID before continuing.'); return }
    if (step === 2 && !apiKey.trim()) { setError('Add an OpenRouter API key in Settings before starting an analysis.'); return }
    setError('')
    setStep((current) => Math.min(3, current + 1))
  }

  const start = async () => {
    if (!files.length || !apiKey.trim() || !modelId.trim()) return
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
      onCreated?.()
      navigate(`/analyses/${job.id}?view=analysis&tab=code`)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to start this analysis.')
    } finally {
      setBusy(false)
    }
  }

  if (!open) return null

  return <div className="analysis-wizard-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !busy) onClose() }}>
    <section className="analysis-wizard" role="dialog" aria-modal="true" aria-labelledby="analysis-wizard-title">
      <header className="analysis-wizard-header">
        <div><span>NEW ANALYSIS</span><h1 id="analysis-wizard-title">Create a security analysis</h1></div>
        <button type="button" className="analysis-wizard-close" onClick={onClose} disabled={busy} aria-label="Close"><X size={19} /></button>
      </header>

      <ol className="analysis-wizard-steps" aria-label="Analysis setup progress">
        {['Project folder', 'Analysis settings', 'Review & start'].map((label, index) => {
          const number = index + 1
          return <li key={label} className={step === number ? 'active' : step > number ? 'complete' : ''}><span>{step > number ? <Check size={13} /> : number}</span><strong>{label}</strong></li>
        })}
      </ol>

      <div className="analysis-wizard-body">
        {step === 1 && <section className="wizard-folder-step">
          <span className="wizard-feature-icon"><UploadCloud size={29} /></span>
          <h2>Select a project folder</h2>
          <p>Only C and C++ source files are included. Build artifacts, dependencies, and unsupported files are skipped automatically.</p>
          <input ref={inputRef} type="file" multiple hidden onChange={(event) => onFiles(event.target.files)} />
          <button type="button" className="wizard-secondary-button" onClick={openPicker}><FolderOpen size={17} /> Choose folder</button>
          {files.length ? <div className="wizard-project-summary"><div><small>Project</small><strong>{projectName}</strong></div><div><small>Source files</small><strong>{files.length.toLocaleString()}</strong></div><div><small>Total size</small><strong className={tooLarge ? 'danger' : ''}>{formatBytes(totalBytes)}</strong></div></div> : <div className="wizard-empty-selection">No project folder selected yet.</div>}
          {excluded.count > 0 && <p className="wizard-exclusion-note">{excluded.count.toLocaleString()} files skipped · {excluded.unsupported} unsupported · {excluded.ignoredDirectory} ignored · {excluded.tooLarge} over 5 MB</p>}
          {tooLarge && <p className="wizard-alert">Selected source files exceed the 100 MB recommendation.</p>}
        </section>}

        {step === 2 && <section className="wizard-settings-step">
          <div className="wizard-setting-title"><span className="wizard-feature-icon"><Settings2 size={22} /></span><div><h2>Analysis settings</h2><p>These settings apply only to this analysis.</p></div></div>
          <div className="wizard-setting-block"><div className="wizard-setting-heading"><div><label htmlFor="wizard-sensitivity">Detection sensitivity</label><p>Higher sensitivity searches for more candidates, which can increase cost and false positives.</p></div><strong>{sensitivity.toFixed(2)}</strong></div><input id="wizard-sensitivity" type="range" min="0" max="1" step="0.05" value={sensitivity} onChange={(event) => setSensitivity(Number(event.target.value))} /><div className="wizard-range-labels"><span>0.0 Low</span><span>{sensitivity < .34 ? 'Low' : sensitivity < .67 ? 'Balanced' : 'High'}</span><span>High 1.0</span></div></div>
          <div className="wizard-setting-block"><label htmlFor="wizard-model">LLM model</label><input id="wizard-model" value={modelId} onChange={(event) => setModelId(event.target.value)} placeholder="provider/model-name" spellCheck={false} /><p>Use the model configured for your OpenRouter account.</p></div>
          <div className={`wizard-key-status ${apiKey ? 'configured' : ''}`}><ShieldCheck size={18} /><div><strong>{apiKey ? 'OpenRouter API key connected' : 'OpenRouter API key required'}</strong><span>{apiKey ? 'Your key is available for this analysis only.' : 'Add your key in Settings to continue.'}</span></div><Link to="/settings">Settings</Link></div>
        </section>}

        {step === 3 && <section className="wizard-review-step">
          <span className="wizard-feature-icon confirmation"><Check size={28} /></span>
          <h2>Ready to analyze</h2>
          <p>Review the request below, then start the security scan.</p>
          <div className="wizard-review-card"><div><span>Project</span><strong>{projectName}</strong></div><div><span>Source files</span><strong>{files.length.toLocaleString()} files</strong></div><div><span>Sensitivity</span><strong>{sensitivity.toFixed(2)}</strong></div><div><span>LLM model</span><strong title={modelId}>{modelId}</strong></div></div>
          <div className="wizard-security-notice"><ShieldCheck size={17} /> Your API key is used only to send this analysis request and is not stored with the results.</div>
        </section>}
        {error && <div className="wizard-error" role="alert">{error}</div>}
      </div>

      <footer className="analysis-wizard-footer"><span>{step} / 3</span><div>{step > 1 && <button type="button" className="wizard-back-button" onClick={() => { setError(''); setStep((current) => current - 1) }} disabled={busy}><ChevronLeft size={16} /> Back</button>}{step < 3 ? <button type="button" className="wizard-primary-button" onClick={next}>Continue <ChevronRight size={16} /></button> : <button type="button" className="wizard-primary-button" onClick={start} disabled={busy}>{busy ? 'Starting analysis…' : <><ScanSearch size={16} /> Start analysis</>}</button>}</div></footer>
    </section>
  </div>
}

function formatBytes(bytes: number) {
  if (!bytes) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1)
  return `${(bytes / 1024 ** index).toFixed(index ? 1 : 0)} ${units[index]}`
}
