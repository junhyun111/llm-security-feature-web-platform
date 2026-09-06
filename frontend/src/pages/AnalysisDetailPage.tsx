import {
  AlertTriangle,
  ArrowLeft,
  CircleStop,
  CheckCircle2,
  Clock3,
  Code2,
  Download,
  FileCode2,
  FileDiff,
  ListChecks,
  LoaderCircle,
  Route,
  ShieldAlert,
  UsersRound,
  WandSparkles,
  XCircle
} from 'lucide-react'
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api, ApiError } from '../api'
import StatusBadge from '../components/StatusBadge'
import { useSettings } from '../settings/SettingsContext'
import type { AnalysisDetail, AnalysisJob, AnalysisStatus, AnalysisSyncInfo, FindingBundle, PatchBatch } from '../types'
import './AnalysisDetailPage.css'

type AnalysisTab = 'findings' | 'code' | 'overview' | 'trace'
type UiError = { message: string; traceId?: string }

const SecurityWorkbench = lazy(() => import('../components/workbench/SecurityWorkbench').then((module) => ({ default: module.SecurityWorkbench })))
const PatchDiffPanel = lazy(() => import('../components/workbench/SecurityWorkbench').then((module) => ({ default: module.PatchDiffPanel })))
const AnalysisTracePanel = lazy(() => import('../components/workbench/SecurityWorkbench').then((module) => ({ default: module.AnalysisTracePanel })))

export default function AnalysisDetailPage() {
  const { id } = useParams()
  const { openRouterApiKey } = useSettings()
  const [params, setParams] = useSearchParams()
  const [detail, setDetail] = useState<AnalysisDetail | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [initialLoadError, setInitialLoadError] = useState<UiError | null>(null)
  const [actionError, setActionError] = useState<UiError | null>(null)
  const [patchBusy, setPatchBusy] = useState(false)
  const [cancelBusy, setCancelBusy] = useState(false)
  const pollFailures = useRef(0)

  const view = params.get('view') === 'patch' ? 'patch' : 'analysis'
  const requestedTab = params.get('tab')
  const tab: AnalysisTab = isAnalysisTab(requestedTab) ? requestedTab : 'code'
  const activeFindingId = params.get('finding')

  const setLocation = useCallback((next: { view?: 'analysis' | 'patch'; tab?: AnalysisTab; finding?: string | null }) => {
    const copy = new URLSearchParams(params)
    copy.set('view', next.view || view)
    if ((next.view || view) === 'analysis') copy.set('tab', next.tab || tab)
    else copy.delete('tab')
    if (next.finding === null) copy.delete('finding')
    else if (next.finding) copy.set('finding', next.finding)
    setParams(copy, { replace: true })
  }, [params, setParams, tab, view])

  const applyDetail = useCallback((result: AnalysisDetail) => {
    setDetail(result)
    const firstFinding = result.analysis?.findings[0]?.finding.finding_id
    if (!activeFindingId && firstFinding) setLocation({ finding: firstFinding })
  }, [activeFindingId, setLocation])

  const refreshDetail = useCallback(async () => {
    if (!id) return
    const result = await api.get<AnalysisDetail>(`/api/analyses/${id}`)
    applyDetail(result)
    return result
  }, [applyDetail, id])

  useEffect(() => {
    setInitialLoadError(null)
    refreshDetail().catch((reason) => setInitialLoadError(toUiError(reason, '분석 정보를 불러오지 못했습니다.')))
  }, [refreshDetail])

  useEffect(() => {
    const status = detail?.job.status
    if (!id || !status || !['uploading', 'queued', 'analyzing', 'cancelling'].includes(status)) return
    let disposed = false
    const poll = async () => {
      try {
        const result = await api.get<AnalysisStatus>(`/api/analyses/${id}/status`)
        pollFailures.current = 0
        if (['completed', 'partial', 'failed', 'cancelled'].includes(result.job.status)) await refreshDetail()
        else setDetail((current) => current ? { ...current, job: result.job, sync: result.sync } : current)
      } catch {
        pollFailures.current += 1
      }
      if (!disposed) window.setTimeout(poll, 2000)
    }
    const timer = window.setTimeout(poll, 2000)
    return () => { disposed = true; window.clearTimeout(timer) }
  }, [detail?.job.status, id, refreshDetail])

  const findings = detail?.analysis?.findings ?? []
  const validated = useMemo(() => findings.filter((item) => item.validation.verdict === 'validated'), [findings])
  const uncertain = useMemo(() => findings.filter((item) => item.validation.verdict === 'uncertain'), [findings])
  const rejected = useMemo(() => findings.filter((item) => item.validation.verdict === 'rejected'), [findings])

  const generatePatch = async (findingIds: string[]) => {
    if (!id || !findingIds.length) return
    if (!openRouterApiKey.trim()) {
      setActionError({ message: '패치를 생성하려면 Settings에서 OpenRouter API key를 설정하세요.' })
      return
    }
    const includesUncertain = findings.some((item) => findingIds.includes(item.finding.finding_id) && item.validation.verdict === 'uncertain')
    if (includesUncertain && !window.confirm('검토가 필요한 항목이 포함되어 있습니다. 계속 패치를 생성할까요?')) return
    setPatchBusy(true)
    setActionError(null)
    try {
      await api.post<PatchBatch>(`/api/analyses/${id}/patches/proposal`, { findingIds, apiKey: openRouterApiKey.trim() })
      await refreshDetail()
      setLocation({ view: 'patch' })
    } catch (reason) {
      setActionError(toUiError(reason, '패치를 생성하지 못했습니다.'))
    } finally {
      setPatchBusy(false)
    }
  }

  const patchAction = async (action: 'approve' | 'reject') => {
    const patch = detail?.analysis?.patch_batch
    if (!id || !patch) return
    setPatchBusy(true)
    setActionError(null)
    try {
      await api.post<PatchBatch>(`/api/analyses/${id}/patches/${encodeURIComponent(patch.patch_id)}/${action}`)
      await refreshDetail()
    } catch (reason) {
      setActionError(toUiError(reason, '패치를 처리하지 못했습니다.'))
    } finally {
      setPatchBusy(false)
    }
  }

  const cancelAnalysis = async () => {
    if (!id || detail?.job.status === 'cancelling') return
    setCancelBusy(true)
    try {
      const job = await api.post<AnalysisJob>(`/api/analyses/${id}/cancel`)
      setDetail((current) => current ? { ...current, job } : current)
    } catch (reason) { setActionError(toUiError(reason, '분석 중단을 요청하지 못했습니다.')) }
    finally { setCancelBusy(false) }
  }

  if (!detail) return <div className="page"><Link className="back-link" to="/analyses"><ArrowLeft size={16} /> Projects</Link>{initialLoadError ? <ErrorMessage error={initialLoadError} /> : <div className="loader" />}</div>

  const { job, analysis } = detail
  const analysisActive = ['uploading', 'queued', 'analyzing', 'cancelling'].includes(job.status)
  const patch = analysis?.patch_batch

  return (
    <div className="analysis-detail-page">
      <header className="detail-header workbench-detail-header">
        <div className="analysis-project-bar"><Link className="analysis-back-link" to="/analyses"><ArrowLeft size={15} /> Library</Link><div><h1>{job.projectName}</h1><p>{job.fileCount.toLocaleString()} files · {job.modelId}</p></div></div>
        <div className="detail-actions">
          <StatusBadge status={job.status} />
          {analysisActive && <button className="danger-button compact" disabled={cancelBusy} onClick={cancelAnalysis}><CircleStop size={15} /> Stop scan</button>}
          {(['completed', 'partial'].includes(job.status) || (job.status === 'cancelled' && analysis)) && <a className="secondary-button compact" href={api.downloadUrl(`/api/analyses/${job.id}/download`)}><Download size={15} /> Download</a>}
        </div>
      </header>

      {actionError && <ErrorMessage error={actionError} />}
      {analysisActive && <AnalysisProgressDashboard job={job} findingCount={findings.length} />}
      {job.status === 'failed' && <section className="panel danger-panel"><XCircle /><div><h2>Analysis failed</h2><p>{job.errorMessage || job.message}</p></div></section>}
      {job.status === 'partial' && <section className="panel partial-result-panel"><AlertTriangle /><div><h2>Partial results are ready</h2><p>See Analysis Trace for incomplete expert tasks.</p></div></section>}

      {analysis && id && <section className="analysis-workspace-shell">
        <nav className="detail-tabs" aria-label="Analysis views">
          <TabButton active={view === 'analysis' && tab === 'findings'} onClick={() => setLocation({ view: 'analysis', tab: 'findings' })} icon={<ListChecks size={14} />} label="Findings" count={findings.length} />
          <TabButton active={view === 'analysis' && tab === 'code'} onClick={() => setLocation({ view: 'analysis', tab: 'code' })} icon={<Code2 size={14} />} label="Code" />
          <TabButton active={view === 'analysis' && tab === 'overview'} onClick={() => setLocation({ view: 'analysis', tab: 'overview' })} icon={<ShieldAlert size={14} />} label="Overview" />
          <TabButton active={view === 'analysis' && tab === 'trace'} onClick={() => setLocation({ view: 'analysis', tab: 'trace' })} icon={<Route size={14} />} label="Analysis Trace" />
          <TabButton active={view === 'patch'} onClick={() => setLocation({ view: 'patch' })} icon={<FileDiff size={14} />} label="Patch" count={patch ? 1 : undefined} />
        </nav>

        {view === 'analysis' ? <>
          {tab === 'findings' && <FindingsView findings={findings} validated={validated.length} uncertain={uncertain.length} rejected={rejected.length} onOpenCode={(findingId) => setLocation({ tab: 'code', finding: findingId })} onGeneratePatch={(findingId) => generatePatch([findingId])} />}
          {tab === 'code' && <Suspense fallback={<WorkbenchLoader />}><SecurityWorkbench analysisId={id} analysis={analysis} activeFindingId={activeFindingId} onFindingSelect={(findingId) => setLocation({ finding: findingId })} onGeneratePatch={(findingId) => generatePatch([findingId])} /></Suspense>}
          {tab === 'overview' && <OverviewPanel analysis={analysis} validatedCount={validated.length} />}
          {tab === 'trace' && <Suspense fallback={<WorkbenchLoader />}><AnalysisTracePanel analysis={analysis} /></Suspense>}
        </> : <PatchWorkspace findings={findings} selected={selected} setSelected={setSelected} patch={patch} busy={patchBusy} onGenerate={() => generatePatch(Array.from(selected))} onAction={patchAction} analysisId={id} />}
      </section>}
    </div>
  )
}

function AnalysisProgressDashboard({ job, findingCount }: { job: AnalysisJob; findingCount: number }) {
  const progress = Math.max(0, Math.min(100, job.progress))
  const expertMatch = job.message.match(/Parallel Expert analysis:\s*(\d+)\/(\d+)\s*finished,\s*(\d+)\s*succeeded,\s*(\d+)\s*failed,\s*active\s*(\d+)/i)
  const completedExperts = expertMatch ? Number(expertMatch[1]) : 0
  const totalExperts = expertMatch ? Number(expertMatch[2]) : 0
  const activeExperts = expertMatch ? Number(expertMatch[5]) : 0
  const stage = progress < 20 ? 0 : progress < 40 ? 1 : progress < 95 ? 2 : 3
  const elapsedSeconds = Math.max(0, Math.floor((Date.now() - new Date(job.createdAt).getTime()) / 1000))
  const stages = [
    { label: 'Repository', detail: `${job.fileCount.toLocaleString()} files` },
    { label: 'Context build', detail: stage > 1 ? 'Completed' : 'Preparing source context' },
    { label: 'Expert analysis', detail: totalExperts ? `${completedExperts} / ${totalExperts} experts` : 'Preparing expert tasks' },
    { label: 'Result aggregation', detail: stage === 3 ? 'Building report' : 'Waiting' }
  ]
  const completedLabel = totalExperts ? `${completedExperts} / ${totalExperts}` : 'Running'
  const remaining = progress >= 95 ? 'Finalizing results' : progress >= 40 ? 'Expert analysis in progress' : 'Preparing analysis workspace'

  return <section className="analysis-progress-dashboard" aria-label="Analysis progress dashboard">
    <div className="analysis-progress-hero"><div><span className="analysis-progress-eyebrow">PARALLEL EXPERT ANALYSIS</span><h2>Analyzing your code…</h2><p>{job.message || 'Multiple experts are preparing to inspect the selected source files.'}</p></div><div className="analysis-progress-score"><strong>{progress}%</strong><span>{remaining}</span></div><div className="analysis-progress-track"><i style={{ width: `${progress}%` }} /></div><ol className="analysis-pipeline">{stages.map((item, index) => <li className={index < stage ? 'complete' : index === stage ? 'current' : ''} key={item.label}><span>{index < stage ? <CheckCircle2 size={17} /> : index === stage ? <LoaderCircle size={18} /> : <i />}</span><div><strong>{item.label}</strong><small>{item.detail}</small></div></li>)}</ol></div>
    <div className="analysis-progress-kpis"><ProgressKpi icon={<UsersRound size={21} />} label="Experts" value={completedLabel} detail={totalExperts ? 'Completed tasks' : 'Preparing tasks'} /><ProgressKpi icon={<FileCode2 size={21} />} label="Files" value={job.fileCount.toLocaleString()} detail="Selected source files" /><ProgressKpi icon={<ShieldAlert size={21} />} label="Findings" value={findingCount.toLocaleString()} detail="Detected so far" /><ProgressKpi icon={<Clock3 size={21} />} label="Elapsed time" value={formatElapsed(elapsedSeconds)} detail="Since scan started" /></div>
    <div className="analysis-progress-bottom"><section><h3>Currently running</h3><div className="analysis-running-item"><span><LoaderCircle size={23} /></span><div><strong>{stage === 2 ? 'Parallel expert analysis' : stages[stage].label}</strong><small>{stage === 2 && activeExperts ? `${activeExperts} expert requests currently active` : job.message || 'Preparing the next analysis step'}</small></div><b>{progress}%</b></div></section><section><h3>Completed work</h3><div className="analysis-completed-list"><p><CheckCircle2 size={16} /> Repository and source files prepared</p><p className={stage > 1 ? '' : 'pending'}><CheckCircle2 size={16} /> Context build and static analysis</p><p className={completedExperts ? '' : 'pending'}><CheckCircle2 size={16} /> {totalExperts ? `${completedExperts} expert tasks completed` : 'Expert tasks will appear here'}</p></div></section></div>
  </section>
}

function ProgressKpi({ icon, label, value, detail }: { icon: ReactNode; label: string; value: string; detail: string }) { return <article className="analysis-progress-kpi"><span>{icon}</span><div><small>{label}</small><strong>{value}</strong><p>{detail}</p></div></article> }

function formatElapsed(seconds: number) { const minutes = Math.floor(seconds / 60); const remainingSeconds = seconds % 60; return `${String(minutes).padStart(2, '0')}:${String(remainingSeconds).padStart(2, '0')}` }

function FindingsView({ findings, validated, uncertain, rejected, onOpenCode, onGeneratePatch }: { findings: FindingBundle[]; validated: number; uncertain: number; rejected: number; onOpenCode: (id: string) => void; onGeneratePatch: (id: string) => void }) {
  const [selectedId, setSelectedId] = useState(findings[0]?.finding.finding_id || '')
  const [showTechnical, setShowTechnical] = useState(false)
  const selected = findings.find((item) => item.finding.finding_id === selectedId) || findings[0]
  useEffect(() => { if (!findings.some((item) => item.finding.finding_id === selectedId)) setSelectedId(findings[0]?.finding.finding_id || '') }, [findings, selectedId])
  if (!selected) return <section className="empty-workbench-panel"><ListChecks size={28} /><h2>No findings</h2><p>This scan has no reportable vulnerabilities.</p></section>
  const { finding, validation } = selected
  return <section className="findings-split-view">
    <div className="finding-summary-strip"><div><span>Detected</span><strong>{findings.length}</strong></div><div className="validated"><span>Validated</span><strong>{validated}</strong></div><div className="uncertain"><span>Needs review</span><strong>{uncertain}</strong></div><div><span>Rejected</span><strong>{rejected}</strong></div></div>
    <div className="findings-split-content">
      <aside className="finding-navigation-list">{findings.map((bundle) => <button key={bundle.finding.finding_id} className={bundle.finding.finding_id === finding.finding_id ? 'active' : ''} onClick={() => { setSelectedId(bundle.finding.finding_id); setShowTechnical(false) }}><VerdictMark verdict={bundle.validation.verdict} /><span><strong>{bundle.finding.cwes?.[0] || 'CWE'}</strong><b>{bundle.finding.title}</b><small>{bundle.finding.file}:{bundle.finding.line_start}</small></span></button>)}</aside>
      <article className="finding-detail"><div className="finding-detail-heading"><div><span className="eyebrow">{finding.cwes?.join(' · ') || 'SECURITY FINDING'}</span><h2>{finding.title}</h2><code>{finding.file} · {finding.function || 'source'} · Line {finding.line_start}</code></div><StatusBadge status={validation.verdict} /></div><DetailField label="Root cause" value={finding.root_cause} /><DetailField label="Impact" value={finding.consequence} />{finding.preconditions?.length ? <DetailList label="Conditions" values={finding.preconditions} /> : null}<details className="technical-disclosure" open={showTechnical} onToggle={(event) => setShowTechnical(event.currentTarget.open)}><summary>Technical evidence</summary>{finding.evidence_for?.length ? <DetailList label="Evidence" values={finding.evidence_for} /> : null}{validation.reasons?.length ? <DetailList label="Validation reasons" values={validation.reasons} /> : null}{finding.supporting_experts?.length ? <DetailList label="Supporting experts" values={finding.supporting_experts} /> : null}</details><div className="finding-detail-actions"><button className="secondary-button compact" onClick={() => onOpenCode(finding.finding_id)}><Code2 size={14} /> View in code</button><button className="primary-button compact" disabled={validation.verdict !== 'validated'} onClick={() => onGeneratePatch(finding.finding_id)}><WandSparkles size={14} /> Generate patch</button></div></article>
    </div>
  </section>
}

function PatchWorkspace({ findings, selected, setSelected, patch, busy, onGenerate, onAction, analysisId }: { findings: FindingBundle[]; selected: Set<string>; setSelected: React.Dispatch<React.SetStateAction<Set<string>>>; patch?: PatchBatch | null; busy: boolean; onGenerate: () => void; onAction: (action: 'approve' | 'reject') => void; analysisId: string }) {
  const selectable = findings.filter((item) => item.validation.verdict === 'validated')
  const toggle = (findingId: string) => setSelected((current) => { const next = new Set(current); next.has(findingId) ? next.delete(findingId) : next.add(findingId); return next })
  return <section className="patch-workspace"><header><div><span className="eyebrow">PATCH WORKSPACE</span><h2>Choose vulnerabilities to fix</h2><p>Use one finding for a quick patch, or combine several findings here.</p></div><button className="primary-button compact" disabled={!selected.size || busy} onClick={onGenerate}><WandSparkles size={15} /> {busy ? 'Generating…' : `Generate patch (${selected.size})`}</button></header><div className="patch-workspace-content"><div className="patch-target-list">{selectable.map((bundle) => <label key={bundle.finding.finding_id}><input type="checkbox" checked={selected.has(bundle.finding.finding_id)} onChange={() => toggle(bundle.finding.finding_id)} /><VerdictMark verdict={bundle.validation.verdict} /><span><strong>{bundle.finding.cwes?.[0] || 'CWE'}</strong><b>{bundle.finding.title}</b><small>{bundle.finding.file}:{bundle.finding.line_start}</small></span></label>)}{!selectable.length && <div className="empty-state">No patchable findings.</div>}</div><div className="patch-preview">{patch ? <Suspense fallback={<WorkbenchLoader />}><PatchDiffPanel analysisId={analysisId} patch={patch} findings={findings} busy={busy} onAction={onAction} /></Suspense> : <div className="empty-workbench-panel"><FileDiff size={28} /><h2>Patch preview</h2><p>Select one or more findings, then generate a patch.</p></div>}</div></div></section>
}

function OverviewPanel({ analysis, validatedCount }: { analysis: NonNullable<AnalysisDetail['analysis']>; validatedCount: number }) { const metrics = [['Source files', analysis.summary.source_file_count], ['Candidates', analysis.summary.candidate_count], ['Findings', analysis.summary.finding_count], ['Validated', validatedCount], ['LLM requests', analysis.summary.request_count], ['Total cost', `$${Number(analysis.summary.total_cost || 0).toFixed(4)}`]]; return <section className="overview-workbench-panel"><div className="detail-metric-row">{metrics.map(([label, value]) => <div key={String(label)}><span>{label}</span><strong>{value}</strong></div>)}</div><div className="overview-columns"><div><h2>Scan summary</h2><dl><div><dt>CWE hypotheses</dt><dd>{analysis.summary.cwe_hypothesis_count}</dd></div><div><dt>Expert tasks</dt><dd>{analysis.summary.submitted_expert_task_count}</dd></div><div><dt>Failed tasks</dt><dd>{analysis.summary.failed_expert_task_count ?? 0}</dd></div></dl></div><div><h2>Verdict distribution</h2>{['validated', 'uncertain', 'rejected'].map((verdict) => { const count = analysis.findings.filter((item) => item.validation.verdict === verdict).length; return <div className="verdict-distribution" key={verdict}><StatusBadge status={verdict} /><div><i style={{ width: `${analysis.findings.length ? count / analysis.findings.length * 100 : 0}%` }} /></div><strong>{count}</strong></div> })}</div></div></section> }
function TabButton({ active, onClick, icon, label, count }: { active: boolean; onClick: () => void; icon: React.ReactNode; label: string; count?: number }) { return <button className={active ? 'active' : ''} onClick={onClick}>{icon}{label}{count !== undefined && <span>{count}</span>}</button> }
function DetailField({ label, value }: { label: string; value?: string | null }) { return value ? <section className="finding-detail-field"><h3>{label}</h3><p>{value}</p></section> : null }
function DetailList({ label, values }: { label: string; values: string[] }) { return <section className="finding-detail-field"><h3>{label}</h3><ul>{values.map((value, index) => <li key={`${value}-${index}`}>{value}</li>)}</ul></section> }
function VerdictMark({ verdict }: { verdict: string }) { return <span className={`verdict-mark ${verdict}`} aria-label={verdict}>{verdict === 'validated' ? '●' : verdict === 'uncertain' ? '▲' : '○'}</span> }
function WorkbenchLoader() { return <div className="empty-workbench-panel"><div className="loader" /><p>Loading workspace…</p></div> }
function ErrorMessage({ error }: { error: UiError }) { return <div className="error-box" role="alert"><div>{error.message}</div>{error.traceId && <small>Error ID: {error.traceId}</small>}</div> }
function isAnalysisTab(value: string | null): value is AnalysisTab { return value === 'findings' || value === 'code' || value === 'overview' || value === 'trace' }
function toUiError(reason: unknown, fallback: string): UiError { if (reason instanceof ApiError) return { message: reason.message || fallback, traceId: reason.traceId }; return { message: reason instanceof Error ? reason.message : fallback } }
