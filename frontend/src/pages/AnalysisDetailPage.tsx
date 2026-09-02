import {
  AlertTriangle,
  ArrowLeft,
  CircleStop,
  Code2,
  Download,
  FileDiff,
  ListChecks,
  Route,
  ShieldAlert,
  WandSparkles,
  XCircle
} from 'lucide-react'
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api, ApiError } from '../api'
import StatusBadge from '../components/StatusBadge'
import { useSettings } from '../settings/SettingsContext'
import type { AnalysisDetail, AnalysisJob, AnalysisStatus, AnalysisSyncInfo, FindingBundle, PatchBatch } from '../types'
import './AnalysisDetailPage.css'

type DetailTab = 'overview' | 'code' | 'findings' | 'patch' | 'trace'
type UiError = { message: string; traceId?: string }

const SecurityWorkbench = lazy(() =>
  import('../components/workbench/SecurityWorkbench').then((module) => ({
    default: module.SecurityWorkbench
  }))
)
const PatchDiffPanel = lazy(() =>
  import('../components/workbench/SecurityWorkbench').then((module) => ({
    default: module.PatchDiffPanel
  }))
)
const AnalysisTracePanel = lazy(() =>
  import('../components/workbench/SecurityWorkbench').then((module) => ({
    default: module.AnalysisTracePanel
  }))
)

export default function AnalysisDetailPage() {
  const { id } = useParams()
  const { openRouterApiKey } = useSettings()
  const [detail, setDetail] = useState<AnalysisDetail | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [activeFindingId, setActiveFindingId] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<DetailTab>('code')
  const [initialLoadError, setInitialLoadError] = useState<UiError | null>(null)
  const [pollError, setPollError] = useState<UiError | null>(null)
  const [actionError, setActionError] = useState<UiError | null>(null)
  const [patchBusy, setPatchBusy] = useState(false)
  const [cancelBusy, setCancelBusy] = useState(false)
  const consecutivePollFailures = useRef(0)

  const applyDetail = useCallback((result: AnalysisDetail) => {
    setDetail(result)
    const findings = result.analysis?.findings || []
    setActiveFindingId((current) =>
      current && findings.some((item) => item.finding.finding_id === current)
        ? current
        : findings[0]?.finding.finding_id || null
    )
    if (result.analysis?.patch_batch?.finding_ids) {
      setSelected(new Set(result.analysis.patch_batch.finding_ids))
    }
    setPollError(syncWarning(result.sync))
  }, [])

  const refreshDetail = useCallback(async () => {
    if (!id) return
    const result = await api.get<AnalysisDetail>(`/api/analyses/${id}`)
    applyDetail(result)
    return result
  }, [applyDetail, id])

  useEffect(() => {
    let disposed = false
    setInitialLoadError(null)
    refreshDetail().catch((reason) => {
      if (!disposed) setInitialLoadError(toUiError(reason, '분석 정보를 불러오지 못했습니다.'))
    })
    return () => { disposed = true }
  }, [refreshDetail])

  useEffect(() => {
    const status = detail?.job.status
    if (!status || !['uploading', 'queued', 'analyzing', 'cancelling'].includes(status)) return

    let disposed = false
    let timer: number | undefined

    const recordPollFailure = (reason: unknown) => {
      consecutivePollFailures.current += 1
      if (consecutivePollFailures.current >= 3) {
        const error = toUiError(reason, '분석 상태 갱신이 일시적으로 지연되고 있습니다.')
        setPollError({
          message: '분석 상태 갱신이 일시적으로 지연되고 있습니다.',
          traceId: error.traceId
        })
      }
    }

    const poll = async () => {
      try {
        const result = await api.get<AnalysisStatus>(`/api/analyses/${id}/status`)
        consecutivePollFailures.current = 0

        if (['completed', 'partial', 'failed', 'cancelled'].includes(result.job.status)) {
          try {
            await refreshDetail()
            consecutivePollFailures.current = 0
          } catch (reason) {
            recordPollFailure(reason)
          }
        } else {
          setDetail((current) => current ? {
            ...current,
            job: result.job,
            sync: result.sync
          } : current)
          setPollError(syncWarning(result.sync))
        }
      } catch (reason) {
        recordPollFailure(reason)
      }

      if (!disposed) timer = window.setTimeout(poll, 2000)
    }

    timer = window.setTimeout(poll, 2000)
    return () => {
      disposed = true
      if (timer !== undefined) window.clearTimeout(timer)
    }
  }, [detail?.job.status, id, refreshDetail])

  const findings = detail?.analysis?.findings ?? []
  const validated = useMemo(
    () => findings.filter((item) => item.validation.verdict === 'validated'),
    [findings]
  )

  const togglePatch = useCallback((findingId: string, checked: boolean) => {
    setSelected((before) => {
      const next = new Set(before)
      if (checked) next.add(findingId)
      else next.delete(findingId)
      return next
    })
  }, [])

  const proposePatch = async () => {
    if (!id || !selected.size) return
    if (!openRouterApiKey.trim()) {
      setActionError({ message: '설정 탭에서 패치 생성에 사용할 OpenRouter API Key를 저장해 주세요.' })
      return
    }
    const containsUncertain = findings.some((item) =>
      selected.has(item.finding.finding_id) &&
      item.validation.verdict === 'uncertain'
    )
    if (containsUncertain && !window.confirm(
      '선택한 항목 중 아직 완전히 검증되지 않은 Finding이 있습니다. 그래도 패치를 생성할까요?'
    )) return
    setPatchBusy(true)
    setActionError(null)
    try {
      await api.post<PatchBatch>(`/api/analyses/${id}/patches/proposal`, {
        findingIds: Array.from(selected),
        apiKey: openRouterApiKey.trim()
      })
      await refreshDetail()
      setActiveTab('patch')
    } catch (reason) {
      setActionError(toUiError(reason, '패치 생성에 실패했습니다.'))
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
      await api.post<PatchBatch>(
        `/api/analyses/${id}/patches/${encodeURIComponent(patch.patch_id)}/${action}`
      )
      await refreshDetail()
    } catch (reason) {
      setActionError(toUiError(reason, '패치 처리에 실패했습니다.'))
    } finally {
      setPatchBusy(false)
    }
  }

  const cancelAnalysis = async () => {
    if (!id || detail?.job.status === 'cancelling') return
    if (!window.confirm('진행 중인 분석을 중단할까요? 이미 OpenRouter에 전송된 요청은 현재 응답 또는 timeout까지 처리될 수 있습니다.')) return
    setCancelBusy(true)
    setActionError(null)
    try {
      const job = await api.post<AnalysisJob>(`/api/analyses/${id}/cancel`)
      setDetail((current) => current ? { ...current, job } : current)
    } catch (reason) {
      setActionError(toUiError(reason, '분석 중단을 요청하지 못했습니다.'))
    } finally {
      setCancelBusy(false)
    }
  }

  if (!detail) {
    return (
      <div className="page">
        <Link className="back-link" to="/analyses"><ArrowLeft size={16} /> 분석 이력</Link>
        {initialLoadError
          ? <ErrorMessage error={initialLoadError} />
          : <div className="loader" />}
      </div>
    )
  }

  const { job, analysis } = detail
  const analysisActive = ['uploading', 'queued', 'analyzing', 'cancelling'].includes(job.status)
  const patch = analysis?.patch_batch
  const patchLocked = patch?.status === 'approved'
  const patchComposer = !patchLocked ? (
    <div className="patch-generation-actions">
      <button
        className="primary-button compact"
        disabled={!selected.size || !openRouterApiKey.trim() || patchBusy}
        onClick={proposePatch}
      >
        <WandSparkles size={15} />
        {patchBusy
          ? '생성 중…'
          : patch
            ? `패치 재생성 v${(patch.revision ?? 1) + 1} (${selected.size})`
            : `통합 패치 생성 (${selected.size})`}
      </button>
      <p className="patch-composer-help">
        Validated는 바로, Uncertain은 확인 후 패치할 수 있습니다. <Link to="/settings">설정 탭의 API Key</Link>를 이 요청에만 사용합니다.
      </p>
    </div>
  ) : null

  return (
    <div className="page analysis-detail-page">
      <Link className="back-link" to="/analyses">
        <ArrowLeft size={16} /> 분석 이력
      </Link>

      <header className="detail-header workbench-detail-header">
        <div>
          <span className="eyebrow">SECURITY WORKBENCH</span>
          <h1>{job.projectName}</h1>
          <p>
            {new Date(job.createdAt).toLocaleString('ko-KR')} · {job.fileCount.toLocaleString()}개 업로드 파일 · {job.modelId}
          </p>
        </div>
        <div className="detail-actions">
          <StatusBadge status={job.status} />
          {analysisActive && (
            <button className="danger-button compact" disabled={cancelBusy || job.status === 'cancelling'} onClick={cancelAnalysis}>
              <CircleStop size={15} /> {job.status === 'cancelling' ? '중단 요청됨' : cancelBusy ? '요청 중…' : '분석 중단'}
            </button>
          )}
          {(['completed', 'partial'].includes(job.status) || (job.status === 'cancelled' && analysis)) && (
            <a className="secondary-button compact" href={api.downloadUrl(`/api/analyses/${job.id}/download`)}>
              <Download size={15} /> 프로젝트 다운로드
            </a>
          )}
        </div>
      </header>

      {actionError && <ErrorMessage error={actionError} />}

      {pollError && (
        <div className={`poll-warning${analysis && !analysisActive ? ' compact' : ''}`} role="status">
          <AlertTriangle size={16} />
          <div>
            <strong>{analysis && !analysisActive ? '결과 저장됨 · 동기화 지연' : pollError.message}</strong>
            <span>{analysis && !analysisActive ? pollError.message : `마지막 정상 상태: ${job.progress}% · ${job.message || job.status}`}</span>
            {pollError.traceId && <small>오류 ID: {pollError.traceId}</small>}
          </div>
        </div>
      )}

      {analysisActive && (
        <section className="panel progress-panel">
          <div className="panel-head">
            <div><h2>{job.message || '분석을 진행하고 있습니다.'}</h2><p>{job.status === 'cancelling' ? '현재 실행 중인 요청을 정리하고 있습니다.' : '완료될 때까지 이 화면이 자동으로 갱신됩니다.'}</p></div>
            <strong>{job.progress}%</strong>
          </div>
          <div className="progress-track"><div className="progress-fill" style={{ width: `${job.progress}%` }} /></div>
        </section>
      )}

      {job.status === 'failed' && (
        <section className="panel danger-panel">
          <XCircle /><div><h2>분석에 실패했습니다.</h2><p>{job.errorMessage || job.message}</p></div>
        </section>
      )}

      {job.status === 'partial' && (
        <section className="panel partial-result-panel">
          <AlertTriangle /><div><h2>분석 결과가 준비되었습니다.</h2><p>완료된 Expert 결과를 기반으로 보고서를 생성했습니다. 미완료 작업의 상세 내용은 Analysis Trace에서 확인할 수 있습니다.</p></div>
        </section>
      )}

      {job.status === 'cancelled' && (
        <section className="panel warning-panel">
          <CircleStop /><div><h2>분석을 중단했습니다.</h2><p>{analysis ? '중단 시점까지 완료된 Expert 결과를 저장했습니다. 아래에서 부분 결과와 미완료 작업을 확인할 수 있습니다.' : 'Expert 분석이 시작되기 전에 중단되어 저장할 결과가 없습니다.'}</p></div>
        </section>
      )}

      {analysis && id && (
        <>
          <nav className="detail-tabs" aria-label="분석 상세 화면">
            <TabButton active={activeTab === 'overview'} onClick={() => setActiveTab('overview')} icon={<ShieldAlert size={14} />} label="Overview" />
            <TabButton active={activeTab === 'code'} onClick={() => setActiveTab('code')} icon={<Code2 size={14} />} label="Code" />
            <TabButton active={activeTab === 'findings'} onClick={() => setActiveTab('findings')} icon={<ListChecks size={14} />} label="Findings" count={findings.length} />
            <TabButton active={activeTab === 'patch'} onClick={() => setActiveTab('patch')} icon={<FileDiff size={14} />} label="Patch" count={patch ? 1 : undefined} />
            <TabButton active={activeTab === 'trace'} onClick={() => setActiveTab('trace')} icon={<Route size={14} />} label="Analysis Trace" />
          </nav>

          {activeTab === 'overview' && (
            <OverviewPanel analysis={analysis} validatedCount={validated.length} />
          )}

          {activeTab === 'code' && (
            <Suspense fallback={<WorkbenchLoader />}>
              <SecurityWorkbench
                analysisId={id}
                analysis={analysis}
                activeFindingId={activeFindingId}
                onFindingSelect={setActiveFindingId}
                selectedForPatch={selected}
                onPatchToggle={togglePatch}
                patchLocked={patchLocked}
                patchComposer={patchComposer}
              />
            </Suspense>
          )}

          {activeTab === 'findings' && (
            <FindingsPanel
              findings={findings}
              selected={selected}
              patchLocked={patchLocked}
              onPatchToggle={togglePatch}
              onOpenCode={(findingId) => {
                setActiveFindingId(findingId)
                setActiveTab('code')
              }}
              patchComposer={patchComposer}
            />
          )}

          {activeTab === 'patch' && (
            patch ? (
              <>
                <Suspense fallback={<WorkbenchLoader />}>
                  <PatchDiffPanel analysisId={id} patch={patch} findings={findings} busy={patchBusy} onAction={patchAction} />
                </Suspense>
                {!patchLocked && <div className="patch-regeneration-row">{patchComposer}</div>}
              </>
            ) : (
              <section className="empty-workbench-panel">
                <FileDiff size={28} />
                <h2>아직 생성된 패치가 없습니다.</h2>
                <p>Code 또는 Findings 탭에서 검증된 취약점을 선택하고 통합 패치를 생성하세요.</p>
                <button className="secondary-button compact" onClick={() => setActiveTab('code')}>Code에서 선택</button>
              </section>
            )
          )}

          {activeTab === 'trace' && (
            <Suspense fallback={<WorkbenchLoader />}><AnalysisTracePanel analysis={analysis} /></Suspense>
          )}
        </>
      )}
    </div>
  )
}

function syncWarning(sync?: AnalysisSyncInfo | null): UiError | null {
  if (!sync?.warning) return null
  return {
    message: sync.warning,
    traceId: sync.traceId || undefined
  }
}

function toUiError(reason: unknown, fallback: string): UiError {
  if (reason instanceof ApiError) {
    const message = reason.status === 401
      ? '로그인이 만료되었습니다. 다시 로그인해주세요.'
      : reason.status === 403
        ? '이 작업을 수행할 권한이 없습니다.'
        : reason.status === 404
          ? '분석 기록을 찾을 수 없습니다.'
          : reason.message || fallback
    return { message, traceId: reason.traceId }
  }
  return {
    message: reason instanceof Error ? reason.message : fallback
  }
}

function ErrorMessage({ error }: { error: UiError }) {
  return (
    <div className="error-box" role="alert">
      <div>{error.message}</div>
      {error.traceId && <small>오류 ID: {error.traceId}</small>}
    </div>
  )
}

function WorkbenchLoader() {
  return <div className="empty-workbench-panel"><div className="loader" /><p>보안 워크벤치를 불러오는 중입니다…</p></div>
}

function TabButton({
  active,
  onClick,
  icon,
  label,
  count
}: {
  active: boolean
  onClick: () => void
  icon: React.ReactNode
  label: string
  count?: number
}) {
  return (
    <button className={active ? 'active' : ''} onClick={onClick}>
      {icon}{label}{count !== undefined && <span>{count}</span>}
    </button>
  )
}

function OverviewPanel({
  analysis,
  validatedCount
}: {
  analysis: NonNullable<AnalysisDetail['analysis']>
  validatedCount: number
}) {
  const metrics = [
    ['Source files', analysis.summary.source_file_count],
    ['Candidates', analysis.summary.candidate_count],
    ['Findings', analysis.summary.finding_count],
    ['Validated', validatedCount],
    ['LLM requests', analysis.summary.request_count],
    ['Expert coverage', formatPercent(analysis.summary.expert_task_coverage ?? 1)],
    ['Candidate coverage', formatPercent(analysis.summary.candidate_coverage ?? 1)],
    ['Total cost', `$${Number(analysis.summary.total_cost || 0).toFixed(4)}`]
  ]
  return (
    <section className="overview-workbench-panel">
      <div className="detail-metric-row">
        {metrics.map(([label, value]) => <div key={label}><span>{label}</span><strong>{value}</strong></div>)}
      </div>
      <div className="overview-columns">
        <div>
          <h2>Scan summary</h2>
          <dl>
            <div><dt>CWE hypotheses</dt><dd>{analysis.summary.cwe_hypothesis_count}</dd></div>
            <div><dt>Planned expert tasks</dt><dd>{analysis.summary.expert_task_count ?? analysis.summary.submitted_expert_task_count}</dd></div>
            <div><dt>Submitted expert tasks</dt><dd>{analysis.summary.submitted_expert_task_count}</dd></div>
            <div><dt>Completed expert tasks</dt><dd>{analysis.summary.completed_expert_task_count ?? analysis.summary.submitted_expert_task_count}</dd></div>
            <div><dt>Failed expert tasks</dt><dd>{analysis.summary.failed_expert_task_count ?? 0}</dd></div>
            <div><dt>Recovered expert tasks</dt><dd>{analysis.summary.recovered_expert_task_count ?? 0}</dd></div>
            <div><dt>Timed out expert tasks</dt><dd>{analysis.summary.timed_out_expert_task_count ?? 0}</dd></div>
            <div><dt>Covered candidates</dt><dd>{analysis.summary.covered_candidate_count ?? analysis.summary.candidate_count} / {analysis.summary.candidate_count}</dd></div>
            <div><dt>Incomplete candidates</dt><dd>{analysis.summary.incomplete_candidate_count ?? 0}</dd></div>
            <div><dt>Skipped source files</dt><dd>{analysis.summary.skipped_source_file_count ?? 0}</dd></div>
            <div><dt>Max concurrency</dt><dd>{analysis.summary.max_concurrent_expert_requests ?? '—'}</dd></div>
            <div><dt>Skipped expert tasks</dt><dd>{analysis.summary.skipped_expert_task_count ?? 0}</dd></div>
            <div><dt>Structural rejections</dt><dd>{analysis.summary.structural_rejected_count ?? 0}</dd></div>
            <div><dt>Pipeline errors</dt><dd>{analysis.errors?.length || 0}</dd></div>
          </dl>
          {(analysis.errors?.length || 0) > 0 && (
            <details className="overview-errors" open>
              <summary>Pipeline errors 상세</summary>
              <ul>{analysis.errors?.map((error, index) => <li key={`${error}-${index}`}>{error}</li>)}</ul>
            </details>
          )}
        </div>
        <div>
          <h2>Verdict distribution</h2>
          {['validated', 'uncertain', 'rejected'].map((verdict) => {
            const count = analysis.findings.filter((item) => item.validation.verdict === verdict).length
            return (
              <div className="verdict-distribution" key={verdict}>
                <StatusBadge status={verdict} />
                <div><i style={{ width: `${analysis.findings.length ? count / analysis.findings.length * 100 : 0}%` }} /></div>
                <strong>{count}</strong>
              </div>
            )
          })}
        </div>
      </div>
    </section>
  )
}

function FindingsPanel({
  findings,
  selected,
  patchLocked,
  onPatchToggle,
  onOpenCode,
  patchComposer
}: {
  findings: FindingBundle[]
  selected: Set<string>
  patchLocked: boolean
  onPatchToggle: (findingId: string, checked: boolean) => void
  onOpenCode: (findingId: string) => void
  patchComposer: React.ReactNode
}) {
  const [query, setQuery] = useState('')
  const [verdict, setVerdict] = useState('all')
  const filtered = findings.filter((bundle) => {
    if (verdict !== 'all' && bundle.validation.verdict !== verdict) return false
    const value = [bundle.finding.title, bundle.finding.file, ...(bundle.finding.cwes || [])].join(' ').toLowerCase()
    return value.includes(query.trim().toLowerCase())
  })
  return (
    <section className="findings-workbench-panel">
      <div className="findings-toolbar">
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="제목, CWE, 파일 검색" />
        <select value={verdict} onChange={(event) => setVerdict(event.target.value)}>
          <option value="all">모든 검증 결과</option><option value="validated">Validated</option>
          <option value="uncertain">Uncertain</option><option value="rejected">Rejected</option>
        </select>
        <div className="findings-patch-composer">{patchComposer}</div>
      </div>
      <div className="finding-table-wrap">
        <table className="finding-table">
          <thead><tr><th>Patch</th><th>Finding</th><th>CWE</th><th>Location</th><th>Expert</th><th>Validation</th><th>Detection confidence</th><th>Validation confidence</th></tr></thead>
          <tbody>
            {filtered.map((bundle) => {
              const finding = bundle.finding
              const canPatch = bundle.validation.verdict !== 'rejected'
              return (
                <tr key={finding.finding_id} onDoubleClick={() => onOpenCode(finding.finding_id)}>
                  <td><input type="checkbox" checked={selected.has(finding.finding_id)} disabled={!canPatch || patchLocked} onChange={(event) => onPatchToggle(finding.finding_id, event.target.checked)} /></td>
                  <td><button onClick={() => onOpenCode(finding.finding_id)}>{finding.title}</button><small>{finding.root_cause}</small></td>
                  <td>{finding.cwes?.join(', ') || '-'}</td>
                  <td><code>{finding.file}:{finding.line_start}</code></td>
                  <td>{expertLabel(finding.expert || finding.supporting_experts?.[0] || '-')}</td>
                  <td><StatusBadge status={bundle.validation.verdict} /></td>
                  <td><strong>{formatPercent(finding.confidence)}</strong></td>
                  <td>{bundle.validation.confidence === null ? '규칙 기반' : formatPercent(bundle.validation.confidence)}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {!filtered.length && <div className="empty-state">검색 조건에 맞는 취약점이 없습니다.</div>}
      </div>
    </section>
  )
}

function expertLabel(expert: string) {
  const labels: Record<string, string> = {
    memory_bounds: 'E1 Memory Safety',
    lifetime_resource: 'E2 Lifetime / Resource',
    integer_size_type: 'E3 Integer / Size / Type',
    taint_api_contract: 'E4 Taint / API Contract',
    control_state_error: 'E5 Control / State / Error',
    concurrency_toctou: 'E6 Concurrency / TOCTOU'
  }
  return labels[expert] || expert
}

function formatPercent(value: number | null | undefined) {
  return `${Math.round((Number(value) || 0) * 100)}%`
}
