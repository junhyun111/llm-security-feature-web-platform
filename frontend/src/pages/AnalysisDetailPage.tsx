import {
  ArrowLeft,
  Code2,
  Download,
  FileDiff,
  ListChecks,
  Route,
  ShieldAlert,
  WandSparkles,
  XCircle
} from 'lucide-react'
import { lazy, Suspense, useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { api } from '../api'
import StatusBadge from '../components/StatusBadge'
import type { AnalysisDetail, FindingBundle, PatchBatch } from '../types'
import './AnalysisDetailPage.css'

type DetailTab = 'overview' | 'code' | 'findings' | 'patch' | 'trace'

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
  const [detail, setDetail] = useState<AnalysisDetail | null>(null)
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [activeFindingId, setActiveFindingId] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState<DetailTab>('code')
  const [error, setError] = useState('')
  const [patchBusy, setPatchBusy] = useState(false)
  const [patchApiKey, setPatchApiKey] = useState('')

  const load = useCallback(async () => {
    if (!id) return
    try {
      const result = await api.get<AnalysisDetail>(`/api/analyses/${id}`)
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
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '분석 정보를 불러오지 못했습니다.')
    }
  }, [id])

  useEffect(() => {
    load()
  }, [load])

  useEffect(() => {
    const status = detail?.job.status
    if (!status || !['uploading', 'queued', 'analyzing'].includes(status)) return
    const timer = window.setInterval(load, 1800)
    return () => window.clearInterval(timer)
  }, [detail?.job.status, load])

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
    if (!patchApiKey.trim()) {
      setError('패치 생성에 사용할 OpenRouter API Key를 입력해 주세요.')
      return
    }
    setPatchBusy(true)
    setError('')
    try {
      await api.post<PatchBatch>(`/api/analyses/${id}/patches/proposal`, {
        findingIds: Array.from(selected),
        apiKey: patchApiKey.trim()
      })
      setPatchApiKey('')
      await load()
      setActiveTab('patch')
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '패치 생성에 실패했습니다.')
    } finally {
      setPatchBusy(false)
    }
  }

  const patchAction = async (action: 'approve' | 'reject') => {
    const patch = detail?.analysis?.patch_batch
    if (!id || !patch) return
    setPatchBusy(true)
    setError('')
    try {
      await api.post<PatchBatch>(
        `/api/analyses/${id}/patches/${encodeURIComponent(patch.patch_id)}/${action}`
      )
      await load()
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '패치 처리에 실패했습니다.')
    } finally {
      setPatchBusy(false)
    }
  }

  if (!detail) {
    return (
      <div className="page">
        <Link className="back-link" to="/analyses"><ArrowLeft size={16} /> 분석 이력</Link>
        {error ? <div className="error-box">{error}</div> : <div className="loader" />}
      </div>
    )
  }

  const { job, analysis } = detail
  const patch = analysis?.patch_batch
  const patchComposer = !patch ? (
    <div className="patch-generation-actions">
      <input
        className="patch-key-input"
        type="password"
        value={patchApiKey}
        onChange={(event) => setPatchApiKey(event.target.value)}
        placeholder="OpenRouter API Key 재입력"
        autoComplete="off"
        spellCheck={false}
        aria-label="패치 생성용 OpenRouter API Key"
      />
      <button
        className="primary-button compact"
        disabled={!selected.size || !patchApiKey.trim() || patchBusy}
        onClick={proposePatch}
      >
        <WandSparkles size={15} />
        {patchBusy ? '생성 중…' : `통합 패치 생성 (${selected.size})`}
      </button>
      <p className="patch-composer-help">
        검증된 항목만 선택할 수 있습니다. 키는 이 요청에만 사용되며 저장되지 않습니다.
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
          {job.status === 'completed' && (
            <a className="secondary-button compact" href={api.downloadUrl(`/api/analyses/${job.id}/download`)}>
              <Download size={15} /> 프로젝트 다운로드
            </a>
          )}
        </div>
      </header>

      {error && <div className="error-box">{error}</div>}

      {['uploading', 'queued', 'analyzing'].includes(job.status) && (
        <section className="panel progress-panel">
          <div className="panel-head">
            <div><h2>{job.message || '분석을 진행하고 있습니다.'}</h2><p>완료될 때까지 이 화면이 자동으로 갱신됩니다.</p></div>
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
                patchLocked={Boolean(patch)}
                patchComposer={patchComposer}
              />
            </Suspense>
          )}

          {activeTab === 'findings' && (
            <FindingsPanel
              findings={findings}
              selected={selected}
              patchLocked={Boolean(patch)}
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
              <Suspense fallback={<WorkbenchLoader />}>
                <PatchDiffPanel analysisId={id} patch={patch} findings={findings} busy={patchBusy} onAction={patchAction} />
              </Suspense>
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
            <div><dt>Submitted expert tasks</dt><dd>{analysis.summary.submitted_expert_task_count}</dd></div>
            <div><dt>Skipped expert tasks</dt><dd>{analysis.summary.skipped_expert_task_count ?? 0}</dd></div>
            <div><dt>Pipeline errors</dt><dd>{analysis.errors?.length || 0}</dd></div>
          </dl>
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
          <thead><tr><th>Patch</th><th>Finding</th><th>CWE</th><th>Location</th><th>Expert</th><th>Verdict</th><th>Confidence</th></tr></thead>
          <tbody>
            {filtered.map((bundle) => {
              const finding = bundle.finding
              const canPatch = bundle.validation.verdict === 'validated'
              return (
                <tr key={finding.finding_id} onDoubleClick={() => onOpenCode(finding.finding_id)}>
                  <td><input type="checkbox" checked={selected.has(finding.finding_id)} disabled={!canPatch || patchLocked} onChange={(event) => onPatchToggle(finding.finding_id, event.target.checked)} /></td>
                  <td><button onClick={() => onOpenCode(finding.finding_id)}>{finding.title}</button><small>{finding.root_cause}</small></td>
                  <td>{finding.cwes?.join(', ') || '-'}</td>
                  <td><code>{finding.file}:{finding.line_start}</code></td>
                  <td>{expertLabel(finding.expert || finding.supporting_experts?.[0] || '-')}</td>
                  <td><StatusBadge status={bundle.validation.verdict} /></td>
                  <td><strong>{Math.round(bundle.validation.confidence * 100)}%</strong></td>
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
