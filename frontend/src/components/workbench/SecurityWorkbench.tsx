import Editor, { DiffEditor, type OnMount } from '@monaco-editor/react'
import type { editor as MonacoEditor, IDisposable } from 'monaco-editor'
import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  FileCode2,
  FileDiff,
  FolderOpen,
  GitBranch,
  Search,
  ShieldCheck,
  X,
  XCircle
} from 'lucide-react'
import {
  type ReactNode,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState
} from 'react'
import { api } from '../../api'
import type {
  AnalysisPayload,
  FindingBundle,
  PatchBatch,
  ProjectFileContent,
  ProjectFileSummary,
  RouteDecision
} from '../../types'
import StatusBadge from '../StatusBadge'
import './SecurityWorkbench.css'
import '../../monaco'

type WorkbenchProps = {
  analysisId: string
  analysis: AnalysisPayload
  activeFindingId: string | null
  onFindingSelect: (findingId: string) => void
  selectedForPatch?: Set<string>
  onPatchToggle?: (findingId: string, checked: boolean) => void
  patchLocked?: boolean
  patchComposer?: ReactNode
  onGeneratePatch?: (findingId: string) => void
}

type FileTreeNode = {
  name: string
  path?: string
  findingCount: number
  children: FileTreeNode[]
}

export function SecurityWorkbench({
  analysisId,
  analysis,
  activeFindingId,
  onFindingSelect,
  selectedForPatch = new Set<string>(),
  onPatchToggle,
  patchLocked = false,
  patchComposer,
  onGeneratePatch
}: WorkbenchProps) {
  const [files, setFiles] = useState<ProjectFileSummary[]>([])
  const [file, setFile] = useState<ProjectFileContent | null>(null)
  const [selectedPath, setSelectedPath] = useState('')
  const [query, setQuery] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(true)
  const [editorRevision, setEditorRevision] = useState(0)
  const [problemsOpen, setProblemsOpen] = useState(false)
  const editorRef = useRef<MonacoEditor.IStandaloneCodeEditor | null>(null)
  const monacoRef = useRef<Parameters<OnMount>[1] | null>(null)

  const findings = analysis.findings || []
  const activeFinding = useMemo(
    () => findings.find((item) => item.finding.finding_id === activeFindingId) ?? null,
    [activeFindingId, findings]
  )

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    api
      .get<ProjectFileSummary[]>(`/api/analyses/${analysisId}/files?version=original`)
      .then((result) => {
        if (cancelled) return
        setFiles(result)
        const firstFindingPath = findings[0]?.finding.file
        const initial =
          result.find((item) => item.path === firstFindingPath)?.path || result[0]?.path || ''
        setSelectedPath((current) => current || initial)
      })
      .catch((reason) => {
        if (!cancelled) {
          setError(reason instanceof Error ? reason.message : '소스 파일 목록을 불러오지 못했습니다.')
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [analysisId, findings])

  useEffect(() => {
    if (!selectedPath) return
    let cancelled = false
    setLoading(true)
    setError('')
    api
      .get<ProjectFileContent>(
        `/api/analyses/${analysisId}/files/content?path=${encodeURIComponent(selectedPath)}&version=original`
      )
      .then((result) => {
        if (!cancelled) setFile(result)
      })
      .catch((reason) => {
        if (!cancelled) {
          setError(reason instanceof Error ? reason.message : '소스 파일을 불러오지 못했습니다.')
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
    }
  }, [analysisId, selectedPath])

  useEffect(() => {
    const path = activeFinding?.finding.file
    if (path && files.some((item) => item.path === path) && path !== selectedPath) {
      setSelectedPath(path)
    }
  }, [activeFinding, files, selectedPath])

  const fileFindings = useMemo(
    () => findings.filter((item) => item.finding.file === selectedPath),
    [findings, selectedPath]
  )

  const filteredFindings = useMemo(() => {
    const normalized = query.trim().toLowerCase()
    if (!normalized) return findings
    return findings.filter((item) => {
      const value = [
        item.finding.title,
        item.finding.file,
        item.finding.function,
        item.validation.verdict,
        ...(item.finding.cwes || [])
      ].join(' ').toLowerCase()
      return value.includes(normalized)
    })
  }, [findings, query])

  const selectFinding = useCallback((bundle: FindingBundle) => {
    setSelectedPath(bundle.finding.file)
    onFindingSelect(bundle.finding.finding_id)
  }, [onFindingSelect])

  const onEditorMount: OnMount = (mountedEditor, monaco) => {
    editorRef.current = mountedEditor
    monacoRef.current = monaco
    setEditorRevision((value) => value + 1)
  }

  useEffect(() => {
    const mountedEditor = editorRef.current
    const monaco = monacoRef.current
    if (!mountedEditor || !monaco || !file) return

    const lineCount = mountedEditor.getModel()?.getLineCount() || 1
    const decorations = mountedEditor.createDecorationsCollection(
      fileFindings.map((bundle) => {
        const start = clampLine(bundle.finding.line_start, lineCount)
        // Large candidate ranges obscure the actual risky statement. Decorate at most three lines.
        const end = Math.min(clampLine(bundle.finding.line_end || start, lineCount), start + 2)
        const active = bundle.finding.finding_id === activeFindingId
        return {
          range: new monaco.Range(start, 1, end, 1),
          options: {
            isWholeLine: true,
            className: active ? 'security-line-active' : 'security-line',
            glyphMarginClassName: active ? 'security-glyph-active' : 'security-glyph',
            glyphMarginHoverMessage: { value: hoverMarkdown(bundle) },
            overviewRuler: {
              color: active ? '#f85149' : '#d29922',
              position: monaco.editor.OverviewRulerLane.Right
            }
          }
        }
      })
    )

    const hover: IDisposable = monaco.languages.registerHoverProvider(file.language, {
      provideHover(model, position) {
        if (model !== mountedEditor.getModel()) return null
        const bundle = fileFindings.find((item) =>
          position.lineNumber >= item.finding.line_start &&
          position.lineNumber <= Math.max(item.finding.line_start, item.finding.line_end)
        )
        if (!bundle) return null
        return {
          range: new monaco.Range(
            clampLine(bundle.finding.line_start, lineCount),
            1,
            clampLine(bundle.finding.line_end, lineCount),
            1
          ),
          contents: [{ value: hoverMarkdown(bundle) }]
        }
      }
    })

    return () => {
      decorations.clear()
      hover.dispose()
    }
  }, [activeFindingId, editorRevision, file, fileFindings])

  useEffect(() => {
    const mountedEditor = editorRef.current
    if (!mountedEditor || !activeFinding || activeFinding.finding.file !== selectedPath) return
    const line = clampLine(
      activeFinding.finding.line_start,
      mountedEditor.getModel()?.getLineCount() || 1
    )
    mountedEditor.revealLineInCenter(line)
    mountedEditor.setPosition({ lineNumber: line, column: 1 })
  }, [activeFinding, selectedPath, file])

  const tree = useMemo(() => buildTree(files), [files])

  return (
    <section className={`security-workbench ${problemsOpen ? 'problems-open' : ''}`} aria-label="보안 코드 워크벤치">
      <div className="workbench-topbar">
        <div className="workbench-breadcrumb">
          <GitBranch size={14} />
          <span>original</span>
          <span>/</span>
          <strong>{selectedPath || 'source'}</strong>
        </div>
        <span className="workbench-file-state">
          {files.length} files · {findings.length} problems
        </span>
      </div>

      <div className="workbench-main">
        <aside className="workbench-explorer">
          <WorkbenchTitle icon={<FolderOpen size={14} />} title="Explorer" />
          <div className="project-tree-heading">
            <ChevronDown size={13} /> PROJECT SOURCE
          </div>
          <div className="file-tree">
            {tree.children.map((node) => (
              <FileTree
                key={`${node.path || 'dir'}-${node.name}`}
                node={node}
                depth={0}
                selectedPath={selectedPath}
                onSelect={setSelectedPath}
              />
            ))}
          </div>
        </aside>

        <div className="workbench-editor-column">
          <div className="editor-tabbar">
            <div className="editor-tab active">
              <FileCode2 size={14} />
              {file?.name || 'source'}
              {fileFindings.length > 0 && <span>{fileFindings.length}</span>}
            </div>
          </div>
          <div className="editor-stage">
            {error ? (
              <div className="workbench-message error">{error}</div>
            ) : !selectedPath && !loading ? (
              <div className="workbench-message">표시할 C/C++ 소스 파일이 없습니다.</div>
            ) : (
              <Editor
                key={file?.path || selectedPath}
                path={`original/${file?.path || selectedPath}`}
                height="100%"
                language={file?.language || 'cpp'}
                value={file?.content || ''}
                theme="vs-dark"
                loading={<div className="workbench-message">소스 파일을 여는 중입니다…</div>}
                onMount={onEditorMount}
                options={{
                  readOnly: true,
                  automaticLayout: true,
                  fontFamily: 'Cascadia Code, SFMono-Regular, Consolas, monospace',
                  fontSize: 13,
                  glyphMargin: true,
                  lineNumbersMinChars: 3,
                  minimap: { enabled: true, scale: 1, showSlider: 'mouseover' },
                  padding: { top: 12, bottom: 12 },
                  renderLineHighlight: 'line',
                  scrollBeyondLastLine: false,
                  smoothScrolling: true,
                  wordWrap: 'off'
                }}
              />
            )}
          </div>
        </div>

        <aside className="workbench-inspector">
          <WorkbenchTitle icon={<ShieldCheck size={14} />} title="Finding Inspector" />
          {activeFinding ? (
            <FindingInspector
              bundle={activeFinding}
              selected={selectedForPatch.has(activeFinding.finding.finding_id)}
              patchLocked={patchLocked}
              onPatchToggle={onPatchToggle || (() => undefined)}
              onGeneratePatch={onGeneratePatch}
            />
          ) : (
            <div className="inspector-empty">
              코드 마커나 아래 Problems 항목을 선택하면 검증 근거가 표시됩니다.
            </div>
          )}
          {patchComposer && <div className="inspector-composer">{patchComposer}</div>}
        </aside>
      </div>

      <div className="workbench-problems">
        <div className="problems-toolbar" onClick={() => setProblemsOpen((open) => !open)}>
          <div className="problems-title">
            <AlertTriangle size={14} /> This file&apos;s findings <span>{fileFindings.length}</span>
          </div>
          <label className="problems-search" onClick={(event) => event.stopPropagation()}>
            <Search size={13} />
            <input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="CWE, 파일, 함수 검색"
            />
          </label>
        </div>
        <div className="problems-list">
          {filteredFindings.map((bundle) => (
            <button
              className={`problem-row ${bundle.finding.finding_id === activeFindingId ? 'active' : ''}`}
              key={bundle.finding.finding_id}
              onClick={() => selectFinding(bundle)}
            >
              <VerdictIcon verdict={bundle.validation.verdict} />
              <span className="problem-title">{bundle.finding.title}</span>
              <span className="problem-cwe">{bundle.finding.cwes?.join(', ') || 'CWE 미분류'}</span>
              <span className="problem-location">
                {bundle.finding.file}:{bundle.finding.line_start}
              </span>
              <strong title="Detection confidence">
                D {percent(bundle.finding.confidence)}
              </strong>
            </button>
          ))}
          {!filteredFindings.length && (
            <div className="problems-empty">검색 조건에 맞는 취약점이 없습니다.</div>
          )}
        </div>
      </div>
    </section>
  )
}

function WorkbenchTitle({ icon, title }: { icon: ReactNode; title: string }) {
  return <div className="workbench-section-title">{icon}{title}</div>
}

function FileTree({
  node,
  depth,
  selectedPath,
  onSelect
}: {
  node: FileTreeNode
  depth: number
  selectedPath: string
  onSelect: (path: string) => void
}) {
  if (node.path) {
    return (
      <button
        className={`file-tree-row ${node.path === selectedPath ? 'active' : ''}`}
        style={{ paddingLeft: 10 + depth * 14 }}
        onClick={() => onSelect(node.path!)}
        title={node.path}
      >
        <FileCode2 size={13} />
        <span>{node.name}</span>
        {node.findingCount > 0 && <strong>{node.findingCount}</strong>}
      </button>
    )
  }

  return (
    <div>
      <div className="file-tree-folder" style={{ paddingLeft: 8 + depth * 14 }}>
        <ChevronDown size={12} />
        <span>{node.name}</span>
        {node.findingCount > 0 && <strong>{node.findingCount}</strong>}
      </div>
      {node.children.map((child) => (
        <FileTree
          key={`${child.path || 'dir'}-${child.name}`}
          node={child}
          depth={depth + 1}
          selectedPath={selectedPath}
          onSelect={onSelect}
        />
      ))}
    </div>
  )
}

function FindingInspector({
  bundle,
  selected,
  patchLocked,
  onPatchToggle,
  onGeneratePatch
}: {
  bundle: FindingBundle
  selected: boolean
  patchLocked: boolean
  onPatchToggle: (findingId: string, checked: boolean) => void
  onGeneratePatch?: (findingId: string) => void
}) {
  const { finding, validation } = bundle
  const patchable = validation.verdict !== 'rejected'
  return (
    <div className="finding-inspector-body">
      <div className="inspector-heading">
        <StatusBadge status={validation.verdict} />
      </div>
      <h3>{finding.title}</h3>
      <code>{finding.file}:{finding.line_start}-{finding.line_end}</code>

      <div className="inspector-confidence-grid">
        <span>Detection confidence<strong>{percent(finding.confidence)}</strong></span>
        <span>Validation confidence<strong>{validationConfidence(validation.confidence)}</strong></span>
      </div>

      <div className="inspector-tags">
        {(finding.cwes || []).map((cwe) => <span key={cwe}>{cwe}</span>)}
        {(finding.supporting_experts || (finding.expert ? [finding.expert] : []))
          .map((expert) => <span className="expert" key={expert}>{expertLabel(expert)}</span>)}
      </div>

      <InspectorField label="Root cause" text={finding.root_cause} />
      <InspectorField label="Impact" text={finding.consequence} />
      {finding.preconditions?.length ? (
        <InspectorList label="Preconditions" values={finding.preconditions} />
      ) : null}
      {finding.evidence_for?.length ? (
        <InspectorList label="Evidence for" values={finding.evidence_for} />
      ) : null}
      {finding.evidence_against?.length ? (
        <InspectorList label="Evidence against" values={finding.evidence_against} />
      ) : null}
      {validation.reasons?.length ? (
        <InspectorList label="Validation reasons" values={validation.reasons} />
      ) : null}
      {validation.checks && (
        <ValidationChecks checks={validation.checks} compact />
      )}

      {patchable && (
        <label className="inspector-patch-toggle">
          <input
            type="checkbox"
            checked={selected}
            disabled={patchLocked}
            onChange={(event) => onPatchToggle(finding.finding_id, event.target.checked)}
          />
          통합 패치에 포함{validation.verdict === 'uncertain' ? ' (생성 전 확인 필요)' : ''}
        </label>
      )}
      {onGeneratePatch && patchable && (
        <button className="primary-button compact inspector-patch-button" onClick={() => onGeneratePatch(finding.finding_id)}>
          <FileDiff size={14} /> Generate patch
        </button>
      )}
    </div>
  )
}

function InspectorField({ label, text }: { label: string; text?: string | null }) {
  if (!text) return null
  return <div className="inspector-field"><span>{label}</span><p>{text}</p></div>
}

function InspectorList({ label, values }: { label: string; values: string[] }) {
  return (
    <div className="inspector-field">
      <span>{label}</span>
      <ul>{values.map((value, index) => <li key={`${value}-${index}`}>{value}</li>)}</ul>
    </div>
  )
}

export function PatchDiffPanel({
  analysisId,
  patch,
  findings,
  busy,
  onAction
}: {
  analysisId: string
  patch: PatchBatch
  findings: FindingBundle[]
  busy: boolean
  onAction: (action: 'approve' | 'reject') => void
}) {
  const paths = useMemo(() => {
    const fromFindings = findings
      .filter((item) => patch.finding_ids.includes(item.finding.finding_id))
      .map((item) => item.finding.file)
    const fromDiff = Array.from(patch.unified_diff.matchAll(/^\+\+\+ b\/(.+)$/gm), (match) => match[1])
    return Array.from(new Set([...fromFindings, ...fromDiff]))
  }, [findings, patch])
  const [path, setPath] = useState(paths[0] || '')
  const [original, setOriginal] = useState<ProjectFileContent | null>(null)
  const [modified, setModified] = useState<ProjectFileContent | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!paths.includes(path)) setPath(paths[0] || '')
  }, [path, paths])

  useEffect(() => {
    if (!path || patch.status === 'rejected') return
    let cancelled = false
    setError('')
    const originalRequest = api.get<ProjectFileContent>(
      `/api/analyses/${analysisId}/files/content?path=${encodeURIComponent(path)}&version=original`
    )
    const modifiedRequest = patch.status === 'approved'
      ? api.get<ProjectFileContent>(
        `/api/analyses/${analysisId}/files/content?path=${encodeURIComponent(path)}&version=approved`
      )
      : api.get<ProjectFileContent>(
        `/api/analyses/${analysisId}/patches/${encodeURIComponent(patch.patch_id)}/preview/content?path=${encodeURIComponent(path)}`
      )

    Promise.all([originalRequest, modifiedRequest])
      .then(([before, after]) => {
        if (cancelled) return
        setOriginal(before)
        setModified(after)
      })
      .catch((reason) => {
        if (!cancelled) {
          setError(reason instanceof Error ? reason.message : '패치 미리보기를 열지 못했습니다.')
        }
      })

    return () => {
      cancelled = true
    }
  }, [analysisId, patch.patch_id, patch.status, path])

  return (
    <section className="patch-diff-panel">
      <div className="patch-diff-header">
        <div>
          <span className="eyebrow">PATCH REVIEW</span>
          <h2>{patch.summary || '통합 보안 패치'}</h2>
          <p>{patch.finding_ids.length}개 검증 취약점 · 원본 프로젝트는 승인 전까지 변경되지 않습니다.</p>
        </div>
        <StatusBadge status={patch.status} />
      </div>

      <div className="diff-file-tabs">
        {paths.map((item) => (
          <button className={item === path ? 'active' : ''} key={item} onClick={() => setPath(item)}>
            <FileDiff size={13} /> {item}
          </button>
        ))}
      </div>

      {patch.status === 'rejected' ? (
        <pre className="diff-view">{patch.unified_diff}</pre>
      ) : error ? (
        <div className="workbench-message error">{error}</div>
      ) : (
        <div className="diff-editor-wrap">
          <DiffEditor
            height="100%"
            language={original?.language || modified?.language || 'cpp'}
            original={original?.content || ''}
            modified={modified?.content || ''}
            originalModelPath={`original/${path}`}
            modifiedModelPath={`${patch.status}/${path}`}
            theme="vs-dark"
            loading={<div className="workbench-message">패치 미리보기를 생성하는 중입니다…</div>}
            options={{
              automaticLayout: true,
              readOnly: true,
              renderSideBySide: true,
              scrollBeyondLastLine: false,
              fontFamily: 'Cascadia Code, SFMono-Regular, Consolas, monospace',
              fontSize: 12,
              minimap: { enabled: false }
            }}
          />
        </div>
      )}

      {patch.status === 'proposed' && (
        <div className="patch-review-actions">
          <button className="primary-button compact" disabled={busy} onClick={() => onAction('approve')}>
            <CheckCircle2 size={16} /> 승인 및 적용
          </button>
          <button className="danger-button compact" disabled={busy} onClick={() => onAction('reject')}>
            <XCircle size={16} /> 거절
          </button>
        </div>
      )}
    </section>
  )
}

export function AnalysisTracePanel({ analysis }: { analysis: AnalysisPayload }) {
  const routes = analysis.routes || []
  const expertFailures = analysis.expert_failures || []
  const recoveredFailures = expertFailures.filter((item) => item.recovered)
  const [selectedId, setSelectedId] = useState(routes[0]?.candidate_id || '')
  const route = routes.find((item) => item.candidate_id === selectedId) || routes[0]
  const routeBundles = analysis.findings.filter(
    (item) => item.finding.candidate_id === route?.candidate_id
  )
  const bundle = routeBundles[0]

  return (
    <section className="trace-panel">
      <div className="trace-header">
        <div>
          <span className="eyebrow">ANALYSIS TRACE</span>
          <h2>Router · Expert · Validator 결정 경로</h2>
          <p>저장된 실제 분석 결과만 표시합니다. 점수나 심각도를 추정해서 채우지 않습니다.</p>
        </div>
        <div className="trace-summary">
          <span>Candidates <strong>{analysis.summary.candidate_count}</strong></span>
          <span>Expert tasks <strong>{analysis.summary.completed_expert_task_count ?? analysis.summary.submitted_expert_task_count}/{analysis.summary.expert_task_count ?? analysis.summary.submitted_expert_task_count}</strong></span>
          <span>Failed <strong>{analysis.summary.failed_expert_task_count ?? 0}</strong></span>
          <span>Recovered <strong>{analysis.summary.recovered_expert_task_count ?? recoveredFailures.length}</strong></span>
          <span>Concurrency <strong>{analysis.summary.max_concurrent_expert_requests ?? '—'}</strong></span>
          <span>Requests <strong>{analysis.summary.request_count}</strong></span>
          <span>Errors <strong>{analysis.errors?.length || 0}</strong></span>
        </div>
      </div>

      {(analysis.errors?.length || 0) > 0 && (
        <details className="trace-errors" open>
          <summary>Pipeline errors ({analysis.errors?.length})</summary>
          <ul>{analysis.errors?.map((item, index) => <li key={`${item}-${index}`}>{item}</li>)}</ul>
        </details>
      )}

      {expertFailures.length > 0 && (
        <details className="trace-errors expert-failure-details">
          <summary>
            Expert 작업 기록 ({expertFailures.length}) · 복구 {recoveredFailures.length}
          </summary>
          <ul className="expert-failure-list">
            {expertFailures.map((failure) => (
              <li key={`${failure.task_id}-${failure.attempts}`}>
                <div>
                  <strong>{failure.task_id} · {failure.expert}</strong>
                  <span className={failure.recovered ? 'recovered' : 'unresolved'}>
                    {failure.recovered ? '복구됨' : failure.code}
                  </span>
                </div>
                <small>
                  Candidate {failure.candidate_id} · {failure.model}
                  {failure.provider ? ` · provider ${failure.provider}` : ''}
                  {` · 시도 ${failure.attempts}회`}
                </small>
                <p>{failure.message}</p>
              </li>
            ))}
          </ul>
        </details>
      )}

      {(analysis.summary.structural_rejected_count || 0) > 0 && (
        <details className="structural-rejection-notice">
          <summary>
            Aggregation 전에 구조가 맞지 않는 Expert finding {analysis.summary.structural_rejected_count}개를 격리했습니다.
          </summary>
          <div>
            {(analysis.structural_validations || [])
              .filter((item) => item.verdict === 'rejected')
              .map((item) => (
                <article key={item.finding_id}>
                  <strong>{item.finding_id}</strong>
                  <ValidationChecks checks={item.checks || {}} />
                  <ul>{item.reasons.map((reason, index) => <li key={`${reason}-${index}`}>{reason}</li>)}</ul>
                </article>
              ))}
          </div>
        </details>
      )}

      {routes.length ? (
        <div className="trace-layout">
          <div className="trace-route-list">
            {routes.map((item) => (
              <button
                className={item.candidate_id === route?.candidate_id ? 'active' : ''}
                key={item.candidate_id}
                onClick={() => setSelectedId(item.candidate_id)}
              >
                <span>{item.candidate_id}</span>
                <strong>{item.selected.map(expertLabel).join(', ') || '전문가 미선택'}</strong>
                <small>{percent(item.top1_confidence)} · {item.policy}</small>
              </button>
            ))}
          </div>

          {route && (
            <div className="trace-detail">
              <div className="trace-pipeline">
                <TraceStep title="Static candidate" value={bundle?.finding.file || route.candidate_id} />
                <TraceStep title="Utility Router" value={`${route.selected.length} expert selected`} />
                <TraceStep title="LLM Expert" value={`${routeBundles.length} independent finding(s)`} />
                <TraceStep title="Validator" value={routeBundles.length ? '검증 완료' : 'finding 미생성'} />
              </div>

              <div className="router-score-panel">
                <h3>Router scores</h3>
                {Object.entries(route.scores)
                  .sort(([, left], [, right]) => right - left)
                  .map(([expert, score]) => (
                    <div className="router-score" key={expert}>
                      <span>{expertLabel(expert)}</span>
                      <div><i style={{ width: scoreWidth(score, route) }} /></div>
                      <strong>{score.toFixed(3)}</strong>
                    </div>
                  ))}
                <div className="trace-meta-grid">
                  <span>Top-1 confidence<strong>{route.top1_confidence.toFixed(3)}</strong></span>
                  <span>Top-1/2 margin<strong>{route.top1_top2_margin.toFixed(3)}</strong></span>
                  <span>Expected cost<strong>${Number(route.expected_cost || 0).toFixed(4)}</strong></span>
                  <span>Escalated<strong>{route.escalated ? 'Yes' : 'No'}</strong></span>
                </div>
                {route.reasons?.length > 0 && (
                  <div className="trace-reasons">
                    <h3>Decision reasons</h3>
                    <ul>{route.reasons.map((reason, index) => <li key={`${reason}-${index}`}>{reason}</li>)}</ul>
                  </div>
                )}

                {routeBundles.length > 0 && (
                  <div className="trace-validation-section">
                    <h3>Validation checks</h3>
                    {routeBundles.map((item) => (
                      <article className="trace-validation-card" key={item.finding.finding_id}>
                        <div>
                          <strong>{item.finding.title}</strong>
                          <StatusBadge status={item.validation.verdict} />
                        </div>
                        <p>
                          Detection {percent(item.finding.confidence)} · Validation {validationConfidence(item.validation.confidence)}
                        </p>
                        <ValidationChecks checks={item.validation.checks || {}} />
                        {item.validation.reasons?.length ? (
                          <ul>{item.validation.reasons.map((reason, index) => <li key={`${reason}-${index}`}>{reason}</li>)}</ul>
                        ) : null}
                      </article>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="trace-empty">이 분석 결과에는 Router trace 데이터가 없습니다.</div>
      )}

      <div className="usage-table-wrap">
        <h3>Model usage</h3>
        <table className="usage-table">
          <thead><tr><th>Model</th><th>Provider</th><th>Prompt</th><th>Completion</th><th>Latency</th><th>Cost</th></tr></thead>
          <tbody>
            {(analysis.usage || []).map((usage, index) => (
              <tr key={`${usage.model}-${index}`}>
                <td>{usage.model}</td><td>{usage.provider || '-'}</td>
                <td>{usage.prompt_tokens.toLocaleString()}</td><td>{usage.completion_tokens.toLocaleString()}</td>
                <td>{usage.latency_seconds.toFixed(2)}s</td><td>${usage.cost.toFixed(5)}</td>
              </tr>
            ))}
            {!analysis.usage?.length && <tr><td colSpan={6}>저장된 사용량 데이터가 없습니다.</td></tr>}
          </tbody>
        </table>
      </div>

    </section>
  )
}

function ValidationChecks({
  checks,
  compact = false
}: {
  checks: Record<string, boolean | null>
  compact?: boolean
}) {
  return (
    <div className={`validation-checks ${compact ? 'compact' : ''}`}>
      {Object.entries(checks).map(([name, value]) => {
        const passed = name === 'contradicting_guard' ? value === false : value === true
        return (
          <span className={passed ? 'passed' : value === null ? 'unknown' : 'failed'} key={name}>
            {passed ? <CheckCircle2 size={12} /> : value === null ? <AlertTriangle size={12} /> : <XCircle size={12} />}
            {name}
          </span>
        )
      })}
    </div>
  )
}

function TraceStep({ title, value }: { title: string; value: string }) {
  return <div className="trace-step"><i /><span>{title}</span><strong>{value}</strong></div>
}

function VerdictIcon({ verdict }: { verdict: string }) {
  if (verdict === 'validated') return <X className="verdict-validated" size={16} strokeWidth={3} />
  if (verdict === 'rejected') return <XCircle className="verdict-rejected" size={14} />
  return <AlertTriangle className="verdict-uncertain" size={14} />
}

function buildTree(files: ProjectFileSummary[]): FileTreeNode {
  const root: FileTreeNode = { name: 'root', findingCount: 0, children: [] }
  for (const file of files) {
    const parts = file.path.split('/')
    let current = root
    current.findingCount += file.finding_count
    parts.forEach((part, index) => {
      const isFile = index === parts.length - 1
      let child = current.children.find((item) => item.name === part && Boolean(item.path) === isFile)
      if (!child) {
        child = {
          name: part,
          path: isFile ? file.path : undefined,
          findingCount: 0,
          children: []
        }
        current.children.push(child)
      }
      child.findingCount += file.finding_count
      current = child
    })
  }
  const sort = (node: FileTreeNode) => {
    node.children.sort((left, right) => {
      if (Boolean(left.path) !== Boolean(right.path)) return left.path ? 1 : -1
      return left.name.localeCompare(right.name)
    })
    node.children.forEach(sort)
  }
  sort(root)
  return root
}

function hoverMarkdown(bundle: FindingBundle) {
  const { finding, validation } = bundle
  const experts = finding.supporting_experts || (finding.expert ? [finding.expert] : [])
  return [
    `**${escapeMarkdown(finding.title)}**`,
    '',
    `- CWE: ${finding.cwes?.join(', ') || '미분류'}`,
    `- 탐지 신뢰도: ${percent(finding.confidence)}`,
    `- 검증: ${validation.verdict}`,
    `- 검증 신뢰도: ${validationConfidence(validation.confidence)}`,
    `- 전문가: ${experts.map(expertLabel).join(', ') || '-'}`,
    '',
    escapeMarkdown(finding.root_cause || '')
  ].join('\n')
}

function escapeMarkdown(value: string) {
  return value.replace(/[\\`*_{}[\]()#+.!-]/g, '\\$&')
}

function clampLine(value: number, lineCount: number) {
  return Math.max(1, Math.min(lineCount, Number(value) || 1))
}

function percent(value: number | null | undefined) {
  return `${Math.round((Number(value) || 0) * 100)}%`
}

function validationConfidence(value: number | null | undefined) {
  return value === null || value === undefined ? '규칙 기반' : percent(value)
}

function scoreWidth(score: number, route: RouteDecision) {
  const max = Math.max(...Object.values(route.scores).map((value) => Math.abs(value)), 0.0001)
  return `${Math.max(2, Math.min(100, Math.abs(score) / max * 100))}%`
}

export function expertLabel(expert: string) {
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
