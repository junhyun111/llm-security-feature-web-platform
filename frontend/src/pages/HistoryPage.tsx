import { ArrowRight, FolderKanban, Grid2X2, Info, List, Plus, Search, SlidersHorizontal, Trash2 } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { api } from '../api'
import NewAnalysisModal from '../components/NewAnalysisModal'
import StatusBadge from '../components/StatusBadge'
import type { AnalysisJob } from '../types'
import './DashboardPage.css'

function formatDate(date: string) { return new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', year: 'numeric' }).format(new Date(date)) }

export default function HistoryPage() {
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [jobs, setJobs] = useState<AnalysisJob[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [query, setQuery] = useState('')
  const [status, setStatus] = useState('all')
  const [view, setView] = useState<'list' | 'grid'>('list')
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const wizardOpen = searchParams.get('new') === '1'

  const loadJobs = useCallback(() => {
    setLoading(true)
    return api.get<AnalysisJob[]>('/api/analyses').then(setJobs).catch((reason) => setError(reason instanceof Error ? reason.message : 'Unable to load projects.')).finally(() => setLoading(false))
  }, [])
  useEffect(() => { void loadJobs() }, [loadJobs])
  const openWizard = () => setSearchParams((current) => { const next = new URLSearchParams(current); next.set('new', '1'); return next })
  const closeWizard = () => setSearchParams((current) => { const next = new URLSearchParams(current); next.delete('new'); return next })
  const filteredJobs = useMemo(() => jobs.filter((job) => job.projectName.toLowerCase().includes(query.trim().toLowerCase()) && (status === 'all' || job.status === status)), [jobs, query, status])
  const deleteJob = async (job: AnalysisJob) => {
    if (!window.confirm(`Delete ${job.projectName}? This cannot be undone.`)) return
    setDeletingId(job.id)
    try { await api.delete<void>(`/api/analyses/${job.id}`); setJobs((current) => current.filter((item) => item.id !== job.id)) }
    catch (reason) { setError(reason instanceof Error ? reason.message : 'Unable to delete this project.') }
    finally { setDeletingId(null) }
  }

  return <div className="analysis-library-page">
    <header className="analysis-library-header"><div><h1>Recent analyses <Info size={17} /></h1><p>Every security analysis in your library, ordered by recent activity.</p></div><div className="analysis-library-actions"><div className="library-view-toggle" aria-label="View mode"><button className={view === 'list' ? 'active' : ''} onClick={() => setView('list')} aria-label="List view"><List size={18} /></button><button className={view === 'grid' ? 'active' : ''} onClick={() => setView('grid')} aria-label="Grid view"><Grid2X2 size={17} /></button></div><button type="button" className="library-create-button" onClick={openWizard}><Plus size={17} /> New analysis</button></div></header>
    {error && <div className="error-box" role="alert">{error}</div>}
    <section className="analysis-library-controls" aria-label="Project controls"><label><Search size={17} /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search your library" aria-label="Search your library" /></label><div className="library-status-filter"><SlidersHorizontal size={16} /><select value={status} onChange={(event) => setStatus(event.target.value)} aria-label="Filter by status"><option value="all">All statuses</option><option value="completed">Completed</option><option value="analyzing">Analyzing</option><option value="partial">Needs review</option><option value="failed">Failed</option></select></div></section>
    {loading ? <div className="workspace-skeleton" /> : !filteredJobs.length ? <section className="workspace-empty compact-empty"><span className="workspace-empty-icon"><FolderKanban size={27} /></span><h2>{jobs.length ? 'No matching projects.' : 'Your library is empty.'}</h2><p>{jobs.length ? 'Try a different project name or status filter.' : 'Create your first analysis to build your security library.'}</p>{!jobs.length && <button type="button" className="library-create-button" onClick={openWizard}>New analysis <ArrowRight size={16} /></button>}</section> : view === 'list' ? <div className="analysis-library-table-wrap"><table className="analysis-library-table"><thead><tr><th>Project</th><th>Status</th><th>Findings</th><th>Last analyzed</th><th><span className="sr-only">Actions</span></th></tr></thead><tbody>{filteredJobs.map((job) => <ProjectTableRow key={job.id} job={job} deleting={deletingId === job.id} onOpen={() => navigate(`/analyses/${job.id}?view=analysis&tab=code`)} onDelete={() => deleteJob(job)} />)}</tbody></table></div> : <div className="library-grid">{filteredJobs.map((job) => <ProjectGridCard key={job.id} job={job} onDelete={() => deleteJob(job)} deleting={deletingId === job.id} />)}</div>}
    <NewAnalysisModal open={wizardOpen} onClose={closeWizard} onCreated={() => { void loadJobs() }} />
  </div>
}

function ProjectTableRow({ job, deleting, onOpen, onDelete }: { job: AnalysisJob; deleting: boolean; onOpen: () => void; onDelete: () => void }) {
  const open = Math.max(0, job.findingCount - job.validatedFindingCount)
  return <tr onClick={onOpen}><td><span className="analysis-library-project"><span><FolderKanban size={17} /></span><strong>{job.projectName}</strong><small>{job.fileCount.toLocaleString()} files</small></span></td><td><StatusBadge status={job.status} /></td><td><span className={open ? 'analysis-library-findings has-open' : 'analysis-library-findings'}>{job.findingCount} total <small>{open ? `${open} to review` : 'All validated'}</small></span></td><td>{formatDate(job.updatedAt || job.createdAt)}</td><td><button className="analysis-library-delete" disabled={deleting} onClick={(event) => { event.stopPropagation(); onDelete() }} aria-label={`Delete ${job.projectName}`}><Trash2 size={15} /></button><ArrowRight size={17} /></td></tr>
}

function ProjectGridCard({ job, deleting, onDelete }: { job: AnalysisJob; deleting: boolean; onDelete: () => void }) {
  const open = Math.max(0, job.findingCount - job.validatedFindingCount)
  return <article className="library-grid-card"><Link to={`/analyses/${job.id}?view=analysis&tab=code`}><span className="recent-project-icon"><FolderKanban size={17} /></span><StatusBadge status={job.status} /><h2>{job.projectName}</h2><p>{job.fileCount.toLocaleString()} files · {formatDate(job.updatedAt || job.createdAt)}</p><footer><span>{job.findingCount} findings</span><strong className={open ? 'has-open' : ''}>{open ? `${open} to review` : 'All validated'}</strong></footer></Link><button disabled={deleting} onClick={onDelete} aria-label={`Delete ${job.projectName}`}><Trash2 size={15} /></button></article>
}
