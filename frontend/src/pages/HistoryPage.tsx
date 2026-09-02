import { ArrowRight, FolderOpen, Plus, Trash2 } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import StatusBadge from '../components/StatusBadge'
import type { AnalysisJob } from '../types'
import './DashboardPage.css'

export default function HistoryPage() {
  const [jobs, setJobs] = useState<AnalysisJob[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [deletingId, setDeletingId] = useState<string | null>(null)

  useEffect(() => { api.get<AnalysisJob[]>('/api/analyses').then(setJobs).catch((reason) => setError(reason instanceof Error ? reason.message : '프로젝트를 불러오지 못했습니다.')).finally(() => setLoading(false)) }, [])
  const deleteJob = async (job: AnalysisJob) => {
    if (!window.confirm(`Delete ${job.projectName}? This cannot be undone.`)) return
    setDeletingId(job.id); setError('')
    try { await api.delete<void>(`/api/analyses/${job.id}`); setJobs((current) => current.filter((item) => item.id !== job.id)) }
    catch (reason) { setError(reason instanceof Error ? reason.message : '프로젝트를 삭제하지 못했습니다.') }
    finally { setDeletingId(null) }
  }

  return <div className="page library-page projects-page"><header className="library-header"><div><span className="eyebrow">PROJECTS</span><h1>All projects</h1><p>업로드한 코드와 분석 결과를 관리하세요.</p></div><Link className="primary-button" to="/analyses/new"><Plus size={17} /> New analysis</Link></header>{error && <div className="error-box">{error}</div>}{loading ? <div className="library-project-skeleton" /> : jobs.length ? <div className="project-card-grid">{jobs.map((job) => <ProjectRow key={job.id} job={job} deleting={deletingId === job.id} onDelete={() => deleteJob(job)} />)}</div> : <section className="library-empty"><div className="library-empty-icon"><FolderOpen size={24} /></div><span className="eyebrow">NO PROJECTS YET</span><h2>라이브러리가 비어 있습니다.</h2><p>첫 프로젝트를 업로드하고 취약점 분석을 시작해보세요.</p><Link className="primary-button compact" to="/analyses/new">Create project <ArrowRight size={14} /></Link></section>}</div>
}

function ProjectRow({ job, deleting, onDelete }: { job: AnalysisJob; deleting: boolean; onDelete: () => void }) { const unresolved = Math.max(0, job.findingCount - job.validatedFindingCount); return <article className="project-card project-row-card"><Link to={`/analyses/${job.id}?view=analysis&tab=findings`}><div className="project-card-top"><span className="project-icon"><FolderOpen size={17} /></span><StatusBadge status={job.status} /></div><h3>{job.projectName}</h3><p>{job.fileCount.toLocaleString()} files <span>·</span> {new Date(job.updatedAt || job.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}</p><div className="project-card-bottom"><span>{job.findingCount} findings</span><strong className={unresolved ? '' : 'all-clear'}>{unresolved ? `${unresolved} to review` : 'All validated'}</strong></div></Link><button className="project-delete" disabled={deleting} onClick={onDelete} aria-label={`Delete ${job.projectName}`}><Trash2 size={14} /></button></article> }
