import { ArrowRight, Clock3, FolderOpen, Plus, ShieldAlert, Sparkles } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import StatusBadge from '../components/StatusBadge'
import { useAuth } from '../auth/AuthContext'
import type { AnalysisJob, Dashboard } from '../types'
import './DashboardPage.css'

const emptyDashboard: Dashboard = { totalScans: 0, completedScans: 0, totalFindings: 0, validatedFindings: 0, approvedPatches: 0, recentJobs: [] }

export default function DashboardPage() {
  const { user } = useAuth()
  const [data, setData] = useState<Dashboard>(emptyDashboard)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get<Dashboard>('/api/dashboard').then(setData).catch((reason) => setError(reason instanceof Error ? reason.message : 'Library를 불러오지 못했습니다.')).finally(() => setLoading(false))
  }, [])

  const attentionJobs = useMemo(() => data.recentJobs.filter((job) => job.findingCount > job.validatedFindingCount || ['failed', 'partial'].includes(job.status)).slice(0, 3), [data.recentJobs])

  return <div className="page library-page">
    <header className="library-header"><div><span className="eyebrow">YOUR LIBRARY</span><h1>안녕하세요, {user?.displayName || 'there'}</h1><p>분석 프로젝트를 관리하고 다음 보안 작업을 시작하세요.</p></div><Link className="primary-button" to="/analyses/new"><Plus size={17} /> New analysis</Link></header>
    {error && <div className="error-box" role="alert">{error}</div>}

    {!loading && data.recentJobs.length === 0 ? <section className="library-empty"><div className="library-empty-icon"><Sparkles size={24} /></div><span className="eyebrow">A CLEAN START</span><h2>첫 번째 프로젝트를 분석해보세요.</h2><p>코드를 업로드하면 취약점과 검증 결과를 하나의 리뷰 흐름으로 확인할 수 있습니다.</p><Link className="primary-button compact" to="/analyses/new">Start an analysis <ArrowRight size={14} /></Link></section> : <>
      <section className="library-hero-card"><div><span className="eyebrow">SECURITY LIBRARY</span><h2>분석 결과를 한 곳에서<br /><em>검토하고 관리하세요.</em></h2><p>{data.totalScans ? `지금까지 ${data.totalScans.toLocaleString()}개의 분석 프로젝트가 라이브러리에 있습니다.` : '프로젝트별 분석 결과와 패치 작업을 관리하세요.'}</p></div><div className="library-hero-orbit"><ShieldAlert size={25} /><span>{data.validatedFindings.toLocaleString()} validated findings</span></div></section>
      {attentionJobs.length > 0 && <section className="library-section"><div className="library-section-heading"><div><span className="eyebrow">NEEDS ATTENTION</span><h2>다음으로 검토할 프로젝트</h2></div><Link to="/analyses">View all <ArrowRight size={14} /></Link></div><div className="attention-grid">{attentionJobs.map((job) => <ProjectCard key={job.id} job={job} attention />)}</div></section>}
      <section className="library-section"><div className="library-section-heading"><div><span className="eyebrow">ALL PROJECTS</span><h2>최근 프로젝트</h2></div><Link to="/analyses">View library <ArrowRight size={14} /></Link></div>{loading ? <div className="library-project-skeleton" /> : <div className="project-card-grid">{data.recentJobs.slice(0, 6).map((job) => <ProjectCard key={job.id} job={job} />)}</div>}</section>
      <section className="library-activity"><Clock3 size={17} /><div><strong>검토가 끝나면 패치를 생성하세요.</strong><span>Finding 상세에서 Generate patch를 누르면 안전한 Patch workspace로 이동합니다.</span></div><Link to={data.recentJobs[0] ? `/analyses/${data.recentJobs[0].id}?view=analysis&tab=findings` : '/analyses'}>Open findings <ArrowRight size={14} /></Link></section>
    </>}
  </div>
}

function ProjectCard({ job, attention = false }: { job: AnalysisJob; attention?: boolean }) {
  const unresolved = Math.max(0, job.findingCount - job.validatedFindingCount)
  return <Link className={`project-card ${attention ? 'attention' : ''}`} to={`/analyses/${job.id}?view=analysis&tab=findings`}><div className="project-card-top"><span className="project-icon"><FolderOpen size={17} /></span><StatusBadge status={job.status} /></div><h3>{job.projectName}</h3><p>{job.fileCount.toLocaleString()} files <span>·</span> {new Date(job.updatedAt || job.createdAt).toLocaleDateString('en-US', { month: 'short', day: 'numeric' })}</p><div className="project-card-bottom"><span>{job.findingCount} findings</span>{unresolved > 0 ? <strong>{unresolved} to review</strong> : <strong className="all-clear">All validated</strong>}</div></Link>
}
