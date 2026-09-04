import { ArrowRight, CircleAlert, Clock3, FolderKanban, Plus, ShieldCheck } from 'lucide-react'
import { useEffect, useMemo, useState, type ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api'
import { useAuth } from '../auth/AuthContext'
import StatusBadge from '../components/StatusBadge'
import type { AnalysisJob, Dashboard } from '../types'
import './DashboardPage.css'

const emptyDashboard: Dashboard = { totalScans: 0, completedScans: 0, totalFindings: 0, validatedFindings: 0, approvedPatches: 0, recentJobs: [] }

function formatDate(date: string) {
  return new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric', year: 'numeric' }).format(new Date(date))
}

function greeting() {
  const hour = new Date().getHours()
  if (hour < 12) return 'Good morning'
  if (hour < 18) return 'Good afternoon'
  return 'Good evening'
}

export default function DashboardPage() {
  const { user } = useAuth()
  const [data, setData] = useState<Dashboard>(emptyDashboard)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    api.get<Dashboard>('/api/dashboard').then(setData).catch((reason) => setError(reason instanceof Error ? reason.message : 'Unable to load your workspace.')).finally(() => setLoading(false))
  }, [])

  const resumeJob = useMemo(() => data.recentJobs.find((job) => !['completed', 'failed', 'cancelled'].includes(job.status)) || data.recentJobs[0], [data.recentJobs])
  const openFindings = Math.max(0, data.totalFindings - data.validatedFindings)

  return <div className="workspace-page home-page">
    <header className="workspace-page-header">
      <div><span className="eyebrow">SECURITY WORKSPACE</span><h1>{greeting()}, {user?.displayName || 'there'}.</h1><p>Pick up where you left off or start a new code security analysis.</p></div>
      <Link className="primary-button" to="/analyses/new"><Plus size={17} /> New analysis</Link>
    </header>
    {error && <div className="error-box" role="alert">{error}</div>}

    {!loading && data.recentJobs.length === 0 ? <section className="workspace-empty">
      <span className="workspace-empty-icon"><ShieldCheck size={27} /></span><span className="eyebrow">READY WHEN YOU ARE</span><h2>Start your first security analysis.</h2><p>Upload a C or C++ project to identify vulnerabilities, review evidence, and generate a verified patch.</p><Link className="primary-button" to="/analyses/new">Start an analysis <ArrowRight size={16} /></Link>
    </section> : <>
      <section className="overview-grid" aria-label="Security overview">
        <OverviewStat icon={<FolderKanban size={18} />} label="All projects" value={data.totalScans} />
        <OverviewStat icon={<CircleAlert size={18} />} label="Open findings" value={openFindings} tone={openFindings ? 'warning' : 'success'} />
        <OverviewStat icon={<ShieldCheck size={18} />} label="Validated findings" value={data.validatedFindings} tone="success" />
        <OverviewStat icon={<Clock3 size={18} />} label="Analyses completed" value={data.completedScans} />
      </section>
      {resumeJob && <section className="resume-panel">
        <div className="resume-panel-icon"><Clock3 size={20} /></div><div className="resume-panel-main"><span className="eyebrow">CONTINUE ANALYSIS</span><h2>{resumeJob.projectName}</h2><p>{resumeJob.fileCount.toLocaleString()} files · Last updated {formatDate(resumeJob.updatedAt || resumeJob.createdAt)}</p></div><div className="resume-panel-status"><StatusBadge status={resumeJob.status} /><span>{resumeJob.findingCount} findings</span></div><Link className="secondary-button compact" to={`/analyses/${resumeJob.id}?view=analysis&tab=findings`}>Resume <ArrowRight size={15} /></Link>
      </section>}
      <section className="recent-section">
        <div className="section-title-row"><div><span className="eyebrow">RECENT PROJECTS</span><h2>Your latest security work</h2></div><Link to="/analyses">View all projects <ArrowRight size={15} /></Link></div>
        {loading ? <div className="workspace-skeleton" /> : <div className="recent-project-list">{data.recentJobs.slice(0, 5).map((job) => <RecentProject key={job.id} job={job} />)}</div>}
      </section>
    </>}
  </div>
}

function OverviewStat({ icon, label, value, tone = 'blue' }: { icon: ReactNode; label: string; value: number; tone?: 'blue' | 'warning' | 'success' }) {
  return <article className={`overview-stat ${tone}`}><span>{icon}</span><strong>{value.toLocaleString()}</strong><small>{label}</small></article>
}

function RecentProject({ job }: { job: AnalysisJob }) {
  const open = Math.max(0, job.findingCount - job.validatedFindingCount)
  return <Link className="recent-project-row" to={`/analyses/${job.id}?view=analysis&tab=findings`}><span className="recent-project-icon"><FolderKanban size={17} /></span><span className="recent-project-name"><strong>{job.projectName}</strong><small>{job.fileCount.toLocaleString()} files · Updated {formatDate(job.updatedAt || job.createdAt)}</small></span><StatusBadge status={job.status} /><span className={open ? 'finding-count has-open' : 'finding-count'}>{open ? `${open} to review` : 'All clear'}</span><ArrowRight className="recent-project-arrow" size={17} /></Link>
}
