import { useEffect, useState } from 'react'
import { api } from '../api'
import JobTable from '../components/JobTable'
import type { AnalysisJob } from '../types'

export default function HistoryPage() {
  const [jobs, setJobs] = useState<AnalysisJob[]>([])
  const [loading, setLoading] = useState(true)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [error, setError] = useState('')

  useEffect(() => {
    api
      .get<AnalysisJob[]>('/api/analyses')
      .then(setJobs)
      .finally(() => setLoading(false))
  }, [])

  const deleteJob = async (job: AnalysisJob) => {
    if (!window.confirm(`“${job.projectName}” 분석 이력과 업로드된 프로젝트 파일을 삭제할까요? 이 작업은 되돌릴 수 없습니다.`)) return
    setDeletingId(job.id)
    setError('')
    try {
      await api.delete<void>(`/api/analyses/${job.id}`)
      setJobs((current) => current.filter((item) => item.id !== job.id))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : '분석 이력을 삭제하지 못했습니다.')
    } finally {
      setDeletingId(null)
    }
  }

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <span className="eyebrow">HISTORY</span>
          <h1>분석 이력</h1>
          <p>내 계정으로 실행한 모든 C/C++ 프로젝트 분석을 확인합니다.</p>
        </div>
      </header>

      <section className="panel">
        {error && <div className="error-box">{error}</div>}
        {deletingId && <p className="history-delete-progress">분석 이력과 프로젝트 파일을 삭제하고 있습니다…</p>}
        {loading ? <div className="skeleton-line" /> : <JobTable jobs={jobs} onDelete={deleteJob} />}
      </section>
    </div>
  )
}
