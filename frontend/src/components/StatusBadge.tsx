import { CheckCircle2, XCircle } from 'lucide-react'

const labels: Record<string, string> = {
  uploading: '업로드 중',
  queued: '대기',
  analyzing: '분석 중',
  finalizing: '결과 불러오는 중',
  cancelling: '중단 요청됨',
  completed: '완료',
  partial: '경고와 함께 완료',
  failed: '실패',
  cancelled: '중단됨',
  validated: '검증됨',
  rejected: '기각',
  proposed: '제안됨',
  approved: '승인됨'
}

export default function StatusBadge({ status }: { status: string }) {
  const isCompleted = status === 'completed'
  const isRedStatus = status === 'approved'
  const label = status === 'validated' ? '취약점' : labels[status] || status
  return (
    <span className={`status-badge status-${status}`}>
      {status !== 'validated' && (isCompleted ? <CheckCircle2 className="status-complete-icon" size={12} /> : isRedStatus ? <XCircle className="status-failure-icon" size={12} /> : <span className="status-dot" />)}
      {label}
    </span>
  )
}
