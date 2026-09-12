export type User = {
  id: string
  email: string
  displayName: string
}

export type AnalysisJob = {
  id: string
  projectName: string
  modelId: string
  sensitivity: number
  status: string
  progress: number
  message: string
  fileCount: number
  sourceFileCount: number
  findingCount: number
  validatedFindingCount: number
  totalCost: number
  errorMessage?: string | null
  createdAt: string
  updatedAt: string
  completedAt?: string | null
}

export type Dashboard = {
  totalScans: number
  completedScans: number
  totalFindings: number
  validatedFindings: number
  approvedPatches: number
  recentJobs: AnalysisJob[]
}

export type FindingBundle = {
  finding: {
    finding_id: string
    candidate_id: string
    title: string
    file: string
    line_start: number
    line_end: number
    function: string
    root_cause: string
    consequence: string
    confidence?: number
    source?: string | null
    sink?: string | null
    missing_guard?: string | null
    trigger_path?: string[]
    preconditions?: string[]
    evidence_for?: string[]
    expert?: string
    supporting_experts?: string[]
    supporting_models?: string[]
    model_id?: string | null
    cwes?: string[]
    evidence_ids?: string[]
    evidence_against?: string[]
  }
  validation: {
    verdict: string
    /** Independent Validator confidence. Null means a deterministic rule verdict. */
    confidence: number | null
    checks?: Record<string, boolean | null>
    reasons?: string[]
    model_used?: string | null
  }
  candidate?: {
    candidate_id?: string
    suspicion_score?: number
    static_score?: number
    features?: Record<string, number>
    cwe_hypotheses?: Array<{
      cwe: string
      confidence: number
      reasons?: string[]
    }>
  }
}

export type ValidationResult = {
  finding_id: string
  verdict: string
  confidence: number | null
  checks: Record<string, boolean | null>
  reasons: string[]
  model_used?: string | null
}

export type ProjectFileSummary = {
  path: string
  name: string
  language: 'c' | 'cpp' | string
  size: number
  finding_count: number
  version: string
}

export type ProjectFileContent = ProjectFileSummary & {
  content: string
  findings: FindingBundle[]
}

export type RouteDecision = {
  candidate_id: string
  scores: Record<string, number>
  selected: string[]
  top1_confidence: number
  top1_top2_margin: number
  policy: string
  reasons: string[]
  available_families?: string[]
  learned_scores?: Record<string, number>
  trigger_scores?: Record<string, number>
  expected_cost?: number
  ranked_experts?: string[]
  top2_experts?: string[]
  escalation_confidence?: number | null
  escalated?: boolean
  escalation_method?: string | null
}

export type UsageRecord = {
  model: string
  provider?: string | null
  prompt_tokens: number
  completion_tokens: number
  reasoning_tokens?: number
  cost: number
  latency_seconds: number
}

export type PatchBatch = {
  patch_id: string
  finding_ids: string[]
  status: string
  summary: string
  unified_diff: string
  revision?: number
}

export type AnalysisPayload = {
  summary: {
    source_file_count: number
    generated_candidate_count?: number
    candidate_count: number
    cwe_hypothesis_count: number
    finding_count: number
    validated_finding_count: number
    review_finding_count?: number
    rejected_finding_count?: number
    validation_failure_count?: number
    analysis_status?: 'completed' | 'partial_failure' | 'cancelled'
    total_cost: number
    request_count: number
    submitted_expert_task_count: number
    completed_expert_task_count?: number
    failed_expert_task_count?: number
    recovered_expert_task_count?: number
    timed_out_expert_task_count?: number
    incomplete_candidate_count?: number
    covered_candidate_count?: number
    skipped_expert_task_count?: number
    expert_task_count?: number
    max_concurrent_expert_requests?: number
    structural_rejected_count?: number
    skipped_source_file_count?: number
    expert_task_coverage?: number
    candidate_coverage?: number
    degraded?: boolean
    cancelled?: boolean
  }
  findings: FindingBundle[]
  routes?: RouteDecision[]
  candidate_selection?: Array<{
    candidate_id: string
    score: number
    selected: boolean
    reason: string
  }>
  candidate_decision_output?: {
    case_id: string
    candidate_probabilities: Record<string, number>
    project_probability: number
    candidate_attention: Record<string, number>
    bundle_attention: Record<string, Record<string, number>>
  } | null
  structural_validations?: ValidationResult[]
  usage?: UsageRecord[]
  errors?: string[]
  expert_failures?: Array<{
    task_id: string
    candidate_id: string
    expert: string
    model: string
    provider?: string | null
    code: string
    recoverable: boolean
    recovered: boolean
    attempts: number
    message: string
  }>
  patch_batch?: PatchBatch | null
}

export type AnalysisDetail = {
  job: AnalysisJob
  analysis?: AnalysisPayload | null
  sync: AnalysisSyncInfo
}

export type AnalysisSyncInfo = {
  state: 'fresh' | 'cached' | 'stale' | string
  warning?: string | null
  lastSuccessfulSyncAt?: string | null
  traceId?: string | null
}

export type AnalysisStatus = {
  job: AnalysisJob
  sync: AnalysisSyncInfo
}
