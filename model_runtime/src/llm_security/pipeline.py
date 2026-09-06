from __future__ import annotations

from .aggregation import FindingAggregator
from .analysis import CandidateAnalyzer
from .experts import ExpertRunner
from .models import (
    PipelineResult,
    ProjectCase,
    ValidationResult,
    ValidationVerdict,
)
from .routing import CandidateGate, Router
from .validation import EvidenceValidator


class VulnerabilityPipeline:
    def __init__(
        self,
        *,
        analyzer: CandidateAnalyzer,
        router: Router,
        expert_runner: ExpertRunner,
        aggregator: FindingAggregator,
        validator: EvidenceValidator,
        candidate_gate: CandidateGate | None = None,
        max_candidates: int | None = None,
    ) -> None:
        self.analyzer = analyzer
        self.router = router
        self.expert_runner = expert_runner
        self.aggregator = aggregator
        self.validator = validator
        self.candidate_gate = candidate_gate or CandidateGate(enabled=False)
        self.max_candidates = max_candidates

    def run(self, case: ProjectCase) -> PipelineResult:
        pre_gate_candidates = self.analyzer.analyze(case)
        candidates, gate_decisions = self.candidate_gate.filter(pre_gate_candidates)
        candidates.sort(
            key=lambda candidate: (
                -candidate.suspicion_score,
                candidate.file,
                candidate.line_start,
                candidate.candidate_id,
            )
        )
        if self.max_candidates is not None:
            candidates = candidates[: self.max_candidates]
        routes = [self.router.route(candidate) for candidate in candidates]
        expert_output = self.expert_runner.run(candidates, routes)
        candidate_by_id = {
            candidate.candidate_id: candidate
            for candidate in candidates
        }
        structurally_valid = []
        structural_validations: list[ValidationResult] = []
        for finding in expert_output.findings:
            candidate = candidate_by_id.get(finding.candidate_id)
            if candidate is None:
                preliminary = ValidationResult(
                    finding_id=finding.finding_id,
                    verdict=ValidationVerdict.REJECTED,
                    confidence=None,
                    checks={
                        "file_matches": False,
                        "function_matches": False,
                        "line_reachable": False,
                        "evidence_exists": bool(finding.evidence_ids),
                        "evidence_ids_valid": False,
                    },
                    reasons=["Finding이 존재하지 않는 candidate를 참조합니다."],
                )
            else:
                preliminary = self.validator.validate_structure(
                    finding,
                    candidate,
                )
            structural_validations.append(preliminary)
            if preliminary.verdict != ValidationVerdict.REJECTED:
                structurally_valid.append(finding)

        findings = self.aggregator.aggregate(structurally_valid)
        validations, validator_usage = self.validator.validate_all(findings, candidates)
        failed_expert_tasks = getattr(expert_output, "failed_task_count", 0)
        validation_failed = any(item.failed for item in validations)
        cancelled = getattr(expert_output, "cancelled", False)
        analysis_status = (
            "cancelled"
            if cancelled
            else "partial_failure"
            if failed_expert_tasks or validation_failed or expert_output.errors
            else "completed"
        )
        return PipelineResult(
            case_id=case.case_id,
            candidates=candidates,
            routes=routes,
            findings=findings,
            validations=validations,
            usage=expert_output.usage + validator_usage,
            structural_validations=structural_validations,
            pre_gate_candidates=pre_gate_candidates,
            gate_decisions=gate_decisions,
            errors=expert_output.errors,
            expert_task_count=expert_output.task_count,
            submitted_expert_task_count=expert_output.submitted_task_count,
            completed_expert_task_count=getattr(
                expert_output,
                "completed_task_count",
                expert_output.submitted_task_count,
            ),
            failed_expert_task_count=failed_expert_tasks,
            incomplete_candidate_count=getattr(
                expert_output,
                "incomplete_candidate_count",
                0,
            ),
            skipped_expert_task_count=expert_output.skipped_task_count,
            recovered_expert_task_count=getattr(
                expert_output,
                "recovered_task_count",
                0,
            ),
            timed_out_expert_task_count=getattr(
                expert_output,
                "timed_out_task_count",
                0,
            ),
            covered_candidate_count=getattr(
                expert_output,
                "covered_candidate_count",
                len(candidates) - getattr(
                    expert_output,
                    "incomplete_candidate_count",
                    0,
                ),
            ),
            cancelled=cancelled,
            expert_failures=getattr(expert_output, "failures", []),
            analysis_status=analysis_status,
        )
