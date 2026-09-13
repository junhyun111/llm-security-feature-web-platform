from __future__ import annotations

from .acceptance import EvidenceGate
from .analysis import CandidateAnalyzer
from .experts import ExpertRunner
from .models import PipelineResult, ProjectCase
from .routing import Router
from .selection import CandidateSelection, CandidateSelector


class VulnerabilityPipeline:
    """Production path: analyze, select, route, assess, gate, and deduplicate."""

    def __init__(
        self,
        *,
        analyzer: CandidateAnalyzer,
        selector: CandidateSelector,
        router: Router,
        expert_runner: ExpertRunner,
        evidence_gate: EvidenceGate | None = None,
    ) -> None:
        self.analyzer = analyzer
        self.selector = selector
        self.router = router
        self.expert_runner = expert_runner
        self.evidence_gate = evidence_gate or EvidenceGate()

    def run(self, case: ProjectCase) -> PipelineResult:
        generated = self.analyzer.analyze(case)
        selection = self.selector.select(generated)
        routes = [self.router.route(candidate) for candidate in selection.selected]
        expert_output = self.expert_runner.run(selection.selected, routes)
        findings, validations = self.evidence_gate.process(
            expert_output.assessments,
            selection.selected,
            routes,
        )
        return _build_result(case, selection, routes, expert_output, findings, validations)


def _build_result(
    case: ProjectCase,
    selection: CandidateSelection,
    routes,
    expert_output,
    findings,
    validations,
) -> PipelineResult:
    failed_tasks = getattr(expert_output, "failed_task_count", 0)
    cancelled = getattr(expert_output, "cancelled", False)
    incomplete = getattr(expert_output, "incomplete_candidate_count", 0)
    covered = getattr(expert_output, "covered_candidate_count", 0)
    if not covered and getattr(expert_output, "completed_task_count", 0):
        covered = max(0, len(selection.selected) - incomplete)
    status = (
        "cancelled"
        if cancelled
        else "partial_failure"
        if failed_tasks or any(item.failed for item in validations) or expert_output.errors
        else "completed"
    )
    return PipelineResult(
        case_id=case.case_id,
        candidates=selection.selected,
        routes=routes,
        findings=findings,
        validations=validations,
        usage=list(expert_output.usage),
        generated_candidate_count=len(selection.generated),
        selection_decisions=selection.decisions,
        errors=expert_output.errors,
        expert_task_count=expert_output.task_count,
        submitted_expert_task_count=expert_output.submitted_task_count,
        completed_expert_task_count=getattr(
            expert_output, "completed_task_count", expert_output.submitted_task_count
        ),
        failed_expert_task_count=failed_tasks,
        incomplete_candidate_count=incomplete,
        skipped_expert_task_count=expert_output.skipped_task_count,
        recovered_expert_task_count=getattr(expert_output, "recovered_task_count", 0),
        timed_out_expert_task_count=getattr(expert_output, "timed_out_task_count", 0),
        covered_candidate_count=covered,
        cancelled=cancelled,
        expert_failures=getattr(expert_output, "failures", []),
        analysis_status=status,
        expert_assessments=list(expert_output.assessments),
    )
