from __future__ import annotations

from dataclasses import replace

from .acceptance import EvidenceGate
from .analysis import CandidateAnalyzer
from .escalation import EvidenceEscalationPolicy
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
        escalation_policy: EvidenceEscalationPolicy | None = None,
        evidence_gate: EvidenceGate | None = None,
    ) -> None:
        self.analyzer = analyzer
        self.selector = selector
        self.router = router
        self.expert_runner = expert_runner
        self.escalation_policy = escalation_policy or EvidenceEscalationPolicy()
        self.evidence_gate = evidence_gate or EvidenceGate()

    def run(self, case: ProjectCase) -> PipelineResult:
        generated = self.analyzer.analyze(case)
        selection = self.selector.select(generated)
        routes = [self.router.route(candidate) for candidate in selection.selected]
        initial_experts_by_candidate = {
            route.candidate_id: list(route.top2_experts or route.selected[:2])
            for route in routes
        }
        initial_output = self._run_experts(
            selection.selected,
            initial_experts_by_candidate,
            routes,
            phase="initial",
        )
        assessments_by_candidate = {
            candidate.candidate_id: [
                assessment
                for assessment in initial_output.assessments
                if assessment.candidate_id == candidate.candidate_id
            ]
            for candidate in selection.selected
        }
        escalations = [
            self.escalation_policy.decide(
                candidate=candidate,
                route=next(route for route in routes if route.candidate_id == candidate.candidate_id),
                assessments=assessments_by_candidate[candidate.candidate_id],
            )
            for candidate in selection.selected
        ]
        remaining_by_candidate = {
            escalation.candidate_id: escalation.remaining_experts
            for escalation in escalations
            if escalation.escalated and escalation.remaining_experts
        }
        escalation_output = self._run_experts(
            selection.selected,
            remaining_by_candidate,
            routes,
            phase="escalation",
        ) if remaining_by_candidate else None
        expert_output = _combine_expert_outputs(initial_output, escalation_output)
        findings, validations = self.evidence_gate.process(
            expert_output.assessments,
            selection.selected,
            routes,
        )
        return _build_result(
            case,
            selection,
            routes,
            expert_output,
            findings,
            validations,
            escalations,
            initial_output.task_count,
            escalation_output.task_count if escalation_output is not None else 0,
        )

    def _run_experts(
        self,
        candidates,
        experts_by_candidate,
        routes,
        *,
        phase: str,
    ):
        """Use the phased runner, retaining the old runner contract for callers.

        The fallback is intentionally only an adapter: production runners expose
        ``run_experts`` and receive the exact per-candidate Expert map.
        """
        phased = getattr(self.expert_runner, "run_experts", None)
        if phased is not None:
            return phased(candidates, experts_by_candidate, phase=phase)
        route_by_id = {route.candidate_id: route for route in routes}
        phased_routes = [
            replace(route_by_id[candidate_id], selected=list(experts))
            for candidate_id, experts in experts_by_candidate.items()
        ]
        return self.expert_runner.run(candidates, phased_routes)


def _build_result(
    case: ProjectCase,
    selection: CandidateSelection,
    routes,
    expert_output,
    findings,
    validations,
    escalations,
    initial_expert_task_count: int,
    escalation_expert_task_count: int,
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
        escalations=escalations,
        initial_expert_task_count=initial_expert_task_count,
        escalation_expert_task_count=escalation_expert_task_count,
        full5_candidate_count=sum(item.escalated for item in escalations),
    )


def _combine_expert_outputs(initial, escalation):
    if escalation is None:
        return initial
    from .experts import ExpertRunOutput

    return ExpertRunOutput(
        assessments=[*initial.assessments, *escalation.assessments],
        usage=[*initial.usage, *escalation.usage],
        errors=[*initial.errors, *escalation.errors],
        task_count=initial.task_count + escalation.task_count,
        submitted_task_count=initial.submitted_task_count + escalation.submitted_task_count,
        completed_task_count=initial.completed_task_count + escalation.completed_task_count,
        failed_task_count=initial.failed_task_count + escalation.failed_task_count,
        incomplete_candidate_count=(
            initial.incomplete_candidate_count + escalation.incomplete_candidate_count
        ),
        skipped_task_count=initial.skipped_task_count + escalation.skipped_task_count,
        recovered_task_count=initial.recovered_task_count + escalation.recovered_task_count,
        timed_out_task_count=initial.timed_out_task_count + escalation.timed_out_task_count,
        covered_candidate_count=len(
            {item.candidate_id for item in [*initial.assessments, *escalation.assessments]}
        ),
        cancelled=initial.cancelled or escalation.cancelled,
        failures=[*initial.failures, *escalation.failures],
    )
