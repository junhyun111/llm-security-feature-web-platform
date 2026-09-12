from __future__ import annotations

from .analysis import CandidateAnalyzer
from .decision import CandidateDecisionModel, DecisionInputBuilder
from .decision.verifier import EvidenceVerifier, VerificationOutput
from .evidence_processing import EvidenceProcessingResult, EvidenceProcessor
from .experts import ExpertRunner
from .models import PipelineResult, ProjectCase
from .routing import Router
from .selection import CandidateSelection, CandidateSelector


class VulnerabilityPipeline:
    """Orchestrate the production vulnerability-analysis path."""

    def __init__(
        self,
        *,
        analyzer: CandidateAnalyzer,
        selector: CandidateSelector,
        router: Router,
        expert_runner: ExpertRunner,
        evidence_processor: EvidenceProcessor,
        decision_model: CandidateDecisionModel | None,
        verifier: EvidenceVerifier | None,
        decision_input_builder: DecisionInputBuilder | None = None,
        collection_only: bool = False,
    ) -> None:
        if not collection_only and (decision_model is None or verifier is None):
            raise RuntimeError("Trained candidate decision model required.")
        self.analyzer = analyzer
        self.selector = selector
        self.router = router
        self.expert_runner = expert_runner
        self.evidence_processor = evidence_processor
        self.decision_model = decision_model
        self.verifier = verifier
        self.decision_input_builder = (
            decision_input_builder or DecisionInputBuilder()
        )
        self.collection_only = collection_only

    def run(self, case: ProjectCase) -> PipelineResult:
        generated = self.analyzer.analyze(case)
        selection = self.selector.select(generated)
        routes = [self.router.route(candidate) for candidate in selection.selected]
        expert_output = self.expert_runner.run(selection.selected, routes)
        evidence = self.evidence_processor.process(expert_output, selection.selected)
        decision_input = self.decision_input_builder.build(
            case_id=case.case_id,
            candidates=selection.selected,
            routes=routes,
            bundles=evidence.bundles,
            expert_output=expert_output,
            project_id=case.project_id,
            cve_id=str(case.metadata.get("cve_id", "")) or None,
        )
        decision_score = None
        verification = VerificationOutput([], [], [])
        if not self.collection_only:
            if self.decision_model is None or self.verifier is None:
                raise RuntimeError("Trained candidate decision model required.")
            decision_score = self.decision_model.predict(decision_input)
            verification = self.verifier.verify(
                decision_score,
                candidates=selection.selected,
                routes=routes,
                bundles=evidence.bundles,
            )
        return _build_result(
            case,
            selection,
            routes,
            expert_output,
            evidence,
            verification,
            decision_score,
            decision_input,
        )


def _build_result(
    case,
    selection: CandidateSelection,
    routes,
    expert_output,
    evidence: EvidenceProcessingResult,
    verification: VerificationOutput,
    decision_score,
    decision_input,
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
        if failed_tasks
        or any(item.failed for item in verification.validations)
        or expert_output.errors
        else "completed"
    )
    return PipelineResult(
        case_id=case.case_id,
        candidates=selection.selected,
        routes=routes,
        findings=verification.findings,
        validations=verification.validations,
        usage=list(expert_output.usage) + verification.usage,
        structural_validations=evidence.structural_validations,
        generated_candidate_count=len(selection.generated),
        selection_decisions=selection.decisions,
        errors=expert_output.errors,
        expert_task_count=expert_output.task_count,
        submitted_expert_task_count=expert_output.submitted_task_count,
        completed_expert_task_count=getattr(
            expert_output,
            "completed_task_count",
            expert_output.submitted_task_count,
        ),
        failed_expert_task_count=failed_tasks,
        incomplete_candidate_count=incomplete,
        skipped_expert_task_count=expert_output.skipped_task_count,
        recovered_expert_task_count=getattr(
            expert_output, "recovered_task_count", 0
        ),
        timed_out_expert_task_count=getattr(
            expert_output, "timed_out_task_count", 0
        ),
        covered_candidate_count=covered,
        cancelled=cancelled,
        expert_failures=getattr(expert_output, "failures", []),
        analysis_status=status,
        evidence_bundles=evidence.bundles,
        candidate_decision_output=decision_score,
        candidate_decision_input=decision_input,
    )
