from __future__ import annotations

from .aggregation import EvidenceAggregator, FindingAggregator, expert_evidence_from_finding
from .analysis import CandidateAnalyzer
from .decision import (
    CalibratedFindingScorer,
    DecisionPolicy,
    EvidenceFeatureBuilder,
    FindingReportBuilder,
)
from .experts import ExpertRunner
from .models import (
    ExpertEvidence,
    PipelineResult,
    ProjectCase,
    ScoredEvidenceBundle,
    ValidationResult,
    ValidationVerdict,
)
from .routing import CandidateGate, Router
from .validation import (
    EvidenceFalsifier,
    EvidenceValidator,
    ExpertEvidenceStructuralValidator,
)


class VulnerabilityPipeline:
    def __init__(
        self,
        *,
        analyzer: CandidateAnalyzer,
        router: Router,
        expert_runner: ExpertRunner,
        aggregator: FindingAggregator | EvidenceAggregator,
        validator: EvidenceValidator,
        candidate_gate: CandidateGate | None = None,
        max_candidates: int | None = None,
        feature_builder: EvidenceFeatureBuilder | None = None,
        scorer: CalibratedFindingScorer | None = None,
        decision_policy: DecisionPolicy | None = None,
        falsifier: EvidenceFalsifier | None = None,
        report_builder: FindingReportBuilder | None = None,
        structural_validator: ExpertEvidenceStructuralValidator | None = None,
    ) -> None:
        self.analyzer = analyzer
        self.router = router
        self.expert_runner = expert_runner
        # Keep accepting FindingAggregator on the public constructor while the
        # live path now fuses pre-decision evidence bundles.
        self._legacy_aggregator_api = isinstance(aggregator, FindingAggregator)
        self.aggregator = (
            aggregator if isinstance(aggregator, EvidenceAggregator) else EvidenceAggregator()
        )
        self.validator = validator
        self.candidate_gate = candidate_gate or CandidateGate(enabled=False)
        self.max_candidates = max_candidates
        self.feature_builder = feature_builder or EvidenceFeatureBuilder()
        self.scorer = scorer or CalibratedFindingScorer()
        self.decision_policy = decision_policy or DecisionPolicy()
        self.falsifier = falsifier or EvidenceFalsifier(
            client=getattr(validator, "client", None),
            model=getattr(validator, "model", None),
        )
        self.report_builder = report_builder or FindingReportBuilder()
        self.structural_validator = (
            structural_validator or ExpertEvidenceStructuralValidator()
        )

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
        candidate_by_id = {candidate.candidate_id: candidate for candidate in candidates}
        route_by_id = {route.candidate_id: route for route in routes}

        native_evidence = list(getattr(expert_output, "evidence", []) or [])
        expert_evidence: list[ExpertEvidence] = []
        structural_validations: list[ValidationResult] = []
        valid_legacy = []
        for finding in list(getattr(expert_output, "findings", []) or []):
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
                preliminary = self.validator.validate_structure(finding, candidate)
            structural_validations.append(preliminary)
            if preliminary.verdict != ValidationVerdict.REJECTED:
                valid_legacy.append(finding)
                expert_evidence.append(expert_evidence_from_finding(finding))

        for index, item in enumerate(native_evidence, start=1):
            result = self.structural_validator.validate(
                item,
                candidate_by_id.get(item.candidate_id),
                identifier=f"EV-{item.candidate_id}-{index}",
            )
            structural_validations.append(result)
            if result.verdict != ValidationVerdict.REJECTED:
                expert_evidence.append(item)

        bundles = self.aggregator.aggregate(expert_evidence, candidate_by_id)
        self._preserve_single_legacy_ids(bundles, valid_legacy)
        scored: list[ScoredEvidenceBundle] = []
        for bundle in bundles:
            candidate = candidate_by_id[bundle.candidate_id]
            route = route_by_id[bundle.candidate_id]
            features = self.feature_builder.build(bundle, candidate, route, expert_output)
            raw_probability, probability = self.scorer.score_with_raw(features)
            scored.append(
                ScoredEvidenceBundle(
                    bundle=bundle,
                    probability=probability,
                    raw_probability=raw_probability,
                    features=features,
                )
            )

        findings = [
            self.report_builder.build(item, candidate_by_id[item.bundle.candidate_id])
            for item in scored
        ]
        validations = self.decision_policy.decide(scored)
        if self._legacy_aggregator_api:
            # Old embedders treated ValidationResult.confidence=None as the
            # marker for a deterministic verdict. The calibrated probability is
            # still available on Finding and ScoredEvidenceBundle.
            for validation in validations:
                validation.confidence = None
        validation_by_id = {item.finding_id: item for item in validations}
        usage = list(expert_output.usage)
        for finding in findings:
            preliminary = validation_by_id[finding.finding_id]
            if preliminary.verdict != ValidationVerdict.UNCERTAIN:
                continue
            candidate = candidate_by_id[finding.candidate_id]
            below_low = bool(preliminary.checks.get("below_low_threshold"))
            # The low band accepts deterministic proof but does not spend a
            # second LLM call on evidence-poor hypotheses.
            active_falsifier = EvidenceFalsifier() if below_low else self.falsifier
            try:
                falsification, falsifier_usage = active_falsifier.run(finding, candidate)
                if falsifier_usage is not None:
                    usage.append(falsifier_usage)
                preliminary.reasons.append(falsification.reason)
                preliminary.model_used = falsification.model_used
                if falsification.falsified:
                    preliminary.verdict = ValidationVerdict.REJECTED
                    finding.evidence_against = [
                        f"{item.file}:{item.line}: {item.expression}"
                        for item in falsification.counter_evidence
                    ]
            except Exception as error:
                preliminary.failed = True
                preliminary.reasons.append(
                    "반증 검증을 완료하지 못해 검토 상태로 유지했습니다: " + str(error)[:300]
                )

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
            usage=usage,
            structural_validations=structural_validations,
            pre_gate_candidates=pre_gate_candidates,
            gate_decisions=gate_decisions,
            errors=expert_output.errors,
            expert_task_count=expert_output.task_count,
            submitted_expert_task_count=expert_output.submitted_task_count,
            completed_expert_task_count=getattr(
                expert_output, "completed_task_count", expert_output.submitted_task_count
            ),
            failed_expert_task_count=failed_expert_tasks,
            incomplete_candidate_count=getattr(expert_output, "incomplete_candidate_count", 0),
            skipped_expert_task_count=expert_output.skipped_task_count,
            recovered_expert_task_count=getattr(expert_output, "recovered_task_count", 0),
            timed_out_expert_task_count=getattr(expert_output, "timed_out_task_count", 0),
            covered_candidate_count=getattr(
                expert_output,
                "covered_candidate_count",
                len(candidates) - getattr(expert_output, "incomplete_candidate_count", 0),
            ),
            cancelled=cancelled,
            expert_failures=getattr(expert_output, "failures", []),
            analysis_status=analysis_status,
            evidence_bundles=bundles,
            scored_evidence=scored,
        )

    @staticmethod
    def _preserve_single_legacy_ids(bundles, findings) -> None:
        """Keep persisted/UI identifiers stable for one-to-one legacy reports."""

        for bundle in bundles:
            matches = [
                item
                for item in findings
                if item.candidate_id == bundle.candidate_id
                and set(item.evidence_ids) == set(bundle.evidence_ids)
                and (not item.sink or item.sink in bundle.sinks)
            ]
            if len(matches) == 1:
                bundle.bundle_id = matches[0].finding_id
