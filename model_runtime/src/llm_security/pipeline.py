from __future__ import annotations

from typing import Any

from .aggregation import EvidenceAggregator, FindingAggregator, expert_evidence_from_finding
from .analysis import CandidateAnalyzer
from .decision import (
    DecisionInputBuilder,
    DecisionPolicy,
    FindingReportBuilder,
    MILDecisionScorer,
)
from .experts import ExpertRunner
from .models import (
    ExpertEvidence,
    ExpertFamily,
    Finding,
    GroundTruth,
    PipelineRecallTrace,
    PipelineResult,
    ProjectCase,
    RecallStageTrace,
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
        mil_scorer: MILDecisionScorer | None = None,
        decision_policy: DecisionPolicy | None = None,
        decision_input_builder: DecisionInputBuilder | None = None,
        falsifier: EvidenceFalsifier | None = None,
        report_builder: FindingReportBuilder | None = None,
        structural_validator: ExpertEvidenceStructuralValidator | None = None,
        # Older callers may still pass this keyword. It is never used by the
        # production EvidenceAggregator path.
        scorer: Any | None = None,
        collection_only: bool = False,
    ) -> None:
        self.analyzer = analyzer
        self.router = router
        self.expert_runner = expert_runner
        self._legacy_aggregator = (
            aggregator if isinstance(aggregator, FindingAggregator) else None
        )
        self.aggregator = (
            aggregator if isinstance(aggregator, EvidenceAggregator) else EvidenceAggregator()
        )
        if self._legacy_aggregator is None and mil_scorer is None and not collection_only:
            raise RuntimeError("Trained MIL decision model required.")
        self.validator = validator
        self.candidate_gate = candidate_gate or CandidateGate(enabled=False)
        self.max_candidates = max_candidates
        self.mil_scorer = mil_scorer
        self.collection_only = collection_only
        self.decision_policy = decision_policy or DecisionPolicy()
        self.decision_input_builder = decision_input_builder or DecisionInputBuilder()
        self.falsifier = falsifier or EvidenceFalsifier(
            client=getattr(validator, "client", None),
            model=getattr(validator, "model", None),
        )
        self.report_builder = report_builder or FindingReportBuilder()
        self.structural_validator = structural_validator or ExpertEvidenceStructuralValidator()

    def run(self, case: ProjectCase) -> PipelineResult:
        pre_gate_candidates = self.analyzer.analyze(case)
        post_gate_candidates, gate_decisions = self.candidate_gate.filter(
            pre_gate_candidates
        )
        post_gate_candidates.sort(
            key=lambda candidate: (
                -candidate.suspicion_score,
                candidate.file,
                candidate.line_start,
                candidate.candidate_id,
            )
        )
        candidates = list(post_gate_candidates)
        if self.max_candidates is not None:
            candidates = candidates[: self.max_candidates]
        routes = [self.router.route(candidate) for candidate in candidates]
        expert_output = self.expert_runner.run(candidates, routes)
        if self._legacy_aggregator is not None:
            return self._run_legacy(
                case,
                pre_gate_candidates,
                post_gate_candidates,
                candidates,
                gate_decisions,
                routes,
                expert_output,
            )
        return self._run_mil(
            case,
            pre_gate_candidates,
            post_gate_candidates,
            candidates,
            gate_decisions,
            routes,
            expert_output,
        )

    def _run_mil(
        self,
        case,
        pre_gate_candidates,
        post_gate_candidates,
        candidates,
        gate_decisions,
        routes,
        expert_output,
    ) -> PipelineResult:
        candidate_by_id = {item.candidate_id: item for item in candidates}
        evidence: list[ExpertEvidence] = []
        structural: list[ValidationResult] = []
        for index, item in enumerate(
            list(getattr(expert_output, "evidence", []) or []), start=1
        ):
            result = self.structural_validator.validate(
                item,
                candidate_by_id.get(item.candidate_id),
                identifier=f"EV-{item.candidate_id}-{index}",
            )
            structural.append(result)
            if result.verdict != ValidationVerdict.REJECTED:
                evidence.append(item)
        # Stored/custom runners on the old carrier remain readable, but are
        # converted before fusion and never scored as Findings.
        for item in list(getattr(expert_output, "findings", []) or []):
            candidate = candidate_by_id.get(item.candidate_id)
            result = (
                self.validator.validate_structure(item, candidate)
                if candidate is not None
                else ValidationResult(
                    item.finding_id,
                    ValidationVerdict.REJECTED,
                    None,
                    {"candidate_exists": False},
                    ["Finding references an unknown candidate."],
                )
            )
            structural.append(result)
            if result.verdict != ValidationVerdict.REJECTED:
                evidence.append(expert_evidence_from_finding(item))

        bundles = self.aggregator.aggregate(evidence, candidate_by_id)
        decision_input = self.decision_input_builder.build(
            sample_id=case.case_id,
            candidates=candidates,
            routes=routes,
            bundles=bundles,
            expert_output=expert_output,
            label=_case_label(case),
            project_id=case.project_id,
            cve_id=str(case.metadata.get("cve_id", "")) or None,
        )
        if self.collection_only:
            return self._result(
                case,
                pre_gate_candidates,
                post_gate_candidates,
                candidates,
                gate_decisions,
                routes,
                expert_output,
                findings=[],
                validations=[],
                usage=list(expert_output.usage),
                structural=structural,
                bundles=bundles,
                case_score=None,
                decision_input=decision_input,
            )
        case_score = self.mil_scorer.score(decision_input)  # type: ignore[union-attr]
        findings = []
        validations = []
        usage = list(expert_output.usage)
        bundles_by_candidate = {
            candidate_id: [
                bundle for bundle in bundles if bundle.candidate_id == candidate_id
            ]
            for candidate_id in candidate_by_id
        }
        for candidate_id, candidate_probability in sorted(
            case_score.candidate_scores.items(),
            key=lambda item: (-item[1], item[0]),
        ):
            if candidate_probability < self.mil_scorer.low_threshold:  # type: ignore[union-attr]
                continue
            candidate = candidate_by_id.get(candidate_id)
            if candidate is None:
                continue
            route = next(item for item in routes if item.candidate_id == candidate.candidate_id)
            fallback_expert = next(
                iter(route.selected or list(route.scores)),
                ExpertFamily.CONTROL_STATE_ERROR,
            )
            candidate_bundles = sorted(
                bundles_by_candidate.get(candidate_id, []),
                key=lambda bundle: (
                    -case_score.bundle_attention.get(candidate_id, {}).get(
                        bundle.bundle_id, 0.0
                    ),
                    bundle.bundle_id,
                ),
            )
            # A qualifying candidate can contain multiple independent CWE/root
            # cause bundles. Emit all of them instead of collapsing the case to
            # one top candidate/top bundle. Keep an evidence-less placeholder so
            # the policy can mark it UNCERTAIN rather than silently dropping it.
            for bundle in candidate_bundles or [None]:
                finding = self.report_builder.build_case(
                    case_score,
                    candidate,
                    bundle,
                    fallback_expert=fallback_expert,
                    probability=candidate_probability,
                )
                evidence_survives = bool(
                    bundle
                    and bundle.support_count > 0
                    and bundle.evidence_ids
                    and set(bundle.evidence_ids).issubset(
                        {item.evidence_id for item in candidate.evidence}
                    )
                )
                deterministic, _ = EvidenceFalsifier().run(finding, candidate)
                llm_falsified = False
                falsifier_failed = False
                falsification_reason = deterministic.reason
                if deterministic.falsified:
                    finding.evidence_against = [
                        f"{item.file}:{item.line}: {item.expression}"
                        for item in deterministic.counter_evidence
                    ]
                elif (
                    evidence_survives
                    and candidate_probability >= self.mil_scorer.low_threshold  # type: ignore[union-attr]
                    and bool(getattr(self.validator, "use_llm_for_uncertain", True))
                    and self.falsifier.client is not None
                    and self.falsifier.model
                ):
                    try:
                        falsification, llm_usage = self.falsifier.run(finding, candidate)
                        if llm_usage is not None:
                            usage.append(llm_usage)
                        llm_falsified = falsification.falsified
                        falsification_reason = falsification.reason
                        if llm_falsified:
                            finding.evidence_against = [
                                f"{item.file}:{item.line}: {item.expression}"
                                for item in falsification.counter_evidence
                            ]
                    except Exception as error:
                        falsifier_failed = True
                        falsification_reason = "Falsifier failed: " + str(error)[:300]
                validation = self.decision_policy.decide_case(
                    case_score,
                    finding_id=finding.finding_id,
                    evidence_survives=evidence_survives,
                    deterministic_counterproof=deterministic.falsified,
                    llm_falsified=llm_falsified,
                    falsifier_failed=falsifier_failed,
                    probability=candidate_probability,
                )
                validation.reasons.append(falsification_reason)
                findings.append(finding)
                validations.append(validation)
        return self._result(
            case,
            pre_gate_candidates,
            post_gate_candidates,
            candidates,
            gate_decisions,
            routes,
            expert_output,
            findings=findings,
            validations=validations,
            usage=usage,
            structural=structural,
            bundles=bundles,
            case_score=case_score,
            decision_input=decision_input,
        )

    def _run_legacy(
        self,
        case,
        pre_gate_candidates,
        post_gate_candidates,
        candidates,
        gate_decisions,
        routes,
        expert_output,
    ) -> PipelineResult:
        candidate_by_id = {item.candidate_id: item for item in candidates}
        structural: list[ValidationResult] = []
        valid = []
        for finding in list(getattr(expert_output, "findings", []) or []):
            candidate = candidate_by_id.get(finding.candidate_id)
            result = (
                self.validator.validate_structure(finding, candidate)
                if candidate is not None
                else ValidationResult(
                    finding.finding_id,
                    ValidationVerdict.REJECTED,
                    None,
                    {"candidate_exists": False},
                    ["Finding references an unknown candidate."],
                )
            )
            structural.append(result)
            if result.verdict != ValidationVerdict.REJECTED:
                valid.append(finding)
        findings = self._legacy_aggregator.aggregate(valid)
        validations, validator_usage = self.validator.validate_all(findings, candidates)
        return self._result(
            case,
            pre_gate_candidates,
            post_gate_candidates,
            candidates,
            gate_decisions,
            routes,
            expert_output,
            findings=findings,
            validations=validations,
            usage=list(expert_output.usage) + validator_usage,
            structural=structural,
            bundles=[],
            case_score=None,
            decision_input=None,
        )

    def _result(
        self,
        case,
        pre_gate_candidates,
        post_gate_candidates,
        candidates,
        gate_decisions,
        routes,
        expert_output,
        *,
        findings,
        validations,
        usage,
        structural,
        bundles,
        case_score,
        decision_input,
    ) -> PipelineResult:
        failed_tasks = getattr(expert_output, "failed_task_count", 0)
        cancelled = getattr(expert_output, "cancelled", False)
        incomplete_candidates = getattr(
            expert_output, "incomplete_candidate_count", 0
        )
        covered_candidates = getattr(expert_output, "covered_candidate_count", 0)
        if not covered_candidates and getattr(expert_output, "completed_task_count", 0):
            covered_candidates = max(0, len(candidates) - incomplete_candidates)
        status = (
            "cancelled"
            if cancelled
            else "partial_failure"
            if failed_tasks or any(item.failed for item in validations) or expert_output.errors
            else "completed"
        )
        recall_trace = _build_recall_trace(
            case,
            pre_gate_candidates=pre_gate_candidates,
            post_gate_candidates=post_gate_candidates,
            top_k_candidates=candidates,
            routes=routes,
            bundles=bundles,
            findings=findings,
            validations=validations,
        )
        return PipelineResult(
            case_id=case.case_id,
            candidates=candidates,
            routes=routes,
            findings=findings,
            validations=validations,
            usage=usage,
            structural_validations=structural,
            pre_gate_candidates=pre_gate_candidates,
            post_gate_candidates=post_gate_candidates,
            gate_decisions=gate_decisions,
            errors=expert_output.errors,
            expert_task_count=expert_output.task_count,
            submitted_expert_task_count=expert_output.submitted_task_count,
            completed_expert_task_count=getattr(
                expert_output, "completed_task_count", expert_output.submitted_task_count
            ),
            failed_expert_task_count=failed_tasks,
            incomplete_candidate_count=incomplete_candidates,
            skipped_expert_task_count=expert_output.skipped_task_count,
            recovered_expert_task_count=getattr(expert_output, "recovered_task_count", 0),
            timed_out_expert_task_count=getattr(expert_output, "timed_out_task_count", 0),
            covered_candidate_count=covered_candidates,
            cancelled=cancelled,
            expert_failures=getattr(expert_output, "failures", []),
            analysis_status=status,
            evidence_bundles=bundles,
            scored_evidence=[],
            case_decision_score=case_score,
            case_decision_input=decision_input,
            recall_trace=recall_trace,
        )


def _case_label(case: ProjectCase) -> int | None:
    if case.split == "unlabeled":
        return None
    if "label" in case.metadata:
        value = int(case.metadata["label"])
        return value if value in {0, 1} else None
    return int(bool(case.ground_truth))


def _build_recall_trace(
    case: ProjectCase,
    *,
    pre_gate_candidates,
    post_gate_candidates,
    top_k_candidates,
    routes,
    bundles,
    findings: list[Finding],
    validations: list[ValidationResult],
) -> PipelineRecallTrace | None:
    truths = list(case.ground_truth)
    if not truths:
        return None

    top_k_by_id = {candidate.candidate_id: candidate for candidate in top_k_candidates}
    routes_by_id = {route.candidate_id: route for route in routes}
    validation_by_id = {item.finding_id: item for item in validations}

    static_ids = _truths_matching_candidates(truths, pre_gate_candidates)
    gate_ids = _truths_matching_candidates(truths, post_gate_candidates)
    top_k_ids = _truths_matching_candidates(truths, top_k_candidates)
    router_ids = {
        truth.truth_id
        for truth in truths
        if any(
            _candidate_matches_truth(candidate, truth)
            and _route_covers_truth(routes_by_id.get(candidate.candidate_id), truth)
            for candidate in top_k_candidates
        )
    }
    expert_ids = {
        truth.truth_id
        for truth in truths
        if any(
            bundle.support_count > 0
            and (candidate := top_k_by_id.get(bundle.candidate_id)) is not None
            and _candidate_matches_truth(candidate, truth)
            and _cwes_match(bundle.cwes, truth.cwes)
            for bundle in bundles
        )
    }
    mil_ids = {
        truth.truth_id
        for truth in truths
        if any(_finding_matches_truth(finding, truth) for finding in findings)
    }
    verdict_truth_ids = {
        verdict.value: sorted(
            truth.truth_id
            for truth in truths
            if any(
                _finding_matches_truth(finding, truth)
                and (validation := validation_by_id.get(finding.finding_id)) is not None
                and validation.verdict == verdict
                for finding in findings
            )
        )
        for verdict in ValidationVerdict
    }
    validated_ids = set(verdict_truth_ids[ValidationVerdict.VALIDATED.value])
    top_k_candidate_recall = {
        k: len(_truths_matching_candidates(truths, post_gate_candidates[:k]))
        / len(truths)
        for k in range(1, len(post_gate_candidates) + 1)
    }
    stages = [
        _recall_stage("static_candidate", truths, static_ids),
        _recall_stage("candidate_gate", truths, gate_ids),
        _recall_stage("ranker_top_k", truths, top_k_ids),
        _recall_stage("router", truths, router_ids),
        _recall_stage("expert_evidence", truths, expert_ids),
        _recall_stage("mil_decision", truths, mil_ids),
        _recall_stage("validator_validated", truths, validated_ids),
    ]
    return PipelineRecallTrace(
        ground_truth_count=len(truths),
        stages=stages,
        top_k_candidate_recall=top_k_candidate_recall,
        validator_verdict_truth_ids=verdict_truth_ids,
    )


def _recall_stage(
    stage: str, truths: list[GroundTruth], retained_ids: set[str]
) -> RecallStageTrace:
    all_ids = {truth.truth_id for truth in truths}
    retained = sorted(all_ids & retained_ids)
    return RecallStageTrace(
        stage=stage,
        retained_truth_count=len(retained),
        ground_truth_count=len(all_ids),
        recall=len(retained) / len(all_ids),
        retained_truth_ids=retained,
        dropped_truth_ids=sorted(all_ids - set(retained)),
    )


def _truths_matching_candidates(truths, candidates) -> set[str]:
    return {
        truth.truth_id
        for truth in truths
        if any(_candidate_matches_truth(candidate, truth) for candidate in candidates)
    }


def _candidate_matches_truth(candidate, truth: GroundTruth) -> bool:
    return (
        candidate.file == truth.file
        and candidate.line_start <= truth.line_end
        and truth.line_start <= candidate.line_end
        and (
            not truth.function
            or not candidate.function
            or candidate.function == truth.function
        )
    )


def _route_covers_truth(route, truth: GroundTruth) -> bool:
    if route is None:
        return False
    selected = set(getattr(route, "selected", []) or [])
    return not truth.experts or bool(selected & set(truth.experts))


def _cwes_match(actual: list[str], expected: list[str]) -> bool:
    return not expected or bool(set(actual) & set(expected))


def _finding_matches_truth(finding: Finding, truth: GroundTruth) -> bool:
    return (
        finding.file == truth.file
        and finding.line_start <= truth.line_end
        and truth.line_start <= finding.line_end
        and (
            not truth.function
            or not finding.function
            or finding.function == truth.function
        )
        and _cwes_match(finding.cwes, truth.cwes)
    )
