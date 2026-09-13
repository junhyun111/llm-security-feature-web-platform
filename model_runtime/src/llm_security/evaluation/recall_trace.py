from __future__ import annotations

from dataclasses import dataclass, field

from ..cwe import cwe_category, normalize_cwe
from ..models import (
    Candidate,
    EvidenceBundle,
    Finding,
    GroundTruth,
    PipelineResult,
    ValidationVerdict,
)
from ..selection import CandidateSelection


@dataclass(slots=True)
class RecallStageTrace:
    stage: str
    retained_truth_count: int
    ground_truth_count: int
    recall: float
    retained_truth_ids: list[str] = field(default_factory=list)
    dropped_truth_ids: list[str] = field(default_factory=list)


@dataclass(slots=True)
class PipelineRecallTrace:
    ground_truth_count: int
    stages: list[RecallStageTrace] = field(default_factory=list)
    top_k_candidate_recall: dict[int, float] = field(default_factory=dict)
    validator_verdict_truth_ids: dict[str, list[str]] = field(default_factory=dict)
    escalation_metrics: dict[str, float] = field(default_factory=dict)


class RecallTracer:
    """Measure ground-truth survival without coupling inference to labels."""

    def evaluate(
        self,
        *,
        ground_truth: list[GroundTruth],
        selection: CandidateSelection,
        result: PipelineResult,
    ) -> PipelineRecallTrace:
        if not ground_truth:
            raise ValueError("Recall tracing requires ground truth")
        truths = list(ground_truth)
        candidates_by_id = {
            candidate.candidate_id: candidate for candidate in selection.selected
        }
        routes_by_id = {route.candidate_id: route for route in result.routes}
        validation_by_id = {
            validation.finding_id: validation for validation in result.validations
        }

        generated_ids = _truths_matching_candidates(truths, selection.generated)
        threshold_ids = _truths_matching_candidates(
            truths, selection.threshold_candidates
        )
        selected_ids = _truths_matching_candidates(truths, selection.selected)
        router_ids = {
            truth.truth_id
            for truth in truths
            if any(
                _candidate_matches_truth(candidate, truth)
                and _route_covers_truth(
                    routes_by_id.get(candidate.candidate_id), truth
                )
                for candidate in selection.selected
            )
        }
        top2_expert_ids = {
            truth.truth_id
            for truth in truths
            if any(
                _assessment_matches_truth(assessment, candidates_by_id, truth)
                and assessment.expert in (
                    (
                        routes_by_id[assessment.candidate_id].top2_experts
                        or routes_by_id[assessment.candidate_id].selected[:2]
                    )
                    if assessment.candidate_id in routes_by_id
                    else []
                )
                for assessment in result.expert_assessments
            )
        }
        post_escalation_ids = {
            truth.truth_id
            for truth in truths
            if any(
                _assessment_matches_truth(assessment, candidates_by_id, truth)
                for assessment in result.expert_assessments
            )
        }
        decision_ids = {
            truth.truth_id
            for truth in truths
            if any(
                _finding_matches_truth(finding, truth)
                for finding in result.findings
            )
        }
        verdict_ids = {
            verdict.value: sorted(
                truth.truth_id
                for truth in truths
                if any(
                    _finding_matches_truth(finding, truth)
                    and (
                        validation := validation_by_id.get(finding.finding_id)
                    )
                    is not None
                    and validation.verdict == verdict
                    for finding in result.findings
                )
            )
            for verdict in ValidationVerdict
        }
        validated_ids = set(verdict_ids[ValidationVerdict.VALIDATED.value])
        return PipelineRecallTrace(
            ground_truth_count=len(truths),
            stages=[
                _stage("static_candidate", truths, generated_ids),
                _stage("candidate_threshold", truths, threshold_ids),
                _stage("candidate_selected", truths, selected_ids),
                _stage("router_top2", truths, router_ids),
                _stage("top2_expert_positive", truths, top2_expert_ids),
                _stage("post_escalation_expert_positive", truths, post_escalation_ids),
                _stage("evidence_gate", truths, decision_ids),
                _stage("final_finding", truths, validated_ids),
            ],
            top_k_candidate_recall={
                k: len(
                    _truths_matching_candidates(
                        truths, selection.threshold_candidates[:k]
                    )
                )
                / len(truths)
                for k in range(1, len(selection.threshold_candidates) + 1)
            },
            validator_verdict_truth_ids=verdict_ids,
            escalation_metrics={
                "top2_recall": len(top2_expert_ids) / len(truths),
                "after_escalation_recall": len(post_escalation_ids) / len(truths),
                "recall_recovery": (len(post_escalation_ids) - len(top2_expert_ids)) / len(truths),
                "full5_rate": (
                    result.escalation_requested_count / len(result.candidates)
                    if result.candidates else 0.0
                ),
                "average_experts_per_candidate": (
                    result.expert_task_count / len(result.candidates)
                    if result.candidates else 0.0
                ),
            },
        )


def _stage(
    name: str, truths: list[GroundTruth], retained_ids: set[str]
) -> RecallStageTrace:
    all_ids = {truth.truth_id for truth in truths}
    retained = sorted(all_ids & retained_ids)
    return RecallStageTrace(
        stage=name,
        retained_truth_count=len(retained),
        ground_truth_count=len(all_ids),
        recall=len(retained) / len(all_ids),
        retained_truth_ids=retained,
        dropped_truth_ids=sorted(all_ids - set(retained)),
    )


def _truths_matching_candidates(
    truths: list[GroundTruth], candidates: list[Candidate]
) -> set[str]:
    return {
        truth.truth_id
        for truth in truths
        if any(_candidate_matches_truth(candidate, truth) for candidate in candidates)
    }


def _candidate_matches_truth(candidate: Candidate, truth: GroundTruth) -> bool:
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
    return not truth.experts or bool(set(route.selected) & set(truth.experts))


def _bundle_matches_truth(
    bundle: EvidenceBundle,
    candidates: dict[str, Candidate],
    truth: GroundTruth,
) -> bool:
    candidate = candidates.get(bundle.candidate_id)
    return bool(
        bundle.support_count > 0
        and candidate is not None
        and _candidate_matches_truth(candidate, truth)
        and _cwes_match(bundle.cwes, truth.cwes)
    )


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


def _assessment_matches_truth(assessment, candidates: dict[str, Candidate], truth: GroundTruth) -> bool:
    candidate = candidates.get(assessment.candidate_id)
    return bool(
        assessment.verdict.value == "vulnerable"
        and candidate is not None
        and _candidate_matches_truth(candidate, truth)
        and _cwes_match(assessment.cwes, truth.cwes)
        and (not truth.experts or assessment.expert in truth.experts)
    )


def _cwes_match(actual: list[str], expected: list[str]) -> bool:
    if not expected:
        return True

    actual_normalized = {normalize_cwe(value) for value in actual}
    actual_normalized.discard("")
    expected_normalized = {normalize_cwe(value) for value in expected}
    expected_normalized.discard("")

    if actual_normalized & expected_normalized:
        return True

    actual_categories = {
        category
        for value in actual_normalized
        for category in [cwe_category(value)]
        if category is not None
    }
    expected_categories = {
        category
        for value in expected_normalized
        for category in [cwe_category(value)]
        if category is not None
    }
    return bool(actual_categories & expected_categories)
