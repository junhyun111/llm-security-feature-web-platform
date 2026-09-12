from __future__ import annotations

from dataclasses import dataclass, field

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
        selected_by_id = {
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
        expert_ids = {
            truth.truth_id
            for truth in truths
            if any(
                _bundle_matches_truth(bundle, selected_by_id, truth)
                for bundle in result.evidence_bundles
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
                _stage("candidate_top_k", truths, selected_ids),
                _stage("router", truths, router_ids),
                _stage("expert_evidence", truths, expert_ids),
                _stage("candidate_decision", truths, decision_ids),
                _stage("verifier_validated", truths, validated_ids),
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


def _cwes_match(actual: list[str], expected: list[str]) -> bool:
    return not expected or bool(set(actual) & set(expected))
