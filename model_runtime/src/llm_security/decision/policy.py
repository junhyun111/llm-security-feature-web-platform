from __future__ import annotations

from ..models import ScoredEvidenceBundle, ValidationResult, ValidationVerdict
from .mil.schema import CaseDecisionScore


class DecisionPolicy:
    """Finalize a sample only after evidence and counterproof checks."""

    def __init__(self, low_threshold: float = 0.28, high_threshold: float = 0.71) -> None:
        if not 0.0 <= low_threshold <= high_threshold <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= low <= high <= 1")
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold

    def decide_case(
        self,
        score: CaseDecisionScore,
        *,
        finding_id: str,
        evidence_survives: bool,
        deterministic_counterproof: bool,
        llm_falsified: bool = False,
        falsifier_failed: bool = False,
    ) -> ValidationResult:
        high = score.probability >= self.high_threshold
        low = score.probability < self.low_threshold
        counterproof = deterministic_counterproof or llm_falsified
        if counterproof:
            verdict = ValidationVerdict.REJECTED
            reason = "검증된 반증 근거가 최상위 취약점 가설을 기각했습니다."
        elif high and evidence_survives and not falsifier_failed:
            verdict = ValidationVerdict.VALIDATED
            reason = "MIL 고위험 점수와 구조적으로 검증된 근거가 모두 확인되었습니다."
        elif not evidence_survives:
            verdict = ValidationVerdict.UNCERTAIN
            reason = "MIL 점수와 무관하게 검증 가능한 최상위 근거가 부족합니다."
        elif falsifier_failed:
            verdict = ValidationVerdict.UNCERTAIN
            reason = "반증 검사를 완료하지 못해 고위험 결과를 확정하지 않았습니다."
        elif low:
            verdict = ValidationVerdict.UNCERTAIN
            reason = "낮은 sample 확률만으로 안전을 증명할 수 없어 검토 상태로 유지합니다."
        else:
            verdict = ValidationVerdict.UNCERTAIN
            reason = "sample 확률이 검토 구간에 있습니다."
        return ValidationResult(
            finding_id=finding_id,
            verdict=verdict,
            confidence=score.probability,
            checks={
                "sample_probability_scored": True,
                "above_high_threshold": high,
                "below_low_threshold": low,
                "evidence_survives": evidence_survives,
                "deterministic_counterproof": deterministic_counterproof,
                "llm_falsified": llm_falsified,
            },
            reasons=[reason],
            failed=falsifier_failed,
        )

    # Compatibility for explicit, older bundle experiments. The production
    # pipeline never calls this method.
    def decide_one(self, scored: ScoredEvidenceBundle) -> ValidationResult:
        score = CaseDecisionScore(
            sample_id=scored.bundle.candidate_id,
            raw_probability=scored.raw_probability or scored.probability,
            probability=scored.probability,
            candidate_scores={scored.bundle.candidate_id: scored.probability},
            candidate_attention={scored.bundle.candidate_id: 1.0},
            bundle_attention={
                scored.bundle.candidate_id: {scored.bundle.bundle_id: 1.0}
            },
            top_candidate_id=scored.bundle.candidate_id,
            top_bundle_id=scored.bundle.bundle_id,
        )
        return self.decide_case(
            score,
            finding_id=scored.bundle.bundle_id,
            evidence_survives=True,
            deterministic_counterproof=False,
        )
