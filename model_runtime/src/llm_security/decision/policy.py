from __future__ import annotations

from ..models import ScoredEvidenceBundle, ValidationResult, ValidationVerdict


class DecisionPolicy:
    """Two-threshold policy. A low score is never proof of safety."""

    def __init__(self, low_threshold: float = 0.28, high_threshold: float = 0.71) -> None:
        if not 0.0 <= low_threshold <= high_threshold <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= low <= high <= 1")
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold

    def decide(self, scored: list[ScoredEvidenceBundle]) -> list[ValidationResult]:
        return [self.decide_one(item) for item in scored]

    def decide_one(self, scored: ScoredEvidenceBundle) -> ValidationResult:
        probability = scored.probability
        if probability >= self.high_threshold:
            verdict = ValidationVerdict.VALIDATED
            reason = "보정된 취약점 확률이 검증 임계값 이상입니다."
        elif probability < self.low_threshold:
            verdict = ValidationVerdict.UNCERTAIN
            reason = "근거 점수가 낮지만 반증 근거가 없어 기각하지 않습니다."
        else:
            verdict = ValidationVerdict.UNCERTAIN
            reason = "보정된 취약점 확률이 선택적 반증 검토 구간에 있습니다."
        return ValidationResult(
            finding_id=scored.bundle.bundle_id,
            verdict=verdict,
            confidence=probability,
            checks={
                "probability_scored": True,
                "above_high_threshold": probability >= self.high_threshold,
                "below_low_threshold": probability < self.low_threshold,
            },
            reasons=[reason],
        )
