from __future__ import annotations

from ..models import ValidationResult, ValidationVerdict


class DecisionPolicy:
    """Finalize one candidate finding after evidence and counterproof checks."""

    def __init__(self, validation_threshold: float = 0.71) -> None:
        if not 0.0 <= validation_threshold <= 1.0:
            raise ValueError("validation_threshold must be between 0 and 1")
        self.validation_threshold = validation_threshold

    def decide(
        self,
        *,
        finding_id: str,
        probability: float,
        evidence_survives: bool,
        deterministic_counterproof: bool,
        llm_falsified: bool = False,
        falsifier_failed: bool = False,
    ) -> ValidationResult:
        above_threshold = probability >= self.validation_threshold
        counterproof = deterministic_counterproof or llm_falsified
        if counterproof:
            verdict = ValidationVerdict.REJECTED
            reason = "검증된 반증 근거가 취약점 가설을 기각했습니다."
        elif above_threshold and evidence_survives and not falsifier_failed:
            verdict = ValidationVerdict.VALIDATED
            reason = "후보 확률과 구조적으로 검증된 근거가 모두 확인되었습니다."
        elif not evidence_survives:
            verdict = ValidationVerdict.UNCERTAIN
            reason = "검증 가능한 Expert 근거가 부족합니다."
        elif falsifier_failed:
            verdict = ValidationVerdict.UNCERTAIN
            reason = "반증 검사를 완료하지 못해 확정하지 않았습니다."
        else:
            verdict = ValidationVerdict.UNCERTAIN
            reason = "후보 확률이 검증 임계값 미만입니다."
        return ValidationResult(
            finding_id=finding_id,
            verdict=verdict,
            confidence=probability,
            checks={
                "candidate_probability_scored": True,
                "above_validation_threshold": above_threshold,
                "evidence_survives": evidence_survives,
                "deterministic_counterproof": deterministic_counterproof,
                "llm_falsified": llm_falsified,
            },
            reasons=[reason],
            failed=falsifier_failed,
        )
