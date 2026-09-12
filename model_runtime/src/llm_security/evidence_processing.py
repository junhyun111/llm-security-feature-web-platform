from __future__ import annotations

from dataclasses import dataclass

from .aggregation import EvidenceAggregator
from .models import (
    Candidate,
    EvidenceBundle,
    ExpertEvidence,
    ValidationResult,
    ValidationVerdict,
)
from .validation import ExpertEvidenceStructuralValidator


@dataclass(slots=True)
class EvidenceProcessingResult:
    evidence: list[ExpertEvidence]
    bundles: list[EvidenceBundle]
    structural_validations: list[ValidationResult]


class EvidenceProcessor:
    """Validate Expert observations structurally, then fuse accepted evidence."""

    def __init__(
        self,
        *,
        aggregator: EvidenceAggregator | None = None,
        structural_validator: ExpertEvidenceStructuralValidator | None = None,
    ) -> None:
        self.aggregator = aggregator or EvidenceAggregator()
        self.structural_validator = (
            structural_validator or ExpertEvidenceStructuralValidator()
        )

    def process(self, expert_output, candidates: list[Candidate]) -> EvidenceProcessingResult:
        candidate_by_id = {
            candidate.candidate_id: candidate for candidate in candidates
        }
        accepted: list[ExpertEvidence] = []
        validations: list[ValidationResult] = []
        for index, item in enumerate(expert_output.evidence, start=1):
            validation = self.structural_validator.validate(
                item,
                candidate_by_id.get(item.candidate_id),
                identifier=f"EV-{item.candidate_id}-{index}",
            )
            validations.append(validation)
            if validation.verdict != ValidationVerdict.REJECTED:
                accepted.append(item)
        return EvidenceProcessingResult(
            evidence=accepted,
            bundles=self.aggregator.aggregate(accepted, candidate_by_id),
            structural_validations=validations,
        )
