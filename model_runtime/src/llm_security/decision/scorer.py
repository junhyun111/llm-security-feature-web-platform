from __future__ import annotations

import math

import torch

from .mil.calibration import PlattCalibrator
from .mil.model import ContextualCandidateClassifier
from .mil.schema import CandidateDecisionContext, CandidateDecisionOutput


class CandidateDecisionModel:
    """Predict candidate vulnerabilities using shared global project context."""

    def __init__(
        self,
        model: ContextualCandidateClassifier,
        calibrator: PlattCalibrator,
        *,
        candidate_threshold: float,
        validation_threshold: float,
    ) -> None:
        if not 0.0 <= candidate_threshold <= validation_threshold <= 1.0:
            raise ValueError(
                "thresholds must satisfy 0 <= candidate <= validation <= 1"
            )
        self.model = model
        self.calibrator = calibrator
        self.candidate_threshold = candidate_threshold
        self.validation_threshold = validation_threshold

    def predict(self, case: CandidateDecisionContext) -> CandidateDecisionOutput:
        self.model.eval()
        with torch.no_grad():
            output = self.model(case)
        raw = [
            float(torch.sigmoid(logit).item()) for logit in output.candidate_logits
        ]
        calibrated = self.calibrator.transform(raw).tolist() if raw else []
        candidate_probabilities = {
            candidate.candidate_id: _bounded(float(probability))
            for candidate, probability in zip(
                case.candidates, calibrated, strict=True
            )
        }
        candidate_attention = {
            candidate.candidate_id: float(weight.item())
            for candidate, weight in zip(
                case.candidates, output.candidate_attention, strict=True
            )
        }
        bundle_attention = {
            candidate.candidate_id: {
                bundle.bundle_id: float(weight.item())
                for bundle, weight in zip(
                    candidate.bundles, weights, strict=True
                )
            }
            for candidate, weights in zip(
                case.candidates, output.bundle_attention, strict=True
            )
        }
        return CandidateDecisionOutput(
            case_id=case.case_id,
            candidate_probabilities=candidate_probabilities,
            project_probability=_project_probability(
                candidate_probabilities.values()
            ),
            candidate_attention=candidate_attention,
            bundle_attention=bundle_attention,
        )


def _project_probability(probabilities) -> float:
    safe_probability = math.prod(1.0 - value for value in probabilities)
    return _bounded(1.0 - safe_probability)


def _bounded(value: float) -> float:
    return max(0.0, min(1.0, value))
