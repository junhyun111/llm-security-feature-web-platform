from __future__ import annotations

import torch

from .mil.calibration import PlattCalibrator
from .mil.model import NormalityGuidedDSMIL
from .mil.schema import CandidateDecisionContext, CandidateDecisionOutput


class CandidateDecisionModel:
    """Predict independent candidate vulnerabilities with NG-DSMIL."""

    def __init__(
        self,
        model: NormalityGuidedDSMIL,
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
        candidate_probabilities_raw = [
            float(torch.sigmoid(logit).item()) for logit in output.candidate_logits
        ]
        candidate_probabilities = {
            candidate.candidate_id: _bounded(float(probability))
            for candidate, probability in zip(
                case.candidates, candidate_probabilities_raw, strict=True
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
            project_probability=_bounded(
                float(
                    self.calibrator.transform(
                        [float(torch.sigmoid(output.sample_logit).item())]
                    )[0]
                )
            ),
            candidate_attention=candidate_attention,
            bundle_attention=bundle_attention,
        )


def _bounded(value: float) -> float:
    return max(0.0, min(1.0, value))
