from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import torch

from .features import DECISION_FEATURE_NAMES
from .mil.calibration import PlattCalibrator
from .mil.model import HierarchicalMIL
from .mil.schema import CaseDecisionInput, CaseDecisionScore


class CalibratedFindingScorer:
    """Legacy explicit bundle scorer; never constructed as a fallback.

    This adapter remains only for reading older experiments. Both classifier and
    calibrator are mandatory, so production cannot silently use hand weights.
    """

    def __init__(
        self,
        classifier: Any,
        calibrator: Any,
        *,
        feature_names: Sequence[str] = DECISION_FEATURE_NAMES,
    ) -> None:
        if classifier is None or calibrator is None:
            raise RuntimeError("A trained classifier and calibrator are required")
        self.classifier = classifier
        self.calibrator = calibrator
        self.feature_names = tuple(feature_names)

    def score(self, features: Mapping[str, float]) -> float:
        _, calibrated = self.score_with_raw(features)
        return calibrated

    predict = score

    def score_with_raw(self, features: Mapping[str, float]) -> tuple[float, float]:
        vector = [[float(features.get(name, 0.0)) for name in self.feature_names]]
        raw = float(self.classifier.predict_proba(vector)[0][1])
        if hasattr(self.calibrator, "transform"):
            calibrated = float(self.calibrator.transform([raw])[0])
        else:
            calibrated = float(self.calibrator.predict_proba([[raw]])[0][1])
        return _bounded(raw), _bounded(calibrated)


class MILDecisionScorer:
    """Score global case context and every candidate in one MIL forward pass."""

    def __init__(
        self,
        model: HierarchicalMIL,
        calibrator: PlattCalibrator,
        *,
        low_threshold: float,
        high_threshold: float,
    ) -> None:
        if not 0.0 <= low_threshold <= high_threshold <= 1.0:
            raise ValueError("thresholds must satisfy 0 <= low <= high <= 1")
        self.model = model
        self.calibrator = calibrator
        self.low_threshold = low_threshold
        self.high_threshold = high_threshold

    def score(self, case: CaseDecisionInput) -> CaseDecisionScore:
        self.model.eval()
        with torch.no_grad():
            output = self.model(case)
            raw = float(torch.sigmoid(output.sample_logit).item())
        probability = _bounded(float(self.calibrator.transform([raw])[0]))
        candidate_scores = {
            candidate.candidate_id: float(torch.sigmoid(logit).item())
            for candidate, logit in zip(case.candidates, output.candidate_logits)
        }
        candidate_attention = {
            candidate.candidate_id: float(weight.item())
            for candidate, weight in zip(case.candidates, output.candidate_attention)
        }
        bundle_attention = {
            candidate.candidate_id: {
                bundle.bundle_id: float(weight.item())
                for bundle, weight in zip(candidate.bundles, weights)
            }
            for candidate, weights in zip(case.candidates, output.bundle_attention)
        }
        top_candidate_id = (
            max(candidate_scores, key=candidate_scores.get) if candidate_scores else None
        )
        top_bundle_id = None
        if top_candidate_id is not None:
            weights = bundle_attention.get(top_candidate_id, {})
            if weights:
                top_bundle_id = max(weights, key=weights.get)
        return CaseDecisionScore(
            sample_id=case.sample_id,
            raw_probability=raw,
            probability=probability,
            candidate_scores=candidate_scores,
            candidate_attention=candidate_attention,
            bundle_attention=bundle_attention,
            top_candidate_id=top_candidate_id,
            top_bundle_id=top_bundle_id,
        )


def _bounded(value: float) -> float:
    return max(0.0, min(1.0, value))
