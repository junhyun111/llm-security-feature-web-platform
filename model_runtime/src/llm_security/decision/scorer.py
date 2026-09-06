from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .features import DECISION_FEATURE_NAMES


DEFAULT_WEIGHTS: dict[str, float] = {
    "candidate_score": 1.40,
    "router_top1": 0.25,
    "router_margin": 0.15,
    "support_expert_count": 0.35,
    "unknown_expert_count": -0.30,
    "expert_coverage": 0.40,
    "unique_evidence_count": 0.25,
    "evidence_diversity": 0.35,
    "source_present": 0.20,
    "sink_present": 0.25,
    "source_sink_path": 0.90,
    "trigger_path_length": 0.05,
    "precondition_count": 0.08,
    "precondition_supported": 0.25,
    "cwe_semantic_support": 0.50,
    "guard_present": -1.60,
    "counter_evidence_count": -2.00,
    "max_expert_confidence": 0.10,
    "mean_expert_confidence": 0.15,
    "expert_agreement": 0.35,
    "failure_ratio": -0.80,
}


@dataclass(slots=True)
class LinearProbabilityClassifier:
    """Auditable logistic fallback used until a trained artifact is supplied."""

    weights: Mapping[str, float]
    intercept: float = -2.2

    def predict_probability(self, features: Mapping[str, float]) -> float:
        logit = self.intercept + sum(
            float(self.weights.get(name, 0.0)) * float(features.get(name, 0.0))
            for name in DECISION_FEATURE_NAMES
        )
        if logit >= 0:
            return 1.0 / (1.0 + math.exp(-logit))
        exponential = math.exp(logit)
        return exponential / (1.0 + exponential)


class IdentityCalibrator:
    def transform(self, probabilities: Sequence[float]) -> list[float]:
        return [float(value) for value in probabilities]


class CalibratedFindingScorer:
    """Classifier plus an independently fitted probability calibrator."""

    def __init__(
        self,
        classifier: Any | None = None,
        calibrator: Any | None = None,
        *,
        feature_names: Sequence[str] = DECISION_FEATURE_NAMES,
    ) -> None:
        self.classifier = classifier or LinearProbabilityClassifier(DEFAULT_WEIGHTS)
        self.calibrator = calibrator or IdentityCalibrator()
        self.feature_names = tuple(feature_names)

    def score(self, features: Mapping[str, float]) -> float:
        _, calibrated = self.score_with_raw(features)
        return calibrated

    predict = score

    def score_with_raw(self, features: Mapping[str, float]) -> tuple[float, float]:
        vector = [[float(features.get(name, 0.0)) for name in self.feature_names]]
        if hasattr(self.classifier, "predict_probability"):
            raw = float(self.classifier.predict_probability(features))
        else:
            raw = float(self.classifier.predict_proba(vector)[0][1])

        if hasattr(self.calibrator, "transform"):
            calibrated = float(self.calibrator.transform([raw])[0])
        elif hasattr(self.calibrator, "predict_proba"):
            calibrated = float(self.calibrator.predict_proba([[raw]])[0][1])
        else:
            calibrated = raw
        return self._bounded(raw), self._bounded(calibrated)

    @staticmethod
    def _bounded(value: float) -> float:
        return max(0.0, min(1.0, value))
