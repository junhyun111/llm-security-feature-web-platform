from __future__ import annotations

from collections.abc import Sequence

import numpy as np
from sklearn.linear_model import LogisticRegression


class PlattCalibrator:
    """Serializable candidate-probability Platt scaling."""

    def __init__(self, slope: float | None = None, intercept: float | None = None) -> None:
        self.slope = slope
        self.intercept = intercept

    def fit(self, probabilities: Sequence[float], labels: Sequence[int]) -> "PlattCalibrator":
        values = np.asarray(probabilities, dtype=float).reshape(-1, 1)
        targets = np.asarray(labels, dtype=int)
        if values.shape[0] != targets.size or targets.size < 2:
            raise ValueError("calibration probabilities and labels must have equal length >= 2")
        if np.unique(targets).size != 2:
            raise ValueError("Platt calibration requires both classes")
        model = LogisticRegression(C=1e6, solver="lbfgs").fit(values, targets)
        self.slope = float(model.coef_[0, 0])
        self.intercept = float(model.intercept_[0])
        return self

    def transform(self, probabilities: Sequence[float]) -> np.ndarray:
        if self.slope is None or self.intercept is None:
            raise RuntimeError("Platt calibrator has not been fitted")
        values = np.asarray(probabilities, dtype=float)
        logits = self.slope * values + self.intercept
        result = np.empty_like(logits)
        positive = logits >= 0
        result[positive] = 1.0 / (1.0 + np.exp(-logits[positive]))
        exponential = np.exp(logits[~positive])
        result[~positive] = exponential / (1.0 + exponential)
        return result

    def state_dict(self) -> dict[str, float]:
        if self.slope is None or self.intercept is None:
            raise RuntimeError("Platt calibrator has not been fitted")
        return {"slope": self.slope, "intercept": self.intercept}

    @classmethod
    def from_state_dict(cls, state: dict[str, float]) -> "PlattCalibrator":
        return cls(float(state["slope"]), float(state["intercept"]))
