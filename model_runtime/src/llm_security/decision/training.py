from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
import pickle

import numpy as np
from sklearn.linear_model import LogisticRegression

from .calibration import PlattCalibrator, select_high_threshold
from .features import DECISION_FEATURE_NAMES
from .scorer import CalibratedFindingScorer


@dataclass(slots=True)
class TrainedDecisionLayer:
    scorer: CalibratedFindingScorer
    low_threshold: float
    high_threshold: float
    feature_schema_version: str = "evidence-decision-v1"

    def save(self, path: str | Path) -> None:
        destination = Path(path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("wb") as handle:
            pickle.dump(self, handle)

    @classmethod
    def load(cls, path: str | Path) -> "TrainedDecisionLayer":
        # Decision artifacts are trusted deployment inputs, just like the
        # existing Router pickle. Never load a user-uploaded artifact here.
        try:
            with Path(path).open("rb") as handle:
                artifact = pickle.load(handle)
        except (pickle.UnpicklingError, EOFError, AttributeError, TypeError) as exc:
            raise ValueError("Decision artifact is unreadable") from exc
        if not isinstance(artifact, cls):
            raise ValueError("Decision artifact has an unexpected type")
        if artifact.feature_schema_version != "evidence-decision-v1":
            raise ValueError("Decision artifact feature schema is incompatible")
        return artifact


def train_decision_layer(
    train_features: Sequence[Mapping[str, float]],
    train_labels: Sequence[int],
    validation_features: Sequence[Mapping[str, float]],
    validation_labels: Sequence[int],
    *,
    low_threshold: float = 0.28,
    max_fpr: float = 0.10,
) -> TrainedDecisionLayer:
    """Fit on train, then calibrate and choose the operating point on validation."""

    names = DECISION_FEATURE_NAMES
    train_x = np.asarray(
        [[float(row.get(name, 0.0)) for name in names] for row in train_features]
    )
    validation_x = np.asarray(
        [[float(row.get(name, 0.0)) for name in names] for row in validation_features]
    )
    train_y = np.asarray(train_labels, dtype=int)
    validation_y = np.asarray(validation_labels, dtype=int)
    if train_x.shape[0] != train_y.size or validation_x.shape[0] != validation_y.size:
        raise ValueError("feature rows and labels must have matching lengths")
    if np.unique(train_y).size != 2 or np.unique(validation_y).size != 2:
        raise ValueError("train and validation splits must both contain two classes")

    classifier = LogisticRegression(max_iter=2_000, class_weight="balanced")
    classifier.fit(train_x, train_y)
    validation_raw = classifier.predict_proba(validation_x)[:, 1]
    calibrator = PlattCalibrator().fit(validation_raw, validation_y)
    validation_probability = calibrator.transform(validation_raw)
    high_threshold = select_high_threshold(
        validation_probability.tolist(), validation_y.tolist(), max_fpr=max_fpr
    )
    return TrainedDecisionLayer(
        scorer=CalibratedFindingScorer(
            classifier=classifier,
            calibrator=calibrator,
            feature_names=names,
        ),
        low_threshold=low_threshold,
        high_threshold=high_threshold,
    )
