from __future__ import annotations

import random
from dataclasses import dataclass

import torch

from ..calibration import select_validation_threshold
from .artifact import CandidateDecisionArtifact
from .calibration import PlattCalibrator
from .losses import candidate_classification_loss
from .model import ContextualCandidateClassifier
from .schema import CandidateDecisionContext


@dataclass(frozen=True, slots=True)
class CandidateDecisionTrainingConfig:
    epochs: int = 40
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    batch_size: int = 16
    seed: int = 2026


def train_candidate_decision_model(
    train_cases: list[CandidateDecisionContext],
    calibration_cases: list[CandidateDecisionContext],
    threshold_cases: list[CandidateDecisionContext],
    *,
    config: CandidateDecisionTrainingConfig | None = None,
    candidate_threshold: float = 0.28,
    max_fpr: float = 0.10,
    device: str | torch.device = "cpu",
) -> CandidateDecisionArtifact:
    settings = config or CandidateDecisionTrainingConfig()
    for rows, split in (
        (train_cases, "train"),
        (calibration_cases, "calibration"),
        (threshold_cases, "threshold"),
    ):
        _require_candidate_labels(rows, split)
    random.seed(settings.seed)
    torch.manual_seed(settings.seed)
    model = ContextualCandidateClassifier().to(device)
    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=settings.learning_rate,
        weight_decay=settings.weight_decay,
    )
    for _ in range(settings.epochs):
        model.train()
        shuffled = list(train_cases)
        random.shuffle(shuffled)
        for start in range(0, len(shuffled), settings.batch_size):
            batch = shuffled[start : start + settings.batch_size]
            outputs = [model(case) for case in batch]
            loss = candidate_classification_loss(
                outputs,
                [_labels(case, device) for case in batch],
            )
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            optimizer.step()

    calibration_raw, calibration_labels = _raw_probabilities(
        model, calibration_cases
    )
    calibrator = PlattCalibrator().fit(calibration_raw, calibration_labels)
    threshold_raw, threshold_labels = _raw_probabilities(model, threshold_cases)
    threshold_probabilities = calibrator.transform(threshold_raw).tolist()
    validation_threshold = select_validation_threshold(
        threshold_probabilities,
        threshold_labels,
        max_fpr=max_fpr,
    )
    model.eval()
    return CandidateDecisionArtifact(
        model=model.cpu(),
        calibrator=calibrator,
        candidate_threshold=candidate_threshold,
        validation_threshold=validation_threshold,
        metadata={
            "training_candidates": sum(len(case.candidates) for case in train_cases),
            "calibration_candidates": sum(
                len(case.candidates) for case in calibration_cases
            ),
            "threshold_candidates": sum(
                len(case.candidates) for case in threshold_cases
            ),
            "max_fpr": max_fpr,
            "seed": settings.seed,
        },
    )


def _raw_probabilities(
    model: ContextualCandidateClassifier, cases: list[CandidateDecisionContext]
) -> tuple[list[float], list[int]]:
    model.eval()
    raw: list[float] = []
    labels: list[int] = []
    with torch.no_grad():
        for case in cases:
            raw.extend(
                float(torch.sigmoid(logit).item())
                for logit in model(case).candidate_logits
            )
            labels.extend(int(candidate.label) for candidate in case.candidates)
    return raw, labels


def _labels(case: CandidateDecisionContext, device) -> torch.Tensor:
    return torch.tensor(
        [candidate.label for candidate in case.candidates],
        dtype=torch.float32,
        device=device,
    )


def _require_candidate_labels(
    cases: list[CandidateDecisionContext], split: str
) -> None:
    labels = [candidate.label for case in cases for candidate in case.candidates]
    if not labels or any(label not in {0, 1} for label in labels):
        raise ValueError(f"{split} cases require candidate labels 0/1")
    if set(int(label) for label in labels) != {0, 1}:
        raise ValueError(f"{split} candidates must contain both classes")
