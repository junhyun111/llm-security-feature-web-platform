from __future__ import annotations

import random
from dataclasses import dataclass

import torch

from ..calibration import select_high_threshold
from .artifact import MILArtifact
from .calibration import PlattCalibrator
from .losses import hierarchical_mil_loss
from .model import HierarchicalMIL
from .schema import CaseDecisionInput


@dataclass(frozen=True, slots=True)
class MILTrainingConfig:
    epochs: int = 40
    learning_rate: float = 1e-3
    weight_decay: float = 1e-4
    batch_size: int = 16
    negative_instance_weight: float = 0.15
    ranking_weight: float = 0.10
    ranking_margin: float = 0.5
    seed: int = 2026


def train_hierarchical_mil(
    train_cases: list[CaseDecisionInput],
    calibration_cases: list[CaseDecisionInput],
    threshold_cases: list[CaseDecisionInput],
    *,
    config: MILTrainingConfig | None = None,
    low_threshold: float = 0.28,
    max_fpr: float = 0.10,
    device: str | torch.device = "cpu",
) -> MILArtifact:
    settings = config or MILTrainingConfig()
    _require_labeled(train_cases, "train")
    _require_labeled(calibration_cases, "calibration")
    _require_labeled(threshold_cases, "threshold")
    random.seed(settings.seed)
    torch.manual_seed(settings.seed)
    model = HierarchicalMIL().to(device)
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
            labels = torch.tensor(
                [case.label for case in batch], dtype=torch.float32, device=device
            )
            loss, _ = hierarchical_mil_loss(
                outputs,
                labels,
                negative_instance_weight=settings.negative_instance_weight,
                ranking_weight=settings.ranking_weight,
                ranking_margin=settings.ranking_margin,
            )
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            optimizer.step()

    calibration_raw = _raw_probabilities(model, calibration_cases)
    calibrator = PlattCalibrator().fit(
        calibration_raw, [int(case.label) for case in calibration_cases]
    )
    threshold_raw = _raw_probabilities(model, threshold_cases)
    threshold_probabilities = calibrator.transform(threshold_raw).tolist()
    high_threshold = select_high_threshold(
        threshold_probabilities,
        [int(case.label) for case in threshold_cases],
        max_fpr=max_fpr,
    )
    model.eval()
    return MILArtifact(
        model=model.cpu(),
        calibrator=calibrator,
        low_threshold=low_threshold,
        high_threshold=high_threshold,
        metadata={
            "training_samples": len(train_cases),
            "calibration_samples": len(calibration_cases),
            "threshold_samples": len(threshold_cases),
            "max_fpr": max_fpr,
            "seed": settings.seed,
        },
    )


def _raw_probabilities(
    model: HierarchicalMIL, cases: list[CaseDecisionInput]
) -> list[float]:
    model.eval()
    with torch.no_grad():
        return [float(torch.sigmoid(model(case).sample_logit).item()) for case in cases]


def _require_labeled(cases: list[CaseDecisionInput], split: str) -> None:
    if not cases or any(case.label not in {0, 1} for case in cases):
        raise ValueError(f"{split} cases must be non-empty and labeled 0/1")
    if {int(case.label) for case in cases} != {0, 1}:
        raise ValueError(f"{split} cases must contain both classes")
