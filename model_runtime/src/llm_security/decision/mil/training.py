from __future__ import annotations

import copy
import random
from dataclasses import dataclass
from pathlib import Path

import torch

from ..calibration import select_candidate_threshold, select_validation_threshold
from .artifact import CandidateDecisionArtifact
from .calibration import PlattCalibrator
from .losses import ng_dsmil_loss
from .model import NormalityGuidedDSMIL
from .schema import CandidateDecisionContext


@dataclass(frozen=True, slots=True)
class BagTrainingExample:
    """One weakly supervised project bag and its safety label."""

    case: CandidateDecisionContext
    label: int


@dataclass(frozen=True, slots=True)
class CandidateDecisionTrainingConfig:
    epochs: int = 80
    learning_rate: float = 5e-4
    weight_decay: float = 1e-4
    batch_size: int = 16
    lambda_normal: float = 0.5
    lambda_rank: float = 0.5
    rank_margin: float = 0.5
    target_recall: float = 0.95
    max_fpr: float = 0.10
    early_stop_patience: int = 12
    seed: int = 2026


def bag_examples_from_cases(
    cases: list[CandidateDecisionContext],
    *,
    labels_by_case_id: dict[str, int] | None = None,
) -> list[BagTrainingExample]:
    """Make weak MIL examples from persisted JSONL without candidate labels.

    Existing collection identifiers ending in ``-V`` and ``-S`` encode vulnerable
    and safe bags respectively. A supplied mapping takes precedence for datasets
    that use another identifier convention.
    """

    mapping = labels_by_case_id or {}
    examples: list[BagTrainingExample] = []
    for case in cases:
        label = mapping.get(case.case_id)
        if label is None:
            suffix = case.case_id.rsplit("-", 1)[-1].upper()
            label = {"V": 1, "S": 0}.get(suffix)
        if label not in {0, 1}:
            raise ValueError(
                f"Bag label missing for {case.case_id!r}; provide labels_by_case_id"
            )
        examples.append(BagTrainingExample(case=case, label=int(label)))
    return examples


def train_candidate_decision_model(
    train_examples: list[BagTrainingExample],
    validation_examples: list[BagTrainingExample],
    calibration_examples: list[BagTrainingExample],
    threshold_examples: list[BagTrainingExample],
    *,
    config: CandidateDecisionTrainingConfig | None = None,
    warm_start_path: str | Path | None = None,
    device: str | torch.device = "cpu",
) -> CandidateDecisionArtifact:
    """Fit NG-DSMIL from project-level labels only.

    The calibrator is fit only to DSMIL bag output. Epoch selection and verifier
    thresholds use raw max-candidate probabilities, matching runtime inference.
    Candidate labels are neither required nor consumed.
    """

    settings = config or CandidateDecisionTrainingConfig()
    _validate_config(settings)
    for examples, split in (
        (train_examples, "train"),
        (validation_examples, "validation"),
        (calibration_examples, "calibration"),
        (threshold_examples, "threshold"),
    ):
        _require_bag_labels(examples, split, require_both_classes=split != "train")

    random.seed(settings.seed)
    torch.manual_seed(settings.seed)
    model = NormalityGuidedDSMIL().to(device)
    warm_start_metadata: dict[str, object] = {}
    if warm_start_path is not None:
        missing, unexpected = load_encoder_warm_start(model, warm_start_path)
        warm_start_metadata = {
            "encoder_warm_start": str(warm_start_path),
            "warm_start_missing_keys": missing,
            "warm_start_unexpected_keys": unexpected,
        }

    optimizer = torch.optim.AdamW(
        model.parameters(),
        lr=settings.learning_rate,
        weight_decay=settings.weight_decay,
    )
    best_state: dict[str, torch.Tensor] | None = None
    best_score = float("-inf")
    stale_epochs = 0
    for _epoch in range(settings.epochs):
        model.train()
        shuffled = list(train_examples)
        random.shuffle(shuffled)
        for start in range(0, len(shuffled), settings.batch_size):
            batch = shuffled[start : start + settings.batch_size]
            outputs = [model(example.case) for example in batch]
            loss = ng_dsmil_loss(
                outputs,
                [example.label for example in batch],
                lambda_normal=settings.lambda_normal,
                lambda_rank=settings.lambda_rank,
                rank_margin=settings.rank_margin,
            )
            optimizer.zero_grad(set_to_none=True)
            loss.backward()
            optimizer.step()

        score = _recall_at_fpr_score(model, validation_examples, settings.max_fpr)
        if score > best_score:
            best_score = score
            best_state = copy.deepcopy(model.state_dict())
            stale_epochs = 0
        else:
            stale_epochs += 1
            if stale_epochs >= settings.early_stop_patience:
                break
    if best_state is None:
        raise RuntimeError("NG-DSMIL training did not produce a model state")
    model.load_state_dict(best_state, strict=True)

    calibration_raw, calibration_labels = _raw_bag_probabilities(
        model, calibration_examples
    )
    calibrator = PlattCalibrator().fit(calibration_raw, calibration_labels)
    threshold_probabilities, threshold_labels = _raw_max_candidate_probabilities(
        model, threshold_examples
    )
    candidate_threshold = select_candidate_threshold(
        threshold_probabilities,
        threshold_labels,
        target_recall=settings.target_recall,
    )
    validation_threshold = max(
        candidate_threshold,
        select_validation_threshold(
            threshold_probabilities,
            threshold_labels,
            max_fpr=settings.max_fpr,
        ),
    )
    model.eval()
    return CandidateDecisionArtifact(
        model=model.cpu(),
        calibrator=calibrator,
        candidate_threshold=candidate_threshold,
        validation_threshold=validation_threshold,
        metadata={
            "training_bags": len(train_examples),
            "validation_bags": len(validation_examples),
            "calibration_bags": len(calibration_examples),
            "threshold_bags": len(threshold_examples),
            "max_fpr": settings.max_fpr,
            "target_recall": settings.target_recall,
            "selection_metric": "max_recall_at_fpr",
            "validation_selection_score": best_score,
            "seed": settings.seed,
            **warm_start_metadata,
        },
    )


def load_encoder_warm_start(
    model: NormalityGuidedDSMIL, old_path: str | Path
) -> tuple[list[str], list[str]]:
    """Reuse only encoders shared with the pre-NG-DSMIL architecture."""

    try:
        payload = torch.load(Path(old_path), map_location="cpu", weights_only=True)
        old_state = payload["model_state"]
    except (KeyError, OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ValueError("Encoder warm-start artifact is unreadable") from exc
    prefixes = ("bundle_encoder.", "bundle_attention.", "candidate_encoder.")
    compatible = {
        key: value
        for key, value in old_state.items()
        if key.startswith(prefixes) or key == "empty_evidence"
    }
    missing, unexpected = model.load_state_dict(compatible, strict=False)
    return list(missing), list(unexpected)


def _raw_bag_probabilities(
    model: NormalityGuidedDSMIL, examples: list[BagTrainingExample]
) -> tuple[list[float], list[int]]:
    model.eval()
    with torch.no_grad():
        raw = [
            float(torch.sigmoid(model(example.case).sample_logit).item())
            for example in examples
        ]
    return raw, [example.label for example in examples]


def _recall_at_fpr_score(
    model: NormalityGuidedDSMIL,
    examples: list[BagTrainingExample],
    max_fpr: float,
) -> float:
    probabilities, labels = _raw_max_candidate_probabilities(model, examples)
    thresholds = sorted({0.0, 1.0, *probabilities}, reverse=True)
    positives = sum(label == 1 for label in labels)
    negatives = sum(label == 0 for label in labels)
    best = float("-inf")
    for threshold in thresholds:
        tp = sum(probability >= threshold and label == 1 for probability, label in zip(probabilities, labels, strict=True))
        fp = sum(probability >= threshold and label == 0 for probability, label in zip(probabilities, labels, strict=True))
        recall = tp / positives
        fpr = fp / negatives
        score = recall if fpr <= max_fpr else recall - (fpr - max_fpr) * 2.0
        best = max(best, score)
    return best


def _raw_max_candidate_probabilities(
    model: NormalityGuidedDSMIL, examples: list[BagTrainingExample]
) -> tuple[list[float], list[int]]:
    """Bag proxy used wherever runtime candidate decisions are selected."""

    model.eval()
    probabilities: list[float] = []
    with torch.no_grad():
        for example in examples:
            candidate_logits = model(example.case).candidate_logits
            if not candidate_logits.numel():
                probabilities.append(0.0)
                continue
            probabilities.append(float(torch.sigmoid(candidate_logits).max().item()))
    return probabilities, [example.label for example in examples]


def _require_bag_labels(
    examples: list[BagTrainingExample], split: str, *, require_both_classes: bool
) -> None:
    labels = [example.label for example in examples]
    if not labels or any(label not in {0, 1} for label in labels):
        raise ValueError(f"{split} examples require bag labels 0/1")
    if require_both_classes and set(labels) != {0, 1}:
        raise ValueError(f"{split} examples must contain both safety classes")


def _validate_config(config: CandidateDecisionTrainingConfig) -> None:
    if config.epochs < 1 or config.batch_size < 1 or config.early_stop_patience < 1:
        raise ValueError("epochs, batch_size, and early_stop_patience must be positive")
    if config.learning_rate <= 0 or config.weight_decay < 0:
        raise ValueError("learning_rate must be positive and weight_decay non-negative")
    if config.lambda_normal < 0 or config.lambda_rank < 0 or config.rank_margin < 0:
        raise ValueError("loss weights and ranking margin must be non-negative")
    if not 0 < config.target_recall <= 1 or not 0 <= config.max_fpr <= 1:
        raise ValueError("target_recall and max_fpr must be probabilities")
