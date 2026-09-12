from __future__ import annotations

import torch
from torch.nn import functional as functional

from .model import CandidateForwardOutput


def _anchor(outputs: list[CandidateForwardOutput]) -> torch.Tensor:
    if not outputs:
        raise ValueError("at least one model output is required")
    return outputs[0].sample_logit * 0.0


def bag_classification_loss(
    outputs: list[CandidateForwardOutput], labels: list[int]
) -> torch.Tensor:
    """Weak supervision: one safety label per project bag."""

    if len(outputs) != len(labels) or not outputs:
        raise ValueError("one bag label is required per model output")
    logits = torch.stack([output.sample_logit for output in outputs])
    targets = torch.tensor(labels, dtype=torch.float32, device=logits.device)
    return functional.binary_cross_entropy_with_logits(logits, targets)


def normality_loss(
    outputs: list[CandidateForwardOutput], labels: list[int]
) -> torch.Tensor:
    """Pull candidate embeddings from known-safe bags toward normal prototypes."""

    if len(outputs) != len(labels) or not outputs:
        raise ValueError("one bag label is required per model output")
    losses = [
        (1.0 - output.normality_similarity).mean()
        for output, label in zip(outputs, labels, strict=True)
        if label == 0 and output.normality_similarity.numel()
    ]
    return torch.stack(losses).mean() if losses else _anchor(outputs)


def ranking_loss(
    outputs: list[CandidateForwardOutput],
    labels: list[int],
    *,
    margin: float = 0.5,
) -> torch.Tensor:
    """Separate the highest-risk instances in vulnerable and safe bags."""

    if len(outputs) != len(labels) or not outputs:
        raise ValueError("one bag label is required per model output")
    if margin < 0:
        raise ValueError("ranking margin must be non-negative")
    positive_scores: list[torch.Tensor] = []
    negative_scores: list[torch.Tensor] = []
    for output, label in zip(outputs, labels, strict=True):
        if not output.candidate_logits.numel():
            continue
        (positive_scores if label == 1 else negative_scores).append(
            output.candidate_logits.max()
        )
    if not positive_scores or not negative_scores:
        return _anchor(outputs)
    hardest_negative = torch.stack(negative_scores).max()
    positives = torch.stack(positive_scores)
    return functional.relu(margin - positives + hardest_negative).mean()


def ng_dsmil_loss(
    outputs: list[CandidateForwardOutput],
    labels: list[int],
    *,
    lambda_normal: float = 0.5,
    lambda_rank: float = 0.5,
    rank_margin: float = 0.5,
) -> torch.Tensor:
    if lambda_normal < 0 or lambda_rank < 0:
        raise ValueError("loss weights must be non-negative")
    bag = bag_classification_loss(outputs, labels)
    normal = normality_loss(outputs, labels)
    rank = ranking_loss(outputs, labels, margin=rank_margin)
    return bag + lambda_normal * normal + lambda_rank * rank
