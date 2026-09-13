from __future__ import annotations

import torch
from torch.nn import functional

from .model import CandidateForwardOutput


def _anchor(outputs: list[CandidateForwardOutput]) -> torch.Tensor:
    if not outputs:
        raise ValueError("at least one model output is required")
    return outputs[0].sample_logit * 0.0


def _validate_inputs(outputs: list[CandidateForwardOutput], labels: list[int]) -> None:
    if len(outputs) != len(labels) or not outputs:
        raise ValueError("one bag label is required per output")
    if any(label not in {0, 1} for label in labels):
        raise ValueError("bag labels must be 0 or 1")


def vulnerable_bag_loss(
    outputs: list[CandidateForwardOutput], labels: list[int]
) -> torch.Tensor:
    """Train non-empty vulnerable bags from their pooled candidate logit only."""
    _validate_inputs(outputs, labels)
    losses = [
        functional.binary_cross_entropy_with_logits(
            output.sample_logit, torch.ones_like(output.sample_logit)
        )
        for output, label in zip(outputs, labels, strict=True)
        if label == 1 and output.candidate_logits.numel()
    ]
    return torch.stack(losses).mean() if losses else _anchor(outputs)


def safe_candidate_loss(
    outputs: list[CandidateForwardOutput], labels: list[int]
) -> torch.Tensor:
    """Apply direct negative supervision to every candidate in safe bags."""
    _validate_inputs(outputs, labels)
    losses = [
        functional.binary_cross_entropy_with_logits(
            output.candidate_logits, torch.zeros_like(output.candidate_logits)
        )
        for output, label in zip(outputs, labels, strict=True)
        if label == 0 and output.candidate_logits.numel()
    ]
    return torch.stack(losses).mean() if losses else _anchor(outputs)


def asymmetric_mil_loss(
    outputs: list[CandidateForwardOutput],
    labels: list[int],
    *,
    lambda_safe: float = 1.0,
) -> torch.Tensor:
    if lambda_safe < 0:
        raise ValueError("lambda_safe must be non-negative")
    return vulnerable_bag_loss(outputs, labels) + lambda_safe * safe_candidate_loss(
        outputs, labels
    )
