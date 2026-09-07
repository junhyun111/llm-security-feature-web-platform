from __future__ import annotations

import torch
from torch.nn import functional as functional

from .model import MILForwardOutput


def hierarchical_mil_loss(
    outputs: list[MILForwardOutput],
    labels: torch.Tensor,
    *,
    negative_instance_weight: float = 0.15,
    ranking_weight: float = 0.10,
    ranking_margin: float = 0.5,
) -> tuple[torch.Tensor, dict[str, torch.Tensor]]:
    if len(outputs) != labels.numel() or not outputs:
        raise ValueError("one label is required for every MIL output")
    sample_logits = torch.stack([output.sample_logit for output in outputs])
    labels = labels.to(device=sample_logits.device, dtype=torch.float32)
    bag_loss = functional.binary_cross_entropy_with_logits(sample_logits, labels)

    safe_logits = [
        output.candidate_logits
        for output, label in zip(outputs, labels)
        if float(label.item()) == 0.0 and output.candidate_logits.numel()
    ]
    negative_instance_loss = (
        functional.binary_cross_entropy_with_logits(
            torch.cat(safe_logits), torch.zeros_like(torch.cat(safe_logits))
        )
        if safe_logits
        else sample_logits.sum() * 0.0
    )
    vulnerable_max = [
        output.candidate_logits.max()
        for output, label in zip(outputs, labels)
        if float(label.item()) == 1.0 and output.candidate_logits.numel()
    ]
    safe_max = [values.max() for values in safe_logits]
    ranking_loss = (
        torch.stack(
            [
                functional.relu(ranking_margin - vulnerable + safe)
                for vulnerable in vulnerable_max
                for safe in safe_max
            ]
        ).mean()
        if vulnerable_max and safe_max
        else sample_logits.sum() * 0.0
    )
    total = (
        bag_loss
        + negative_instance_weight * negative_instance_loss
        + ranking_weight * ranking_loss
    )
    return total, {
        "bag_loss": bag_loss.detach(),
        "negative_instance_loss": negative_instance_loss.detach(),
        "ranking_loss": ranking_loss.detach(),
    }
