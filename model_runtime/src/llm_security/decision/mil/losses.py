from __future__ import annotations

import torch
from torch.nn import functional

from .model import CandidateForwardOutput


def candidate_classification_loss(
    outputs: list[CandidateForwardOutput],
    labels: list[torch.Tensor],
) -> torch.Tensor:
    if len(outputs) != len(labels) or not outputs:
        raise ValueError("one candidate-label tensor is required per output")
    logits = torch.cat([output.candidate_logits for output in outputs])
    targets = torch.cat(
        [label.to(device=logits.device, dtype=torch.float32) for label in labels]
    )
    if logits.numel() != targets.numel() or not logits.numel():
        raise ValueError("candidate logits and labels must be aligned and non-empty")
    return functional.binary_cross_entropy_with_logits(logits, targets)
