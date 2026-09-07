from __future__ import annotations

import torch
from torch import nn


class GatedAttention(nn.Module):
    def __init__(self, input_dim: int, hidden_dim: int | None = None) -> None:
        super().__init__()
        hidden = hidden_dim or input_dim
        self.v = nn.Linear(input_dim, hidden)
        self.u = nn.Linear(input_dim, hidden)
        self.w = nn.Linear(hidden, 1, bias=False)

    def forward(self, values: torch.Tensor) -> tuple[torch.Tensor, torch.Tensor]:
        if values.ndim != 2 or values.shape[0] == 0:
            raise ValueError("GatedAttention expects a non-empty [instances, features] tensor")
        logits = self.w(torch.tanh(self.v(values)) * torch.sigmoid(self.u(values))).squeeze(-1)
        weights = torch.softmax(logits, dim=0)
        return torch.sum(weights.unsqueeze(-1) * values, dim=0), weights
