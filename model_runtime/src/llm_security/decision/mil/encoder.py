from __future__ import annotations

from torch import nn


class BundleEncoder(nn.Sequential):
    def __init__(self, input_dim: int, dropout: float = 0.15) -> None:
        super().__init__(
            nn.Linear(input_dim, 64),
            nn.LayerNorm(64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 32),
            nn.ReLU(),
        )


class CandidateEncoder(nn.Sequential):
    def __init__(self, input_dim: int, dropout: float = 0.15) -> None:
        super().__init__(
            nn.Linear(input_dim, 64),
            nn.LayerNorm(64),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(64, 64),
        )
