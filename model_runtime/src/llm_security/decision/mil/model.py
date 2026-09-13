from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import nn

from ..features import DECISION_FEATURE_NAMES
from .attention import GatedAttention
from .encoder import BundleEncoder, CandidateEncoder
from .schema import (
    CANDIDATE_FEATURE_NAMES,
    EXPERT_FAMILIES,
    CandidateDecisionContext,
)


@dataclass(frozen=True, slots=True)
class DirectAsymmetricMILConfig:
    bundle_feature_dim: int = len(DECISION_FEATURE_NAMES) + len(EXPERT_FAMILIES)
    candidate_feature_dim: int = len(CANDIDATE_FEATURE_NAMES)
    candidate_embedding_dim: int = 64
    dropout: float = 0.15
    pooling_temperature: float = 0.5


@dataclass(slots=True)
class CandidateForwardOutput:
    candidate_logits: torch.Tensor
    sample_logit: torch.Tensor
    candidate_attention: torch.Tensor
    bundle_attention: list[torch.Tensor]
    candidate_embeddings: torch.Tensor


class DirectAsymmetricMIL(nn.Module):
    """Candidate-independent classifier with asymmetric weak MIL supervision."""

    def __init__(self, config: DirectAsymmetricMILConfig | None = None) -> None:
        super().__init__()
        self.config = config or DirectAsymmetricMILConfig()
        if self.config.candidate_embedding_dim != 64:
            raise ValueError("CandidateEncoder currently produces 64-dimensional embeddings")
        if self.config.pooling_temperature <= 0:
            raise ValueError("pooling_temperature must be positive")

        self.bundle_encoder = BundleEncoder(
            self.config.bundle_feature_dim, self.config.dropout
        )
        self.bundle_attention = GatedAttention(32)
        self.empty_evidence = nn.Parameter(torch.zeros(32))
        self.candidate_encoder = CandidateEncoder(
            self.config.candidate_feature_dim + 32, self.config.dropout
        )
        self.candidate_head = nn.Sequential(
            nn.LayerNorm(self.config.candidate_embedding_dim),
            nn.Linear(self.config.candidate_embedding_dim, 32),
            nn.GELU(),
            nn.Dropout(self.config.dropout),
            nn.Linear(32, 1),
        )

    def _encode_candidates(
        self, case: CandidateDecisionContext
    ) -> tuple[torch.Tensor, list[torch.Tensor]]:
        device = self.empty_evidence.device
        embeddings: list[torch.Tensor] = []
        bundle_weights: list[torch.Tensor] = []
        for candidate in case.candidates:
            if candidate.bundles:
                vectors = torch.tensor(
                    [bundle.vector() for bundle in candidate.bundles],
                    dtype=torch.float32,
                    device=device,
                )
                encoded = self.bundle_encoder(vectors)
                evidence_embedding, attention = self.bundle_attention(encoded)
            else:
                evidence_embedding = self.empty_evidence
                attention = torch.empty(0, dtype=torch.float32, device=device)
            candidate_vector = torch.tensor(
                candidate.vector(), dtype=torch.float32, device=device
            )
            embeddings.append(
                self.candidate_encoder(
                    torch.cat([candidate_vector, evidence_embedding], dim=0)
                )
            )
            bundle_weights.append(attention)

        if not embeddings:
            return (
                torch.empty(
                    0,
                    self.config.candidate_embedding_dim,
                    dtype=torch.float32,
                    device=device,
                ),
                bundle_weights,
            )
        return torch.stack(embeddings), bundle_weights

    def forward(self, case: CandidateDecisionContext) -> CandidateForwardOutput:
        embeddings, bundle_attention = self._encode_candidates(case)
        if embeddings.shape[0] == 0:
            empty = torch.empty(0, dtype=torch.float32, device=embeddings.device)
            negative = self.empty_evidence.sum() * 0.0 - 20.0
            return CandidateForwardOutput(
                candidate_logits=empty,
                sample_logit=negative,
                candidate_attention=empty,
                bundle_attention=bundle_attention,
                candidate_embeddings=embeddings,
            )

        candidate_logits = self.candidate_head(embeddings).squeeze(-1)
        candidate_attention = torch.softmax(
            candidate_logits / self.config.pooling_temperature, dim=0
        )
        sample_logit = torch.sum(candidate_attention * candidate_logits)
        return CandidateForwardOutput(
            candidate_logits=candidate_logits,
            sample_logit=sample_logit,
            candidate_attention=candidate_attention,
            bundle_attention=bundle_attention,
            candidate_embeddings=embeddings,
        )
