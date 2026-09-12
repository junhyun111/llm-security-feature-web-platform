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
class ContextualCandidateClassifierConfig:
    bundle_feature_dim: int = len(DECISION_FEATURE_NAMES) + len(EXPERT_FAMILIES)
    candidate_feature_dim: int = len(CANDIDATE_FEATURE_NAMES)
    dropout: float = 0.15


@dataclass(slots=True)
class CandidateForwardOutput:
    candidate_logits: torch.Tensor
    candidate_attention: torch.Tensor
    bundle_attention: list[torch.Tensor]


class ContextualCandidateClassifier(nn.Module):
    """Bundle and candidate encoders with shared global project context."""

    def __init__(
        self, config: ContextualCandidateClassifierConfig | None = None
    ) -> None:
        super().__init__()
        self.config = config or ContextualCandidateClassifierConfig()
        self.bundle_encoder = BundleEncoder(
            self.config.bundle_feature_dim, self.config.dropout
        )
        self.bundle_attention = GatedAttention(32)
        self.empty_evidence = nn.Parameter(torch.zeros(32))
        self.candidate_encoder = CandidateEncoder(
            self.config.candidate_feature_dim + 32, self.config.dropout
        )
        self.candidate_score = nn.Linear(64, 1)
        self.candidate_attention = GatedAttention(64)

    def forward(self, case: CandidateDecisionContext) -> CandidateForwardOutput:
        device = self.empty_evidence.device
        candidate_embeddings: list[torch.Tensor] = []
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
            candidate_embeddings.append(
                self.candidate_encoder(
                    torch.cat([candidate_vector, evidence_embedding], dim=0)
                )
            )
            bundle_weights.append(attention)

        if candidate_embeddings:
            encoded_candidates = torch.stack(candidate_embeddings)
            global_context, candidate_attention = self.candidate_attention(
                encoded_candidates
            )
            contextual_candidates = encoded_candidates + global_context.unsqueeze(0)
            candidate_logits = self.candidate_score(contextual_candidates).squeeze(-1)
        else:
            candidate_logits = torch.empty(0, dtype=torch.float32, device=device)
            candidate_attention = torch.empty(0, dtype=torch.float32, device=device)
        return CandidateForwardOutput(
            candidate_logits=candidate_logits,
            candidate_attention=candidate_attention,
            bundle_attention=bundle_weights,
        )
