from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import nn

from ..features import DECISION_FEATURE_NAMES
from .attention import GatedAttention
from .encoder import BundleEncoder, CandidateEncoder
from .schema import CANDIDATE_FEATURE_NAMES, MIL_FAMILIES, CaseDecisionInput


@dataclass(frozen=True, slots=True)
class HierarchicalMILConfig:
    bundle_feature_dim: int = len(DECISION_FEATURE_NAMES) + len(MIL_FAMILIES)
    candidate_feature_dim: int = len(CANDIDATE_FEATURE_NAMES)
    dropout: float = 0.15


@dataclass(slots=True)
class MILForwardOutput:
    sample_logit: torch.Tensor
    candidate_logits: torch.Tensor
    candidate_attention: torch.Tensor
    bundle_attention: list[torch.Tensor]


class HierarchicalMIL(nn.Module):
    """Two-stage Bundle→Candidate→Sample multiple-instance model."""

    def __init__(self, config: HierarchicalMILConfig | None = None) -> None:
        super().__init__()
        self.config = config or HierarchicalMILConfig()
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
        self.empty_candidate = nn.Parameter(torch.zeros(64))
        self.sample_head = nn.Sequential(
            nn.Linear(130, 64),
            nn.ReLU(),
            nn.Dropout(self.config.dropout),
            nn.Linear(64, 1),
        )

    def forward(self, case: CaseDecisionInput) -> MILForwardOutput:
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
            candidate_logits = self.candidate_score(encoded_candidates).squeeze(-1)
            attention_embedding, candidate_attention = self.candidate_attention(
                encoded_candidates
            )
            critical_index = int(torch.argmax(candidate_logits).item())
            critical_embedding = encoded_candidates[critical_index]
            top_count = min(2, candidate_logits.numel())
            top_values = torch.topk(candidate_logits, top_count).values
            max_score = top_values[0]
            top2_mean = top_values.mean()
        else:
            encoded_candidates = self.empty_candidate.unsqueeze(0)
            candidate_logits = torch.empty(0, dtype=torch.float32, device=device)
            candidate_attention = torch.empty(0, dtype=torch.float32, device=device)
            attention_embedding = self.empty_candidate
            critical_embedding = self.empty_candidate
            max_score = torch.zeros((), dtype=torch.float32, device=device)
            top2_mean = max_score

        sample_vector = torch.cat(
            [
                attention_embedding,
                critical_embedding,
                max_score.reshape(1),
                top2_mean.reshape(1),
            ]
        )
        return MILForwardOutput(
            sample_logit=self.sample_head(sample_vector).squeeze(),
            candidate_logits=candidate_logits,
            candidate_attention=candidate_attention,
            bundle_attention=bundle_weights,
        )
