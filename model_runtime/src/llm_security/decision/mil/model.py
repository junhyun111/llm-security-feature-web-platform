from __future__ import annotations

from dataclasses import dataclass

import torch
from torch import nn
from torch.nn import functional as functional

from ..features import DECISION_FEATURE_NAMES
from .attention import GatedAttention
from .encoder import BundleEncoder, CandidateEncoder
from .schema import (
    CANDIDATE_FEATURE_NAMES,
    EXPERT_FAMILIES,
    CandidateDecisionContext,
)


@dataclass(frozen=True, slots=True)
class NormalityGuidedDSMILConfig:
    bundle_feature_dim: int = len(DECISION_FEATURE_NAMES) + len(EXPERT_FAMILIES)
    candidate_feature_dim: int = len(CANDIDATE_FEATURE_NAMES)
    candidate_embedding_dim: int = 64
    prototype_count: int = 8
    attention_dim: int = 32
    dropout: float = 0.15
    dsmil_temperature: float = 0.2


@dataclass(slots=True)
class CandidateForwardOutput:
    """Candidate scores plus the bag-level DSMIL supervision branch."""

    candidate_logits: torch.Tensor
    bag_logit: torch.Tensor
    sample_logit: torch.Tensor
    candidate_attention: torch.Tensor
    bundle_attention: list[torch.Tensor]
    candidate_embeddings: torch.Tensor
    normality_similarity: torch.Tensor


class NormalityGuidedDSMIL(nn.Module):
    """Independent instance scores with normal-prototype and DSMIL bag learning.

    A candidate's vulnerability logit depends only on its own static and evidence
    features. Other candidates may affect the *bag* prediction and attention, but
    never the instance logit emitted to the verifier.
    """

    def __init__(self, config: NormalityGuidedDSMILConfig | None = None) -> None:
        super().__init__()
        self.config = config or NormalityGuidedDSMILConfig()
        if self.config.candidate_embedding_dim != 64:
            raise ValueError("CandidateEncoder currently produces 64-dimensional embeddings")
        if self.config.prototype_count < 1:
            raise ValueError("prototype_count must be positive")
        if self.config.attention_dim < 1 or self.config.dsmil_temperature <= 0:
            raise ValueError("DSMIL attention dimensions and temperature must be positive")

        self.bundle_encoder = BundleEncoder(
            self.config.bundle_feature_dim, self.config.dropout
        )
        self.bundle_attention = GatedAttention(32)
        self.empty_evidence = nn.Parameter(torch.zeros(32))
        self.candidate_encoder = CandidateEncoder(
            self.config.candidate_feature_dim + 32, self.config.dropout
        )

        self.vulnerability_head = nn.Sequential(
            nn.LayerNorm(self.config.candidate_embedding_dim),
            nn.Linear(self.config.candidate_embedding_dim, 32),
            nn.GELU(),
            nn.Dropout(self.config.dropout),
            nn.Linear(32, 1),
        )
        self.normal_prototypes = nn.Parameter(
            torch.randn(
                self.config.prototype_count,
                self.config.candidate_embedding_dim,
            )
        )
        self.raw_vulnerability_scale = nn.Parameter(torch.tensor(0.0))
        self.raw_normality_scale = nn.Parameter(torch.tensor(0.0))
        self.candidate_bias = nn.Parameter(torch.tensor(0.0))

        self.query = nn.Linear(
            self.config.candidate_embedding_dim, self.config.attention_dim
        )
        self.value = nn.Linear(
            self.config.candidate_embedding_dim, self.config.candidate_embedding_dim
        )
        self.bag_classifier = nn.Linear(self.config.candidate_embedding_dim, 1)

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

    def _candidate_scores(
        self, embeddings: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor]:
        vulnerability_logit = self.vulnerability_head(embeddings).squeeze(-1)
        normalized_embeddings = functional.normalize(embeddings, dim=-1)
        normalized_prototypes = functional.normalize(self.normal_prototypes, dim=-1)
        similarity = normalized_embeddings @ normalized_prototypes.transpose(0, 1)
        max_normal_similarity = similarity.max(dim=1).values
        normality_distance = 1.0 - max_normal_similarity
        alpha = functional.softplus(self.raw_vulnerability_scale)
        beta = functional.softplus(self.raw_normality_scale)
        candidate_logits = (
            alpha * vulnerability_logit
            + beta * normality_distance
            + self.candidate_bias
        )
        return candidate_logits, max_normal_similarity

    def _dsmil(
        self, embeddings: torch.Tensor, candidate_logits: torch.Tensor
    ) -> tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
        if embeddings.shape[0] == 0:
            empty = torch.empty(0, dtype=torch.float32, device=embeddings.device)
            # Keep an autograd path for an empty bag during bag-level training.
            negative = self.empty_evidence.sum() * 0.0 - 20.0
            return negative, negative, empty

        critical_index = torch.argmax(candidate_logits)
        queries = self.query(embeddings)
        critical_query = queries[critical_index]
        scale = self.config.attention_dim**0.5
        attention_logits = (queries @ critical_query) / (
            scale * self.config.dsmil_temperature
        )
        attention = torch.softmax(attention_logits, dim=0)
        values = self.value(embeddings)
        bag_embedding = torch.sum(attention.unsqueeze(-1) * values, dim=0)
        bag_logit = self.bag_classifier(bag_embedding).squeeze()
        sample_logit = (candidate_logits.max() + bag_logit) / 2.0
        return bag_logit, sample_logit, attention

    def forward(self, case: CandidateDecisionContext) -> CandidateForwardOutput:
        embeddings, bundle_attention = self._encode_candidates(case)
        if embeddings.shape[0] == 0:
            empty = torch.empty(0, dtype=torch.float32, device=embeddings.device)
            negative = self.empty_evidence.sum() * 0.0 - 20.0
            return CandidateForwardOutput(
                candidate_logits=empty,
                bag_logit=negative,
                sample_logit=negative,
                candidate_attention=empty,
                bundle_attention=bundle_attention,
                candidate_embeddings=embeddings,
                normality_similarity=empty,
            )
        candidate_logits, similarity = self._candidate_scores(embeddings)
        bag_logit, sample_logit, candidate_attention = self._dsmil(
            embeddings, candidate_logits
        )
        return CandidateForwardOutput(
            candidate_logits=candidate_logits,
            bag_logit=bag_logit,
            sample_logit=sample_logit,
            candidate_attention=candidate_attention,
            bundle_attention=bundle_attention,
            candidate_embeddings=embeddings,
            normality_similarity=similarity,
        )
