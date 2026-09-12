from __future__ import annotations

from dataclasses import dataclass

from ..analysis.suspicion import SuspicionScorer
from ..models import Candidate


@dataclass(slots=True, frozen=True)
class GateDecision:
    candidate_id: str
    score: float
    threshold: float
    accepted: bool
    reasons: list[str]


@dataclass(slots=True, frozen=True)
class GateMetrics:
    candidate_count: int
    accepted_count: int
    rejected_count: int
    reduction_rate: float


@dataclass(slots=True, frozen=True)
class GateCalibration:
    threshold: float
    target_recall: float
    achieved_recall: float
    accepted_count: int
    target_met: bool
    vulnerable_sample_count: int = 0
    retained_vulnerable_sample_count: int = 0


class CandidateGate:
    def __init__(
        self,
        *,
        threshold: float = 0.40,
        enabled: bool = True,
        scorer: SuspicionScorer | None = None,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Candidate gate threshold must be between 0 and 1")
        self.threshold = threshold
        self.enabled = enabled
        self.scorer = scorer or SuspicionScorer()

    @classmethod
    def for_feature_collection(cls) -> "CandidateGate":
        """Training collection keeps the Top-K stage but disables hard gating."""

        return cls(enabled=False)

    def decide(self, candidate: Candidate) -> GateDecision:
        accepted = not self.enabled or candidate.suspicion_score >= self.threshold
        reasons = self.scorer.reasons(candidate.features)
        if not reasons:
            reasons = [f"suspicion_score={candidate.suspicion_score:.4f}"]
        reasons.append(
            "candidate gate disabled"
            if not self.enabled
            else (
                f"accepted: score >= {self.threshold:.4f}"
                if accepted
                else f"rejected: score < {self.threshold:.4f}"
            )
        )
        return GateDecision(
            candidate_id=candidate.candidate_id,
            score=candidate.suspicion_score,
            threshold=self.threshold,
            accepted=accepted,
            reasons=reasons,
        )

    def filter(
        self, candidates: list[Candidate]
    ) -> tuple[list[Candidate], list[GateDecision]]:
        decisions = [self.decide(candidate) for candidate in candidates]
        accepted = [
            candidate
            for candidate, decision in zip(candidates, decisions, strict=True)
            if decision.accepted
        ]
        return accepted, decisions

    def metrics(self, decisions: list[GateDecision]) -> GateMetrics:
        accepted = sum(decision.accepted for decision in decisions)
        count = len(decisions)
        return GateMetrics(
            candidate_count=count,
            accepted_count=accepted,
            rejected_count=count - accepted,
            reduction_rate=(count - accepted) / count if count else 0.0,
        )

    @staticmethod
    def calibrate(
        scores: list[float],
        labels: list[int],
        *,
        sample_ids: list[str] | None = None,
        target_recall: float = 0.985,
    ) -> GateCalibration:
        """Select the highest validation threshold meeting candidate recall."""

        if len(scores) != len(labels) or not scores:
            raise ValueError("scores and labels must be non-empty and equal length")
        if not 0.0 <= target_recall <= 1.0:
            raise ValueError("target_recall must be between 0 and 1")
        if sample_ids is not None and len(sample_ids) != len(scores):
            raise ValueError("sample_ids must match scores length")
        ids = sample_ids or [str(index) for index in range(len(scores))]
        pairs = [
            (float(score), int(label), str(sample_id))
            for score, label, sample_id in zip(scores, labels, ids)
        ]
        labels_by_sample: dict[str, int] = {}
        for _, label, sample_id in pairs:
            previous = labels_by_sample.setdefault(sample_id, label)
            if previous != label:
                raise ValueError("all candidates in a sample must share one label")
        vulnerable_samples = {
            sample_id for sample_id, label in labels_by_sample.items() if label == 1
        }
        if not vulnerable_samples:
            raise ValueError("gate calibration requires a vulnerable sample")
        selected_threshold = 0.0
        achieved_recall = 1.0
        for threshold in sorted({0.0, *(score for score, _, _ in pairs)}, reverse=True):
            retained = {
                sample_id
                for score, label, sample_id in pairs
                if label == 1 and score >= threshold
            }
            recalled = len(retained) / len(vulnerable_samples)
            if recalled >= target_recall:
                selected_threshold = threshold
                achieved_recall = recalled
                break
        accepted = sum(score >= selected_threshold for score, _, _ in pairs)
        retained = {
            sample_id
            for score, label, sample_id in pairs
            if label == 1 and score >= selected_threshold
        }
        return GateCalibration(
            threshold=selected_threshold,
            target_recall=target_recall,
            achieved_recall=achieved_recall,
            accepted_count=accepted,
            target_met=achieved_recall >= target_recall,
            vulnerable_sample_count=len(vulnerable_samples),
            retained_vulnerable_sample_count=len(retained),
        )
