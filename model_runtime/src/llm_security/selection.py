from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from .analysis.suspicion import SuspicionScorer
from .models import Candidate


@dataclass(slots=True, frozen=True)
class CandidateSelectionDecision:
    candidate_id: str
    score: float
    selected: bool
    reason: str


@dataclass(slots=True)
class CandidateSelection:
    generated: list[Candidate]
    ranked: list[Candidate]
    threshold_candidates: list[Candidate]
    selected: list[Candidate]
    rejected: list[Candidate]
    scores: dict[str, float]
    decisions: list[CandidateSelectionDecision] = field(default_factory=list)


@dataclass(slots=True, frozen=True)
class SelectionCalibration:
    threshold: float
    target_recall: float
    achieved_recall: float
    accepted_count: int
    target_met: bool
    vulnerable_case_count: int
    retained_vulnerable_case_count: int


class CandidateRanker(Protocol):
    def rank(self, candidates: list[Candidate]) -> list[Candidate]: ...


class CandidateSelector:
    """Own ranking, recall thresholding, and the Expert-budget Top-K cut."""

    def __init__(
        self,
        *,
        ranker: CandidateRanker | None = None,
        threshold: float = 0.40,
        threshold_enabled: bool = True,
        max_candidates: int | None = None,
        suspicion_scorer: SuspicionScorer | None = None,
    ) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("Candidate threshold must be between 0 and 1")
        if max_candidates is not None and max_candidates < 1:
            raise ValueError("max_candidates must be positive")
        self.ranker = ranker
        self.threshold = threshold
        self.threshold_enabled = threshold_enabled
        self.max_candidates = max_candidates
        self.suspicion_scorer = suspicion_scorer or SuspicionScorer()

    def select(self, candidates: list[Candidate]) -> CandidateSelection:
        generated = list(candidates)
        ranked = (
            self.ranker.rank(list(generated))
            if self.ranker is not None
            else sorted(generated, key=_candidate_order)
        )
        threshold_candidates = [
            candidate
            for candidate in ranked
            if not self.threshold_enabled
            or candidate.suspicion_score >= self.threshold
        ]
        selected = (
            threshold_candidates
            if self.max_candidates is None
            else threshold_candidates[: self.max_candidates]
        )
        selected_ids = {candidate.candidate_id for candidate in selected}
        rejected = [
            candidate for candidate in ranked if candidate.candidate_id not in selected_ids
        ]
        decisions = [
            CandidateSelectionDecision(
                candidate_id=candidate.candidate_id,
                score=candidate.suspicion_score,
                selected=candidate.candidate_id in selected_ids,
                reason=self._reason(candidate, candidate.candidate_id in selected_ids),
            )
            for candidate in ranked
        ]
        return CandidateSelection(
            generated=generated,
            ranked=ranked,
            threshold_candidates=threshold_candidates,
            selected=list(selected),
            rejected=rejected,
            scores={
                candidate.candidate_id: candidate.suspicion_score
                for candidate in ranked
            },
            decisions=decisions,
        )

    def _reason(self, candidate: Candidate, selected: bool) -> str:
        if self.threshold_enabled and candidate.suspicion_score < self.threshold:
            return f"below recall threshold {self.threshold:.4f}"
        if not selected:
            return f"outside Top-{self.max_candidates} Expert budget"
        reasons = self.suspicion_scorer.reasons(candidate.features)
        return reasons[0] if reasons else "selected by candidate score"

    @staticmethod
    def calibrate(
        scores: list[float],
        labels: list[int],
        *,
        case_ids: list[str] | None = None,
        target_recall: float = 0.985,
    ) -> SelectionCalibration:
        if len(scores) != len(labels) or not scores:
            raise ValueError("scores and labels must be non-empty and equal length")
        if not 0.0 <= target_recall <= 1.0:
            raise ValueError("target_recall must be between 0 and 1")
        if case_ids is not None and len(case_ids) != len(scores):
            raise ValueError("case_ids must match scores length")
        ids = case_ids or [str(index) for index in range(len(scores))]
        pairs = [
            (float(score), int(label), str(case_id))
            for score, label, case_id in zip(scores, labels, ids, strict=True)
        ]
        labels_by_case: dict[str, int] = {}
        for _, label, case_id in pairs:
            previous = labels_by_case.setdefault(case_id, label)
            if previous != label:
                raise ValueError("all candidates in a case must share one label")
        vulnerable_cases = {
            case_id for case_id, label in labels_by_case.items() if label == 1
        }
        if not vulnerable_cases:
            raise ValueError("selection calibration requires a vulnerable sample")

        selected_threshold = 0.0
        achieved_recall = 1.0
        for threshold in sorted({0.0, *(score for score, _, _ in pairs)}, reverse=True):
            retained = {
                case_id
                for score, label, case_id in pairs
                if label == 1 and score >= threshold
            }
            recall = len(retained) / len(vulnerable_cases)
            if recall >= target_recall:
                selected_threshold = threshold
                achieved_recall = recall
                break
        retained = {
            case_id
            for score, label, case_id in pairs
            if label == 1 and score >= selected_threshold
        }
        return SelectionCalibration(
            threshold=selected_threshold,
            target_recall=target_recall,
            achieved_recall=achieved_recall,
            accepted_count=sum(
                score >= selected_threshold for score, _, _ in pairs
            ),
            target_met=achieved_recall >= target_recall,
            vulnerable_case_count=len(vulnerable_cases),
            retained_vulnerable_case_count=len(retained),
        )


def _candidate_order(candidate: Candidate) -> tuple[float, str, int, str]:
    return (
        -candidate.suspicion_score,
        candidate.file,
        candidate.line_start,
        candidate.candidate_id,
    )
