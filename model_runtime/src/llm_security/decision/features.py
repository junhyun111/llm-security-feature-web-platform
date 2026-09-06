from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from ..cwe import cwe_categories, cwes_supported_by_evidence
from ..models import Candidate, EvidenceBundle, RouteDecision


DECISION_FEATURE_NAMES: tuple[str, ...] = (
    "candidate_score",
    "router_top1",
    "router_margin",
    "support_expert_count",
    "unknown_expert_count",
    "expert_coverage",
    "unique_evidence_count",
    "evidence_diversity",
    "source_present",
    "sink_present",
    "source_sink_path",
    "trigger_path_length",
    "precondition_count",
    "precondition_supported",
    "cwe_semantic_support",
    "guard_present",
    "counter_evidence_count",
    "max_expert_confidence",
    "mean_expert_confidence",
    "expert_agreement",
    "failure_ratio",
)


_COUNTER_EVIDENCE_KINDS = {
    "guard_protects_sink",
    "ownership_lifetime_proof",
    "checked_arithmetic",
    "explicit_range_bound",
    "sanitizer_protects_sink",
    "return_value_checked",
    "same_lockset",
    "atomicity_proof",
    "happens_before",
}


class EvidenceFeatureBuilder:
    """Convert a fused bundle into a stable numeric feature vector."""

    feature_names = DECISION_FEATURE_NAMES

    def build(
        self,
        bundle: EvidenceBundle,
        candidate: Candidate,
        route: RouteDecision | Any,
        expert_stats: Mapping[str, float] | Any | None = None,
    ) -> dict[str, float]:
        cited = [
            item for item in candidate.evidence if item.evidence_id in bundle.evidence_ids
        ]
        counter = [
            item
            for item in candidate.evidence
            if item.kind in _COUNTER_EVIDENCE_KINDS
            and self._counter_evidence_applies(item, bundle)
        ]
        confidences = bundle.expert_confidences
        all_experts = set(bundle.supporting_experts) | set(bundle.unknown_experts)
        selected = set(getattr(route, "selected", []) or [])
        assigned = len(selected) or len(all_experts)
        completed, failed = self._execution_counts(
            expert_stats, bundle.candidate_id, assigned
        )
        assigned = assigned or completed + failed
        if completed == 0 and failed == 0:
            completed = len(all_experts)
        path_lengths = [len(path) for path in bundle.trigger_paths if path]
        total_positions = bundle.support_count + bundle.unknown_count

        values = {
            "candidate_score": float(candidate.suspicion_score),
            "router_top1": float(getattr(route, "top1_confidence", 0.0) or 0.0),
            "router_margin": float(getattr(route, "top1_top2_margin", 0.0) or 0.0),
            "support_expert_count": float(len(set(bundle.supporting_experts))),
            "unknown_expert_count": float(len(set(bundle.unknown_experts))),
            "expert_coverage": min(1.0, completed / max(1, assigned)),
            "unique_evidence_count": float(len(bundle.evidence_ids)),
            "evidence_diversity": len(bundle.evidence_ids)
            / max(1, bundle.total_evidence_references),
            "source_present": float(bool(bundle.sources)),
            "sink_present": float(bool(bundle.sinks)),
            "source_sink_path": float(
                bool(bundle.sources and bundle.sinks and path_lengths)
            ),
            "trigger_path_length": float(max(path_lengths, default=0)),
            "precondition_count": float(len(bundle.preconditions)),
            "precondition_supported": float(
                bool(bundle.preconditions and bundle.evidence_ids)
            ),
            "cwe_semantic_support": float(
                cwes_supported_by_evidence(bundle.cwes, cited)
            ),
            "guard_present": float(any(item.kind == "guard_protects_sink" for item in counter)),
            "counter_evidence_count": float(len(counter)),
            "max_expert_confidence": max(confidences, default=0.0),
            "mean_expert_confidence": (
                sum(confidences) / len(confidences) if confidences else 0.0
            ),
            "expert_agreement": bundle.support_count / max(1, total_positions),
            "failure_ratio": failed / max(1, completed + failed),
        }
        return {name: float(values[name]) for name in self.feature_names}

    @staticmethod
    def _execution_counts(
        stats: Mapping[str, float] | Any | None,
        candidate_id: str,
        assigned: int,
    ) -> tuple[int, int]:
        if stats is None:
            return 0, 0
        if isinstance(stats, Mapping):
            return (
                int(stats.get("completed_task_count", 0)),
                int(stats.get("failed_task_count", 0)),
            )
        failures = getattr(stats, "failures", None)
        if failures:
            failed = sum(
                getattr(item, "candidate_id", None) == candidate_id
                and not bool(getattr(item, "recovered", False))
                for item in failures
            )
            return max(0, assigned - failed), failed
        task_count = int(getattr(stats, "task_count", 0))
        completed_count = int(getattr(stats, "completed_task_count", task_count))
        global_failed = int(
            getattr(stats, "failed_task_count", 0)
            or max(0, task_count - completed_count)
        )
        if global_failed and task_count:
            estimated_failed = min(
                assigned,
                max(1, round(assigned * global_failed / task_count)),
            )
            return max(0, assigned - estimated_failed), estimated_failed
        return (
            int(getattr(stats, "completed_task_count", 0)),
            int(getattr(stats, "failed_task_count", 0)),
        )

    @staticmethod
    def _counter_evidence_applies(item: Any, bundle: EvidenceBundle) -> bool:
        if item.file != bundle.file:
            return False
        sink_line = item.facts.get("sink_line")
        if sink_line is not None:
            try:
                if not bundle.line_start <= int(sink_line) <= bundle.line_end:
                    return False
            except (TypeError, ValueError):
                return False
        if item.kind == "guard_protects_sink":
            return (
                "memory_spatial" in cwe_categories(bundle.cwes)
                and item.facts.get("semantically_protective") is True
            )
        allowed_categories = {
            "ownership_lifetime_proof": "memory_temporal",
            "checked_arithmetic": "integer",
            "explicit_range_bound": "integer",
            "sanitizer_protects_sink": "taint_api",
            "return_value_checked": "control_state",
            "same_lockset": "concurrency",
            "atomicity_proof": "concurrency",
            "happens_before": "concurrency",
        }
        if allowed_categories.get(item.kind) not in cwe_categories(bundle.cwes):
            return False
        return item.facts.get("verified", True) is True
