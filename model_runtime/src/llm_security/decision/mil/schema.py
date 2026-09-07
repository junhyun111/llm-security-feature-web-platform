from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ...cwe import cwe_categories
from ...models import Candidate, EvidenceBundle, RouteDecision
from ..features import DECISION_FEATURE_NAMES, EvidenceFeatureBuilder


MIL_FAMILIES: tuple[str, ...] = (
    "memory_safety",
    "integer_size_type",
    "taint_api_contract",
    "control_state_error",
    "concurrency_toctou",
)

CANDIDATE_FEATURE_NAMES: tuple[str, ...] = (
    "suspicion_score",
    "candidate_rank",
    "router_top1",
    "router_margin",
    "selected_expert_count",
    "bundle_count",
    "support_bundle_count",
    "unknown_bundle_count",
    "expert_failure_ratio",
)


@dataclass(slots=True)
class BundleDecisionInput:
    bundle_id: str
    family: str
    features: dict[str, float]

    def vector(self) -> list[float]:
        family = _mil_family(self.family)
        return [
            *(float(self.features.get(name, 0.0)) for name in DECISION_FEATURE_NAMES),
            *(1.0 if name == family else 0.0 for name in MIL_FAMILIES),
        ]


@dataclass(slots=True)
class CandidateDecisionInput:
    candidate_id: str
    features: dict[str, float]
    bundles: list[BundleDecisionInput] = field(default_factory=list)

    def vector(self) -> list[float]:
        return [float(self.features.get(name, 0.0)) for name in CANDIDATE_FEATURE_NAMES]


@dataclass(slots=True)
class CaseDecisionInput:
    sample_id: str
    candidates: list[CandidateDecisionInput]
    label: int | None = None
    project_id: str | None = None
    cve_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CaseDecisionInput":
        return cls(
            sample_id=str(value["sample_id"]),
            label=None if value.get("label") is None else int(value["label"]),
            project_id=value.get("project_id"),
            cve_id=value.get("cve_id"),
            candidates=[
                CandidateDecisionInput(
                    candidate_id=str(candidate["candidate_id"]),
                    features={
                        str(key): float(item)
                        for key, item in candidate.get("features", {}).items()
                    },
                    bundles=[
                        BundleDecisionInput(
                            bundle_id=str(bundle["bundle_id"]),
                            family=str(bundle["family"]),
                            features={
                                str(key): float(item)
                                for key, item in bundle.get("features", {}).items()
                            },
                        )
                        for bundle in candidate.get("bundles", [])
                    ],
                )
                for candidate in value.get("candidates", [])
            ],
        )


@dataclass(slots=True)
class CaseDecisionScore:
    sample_id: str
    raw_probability: float
    probability: float
    candidate_scores: dict[str, float]
    candidate_attention: dict[str, float]
    bundle_attention: dict[str, dict[str, float]]
    top_candidate_id: str | None
    top_bundle_id: str | None


class DecisionInputBuilder:
    """Build one hierarchy while retaining candidates with zero bundles."""

    def __init__(self, feature_builder: EvidenceFeatureBuilder | None = None) -> None:
        self.feature_builder = feature_builder or EvidenceFeatureBuilder()

    def build(
        self,
        *,
        sample_id: str,
        candidates: list[Candidate],
        routes: list[RouteDecision],
        bundles: list[EvidenceBundle],
        expert_output: Any,
        label: int | None = None,
        project_id: str | None = None,
        cve_id: str | None = None,
    ) -> CaseDecisionInput:
        route_by_id = {route.candidate_id: route for route in routes}
        bundles_by_candidate: dict[str, list[EvidenceBundle]] = {}
        for bundle in bundles:
            bundles_by_candidate.setdefault(bundle.candidate_id, []).append(bundle)
        ordered = sorted(
            candidates,
            key=lambda item: (-item.suspicion_score, item.candidate_id),
        )
        result: list[CandidateDecisionInput] = []
        for rank, candidate in enumerate(ordered, start=1):
            route = route_by_id[candidate.candidate_id]
            candidate_bundles = bundles_by_candidate.get(candidate.candidate_id, [])
            encoded_bundles = [
                BundleDecisionInput(
                    bundle_id=bundle.bundle_id,
                    family=_mil_family_for_bundle(bundle),
                    features=self.feature_builder.build(
                        bundle, candidate, route, expert_output
                    ),
                )
                for bundle in candidate_bundles
            ]
            failure_ratio = max(
                (item.features["failure_ratio"] for item in encoded_bundles),
                default=_candidate_failure_ratio(
                    expert_output, candidate.candidate_id, len(route.selected)
                ),
            )
            result.append(
                CandidateDecisionInput(
                    candidate_id=candidate.candidate_id,
                    features={
                        "suspicion_score": float(candidate.suspicion_score),
                        "candidate_rank": float(rank),
                        "router_top1": float(route.top1_confidence),
                        "router_margin": float(route.top1_top2_margin),
                        "selected_expert_count": float(len(set(route.selected))),
                        "bundle_count": float(len(encoded_bundles)),
                        "support_bundle_count": float(
                            sum(bundle.support_count > 0 for bundle in candidate_bundles)
                        ),
                        "unknown_bundle_count": float(
                            sum(bundle.support_count == 0 for bundle in candidate_bundles)
                        ),
                        "expert_failure_ratio": float(failure_ratio),
                    },
                    bundles=encoded_bundles,
                )
            )
        return CaseDecisionInput(
            sample_id=sample_id,
            candidates=result,
            label=label,
            project_id=project_id,
            cve_id=cve_id,
        )


def _mil_family_for_bundle(bundle: EvidenceBundle) -> str:
    categories = cwe_categories(bundle.cwes)
    if categories & {"memory_spatial", "memory_temporal"}:
        return "memory_safety"
    if "integer" in categories:
        return "integer_size_type"
    if "taint_api" in categories:
        return "taint_api_contract"
    if "control_state" in categories:
        return "control_state_error"
    if "concurrency" in categories:
        return "concurrency_toctou"
    experts = bundle.supporting_experts or bundle.unknown_experts
    return _mil_family(experts[0].value if experts else bundle.vulnerability_family)


def _mil_family(value: str) -> str:
    normalized = value.lower()
    if normalized in {"memory_bounds", "lifetime_resource", "memory_safety"}:
        return "memory_safety"
    for family in MIL_FAMILIES:
        if normalized == family:
            return family
    return "control_state_error"


def _candidate_failure_ratio(output: Any, candidate_id: str, assigned: int) -> float:
    failures = [
        failure
        for failure in getattr(output, "failures", [])
        if getattr(failure, "candidate_id", None) == candidate_id
        and not getattr(failure, "recovered", False)
    ]
    return len(failures) / max(1, assigned)
