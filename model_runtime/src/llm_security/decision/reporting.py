from __future__ import annotations

from ..models import Candidate, EvidenceBundle, ExpertFamily, Finding
from .mil.schema import CandidateDecisionOutput


class FindingReportBuilder:
    """Create a human-facing report from one candidate decision and bundle."""

    def build(
        self,
        decision: CandidateDecisionOutput,
        candidate: Candidate,
        bundle: EvidenceBundle | None,
        *,
        fallback_expert: ExpertFamily,
        probability: float,
    ) -> Finding:
        if bundle is None:
            return self._without_bundle(
                decision, candidate, fallback_expert, probability
            )
        experts = bundle.supporting_experts or bundle.unknown_experts
        expert = experts[0] if experts else fallback_expert
        family = bundle.vulnerability_family.replace("_", " ")
        path = " -> ".join(bundle.trigger_paths[0]) if bundle.trigger_paths else ""
        cited = [
            item.expression
            for item in candidate.evidence
            if item.evidence_id in bundle.evidence_ids
        ]
        root_cause = (
            f"정적 근거 {', '.join(bundle.evidence_ids)}가 {family} 경로를 지지합니다."
        )
        if path:
            root_cause += f" 관찰된 경로: {path}."
        return Finding(
            finding_id=bundle.bundle_id,
            candidate_id=bundle.candidate_id,
            expert=expert,
            title=f"잠재적 {family} 취약점",
            root_cause=root_cause,
            consequence="공격 가능한 경로에서 보안 속성이 손상될 수 있습니다.",
            file=bundle.file,
            function=bundle.function,
            line_start=bundle.line_start,
            line_end=bundle.line_end,
            cwes=list(bundle.cwes),
            source=bundle.sources[0] if bundle.sources else None,
            sink=bundle.sinks[0] if bundle.sinks else None,
            missing_guard=None,
            trigger_path=list(bundle.trigger_paths[0]) if bundle.trigger_paths else [],
            evidence_ids=list(bundle.evidence_ids),
            confidence=probability,
            position="support" if bundle.support_count else "unknown",
            preconditions=list(bundle.preconditions),
            evidence_for=cited,
            model_id=bundle.model_ids[0] if bundle.model_ids else None,
            supporting_experts=list(bundle.supporting_experts),
            supporting_models=list(bundle.model_ids),
            probability=probability,
            decision_features=_decision_features(
                decision, candidate.candidate_id, probability
            ),
            evidence_bundle_id=bundle.bundle_id,
        )

    @staticmethod
    def _without_bundle(
        decision: CandidateDecisionOutput,
        candidate: Candidate,
        fallback_expert: ExpertFamily,
        probability: float,
    ) -> Finding:
        return Finding(
            finding_id=f"C-{decision.case_id}-{candidate.candidate_id}",
            candidate_id=candidate.candidate_id,
            expert=fallback_expert,
            title="근거가 부족한 잠재적 취약점",
            root_cause="후보 점수는 임계값을 넘었지만 검증 가능한 evidence bundle이 없습니다.",
            consequence="추가 정적 분석 또는 전문가 검토가 필요합니다.",
            file=candidate.file,
            function=candidate.function,
            line_start=candidate.line_start,
            line_end=candidate.line_end,
            cwes=[],
            source=None,
            sink=None,
            missing_guard=None,
            trigger_path=[],
            evidence_ids=[],
            confidence=probability,
            position="unknown",
            probability=probability,
            decision_features=_decision_features(
                decision, candidate.candidate_id, probability
            ),
        )


def _decision_features(
    decision: CandidateDecisionOutput,
    candidate_id: str,
    probability: float,
) -> dict[str, float]:
    return {
        "candidate_probability": probability,
        "project_probability": decision.project_probability,
        "candidate_attention": decision.candidate_attention.get(candidate_id, 0.0),
    }
