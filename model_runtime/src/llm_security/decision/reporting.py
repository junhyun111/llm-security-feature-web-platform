from __future__ import annotations

from ..models import Candidate, Finding, ScoredEvidenceBundle


class FindingReportBuilder:
    """Create human-facing output only after scoring and policy evaluation."""

    def build(self, scored: ScoredEvidenceBundle, candidate: Candidate) -> Finding:
        bundle = scored.bundle
        expert = (bundle.supporting_experts or bundle.unknown_experts)[0]
        family = bundle.vulnerability_family.replace("_", " ")
        path = " → ".join(bundle.trigger_paths[0]) if bundle.trigger_paths else ""
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
            consequence="도달 가능한 공격 경로에서 보안 속성이 손상될 수 있습니다.",
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
            confidence=scored.probability,
            position="support" if bundle.support_count else "unknown",
            preconditions=list(bundle.preconditions),
            evidence_for=cited,
            model_id=bundle.model_ids[0] if bundle.model_ids else None,
            supporting_experts=list(bundle.supporting_experts),
            supporting_models=list(bundle.model_ids),
            probability=scored.probability,
            decision_features=dict(scored.features),
            evidence_bundle_id=bundle.bundle_id,
        )
