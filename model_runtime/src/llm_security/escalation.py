from __future__ import annotations

from .cwe import cwes_supported_by_evidence
from .models import (
    Candidate,
    EscalationDecision,
    ExpertAssessment,
    ExpertFamily,
    ExpertVerdict,
    RouteDecision,
)

PROTECTIVE_EVIDENCE_KINDS = frozenset({
    "guard_protects_sink",
    "guard",
    "lock_acquire",
    "lock_release",
})


class EvidenceEscalationPolicy:
    """Escalate from the initial Top-2 only when their evidence is insufficient."""

    def decide(
        self,
        *,
        candidate: Candidate,
        route: RouteDecision,
        assessments: list[ExpertAssessment],
    ) -> EscalationDecision:
        initial = list(route.top2_experts or route.selected[:2])
        initial_assessments = [
            item for item in assessments if item.expert in initial
        ]
        returned = {item.expert for item in initial_assessments}
        reasons: list[str] = []
        missing_requirements: list[str] = []

        for expert in initial:
            if expert not in returned:
                reasons.append(f"missing result from {expert.value}")
        for assessment in initial_assessments:
            if assessment.verdict is ExpertVerdict.UNCERTAIN:
                reasons.append(f"{assessment.expert.value} returned UNCERTAIN")
            elif assessment.verdict is ExpertVerdict.VULNERABLE:
                complete, missing = _vulnerability_proof_complete(assessment, candidate)
                if not complete:
                    reasons.append(
                        f"incomplete vulnerability proof from {assessment.expert.value}"
                    )
                    missing_requirements.extend(missing)
            elif assessment.verdict is ExpertVerdict.SAFE and not _safe_proof_complete(
                assessment, candidate
            ):
                reasons.append(f"weak SAFE evidence from {assessment.expert.value}")

        escalated = bool(reasons)
        return EscalationDecision(
            candidate_id=candidate.candidate_id,
            escalated=escalated,
            initial_experts=initial,
            remaining_experts=(
                [expert for expert in route.ranked_experts if expert not in initial]
                if escalated
                else []
            ),
            reasons=reasons,
            missing_requirements=sorted(set(missing_requirements)),
        )


def _vulnerability_proof_complete(
    assessment: ExpertAssessment, candidate: Candidate
) -> tuple[bool, list[str]]:
    missing: list[str] = []
    evidence_by_id = {item.evidence_id: item for item in candidate.evidence}
    if not assessment.cwes:
        missing.append("cwe")
    if not assessment.evidence_ids:
        missing.append("evidence_ids")
    cited = [
        evidence_by_id[evidence_id]
        for evidence_id in assessment.evidence_ids
        if evidence_id in evidence_by_id
    ]
    if len(cited) != len(assessment.evidence_ids):
        missing.append("valid_evidence_attribution")
    if assessment.cwes and cited and not cwes_supported_by_evidence(assessment.cwes, cited):
        missing.append("cwe_supported_by_evidence")
    if not assessment.preconditions:
        missing.append("preconditions")
    if assessment.expert is ExpertFamily.TAINT_API_CONTRACT:
        if not assessment.source:
            missing.append("source")
        if not assessment.sink:
            missing.append("sink")
    elif assessment.expert is ExpertFamily.INTEGER_SIZE_TYPE and not assessment.sink:
        missing.append("security_sensitive_sink")
    elif assessment.expert is ExpertFamily.CONCURRENCY_TOCTOU and not assessment.preconditions:
        missing.append("interleaving_preconditions")
    return not missing, missing


def _safe_proof_complete(assessment: ExpertAssessment, candidate: Candidate) -> bool:
    evidence_by_id = {item.evidence_id: item for item in candidate.evidence}
    cited = [
        evidence_by_id[evidence_id]
        for evidence_id in assessment.counter_evidence_ids
        if evidence_id in evidence_by_id
    ]
    return (
        bool(cited)
        and len(cited) == len(assessment.counter_evidence_ids)
        and any(item.kind in PROTECTIVE_EVIDENCE_KINDS for item in cited)
    )
