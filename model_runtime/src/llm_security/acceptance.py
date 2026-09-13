from __future__ import annotations

import hashlib
from collections import defaultdict

from .cwe import cwes_supported_by_evidence
from .models import (
    Candidate,
    ExpertAssessment,
    ExpertVerdict,
    Finding,
    RouteDecision,
    ValidationResult,
    ValidationVerdict,
)


class EvidenceGate:
    """Accept only attributed Expert vulnerability claims.

    The gate validates provenance and domain consistency; it deliberately does
    not make a second vulnerability judgement or use LLM confidence as policy.
    """

    def process(
        self,
        assessments: list[ExpertAssessment],
        candidates: list[Candidate],
        routes: list[RouteDecision],
    ) -> tuple[list[Finding], list[ValidationResult]]:
        candidates_by_id = {candidate.candidate_id: candidate for candidate in candidates}
        routes_by_id = {route.candidate_id: route for route in routes}
        findings: list[Finding] = []
        validations: list[ValidationResult] = []

        for assessment in assessments:
            if assessment.verdict is not ExpertVerdict.VULNERABLE:
                continue
            candidate = candidates_by_id.get(assessment.candidate_id)
            route = routes_by_id.get(assessment.candidate_id)
            finding = self._finding(assessment, candidate)
            validation = self.evaluate(assessment, candidate, route, finding.finding_id)
            validations.append(validation)
            if validation.verdict is ValidationVerdict.VALIDATED:
                findings.append(finding)
        return self._deduplicate(findings), validations

    def evaluate(
        self,
        assessment: ExpertAssessment,
        candidate: Candidate | None,
        route: RouteDecision | None,
        finding_id: str,
    ) -> ValidationResult:
        evidence_by_id = {item.evidence_id: item for item in candidate.evidence} if candidate else {}
        evidence_ids = set(evidence_by_id)
        cited_evidence = [
            evidence_by_id[evidence_id]
            for evidence_id in assessment.evidence_ids
            if evidence_id in evidence_by_id
        ]
        checks: dict[str, bool | None] = {
            "candidate_attribution_valid": candidate is not None,
            # ``selected`` records the initial Top-2.  A ranked Expert can also
            # be executed in the evidence-driven escalation pass, so use the
            # full ranked execution pool when it is available.
            "expert_route_valid": route is not None and assessment.expert in (
                route.ranked_experts or route.selected
            ),
            "cwe_present": bool(assessment.cwes),
            "cwe_evidence_supported": bool(assessment.cwes)
            and bool(cited_evidence)
            and cwes_supported_by_evidence(assessment.cwes, cited_evidence),
            "evidence_ids_valid": bool(assessment.evidence_ids)
            and set(assessment.evidence_ids).issubset(evidence_ids),
            "counter_evidence_ids_valid": set(assessment.counter_evidence_ids).issubset(
                evidence_ids
            ),
        }
        failed = [name for name, passed in checks.items() if passed is False]
        return ValidationResult(
            finding_id=finding_id,
            verdict=(
                ValidationVerdict.VALIDATED
                if not failed
                else ValidationVerdict.REJECTED
            ),
            confidence=None,
            checks=checks,
            reasons=(
                ["Expert claim is attributed to valid routed static evidence."]
                if not failed
                else ["Evidence gate rejected: " + ", ".join(failed)]
            ),
        )

    @staticmethod
    def _finding(assessment: ExpertAssessment, candidate: Candidate | None) -> Finding:
        if candidate is None:
            file, function, line_start, line_end = "", "", 0, 0
        else:
            file = candidate.file
            function = candidate.function
            line_start = candidate.line_start
            line_end = candidate.line_end
        identity = "|".join(
            [assessment.candidate_id, assessment.expert.value, *sorted(assessment.cwes), assessment.sink or ""]
        )
        return Finding(
            finding_id="F-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
            candidate_id=assessment.candidate_id,
            expert=assessment.expert,
            title=assessment.title,
            root_cause=assessment.root_cause,
            consequence=assessment.consequence,
            file=file,
            function=function,
            line_start=line_start,
            line_end=line_end,
            cwes=assessment.cwes,
            source=assessment.source,
            sink=assessment.sink,
            missing_guard=assessment.missing_guard,
            trigger_path=assessment.trigger_path,
            evidence_ids=assessment.evidence_ids,
            confidence=assessment.confidence,
            preconditions=assessment.preconditions,
            evidence_for=assessment.evidence_ids,
            evidence_against=assessment.counter_evidence_ids,
            model_id=assessment.model_id,
            prompt_version=assessment.prompt_version,
            supporting_experts=[assessment.expert],
            supporting_models=[assessment.model_id] if assessment.model_id else [],
        )

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        groups: dict[tuple[str, tuple[str, ...], str], list[Finding]] = defaultdict(list)
        for finding in findings:
            groups[(finding.candidate_id, tuple(sorted(finding.cwes)), _normalize(finding.sink))].append(finding)
        merged: list[Finding] = []
        for group in groups.values():
            primary = group[0]
            primary.supporting_experts = sorted(
                {item.expert for item in group}, key=lambda item: item.value
            )
            primary.supporting_models = sorted(
                {model for item in group for model in item.supporting_models}
            )
            primary.evidence_ids = sorted(
                {evidence_id for item in group for evidence_id in item.evidence_ids}
            )
            primary.evidence_for = list(primary.evidence_ids)
            merged.append(primary)
        return sorted(merged, key=lambda item: (item.candidate_id, item.finding_id))


def _normalize(value: str | None) -> str:
    return "".join(character.lower() for character in value or "" if character.isalnum() or character == "_")
