from __future__ import annotations

from collections import defaultdict

from .cwe import causal_cwe_family
from .models import Finding


class FindingAggregator:
    """Fuse causal findings across Expert families and model providers."""

    def aggregate(self, findings: list[Finding]) -> list[Finding]:
        buckets: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
        for finding in findings:
            buckets[(finding.candidate_id, finding.file, finding.function)].append(finding)

        aggregated: list[Finding] = []
        for bucket in buckets.values():
            aggregated.extend(self._aggregate_bucket(bucket))
        aggregated.sort(key=lambda item: (-item.confidence, item.file, item.line_start))
        return aggregated

    def _aggregate_bucket(self, findings: list[Finding]) -> list[Finding]:
        ordered = sorted(findings, key=lambda item: item.confidence, reverse=True)
        groups: list[list[Finding]] = []

        for finding in ordered:
            for group in groups:
                # Compare with the strongest representative only. This deliberately
                # prevents A<->B and B<->C from transitively merging A+B+C.
                if _causally_related(group[0], finding):
                    group.append(finding)
                    break
            else:
                groups.append([finding])

        return [self._fuse(group) for group in groups]

    @staticmethod
    def _fuse(group: list[Finding]) -> Finding:
        primary = max(group, key=lambda item: item.confidence)
        experts = {
            expert
            for item in group
            for expert in (item.supporting_experts or [item.expert])
        }
        models = {
            model
            for item in group
            for model in (
                item.supporting_models
                or ([item.model_id] if item.model_id else [])
            )
        }
        primary_family = _vulnerability_family(primary)
        compatible_cwes = {
            cwe
            for item in group
            for cwe in item.cwes
            if _cwe_family(cwe) == primary_family
        }
        if compatible_cwes:
            primary.cwes = sorted(compatible_cwes)
        primary.evidence_ids = sorted(
            {evidence_id for item in group for evidence_id in item.evidence_ids}
        )
        primary.evidence_for = list(
            dict.fromkeys(value for item in group for value in item.evidence_for)
        )
        # Counter-evidence belongs to the Validator/Falsification Critic. Discard
        # legacy Expert-authored values before final validation.
        primary.evidence_against = []
        primary.preconditions = list(
            dict.fromkeys(value for item in group for value in item.preconditions)
        )
        primary.trigger_path = list(
            dict.fromkeys(node for item in group for node in item.trigger_path)
        )
        primary.supporting_experts = sorted(experts, key=lambda item: item.value)
        primary.supporting_models = sorted(models)
        agreement_bonus = 0.03 * max(0, len(experts) - 1)
        diversity_bonus = 0.02 * max(0, len(models) - 1)
        primary.confidence = min(
            1.0,
            max(item.confidence for item in group) + agreement_bonus + diversity_bonus,
        )
        intersection_start = max(item.line_start for item in group)
        intersection_end = min(item.line_end for item in group)
        if intersection_start <= intersection_end:
            primary.line_start = intersection_start
            primary.line_end = intersection_end
        return primary


def _causally_related(left: Finding, right: Finding) -> bool:
    if _vulnerability_family(left) != _vulnerability_family(right):
        return False

    overlap = (
        left.line_start <= right.line_end + 2
        and right.line_start <= left.line_end + 2
    )
    same_sink = bool(
        left.sink
        and right.sink
        and _normalize(left.sink) == _normalize(right.sink)
    )
    left_evidence = set(left.evidence_ids)
    right_evidence = set(right.evidence_ids)
    shared_evidence = left_evidence & right_evidence
    evidence_overlap = len(shared_evidence) / max(
        1,
        min(len(left_evidence), len(right_evidence)),
    )
    return overlap and (same_sink or evidence_overlap >= 0.5)


def _vulnerability_family(finding: Finding) -> str:
    families = {_cwe_family(cwe) for cwe in finding.cwes if cwe}
    if len(families) == 1:
        return next(iter(families))
    if families:
        # Mixed-family reports are suspicious. They may merge only with a report
        # carrying the exact same family set, never with one of their components.
        return "mixed:" + ",".join(sorted(families))
    title = _normalize(finding.title)
    return f"unclassified:{title or finding.finding_id}"


def _cwe_family(cwe: str) -> str:
    return causal_cwe_family(cwe)


def _normalize(value: str) -> str:
    return "".join(
        character.lower()
        for character in value
        if character.isalnum() or character == "_"
    )
