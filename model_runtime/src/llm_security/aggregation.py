from __future__ import annotations

from collections import defaultdict
import hashlib

from .cwe import causal_cwe_family
from .models import Candidate, EvidenceBundle, ExpertEvidence, ExpertFamily, Finding


class EvidenceAggregator:
    """Fuse Expert observations without assigning a probability or verdict."""

    def aggregate(
        self,
        evidence: list[ExpertEvidence],
        candidates: list[Candidate] | dict[str, Candidate],
    ) -> list[EvidenceBundle]:
        candidate_by_id = (
            candidates
            if isinstance(candidates, dict)
            else {item.candidate_id: item for item in candidates}
        )
        buckets: dict[tuple[str, str], list[ExpertEvidence]] = defaultdict(list)
        for item in evidence:
            if item.position == "oppose" or item.candidate_id not in candidate_by_id:
                continue
            buckets[(item.candidate_id, item.vulnerability_family)].append(item)

        bundles: list[EvidenceBundle] = []
        for (candidate_id, family), bucket in buckets.items():
            candidate = candidate_by_id[candidate_id]
            for group in self._groups(bucket):
                bundles.append(self._fuse(candidate, family, group))
        bundles.sort(
            key=lambda item: (
                item.candidate_id,
                item.vulnerability_family,
                item.bundle_id,
            )
        )
        return bundles

    @staticmethod
    def _groups(bucket: list[ExpertEvidence]) -> list[list[ExpertEvidence]]:
        groups: list[list[ExpertEvidence]] = []
        for item in bucket:
            for group in groups:
                representative = group[0]
                same_sink = bool(
                    item.sink
                    and representative.sink
                    and _normalize(item.sink) == _normalize(representative.sink)
                )
                shared = bool(set(item.evidence_ids) & set(representative.evidence_ids))
                # Missing sink data is common for partial observations.  It may
                # join only when evidence overlaps, preventing unrelated flaws in
                # one candidate from collapsing into a single bundle.
                if same_sink or shared:
                    group.append(item)
                    break
            else:
                groups.append([item])
        return groups

    @staticmethod
    def _fuse(
        candidate: Candidate,
        family: str,
        group: list[ExpertEvidence],
    ) -> EvidenceBundle:
        evidence_ids = sorted(
            {evidence_id for item in group for evidence_id in item.evidence_ids}
        )
        support = [item for item in group if item.position == "support"]
        unknown = [item for item in group if item.position != "support"]
        identity = "|".join(
            [candidate.candidate_id, family, *evidence_ids, *sorted(item.sink or "" for item in group)]
        )
        bundle_id = "B-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
        return EvidenceBundle(
            bundle_id=bundle_id,
            candidate_id=candidate.candidate_id,
            file=candidate.file,
            function=candidate.function,
            line_start=candidate.line_start,
            line_end=candidate.line_end,
            vulnerability_family=family,
            cwes=sorted({cwe for item in group for cwe in item.cwes}),
            evidence_ids=evidence_ids,
            supporting_experts=sorted(
                {item.expert for item in support}, key=lambda item: item.value
            ),
            unknown_experts=sorted(
                {item.expert for item in unknown}, key=lambda item: item.value
            ),
            sources=list(dict.fromkeys(item.source for item in group if item.source)),
            sinks=list(dict.fromkeys(item.sink for item in group if item.sink)),
            trigger_paths=[item.trigger_path for item in group if item.trigger_path],
            preconditions=list(
                dict.fromkeys(value for item in group for value in item.preconditions)
            ),
            expert_confidences=[
                item.self_confidence
                for item in group
                if item.self_confidence is not None
            ],
            model_ids=sorted({item.model_id for item in group if item.model_id}),
            support_count=len(support),
            unknown_count=len(unknown),
            total_evidence_references=sum(len(item.evidence_ids) for item in group),
        )


def expert_evidence_from_finding(finding: Finding) -> ExpertEvidence:
    """Compatibility adapter for stored results and third-party Expert runners."""

    families = {causal_cwe_family(cwe) for cwe in finding.cwes if cwe}
    family = (
        next(iter(families))
        if len(families) == 1
        else "mixed:" + ",".join(sorted(families))
        if families
        else f"unclassified:{finding.expert.value}"
    )
    return ExpertEvidence(
        candidate_id=finding.candidate_id,
        expert=finding.expert,
        position=finding.position,
        vulnerability_family=family,
        cwes=list(finding.cwes),
        evidence_ids=list(finding.evidence_ids),
        source=finding.source,
        sink=finding.sink,
        trigger_path=list(finding.trigger_path),
        preconditions=list(finding.preconditions),
        self_confidence=finding.confidence,
        model_id=finding.model_id,
        prompt_version=finding.prompt_version,
    )


class FindingAggregator:
    """Fuse causal findings across Expert families and model providers."""

    def aggregate(self, findings: list[Finding]) -> list[Finding]:
        buckets: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
        for finding in findings:
            # An Expert may explicitly oppose its own tentative hypothesis. It
            # contributes no positive security finding; concrete counter-evidence
            # remains the Validator's responsibility.
            if finding.position == "oppose":
                continue
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
        # This is an evidence merge, not a trained/calibrated probability model.
        # Keep the strongest Expert's bounded confidence for transparency but do
        # not fabricate agreement weights or probability calibration.
        primary.confidence = max(item.confidence for item in group)
        primary.position = (
            "support" if any(item.position == "support" for item in group) else "unknown"
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
