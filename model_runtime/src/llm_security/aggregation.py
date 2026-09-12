from __future__ import annotations

import hashlib
from collections import defaultdict

from .models import Candidate, EvidenceBundle, ExpertEvidence


class EvidenceAggregator:
    """Fuse Expert observations without assigning probability or verdict."""

    def aggregate(
        self,
        evidence: list[ExpertEvidence],
        candidates: list[Candidate] | dict[str, Candidate],
    ) -> list[EvidenceBundle]:
        candidate_by_id = (
            candidates
            if isinstance(candidates, dict)
            else {candidate.candidate_id: candidate for candidate in candidates}
        )
        buckets: dict[tuple[str, str, tuple[str, ...]], list[ExpertEvidence]] = (
            defaultdict(list)
        )
        for item in evidence:
            if item.position == "oppose" or item.candidate_id not in candidate_by_id:
                continue
            # Exact CWE hypotheses are output identities. Different CWEs must
            # remain separate even in the same function and at the same sink.
            key = (
                item.candidate_id,
                item.vulnerability_family,
                tuple(sorted(set(item.cwes))),
            )
            buckets[key].append(item)

        bundles: list[EvidenceBundle] = []
        for (candidate_id, family, _), bucket in buckets.items():
            candidate = candidate_by_id[candidate_id]
            bundles.extend(
                self._fuse(candidate, family, group)
                for group in self._groups(bucket)
            )
        return sorted(
            bundles,
            key=lambda bundle: (
                bundle.candidate_id,
                bundle.vulnerability_family,
                bundle.bundle_id,
            ),
        )

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
                shared_evidence = bool(
                    set(item.evidence_ids) & set(representative.evidence_ids)
                )
                if same_sink or shared_evidence:
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
        cwes = sorted({cwe for item in group for cwe in item.cwes})
        support = [item for item in group if item.position == "support"]
        unknown = [item for item in group if item.position != "support"]
        identity = "|".join(
            [
                candidate.candidate_id,
                family,
                *cwes,
                *evidence_ids,
                *sorted(item.sink or "" for item in group),
            ]
        )
        return EvidenceBundle(
            bundle_id="B-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16],
            candidate_id=candidate.candidate_id,
            file=candidate.file,
            function=candidate.function,
            line_start=candidate.line_start,
            line_end=candidate.line_end,
            vulnerability_family=family,
            cwes=cwes,
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


def _normalize(value: str) -> str:
    return "".join(
        character.lower()
        for character in value
        if character.isalnum() or character == "_"
    )
