from __future__ import annotations

import hashlib

from ..models import Evidence
from .semantic_analyzer import SemanticFunctionAnalysis


class SemanticEvidenceNormalizer:
    def normalize(
        self, analysis: SemanticFunctionAnalysis
    ) -> list[Evidence]:
        structural = analysis.structural
        cfg = structural.cfg
        evidence: list[Evidence] = []
        for fact in analysis.facts:
            source_node = cfg.nodes.get(fact.source_node_id or "")
            sink_node = cfg.nodes.get(fact.sink_node_id or "")
            representative = sink_node or source_node
            source_line = source_node.span.line_start if source_node and source_node.span else None
            sink_line = sink_node.span.line_start if sink_node and sink_node.span else None
            line = sink_line or source_line or structural.function.line_start
            expression = representative.text if representative is not None else fact.kind.value
            facts = {
                **fact.attributes,
                "semantic_fact_id": fact.fact_id,
                "confidence": fact.confidence,
                "source_node_id": fact.source_node_id,
                "sink_node_id": fact.sink_node_id,
                "path": list(fact.path),
                "source_line": source_line,
                "sink_line": sink_line,
            }
            digest = hashlib.sha1(
                f"{fact.fact_id}:{structural.function.file}:{line}:{expression}".encode("utf-8")
            ).hexdigest()[:16]
            evidence.append(
                Evidence(
                    evidence_id=f"EV-{digest}",
                    kind=fact.kind.value,
                    file=structural.function.file,
                    line=line,
                    expression=expression,
                    function=structural.function.name,
                    subject=fact.subject,
                    object=fact.object,
                    facts=facts,
                )
            )

        function = structural.function
        for access in function.memory_accesses:
            digest = hashlib.sha1(
                (
                    f"{access.access_id}:{function.file}:"
                    f"{access.span.line_start}:{access.text}"
                ).encode("utf-8")
            ).hexdigest()[:16]
            evidence.append(
                Evidence(
                    evidence_id=f"EV-{digest}",
                    kind="memory_access",
                    file=function.file,
                    line=access.span.line_start,
                    expression=access.text,
                    function=function.name,
                    subject=access.base,
                    object=access.index,
                    facts={
                        "access_id": access.access_id,
                        "access_kind": access.kind,
                        "base": access.base,
                        "index": access.index,
                        "base_symbols": sorted(access.base_symbols),
                        "index_symbols": sorted(access.index_symbols),
                        "confidence": 1.0,
                    },
                )
            )

        unique = {item.evidence_id: item for item in evidence}
        return sorted(
            unique.values(),
            key=lambda item: (item.line, item.kind, item.evidence_id),
        )
