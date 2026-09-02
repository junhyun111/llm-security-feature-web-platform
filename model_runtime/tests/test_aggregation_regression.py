from __future__ import annotations

import unittest

from llm_security.aggregation import FindingAggregator
from llm_security.models import ExpertFamily, Finding
from llm_security.prompts import finding_payload_schema


def finding(
    finding_id: str,
    *,
    cwes: list[str],
    line_start: int,
    line_end: int | None = None,
    sink: str,
    evidence_ids: list[str],
    confidence: float,
    expert: ExpertFamily = ExpertFamily.MEMORY_BOUNDS,
) -> Finding:
    return Finding(
        finding_id=finding_id,
        candidate_id="C-ProcessImage",
        expert=expert,
        title=finding_id,
        root_cause=f"root cause for {finding_id}",
        consequence=f"consequence for {finding_id}",
        file="dvcp.c",
        function="ProcessImage",
        line_start=line_start,
        line_end=line_start if line_end is None else line_end,
        cwes=cwes,
        source="img",
        sink=sink,
        missing_guard=None,
        trigger_path=["ProcessImage", sink],
        evidence_ids=evidence_ids,
        confidence=confidence,
        evidence_against=["legacy expert counter-evidence"],
        supporting_experts=[expert],
    )


class DamnVulnerableCProgramAggregationRegression(unittest.TestCase):
    """Regression for the multi-vulnerability ProcessImage-style candidate."""

    def test_distinct_vulnerability_families_remain_independent(self) -> None:
        findings = [
            finding(
                "division-by-zero",
                cwes=["CWE-369"],
                line_start=57,
                sink="size1 / img.height",
                evidence_ids=["E-DIV"],
                confidence=0.99,
                expert=ExpertFamily.INTEGER_SIZE_TYPE,
            ),
            finding(
                "integer-overflow",
                cwes=["CWE-190"],
                line_start=48,
                sink="malloc(size1)",
                evidence_ids=["E-INT"],
                confidence=0.96,
                expert=ExpertFamily.INTEGER_SIZE_TYPE,
            ),
            finding(
                "double-free",
                cwes=["CWE-415"],
                line_start=61,
                sink="free(buff1)",
                evidence_ids=["E-DOUBLE-FREE"],
                confidence=0.95,
            ),
            finding(
                "use-after-free",
                cwes=["CWE-416"],
                line_start=65,
                sink="buff1[0]",
                evidence_ids=["E-UAF"],
                confidence=0.94,
            ),
            finding(
                "out-of-bounds-write",
                cwes=["CWE-787"],
                line_start=72,
                sink="buff2[img.width]",
                evidence_ids=["E-OOB-WRITE"],
                confidence=0.93,
            ),
        ]

        result = FindingAggregator().aggregate(findings)

        self.assertEqual(5, len(result))
        division = next(item for item in result if item.finding_id == "division-by-zero")
        self.assertEqual(["CWE-369"], division.cwes)
        self.assertEqual((57, 57), (division.line_start, division.line_end))
        self.assertNotIn("CWE-415", division.cwes)
        self.assertNotIn("CWE-416", division.cwes)
        self.assertLess(len(division.cwes), 10)

    def test_transitive_neighbors_do_not_form_one_large_cluster(self) -> None:
        findings = [
            finding(
                "A",
                cwes=["CWE-787"],
                line_start=10,
                sink="sink_a",
                evidence_ids=["E-A", "E-AB"],
                confidence=0.99,
            ),
            finding(
                "B",
                cwes=["CWE-125"],
                line_start=12,
                sink="sink_b",
                evidence_ids=["E-AB", "E-BC"],
                confidence=0.98,
            ),
            finding(
                "C",
                cwes=["CWE-120"],
                line_start=14,
                sink="sink_c",
                evidence_ids=["E-BC", "E-C"],
                confidence=0.97,
            ),
        ]

        result = FindingAggregator().aggregate(findings)

        self.assertEqual(2, len(result))

    def test_same_family_requires_local_overlap_and_causal_evidence(self) -> None:
        findings = [
            finding(
                "bounds-read",
                cwes=["CWE-125"],
                line_start=70,
                line_end=72,
                sink="buffer[index]",
                evidence_ids=["E-INDEX", "E-SINK"],
                confidence=0.9,
            ),
            finding(
                "bounds-write",
                cwes=["CWE-787"],
                line_start=71,
                line_end=72,
                sink="buffer[index]",
                evidence_ids=["E-SINK"],
                confidence=0.85,
            ),
        ]

        result = FindingAggregator().aggregate(findings)

        self.assertEqual(1, len(result))
        self.assertEqual(["CWE-125", "CWE-787"], result[0].cwes)
        self.assertEqual((71, 72), (result[0].line_start, result[0].line_end))
        self.assertEqual([], result[0].evidence_against)

    def test_expert_schema_does_not_accept_evidence_against(self) -> None:
        schema = finding_payload_schema()
        self.assertNotIn("evidence_against", schema["properties"])
        self.assertNotIn("evidence_against", schema["required"])


if __name__ == "__main__":
    unittest.main()
