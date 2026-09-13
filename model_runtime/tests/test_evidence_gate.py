from __future__ import annotations

import unittest

from llm_security.acceptance import EvidenceGate
from llm_security.models import (
    Candidate,
    Evidence,
    ExpertAssessment,
    ExpertFamily,
    ExpertVerdict,
    RouteDecision,
    ValidationVerdict,
)


def candidate() -> Candidate:
    return Candidate(
        candidate_id="C-1",
        project_id="project",
        file="copy.c",
        function="copy",
        line_start=10,
        line_end=12,
        code="memcpy(dst, src, length);",
        evidence=[Evidence("E-1", "memory_sink", "copy.c", 11, "memcpy", "copy")],
        features={},
    )


def route() -> RouteDecision:
    return RouteDecision(
        candidate_id="C-1",
        scores={ExpertFamily.MEMORY_SAFETY: 1.0},
        selected=[ExpertFamily.MEMORY_SAFETY],
        top1_confidence=1.0,
        top1_top2_margin=1.0,
        policy="top1",
        reasons=[],
    )


def assessment(verdict: ExpertVerdict, *, evidence_ids: list[str] | None = None) -> ExpertAssessment:
    return ExpertAssessment(
        candidate_id="C-1",
        expert=ExpertFamily.MEMORY_SAFETY,
        verdict=verdict,
        cwes=["CWE-787"] if verdict is ExpertVerdict.VULNERABLE else [],
        evidence_ids=["E-1"] if evidence_ids is None else evidence_ids,
        counter_evidence_ids=[],
        source="src",
        sink="memcpy",
        missing_guard="length bound",
        trigger_path=["src", "memcpy"],
        preconditions=["length exceeds destination capacity"],
        title="Out-of-bounds copy",
        root_cause="Unchecked length",
        consequence="Memory corruption",
    )


class EvidenceGateTests(unittest.TestCase):
    def test_valid_vulnerable_assessment_becomes_a_validated_finding(self) -> None:
        findings, validations = EvidenceGate().process(
            [assessment(ExpertVerdict.VULNERABLE)], [candidate()], [route()]
        )

        self.assertEqual(1, len(findings))
        self.assertEqual(ValidationVerdict.VALIDATED, validations[0].verdict)

    def test_safe_and_uncertain_assessments_do_not_create_findings(self) -> None:
        findings, validations = EvidenceGate().process(
            [assessment(ExpertVerdict.SAFE), assessment(ExpertVerdict.UNCERTAIN)],
            [candidate()],
            [route()],
        )

        self.assertEqual([], findings)
        self.assertEqual([], validations)

    def test_unknown_evidence_id_is_rejected(self) -> None:
        findings, validations = EvidenceGate().process(
            [assessment(ExpertVerdict.VULNERABLE, evidence_ids=["invented"])],
            [candidate()],
            [route()],
        )

        self.assertEqual([], findings)
        self.assertEqual(ValidationVerdict.REJECTED, validations[0].verdict)
        self.assertFalse(validations[0].checks["evidence_ids_valid"])

    def test_cwe_outside_the_routed_expert_domain_is_rejected(self) -> None:
        item = assessment(ExpertVerdict.VULNERABLE)
        item.cwes = ["CWE-190"]
        findings, validations = EvidenceGate().process([item], [candidate()], [route()])

        self.assertEqual([], findings)
        self.assertEqual(ValidationVerdict.REJECTED, validations[0].verdict)
        self.assertFalse(validations[0].checks["cwe_domain_valid"])


if __name__ == "__main__":
    unittest.main()
