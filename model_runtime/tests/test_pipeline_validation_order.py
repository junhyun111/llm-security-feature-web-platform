from __future__ import annotations

import unittest
from types import SimpleNamespace

from llm_security.aggregation import FindingAggregator
from llm_security.models import (
    Candidate,
    Evidence,
    ExpertFamily,
    Finding,
    ProjectCase,
    ValidationVerdict,
)
from llm_security.pipeline import VulnerabilityPipeline
from llm_security.validation import EvidenceValidator


class Analyzer:
    def __init__(self, candidate: Candidate) -> None:
        self.candidate = candidate

    def analyze(self, _case: ProjectCase) -> list[Candidate]:
        return [self.candidate]


class Router:
    def route(self, candidate: Candidate) -> SimpleNamespace:
        return SimpleNamespace(candidate_id=candidate.candidate_id)


class ExpertRunner:
    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings

    def run(self, _candidates, _routes) -> SimpleNamespace:
        return SimpleNamespace(
            findings=self.findings,
            usage=[],
            errors=[],
            task_count=len(self.findings),
            submitted_task_count=len(self.findings),
            skipped_task_count=0,
        )


def make_finding(finding_id: str, *, file: str, confidence: float) -> Finding:
    return Finding(
        finding_id=finding_id,
        candidate_id="C-1",
        expert=ExpertFamily.INTEGER_SIZE_TYPE,
        title=finding_id,
        root_cause="unchecked arithmetic",
        consequence="unsafe allocation size",
        file=file,
        function="ProcessImage",
        line_start=10,
        line_end=10,
        cwes=["CWE-190"],
        source="img.width",
        sink="malloc(size1)",
        missing_guard="overflow check",
        trigger_path=["img.width", "size1", "malloc"],
        evidence_ids=["E-1"],
        confidence=confidence,
        evidence_against=["Expert must not own this field"],
    )


class PipelineValidationOrderTest(unittest.TestCase):
    def test_structural_rejection_happens_before_aggregation(self) -> None:
        candidate = Candidate(
            candidate_id="C-1",
            project_id="dvcp",
            file="dvcp.c",
            function="ProcessImage",
            line_start=1,
            line_end=100,
            code="int ProcessImage(void) { return 0; }",
            evidence=[
                Evidence(
                    evidence_id="E-1",
                    kind="integer_arithmetic",
                    file="dvcp.c",
                    line=10,
                    expression="size1 = width + height",
                    function="ProcessImage",
                )
            ],
            features={},
            suspicion_score=0.9,
        )
        invalid_high_confidence = make_finding(
            "invalid-file",
            file="wrong.c",
            confidence=1.0,
        )
        valid = make_finding("valid", file="dvcp.c", confidence=0.8)
        oversized_cwe_scope = make_finding(
            "too-many-cwes",
            file="dvcp.c",
            confidence=0.9,
        )
        oversized_cwe_scope.cwes = [
            "CWE-120",
            "CWE-125",
            "CWE-190",
            "CWE-369",
            "CWE-415",
            "CWE-416",
            "CWE-476",
            "CWE-787",
            "CWE-252",
            "CWE-367",
        ]
        mixed_cwe_scope = make_finding(
            "mixed-cwe-families",
            file="dvcp.c",
            confidence=0.85,
        )
        mixed_cwe_scope.cwes = ["CWE-369", "CWE-190"]
        pipeline = VulnerabilityPipeline(
            analyzer=Analyzer(candidate),
            router=Router(),
            expert_runner=ExpertRunner(
                [
                    invalid_high_confidence,
                    oversized_cwe_scope,
                    mixed_cwe_scope,
                    valid,
                ]
            ),
            aggregator=FindingAggregator(),
            validator=EvidenceValidator(minimum_confidence=0.5),
        )

        result = pipeline.run(
            ProjectCase(
                case_id="dvcp-regression",
                project_id="dvcp",
                source_files={"dvcp.c": candidate.code},
            )
        )

        self.assertEqual(["valid"], [item.finding_id for item in result.findings])
        self.assertEqual(4, len(result.structural_validations))
        rejected = next(
            item
            for item in result.structural_validations
            if item.finding_id == "invalid-file"
        )
        self.assertEqual(ValidationVerdict.REJECTED, rejected.verdict)
        self.assertFalse(rejected.checks["file_matches"])
        self.assertIsNone(rejected.confidence)
        cwe_rejected = next(
            item
            for item in result.structural_validations
            if item.finding_id == "too-many-cwes"
        )
        self.assertEqual(ValidationVerdict.REJECTED, cwe_rejected.verdict)
        self.assertFalse(cwe_rejected.checks["cwe_scope_bounded"])
        self.assertFalse(cwe_rejected.checks["cwe_family_coherent"])
        mixed_rejected = next(
            item
            for item in result.structural_validations
            if item.finding_id == "mixed-cwe-families"
        )
        self.assertTrue(mixed_rejected.checks["cwe_scope_bounded"])
        self.assertFalse(mixed_rejected.checks["cwe_family_coherent"])
        self.assertEqual(ValidationVerdict.VALIDATED, result.validations[0].verdict)
        self.assertIsNone(result.validations[0].confidence)
        self.assertEqual([], result.findings[0].evidence_against)


if __name__ == "__main__":
    unittest.main()
