from __future__ import annotations

import unittest

from llm_security.llm import LLMResponse
from llm_security.models import Candidate, Evidence, ExpertFamily, Finding, UsageRecord, ValidationVerdict
from llm_security.validation import EvidenceValidator


def finding(*, expert: ExpertFamily = ExpertFamily.MEMORY_BOUNDS, confidence: float = 0.8) -> Finding:
    return Finding(
        finding_id="F-1",
        candidate_id="C-1",
        expert=expert,
        title="candidate",
        root_cause="missing check",
        consequence="memory corruption",
        file="candidate.c",
        function="copy_value",
        line_start=10,
        line_end=10,
        cwes=["CWE-787"],
        source="input",
        sink="memcpy",
        missing_guard="length bound",
        trigger_path=["input", "memcpy"],
        evidence_ids=["E-1"],
        confidence=confidence,
    )


class CounterEvidenceFreeCritic:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, **kwargs) -> LLMResponse:
        self.calls += 1
        return LLMResponse(
            data={
                "verdict": "rejected",
                "confidence": 0.99,
                "reasons": ["looks safe"],
                "evidence_against": ["a check might exist"],
            },
            usage=UsageRecord(model=kwargs["model"]),
            raw={},
        )


class EvidenceValidatorFalsificationTest(unittest.TestCase):
    def test_unknown_expert_position_remains_reviewable(self) -> None:
        candidate = Candidate(
            candidate_id="C-1",
            project_id="project",
            file="candidate.c",
            function="copy_value",
            line_start=1,
            line_end=20,
            code="void copy_value(void) {}",
            evidence=[
                Evidence("E-1", "memory_sink", "candidate.c", 10, "memcpy(dst, src, len)", "copy_value"),
            ],
            features={},
        )
        item = finding()
        item.position = "unknown"

        result = EvidenceValidator(use_llm_for_uncertain=False).validate(item, candidate)

        self.assertEqual(ValidationVerdict.UNCERTAIN, result.verdict)

    def test_static_guard_rejection_keeps_location_bearing_counter_evidence(self) -> None:
        candidate = Candidate(
            candidate_id="C-1",
            project_id="project",
            file="candidate.c",
            function="copy_value",
            line_start=1,
            line_end=20,
            code="void copy_value(void) {}",
            evidence=[
                Evidence("E-1", "memory_sink", "candidate.c", 10, "memcpy(dst, src, len)", "copy_value"),
                Evidence(
                    "E-2",
                    "guard_protects_sink",
                    "candidate.c",
                    8,
                    "if (len <= sizeof(dst))",
                    "copy_value",
                    facts={"semantically_protective": True, "sink_line": 10},
                ),
            ],
            features={},
            feature_schema_version="semantic-cwe-v3",
        )

        item = finding()
        result = EvidenceValidator().validate(item, candidate)

        self.assertEqual(ValidationVerdict.REJECTED, result.verdict)
        self.assertEqual(["candidate.c:8: if (len <= sizeof(dst))"], item.evidence_against)

    def test_critic_cannot_reject_without_concrete_counter_evidence(self) -> None:
        candidate = Candidate(
            candidate_id="C-1",
            project_id="project",
            file="candidate.c",
            function="copy_value",
            line_start=1,
            line_end=20,
            code="void copy_value(void) {}",
            evidence=[
                Evidence("E-1", "memory_sink", "candidate.c", 10, "memcpy(dst, src, len)", "copy_value"),
            ],
            features={},
        )
        client = CounterEvidenceFreeCritic()

        results, _ = EvidenceValidator(
            minimum_confidence=0.9,
            client=client,
            model="test/model",
        ).validate_all([finding(confidence=0.2)], [candidate])

        self.assertEqual(1, client.calls)
        self.assertEqual(ValidationVerdict.UNCERTAIN, results[0].verdict)


if __name__ == "__main__":
    unittest.main()
