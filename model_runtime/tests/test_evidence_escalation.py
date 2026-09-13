from __future__ import annotations

import unittest
from types import SimpleNamespace

from llm_security.escalation import EvidenceEscalationPolicy
from llm_security.experts import ExpertRunOutput
from llm_security.models import (
    ACTIVE_UTILITY_EXPERTS,
    Candidate,
    Evidence,
    ExpertAssessment,
    ExpertFamily,
    ExpertVerdict,
    ProjectCase,
    RouteDecision,
)
from llm_security.pipeline import VulnerabilityPipeline
from llm_security.selection import CandidateSelector


def candidate() -> Candidate:
    return Candidate(
        "C-1", "project", "copy.c", "copy", 10, 12, "memcpy(dst, src, n);",
        [
            Evidence("E-memory", "memory_sink", "copy.c", 11, "memcpy", "copy"),
            Evidence("E-guard", "state", "copy.c", 10, "n <= sizeof(dst)", "copy"),
        ],
        {},
    )


def route() -> RouteDecision:
    experts = list(ACTIVE_UTILITY_EXPERTS)
    return RouteDecision(
        candidate_id="C-1",
        scores={expert: 0.5 for expert in experts},
        selected=experts[:2],
        top1_confidence=0.5,
        top1_top2_margin=0.1,
        policy="utility_top2",
        reasons=[],
        ranked_experts=experts,
        top2_experts=experts[:2],
    )


def assessment(
    expert: ExpertFamily,
    verdict: ExpertVerdict,
    *,
    cwes: list[str] | None = None,
    evidence_ids: list[str] | None = None,
    counter_evidence_ids: list[str] | None = None,
    preconditions: list[str] | None = None,
) -> ExpertAssessment:
    return ExpertAssessment(
        candidate_id="C-1",
        expert=expert,
        verdict=verdict,
        cwes=cwes or [],
        evidence_ids=evidence_ids or [],
        counter_evidence_ids=counter_evidence_ids or [],
        source="input",
        sink="memcpy",
        missing_guard=None,
        trigger_path=["input", "memcpy"],
        preconditions=preconditions or [],
        title="assessment",
        root_cause="reason",
        consequence="impact",
    )


class EvidenceEscalationPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = EvidenceEscalationPolicy()
        self.candidate = candidate()
        self.route = route()

    def test_complete_vulnerability_and_attributed_safe_result_stay_top2(self) -> None:
        decision = self.policy.decide(
            candidate=self.candidate,
            route=self.route,
            assessments=[
                assessment(
                    ExpertFamily.MEMORY_SAFETY,
                    ExpertVerdict.VULNERABLE,
                    cwes=["CWE-787"],
                    evidence_ids=["E-memory"],
                    preconditions=["n exceeds destination capacity"],
                ),
                assessment(
                    ExpertFamily.INTEGER_SIZE_TYPE,
                    ExpertVerdict.SAFE,
                    counter_evidence_ids=["E-guard"],
                ),
            ],
        )

        self.assertFalse(decision.escalated)
        self.assertEqual([], decision.remaining_experts)

    def test_uncertain_or_missing_initial_result_escalates_to_remaining_three(self) -> None:
        decision = self.policy.decide(
            candidate=self.candidate,
            route=self.route,
            assessments=[
                assessment(ExpertFamily.MEMORY_SAFETY, ExpertVerdict.UNCERTAIN),
            ],
        )

        self.assertTrue(decision.escalated)
        self.assertEqual(list(ACTIVE_UTILITY_EXPERTS)[2:], decision.remaining_experts)
        self.assertTrue(any("UNCERTAIN" in reason for reason in decision.reasons))
        self.assertTrue(any("missing result" in reason for reason in decision.reasons))

    def test_incomplete_vulnerability_and_weak_safe_result_escalate(self) -> None:
        decision = self.policy.decide(
            candidate=self.candidate,
            route=self.route,
            assessments=[
                assessment(
                    ExpertFamily.MEMORY_SAFETY,
                    ExpertVerdict.VULNERABLE,
                    cwes=["CWE-787"],
                    evidence_ids=["E-memory"],
                ),
                assessment(ExpertFamily.INTEGER_SIZE_TYPE, ExpertVerdict.SAFE),
            ],
        )

        self.assertTrue(decision.escalated)
        self.assertIn("preconditions", decision.missing_requirements)
        self.assertTrue(any("weak SAFE" in reason for reason in decision.reasons))


class _PhasedRunner:
    def __init__(self, initial: list[ExpertAssessment], escalation: list[ExpertAssessment]) -> None:
        self.initial = initial
        self.escalation = escalation
        self.calls: list[tuple[str, dict[str, list[ExpertFamily]]]] = []

    def run_experts(self, candidates, experts_by_candidate, *, phase: str) -> ExpertRunOutput:
        self.calls.append((phase, experts_by_candidate))
        available = {
            (candidate_id, expert)
            for candidate_id, experts in experts_by_candidate.items()
            for expert in experts
        }
        responses = self.initial if phase == "initial" else self.escalation
        assessments = [
            item for item in responses if (item.candidate_id, item.expert) in available
        ]
        task_count = sum(len(experts) for experts in experts_by_candidate.values())
        return ExpertRunOutput(
            assessments=assessments,
            usage=[],
            errors=[],
            task_count=task_count,
            submitted_task_count=task_count,
            completed_task_count=len(assessments),
            covered_candidate_count=len({item.candidate_id for item in assessments}),
        )


class EvidenceEscalationPipelineTests(unittest.TestCase):
    def test_pipeline_runs_remaining_three_only_after_initial_evidence_requests_it(self) -> None:
        item = candidate()
        runner = _PhasedRunner(
            initial=[
                assessment(
                    ExpertFamily.MEMORY_SAFETY,
                    ExpertVerdict.SAFE,
                    counter_evidence_ids=["E-guard"],
                ),
                assessment(ExpertFamily.INTEGER_SIZE_TYPE, ExpertVerdict.UNCERTAIN),
            ],
            escalation=[
                assessment(
                    ExpertFamily.CONTROL_STATE_ERROR,
                    ExpertVerdict.VULNERABLE,
                    cwes=["CWE-703"],
                    evidence_ids=["E-guard"],
                    preconditions=["error result is ignored"],
                ),
            ],
        )
        pipeline = VulnerabilityPipeline(
            analyzer=SimpleNamespace(analyze=lambda _case: [item]),
            selector=CandidateSelector(threshold_enabled=False),
            router=SimpleNamespace(route=lambda _item: route()),
            expert_runner=runner,
        )

        result = pipeline.run(ProjectCase("case", "project", {}))

        self.assertEqual(["initial", "escalation"], [call[0] for call in runner.calls])
        self.assertEqual(list(ACTIVE_UTILITY_EXPERTS)[:2], runner.calls[0][1]["C-1"])
        self.assertEqual(list(ACTIVE_UTILITY_EXPERTS)[2:], runner.calls[1][1]["C-1"])
        self.assertEqual(2, result.initial_expert_task_count)
        self.assertEqual(3, result.escalation_expert_task_count)
        self.assertEqual(1, result.full5_candidate_count)
        self.assertTrue(result.escalations[0].escalated)
        self.assertEqual(["CWE-703"], result.findings[0].cwes)


if __name__ == "__main__":
    unittest.main()
