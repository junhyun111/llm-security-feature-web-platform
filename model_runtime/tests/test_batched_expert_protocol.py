from __future__ import annotations

import json
import unittest

from llm_security.evidence import ExpertContext
from llm_security.experts import BatchedExpertRunner
from llm_security.llm import LLMResponse
from llm_security.models import (
    ACTIVE_UTILITY_EXPERTS,
    Candidate,
    ExpertFamily,
    RouteDecision,
    UsageRecord,
)
from llm_security.prompts import batched_findings_schema
from llm_security.web.service import JobStatus, _analysis_outcome


class ContextBuilder:
    def build(
        self,
        candidate: Candidate,
        expert: ExpertFamily,
    ) -> ExpertContext:
        return ExpertContext(
            candidate_id=candidate.candidate_id,
            expert=expert,
            code=candidate.code,
            evidence_text="No matching static evidence.",
            cwe_hypotheses_text="No static CWE hypothesis.",
        )


class ExactResultClient:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        response_schema: dict,
        metadata: dict | None = None,
    ) -> LLMResponse:
        packets = json.loads(messages[-1]["content"].split("\n\n", 1)[1])
        results = [
            {
                "task_id": task["task_id"],
                "findings": [],
            }
            for packet in packets
            for task in packet["expert_tasks"]
        ]
        self.calls.append(
            {
                "schema": response_schema,
                "metadata": metadata,
                "results": results,
            }
        )
        return LLMResponse(
            data={"expert_results": results},
            usage=UsageRecord(model=model),
            raw={},
        )


class UnknownTaskClient:
    def complete(self, **kwargs) -> LLMResponse:
        return LLMResponse(
            data={
                "expert_results": [
                    {
                        "task_id": "TASK-001",
                        "findings": [],
                    }
                ]
            },
            usage=UsageRecord(model=kwargs["model"]),
            raw={},
        )


class SecondBatchFailureClient(ExactResultClient):
    def __init__(self) -> None:
        super().__init__()
        self.failed_once = False

    def complete(self, **kwargs) -> LLMResponse:
        if len(self.calls) == 1 and not self.failed_once:
            self.failed_once = True
            raise RuntimeError("provider failure")
        return super().complete(**kwargs)


def candidate(index: int) -> Candidate:
    return Candidate(
        candidate_id=f"C-{index}",
        project_id="project",
        file=f"source-{index}.c",
        function=f"function_{index}",
        line_start=1,
        line_end=3,
        code=f"int function_{index}(void) {{ return {index}; }}",
        evidence=[],
        features={},
        suspicion_score=1.0 - (index / 100),
    )


def route(item: Candidate) -> RouteDecision:
    experts = list(ACTIVE_UTILITY_EXPERTS)
    return RouteDecision(
        candidate_id=item.candidate_id,
        scores={expert: 0.2 for expert in experts},
        selected=experts,
        top1_confidence=0.2,
        top1_top2_margin=0.0,
        policy="utility_full5_escalation",
        reasons=["test"],
        ranked_experts=experts,
        top2_experts=experts[:2],
        escalation_confidence=0.1,
        escalated=True,
        escalation_method="test",
    )


class BatchedExpertProtocolTest(unittest.TestCase):
    def test_schema_restricts_ids_and_requires_one_result_per_task(self) -> None:
        schema = batched_findings_schema(["T00001", "T00002"])
        root = schema["schema"]
        results = root["properties"]["expert_results"]
        task_id = results["items"]["properties"]["task_id"]

        self.assertNotIn("reviewed_task_ids", root["properties"])
        self.assertEqual(["expert_results"], root["required"])
        self.assertEqual(2, results["minItems"])
        self.assertEqual(2, results["maxItems"])
        self.assertEqual(["T00001", "T00002"], task_id["enum"])
        self.assertEqual(
            {"task_id", "findings"},
            set(results["items"]["properties"]),
        )

    def test_all_full5_tasks_are_split_without_being_discarded(self) -> None:
        candidates = [candidate(index) for index in range(1, 5)]
        client = ExactResultClient()
        runner = BatchedExpertRunner(
            client=client,
            model="test/model",
            context_builder=ContextBuilder(),
            max_batch_characters=120_000,
            max_tasks=6,
        )

        output = runner.run(candidates, [route(item) for item in candidates])

        self.assertEqual(20, output.task_count)
        self.assertEqual(20, output.submitted_task_count)
        self.assertEqual(20, output.completed_task_count)
        self.assertEqual(0, output.skipped_task_count)
        self.assertEqual([], output.errors)
        self.assertEqual([6, 6, 6, 2], [
            call["metadata"]["task_count"] for call in client.calls
        ])
        for call in client.calls:
            enum_ids = (
                call["schema"]["schema"]["properties"]["expert_results"]
                ["items"]["properties"]["task_id"]["enum"]
            )
            returned_ids = [item["task_id"] for item in call["results"]]
            self.assertEqual(returned_ids, enum_ids)

    def test_unknown_task_id_is_reported_without_raw_key_error(self) -> None:
        item = candidate(1)
        one_expert_route = route(item)
        one_expert_route.selected = [ExpertFamily.MEMORY_BOUNDS]
        one_expert_route.ranked_experts = [ExpertFamily.MEMORY_BOUNDS]
        one_expert_route.top2_experts = [ExpertFamily.MEMORY_BOUNDS]
        runner = BatchedExpertRunner(
            client=UnknownTaskClient(),
            model="test/model",
            context_builder=ContextBuilder(),
            max_tasks=6,
        )

        output = runner.run([item], [one_expert_route])

        self.assertEqual(0, output.completed_task_count)
        self.assertTrue(
            any("unknown Expert task ID: TASK-001" in error for error in output.errors)
        )
        self.assertFalse(any(error == "'TASK-001'" for error in output.errors))

    def test_later_batch_failure_preserves_completed_work_as_partial_input(self) -> None:
        candidates = [candidate(index) for index in range(1, 5)]
        runner = BatchedExpertRunner(
            client=SecondBatchFailureClient(),
            model="test/model",
            context_builder=ContextBuilder(),
            max_tasks=6,
        )

        output = runner.run(candidates, [route(item) for item in candidates])

        self.assertEqual(20, output.task_count)
        self.assertEqual(20, output.submitted_task_count)
        self.assertEqual(14, output.completed_task_count)
        self.assertEqual(6, output.failed_task_count)
        self.assertTrue(any("batch 2/4 request failed" in item for item in output.errors))
        self.assertFalse(any("Stopped before submitting" in item for item in output.errors))

    def test_job_outcome_distinguishes_failed_partial_and_completed(self) -> None:
        failed = _analysis_outcome(
            {
                "summary": {
                    "expert_task_count": 6,
                    "submitted_expert_task_count": 6,
                    "completed_expert_task_count": 0,
                },
                "errors": ["unknown task ID"],
            }
        )
        partial = _analysis_outcome(
            {
                "summary": {
                    "expert_task_count": 20,
                    "submitted_expert_task_count": 20,
                    "completed_expert_task_count": 17,
                    "failed_expert_task_count": 3,
                },
                "errors": ["one batch failed"],
            }
        )
        low_coverage_partial = _analysis_outcome(
            {
                "summary": {
                    "expert_task_count": 20,
                    "submitted_expert_task_count": 20,
                    "completed_expert_task_count": 15,
                    "failed_expert_task_count": 5,
                    "candidate_count": 4,
                    "covered_candidate_count": 2,
                },
                "errors": ["too many requests failed"],
            }
        )
        completed = _analysis_outcome(
            {
                "summary": {
                    "expert_task_count": 20,
                    "submitted_expert_task_count": 20,
                    "completed_expert_task_count": 20,
                },
                "errors": [],
            }
        )
        cancelled = _analysis_outcome(
            {
                "summary": {
                    "cancelled": True,
                    "expert_task_count": 20,
                    "completed_expert_task_count": 7,
                    "candidate_count": 4,
                    "covered_candidate_count": 3,
                },
                "errors": [],
            }
        )

        self.assertEqual(JobStatus.FAILED, failed[0])
        self.assertEqual(JobStatus.PARTIAL, partial[0])
        self.assertEqual(JobStatus.PARTIAL, low_coverage_partial[0])
        self.assertEqual(JobStatus.COMPLETED, completed[0])
        self.assertEqual(JobStatus.CANCELLED, cancelled[0])


if __name__ == "__main__":
    unittest.main()
