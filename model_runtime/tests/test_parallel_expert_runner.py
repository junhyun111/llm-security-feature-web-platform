from __future__ import annotations

import threading
import unittest

from llm_security.evidence import ExpertContext
from llm_security.experts import (
    AnalysisCancelled,
    ExpertFailureCode,
    ParallelExpertRunner,
)
from llm_security.llm import LLMResponse
from llm_security.models import (
    Candidate,
    ExpertFamily,
    RouteDecision,
    UsageRecord,
)


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


class ConcurrentClient:
    def __init__(
        self,
        *,
        expected_concurrency: int,
        failed_task_ids: set[str] | None = None,
    ) -> None:
        self.expected_concurrency = expected_concurrency
        self.failed_task_ids = set(failed_task_ids or set())
        self.lock = threading.Lock()
        self.release = threading.Event()
        self.active = 0
        self.max_active = 0
        self.calls: list[dict] = []

    def complete(self, **kwargs) -> LLMResponse:
        metadata = dict(kwargs["metadata"])
        task_id = str(metadata["task_id"])
        with self.lock:
            self.active += 1
            self.max_active = max(self.max_active, self.active)
            self.calls.append(
                {
                    "metadata": metadata,
                    "schema": kwargs["response_schema"],
                }
            )
            if self.active >= self.expected_concurrency:
                self.release.set()

        try:
            if not self.release.wait(timeout=2):
                raise RuntimeError("concurrency gate timed out")
            if task_id in self.failed_task_ids:
                raise RuntimeError("simulated provider failure")
            return LLMResponse(
                data={"findings": []},
                usage=UsageRecord(model=kwargs["model"]),
                raw={},
            )
        finally:
            with self.lock:
                self.active -= 1


class RecoveryClient:
    def __init__(self) -> None:
        self.calls: dict[str, int] = {}
        self.metadata: dict[str, list[dict]] = {}

    def complete(self, **kwargs) -> LLMResponse:
        task_id = str(kwargs["metadata"]["task_id"])
        self.calls[task_id] = self.calls.get(task_id, 0) + 1
        self.metadata.setdefault(task_id, []).append(dict(kwargs["metadata"]))
        if task_id == "T00001" and self.calls[task_id] == 1:
            raise RuntimeError("OpenRouter HTTP 429: rate limited (provider=Wafer)")
        return LLMResponse(
            data={"findings": []},
            usage=UsageRecord(model=kwargs["model"]),
            raw={},
        )


class PartialCancellationClient:
    def __init__(self) -> None:
        self.cancel = threading.Event()
        self.release = threading.Event()

    def complete(self, **kwargs) -> LLMResponse:
        task_id = str(kwargs["metadata"]["task_id"])
        if task_id == "T00001":
            threading.Timer(0.02, self.cancel.set).start()
        else:
            self.release.wait(timeout=2)
        return LLMResponse(
            data={"findings": []},
            usage=UsageRecord(model=kwargs["model"]),
            raw={},
        )


def candidate(index: int) -> Candidate:
    return Candidate(
        candidate_id=f"C-{index}",
        project_id="parallel",
        file=f"source-{index}.c",
        function=f"function_{index}",
        line_start=1,
        line_end=3,
        code=f"int function_{index}(void) {{ return {index}; }}",
        evidence=[],
        features={},
        suspicion_score=1.0 - index / 100,
    )


def route(item: Candidate) -> RouteDecision:
    selected = [
        ExpertFamily.MEMORY_BOUNDS,
        ExpertFamily.INTEGER_SIZE_TYPE,
    ]
    return RouteDecision(
        candidate_id=item.candidate_id,
        scores={expert: 0.5 for expert in selected},
        selected=selected,
        top1_confidence=0.5,
        top1_top2_margin=0.0,
        policy="utility_top2",
        reasons=["test"],
        ranked_experts=selected,
        top2_experts=selected,
        escalation_confidence=0.9,
    )


class ParallelExpertRunnerTest(unittest.TestCase):
    def test_tasks_prioritize_top1_then_top2_for_every_candidate(self) -> None:
        candidates = [candidate(index) for index in range(1, 4)]
        runner = ParallelExpertRunner(
            client=ConcurrentClient(expected_concurrency=1),
            model="test/model",
            context_builder=ContextBuilder(),
            max_concurrency=3,
        )

        tasks = runner._build_tasks(
            candidates,
            [route(item) for item in candidates],
        )

        self.assertEqual(
            [
                ("T00001", "C-1", ExpertFamily.MEMORY_BOUNDS),
                ("T00002", "C-2", ExpertFamily.MEMORY_BOUNDS),
                ("T00003", "C-3", ExpertFamily.MEMORY_BOUNDS),
                ("T00004", "C-1", ExpertFamily.INTEGER_SIZE_TYPE),
                ("T00005", "C-2", ExpertFamily.INTEGER_SIZE_TYPE),
                ("T00006", "C-3", ExpertFamily.INTEGER_SIZE_TYPE),
            ],
            [
                (
                    task.task_id,
                    task.candidate.candidate_id,
                    task.assignment.expert,
                )
                for task in tasks
            ],
        )

    def test_independent_requests_are_bounded_and_failures_are_isolated(self) -> None:
        candidates = [candidate(index) for index in range(1, 4)]
        client = ConcurrentClient(
            expected_concurrency=3,
            failed_task_ids={"T00001", "T00004"},
        )
        progress = []
        runner = ParallelExpertRunner(
            client=client,
            model="test/model",
            context_builder=ContextBuilder(),
            max_concurrency=3,
            progress_callback=progress.append,
        )

        output = runner.run(candidates, [route(item) for item in candidates])

        self.assertEqual(6, output.task_count)
        self.assertEqual(6, output.submitted_task_count)
        self.assertEqual(4, output.completed_task_count)
        self.assertEqual(2, output.failed_task_count)
        self.assertEqual(1, output.incomplete_candidate_count)
        self.assertEqual(2, len(output.errors))
        self.assertEqual(3, client.max_active)
        self.assertLessEqual(client.max_active, 3)
        self.assertEqual(6, len(client.calls))
        self.assertTrue(all(
            "findings" in call["schema"]["schema"]["properties"]
            for call in client.calls
        ))
        self.assertTrue(all(
            "expert_results" not in call["schema"]["schema"]["properties"]
            for call in client.calls
        ))
        self.assertEqual(6, progress[-1].finished_task_count)
        self.assertEqual(4, progress[-1].successful_task_count)
        self.assertEqual(2, progress[-1].failed_task_count)
        self.assertEqual(0, progress[-1].active_request_count)

    def test_concurrency_is_capped_at_one_hundred(self) -> None:
        runner = ParallelExpertRunner(
            client=ConcurrentClient(expected_concurrency=1),
            model="test/model",
            context_builder=ContextBuilder(),
            max_concurrency=500,
        )

        self.assertEqual(100, runner.max_concurrency)

    def test_recoverable_failure_is_retried_once_without_losing_other_work(self) -> None:
        item = candidate(1)
        client = RecoveryClient()
        runner = ParallelExpertRunner(
            client=client,
            model="test/model",
            context_builder=ContextBuilder(),
            max_concurrency=2,
            recovery_attempts=1,
        )

        output = runner.run([item], [route(item)])

        self.assertEqual(2, output.completed_task_count)
        self.assertEqual(0, output.failed_task_count)
        self.assertEqual(1, output.recovered_task_count)
        self.assertEqual([], output.errors)
        self.assertEqual(2, client.calls["T00001"])
        self.assertEqual("Wafer", client.metadata["T00001"][1]["exclude_provider"])
        self.assertEqual(1, len(output.failures))
        self.assertTrue(output.failures[0].recovered)
        self.assertEqual(ExpertFailureCode.RATE_LIMIT, output.failures[0].code)

    def test_cancelled_run_keeps_results_collected_before_cancellation(self) -> None:
        item = candidate(1)
        client = PartialCancellationClient()
        runner = ParallelExpertRunner(
            client=client,
            model="test/model",
            context_builder=ContextBuilder(),
            max_concurrency=2,
            cancel_callback=client.cancel.is_set,
        )

        try:
            output = runner.run([item], [route(item)])
        finally:
            client.release.set()

        self.assertTrue(output.cancelled)
        self.assertEqual(1, output.completed_task_count)
        self.assertEqual(1, output.skipped_task_count)
        self.assertEqual([], output.errors)
        self.assertTrue(any(
            failure.code == ExpertFailureCode.CANCELLED
            for failure in output.failures
        ))

    def test_cancelled_run_stops_before_submitting_requests(self) -> None:
        client = ConcurrentClient(expected_concurrency=1)
        runner = ParallelExpertRunner(
            client=client,
            model="test/model",
            context_builder=ContextBuilder(),
            max_concurrency=3,
            cancel_callback=lambda: True,
        )

        with self.assertRaises(AnalysisCancelled):
            runner.run([candidate(1)], [route(candidate(1))])

        self.assertEqual([], client.calls)


if __name__ == "__main__":
    unittest.main()
