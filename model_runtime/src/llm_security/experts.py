from __future__ import annotations

import re
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable

from .evidence import ContextBuilder
from .llm import LLMClient
from .models import (
    Candidate,
    ExpertAssignment,
    ExpertFamily,
    Finding,
    RouteDecision,
    UsageRecord,
)
from .prompts import (
    batched_expert_messages,
    batched_findings_schema,
    expert_messages,
    finding_from_payload,
    findings_schema,
)


class AnalysisCancelled(RuntimeError):
    """Raised when an authenticated user cancels an in-flight analysis."""


class ExpertFailureCode(str, Enum):
    RATE_LIMIT = "RATE_LIMIT"
    PROVIDER_ERROR = "PROVIDER_ERROR"
    AUTHENTICATION_ERROR = "AUTHENTICATION_ERROR"
    READ_TIMEOUT = "READ_TIMEOUT"
    HARD_TIMEOUT = "HARD_TIMEOUT"
    INVALID_JSON = "INVALID_JSON"
    SCHEMA_ERROR = "SCHEMA_ERROR"
    NO_FINAL_CONTENT = "NO_FINAL_CONTENT"
    OUTPUT_LIMIT = "OUTPUT_LIMIT"
    REASONING_BUDGET_EXHAUSTED = "REASONING_BUDGET_EXHAUSTED"
    CANCELLED = "CANCELLED"
    UNKNOWN = "UNKNOWN"


@dataclass(slots=True)
class ExpertTaskFailure:
    task_id: str
    candidate_id: str
    expert: str
    model: str
    provider: str | None
    code: ExpertFailureCode
    recoverable: bool
    recovered: bool
    attempts: int
    message: str


@dataclass(slots=True)
class ExpertRunOutput:
    findings: list[Finding]
    usage: list[UsageRecord]
    errors: list[str]
    task_count: int = 0
    submitted_task_count: int = 0
    completed_task_count: int = 0
    failed_task_count: int = 0
    incomplete_candidate_count: int = 0
    skipped_task_count: int = 0
    recovered_task_count: int = 0
    timed_out_task_count: int = 0
    covered_candidate_count: int = 0
    cancelled: bool = False
    failures: list[ExpertTaskFailure] = field(default_factory=list)


class ExpertRunner:
    def __init__(
        self,
        client: LLMClient,
        model: str,
        context_builder: ContextBuilder,
        models_by_family: dict[ExpertFamily, str] | None = None,
        prompt_version: str = "expert-v6-validator-counterevidence",
    ) -> None:
        self.client = client
        self.model = model
        self.context_builder = context_builder
        self.models_by_family = dict(models_by_family or {})
        self.prompt_version = prompt_version

    def run(
        self,
        candidates: list[Candidate],
        routes: list[RouteDecision],
    ) -> ExpertRunOutput:
        by_id = {candidate.candidate_id: candidate for candidate in candidates}
        findings: list[Finding] = []
        usage: list[UsageRecord] = []
        errors: list[str] = []
        task_count = 0
        completed_task_count = 0
        for route in routes:
            candidate = by_id[route.candidate_id]
            assignments = route.assignments or [
                ExpertAssignment(
                    expert=expert,
                    model_id=self.models_by_family.get(expert, self.model),
                    prompt_version=self.prompt_version,
                )
                for expert in route.selected
            ]
            for assignment in assignments:
                task_count += 1
                expert = assignment.expert
                context = self.context_builder.build(candidate, expert)
                try:
                    response = self.client.complete(
                        model=assignment.model_id,
                        messages=expert_messages(candidate, context),
                        response_schema=findings_schema(),
                        metadata={
                            "task": "expert",
                            "candidate": candidate,
                            "expert": expert,
                            "assignment": assignment,
                        },
                    )
                    usage.append(response.usage)
                    payloads = response.data.get("findings", [])
                    if not isinstance(payloads, list):
                        raise TypeError("The model response 'findings' field must be a list")
                    for index, payload in enumerate(payloads, start=1):
                        findings.append(
                            finding_from_payload(
                                payload,
                                index=index,
                                candidate=candidate,
                                expert=expert,
                                model_id=assignment.model_id,
                                prompt_version=self.prompt_version,
                            )
                        )
                    completed_task_count += 1
                except (KeyError, TypeError, ValueError, RuntimeError) as error:
                    errors.append(
                        f"{candidate.candidate_id}/{expert.value}/"
                        f"{assignment.model_id}: {error}"
                    )
        return ExpertRunOutput(
            findings=findings,
            usage=usage,
            errors=errors,
            task_count=task_count,
            submitted_task_count=task_count,
            completed_task_count=completed_task_count,
        )


@dataclass(frozen=True, slots=True)
class ExpertTask:
    task_id: str
    candidate: Candidate
    assignment: ExpertAssignment


@dataclass(slots=True)
class ExpertTaskResult:
    task_id: str
    candidate_id: str
    findings: list[Finding]
    usage: UsageRecord


@dataclass(frozen=True, slots=True)
class ExpertProgress:
    finished_task_count: int
    successful_task_count: int
    failed_task_count: int
    total_task_count: int
    active_request_count: int
    max_concurrency: int
    recovery_task_count: int = 0
    recovered_task_count: int = 0


class ParallelExpertRunner:
    """Run one independent OpenRouter request per Candidate × Expert task."""

    prompt_version = "parallel-expert-v1"

    def __init__(
        self,
        client: LLMClient,
        model: str,
        context_builder: ContextBuilder,
        *,
        models_by_family: dict[ExpertFamily, str] | None = None,
        max_concurrency: int = 100,
        recovery_attempts: int = 0,
        progress_callback: Callable[[ExpertProgress], None] | None = None,
        cancel_callback: Callable[[], bool] | None = None,
    ) -> None:
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        self.client = client
        self.model = model
        self.context_builder = context_builder
        self.models_by_family = dict(models_by_family or {})
        self.max_concurrency = min(100, max_concurrency)
        self.recovery_attempts = max(0, min(2, recovery_attempts))
        self.progress_callback = progress_callback
        self.cancel_callback = cancel_callback

    def run(
        self,
        candidates: list[Candidate],
        routes: list[RouteDecision],
    ) -> ExpertRunOutput:
        self._raise_if_cancelled()
        tasks = self._build_tasks(candidates, routes)
        total = len(tasks)
        if not tasks:
            self._notify_progress(
                ExpertProgress(0, 0, 0, 0, 0, self.max_concurrency)
            )
            return ExpertRunOutput(findings=[], usage=[], errors=[])

        results: dict[str, ExpertTaskResult] = {}
        failures: dict[str, ExpertTaskFailure] = {}
        successful_candidates: set[str] = set()
        successful = 0
        failed = 0
        finished = 0
        worker_count = min(self.max_concurrency, total)
        self._notify_progress(
            ExpertProgress(0, 0, 0, total, worker_count, self.max_concurrency)
        )

        executor = ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="expert-request",
        )
        cancelled = False
        accounted_task_ids: set[str] = set()
        try:
            futures = {
                executor.submit(self._run_task, task): task
                for task in tasks
            }
            pending = set(futures)
            while pending:
                if self._is_cancelled():
                    cancelled = True
                    ready = {future for future in pending if future.done()}
                    pending -= ready
                else:
                    ready, pending = wait(
                        pending,
                        timeout=0.25,
                        return_when=FIRST_COMPLETED,
                    )
                for future in ready:
                    task = futures[future]
                    try:
                        result = future.result()
                    except AnalysisCancelled:
                        cancelled = True
                        continue
                    except Exception as error:  # isolate one remote Expert failure
                        failed += 1
                        failures[task.task_id] = _task_failure(task, error)
                    else:
                        successful += 1
                        results[task.task_id] = result
                        successful_candidates.add(result.candidate_id)
                    accounted_task_ids.add(task.task_id)
                    finished += 1

                if ready:
                    active = sum(future.running() for future in pending)
                    self._notify_progress(
                        ExpertProgress(
                            finished,
                            successful,
                            failed,
                            total,
                            active,
                            self.max_concurrency,
                        )
                    )
                if cancelled:
                    break
        finally:
            if cancelled:
                for future in futures:
                    future.cancel()
                executor.shutdown(wait=False, cancel_futures=True)
            else:
                executor.shutdown(wait=True)

        if cancelled:
            for task in tasks:
                if task.task_id in accounted_task_ids:
                    continue
                failures[task.task_id] = ExpertTaskFailure(
                    task_id=task.task_id,
                    candidate_id=task.candidate.candidate_id,
                    expert=task.assignment.expert.value,
                    model=task.assignment.model_id,
                    provider=None,
                    code=ExpertFailureCode.CANCELLED,
                    recoverable=False,
                    recovered=False,
                    attempts=0,
                    message="Cancelled before a result was collected",
                )

        recovered = 0
        if not cancelled and self.recovery_attempts:
            for _ in range(self.recovery_attempts):
                recovery_tasks = [
                    task
                    for task in tasks
                    if task.task_id in failures
                    and not failures[task.task_id].recovered
                    and failures[task.task_id].recoverable
                ]
                if not recovery_tasks:
                    break
                recovery_workers = min(self.max_concurrency, len(recovery_tasks))
                self._notify_progress(
                    ExpertProgress(
                        finished,
                        successful,
                        failed,
                        total,
                        recovery_workers,
                        self.max_concurrency,
                        len(recovery_tasks),
                        recovered,
                    )
                )
                recovery_executor = ThreadPoolExecutor(
                    max_workers=recovery_workers,
                    thread_name_prefix="expert-recovery",
                )
                try:
                    recovery_futures = {
                        recovery_executor.submit(
                            self._run_task,
                            task,
                            failures[task.task_id].provider,
                        ): task
                        for task in recovery_tasks
                    }
                    recovery_pending = set(recovery_futures)
                    while recovery_pending:
                        if self._is_cancelled():
                            cancelled = True
                            break
                        ready, recovery_pending = wait(
                            recovery_pending,
                            timeout=0.25,
                            return_when=FIRST_COMPLETED,
                        )
                        for future in ready:
                            task = recovery_futures[future]
                            try:
                                result = future.result()
                            except AnalysisCancelled:
                                cancelled = True
                                continue
                            except Exception as error:
                                previous = failures[task.task_id]
                                current = _task_failure(task, error)
                                current.attempts = previous.attempts + 1
                                failures[task.task_id] = current
                            else:
                                previous = failures[task.task_id]
                                previous.recovered = True
                                previous.attempts += 1
                                results[task.task_id] = result
                                successful_candidates.add(result.candidate_id)
                                successful += 1
                                failed -= 1
                                recovered += 1

                        if ready:
                            active = sum(
                                future.running() for future in recovery_pending
                            )
                            self._notify_progress(
                                ExpertProgress(
                                    finished,
                                    successful,
                                    failed,
                                    total,
                                    active,
                                    self.max_concurrency,
                                    len(recovery_tasks),
                                    recovered,
                                )
                            )
                        if cancelled:
                            break
                finally:
                    if cancelled:
                        for future in recovery_futures:
                            future.cancel()
                        recovery_executor.shutdown(wait=False, cancel_futures=True)
                    else:
                        recovery_executor.shutdown(wait=True)
                if cancelled:
                    break

        findings: list[Finding] = []
        usage: list[UsageRecord] = []
        ordered_errors: list[str] = []
        candidate_ids = {task.candidate.candidate_id for task in tasks}
        for task in tasks:
            result = results.get(task.task_id)
            if result is not None:
                findings.extend(result.findings)
                usage.append(result.usage)
            elif (
                task.task_id in failures
                and failures[task.task_id].code != ExpertFailureCode.CANCELLED
            ):
                failure = failures[task.task_id]
                ordered_errors.append(
                    f"{failure.task_id}/{failure.candidate_id}/"
                    f"{failure.expert}/{failure.model} [{failure.code.value}]: "
                    f"{failure.message}"
                )

        ordered_failures = [
            failures[task.task_id]
            for task in tasks
            if task.task_id in failures
        ]
        timed_out = sum(
            failure.code in {
                ExpertFailureCode.READ_TIMEOUT,
                ExpertFailureCode.HARD_TIMEOUT,
            }
            and not failure.recovered
            for failure in ordered_failures
        )

        return ExpertRunOutput(
            findings=findings,
            usage=usage,
            errors=ordered_errors,
            task_count=total,
            submitted_task_count=total,
            completed_task_count=successful,
            failed_task_count=failed,
            incomplete_candidate_count=len(
                candidate_ids - successful_candidates
            ),
            skipped_task_count=sum(
                failure.code == ExpertFailureCode.CANCELLED
                for failure in ordered_failures
            ),
            recovered_task_count=recovered,
            timed_out_task_count=timed_out,
            covered_candidate_count=len(successful_candidates),
            cancelled=cancelled,
            failures=ordered_failures,
        )

    def _build_tasks(
        self,
        candidates: list[Candidate],
        routes: list[RouteDecision],
    ) -> list[ExpertTask]:
        routes_by_id = {route.candidate_id: route for route in routes}
        desired: dict[str, list[ExpertFamily]] = {}
        for candidate in candidates:
            route = routes_by_id[candidate.candidate_id]
            desired[candidate.candidate_id] = list(
                dict.fromkeys(
                    assignment.expert for assignment in route.assignments
                )
            ) or list(dict.fromkeys(route.selected))

        # Submit every candidate's Top-1 first, then Top-2, then escalation
        # extras. ThreadPoolExecutor preserves this queue order when the number
        # of tasks is larger than the concurrency cap.
        ordered: list[tuple[Candidate, ExpertFamily]] = []
        for rank in range(2):
            ordered.extend(
                (candidate, desired[candidate.candidate_id][rank])
                for candidate in candidates
                if len(desired[candidate.candidate_id]) > rank
            )
        extras = sorted(
            [
                (candidate, expert)
                for candidate in candidates
                for expert in desired[candidate.candidate_id][2:]
            ],
            key=lambda item: (
                routes_by_id[item[0].candidate_id].escalation_confidence
                if routes_by_id[item[0].candidate_id].escalation_confidence is not None
                else 1.0,
                -item[0].suspicion_score,
                item[0].candidate_id,
                item[1].value,
            ),
        )
        ordered.extend(extras)

        return [
            ExpertTask(
                task_id=f"T{index:05d}",
                candidate=candidate,
                assignment=ExpertAssignment(
                    expert=expert,
                    model_id=self.models_by_family.get(expert, self.model),
                    prompt_version=self.prompt_version,
                ),
            )
            for index, (candidate, expert) in enumerate(ordered, start=1)
        ]

    def _run_task(
        self,
        task: ExpertTask,
        excluded_provider: str | None = None,
    ) -> ExpertTaskResult:
        self._raise_if_cancelled()
        candidate = task.candidate
        assignment = task.assignment
        expert = assignment.expert
        context = self.context_builder.build(candidate, expert)
        response = self.client.complete(
            model=assignment.model_id,
            messages=expert_messages(candidate, context),
            response_schema=findings_schema(best_effort=True),
            metadata={
                "task": "expert",
                "task_id": task.task_id,
                "candidate_id": candidate.candidate_id,
                "expert": expert.value,
                "exclude_provider": excluded_provider,
            },
        )
        payloads = response.data.get("findings", [])
        if not isinstance(payloads, list):
            raise TypeError("The model response 'findings' field must be a list")
        findings = [
            finding_from_payload(
                payload,
                index=index,
                candidate=candidate,
                expert=expert,
                model_id=response.usage.model,
                prompt_version=assignment.prompt_version,
                best_effort=True,
            )
            for index, payload in enumerate(payloads, start=1)
        ]
        return ExpertTaskResult(
            task_id=task.task_id,
            candidate_id=candidate.candidate_id,
            findings=findings,
            usage=response.usage,
        )

    def _notify_progress(self, state: ExpertProgress) -> None:
        if self.progress_callback is None:
            return
        try:
            self.progress_callback(state)
        except Exception:
            # Progress persistence must never invalidate paid analysis work.
            pass

    def _is_cancelled(self) -> bool:
        return bool(self.cancel_callback and self.cancel_callback())

    def _raise_if_cancelled(self) -> None:
        if self._is_cancelled():
            raise AnalysisCancelled("Analysis cancellation requested")


def _task_failure(task: ExpertTask, error: Exception) -> ExpertTaskFailure:
    message = str(error)
    lowered = message.lower()
    provider_match = re.search(r"provider=([^,\s)]+)", message, re.IGNORECASE)
    if provider_match is None:
        provider_match = re.search(
            r'["\']provider_name["\']\s*:\s*["\']([^"\']+)',
            message,
            re.IGNORECASE,
        )
    provider = provider_match.group(1) if provider_match else None

    if "http 401" in lowered or "http 403" in lowered:
        code = ExpertFailureCode.AUTHENTICATION_ERROR
        recoverable = False
    elif "http 429" in lowered or "rate limit" in lowered:
        code = ExpertFailureCode.RATE_LIMIT
        recoverable = True
    elif (
        "no final content" in lowered
        and (reasoning_match := re.search(r"reasoning_tokens=(\d+)", lowered))
        and int(reasoning_match.group(1)) > 0
    ):
        code = ExpertFailureCode.REASONING_BUDGET_EXHAUSTED
        recoverable = True
    elif "no final content" in lowered:
        code = ExpertFailureCode.NO_FINAL_CONTENT
        recoverable = True
    elif "finish_reason=length" in lowered or "output-token" in lowered:
        code = ExpertFailureCode.OUTPUT_LIMIT
        recoverable = True
    elif "invalid json" in lowered or "incomplete" in lowered:
        code = ExpertFailureCode.INVALID_JSON
        recoverable = True
    elif "schema" in lowered or isinstance(error, (KeyError, TypeError, ValueError)):
        code = ExpertFailureCode.SCHEMA_ERROR
        recoverable = True
    elif "hard timeout" in lowered:
        code = ExpertFailureCode.HARD_TIMEOUT
        recoverable = True
    elif "timeout" in lowered or "timed out" in lowered:
        code = ExpertFailureCode.READ_TIMEOUT
        recoverable = True
    elif "http 5" in lowered or "provider" in lowered:
        code = ExpertFailureCode.PROVIDER_ERROR
        recoverable = True
    else:
        code = ExpertFailureCode.UNKNOWN
        recoverable = True

    return ExpertTaskFailure(
        task_id=task.task_id,
        candidate_id=task.candidate.candidate_id,
        expert=task.assignment.expert.value,
        model=task.assignment.model_id,
        provider=provider,
        code=code,
        recoverable=recoverable,
        recovered=False,
        attempts=1,
        message=message[:2000],
    )


@dataclass(slots=True)
class _BatchedTask:
    task_id: str
    candidate: Candidate
    expert: ExpertFamily
    context: Any


class BatchedExpertRunner:
    """Execute Router-selected Experts in bounded structured-output batches.

    max_tasks and max_batch_characters apply to each physical request. Every
    logical task that fits by itself is eventually submitted, so a Router
    escalation cannot silently discard later Expert assignments.
    """

    prompt_version = "batched-expert-v7-exact-task-results"

    def __init__(
        self,
        client: LLMClient,
        model: str,
        context_builder: ContextBuilder,
        *,
        max_batch_characters: int = 120_000,
        max_tasks: int = 24,
    ) -> None:
        if max_batch_characters < 1:
            raise ValueError("max_batch_characters must be positive")
        if max_tasks < 1:
            raise ValueError("max_tasks must be positive")
        self.client = client
        self.model = model
        self.context_builder = context_builder
        self.max_batch_characters = max_batch_characters
        self.max_tasks = max_tasks

    def run(
        self,
        candidates: list[Candidate],
        routes: list[RouteDecision],
    ) -> ExpertRunOutput:
        routes_by_id = {route.candidate_id: route for route in routes}
        desired: dict[str, list[ExpertFamily]] = {}
        for candidate in candidates:
            route = routes_by_id[candidate.candidate_id]
            desired[candidate.candidate_id] = list(
                dict.fromkeys(
                    assignment.expert for assignment in route.assignments
                )
            ) or list(dict.fromkeys(route.selected))

        ordered_assignments = self._ordered_assignments(
            candidates,
            routes_by_id,
            desired,
        )
        tasks = [
            _BatchedTask(
                task_id=f"T{index:05d}",
                candidate=candidate,
                expert=expert,
                context=self.context_builder.build(candidate, expert),
            )
            for index, (candidate, expert) in enumerate(
                ordered_assignments,
                start=1,
            )
        ]
        batches, oversized = self._partition_batches(tasks)

        findings: list[Finding] = []
        usage: list[UsageRecord] = []
        errors: list[str] = []
        completed_task_count = 0
        submitted_task_count = 0
        failed_task_count = 0

        for batch_index, batch in enumerate(batches, start=1):
            packets, task_lookup = self._build_packets(batch)
            submitted_task_count += len(batch)
            try:
                response = self.client.complete(
                    model=self.model,
                    messages=batched_expert_messages(packets),
                    response_schema=batched_findings_schema(list(task_lookup)),
                    metadata={
                        "task": "batched_experts",
                        "batch_index": batch_index,
                        "batch_count": len(batches),
                        "task_count": len(task_lookup),
                        "candidate_count": len(packets),
                    },
                )
            except RuntimeError as error:
                errors.append(
                    f"Expert batch {batch_index}/{len(batches)} request failed: {error}"
                )
                # A physical batch is only a transport optimization. Do not let
                # one provider failure erase later independent Expert tasks.
                failed_task_count += len(batch)
                continue
            batch_findings, batch_errors, batch_completed = (
                self._parse_batch_response(
                    response.data,
                    task_lookup,
                    model_id=response.usage.model,
                )
            )
            findings.extend(batch_findings)
            usage.append(response.usage)
            completed_task_count += batch_completed
            failed_task_count += len(batch) - batch_completed
            errors.extend(
                f"Expert batch {batch_index}/{len(batches)}: {error}"
                for error in batch_errors
            )

        if oversized:
            errors.append(
                "Skipped Expert tasks that individually exceeded the prompt budget "
                f"of {self.max_batch_characters} characters: "
                + ", ".join(task.task_id for task in oversized)
            )

        return ExpertRunOutput(
            findings=findings,
            usage=usage,
            errors=errors,
            task_count=len(tasks),
            submitted_task_count=submitted_task_count,
            completed_task_count=completed_task_count,
            failed_task_count=failed_task_count,
            skipped_task_count=len(oversized),
        )

    def _ordered_assignments(
        self,
        candidates: list[Candidate],
        routes_by_id: dict[str, RouteDecision],
        desired: dict[str, list[ExpertFamily]],
    ) -> list[tuple[Candidate, ExpertFamily]]:
        """Prioritize every candidate's Top-2 before Full-5 escalation extras."""

        candidate_order = sorted(
            enumerate(candidates),
            key=lambda item: (-item[1].suspicion_score, item[0]),
        )
        base = [
            (candidate, expert)
            for _, candidate in candidate_order
            for expert in desired[candidate.candidate_id][:2]
        ]
        extras = sorted(
            [
                (candidate, expert)
                for candidate in candidates
                for expert in desired[candidate.candidate_id][2:]
            ],
            key=lambda item: (
                routes_by_id[item[0].candidate_id].escalation_confidence
                if routes_by_id[item[0].candidate_id].escalation_confidence is not None
                else 1.0,
                -item[0].suspicion_score,
                item[0].candidate_id,
                item[1].value,
            ),
        )
        return [*base, *extras]

    def _partition_batches(
        self,
        tasks: list[_BatchedTask],
    ) -> tuple[list[list[_BatchedTask]], list[_BatchedTask]]:
        batches: list[list[_BatchedTask]] = []
        current: list[_BatchedTask] = []
        oversized: list[_BatchedTask] = []

        for task in tasks:
            proposed = [*current, task]
            if self._fits_batch(proposed):
                current = proposed
                continue

            if current:
                batches.append(current)
                current = []

            if self._fits_batch([task]):
                current = [task]
            else:
                oversized.append(task)

        if current:
            batches.append(current)
        return batches, oversized

    def _fits_batch(self, tasks: list[_BatchedTask]) -> bool:
        if not tasks or len(tasks) > self.max_tasks:
            return False
        packets, _ = self._build_packets(tasks)
        prompt_size = sum(
            len(message["content"])
            for message in batched_expert_messages(packets)
        )
        return prompt_size <= self.max_batch_characters

    def _parse_batch_response(
        self,
        data: dict[str, Any],
        task_lookup: dict[str, tuple[Candidate, ExpertFamily]],
        *,
        model_id: str,
    ) -> tuple[list[Finding], list[str], int]:
        findings: list[Finding] = []
        errors: list[str] = []
        completed: set[str] = set()
        seen: set[str] = set()
        payloads = data.get("expert_results", [])

        if not isinstance(payloads, list):
            return (
                [],
                ["The model response 'expert_results' field must be a list"],
                0,
            )

        for payload in payloads:
            if not isinstance(payload, dict):
                errors.append("Expert result must be an object")
                continue

            raw_task_id = payload.get("task_id")
            if raw_task_id is None:
                errors.append("Expert result is missing task_id")
                continue
            task_id = str(raw_task_id)

            # Provider-side schemas are not trusted as the only safety layer.
            # Unknown IDs are reported and discarded before any lookup.
            if task_id not in task_lookup:
                errors.append(f"Model returned unknown Expert task ID: {task_id}")
                continue
            if task_id in seen:
                errors.append(f"Duplicate Expert result: {task_id}")
                continue
            seen.add(task_id)

            candidate, expert = task_lookup[task_id]
            try:
                task_findings = payload.get("findings", [])
                if not isinstance(task_findings, list):
                    raise TypeError(f"Findings for {task_id} must be a list")

                converted = [
                    finding_from_payload(
                        finding_payload,
                        index=index,
                        candidate=candidate,
                        expert=expert,
                        model_id=model_id,
                        prompt_version=self.prompt_version,
                    )
                    for index, finding_payload in enumerate(
                        task_findings,
                        start=1,
                    )
                ]
            except (KeyError, TypeError, ValueError) as error:
                errors.append(str(error))
                continue

            findings.extend(converted)
            completed.add(task_id)

        missing = sorted(set(task_lookup) - completed)
        if missing:
            errors.append(
                "Model did not return a valid result for Expert tasks: "
                + ", ".join(missing)
            )
        return findings, errors, len(completed)

    def _build_packets(
        self,
        tasks: list[_BatchedTask],
    ) -> tuple[list[dict[str, Any]], dict[str, tuple[Candidate, ExpertFamily]]]:
        grouped: dict[str, list[_BatchedTask]] = {}
        for task in tasks:
            grouped.setdefault(task.candidate.candidate_id, []).append(task)

        packets: list[dict[str, Any]] = []
        lookup: dict[str, tuple[Candidate, ExpertFamily]] = {}
        for candidate_tasks in grouped.values():
            packet, packet_tasks = self._candidate_packet(candidate_tasks)
            packets.append(packet)
            lookup.update(packet_tasks)
        return packets, lookup

    def _candidate_packet(
        self,
        tasks: list[_BatchedTask],
    ) -> tuple[dict[str, Any], dict[str, tuple[Candidate, ExpertFamily]]]:
        candidate = tasks[0].candidate
        task_payloads: list[dict[str, Any]] = []
        lookup: dict[str, tuple[Candidate, ExpertFamily]] = {}
        comments: list[str] = []

        for task in tasks:
            context = task.context
            task_payloads.append(
                {
                    "task_id": task.task_id,
                    "expert": task.expert.value,
                    "static_evidence": context.evidence_text,
                    "vulnerability_slice": context.code_slice,
                    "evidence_graph": context.evidence_graph_text,
                    "type_information": context.type_information_text,
                    "related_function_summaries": context.related_functions_text,
                    "static_cwe_hypotheses": context.cwe_hypotheses_text,
                    "security_knowledge": context.knowledge_text,
                }
            )
            if context.comments_untrusted and context.comments_untrusted not in comments:
                comments.append(context.comments_untrusted)
            lookup[task.task_id] = (candidate, task.expert)

        return (
            {
                "candidate_id": candidate.candidate_id,
                "location": {
                    "file": candidate.file,
                    "function": candidate.function,
                    "line_start": candidate.line_start,
                    "line_end": candidate.line_end,
                },
                "suspicion_score": candidate.suspicion_score,
                "callers": candidate.callers,
                "callees": candidate.callees,
                "normalized_code": tasks[0].context.code,
                "untrusted_comments": "\n".join(comments) or "(none)",
                "expert_tasks": task_payloads,
            },
            lookup,
        )
