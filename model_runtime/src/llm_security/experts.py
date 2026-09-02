from __future__ import annotations

from dataclasses import dataclass
from typing import Any

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


@dataclass(slots=True)
class ExpertRunOutput:
    findings: list[Finding]
    usage: list[UsageRecord]
    errors: list[str]
    task_count: int = 0
    submitted_task_count: int = 0
    completed_task_count: int = 0
    skipped_task_count: int = 0


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
                remaining = sum(
                    len(item)
                    for item in batches[batch_index:]
                )
                if remaining:
                    errors.append(
                        f"Stopped before submitting {remaining} remaining Expert tasks."
                    )
                break
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
                if str(payload["candidate_id"]) != candidate.candidate_id:
                    raise ValueError(f"Candidate mismatch for {task_id}")
                if ExpertFamily(str(payload["expert"])) != expert:
                    raise ValueError(f"Expert mismatch for {task_id}")
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
