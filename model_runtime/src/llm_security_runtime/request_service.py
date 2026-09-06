from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Callable, Sequence

from llm_security.config import AppConfig
from llm_security.datasets import _candidate_from_raw
from llm_security.factory import build_openrouter_client, build_parallel_web_pipeline
from llm_security.models import ProjectCase, ValidationVerdict, to_dict
from llm_security.patching import LLMBatchPatchAgent
from llm_security.verification import TemporaryPatchVerifier
from llm_security.web.service import (
    PatchBatchRecord,
    WebJobService,
    WebSettings,
    _expert_progress_callback,
    _finding_bundle,
    _finding_from_raw,
    _now,
    _validation_from_raw,
    _write_json_atomic,
    load_project_sources,
    load_router_artifact,
    validate_patch_scope_for_files,
)


@dataclass(frozen=True, slots=True)
class RuntimeJobOptions:
    sensitivity: float = 0.5
    model: str | None = None
    api_key: str | None = None
    router_validated: bool = False

    def safe_metadata(self) -> dict[str, object]:
        return {
            "sensitivity": self.sensitivity,
            "model_override": self.model,
            "router_model_validated": self.router_validated,
            "api_key_source": "request",
        }


class RequestAwareWebJobService(WebJobService):
    """WebJobService with per-job OpenRouter and sensitivity configuration.

    Secrets are intentionally kept only in process memory. They are never
    serialized into job.json, analysis.json, or the SQLite web database.
    """

    def __init__(self, settings: WebSettings) -> None:
        self._request_options_lock = threading.RLock()
        self._request_options: dict[str, RuntimeJobOptions] = {}
        super().__init__(settings)

    def create_job(
        self,
        project_name: str,
        uploads: Sequence[tuple[str, BinaryIO]],
        *,
        options: RuntimeJobOptions | None = None,
    ):
        selected = options or RuntimeJobOptions()

        # WebJobService submits the worker before returning the JobRecord.
        # Holding this lock creates a barrier so the worker cannot start until
        # the options map contains the newly-created job id.
        with self._request_options_lock:
            record = super().create_job(project_name, uploads)
            self._request_options[record.job_id] = selected
            return record

    def _run_analysis(self, job_id: str) -> None:
        with self._request_options_lock:
            self._request_options.setdefault(job_id, RuntimeJobOptions())
        try:
            super()._run_analysis(job_id)
        finally:
            # Keep only non-secret settings for a later patch request.
            with self._request_options_lock:
                options = self._request_options.get(job_id, RuntimeJobOptions())
                self._request_options[job_id] = RuntimeJobOptions(
                    sensitivity=options.sensitivity,
                    model=options.model,
                    api_key=None,
                    router_validated=options.router_validated,
                )

    def request_options(self, job_id: str) -> RuntimeJobOptions:
        with self._request_options_lock:
            return self._request_options.get(job_id, RuntimeJobOptions())

    def delete_job(self, job_id: str) -> None:
        super().delete_job(job_id)
        with self._request_options_lock:
            self._request_options.pop(job_id, None)

    def _config_for_options(self, options: RuntimeJobOptions) -> AppConfig:
        config = AppConfig.from_env(self.settings.env_file)
        if not options.api_key:
            raise RuntimeError("OpenRouter API Key를 입력해주세요.")
        if not options.model:
            raise RuntimeError("OpenRouter 모델 ID를 입력해주세요.")

        config.model.api_key = options.api_key
        config.runtime.allow_paid_experiments = True

        selected_model = options.model
        config.model.expert_model = selected_model
        config.model.validator_model = selected_model
        config.model.patch_model = selected_model
        config.model.strong_model = selected_model
        config.model.expert_models = {
            family: selected_model
            for family in config.model.expert_models
        }

        sensitivity = min(1.0, max(0.0, options.sensitivity))

        # 0.5 exactly reproduces the current .env defaults:
        # Candidate Gate 0.40 / minimum validation confidence 0.60.
        # Higher sensitivity lowers both thresholds.
        candidate_threshold = round(0.70 - (0.60 * sensitivity), 4)
        validation_threshold = round(0.85 - (0.50 * sensitivity), 4)

        config.candidate_gate.threshold = candidate_threshold
        config.validation.minimum_confidence = validation_threshold
        config.validation.minimum_confidence_by_expert = {
            expert: validation_threshold
            for expert in config.validation.minimum_confidence_by_expert
        }

        config.validate()
        return config

    def _config_for_job(self, job_id: str) -> AppConfig:
        return self._config_for_options(self.request_options(job_id))

    def _analyze_project(
        self,
        input_directory: Path,
        job,
        progress: Callable[[int, str], None],
    ) -> dict:
        config = self._config_for_job(job.job_id)

        config.analysis.backend = "semantic"
        config.candidate_gate.enabled = self.settings.candidate_gate_enabled
        config.model.max_output_tokens = self.settings.detection_max_output_tokens
        self._raise_if_cancelled(job.job_id)

        progress(20, "Loading C/C++ source files")
        source_warnings: list[str] = []
        source_files = load_project_sources(
            input_directory,
            max_file_bytes=self.settings.max_source_file_bytes,
            max_total_bytes=self.settings.max_source_total_bytes,
            warnings=source_warnings,
        )
        self._raise_if_cancelled(job.job_id)

        progress(30, "Loading Router and static analyzer")
        router = load_router_artifact(self.settings.router_artifact)
        self._raise_if_cancelled(job.job_id)

        case = ProjectCase(
            case_id=f"web-{job.job_id}",
            project_id=job.project_name,
            source_files=source_files,
            split="unlabeled",
            metadata={"source": "web-upload"},
        )

        progress(40, "Preparing parallel Candidate × Expert tasks")
        result = build_parallel_web_pipeline(
            config,
            router,
            max_concurrency=self.settings.max_concurrent_expert_requests,
            recovery_attempts=self.settings.expert_recovery_attempts,
            progress_callback=_expert_progress_callback(progress),
            cancel_callback=lambda: self._is_cancel_requested(job.job_id),
        ).run(case)
        result.cancelled = result.cancelled or self._is_cancel_requested(job.job_id)
        if result.cancelled:
            result.analysis_status = "cancelled"
        if not result.cancelled:
            progress(95, "Preparing evidence-grounded report")

        candidates = {item.candidate_id: item for item in result.candidates}
        validations = {item.finding_id: item for item in result.validations}
        bundles = [
            {
                "finding": to_dict(finding),
                "validation": to_dict(validations[finding.finding_id]),
                "candidate": to_dict(candidates[finding.candidate_id]),
                "patch": None,
            }
            for finding in result.findings
        ]
        validated = sum(
            item.verdict == ValidationVerdict.VALIDATED
            for item in result.validations
        )
        review = sum(
            item.verdict == ValidationVerdict.UNCERTAIN
            for item in result.validations
        )
        rejected = sum(
            item.verdict == ValidationVerdict.REJECTED
            for item in result.validations
        )
        validation_failures = sum(item.failed for item in result.validations)

        options = self.request_options(job.job_id)
        return {
            "summary": {
                "router_artifact": str(self.settings.router_artifact.resolve()),
                "router_artifact_sha256": _file_sha256(
                    self.settings.router_artifact
                ),
                "candidate_ranker_artifact": config.analysis.candidate_ranker_path,
                "candidate_ranker_artifact_sha256": (
                    _file_sha256(config.analysis.candidate_ranker_path)
                    if config.analysis.candidate_ranker_path
                    else None
                ),
                "max_candidates": config.analysis.max_candidates_per_project,
                "source_file_count": len(source_files),
                "candidate_count": len(result.candidates),
                "cwe_hypothesis_count": sum(
                    len(item.cwe_hypotheses) for item in result.candidates
                ),
                "finding_count": len(result.findings),
                "validated_finding_count": validated,
                "review_finding_count": review,
                "rejected_finding_count": rejected,
                "validation_failure_count": validation_failures,
                "analysis_status": result.analysis_status,
                "total_cost": sum(item.cost for item in result.usage),
                "request_count": len(result.usage),
                "expert_task_count": result.expert_task_count,
                "submitted_expert_task_count": result.submitted_expert_task_count,
                "completed_expert_task_count": result.completed_expert_task_count,
                "failed_expert_task_count": result.failed_expert_task_count,
                "recovered_expert_task_count": result.recovered_expert_task_count,
                "timed_out_expert_task_count": result.timed_out_expert_task_count,
                "incomplete_candidate_count": result.incomplete_candidate_count,
                "covered_candidate_count": result.covered_candidate_count,
                "skipped_expert_task_count": result.skipped_expert_task_count,
                "cancelled": result.cancelled,
                "structural_rejected_count": sum(
                    item.verdict == ValidationVerdict.REJECTED
                    for item in result.structural_validations
                ),
                "max_concurrent_expert_requests": (
                    self.settings.max_concurrent_expert_requests
                ),
                "expert_task_coverage": (
                    result.completed_expert_task_count / result.expert_task_count
                    if result.expert_task_count
                    else 1.0
                ),
                "candidate_coverage": (
                    result.covered_candidate_count / len(result.candidates)
                    if result.candidates
                    else 1.0
                ),
                "skipped_source_file_count": len(source_warnings),
                "degraded": bool(
                    result.failed_expert_task_count
                    or result.skipped_expert_task_count
                    or result.recovered_expert_task_count
                    or result.cancelled
                    or validation_failures
                    or result.errors
                    or source_warnings
                ),
                "request_settings": {
                    **options.safe_metadata(),
                    "effective_model": config.model.expert_model,
                    "candidate_gate_threshold": config.candidate_gate.threshold,
                    "minimum_confidence": config.validation.minimum_confidence,
                },
            },
            "findings": bundles,
            "routes": [to_dict(item) for item in result.routes],
            "structural_validations": [
                to_dict(item) for item in result.structural_validations
            ],
            "errors": source_warnings + result.errors,
            "expert_failures": [to_dict(item) for item in result.expert_failures],
            "usage": [to_dict(item) for item in result.usage],
        }

    def propose_patch_batch(
        self,
        job_id: str,
        finding_ids: Sequence[str],
        *,
        model: str,
        api_key: str,
    ) -> PatchBatchRecord:
        """Generate one patch without persisting the user's API key."""
        selected_ids = sorted(
            dict.fromkeys(str(item) for item in finding_ids if item)
        )
        if not selected_ids:
            raise ValueError("Select at least one finding")

        analysis = self.get_analysis(job_id)
        bundles = [
            _finding_bundle(analysis, finding_id)
            for finding_id in selected_ids
        ]
        for bundle in bundles:
            if bundle["validation"]["verdict"] != ValidationVerdict.VALIDATED.value:
                raise ValueError("Only validated findings can be patched")

        prior_options = self.request_options(job_id)
        config = self._config_for_options(RuntimeJobOptions(
            sensitivity=prior_options.sensitivity,
            model=model,
            api_key=api_key,
            router_validated=prior_options.router_validated,
        ))
        # Patch generation has a larger, independent output budget than analysis.
        # Without this override ModelConfig's conservative 2,500-token default is used.
        config.model.max_output_tokens = self.settings.patch_max_output_tokens

        with self._lock:
            existing = self.get_patch_batch(job_id)
            revision = 1
            if existing is not None:
                if existing.status == "approved":
                    raise RuntimeError("An applied patch cannot be regenerated")
                revision = existing.revision + 1
                if existing.revision - 1 >= self.settings.max_patch_regenerations:
                    raise RuntimeError(
                        "Patch regeneration limit reached "
                        f"({self.settings.max_patch_regenerations})"
                    )
                self._archive_patch_batch(job_id, existing)

        items = [
            (
                _finding_from_raw(bundle["finding"]),
                _validation_from_raw(bundle["validation"]),
                _candidate_from_raw(bundle["candidate"]),
            )
            for bundle in bundles
        ]

        proposal_agent = LLMBatchPatchAgent(
            build_openrouter_client(config),
            config.model.patch_model,
            max_prompt_characters=self.settings.patch_max_prompt_characters,
        )
        proposal = None
        last_error: Exception | None = None
        for attempt in range(self.settings.patch_recovery_attempts + 1):
            try:
                proposal = proposal_agent.propose(items)
                break
            except RuntimeError as error:
                last_error = error
                message = str(error).lower()
                if attempt >= self.settings.patch_recovery_attempts or not (
                    "finish_reason=length" in message
                    or "incomplete or invalid json" in message
                    or "output-token" in message
                ):
                    raise
                # A truncated structured response cannot be repaired locally. Retry once
                # with a larger budget while keeping reasoning disabled by the web defaults.
                config.model.max_output_tokens = min(
                    32_768,
                    max(config.model.max_output_tokens * 2, 1),
                )
                proposal_agent = LLMBatchPatchAgent(
                    build_openrouter_client(config),
                    config.model.patch_model,
                    max_prompt_characters=self.settings.patch_max_prompt_characters,
                )
        if proposal is None:
            raise last_error or RuntimeError("Patch generation failed")

        approved_files = {finding.file for finding, _, _ in items}
        validate_patch_scope_for_files(proposal.unified_diff, approved_files)

        verifier = TemporaryPatchVerifier()
        verification = verifier.verify(
            self._job_dir(job_id) / "input",
            proposal,
            [],
        )
        if (
            not verification.patch_applied
            and self.settings.patch_recovery_attempts > 0
        ):
            # A syntactically valid diff can still miss its source context. Give the
            # model the real verifier output and ask for one corrected proposal.
            proposal = proposal_agent.propose(
                items,
                previous_failure=verification.error or "patch context mismatch",
            )
            validate_patch_scope_for_files(proposal.unified_diff, approved_files)
            verification = verifier.verify(
                self._job_dir(job_id) / "input",
                proposal,
                [],
            )
        if not verification.patch_applied:
            raise RuntimeError(
                verification.error or "Generated patch could not be applied"
            )

        now = _now()
        record = PatchBatchRecord(
            patch_id="PB-"
            + hashlib.sha256(
                ("\n".join(selected_ids) + f"\nrevision={revision}").encode("utf-8")
            ).hexdigest()[:16],
            finding_ids=selected_ids,
            status="proposed",
            summary=proposal.summary,
            unified_diff=proposal.unified_diff,
            model=proposal.model,
            verification=to_dict(verification),
            usage=to_dict(proposal.usage),
            created_at=now,
            updated_at=now,
            revision=revision,
        )
        self._write_patch_batch(job_id, record)
        return record


def _file_sha256(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
