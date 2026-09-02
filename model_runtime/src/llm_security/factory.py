from __future__ import annotations

from collections.abc import Callable

from .aggregation import FindingAggregator
from .analysis import LearnedCandidateRanker, SemanticStaticAnalyzer
from .config import AppConfig
from .evidence import ContextBuilder
from .experts import (
    BatchedExpertRunner,
    ExpertProgress,
    ExpertRunner,
    ParallelExpertRunner,
)
from .llm import OpenRouterClient
from .knowledge import LocalSecurityKnowledgeRetriever
from .pipeline import VulnerabilityPipeline
from .routing import BudgetedUtilityRouter, CandidateGate, Router
from .static_analysis import LightweightStaticAnalyzer
from .validation import EvidenceValidator


def build_openrouter_client(config: AppConfig) -> OpenRouterClient:
    config.validate()
    return OpenRouterClient(
        api_key=config.model.api_key,
        timeout_seconds=config.runtime.request_timeout_seconds,
        max_retries=config.runtime.max_retries,
        temperature=config.model.temperature,
        max_output_tokens=config.model.max_output_tokens,
        reasoning_enabled=config.model.reasoning_enabled,
        reasoning_effort=config.model.reasoning_effort,
        provider=config.model.provider,
        require_parameters=config.model.require_parameters,
        allow_fallbacks=config.model.allow_fallbacks,
        structured_output=config.model.structured_output,
    )


def build_context_builder(config: AppConfig) -> ContextBuilder:
    knowledge_retriever = (
        LocalSecurityKnowledgeRetriever.from_jsonl(
            config.analysis.security_knowledge_path
        )
        if config.analysis.security_knowledge_path
        else None
    )
    return ContextBuilder(
        config.analysis.max_context_characters,
        knowledge_retriever=knowledge_retriever,
    )


def build_candidate_analyzer(
    config: AppConfig,
    *,
    max_source_bytes: int = 2 * 1024 * 1024,
    parse_timeout_ms: int = 30_000,
    require_ranker: bool = False,
):
    """Build the configured analyzer and fail closed for required rankers."""

    config.validate()
    if config.analysis.backend == "legacy":
        if require_ranker:
            raise ValueError(
                "The learned Utility Router requires the semantic Candidate Ranker"
            )
        return LightweightStaticAnalyzer(
            max_candidates=None,
            context_lines=config.analysis.context_lines,
        )

    ranker = None
    if config.analysis.candidate_ranker_path:
        ranker_path = config.analysis.candidate_ranker_path
        try:
            ranker = LearnedCandidateRanker.load(ranker_path)
        except (OSError, ValueError) as exc:
            raise ValueError(
                f"Cannot load configured Candidate Ranker artifact: {ranker_path}"
            ) from exc
    elif config.analysis.candidate_ranker_required or require_ranker:
        raise ValueError("A Candidate Ranker artifact is required but not configured")

    return SemanticStaticAnalyzer(
        max_source_bytes=max_source_bytes,
        parse_timeout_ms=parse_timeout_ms,
        candidate_ranker=ranker,
    )


def build_pipeline(config: AppConfig, router: Router) -> VulnerabilityPipeline:
    client = build_openrouter_client(config)
    analyzer = build_candidate_analyzer(
        config,
        require_ranker=isinstance(router, BudgetedUtilityRouter),
    )
    return VulnerabilityPipeline(
        analyzer=analyzer,
        router=router,
        expert_runner=ExpertRunner(
            client=client,
            model=config.model.expert_model,
            context_builder=build_context_builder(config),
            models_by_family=config.model.expert_models,
        ),
        aggregator=FindingAggregator(),
        validator=EvidenceValidator(
            minimum_confidence=config.validation.minimum_confidence,
            minimum_confidence_by_expert=(
                config.validation.minimum_confidence_by_expert
            ),
            client=client,
            model=config.model.validator_model,
            strong_model=config.model.strong_model,
            use_llm_for_uncertain=config.validation.use_llm_for_uncertain,
            falsify_all_supported=config.validation.falsify_all_supported,
        ),
        candidate_gate=CandidateGate(
            enabled=config.candidate_gate.enabled,
            threshold=config.candidate_gate.threshold,
        ),
        max_candidates=config.analysis.max_candidates_per_project,
    )


def build_batched_web_pipeline(
    config: AppConfig,
    router: Router,
    *,
    max_batch_characters: int,
    max_batch_tasks: int,
) -> VulnerabilityPipeline:
    """Build the web pipeline with bounded LLM batches for logical Experts."""

    client = build_openrouter_client(config)
    if isinstance(router, BudgetedUtilityRouter):
        trained_models = {
            assignment.model_id for assignment in router.assignments.values()
        }
        if config.model.expert_model in trained_models:
            router.restrict_to_model(config.model.expert_model)
        else:
            # The trained Router still selects logical Experts using its learned
            # utility statistics; the user's model executes the batched request.
            # This path is surfaced as unvalidated in the web UI and result JSON.
            router.execution_model_id = None
    analyzer = build_candidate_analyzer(
        config,
        require_ranker=isinstance(router, BudgetedUtilityRouter),
    )
    return VulnerabilityPipeline(
        analyzer=analyzer,
        router=router,
        expert_runner=BatchedExpertRunner(
            client=client,
            model=config.model.expert_model,
            context_builder=build_context_builder(config),
            max_batch_characters=max_batch_characters,
            max_tasks=max_batch_tasks,
        ),
        aggregator=FindingAggregator(),
        validator=EvidenceValidator(
            minimum_confidence=config.validation.minimum_confidence,
            minimum_confidence_by_expert=(
                config.validation.minimum_confidence_by_expert
            ),
            client=None,
            model=None,
            strong_model=None,
            use_llm_for_uncertain=False,
            falsify_all_supported=False,
        ),
        candidate_gate=CandidateGate(
            enabled=config.candidate_gate.enabled,
            threshold=config.candidate_gate.threshold,
        ),
        max_candidates=config.analysis.max_candidates_per_project,
    )


def build_parallel_web_pipeline(
    config: AppConfig,
    router: Router,
    *,
    max_concurrency: int,
    progress_callback: Callable[[ExpertProgress], None] | None = None,
) -> VulnerabilityPipeline:
    """Build the production web pipeline with one request per logical Expert."""

    client = build_openrouter_client(config)
    if isinstance(router, BudgetedUtilityRouter):
        trained_models = {
            assignment.model_id for assignment in router.assignments.values()
        }
        if config.model.expert_model in trained_models:
            router.restrict_to_model(config.model.expert_model)
        else:
            # The learned Router still chooses logical Experts, while the
            # request-selected model executes every independent task.
            router.execution_model_id = None
    analyzer = build_candidate_analyzer(
        config,
        require_ranker=isinstance(router, BudgetedUtilityRouter),
    )
    return VulnerabilityPipeline(
        analyzer=analyzer,
        router=router,
        expert_runner=ParallelExpertRunner(
            client=client,
            model=config.model.expert_model,
            context_builder=build_context_builder(config),
            models_by_family=config.model.expert_models,
            max_concurrency=max_concurrency,
            progress_callback=progress_callback,
        ),
        aggregator=FindingAggregator(),
        validator=EvidenceValidator(
            minimum_confidence=config.validation.minimum_confidence,
            minimum_confidence_by_expert=(
                config.validation.minimum_confidence_by_expert
            ),
            client=None,
            model=None,
            strong_model=None,
            use_llm_for_uncertain=False,
            falsify_all_supported=False,
        ),
        candidate_gate=CandidateGate(
            enabled=config.candidate_gate.enabled,
            threshold=config.candidate_gate.threshold,
        ),
        max_candidates=config.analysis.max_candidates_per_project,
    )
