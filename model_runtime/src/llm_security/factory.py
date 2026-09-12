from __future__ import annotations

from collections.abc import Callable

from .aggregation import EvidenceAggregator
from .decision import (
    CandidateDecisionArtifact,
    CandidateDecisionModel,
    DecisionPolicy,
)
from .decision.verifier import EvidenceVerifier
from .analysis import LearnedCandidateRanker, SemanticStaticAnalyzer
from .config import AppConfig
from .evidence import ContextBuilder
from .experts import (
    BatchedExpertRunner,
    ExpertProgress,
    ExpertRunner,
    ParallelExpertRunner,
)
from .evidence_processing import EvidenceProcessor
from .llm import OpenRouterClient
from .knowledge import LocalSecurityKnowledgeRetriever
from .pipeline import VulnerabilityPipeline
from .routing import BudgetedUtilityRouter, Router
from .selection import CandidateSelector
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
        provider_sort=config.model.provider_sort,
        provider_ignore=config.model.provider_ignore,
        require_parameters=config.model.require_parameters,
        allow_fallbacks=config.model.allow_fallbacks,
        structured_output=config.model.structured_output,
        json_repair=config.model.json_repair,
        structured_output_fallback=config.model.structured_output_fallback,
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


def build_decision_components(
    config: AppConfig,
) -> tuple[CandidateDecisionModel, DecisionPolicy]:
    if not config.validation.decision_model_path:
        raise RuntimeError("Trained candidate decision model required.")
    try:
        artifact = CandidateDecisionArtifact.load(
            config.validation.decision_model_path
        )
    except (OSError, ValueError) as exc:
        raise ValueError(
            "Cannot load configured candidate decision artifact: "
            + config.validation.decision_model_path
        ) from exc
    config.validation.candidate_probability_threshold = (
        artifact.candidate_threshold
    )
    config.validation.finding_validation_threshold = (
        artifact.validation_threshold
    )
    return CandidateDecisionModel(
        artifact.model,
        artifact.calibrator,
        candidate_threshold=artifact.candidate_threshold,
        validation_threshold=artifact.validation_threshold,
    ), DecisionPolicy(
        validation_threshold=artifact.validation_threshold,
    )


def build_candidate_analyzer(
    config: AppConfig,
    *,
    max_source_bytes: int = 2 * 1024 * 1024,
    parse_timeout_ms: int = 30_000,
):
    """Build the semantic analyzer; candidate selection is downstream."""

    config.validate()
    return SemanticStaticAnalyzer(
        max_source_bytes=max_source_bytes,
        parse_timeout_ms=parse_timeout_ms,
    )


def build_candidate_selector(
    config: AppConfig, *, require_ranker: bool = False
) -> CandidateSelector:
    """Build the one component that owns rank, threshold, and Top-K."""

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

    return CandidateSelector(
        ranker=ranker,
        threshold=config.candidate_selection.threshold,
        threshold_enabled=config.candidate_selection.enabled,
        max_candidates=config.analysis.max_candidates_per_project,
    )


def build_pipeline(
    config: AppConfig,
    router: Router,
    *,
    collect_decision_features: bool = False,
) -> VulnerabilityPipeline:
    client = build_openrouter_client(config)
    if collect_decision_features:
        config.configure_decision_feature_collection()
        scorer = None
        decision_policy = DecisionPolicy(
            validation_threshold=config.validation.finding_validation_threshold,
        )
    else:
        scorer, decision_policy = build_decision_components(config)
    analyzer = build_candidate_analyzer(config)
    selector = build_candidate_selector(
        config, require_ranker=isinstance(router, BudgetedUtilityRouter)
    )
    validator = EvidenceValidator(
        minimum_confidence=config.validation.minimum_confidence,
        minimum_confidence_by_expert=config.validation.minimum_confidence_by_expert,
        client=client,
        model=config.model.validator_model,
        strong_model=config.model.strong_model,
        use_llm_for_uncertain=config.validation.use_llm_for_uncertain,
    )
    return VulnerabilityPipeline(
        analyzer=analyzer,
        selector=selector,
        router=router,
        expert_runner=ExpertRunner(
            client=client,
            model=config.model.expert_model,
            context_builder=build_context_builder(config),
            models_by_family=config.model.expert_models,
        ),
        evidence_processor=EvidenceProcessor(aggregator=EvidenceAggregator()),
        decision_model=scorer,
        verifier=(
            None
            if collect_decision_features
            else EvidenceVerifier(
                candidate_threshold=scorer.candidate_threshold,
                policy=decision_policy,
                validator=validator,
            )
        ),
        collection_only=collect_decision_features,
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
    scorer, decision_policy = build_decision_components(config)
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
    analyzer = build_candidate_analyzer(config)
    selector = build_candidate_selector(
        config, require_ranker=isinstance(router, BudgetedUtilityRouter)
    )
    validator = EvidenceValidator(
        minimum_confidence=config.validation.minimum_confidence,
        minimum_confidence_by_expert=config.validation.minimum_confidence_by_expert,
        client=client,
        model=config.model.validator_model,
        strong_model=None,
        use_llm_for_uncertain=True,
    )
    return VulnerabilityPipeline(
        analyzer=analyzer,
        selector=selector,
        router=router,
        expert_runner=BatchedExpertRunner(
            client=client,
            model=config.model.expert_model,
            context_builder=build_context_builder(config),
            max_batch_characters=max_batch_characters,
            max_tasks=max_batch_tasks,
        ),
        evidence_processor=EvidenceProcessor(aggregator=EvidenceAggregator()),
        decision_model=scorer,
        verifier=EvidenceVerifier(
            candidate_threshold=scorer.candidate_threshold,
            policy=decision_policy,
            validator=validator,
        ),
    )


def build_parallel_web_pipeline(
    config: AppConfig,
    router: Router,
    *,
    max_concurrency: int,
    recovery_attempts: int = 1,
    progress_callback: Callable[[ExpertProgress], None] | None = None,
    cancel_callback: Callable[[], bool] | None = None,
) -> VulnerabilityPipeline:
    """Build the production web pipeline with one request per logical Expert."""

    config.model.json_repair = True
    config.model.structured_output_fallback = True
    client = build_openrouter_client(config)
    scorer, decision_policy = build_decision_components(config)
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
    analyzer = build_candidate_analyzer(config)
    selector = build_candidate_selector(
        config, require_ranker=isinstance(router, BudgetedUtilityRouter)
    )
    validator = EvidenceValidator(
        minimum_confidence=config.validation.minimum_confidence,
        minimum_confidence_by_expert=config.validation.minimum_confidence_by_expert,
        client=client,
        model=config.model.validator_model,
        strong_model=None,
        use_llm_for_uncertain=True,
    )
    return VulnerabilityPipeline(
        analyzer=analyzer,
        selector=selector,
        router=router,
        expert_runner=ParallelExpertRunner(
            client=client,
            model=config.model.expert_model,
            context_builder=build_context_builder(config),
            models_by_family=config.model.expert_models,
            max_concurrency=max_concurrency,
            recovery_attempts=recovery_attempts,
            progress_callback=progress_callback,
            cancel_callback=cancel_callback,
        ),
        evidence_processor=EvidenceProcessor(aggregator=EvidenceAggregator()),
        decision_model=scorer,
        verifier=EvidenceVerifier(
            candidate_threshold=scorer.candidate_threshold,
            policy=decision_policy,
            validator=validator,
        ),
    )
