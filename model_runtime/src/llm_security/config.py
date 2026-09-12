from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .models import ExpertFamily


@dataclass(slots=True)
class ModelConfig:
    api_key: str | None = None
    expert_model: str = ""
    expert_models: dict[ExpertFamily, str] = field(default_factory=dict)
    validator_model: str = ""
    patch_model: str = ""
    strong_model: str | None = None
    sweep_models: tuple[str, ...] = ()
    temperature: float | None = None
    max_output_tokens: int = 2500
    reasoning_enabled: bool | None = None
    reasoning_effort: str | None = "medium"
    provider: str | None = None
    provider_sort: str | None = "throughput"
    provider_ignore: tuple[str, ...] = ("baidu",)
    require_parameters: bool = True
    allow_fallbacks: bool = True
    structured_output: bool = True
    json_repair: bool = False
    structured_output_fallback: bool = False


@dataclass(slots=True)
class RouterConfig:
    high_confidence: float = 0.72
    min_margin: float = 0.18
    max_entropy: float = 1.0
    max_experts: int = 2
    target_coverage: float = 0.95
    use_rule_fallback: bool = True


@dataclass(slots=True)
class CandidateSelectionConfig:
    enabled: bool = False
    threshold: float = 0.40


@dataclass(slots=True)
class AnalysisConfig:
    max_candidates_per_project: int = 4
    context_lines: int = 25
    max_context_characters: int = 30_000
    security_knowledge_path: str | None = None
    candidate_ranker_path: str | None = None
    candidate_ranker_required: bool = False


@dataclass(slots=True)
class ValidationConfig:
    minimum_confidence: float = 0.60
    # These are deployment values exported from validation-set selection. They
    # are not adjusted from web sensitivity at request time.
    candidate_probability_threshold: float = 0.28
    finding_validation_threshold: float = 0.71
    decision_model_path: str | None = None
    minimum_confidence_by_expert: dict[ExpertFamily, float] = field(
        default_factory=dict
    )
    use_llm_for_uncertain: bool = True


@dataclass(slots=True)
class RuntimeConfig:
    seed: int = 2026
    request_timeout_seconds: float = 90.0
    max_retries: int = 1
    allow_paid_experiments: bool = False
    run_model_sweep: bool = False


@dataclass(slots=True)
class AppConfig:
    model: ModelConfig = field(default_factory=ModelConfig)
    router: RouterConfig = field(default_factory=RouterConfig)
    candidate_selection: CandidateSelectionConfig = field(
        default_factory=CandidateSelectionConfig
    )
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    validation: ValidationConfig = field(default_factory=ValidationConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)

    def configure_decision_feature_collection(self) -> None:
        """Preserve candidate coverage while collecting decision inputs."""

        self.candidate_selection.enabled = False
        self.analysis.max_candidates_per_project = 4

    @classmethod
    def from_env(cls, path: str | Path = ".env") -> "AppConfig":
        env_path = Path(path).resolve()
        values = _read_env_file(path)
        values.update(os.environ)
        sweep_models = tuple(
            item.strip()
            for item in values.get("OPENROUTER_SWEEP_MODELS", "").split(",")
            if item.strip()
        )
        provider_ignore = tuple(
            item.strip().lower()
            for item in values.get("OPENROUTER_PROVIDER_IGNORE", "baidu").split(",")
            if item.strip()
        )
        default_expert_model = (
            _optional(values.get("OPENROUTER_EXPERT_MODEL"))
            or "request/model-required"
        )
        expert_models = {
            family: _optional(values.get(env_name)) or default_expert_model
            for family, env_name in _EXPERT_MODEL_ENV.items()
        }
        config = cls(
            model=ModelConfig(
                api_key=_optional(values.get("OPENROUTER_API_KEY")),
                expert_model=default_expert_model,
                expert_models=expert_models,
                validator_model=(
                    _optional(values.get("OPENROUTER_VALIDATOR_MODEL"))
                    or default_expert_model
                ),
                patch_model=(
                    _optional(values.get("OPENROUTER_PATCH_MODEL"))
                    or default_expert_model
                ),
                strong_model=_optional(values.get("OPENROUTER_STRONG_MODEL")),
                sweep_models=sweep_models,
                temperature=_as_optional_float(
                    values.get("OPENROUTER_TEMPERATURE")
                ),
                max_output_tokens=int(values.get("OPENROUTER_MAX_OUTPUT_TOKENS", "2500")),
                reasoning_enabled=_as_optional_bool(
                    values.get("OPENROUTER_REASONING_ENABLED")
                ),
                reasoning_effort=_optional(
                    values.get("OPENROUTER_REASONING_EFFORT", "medium")
                ),
                provider=_optional(values.get("OPENROUTER_PROVIDER")),
                provider_sort=_optional(
                    values.get("OPENROUTER_PROVIDER_SORT", "throughput")
                ),
                provider_ignore=provider_ignore,
                require_parameters=_as_bool(
                    values.get("OPENROUTER_REQUIRE_PARAMETERS", "true")
                ),
                allow_fallbacks=_as_bool(
                    values.get("OPENROUTER_ALLOW_FALLBACKS", "true")
                ),
                structured_output=_as_bool(
                    values.get("OPENROUTER_STRUCTURED_OUTPUT", "true")
                ),
                json_repair=_as_bool(
                    values.get("OPENROUTER_JSON_REPAIR", "false")
                ),
                structured_output_fallback=_as_bool(
                    values.get("OPENROUTER_STRUCTURED_OUTPUT_FALLBACK", "false")
                ),
            ),
            router=RouterConfig(
                high_confidence=float(
                    values.get("ROUTER_HIGH_CONFIDENCE", "0.72")
                ),
                min_margin=float(values.get("ROUTER_MIN_MARGIN", "0.18")),
                max_entropy=float(values.get("ROUTER_MAX_ENTROPY", "1.0")),
                max_experts=int(values.get("ROUTER_MAX_EXPERTS", "2")),
                target_coverage=float(
                    values.get("ROUTER_TARGET_COVERAGE", "0.95")
                ),
                use_rule_fallback=_as_bool(
                    values.get("USE_RULE_FALLBACK", "true")
                ),
            ),
            candidate_selection=CandidateSelectionConfig(
                enabled=_as_bool(
                    values.get("CANDIDATE_SELECTION_ENABLED", "false")
                ),
                threshold=float(
                    values.get("CANDIDATE_SELECTION_THRESHOLD", "0.40")
                ),
            ),
            analysis=AnalysisConfig(
                max_candidates_per_project=int(values.get("MAX_CANDIDATES", "4")),
                context_lines=int(values.get("CONTEXT_LINES", "25")),
                max_context_characters=int(values.get("MAX_CONTEXT_CHARACTERS", "30000")),
                security_knowledge_path=_optional(
                    values.get("SECURITY_KNOWLEDGE_PATH")
                ),
                candidate_ranker_path=_resolve_optional_path(
                    values.get("CANDIDATE_RANKER_PATH"),
                    base_directory=env_path.parent,
                ),
                candidate_ranker_required=_as_bool(
                    values.get("CANDIDATE_RANKER_REQUIRED", "false")
                ),
            ),
            validation=ValidationConfig(
                minimum_confidence=float(values.get("MINIMUM_CONFIDENCE", "0.60")),
                candidate_probability_threshold=float(
                    values.get("CANDIDATE_DECISION_THRESHOLD", "0.28")
                ),
                finding_validation_threshold=float(
                    values.get("FINDING_VALIDATION_THRESHOLD", "0.71")
                ),
                decision_model_path=_resolve_optional_path(
                    values.get("DECISION_MODEL_PATH"),
                    base_directory=env_path.parent,
                ),
                minimum_confidence_by_expert={
                    expert: float(values[env_name])
                    for expert, env_name in _VALIDATOR_CONFIDENCE_ENV.items()
                    if _optional(values.get(env_name)) is not None
                },
                use_llm_for_uncertain=_as_bool(
                    values.get("USE_LLM_FOR_UNCERTAIN", "true")
                ),
            ),
            runtime=RuntimeConfig(
                seed=int(values.get("EXPERIMENT_SEED", "2026")),
                request_timeout_seconds=float(values.get("REQUEST_TIMEOUT_SECONDS", "90")),
                max_retries=int(values.get("MAX_RETRIES", "1")),
                allow_paid_experiments=_as_bool(
                    values.get("RUN_PAID_EXPERIMENTS", "false")
                ),
                run_model_sweep=_as_bool(values.get("RUN_MODEL_SWEEP", "false")),
            ),
        )
        config.validate()
        return config

    def validate(self) -> None:
        if not 0.0 <= self.candidate_selection.threshold <= 1.0:
            raise ValueError(
                "CANDIDATE_SELECTION_THRESHOLD must be between 0 and 1"
            )
        if not 0.0 <= self.router.high_confidence <= 1.0:
            raise ValueError("ROUTER_HIGH_CONFIDENCE must be between 0 and 1")
        if not 0.0 <= self.router.min_margin <= 1.0:
            raise ValueError("ROUTER_MIN_MARGIN must be between 0 and 1")
        if self.router.max_entropy < 0.0:
            raise ValueError("ROUTER_MAX_ENTROPY cannot be negative")
        if self.router.max_experts not in {1, 2}:
            raise ValueError("ROUTER_MAX_EXPERTS must be 1 or 2")
        if not 0.0 <= self.router.target_coverage <= 1.0:
            raise ValueError("ROUTER_TARGET_COVERAGE must be between 0 and 1")
        if self.analysis.max_candidates_per_project < 1:
            raise ValueError("MAX_CANDIDATES must be positive")
        if self.analysis.candidate_ranker_required and not self.analysis.candidate_ranker_path:
            raise ValueError(
                "CANDIDATE_RANKER_PATH is required when CANDIDATE_RANKER_REQUIRED=true"
            )
        if not 0.0 <= self.validation.minimum_confidence <= 1.0:
            raise ValueError("MINIMUM_CONFIDENCE must be between 0 and 1")
        if not (
            0.0
            <= self.validation.candidate_probability_threshold
            <= self.validation.finding_validation_threshold
            <= 1.0
        ):
            raise ValueError(
                "Decision thresholds must satisfy 0 <= low <= high <= 1"
            )
        if self.runtime.request_timeout_seconds <= 0:
            raise ValueError("REQUEST_TIMEOUT_SECONDS must be positive")
        if self.runtime.max_retries < 0:
            raise ValueError("MAX_RETRIES cannot be negative")
        if any(
            not provider or any(character.isspace() for character in provider)
            for provider in self.model.provider_ignore
        ):
            raise ValueError("OPENROUTER_PROVIDER_IGNORE contains an invalid provider")
        if any(
            not 0.0 <= value <= 1.0
            for value in self.validation.minimum_confidence_by_expert.values()
        ):
            raise ValueError(
                "Per-Expert minimum confidence values must be between 0 and 1"
            )
        for model_id in (
            self.model.expert_model,
            self.model.validator_model,
            self.model.patch_model,
            *self.model.expert_models.values(),
        ):
            if not model_id:
                raise ValueError("OpenRouter role model names cannot be empty")
            if model_id.startswith("~"):
                raise ValueError("Experiments require canonical model IDs, not latest aliases")


_EXPERT_MODEL_ENV = {
    ExpertFamily.MEMORY_BOUNDS: "OPENROUTER_MEMORY_MODEL",
    ExpertFamily.LIFETIME_RESOURCE: "OPENROUTER_LIFETIME_MODEL",
    ExpertFamily.INTEGER_SIZE_TYPE: "OPENROUTER_INTEGER_MODEL",
    ExpertFamily.TAINT_API_CONTRACT: "OPENROUTER_TAINT_MODEL",
    ExpertFamily.CONTROL_STATE_ERROR: "OPENROUTER_CONTROL_MODEL",
    ExpertFamily.CONCURRENCY_TOCTOU: "OPENROUTER_CONCURRENCY_MODEL",
}


_VALIDATOR_CONFIDENCE_ENV = {
    ExpertFamily.MEMORY_SAFETY: "MINIMUM_CONFIDENCE_MEMORY_BOUNDS",
    ExpertFamily.LIFETIME_RESOURCE: "MINIMUM_CONFIDENCE_LIFETIME_RESOURCE",
    ExpertFamily.INTEGER_SIZE_TYPE: "MINIMUM_CONFIDENCE_INTEGER_SIZE_TYPE",
    ExpertFamily.TAINT_API_CONTRACT: "MINIMUM_CONFIDENCE_TAINT_API_CONTRACT",
    ExpertFamily.CONTROL_STATE_ERROR: "MINIMUM_CONFIDENCE_CONTROL_STATE_ERROR",
    ExpertFamily.CONCURRENCY_TOCTOU: "MINIMUM_CONFIDENCE_CONCURRENCY_TOCTOU",
}


def _read_env_file(path: str | Path) -> dict[str, str]:
    env_path = Path(path)
    if not env_path.exists():
        return {}
    values: dict[str, str] = {}
    for line_number, raw_line in enumerate(
        env_path.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ValueError(f"Invalid .env entry at line {line_number}")
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _optional(value: str | None) -> str | None:
    return value if value and value.strip() else None


def _resolve_optional_path(
    value: str | None, *, base_directory: Path
) -> str | None:
    normalized = _optional(value)
    if normalized is None:
        return None
    path = Path(normalized).expanduser()
    if not path.is_absolute():
        path = base_directory / path
    return str(path.resolve())


def _required(values: dict[str, str], key: str) -> str:
    value = _optional(values.get(key))
    if value is None:
        raise ValueError(f"{key} must be set in .env or the process environment")
    return value


def _as_optional_float(value: str | None) -> float | None:
    normalized = _optional(value)
    return float(normalized) if normalized is not None else None


def _as_bool(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Invalid boolean value: {value}")


def _as_optional_bool(value: str | None) -> bool | None:
    if value is None or not value.strip():
        return None
    return _as_bool(value)
