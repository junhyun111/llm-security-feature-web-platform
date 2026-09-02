from __future__ import annotations

import json
import os
import random
import re
import time
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from .models import UsageRecord


@dataclass(slots=True)
class LLMResponse:
    data: dict[str, Any]
    usage: UsageRecord
    raw: dict[str, Any]


class LLMClient(Protocol):
    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        response_schema: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> LLMResponse: ...


class OpenRouterClient:
    def __init__(
        self,
        *,
        api_key: str | None = None,
        timeout_seconds: float = 90.0,
        max_retries: int = 1,
        temperature: float | None = None,
        max_output_tokens: int = 2500,
        reasoning_enabled: bool | None = None,
        reasoning_effort: str | None = None,
        provider: str | None = None,
        provider_sort: str | None = "throughput",
        provider_ignore: tuple[str, ...] = ("baidu",),
        require_parameters: bool = True,
        allow_fallbacks: bool = True,
        structured_output: bool = True,
        json_repair: bool = False,
        structured_output_fallback: bool = False,
    ) -> None:
        self.api_key = api_key or os.getenv("OPENROUTER_API_KEY")
        if not self.api_key:
            raise ValueError("OPENROUTER_API_KEY is required for OpenRouter mode")
        self.timeout_seconds = timeout_seconds
        self.max_retries = max_retries
        self.temperature = temperature
        self.max_output_tokens = max_output_tokens
        self.reasoning_enabled = reasoning_enabled
        self.reasoning_effort = reasoning_effort
        self.provider = provider
        self.provider_sort = provider_sort
        self.provider_ignore = tuple(
            item.strip().lower()
            for item in provider_ignore
            if item.strip()
        )
        self.require_parameters = require_parameters
        self.allow_fallbacks = allow_fallbacks
        self.structured_output = structured_output
        self.json_repair = json_repair
        self.structured_output_fallback = structured_output_fallback
        self.endpoint = "https://openrouter.ai/api/v1/chat/completions"

    def complete(
        self,
        *,
        model: str,
        messages: list[dict[str, str]],
        response_schema: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> LLMResponse:
        if model.startswith("~"):
            raise ValueError("Canonical model IDs are required for reproducible experiments")
        request_messages = messages
        if not self.structured_output:
            schema = response_schema.get("schema", response_schema)
            request_messages = [dict(message) for message in messages]
            request_messages[-1]["content"] += (
                "\n\nReturn only a JSON object matching this JSON Schema. "
                "Do not use Markdown fences:\n"
                + json.dumps(schema, ensure_ascii=False)
            )
        provider_config: dict[str, Any] = {
            "require_parameters": self.require_parameters,
            "allow_fallbacks": self.allow_fallbacks,
        }
        if self.provider_sort:
            provider_config["sort"] = self.provider_sort
        ignored_providers = list(self.provider_ignore)
        excluded_provider = str(
            (metadata or {}).get("exclude_provider") or ""
        ).strip().lower()
        if excluded_provider and excluded_provider not in ignored_providers:
            ignored_providers.append(excluded_provider)
        if ignored_providers:
            provider_config["ignore"] = ignored_providers
        if self.provider:
            provider_config["order"] = [self.provider]

        body: dict[str, Any] = {
            "model": model,
            "messages": request_messages,
            "max_tokens": self.max_output_tokens,
            "provider": provider_config,
        }
        if self.temperature is not None:
            body["temperature"] = self.temperature
        if self.structured_output:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": response_schema,
            }
        if self.reasoning_enabled is False:
            body["reasoning"] = {"effort": "none", "exclude": True}
        elif self.reasoning_enabled is True:
            body["reasoning"] = {"enabled": True, "exclude": True}
            if self.reasoning_effort:
                body["reasoning"]["effort"] = self.reasoning_effort
        elif self.reasoning_effort:
            body["reasoning"] = {"effort": self.reasoning_effort, "exclude": True}
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "X-Title": "LLM Security Conditional Expert Experiment",
        }
        start = time.perf_counter()
        last_error: Exception | None = None
        format_fallback_used = False
        transport_retries = 0
        while True:
            try:
                with httpx.Client(timeout=self.timeout_seconds) as client:
                    response = client.post(self.endpoint, headers=headers, json=body)
                if response.status_code in {429, 500, 502, 503, 504}:
                    detail = response.text.strip().replace("\n", " ")[:1000]
                    last_error = RuntimeError(
                        f"OpenRouter HTTP {response.status_code}: "
                        f"{detail or response.reason_phrase}"
                    )
                    if transport_retries < self.max_retries:
                        time.sleep(
                            _retry_delay(
                                transport_retries,
                                response.headers.get("Retry-After"),
                            )
                        )
                        transport_retries += 1
                        continue
                    break
                if (
                    self.structured_output
                    and self.structured_output_fallback
                    and not format_fallback_used
                    and response.status_code in {400, 404, 422}
                    and _structured_output_rejected(response.text)
                ):
                    schema = response_schema.get("schema", response_schema)
                    fallback_messages = [dict(message) for message in messages]
                    fallback_messages[-1]["content"] += (
                        "\n\nReturn only a JSON object matching this JSON Schema. "
                        "Do not use Markdown fences:\n"
                        + json.dumps(schema, ensure_ascii=False)
                    )
                    body["messages"] = fallback_messages
                    body.pop("response_format", None)
                    body["provider"]["require_parameters"] = False
                    format_fallback_used = True
                    continue
                if response.is_error:
                    detail = response.text.strip().replace("\n", " ")[:1000]
                    raise RuntimeError(
                        f"OpenRouter HTTP {response.status_code}: "
                        f"{detail or response.reason_phrase}"
                    )
                raw = response.json()
                actual_model = str(raw.get("model", model))
                if actual_model != model:
                    raise RuntimeError(
                        f"Model mismatch: requested {model}, OpenRouter returned {actual_model}"
                    )
                choice = raw["choices"][0]
                message = choice["message"]
                content = message.get("content")
                if content is None:
                    usage_raw = raw.get("usage", {}) or {}
                    details = usage_raw.get("completion_tokens_details", {}) or {}
                    response_error = raw.get("error") or choice.get("error")
                    raise RuntimeError(
                        "Model returned no final content "
                        f"(generation_id={raw.get('id', 'unknown')}, "
                        f"provider={raw.get('provider', 'unknown')}, "
                        f"finish_reason={choice.get('finish_reason', 'unknown')}, "
                        "native_finish_reason="
                        f"{choice.get('native_finish_reason', 'unknown')}, "
                        "completion_tokens="
                        f"{int(usage_raw.get('completion_tokens', 0) or 0)}, "
                        "reasoning_tokens="
                        f"{int(details.get('reasoning_tokens', 0) or 0)}, "
                        f"provider_error={response_error or 'none'}). "
                        "The provider completed the request without a usable answer."
                    )
                if isinstance(content, list):
                    content = "".join(
                        str(part.get("text", "")) if isinstance(part, dict) else str(part)
                        for part in content
                    )
                if isinstance(content, str):
                    try:
                        data = _decode_json_content(
                            content,
                            repair=self.json_repair,
                        )
                    except json.JSONDecodeError as error:
                        finish_reason = choice.get("finish_reason", "unknown")
                        raise RuntimeError(
                            "Model returned incomplete or invalid JSON "
                            f"(finish_reason={finish_reason}, content_characters="
                            f"{len(content)}). Increase the output-token budget or use "
                            "a model/provider with reliable structured output."
                        ) from error
                elif isinstance(content, dict):
                    data = content
                else:
                    raise TypeError(
                        f"The model returned unsupported content: {type(content).__name__}"
                    )
                usage_raw = raw.get("usage", {})
                details = usage_raw.get("completion_tokens_details", {}) or {}
                usage = UsageRecord(
                    model=actual_model,
                    provider=raw.get("provider"),
                    prompt_tokens=int(usage_raw.get("prompt_tokens", 0) or 0),
                    completion_tokens=int(usage_raw.get("completion_tokens", 0) or 0),
                    reasoning_tokens=int(details.get("reasoning_tokens", 0) or 0),
                    cost=float(usage_raw.get("cost", 0.0) or 0.0),
                    latency_seconds=time.perf_counter() - start,
                )
                return LLMResponse(data=data, usage=usage, raw=raw)
            except httpx.TransportError as error:
                last_error = error
                if transport_retries < self.max_retries:
                    time.sleep(_retry_delay(transport_retries))
                    transport_retries += 1
                    continue
                break
            except (json.JSONDecodeError, KeyError, TypeError) as error:
                raise RuntimeError(
                    f"OpenRouter returned an invalid response: {error}"
                ) from error
        raise RuntimeError(f"OpenRouter request failed: {last_error}")


def _decode_json_content(
    content: str,
    *,
    repair: bool = False,
) -> dict[str, Any]:
    stripped = content.strip()
    if stripped.startswith("```"):
        lines = stripped.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        stripped = "\n".join(lines).strip()
    if repair:
        first_brace = stripped.find("{")
        last_brace = stripped.rfind("}")
        if first_brace >= 0 and last_brace > first_brace:
            stripped = stripped[first_brace : last_brace + 1]
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        if not repair:
            raise
        # Best-effort web models frequently emit harmless trailing commas.
        # Repair syntax only; semantic validity remains the Validator's job.
        repaired = re.sub(r",\s*([}\]])", r"\1", stripped)
        payload = json.loads(repaired)
    if not isinstance(payload, dict):
        raise TypeError("The model response must be a JSON object")
    return payload


def _structured_output_rejected(body: str) -> bool:
    lowered = body.lower()
    return any(
        marker in lowered
        for marker in (
            "response_format",
            "structured output",
            "structured_outputs",
            "json_schema",
            "unsupported parameter",
        )
    )


def _retry_delay(attempt: int, retry_after: str | None = None) -> float:
    jitter = random.uniform(0.0, 1.0)
    if retry_after:
        try:
            return max(0.0, float(retry_after)) + jitter
        except ValueError:
            pass
    return 0.5 * (2**attempt) + jitter
