from __future__ import annotations

import copy
import unittest
from unittest.mock import patch

import httpx

from llm_security.llm import OpenRouterClient


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        *,
        payload: dict | None = None,
        text: str = "",
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.payload = payload or {}
        self.text = text
        self.headers = headers or {}
        self.reason_phrase = "test response"

    @property
    def is_error(self) -> bool:
        return self.status_code >= 400

    def json(self) -> dict:
        return self.payload


class FakeHttpClient:
    def __init__(self, responses: list[FakeResponse | Exception]) -> None:
        self.responses = responses
        self.call_count = 0
        self.calls: list[dict] = []

    def __enter__(self) -> FakeHttpClient:
        return self

    def __exit__(self, *args) -> None:
        return None

    def post(self, *args, **kwargs) -> FakeResponse:
        self.calls.append(copy.deepcopy(kwargs))
        response = self.responses[self.call_count]
        self.call_count += 1
        if isinstance(response, Exception):
            raise response
        return response


def success_response() -> FakeResponse:
    return FakeResponse(
        200,
        payload={
            "model": "test/model",
            "provider": "test-provider",
            "choices": [
                {
                    "message": {"content": '{"findings": []}'},
                    "finish_reason": "stop",
                }
            ],
            "usage": {},
        },
    )


class OpenRouterRetryTest(unittest.TestCase):
    def client(self) -> OpenRouterClient:
        return OpenRouterClient(
            api_key="test-key",
            max_retries=1,
            timeout_seconds=90,
        )

    def complete(self, client: OpenRouterClient):
        return client.complete(
            model="test/model",
            messages=[{"role": "user", "content": "test"}],
            response_schema={
                "name": "test",
                "strict": True,
                "schema": {
                    "type": "object",
                    "properties": {"findings": {"type": "array"}},
                    "required": ["findings"],
                    "additionalProperties": False,
                },
            },
        )

    def test_rate_limit_is_retried_once(self) -> None:
        transport = FakeHttpClient(
            [
                FakeResponse(429, text="rate limited", headers={"Retry-After": "1"}),
                success_response(),
            ]
        )

        with (
            patch("llm_security.llm.httpx.Client", return_value=transport),
            patch("llm_security.llm.time.sleep") as sleep,
            patch("llm_security.llm.random.uniform", return_value=0.25),
        ):
            response = self.complete(self.client())

        self.assertEqual({"findings": []}, response.data)
        self.assertEqual(2, transport.call_count)
        sleep.assert_called_once_with(1.25)

    def test_authentication_error_is_not_retried(self) -> None:
        transport = FakeHttpClient([FakeResponse(401, text="invalid API key")])

        with patch("llm_security.llm.httpx.Client", return_value=transport):
            with self.assertRaisesRegex(RuntimeError, "OpenRouter HTTP 401"):
                self.complete(self.client())

        self.assertEqual(1, transport.call_count)

    def test_invalid_json_is_not_retried(self) -> None:
        invalid = success_response()
        invalid.payload["choices"][0]["message"]["content"] = "{"
        transport = FakeHttpClient([invalid, success_response()])

        with patch("llm_security.llm.httpx.Client", return_value=transport):
            with self.assertRaisesRegex(RuntimeError, "incomplete or invalid JSON"):
                self.complete(self.client())

        self.assertEqual(1, transport.call_count)

    def test_network_timeout_is_retried_once(self) -> None:
        transport = FakeHttpClient(
            [
                httpx.ReadTimeout("timed out"),
                success_response(),
            ]
        )

        with (
            patch("llm_security.llm.httpx.Client", return_value=transport),
            patch("llm_security.llm.time.sleep") as sleep,
            patch("llm_security.llm.random.uniform", return_value=0.0),
        ):
            response = self.complete(self.client())

        self.assertEqual({"findings": []}, response.data)
        self.assertEqual(2, transport.call_count)
        sleep.assert_called_once_with(0.5)

    def test_provider_routing_excludes_baidu_and_disables_reasoning(self) -> None:
        transport = FakeHttpClient([success_response()])
        client = OpenRouterClient(
            api_key="test-key",
            max_retries=1,
            timeout_seconds=90,
            reasoning_enabled=False,
            provider_sort="throughput",
            provider_ignore=("baidu", "example-provider"),
        )

        with patch("llm_security.llm.httpx.Client", return_value=transport):
            self.complete(client)

        body = transport.calls[0]["json"]
        self.assertEqual("throughput", body["provider"]["sort"])
        self.assertEqual(
            ["baidu", "example-provider"],
            body["provider"]["ignore"],
        )
        self.assertEqual(
            {"effort": "none", "exclude": True},
            body["reasoning"],
        )

    def test_web_json_repair_accepts_fenced_json_with_trailing_comma(self) -> None:
        repaired = success_response()
        repaired.payload["choices"][0]["message"]["content"] = (
            '```json\n{"findings": [],}\n```'
        )
        transport = FakeHttpClient([repaired])
        client = OpenRouterClient(
            api_key="test-key",
            max_retries=0,
            json_repair=True,
        )

        with patch("llm_security.llm.httpx.Client", return_value=transport):
            response = self.complete(client)

        self.assertEqual({"findings": []}, response.data)

    def test_structured_output_rejection_falls_back_to_prompt_schema(self) -> None:
        transport = FakeHttpClient([
            FakeResponse(
                400,
                text="response_format json_schema is an unsupported parameter",
            ),
            success_response(),
        ])
        client = OpenRouterClient(
            api_key="test-key",
            max_retries=0,
            structured_output_fallback=True,
        )

        with patch("llm_security.llm.httpx.Client", return_value=transport):
            response = self.complete(client)

        self.assertEqual({"findings": []}, response.data)
        self.assertIn("response_format", transport.calls[0]["json"])
        self.assertNotIn("response_format", transport.calls[1]["json"])
        self.assertFalse(
            transport.calls[1]["json"]["provider"]["require_parameters"]
        )
        self.assertIn(
            "Return only a JSON object matching this JSON Schema",
            transport.calls[1]["json"]["messages"][-1]["content"],
        )

    def test_format_fallback_does_not_consume_transport_retry_budget(self) -> None:
        transport = FakeHttpClient([
            FakeResponse(400, text="response_format json_schema unsupported"),
            FakeResponse(429, text="rate limited"),
            success_response(),
        ])
        client = OpenRouterClient(
            api_key="test-key",
            max_retries=1,
            structured_output_fallback=True,
        )

        with (
            patch("llm_security.llm.httpx.Client", return_value=transport),
            patch("llm_security.llm.time.sleep") as sleep,
            patch("llm_security.llm.random.uniform", return_value=0.0),
        ):
            response = self.complete(client)

        self.assertEqual({"findings": []}, response.data)
        self.assertEqual(3, transport.call_count)
        sleep.assert_called_once_with(0.5)


if __name__ == "__main__":
    unittest.main()
