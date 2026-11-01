"""LLM access. Every agent call goes through Vultr Serverless Inference
(OpenAI-compatible, https://api.vultrinference.com/v1). MockLLM exists for tests."""
from __future__ import annotations

import json
import os
import re
from typing import Optional

import httpx

DEFAULT_BASE_URL = "https://api.vultrinference.com/v1"


class LLMError(RuntimeError):
    pass


def strip_reasoning(text: str) -> str:
    return re.sub(r"<think>.*?</think>", "", text, flags=re.S).strip()


def extract_json(text: str) -> dict:
    """Pull the first JSON object out of a model reply (handles ``` fences)."""
    text = strip_reasoning(text)
    fence = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, flags=re.S)
    if fence:
        return json.loads(fence.group(1))
    start = text.find("{")
    if start == -1:
        raise LLMError("no JSON object in model reply")
    depth = 0
    for i in range(start, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return json.loads(text[start:i + 1])
    raise LLMError("unterminated JSON object in model reply")


class VultrLLM:
    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None,
                 base_url: Optional[str] = None, timeout: float = 90.0):
        self.api_key = api_key or os.environ.get("VULTR_INFERENCE_API_KEY", "")
        self.model = model or os.environ.get("TRIPWIRE_MODEL", "")
        self.base_url = (base_url or os.environ.get("VULTR_INFERENCE_BASE_URL") or DEFAULT_BASE_URL).rstrip("/")
        self.timeout = timeout
        self.calls = 0
        if not self.api_key:
            raise LLMError("VULTR_INFERENCE_API_KEY is not set")
        if not self.model:
            raise LLMError("TRIPWIRE_MODEL is not set (pick an id from /v1/models)")

    def chat(self, messages: list, temperature: float = 0.0, max_tokens: int = 2000) -> str:
        self.calls += 1
        r = httpx.post(
            f"{self.base_url}/chat/completions",
            headers={"Authorization": f"Bearer {self.api_key}"},
            json={"model": self.model, "messages": messages,
                  "temperature": temperature, "max_tokens": max_tokens},
            timeout=self.timeout,
        )
        if r.status_code != 200:
            raise LLMError(f"inference HTTP {r.status_code}: {r.text[:200]}")
        return r.json()["choices"][0]["message"]["content"] or ""


class MockLLM:
    """Replays canned replies in order; records prompts for assertions."""

    def __init__(self, replies: list):
        self.replies = list(replies)
        self.prompts: list = []
        self.calls = 0
        self.model = "mock"

    def chat(self, messages: list, temperature: float = 0.0, max_tokens: int = 2000) -> str:
        self.calls += 1
        self.prompts.append(messages)
        if not self.replies:
            raise LLMError("MockLLM ran out of replies")
        return self.replies.pop(0)
