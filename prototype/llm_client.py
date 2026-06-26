"""
llm_client.py — LLM backend abstraction using OpenAI-compatible API.

Supports any backend that follows the OpenAI Chat Completions format:
  - Ollama        (local):  base_url=http://localhost:11434/v1, api_key="ollama"
  - DashScope     (Qwen):   base_url=https://dashscope.aliyuncs.com/compatible-mode/v1
  - DeepSeek:               base_url=https://api.deepseek.com/v1
  - Groq:                   base_url=https://api.groq.com/openai/v1
  - OpenAI:                 base_url=https://api.openai.com/v1  (default)

Tool schemas follow the standard OpenAI function-calling format.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Optional

OpenAI = None


# ---------------------------------------------------------------------------
# Backend presets
# ---------------------------------------------------------------------------

BACKENDS = {
    # Trae: ByteDance IDE tool token — currently only exposes IDE-specific endpoints
    # (/user/profile, /analyze/code), NOT a general LLM chat completions API.
    # If Trae releases an OpenAI-compatible LLM endpoint in future, update base_url here.
    "trae": {
        "base_url": "https://api.trae.cn/v1",
        "api_key_env": "TRAE_TOKEN",
        "default_model": "gpt-4o",  # placeholder; update when Trae exposes LLM API
        "_note": "Not usable as LLM backend until Trae exposes /chat/completions",
    },
    "ollama": {
        "base_url": "http://localhost:11434/v1",
        "api_key": "ollama",
        "default_model": "qwen2.5:7b",
    },
    "dashscope": {
        # JISA v8: standard Bailian endpoint (NOT the Coding Plan sk-sp- key).
        # Try QWEN_TOKEN (v8 default) then DASHSCOPE_API_KEY (v7 fallback).
        "base_url": "https://dashscope.aliyuncs.com/compatible-mode/v1",
        "api_key_env": ["QWEN_TOKEN", "DASHSCOPE_API_KEY"],
        "default_model": "qwen3.5-plus",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "api_key_env": "DEEPSEEK_TOKEN",
        "default_model": "deepseek-v4-pro",
        # JISA v8: deepseek-v4-pro / v4-flash default to thinking mode, which forces
        # callers to round-trip `reasoning_content` across multi-turn conversations.
        # We disable thinking for parity with v7's deepseek-chat baseline and to
        # keep the agent_runner's message construction simple. Reviewers comparing
        # to v7's results are comparing non-thinking behaviour; keep that constant.
        # `disabled` is the documented enum value (alongside `enabled` and `adaptive`).
        "extra_body": {"thinking": {"type": "disabled"}},
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "api_key_env": "GROQ_API_KEY",
        "default_model": "llama-3.3-70b-versatile",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "api_key_env": "OPENAI_API_KEY",
        "default_model": "gpt-4o-mini",
    },
    "openrouter": {
        # OpenRouter: single API key, 100+ models via OpenAI-compatible interface.
        # Model names use provider/model format, e.g.:
        #   meta-llama/llama-3.3-70b-instruct
        #   anthropic/claude-3.5-haiku
        #   openai/gpt-4o-mini
        #   qwen/qwen-2.5-72b-instruct
        #   mistralai/mistral-large
        # JISA v8: try OPENROUTER_TOKEN (v8) then OPENROUTER_API_KEY (v7 fallback).
        "base_url": "https://openrouter.ai/api/v1",
        "api_key_env": ["OPENROUTER_TOKEN", "OPENROUTER_API_KEY"],
        "default_model": "meta-llama/llama-3.3-70b-instruct",
    },
}


# ---------------------------------------------------------------------------
# Tool call result from LLM
# ---------------------------------------------------------------------------

@dataclass
class LLMToolCall:
    id: str
    name: str      # tool name, e.g. "web_search__search"
    args: dict     # parsed arguments


@dataclass
class LLMResponse:
    content: Optional[str]          # text response (when no tool call)
    tool_calls: list[LLMToolCall]   # tool calls requested by LLM
    stop_reason: str                # "tool_calls" | "stop" | "length"
    raw: object                     # raw API response object


# ---------------------------------------------------------------------------
# LLMClient
# ---------------------------------------------------------------------------

class LLMClient:
    """
    Thin wrapper around OpenAI-compatible chat completions API.

    Tool names use "__" as separator internally (e.g. "filesystem__read_file")
    because OpenAI function names cannot contain dots.
    The registry maps "filesystem.read_file" → tool; this client translates.
    """

    def __init__(
        self,
        backend: str = "ollama",
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        temperature: float = 0.0,
        max_tokens: int = 1024,
    ):
        global OpenAI
        if OpenAI is None:
            try:
                from openai import OpenAI as _OpenAI
                OpenAI = _OpenAI
            except ImportError:
                raise ImportError(
                    "The OpenAI SDK is required only for --mode llm. "
                    "Install dependencies with: pip install -r requirements.txt"
                )

        preset = BACKENDS.get(backend, BACKENDS["ollama"])

        resolved_base_url = base_url or preset["base_url"]
        if api_key:
            resolved_api_key = api_key
        elif "api_key" in preset:
            resolved_api_key = preset["api_key"]
        else:
            # api_key_env may be a single string or a list (try in order, first non-empty wins).
            env_vars = preset.get("api_key_env", "OPENAI_API_KEY")
            if isinstance(env_vars, str):
                env_vars = [env_vars]
            resolved_api_key = ""
            for ev in env_vars:
                val = os.environ.get(ev, "")
                if val:
                    resolved_api_key = val
                    break
            if not resolved_api_key:
                raise ValueError(
                    f"API key not found. Set one of {env_vars} "
                    f"or pass api_key= to LLMClient()."
                )

        # Per-request timeout + retries handle transient API stalls (e.g. deepseek
        # half-open connections). Configurable via env so a fail-fast-and-retry policy
        # can be used for batch runs (LLM_TIMEOUT seconds, LLM_MAX_RETRIES count);
        # defaults preserve the prior 180s/2-retry behaviour.
        import os as _os
        _timeout = float(_os.environ.get("LLM_TIMEOUT", "180"))
        _retries = int(_os.environ.get("LLM_MAX_RETRIES", "2"))
        self._client = OpenAI(
            base_url=resolved_base_url,
            api_key=resolved_api_key,
            timeout=_timeout,
            max_retries=_retries,
        )
        self._model = model or preset["default_model"]
        self._temperature = temperature
        self._max_tokens = max_tokens
        self.backend = backend
        # Backend-specific extra body fields (e.g., DeepSeek thinking-mode opt-out).
        # Carried into every chat() call as `extra_body=` to the OpenAI SDK.
        self._extra_body = dict(preset.get("extra_body") or {})

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def chat(
        self,
        messages: list[dict],
        tools: Optional[list[dict]] = None,
        system_prompt: Optional[str] = None,
    ) -> LLMResponse:
        """
        Send a chat request.

        messages: list of {"role": "user"|"assistant"|"tool", "content": ...}
        tools:    list of OpenAI-format tool schemas (optional)
        """
        full_messages = []
        if system_prompt:
            full_messages.append({"role": "system", "content": system_prompt})
        full_messages.extend(messages)

        kwargs = dict(
            model=self._model,
            messages=full_messages,
            temperature=self._temperature,
            max_tokens=self._max_tokens,
        )
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"
        if self._extra_body:
            kwargs["extra_body"] = self._extra_body

        response = self._client.chat.completions.create(**kwargs)
        return self._parse_response(response)

    # ------------------------------------------------------------------
    # Tool schema helpers
    # ------------------------------------------------------------------

    @staticmethod
    def make_tool_schema(
        name: str,          # dot-style: "filesystem.read_file"
        description: str,
        parameters: dict,   # JSON Schema for args
    ) -> dict:
        """Build an OpenAI-format tool schema. Dots in name → double underscores."""
        return {
            "type": "function",
            "function": {
                "name": name.replace(".", "__"),
                "description": description,
                "parameters": parameters,
            },
        }

    @staticmethod
    def tool_name_to_registry(name: str) -> str:
        """Convert LLM tool name back to registry key: "filesystem__read_file" → "filesystem.read_file"."""
        return name.replace("__", ".")

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _parse_response(self, response) -> LLMResponse:
        choice = response.choices[0]
        msg = choice.message
        stop = choice.finish_reason or "stop"

        tool_calls = []
        if msg.tool_calls:
            for tc in msg.tool_calls:
                try:
                    args = json.loads(tc.function.arguments)
                except json.JSONDecodeError:
                    args = {"raw": tc.function.arguments}
                tool_calls.append(LLMToolCall(
                    id=tc.id,
                    name=tc.function.name,
                    args=args,
                ))

        return LLMResponse(
            content=msg.content,
            tool_calls=tool_calls,
            stop_reason="tool_calls" if tool_calls else stop,
            raw=response,
        )
