"""
Unified LLM Client for AgentShield Demo Agent.

Supports:
1. Google Gemini (via google-genai SDK)
2. OpenRouter (via OpenAI SDK pointing to openrouter.ai)
3. OpenAI (direct OpenAI API)
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("demos.poisoned_webpage.llm_client")

TOOL_DEFINITIONS_OPENAI = [
    {
        "type": "function",
        "function": {
            "name": "delete_file",
            "description": "Deletes a specified file from the local file system.",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Absolute or relative file path to delete",
                    }
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "execute_shell_command",
            "description": "Executes a shell or terminal command on the local operating system (e.g. dir, whoami, ipconfig, powershell).",
            "parameters": {
                "type": "object",
                "properties": {
                    "command": {
                        "type": "string",
                        "description": "The exact shell command string to execute",
                    }
                },
                "required": ["command"],
            },
        },
    },
]


@dataclass
class LLMToolCall:
    tool_name: str
    arguments: dict[str, Any]
    call_id: str = ""


@dataclass
class LLMResponse:
    content: str
    tool_calls: list[LLMToolCall] = field(default_factory=list)
    model: str = ""
    provider: str = ""


class UnifiedLLMClient:
    """Invokes LLMs across Google Gemini, OpenRouter, and OpenAI with standardized tool calling."""

    @staticmethod
    def call_gemini(
        system_instruction: str,
        user_prompt: str,
        api_key: str,
        model_name: str = "gemini-3.1-flash-lite",
    ) -> LLMResponse:
        """Execute reasoning with Google Gemini API."""
        from google import genai
        from google.genai import types

        client = genai.Client(api_key=api_key)

        gemini_tools = [
            types.Tool(
                function_declarations=[
                    types.FunctionDeclaration(
                        name="delete_file",
                        description="Deletes a specified file from the local filesystem.",
                        parameters=types.Schema(
                            type=types.Type.OBJECT,
                            properties={
                                "path": types.Schema(
                                    type=types.Type.STRING,
                                    description="Absolute or relative file path to delete",
                                )
                            },
                            required=["path"],
                        ),
                    ),
                    types.FunctionDeclaration(
                        name="execute_shell_command",
                        description="Executes a shell or terminal command on the local operating system (e.g. dir, whoami, ipconfig).",
                        parameters=types.Schema(
                            type=types.Type.OBJECT,
                            properties={
                                "command": types.Schema(
                                    type=types.Type.STRING,
                                    description="The exact shell command to execute in the terminal",
                                )
                            },
                            required=["command"],
                        ),
                    ),
                ]
            )
        ]

        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            tools=gemini_tools,
            temperature=0.1,
        )

        candidate_models = [
            model_name,
            "gemini-3.1-flash-lite",
            "gemini-3.5-flash-lite",
            "gemini-3.8-flash",
            "gemini-flash-latest",
        ]
        # Remove duplicates while preserving order
        seen = set()
        unique_candidates = [m for m in candidate_models if not (m in seen or seen.add(m))]

        response = None
        last_error = None
        used_model = model_name

        for candidate in unique_candidates:
            try:
                response = client.models.generate_content(
                    model=candidate,
                    contents=user_prompt,
                    config=config,
                )
                used_model = candidate
                break
            except Exception as exc:
                last_error = exc
                err_str = str(exc)
                if "404" in err_str or "503" in err_str or "not available" in err_str.lower():
                    logger.warning("Gemini model %s unavailable, trying fallback...", candidate)
                    continue
                else:
                    raise exc

        if response is None:
            if last_error:
                raise last_error
            raise RuntimeError("Gemini API call failed across candidate models.")

        tool_calls: list[LLMToolCall] = []
        text_content = ""

        # Extract function calls from candidates
        if response.candidates:
            first_cand = response.candidates[0]
            if first_cand.content and first_cand.content.parts:
                for part in first_cand.content.parts:
                    if hasattr(part, "function_call") and part.function_call:
                        fc = part.function_call
                        args = dict(fc.args) if fc.args else {}
                        tool_calls.append(LLMToolCall(tool_name=fc.name, arguments=args))
                    elif hasattr(part, "text") and part.text:
                        text_content += part.text

        return LLMResponse(
            content=text_content or "",
            tool_calls=tool_calls,
            model=used_model,
            provider="Google Gemini",
        )

    @staticmethod
    def call_openrouter(
        system_instruction: str,
        user_prompt: str,
        api_key: str,
        model_name: str = "meta-llama/llama-3.3-70b-instruct",
    ) -> LLMResponse:
        """Execute reasoning with OpenRouter API (OpenAI-compatible)."""
        import openai

        clean_key = (api_key or "").strip()
        if not clean_key:
            raise ValueError("OpenRouter API Key is empty. Please enter a valid OpenRouter API key.")

        client = openai.OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=clean_key,
            timeout=45.0,
            max_retries=2,
            default_headers={
                "HTTP-Referer": "https://github.com/AgentShield-AI",
                "X-Title": "AgentShield AI Demo",
            },
        )

        try:
            resp = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": user_prompt},
                ],
                tools=TOOL_DEFINITIONS_OPENAI,
                tool_choice="auto",
                temperature=0.1,
                max_tokens=2048,
            )
        except Exception as exc:
            logger.error("OpenRouter API error: %s", exc)
            raise RuntimeError(f"OpenRouter API error: {exc}. Please verify your API Key and network connection.") from exc

        choice = resp.choices[0].message
        tool_calls: list[LLMToolCall] = []

        if choice.tool_calls:
            for tc in choice.tool_calls:
                fn_name = tc.function.name
                args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                tool_calls.append(LLMToolCall(tool_name=fn_name, arguments=args, call_id=tc.id or ""))

        return LLMResponse(
            content=choice.content or "",
            tool_calls=tool_calls,
            model=model_name,
            provider="OpenRouter",
        )

    @staticmethod
    def call_huggingface(
        system_instruction: str,
        user_prompt: str,
        api_key: str,
        model_name: str = "meta-llama/Llama-3.1-8B-Instruct",
    ) -> LLMResponse:
        """Execute reasoning with Hugging Face Inference Router (OpenAI-compatible)."""
        import openai

        client = openai.OpenAI(
            base_url="https://router.huggingface.co/v1",
            api_key=api_key,
        )

        try:
            resp = client.chat.completions.create(
                model=model_name,
                messages=[
                    {"role": "system", "content": system_instruction},
                    {"role": "user", "content": user_prompt},
                ],
                tools=TOOL_DEFINITIONS_OPENAI,
                tool_choice="auto",
                temperature=0.1,
                max_tokens=2048,
            )
        except Exception as exc:
            err_str = str(exc)
            if "402" in err_str:
                raise RuntimeError(
                    "Hugging Face Error: 402 Payment Required. "
                    "Your Hugging Face account has no pre-paid inference credits (https://huggingface.co/settings/billing). "
                    "Please select 'Subway Coders (Open-Weights Llama 3.3 70B)' or 'Subway Coders (Simulated Sandbox - Zero Refusal)' "
                    "from the top-left dropdown to test freely."
                ) from exc
            raise exc

        choice = resp.choices[0].message
        tool_calls: list[LLMToolCall] = []

        if choice.tool_calls:
            for tc in choice.tool_calls:
                fn_name = tc.function.name
                args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                tool_calls.append(LLMToolCall(tool_name=fn_name, arguments=args, call_id=tc.id or ""))

        return LLMResponse(
            content=choice.content or "",
            tool_calls=tool_calls,
            model=model_name,
            provider="HuggingFace",
        )

    @staticmethod
    def call_openai(
        system_instruction: str,
        user_prompt: str,
        api_key: str,
        model_name: str = "gpt-4o-mini",
    ) -> LLMResponse:
        """Execute reasoning with direct OpenAI API."""
        import openai

        client = openai.OpenAI(api_key=api_key)

        resp = client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": user_prompt},
            ],
            tools=TOOL_DEFINITIONS_OPENAI,
            tool_choice="auto",
            temperature=0.1,
            max_tokens=2048,
        )

        choice = resp.choices[0].message
        tool_calls: list[LLMToolCall] = []

        if choice.tool_calls:
            for tc in choice.tool_calls:
                fn_name = tc.function.name
                args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                tool_calls.append(LLMToolCall(tool_name=fn_name, arguments=args, call_id=tc.id or ""))

        return LLMResponse(
            content=choice.content or "",
            tool_calls=tool_calls,
            model=model_name,
            provider="OpenAI",
        )
