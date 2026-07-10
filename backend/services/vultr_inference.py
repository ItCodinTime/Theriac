# Vultr Serverless Inference API client. Handles streaming, tool calling, and reasoning token forwarding.

import json
import inspect
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import AsyncGenerator, Awaitable, Callable

import httpx

BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from config import (
    VULTR_FALLBACK_MODEL,
    VULTR_INFERENCE_API_KEY,
    VULTR_INFERENCE_BASE_URL,
    VULTR_INFERENCE_TIMEOUT,
    VULTR_MAIN_MODEL,
    VULTR_MAX_TOKENS,
    VULTR_TEMPERATURE,
    VULTR_TOOL_MODEL,
)

HEADERS = {
    "Authorization": f"Bearer {VULTR_INFERENCE_API_KEY}",
    "Content-Type": "application/json",
}


@dataclass
class StreamToken:
    """A single token emitted during streaming. type is 'reasoning' or 'content'."""
    text: str
    type: str = "content"


@dataclass
class ToolCallRequest:
    """Nemotron wants to invoke a tool."""
    call_id: str
    name: str
    arguments: dict = field(default_factory=dict)


def _base_payload(model: str, messages: list[dict], max_tokens: int | None = None) -> dict:
    return {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens or VULTR_MAX_TOKENS,
        "temperature": VULTR_TEMPERATURE,
    }


# ---------------------------------------------------------------------------
# Streaming (reasoning + content tokens)
# ---------------------------------------------------------------------------

async def _stream_raw(model: str, messages: list[dict], max_tokens: int | None = None) -> AsyncGenerator[StreamToken, None]:
    """Streams reasoning and content tokens from a single model, labelling each."""
    payload = {**_base_payload(model, messages, max_tokens), "stream": True}

    async with httpx.AsyncClient(timeout=VULTR_INFERENCE_TIMEOUT) as client:
        async with client.stream(
            "POST",
            f"{VULTR_INFERENCE_BASE_URL}/chat/completions",
            headers=HEADERS,
            json=payload,
        ) as response:
            response.raise_for_status()
            async for line in response.aiter_lines():
                if not line.startswith("data: "):
                    continue
                data = line[len("data: "):]
                if data.strip() == "[DONE]":
                    break
                try:
                    choices = json.loads(data).get("choices") or []
                    if not choices:
                        continue
                    delta = choices[0].get("delta") or {}
                    reasoning = delta.get("reasoning") or delta.get("reasoning_content") or ""
                    content = delta.get("content") or ""
                    if reasoning:
                        yield StreamToken(text=reasoning, type="reasoning")
                    if content:
                        yield StreamToken(text=content, type="content")
                except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                    continue


async def stream_completion(messages: list[dict], max_tokens: int | None = None) -> AsyncGenerator[StreamToken, None]:
    """
    Public streaming interface. Falls back to VULTR_FALLBACK_MODEL on timeout/error.
    Yields StreamToken objects so callers can distinguish reasoning from content.
    """
    try:
        async for token in _stream_raw(VULTR_MAIN_MODEL, messages, max_tokens):
            yield token
    except httpx.TimeoutException:
        yield StreamToken(text=f"[WARN: {VULTR_MAIN_MODEL} timed out — switching to {VULTR_FALLBACK_MODEL}]", type="reasoning")
        try:
            async for token in _stream_raw(VULTR_FALLBACK_MODEL, messages, max_tokens):
                yield token
        except Exception as e:
            yield StreamToken(text=f"[ERROR: {e}]", type="reasoning")
    except httpx.HTTPStatusError as e:
        yield StreamToken(text=f"[WARN: {VULTR_MAIN_MODEL} HTTP {e.response.status_code} — switching to {VULTR_FALLBACK_MODEL}]", type="reasoning")
        try:
            async for token in _stream_raw(VULTR_FALLBACK_MODEL, messages, max_tokens):
                yield token
        except Exception as fallback_err:
            yield StreamToken(text=f"[ERROR: {fallback_err}]", type="reasoning")
    except Exception as e:
        yield StreamToken(text=f"[ERROR: {e}]", type="reasoning")


async def complete(messages: list[dict], max_tokens: int | None = None) -> str:
    """Collects full streamed response as a single string. Prefers content tokens; falls back to reasoning if content is empty."""
    content_parts = []
    reasoning_parts = []
    async for token in stream_completion(messages, max_tokens):
        if token.type == "content":
            content_parts.append(token.text)
        else:
            reasoning_parts.append(token.text)
    # Some Nemotron models emit the answer inside reasoning_content with no separate content field
    return "".join(content_parts) or "".join(reasoning_parts)


# ---------------------------------------------------------------------------
# Agentic tool calling — Nemotron drives the loop
# ---------------------------------------------------------------------------

async def run_agentic_loop(
    messages: list[dict],
    tools: list[dict],
    tool_executor: Callable[[str, dict], str | Awaitable[str]],
    on_token: Callable[[StreamToken], Awaitable[None]] | None = None,
) -> dict:
    """
    Runs Nemotron in an agentic tool-calling loop.

    - tools: list of tool schemas from prompts.TOOLS
    - tool_executor: called when Nemotron requests a tool. Receives (tool_name, arguments),
      returns a string result to feed back to the model.
    - on_token: optional callback for streaming reasoning/content tokens to the WebSocket.

    Returns the final assistant message dict once Nemotron stops calling tools.
    """
    history = list(messages)

    for _ in range(10):  # max 10 tool call rounds to prevent infinite loops
        payload = {
            **_base_payload(VULTR_TOOL_MODEL, history),
            "tools": tools,
            "tool_choice": "auto",
            "stream": False,
        }

        try:
            async with httpx.AsyncClient(timeout=VULTR_INFERENCE_TIMEOUT) as client:
                resp = await client.post(
                    f"{VULTR_INFERENCE_BASE_URL}/chat/completions",
                    headers=HEADERS,
                    json=payload,
                )
                resp.raise_for_status()
                response_data = resp.json()
        except (httpx.TimeoutException, httpx.HTTPStatusError) as e:
            return {"role": "assistant", "content": f"[ERROR: {e}]"}

        message = response_data["choices"][0]["message"]

        # Stream any reasoning tokens to the WebSocket
        reasoning = message.get("reasoning") or message.get("reasoning_content") or ""
        if reasoning and on_token:
            for chunk in _chunk_text(reasoning):
                await on_token(StreamToken(text=chunk, type="reasoning"))

        # If no tool calls, Nemotron is done — return the final message
        if not message.get("tool_calls"):
            if on_token and message.get("content"):
                for chunk in _chunk_text(message["content"]):
                    await on_token(StreamToken(text=chunk, type="content"))
            return message

        # Append a sanitized assistant message — only fields the API expects.
        # Raw message has null audio/function_call/reasoning fields that break the next round.
        history.append({
            "role": "assistant",
            "content": message.get("content"),
            "tool_calls": message["tool_calls"],
        })
        for tool_call in message["tool_calls"]:
            fn = tool_call["function"]
            tool_name = fn["name"]
            try:
                arguments = json.loads(fn["arguments"])
            except json.JSONDecodeError:
                arguments = {}

            if on_token:
                await on_token(StreamToken(text=f"\n[TOOL CALL → {tool_name}({arguments})]\n", type="reasoning"))

            result = tool_executor(tool_name, arguments)
            if inspect.isawaitable(result):
                result = await result

            if on_token:
                await on_token(StreamToken(text=f"[TOOL RESULT ← {result}]\n", type="reasoning"))

            history.append({
                "role": "tool",
                "tool_call_id": tool_call["id"],
                "content": str(result),
            })

    return {"role": "assistant", "content": "[ERROR: max tool call rounds exceeded]"}


def _chunk_text(text: str, size: int = 20) -> list[str]:
    """Split text into small chunks for realistic streaming simulation."""
    return [text[i:i + size] for i in range(0, len(text), size)]
