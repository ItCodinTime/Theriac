# Debug script — dumps the raw Nemotron API response so we can see if tool calling works.
# Run: venv/bin/python debug_nemotron.py

import asyncio
import json

import httpx

from config import (
    VULTR_INFERENCE_API_KEY,
    VULTR_INFERENCE_BASE_URL,
    VULTR_MAIN_MODEL,
    VULTR_FALLBACK_MODEL,
)
from agent.prompts import TOOLS, agentic_policy_prompt

HEADERS = {
    "Authorization": f"Bearer {VULTR_INFERENCE_API_KEY}",
    "Content-Type": "application/json",
}


async def test_model(model: str):
    print(f"\n{'=' * 70}\nTESTING MODEL: {model}\n{'=' * 70}")

    messages = agentic_policy_prompt(
        device_model="Philips_IntelliVue",
        firmware_version="B.01",
        allowed_ports=[
            {"port": 24105, "protocol": "UDP", "reason": "Data Export Interface (main data channel)"},
            {"port": 104, "protocol": "TCP", "reason": "DICOM imaging"},
        ],
        vpc_id="vpc-medical-01",
    )

    payload = {
        "model": model,
        "messages": messages,
        "tools": TOOLS,
        "tool_choice": "auto",
        "stream": False,
        "max_tokens": 1200,
        "temperature": 0.2,
    }

    try:
        async with httpx.AsyncClient(timeout=90.0) as client:
            resp = await client.post(
                f"{VULTR_INFERENCE_BASE_URL}/chat/completions",
                headers=HEADERS,
                json=payload,
            )
            print(f"HTTP status: {resp.status_code}")
            data = resp.json()
            message = data["choices"][0]["message"]
            print(f"\n--- Has tool_calls? {'YES' if message.get('tool_calls') else 'NO'} ---")
            if message.get("tool_calls"):
                for tc in message["tool_calls"]:
                    print(f"  Tool: {tc['function']['name']}")
                    print(f"  Args: {tc['function']['arguments']}")
            print(f"\n--- Content field ---\n{message.get('content', '(empty)')}")
            print(f"\n--- Full message keys: {list(message.keys())} ---")
    except Exception as e:
        print(f"ERROR: {type(e).__name__}: {e}")


async def main():
    await test_model(VULTR_MAIN_MODEL)
    await test_model(VULTR_FALLBACK_MODEL)


if __name__ == "__main__":
    asyncio.run(main())
