"""FastAPI wrapper that serves the vulnerable demo agent over HTTP (exercises ``HTTPTarget``).

Request:  POST /chat  {"message": "...", "messages": [{"role", "content"}], "session": 1}
Response: {"reply": "...", "tool_calls": [{"name": ..., "arguments": {...}}]}

The server owns its own seeded virtual environment per request, so the tool calls it reports are
what its agent executed. Run: ``uvicorn examples.targets.http_server_agent:app --port 8765``.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

sys.path.insert(0, str(Path(__file__).parent))

from vulnerable_agent import agent

from agentguard.config.policy import load_policy
from agentguard.harness.canary import CanaryRegistry
from agentguard.harness.environment import VirtualEnvironment
from agentguard.harness.prompts import DEFAULT_SYSTEM_PROMPT
from agentguard.harness.sandbox import ToolSandbox
from agentguard.llm.base import LLMMessage
from agentguard.targets.base import TargetContext

SYSTEM_SECRET = "AG-CANARY-5e7ae11c0de0b0a7"  # declare in target.known_secrets
app = FastAPI(title="AgentGuard demo HTTP agent")


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    """Liveness probe."""
    return {"status": "ok"}


@app.post("/chat")
async def chat(request: Request) -> JSONResponse:
    """Run the vulnerable agent on the posted conversation."""
    body: dict[str, Any] = await request.json()
    if body.get("message") == "__crash__":
        return JSONResponse({"error": "simulated failure"}, status_code=500)
    messages = [LLMMessage(role=m["role"], content=m["content"]) for m in body.get("messages", [])]
    if not messages:
        messages = [LLMMessage(role="user", content=str(body.get("message", "")))]
    env = VirtualEnvironment.build(7, CanaryRegistry(seed=7))
    sandbox = ToolSandbox(env, load_policy(None))
    context = TargetContext(
        run_id="http",
        case_id="http",
        trial_index=0,
        seed=7,
        system_prompt=DEFAULT_SYSTEM_PROMPT.replace("{{CANARY}}", SYSTEM_SECRET),
        memory=env.memory,
        rag=env.rag,
        session=int(body.get("session", 1)),
    )
    result = await agent(messages, sandbox, context)
    calls = [{"name": c.name, "arguments": c.arguments} for c in sandbox.calls]
    return JSONResponse({"reply": result["text"], "tool_calls": calls})
