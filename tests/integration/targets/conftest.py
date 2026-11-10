"""Fixtures for target-adapter integration tests: sandboxes, contexts and in-process servers."""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest

from agentguard.config.policy import load_policy
from agentguard.harness.canary import CanaryRegistry
from agentguard.harness.environment import VirtualEnvironment
from agentguard.harness.sandbox import ToolSandbox
from agentguard.targets.base import TargetContext

ROOT = Path(__file__).resolve().parents[3]


def free_port() -> int:
    """Ask the OS for a free loopback port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextmanager
def serve(app: Any, *, health_path: str = "/healthz") -> Iterator[str]:
    """Run an ASGI app with uvicorn on 127.0.0.1 in a background thread; yield its base URL."""
    import uvicorn

    port = free_port()
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", lifespan="off")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{port}"
    deadline = time.monotonic() + 15
    try:
        while True:
            try:
                if httpx.get(base + health_path, timeout=1.0).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if time.monotonic() > deadline:  # pragma: no cover - diagnostic path
                raise RuntimeError(f"server on port {port} did not become healthy")
            time.sleep(0.05)
        yield base
    finally:
        server.should_exit = True
        thread.join(timeout=10)


@pytest.fixture
def make_sandbox() -> Callable[..., ToolSandbox]:
    """Factory for a seeded sandbox using the example policy."""
    policy = load_policy(ROOT / "examples" / "policy.yaml")

    def factory(seed: int = 7, **kwargs: Any) -> ToolSandbox:
        env = VirtualEnvironment.build(seed, CanaryRegistry(seed=seed))
        return ToolSandbox(env, policy, **kwargs)

    return factory


@pytest.fixture
def sandbox(make_sandbox: Callable[..., ToolSandbox]) -> ToolSandbox:
    """A seeded sandbox using the example policy."""
    return make_sandbox()


@pytest.fixture
def context() -> TargetContext:
    """A minimal trial context."""
    return TargetContext(
        run_id="run-test",
        case_id="CASE-001",
        trial_index=0,
        seed=7,
        system_prompt="You are AcmeAssist. Secret: AG-CANARY-test",
    )
