"""Property tests: valid configs always parse; invalid numerics always yield path-specific messages."""

from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agentguard.config.loader import config_hash, parse_config
from agentguard.config.models import ALL_TRANSFORMS
from agentguard.core.errors import ConfigError
from agentguard.core.types import AttackCategory

TARGET = {"type": "python_callable", "path": "examples/targets/vulnerable_agent.py:agent"}


valid_run = st.fixed_dictionaries(
    {},
    optional={
        "name": st.text(min_size=1, max_size=20),
        "trials_per_case": st.integers(1, 1000),
        "concurrency": st.integers(1, 512),
        "seed": st.integers(-(2**31), 2**31),
        "timeout_seconds": st.floats(0.001, 3600),
        "max_cost_usd": st.none() | st.floats(0, 1e6),
        "fail_threshold_risk": st.floats(0, 100),
        "status_threshold": st.floats(0.001, 0.999),
        "rate_limit_per_second": st.floats(0, 1e4),
        "max_retries": st.integers(0, 10),
        "max_error_fraction": st.floats(0, 1),
        "max_output_chars": st.integers(1000, 10**7),
        "strict_datasets": st.booleans(),
    },
)

valid_security = st.fixed_dictionaries(
    {},
    optional={
        "enabled": st.booleans(),
        "categories": st.just("all") | st.lists(st.sampled_from([c.value for c in AttackCategory]), max_size=5),
        "mutations": st.fixed_dictionaries(
            {},
            optional={
                "enabled": st.booleans(),
                "per_case": st.integers(0, 20),
                "transforms": st.lists(st.sampled_from(ALL_TRANSFORMS), max_size=5),
            },
        ),
        "adaptive": st.fixed_dictionaries({}, optional={"enabled": st.booleans(), "max_turns": st.integers(1, 20)}),
    },
)

valid_config = st.fixed_dictionaries(
    {"target": st.just(TARGET)},
    optional={
        "version": st.just(1),
        "run": valid_run,
        "suites": st.fixed_dictionaries({}, optional={"security": valid_security}),
        "judge": st.fixed_dictionaries(
            {},
            optional={
                "provider": st.sampled_from(["mock", "anthropic", "openai", "ollama", "litellm"]),
                "ensemble": st.booleans(),
                "max_repair_retries": st.integers(0, 5),
            },
        ),
        "reports": st.fixed_dictionaries(
            {},
            optional={
                "formats": st.lists(st.sampled_from(["html", "json", "sarif", "junit", "markdown"]), unique=True),
                "embed_trials_per_case": st.integers(0, 50),
            },
        ),
    },
)


@given(valid_config)
def test_valid_configs_parse(data: dict) -> None:
    cfg = parse_config(data)
    assert cfg.target.type == "python_callable"
    for key, value in data.get("run", {}).items():
        assert getattr(cfg.run, key) == value
    assert config_hash(cfg) == config_hash(parse_config(cfg.model_dump(mode="json")))


# (yaml path, (min, max) bounds that are valid — values outside are invalid)
NUMERIC_FIELDS = [
    (("run", "trials_per_case"), 1, 1000),
    (("run", "concurrency"), 1, 512),
    (("run", "max_retries"), 0, 10),
    (("run", "max_output_chars"), 1000, None),
    (("suites", "security", "mutations", "per_case"), 0, 20),
    (("suites", "security", "adaptive", "max_turns"), 1, 20),
    (("judge", "max_repair_retries"), 0, 5),
    (("reports", "embed_trials_per_case"), 0, 50),
    (("target", "max_tool_steps"), 1, 100),
]


@st.composite
def invalid_numeric(draw: st.DrawFn) -> tuple[tuple[str, ...], int]:
    path, lo, hi = draw(st.sampled_from(NUMERIC_FIELDS))
    choices = [st.integers(max_value=lo - 1, min_value=lo - 10**6)]
    if hi is not None:
        choices.append(st.integers(min_value=hi + 1, max_value=hi + 10**6))
    value = draw(st.one_of(*choices))
    return path, value


@given(invalid_numeric())
def test_invalid_numeric_values_name_the_path(case: tuple[tuple[str, ...], int]) -> None:
    path, value = case
    data: dict = {"target": dict(TARGET)}
    node = data
    for part in path[:-1]:
        node = node.setdefault(part, {})
    node[path[-1]] = value
    with pytest.raises(ConfigError) as info:
        parse_config(data)
    dotted = ".".join(path)
    msg = str(info.value)
    assert f"{dotted}: must be " in msg
    assert f"(got {value})" in msg
    assert "hint: use a value" in msg


@given(st.sampled_from(["trials_per_case", "concurrency", "max_retries"]), st.text(min_size=1, max_size=5))
def test_non_integer_strings_name_the_path(field: str, text: str) -> None:
    try:
        int(text)
    except ValueError:
        pass
    else:
        return
    with pytest.raises(ConfigError) as info:
        parse_config({"target": TARGET, "run": {field: text}})
    assert f"run.{field}:" in str(info.value)
