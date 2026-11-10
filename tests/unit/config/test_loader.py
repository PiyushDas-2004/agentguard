"""Tests for agentguard.config.loader: path-specific errors, env interpolation, hashing."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from agentguard.config.loader import (
    config_hash,
    format_validation_error,
    interpolate_env,
    load_config,
    parse_config,
    resolve_path,
)
from agentguard.config.models import AgentGuardConfig, MutationConfig
from agentguard.core.errors import ConfigError

MINIMAL = {"target": {"type": "python_callable", "path": "examples/targets/vulnerable_agent.py:agent"}}


def _write(tmp_path: Path, data: object, name: str = "agentguard.yaml") -> Path:
    path = tmp_path / name
    path.write_text(yaml.safe_dump(data) if not isinstance(data, str) else data, encoding="utf-8")
    return path


def _with(**overrides: object) -> dict:
    data = {"target": dict(MINIMAL["target"])}
    data.update(overrides)
    return data


class TestLoadConfig:
    def test_example_demo_loads(self) -> None:
        cfg = load_config("examples/demo.yaml")
        assert cfg.run.name == "demo-vulnerable"
        assert cfg.suites.security.mutations.per_case == 3
        assert cfg.target.llm.provider == "mock"

    def test_minimal_defaults(self, tmp_path: Path) -> None:
        cfg = load_config(_write(tmp_path, MINIMAL))
        assert cfg.version == 1
        assert cfg.run.trials_per_case == 5
        assert cfg.suites.security.categories == "all"
        assert cfg.suites.quality is None
        assert cfg.reports.formats == ["html", "json", "sarif", "junit", "markdown"]

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError) as info:
            load_config(tmp_path / "nope.yaml")
        assert "config file not found" in str(info.value)
        assert "agentguard init" in str(info.value)

    def test_yaml_syntax_error_reports_line(self, tmp_path: Path) -> None:
        path = _write(tmp_path, "version: 1\nrun:\n  name: [unclosed\ntarget: {type: x}\n")
        with pytest.raises(ConfigError) as info:
            load_config(path)
        msg = str(info.value)
        assert "invalid YAML" in msg
        assert "at line" in msg
        assert str(path) in msg

    @pytest.mark.parametrize(("text", "kind"), [("- a\n- b\n", "list"), ("just a string\n", "str"), ("", "NoneType")])
    def test_non_mapping_root(self, tmp_path: Path, text: str, kind: str) -> None:
        with pytest.raises(ConfigError) as info:
            load_config(_write(tmp_path, text))
        assert "top level must be a mapping" in str(info.value)
        assert f"(got {kind})" in str(info.value)

    def test_unreadable_file(self, tmp_path: Path) -> None:
        path = tmp_path / "bin.yaml"
        path.write_bytes(b"\xff\xfe\x00bad")
        with pytest.raises(ConfigError, match="cannot read config"):
            load_config(path)

    def test_negative_per_case_message(self, tmp_path: Path) -> None:
        data = _with(suites={"security": {"mutations": {"per_case": -1}}})
        with pytest.raises(ConfigError) as info:
            load_config(_write(tmp_path, data))
        msg = str(info.value)
        assert "suites.security.mutations.per_case: must be >= 0 (got -1)" in msg
        assert "hint: use a value >= 0" in msg
        assert msg.startswith("invalid configuration in ")

    def test_unknown_key(self, tmp_path: Path) -> None:
        data = _with(run={"trails_per_case": 3})
        with pytest.raises(ConfigError) as info:
            load_config(_write(tmp_path, data))
        msg = str(info.value)
        assert "run.trails_per_case: is not a recognised key" in msg
        assert "remove this key or check its spelling" in msg

    def test_missing_target(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError) as info:
            load_config(_write(tmp_path, {"version": 1}))
        msg = str(info.value)
        assert "target: is required" in msg
        assert "add this required key" in msg
        assert "(got" not in msg.split("target:")[1].splitlines()[0]

    def test_literal_error_hint(self, tmp_path: Path) -> None:
        data = _with(judge={"provider": "gpt"})
        with pytest.raises(ConfigError) as info:
            load_config(_write(tmp_path, data))
        msg = str(info.value)
        assert "judge.provider:" in msg
        assert "(got 'gpt')" in msg
        assert "allowed values:" in msg

    def test_list_index_in_path(self, tmp_path: Path) -> None:
        data = _with(reports={"formats": ["html", "pdf"]})
        with pytest.raises(ConfigError) as info:
            load_config(_write(tmp_path, data))
        assert "reports.formats[1]:" in str(info.value)

    def test_categories_invalid(self, tmp_path: Path) -> None:
        data = _with(suites={"security": {"categories": ["PI_DIRECT", "NOPE"]}})
        with pytest.raises(ConfigError) as info:
            load_config(_write(tmp_path, data))
        assert "suites.security.categories" in str(info.value)

    def test_unknown_transform(self) -> None:
        with pytest.raises(ConfigError) as info:
            parse_config(_with(suites={"security": {"mutations": {"transforms": ["base64", "nope"]}}}))
        msg = str(info.value)
        assert "suites.security.mutations.transforms:" in msg
        assert "unknown transform(s) ['nope']" in msg
        assert "Value error" not in msg

    def test_target_required_field(self) -> None:
        with pytest.raises(ConfigError) as info:
            parse_config({"target": {"type": "http"}})
        assert "target: target type 'http' requires 'url'" in str(info.value)

    @pytest.mark.parametrize(
        ("ttype", "field", "value"),
        [
            ("python_callable", "path", "a.py:f"),
            ("http", "url", "http://x"),
            ("openai_compat", "url", "http://x"),
            ("langchain", "path", "a.py:f"),
            ("mcp", "command", "server"),
        ],
    )
    def test_target_types_ok(self, ttype: str, field: str, value: str) -> None:
        cfg = parse_config({"target": {"type": ttype, field: value}})
        assert getattr(cfg.target, field) == value

    def test_plugin_target_needs_nothing(self) -> None:
        assert parse_config({"target": {"type": "my_plugin"}}).target.type == "my_plugin"

    def test_type_errors_and_hints(self) -> None:
        with pytest.raises(ConfigError) as info:
            parse_config(_with(run={"concurrency": "many", "otel": "maybe", "timeout_seconds": "x"}))
        msg = str(info.value)
        assert "run.concurrency:" in msg and "use an integer" in msg
        assert "run.otel:" in msg and "use true or false" in msg
        assert "run.timeout_seconds:" in msg and "use a number" in msg

    def test_gt_lt_messages(self) -> None:
        with pytest.raises(ConfigError) as info:
            parse_config(_with(run={"timeout_seconds": 0, "status_threshold": 1}))
        msg = str(info.value)
        assert "run.timeout_seconds: must be > 0.0 (got 0)" in msg
        assert "hint: use a value > 0.0" in msg
        assert "run.status_threshold: must be < 1.0 (got 1)" in msg
        assert "hint: use a value < 1.0" in msg

    def test_le_message(self) -> None:
        with pytest.raises(ConfigError) as info:
            parse_config(_with(run={"concurrency": 10_000}))
        msg = str(info.value)
        assert "run.concurrency: must be <= 512 (got 10000)" in msg
        assert "use a value <= 512" in msg

    def test_dict_and_list_type(self) -> None:
        with pytest.raises(ConfigError) as info:
            parse_config(_with(run=["x"], plugins="p"))
        msg = str(info.value)
        assert "run:" in msg
        assert "plugins:" in msg and "use a YAML list" in msg

    def test_string_type_hint(self) -> None:
        with pytest.raises(ConfigError) as info:
            parse_config(_with(storage={"db_path": 5}))
        assert "storage.db_path:" in str(info.value)
        assert "use a string" in str(info.value)

    def test_dict_type_hint(self) -> None:
        with pytest.raises(ConfigError) as info:
            parse_config({"target": {"type": "http", "url": "u", "headers": ["a"]}})
        assert "target.headers:" in str(info.value)
        assert "use a YAML mapping" in str(info.value)

    def test_multiple_errors_each_on_own_line(self) -> None:
        with pytest.raises(ConfigError) as info:
            parse_config(_with(run={"trials_per_case": 0, "concurrency": 0}))
        lines = str(info.value).splitlines()
        assert lines[0] == "invalid configuration in config:"
        assert any(line.strip().startswith("run.trials_per_case:") for line in lines[1:])
        assert any(line.strip().startswith("run.concurrency:") for line in lines[1:])


class TestFormatValidationError:
    def test_prefix_and_root(self) -> None:
        from pydantic import ValidationError

        try:
            MutationConfig.model_validate({"per_case": 99})
        except ValidationError as exc:
            msg = format_validation_error(exc, prefix="x.y", origin="o.yaml")
        assert msg.startswith("invalid configuration in o.yaml:")
        assert "x.y.per_case: must be <= 20 (got 99)" in msg

    def test_root_level_error(self) -> None:
        from pydantic import ValidationError

        try:
            MutationConfig.model_validate("nope")
        except ValidationError as exc:
            assert "<root>:" in format_validation_error(exc)
            assert "x:" in format_validation_error(exc, prefix="x")

    def test_hint_with_missing_ctx_key_is_skipped(self) -> None:
        from pydantic import BaseModel, ValidationError

        class M(BaseModel):
            v: int

        try:
            M.model_validate({"v": "abc"})
        except ValidationError as exc:
            msg = format_validation_error(exc)
        assert "v:" in msg and "use an integer" in msg


class TestInterpolateEnv:
    def test_set_variable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AG_TEST_VAR", "hello")
        assert interpolate_env("x-${AG_TEST_VAR}-y") == "x-hello-y"

    def test_default_used_when_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AG_TEST_VAR", raising=False)
        assert interpolate_env("${AG_TEST_VAR:-fallback}") == "fallback"
        assert interpolate_env("${AG_TEST_VAR:-}") == ""

    def test_set_variable_overrides_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AG_TEST_VAR", "real")
        assert interpolate_env("${AG_TEST_VAR:-fallback}") == "real"

    def test_unset_non_strict_is_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AG_TEST_VAR", raising=False)
        assert interpolate_env("a${AG_TEST_VAR}b") == "ab"

    def test_unset_strict_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AG_TEST_VAR", raising=False)
        with pytest.raises(ConfigError) as info:
            interpolate_env("${AG_TEST_VAR}", strict=True)
        assert "AG_TEST_VAR is not set" in str(info.value)
        assert "${AG_TEST_VAR}" in str(info.value)

    def test_strict_with_default_ok(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AG_TEST_VAR", raising=False)
        assert interpolate_env("${AG_TEST_VAR:-d}", strict=True) == "d"

    def test_multiple_and_no_vars(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AG_A", "1")
        monkeypatch.setenv("AG_B", "2")
        assert interpolate_env("${AG_A}+${AG_B}") == "1+2"
        assert interpolate_env("no vars $HOME {x}") == "no vars $HOME {x}"


class TestResolvePath:
    def test_absolute(self, tmp_path: Path) -> None:
        p = tmp_path / "missing.txt"
        assert resolve_path(str(p), Path("/elsewhere")) == p

    def test_cwd_relative_exists(self, repo_root: Path) -> None:
        assert resolve_path("examples/policy.yaml", Path("/nonexistent")) == (repo_root / "examples/policy.yaml")

    def test_config_dir_relative(self, tmp_path: Path) -> None:
        (tmp_path / "data.yaml").write_text("x: 1")
        assert resolve_path("data.yaml", tmp_path) == (tmp_path / "data.yaml").resolve()

    def test_missing_returns_as_is(self, tmp_path: Path) -> None:
        assert resolve_path("nowhere/x.yaml", tmp_path) == Path("nowhere/x.yaml")


class TestConfigHash:
    def test_stable_and_short(self) -> None:
        a = parse_config(MINIMAL)
        b = parse_config(MINIMAL)
        assert config_hash(a) == config_hash(b)
        assert len(config_hash(a)) == 16
        int(config_hash(a), 16)

    def test_explicit_defaults_hash_equal(self) -> None:
        explicit = _with(run={"trials_per_case": 5, "seed": 1337})
        assert config_hash(parse_config(explicit)) == config_hash(parse_config(MINIMAL))

    def test_key_order_irrelevant(self) -> None:
        a = parse_config({"run": {"seed": 1, "name": "n"}, **MINIMAL})
        b = parse_config({**MINIMAL, "run": {"name": "n", "seed": 1}})
        assert config_hash(a) == config_hash(b)

    def test_changes_with_content(self) -> None:
        a = parse_config(MINIMAL)
        b = parse_config(_with(run={"seed": 7}))
        assert config_hash(a) != config_hash(b)

    def test_known_value_regression(self) -> None:
        # Hash of the model dump must be deterministic across processes.
        cfg = AgentGuardConfig.model_validate(MINIMAL)
        import hashlib
        import json

        expected = hashlib.sha256(json.dumps(cfg.model_dump(mode="json"), sort_keys=True).encode()).hexdigest()[:16]
        assert config_hash(cfg) == expected
