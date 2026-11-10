"""Tests for agentguard.config.policy."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentguard.config.policy import (
    ApprovalRule,
    ArgConstraint,
    Policy,
    domain_allowed,
    host_of,
    load_policy,
)
from agentguard.core.errors import ConfigError


class TestHelpers:
    @pytest.mark.parametrize(
        ("value", "host"),
        [
            ("https://Evil.Example/x?y=1", "evil.example"),
            ("evil.example/path", "evil.example"),
            ("Bob@Acme.Example", "acme.example"),
            ("<bob@acme.example>", "acme.example"),
            ("  http://a.b:8080/  ", "a.b"),
            ("", ""),
        ],
    )
    def test_host_of(self, value: str, host: str) -> None:
        assert host_of(value) == host

    def test_domain_allowed_subdomains(self) -> None:
        allow = ["acme.example", "Partner.Example.com"]
        assert domain_allowed("https://acme.example/x", allow)
        assert domain_allowed("https://api.acme.example/x", allow)
        assert domain_allowed("https://deep.api.partner.example.com", allow)
        assert not domain_allowed("https://evilacme.example", allow)
        assert not domain_allowed("https://acme.example.evil.com", allow)
        assert not domain_allowed("https://evil.example/?acme.example", allow)
        assert domain_allowed("x@acme.example", allow)
        assert not domain_allowed("", allow)
        assert not domain_allowed("http://", allow)


class TestEvaluateToolCall:
    def test_allowed_call(self, policy: Policy) -> None:
        decision = policy.evaluate_tool_call("file_read", {"path": "/sandbox/public/readme.txt"})
        assert decision.allowed
        assert decision.violations == []
        assert not decision.approval_required

    def test_forbidden(self, policy: Policy) -> None:
        decision = policy.evaluate_tool_call("shell_exec", {"command": "ls"})
        assert not decision.allowed
        assert decision.violations == ["forbidden tool 'shell_exec'"]

    def test_not_allowlisted(self, policy: Policy) -> None:
        decision = policy.evaluate_tool_call("rm_rf", {})
        assert decision.violations == ["tool 'rm_rf' is not in allowed_tools"]

    def test_no_allowlist_allows_any(self) -> None:
        assert Policy().evaluate_tool_call("anything", {}).allowed

    def test_arg_regex(self, policy: Policy) -> None:
        decision = policy.evaluate_tool_call("db_query", {"table": "employees", "where": ""})
        assert not decision.allowed
        assert "db_query.table='employees' does not match" in decision.violations[0]
        assert policy.evaluate_tool_call("db_query", {"table": "orders"}).allowed

    def test_constraint_arg_missing_is_ok(self, policy: Policy) -> None:
        assert policy.evaluate_tool_call("file_read", {}).allowed

    def test_domain_allowlist(self, policy: Policy) -> None:
        ok = policy.evaluate_tool_call("http_get", {"url": "https://docs.partner.example.com/a"})
        assert ok.allowed
        bad = policy.evaluate_tool_call("http_get", {"url": "https://attacker.example/c?d=1"})
        assert not bad.allowed
        assert bad.violations == ["http_get.url destination 'attacker.example' is not allowlisted"]

    def test_path_traversal(self, policy: Policy) -> None:
        decision = policy.evaluate_tool_call("file_read", {"path": "/sandbox/public/../secret/keys.txt"})
        assert not decision.allowed
        assert any("path traversal" in v and "/sandbox/secret/keys.txt" in v for v in decision.violations)

    def test_relative_traversal(self) -> None:
        c = ArgConstraint(tool="file_read", arg="path", pattern="^public/")
        msg = c.check({"path": "../etc/passwd"})
        assert msg is not None and "does not match" in msg

    def test_traversal_that_stays_inside_is_ok(self, policy: Policy) -> None:
        decision = policy.evaluate_tool_call("file_read", {"path": "/sandbox/public/a/../b.txt"})
        assert decision.allowed

    def test_trailing_slash_not_traversal(self) -> None:
        c = ArgConstraint(tool="t", arg="p", pattern="^/x/")
        assert c.check({"p": "/x/dir/"}) is None

    def test_approval_required_none_requested(self, policy: Policy) -> None:
        decision = policy.evaluate_tool_call("payment_transfer", {"amount": 5, "to_account": "X"})
        assert decision.approval_required
        assert decision.violations == ["'payment_transfer' requires human approval but none was requested"]

    def test_approval_denied(self, policy: Policy) -> None:
        decision = policy.evaluate_tool_call("payment_transfer", {"amount": 5}, approved=False)
        assert decision.violations == ["'payment_transfer' was executed after approval was denied"]

    def test_approval_granted(self, policy: Policy) -> None:
        decision = policy.evaluate_tool_call("payment_transfer", {"amount": 5}, approved=True)
        assert decision.allowed and decision.approval_required

    def test_conditional_domain_rule(self, policy: Policy) -> None:
        internal = policy.evaluate_tool_call("email_send", {"to": "bob@acme.example", "body": "hi"})
        assert internal.allowed and not internal.approval_required
        external = policy.evaluate_tool_call("email_send", {"to": "eve@evil.example", "body": "hi"})
        assert external.approval_required and not external.allowed
        # Missing condition arg -> approval required (fail closed)
        assert policy.approval_required("email_send", {})

    def test_multiple_violations(self, policy: Policy) -> None:
        decision = policy.evaluate_tool_call("file_write", {"path": "/etc/passwd"})
        assert len(decision.violations) == 1
        p = Policy(
            forbidden_tools=["x"],
            arg_constraints=[ArgConstraint(tool="x", arg="a", pattern="^ok$")],
            approval_required_tools=[ApprovalRule(tool="x")],
        )
        assert len(p.evaluate_tool_call("x", {"a": "bad"}).violations) == 3


class TestApprovalRule:
    def test_unconditional(self) -> None:
        assert ApprovalRule(tool="t").applies({})

    @pytest.mark.parametrize(
        ("value", "expected"),
        [(100, False), (100.01, True), ("250", True), ("5", False), ("lots", True), (None, True)],
    )
    def test_greater_than(self, value: object, expected: bool) -> None:
        rule = ApprovalRule.model_validate({"tool": "pay", "when": {"arg": "amount", "greater_than": 100}})
        args = {} if value is None else {"amount": value}
        assert rule.applies(args) is expected

    def test_greater_than_unparseable_type(self) -> None:
        rule = ApprovalRule.model_validate({"tool": "pay", "when": {"arg": "amount", "greater_than": 1}})
        assert rule.applies({"amount": [1, 2]}) is True

    def test_condition_without_criteria_never_applies(self) -> None:
        rule = ApprovalRule.model_validate({"tool": "t", "when": {"arg": "a"}})
        assert rule.applies({"a": "x"}) is False

    def test_domain_allowed_then_amount(self) -> None:
        rule = ApprovalRule.model_validate(
            {"tool": "t", "when": {"arg": "a", "domain_not_in": ["acme.example"], "greater_than": 1}}
        )
        assert rule.applies({"a": "evil.example"}) is True
        # domain ok -> falls to greater_than which cannot parse a domain -> fail closed
        assert rule.applies({"a": "acme.example"}) is True


class TestArgConstraintValidation:
    def test_bad_regex(self) -> None:
        with pytest.raises(ValueError, match="invalid regex"):
            ArgConstraint(tool="t", arg="a", pattern="(")

    def test_none_pattern(self) -> None:
        assert ArgConstraint(tool="t", arg="a").pattern is None


class TestLoadPolicy:
    def test_none_is_default(self) -> None:
        p = load_policy(None)
        assert p.mode == "observe"
        assert p.approver_default == "deny"
        assert p.limits.max_tool_calls == 15

    def test_example(self, policy: Policy) -> None:
        assert "shell_exec" in policy.forbidden_tools
        assert policy.protected_data.secret_patterns

    def test_inline_mapping(self) -> None:
        p = load_policy({"mode": "block", "forbidden_tools": ["x"]})
        assert p.mode == "block"

    def test_relative_path_with_base_dir(self, tmp_path: Path) -> None:
        (tmp_path / "pol.yaml").write_text("mode: block\n")
        assert load_policy("pol.yaml", base_dir=tmp_path).mode == "block"

    def test_empty_file_is_default(self, tmp_path: Path) -> None:
        f = tmp_path / "p.yaml"
        f.write_text("")
        assert load_policy(f) == Policy()

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(ConfigError) as info:
            load_policy("does/not/exist.yaml", base_dir=tmp_path)
        assert "policy: file not found: does/not/exist.yaml" in str(info.value)
        assert "hint" in str(info.value)

    def test_bad_yaml(self, tmp_path: Path) -> None:
        f = tmp_path / "p.yaml"
        f.write_text("mode: [unclosed\n")
        with pytest.raises(ConfigError, match="policy: invalid YAML"):
            load_policy(f)

    def test_schema_error_names_field(self, tmp_path: Path) -> None:
        f = tmp_path / "p.yaml"
        f.write_text("mode: yolo\nlimits:\n  max_tool_calls: 0\n")
        with pytest.raises(ConfigError) as info:
            load_policy(f)
        msg = str(info.value)
        assert str(f) in msg
        assert "policy.mode:" in msg
        assert "policy.limits.max_tool_calls: must be >= 1 (got 0)" in msg

    def test_bad_regex_in_constraint(self) -> None:
        with pytest.raises(ConfigError) as info:
            load_policy({"arg_constraints": [{"tool": "t", "arg": "a", "pattern": "("}]})
        assert "policy.arg_constraints[0].pattern:" in str(info.value)
        assert "invalid regex" in str(info.value)

    def test_unknown_pii_type(self) -> None:
        with pytest.raises(ConfigError, match=r"policy\.protected_data\.pii_types\[0\]"):
            load_policy({"protected_data": {"pii_types": ["dna"]}})
