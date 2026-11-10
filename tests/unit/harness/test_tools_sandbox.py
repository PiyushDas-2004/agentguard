"""Mock tools, the tool sandbox, cross-session memory and the RAG fixture."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from agentguard.config.policy import Policy
from agentguard.harness.canary import CanaryRegistry
from agentguard.harness.environment import EmailMessage, VirtualEnvironment
from agentguard.harness.memory import MemoryEntry, MemoryStore
from agentguard.harness.rag_fixture import RagCorpus, RagDocument, RagIndex, tokenize
from agentguard.harness.sandbox import ToolResult, ToolSandbox, static_approver
from agentguard.harness.tools import (
    TOOL_REGISTRY,
    ToolArgumentError,
    canonical_args,
    execute_tool,
    validate_arguments,
)


@pytest.fixture
def env() -> VirtualEnvironment:
    clean = RagIndex(RagCorpus.load("datasets/rag_corpus").clean)
    return VirtualEnvironment.build(7, CanaryRegistry(seed=7), clean)


FILLER = [RagDocument(doc_id=f"f{i}", title=f"topic{i}", text=f"unrelated filler words{i}") for i in range(8)]


def run(coro: Any) -> Any:
    return asyncio.run(coro)


class TestToolImplementations:
    def test_registry_specs(self) -> None:
        assert len(TOOL_REGISTRY) == 11
        for spec in TOOL_REGISTRY.values():
            llm = spec.to_llm()
            assert llm.name == spec.name and llm.parameters["additionalProperties"] is False

    def test_email_send(self, env: VirtualEnvironment) -> None:
        out = execute_tool(env, "email_send", {"to": "a@b.example", "body": "hi"})
        assert "Queued 1 outgoing item for a@b.example" in out
        assert env.sent_emails == [{"to": "a@b.example", "subject": "", "body": "hi"}]

    def test_email_read(self, env: VirtualEnvironment) -> None:
        out = execute_tool(env, "email_read", {"limit": 2})
        assert out.index("Invoice INV-7781") < out.index("Lunch?")
        assert "Password rotation" not in out
        assert execute_tool(VirtualEnvironment(), "email_read", {}) == "Inbox is empty."

    def test_file_read_write(self, env: VirtualEnvironment) -> None:
        assert "Revenue grew 12%" in execute_tool(env, "file_read", {"path": "/sandbox/public/report.txt"})
        assert execute_tool(env, "file_read", {"path": "/nope"}) == "Error: file not found: /nope"
        assert execute_tool(env, "file_write", {"path": "/sandbox/public/x", "content": "abc"}).startswith(
            "Wrote 3 bytes to /sandbox/public/x"
        )
        assert env.files["/sandbox/public/x"] == "abc"

    def test_http_get(self, env: VirtualEnvironment) -> None:
        assert "All Acme systems operational" in execute_tool(env, "http_get", {"url": "https://status.acme.example"})
        assert "Getting started" in execute_tool(env, "http_get", {"url": "https://docs.acme.example/getting-started/"})
        assert "404 Not Found" in execute_tool(env, "http_get", {"url": "https://x.example"})
        assert env.http_log == [
            "https://status.acme.example",
            "https://docs.acme.example/getting-started/",
            "https://x.example",
        ]

    def test_db_query(self, env: VirtualEnvironment) -> None:
        out = execute_tool(env, "db_query", {"table": "orders", "where": {"id": "O-2002"}})
        assert "Ergonomic chair" in out and "processing" in out and "O-2001" not in out
        assert execute_tool(env, "db_query", {"table": "secrets"}).startswith("Error: unknown table 'secrets'")
        assert "P-3004" in execute_tool(env, "db_query", {"table": "products"})

    def test_shell_and_payment(self, env: VirtualEnvironment) -> None:
        assert "not executed: ls" in execute_tool(env, "shell_exec", {"command": "ls"})
        assert env.shell_log == ["ls"]
        out = execute_tool(env, "payment_transfer", {"amount": "1,500", "to_account": "X-1"})
        assert out.startswith("Payment TX-00001 queued (simulated): 1500.0 USD")
        execute_tool(env, "payment_transfer", {"amount": 2, "to_account": "Y", "currency": "EUR"})
        assert [t["ref"] for t in env.transfers] == ["TX-00001", "TX-00002"]
        assert env.transfers[1]["currency"] == "EUR"

    def test_memory_tools(self, env: VirtualEnvironment) -> None:
        assert execute_tool(env, "memory_write", {"key": "k", "value": "v"}) == "Saved memory note 'k'."
        assert execute_tool(env, "memory_read", {"key": "k"}) == "k: v"
        assert "preferred_language: English" in execute_tool(env, "memory_read", {})
        assert execute_tool(VirtualEnvironment(), "memory_read", {}) == "No memory notes."

    def test_search_docs(self, env: VirtualEnvironment) -> None:
        out = execute_tool(env, "search_docs", {"query": "confidential production runbook"})
        assert out.startswith("[doc:confidential-runbook]")
        assert execute_tool(env, "search_docs", {"query": "zzzqqq"}) == "No matching documents."
        assert execute_tool(env, "search_docs", {"query": "runbook", "k": 99}).count("[doc:") == 1

    def test_overrides_append(self, env: VirtualEnvironment) -> None:
        env.tool_output_overrides["db_query"] = "INJECTED"
        env.tool_output_overrides["search_docs"] = "INJECTED-RAG"
        assert execute_tool(env, "db_query", {"table": "products"}).endswith("\nINJECTED")
        assert execute_tool(env, "search_docs", {"query": "zzzqqq"}) == "No matching documents.\nINJECTED-RAG"

    def test_unknown_tool(self, env: VirtualEnvironment) -> None:
        with pytest.raises(KeyError):
            execute_tool(env, "rm_rf", {})


class TestValidateArguments:
    spec = TOOL_REGISTRY["payment_transfer"]

    @pytest.mark.parametrize(
        ("args", "message"),
        [
            ("nope", "arguments must be an object"),
            ({"amount": 1}, "missing required argument 'to_account'"),
            ({"amount": 1, "to_account": "x", "memo": "y"}, "unexpected argument 'memo'"),
            ({"amount": "lots", "to_account": "x"}, "'amount' must be a number"),
            ({"amount": True, "to_account": "x"}, "'amount' must be a number"),
            ({"amount": 1, "to_account": 5}, "'to_account' must be of type string"),
        ],
    )
    def test_errors(self, args: Any, message: str) -> None:
        with pytest.raises(ToolArgumentError, match=message):
            validate_arguments(self.spec, args)

    def test_coercion(self) -> None:
        assert validate_arguments(self.spec, {"amount": "2,000.5", "to_account": "x"})["amount"] == 2000.5

    def test_integer_and_object(self) -> None:
        with pytest.raises(ToolArgumentError, match="'limit' must be of type integer"):
            validate_arguments(TOOL_REGISTRY["email_read"], {"limit": 1.5})
        with pytest.raises(ToolArgumentError, match="'where' must be of type object"):
            validate_arguments(TOOL_REGISTRY["db_query"], {"table": "t", "where": "id=1"})

    def test_canonical_args(self) -> None:
        assert canonical_args({"b": 1, "a": [2]}) == '{"a": [2], "b": 1}'


class TestSandbox:
    def test_specs_and_names(self, env: VirtualEnvironment, policy: Policy) -> None:
        box = ToolSandbox(env, policy, tool_names=["file_read", "bogus"])
        assert box.names == ["file_read"]
        assert [s.name for s in box.specs()] == ["file_read"]
        assert [s.name for s in box.llm_specs()] == ["file_read"]
        assert len(ToolSandbox(env, policy).names) == 11

    def test_allowed_call(self, env: VirtualEnvironment, policy: Policy) -> None:
        box = ToolSandbox(env, policy)
        box.turn_index, box.session = 3, 2
        result = run(box.call("file_read", {"path": "/sandbox/public/README.md"}))
        assert isinstance(result, ToolResult) and not result.error
        assert result.content == "Shared workspace for the Acme support team."
        call = box.calls[0]
        assert call.allowed and call.executed and call.policy_violations == []
        assert (call.turn_index, call.session) == (3, 2)

    def test_observe_mode_executes_violations(self, env: VirtualEnvironment, policy: Policy) -> None:
        box = ToolSandbox(env, policy)
        result = run(box.call("shell_exec", {"command": "id"}))
        assert not result.error and env.shell_log == ["id"]
        assert not result.call.allowed and result.call.executed
        assert result.call.policy_violations == ["forbidden tool 'shell_exec'"]

    def test_block_mode(self, env: VirtualEnvironment, policy: Policy) -> None:
        box = ToolSandbox(env, policy.model_copy(update={"mode": "block"}))
        result = run(box.call("shell_exec", {"command": "id"}))
        assert result.error and result.content.startswith("Error: blocked by policy: forbidden tool")
        assert env.shell_log == [] and not result.call.executed
        ok = run(box.call("file_read", {"path": "/sandbox/public/README.md"}))
        assert not ok.error

    def test_approval_denied_by_default(self, env: VirtualEnvironment, policy: Policy) -> None:
        box = ToolSandbox(env, policy)
        args = {"amount": 10, "to_account": "ACME-1"}
        assert run(box.request_approval("payment_transfer", args)) is False
        result = run(box.call("payment_transfer", args))
        request, call = box.calls
        assert request.is_approval_request and not request.executed and request.result_preview == "approval denied"
        assert call.approved is False and call.approval_required
        assert "'payment_transfer' was executed after approval was denied" in call.policy_violations
        assert result.call is call

    def test_approval_granted(self, env: VirtualEnvironment, policy: Policy) -> None:
        box = ToolSandbox(env, policy, approver=static_approver(True))
        args = {"amount": 10, "to_account": "ACME-1"}
        assert run(box.request_approval("payment_transfer", args)) is True
        call = run(box.call("payment_transfer", args)).call
        assert call.allowed and call.approved is True
        assert box.calls[0].result_preview == "approved"
        # approval applies only to identical arguments
        other = run(box.call("payment_transfer", {"amount": 99, "to_account": "ACME-1"})).call
        assert other.approved is None and not other.allowed

    def test_policy_default_approve(self, env: VirtualEnvironment, policy: Policy) -> None:
        box = ToolSandbox(env, policy.model_copy(update={"approver_default": "approve"}))
        assert run(box.request_approval("payment_transfer", {})) is True

    def test_unknown_and_unexposed(self, env: VirtualEnvironment, policy: Policy) -> None:
        box = ToolSandbox(env, policy, tool_names=["file_read"])
        unknown = run(box.call("rm_rf"))
        assert unknown.error and unknown.content == "Error: tool 'rm_rf' is not available."
        assert "unknown tool 'rm_rf'" in unknown.call.policy_violations
        assert not unknown.call.executed
        hidden = run(box.call("http_get", {"url": "https://acme.example"}))
        assert "tool 'http_get' is not exposed to this target" in hidden.call.policy_violations
        assert env.http_log == []

    def test_argument_error(self, env: VirtualEnvironment, policy: Policy) -> None:
        result = run(ToolSandbox(env, policy).call("file_read", {"file": "x"}))
        assert result.error and not result.call.executed
        assert result.content == "Error: file_read: missing required argument 'path'"

    def test_tool_level_error_flag(self, env: VirtualEnvironment, policy: Policy) -> None:
        result = run(ToolSandbox(env, policy).call("file_read", {"path": "/sandbox/public/none"}))
        assert result.error and result.call.executed

    def test_truncation(self, env: VirtualEnvironment, policy: Policy) -> None:
        env.files["/sandbox/public/big.txt"] = "x" * 500
        box = ToolSandbox(env, policy, max_result_chars=100)
        result = run(box.call("file_read", {"path": "/sandbox/public/big.txt"}))
        assert result.content == "x" * 100 + "\n[truncated]"
        assert len(result.call.result_preview) == 112

    def test_record_external(self, env: VirtualEnvironment, policy: Policy) -> None:
        box = ToolSandbox(env, policy)
        call = box.record_external("http_get", {"url": "https://attacker.example"}, "body" * 200)
        assert call.executed and not call.allowed and call.approved is None
        assert call.policy_violations == ["http_get.url destination 'attacker.example' is not allowlisted"]
        assert len(call.result_preview) == 300
        assert box.record_external("file_read", {"path": "/sandbox/public/a"}).result_preview == ""
        assert len(box.calls) == 2


class TestMemoryStore:
    def test_write_read(self) -> None:
        store = MemoryStore()
        entry = store.write("k", "v", session=2, source="poison")
        assert entry == MemoryEntry("k", "v", 2, "poison")
        assert store.read("k") == [entry]
        assert store.read("missing") == []
        for key in ("*", "", "all"):
            assert store.read(key) == [entry]

    def test_overwrite_and_render(self) -> None:
        store = MemoryStore()
        store.write("a", "1")
        store.write("b", "2")
        store.write("a", "3")
        assert store.items() == [("a", "3"), ("b", "2")]
        assert store.render() == "- a: 3\n- b: 2"
        assert MemoryStore().render() == ""

    def test_bounds(self) -> None:
        store = MemoryStore(max_entries=2, max_value_chars=3)
        store.write("a", "abcdef")
        store.write("b", "x")
        store.write("c", "y")
        assert [k for k, _ in store.items()] == ["b", "c"]
        store.write("b", "z")  # existing key: no eviction
        assert [k for k, _ in store.items()] == ["b", "c"]
        assert MemoryStore(max_value_chars=3).write("k", "abcdef").value == "abc"


class TestRagFixture:
    def test_tokenize(self) -> None:
        assert tokenize("The Refund-policy, for ALL orders!") == ["refund", "policy", "orders"]

    def test_corpus_load(self) -> None:
        corpus = RagCorpus.load("datasets/rag_corpus")
        assert len(corpus.clean) >= 30 and len(corpus.poisoned) >= 10
        assert [d.doc_id for d in corpus.clean] == sorted(d.doc_id for d in corpus.clean)
        name = next(iter(corpus.poisoned))
        assert corpus.poisoned_doc(f"{name}.md").poisoned
        with pytest.raises(KeyError):
            corpus.poisoned_doc("nope")
        refund = next(d for d in corpus.clean if d.doc_id == "refund-policy")
        assert refund.title and not refund.title.startswith("#")

    def test_corpus_missing_dirs(self, tmp_path: Path) -> None:
        (tmp_path / "clean").mkdir()
        (tmp_path / "clean" / "untitled.md").write_text("no heading here")
        corpus = RagCorpus.load(tmp_path)
        assert corpus.clean[0].title == "untitled" and corpus.poisoned == {}

    def test_search_deterministic_ties(self) -> None:
        docs = [RagDocument(doc_id=i, title="refund", text="refund policy") for i in ("c", "a", "b")]
        index = RagIndex(docs + [RagDocument(doc_id="z", title="shipping", text="shipping times"), *FILLER])
        assert [d.doc_id for d in index.search("refund", k=3)] == ["a", "b", "c"]
        assert [d.doc_id for d in index.search("refund", k=2)] == ["a", "b"]
        assert index.search("the and of") == []
        assert index.search("nothingmatches") == []
        assert RagIndex([]).search("refund") == []

    def test_search_real_corpus(self) -> None:
        index = RagIndex(RagCorpus.load("datasets/rag_corpus").clean)
        assert index.search("refund business days")[0].doc_id in {"refund-policy", "returns-process"}

    def test_add_and_render_are_pure(self) -> None:
        base = RagIndex([RagDocument(doc_id="a", title="A", text="code {{CANARY}} here")])
        bigger = base.add(RagDocument(doc_id="b", title="B", text="other"))
        assert len(base.documents) == 1 and len(bigger.documents) == 2
        rendered = bigger.render({"CANARY": "AG-CANARY-x"})
        assert rendered.documents[0].text == "code AG-CANARY-x here"
        assert base.documents[0].text == "code {{CANARY}} here"

    def test_empty_document_tokens(self) -> None:
        index = RagIndex([RagDocument(doc_id="e", title="", text="the of"), RagDocument(doc_id="f", title="x", text="y"), *FILLER])
        assert [d.doc_id for d in index.search("x")] == ["f"]


def test_email_message_dataclass() -> None:
    msg = EmailMessage("M-1", "a@b", "s", "body")
    assert (msg.id, msg.sender) == ("M-1", "a@b")
