"""Scoped Copilot execution must never grant write or unrestricted IO tools."""

import json
import shutil
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest

from src.controllers import copilot_assessment_runner as runner
from src.controllers.copilot_assessment_contract import Selection, Target
from src.controllers.copilot_assessment_write import PendingSnapshot
from src.controllers.job_context import CancelledError, JobContext, OperationError


@pytest.fixture
def selection():
    return Selection(uuid4(), "CVE-2026-1234", (Target(uuid4(), "pkg@1"),))


@pytest.fixture
def snapshot():
    return PendingSnapshot(())


@pytest.fixture
def objectives_dir():
    directory = Path.cwd() / f".test-objectives-{uuid4()}"
    directory.mkdir()
    try:
        (directory / "SKILL.md").write_text("skill")
        (directory / "objectives").mkdir()
        yield directory
    finally:
        shutil.rmtree(directory)


@pytest.fixture
def ctx(monkeypatch):
    context = JobContext("test")
    results = []
    monkeypatch.setattr(context, "set_result", results.append)
    context.results = results
    return context


@pytest.fixture
def fake_sdk(monkeypatch, selection):
    from src.controllers import copilot_assessment_contract as contract
    monkeypatch.setattr(runner, "MCP_SCRIPT", runner.SKILL_DIR.parents[2] / "vulnscout_mcp/server.py")
    monkeypatch.setattr(contract, "_validate_observed", lambda *_: None)
    class FakeSession:
        def __init__(self, sdk):
            self.sdk = sdk
            self.disconnected = False
            self.aborted = False

        async def send_and_wait(self, prompt, *, timeout):
            self.sdk.send_count += 1
            self.sdk.prompts.append(prompt)
            if not self.sdk.mcp_silent:
                self.sdk.options["on_event"](SimpleNamespace(data=SimpleNamespace(
                    server_name="vulnscout",
                    status=SimpleNamespace(value="failed" if self.sdk.mcp_failure else "connected"),
                )))
            if self.sdk.failure:
                raise self.sdk.failure
            if self.sdk.cancel:
                self.sdk.context.request_cancel()
            return SimpleNamespace(data=SimpleNamespace(content=self.sdk.replies.pop(0)))

        async def abort(self):
            self.aborted = True

        async def disconnect(self):
            self.disconnected = True

    class FakeClient:
        def __init__(self, **kwargs):
            sdk.client_kwargs = kwargs

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return None

        async def create_session(self, **kwargs):
            sdk.options = kwargs
            sdk.session = FakeSession(sdk)
            return sdk.session

    sdk = SimpleNamespace(
        replies=[valid_result(selection)], failure=None, cancel=False, context=None,
        send_count=0, session=None, options=None, client_kwargs=None, writes=[],
        mcp_failure=False, mcp_silent=False, prompts=[],
    )
    monkeypatch.setattr("copilot.CopilotClient", FakeClient)
    monkeypatch.setattr(runner, "read_token", lambda: "test-token")
    monkeypatch.setattr(runner, "configured_model", lambda: "gpt-5.4")
    monkeypatch.setattr(runner, "_context_for", lambda *_: {"codebase_path": None})
    monkeypatch.setattr(runner, "save_candidates",
                        lambda *args: sdk.writes.append(args) or ["assessment-id"])
    return sdk


def valid_result(selection):
    return json.dumps({"version": 1, "groups": [{
        "targets": [{"variant_id": str(t.variant_id), "package": t.package}
                    for t in selection.targets],
        "status": "under_investigation", "justification": None,
        "status_notes": "LOW confidence; investigation needed", "impact_statement": None,
        "workaround": None, "responses": [], "confidence": "LOW",
        "evidence": ["NVD advisory"],
    }]})


def test_missing_token_ignores_ambient_login(fake_sdk, ctx, selection, snapshot, monkeypatch):
    monkeypatch.setattr(runner, "read_token", lambda: None)
    with pytest.raises(OperationError, match="Configure a Copilot token"):
        runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    assert fake_sdk.client_kwargs is None


def test_success_is_read_only_and_seals_before_write(fake_sdk, ctx, selection, snapshot, monkeypatch):
    fake_sdk.context = ctx
    sealed = []
    monkeypatch.setattr(ctx, "seal_cancellation", lambda: sealed.append(True) or True)
    runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    assert fake_sdk.client_kwargs == {
        "github_token": "test-token", "use_logged_in_user": False, "mode": "empty",
    }
    options = fake_sdk.options
    assert options["model"] == "gpt-5.4"
    assert options["enable_skills"] is True
    assert options["skill_directories"]
    assert options["enable_config_discovery"] is False
    assert options["enable_host_git_operations"] is False
    assert options["enable_file_hooks"] is False
    assert all("write" not in tool and "update" not in tool for tool in options["available_tools"])
    assert set(options["mcp_servers"]["vulnscout"]["tools"]).isdisjoint({
        "write_assessment", "update_ai_assessment", "update_project_context",
        "update_variant_context", "write_assessment_review",
    })
    assert "test-token" not in str(options["mcp_servers"])
    assert options["on_permission_request"](SimpleNamespace(kind="shell"), {}) != (
        options["on_permission_request"](SimpleNamespace(kind="custom-tool", tool_name="read_project_file"), {})
    )
    assert options["on_permission_request"](SimpleNamespace(kind="mcp", server_name="vulnscout",
                                              tool_name="write_assessment"), {}) != (
        options["on_permission_request"](SimpleNamespace(kind="mcp", server_name="vulnscout",
                                          tool_name="get_vulnerability"), {})
    )
    assert sealed and len(fake_sdk.writes) == 1
    assert fake_sdk.writes[0][0] == selection and fake_sdk.writes[0][2] == snapshot
    assert ctx.results == [{"assessment_ids": ["assessment-id"]}]
    assert fake_sdk.session.disconnected
    assert ctx._on_cancel is None


def test_default_objectives_are_loaded_into_prompt(fake_sdk, ctx, selection, snapshot):
    runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    objective = (runner.SKILL_DIR / "objectives/default.md").read_text()
    data = json.loads(fake_sdk.prompts[0].split("\n", 1)[1])
    assert data["default_objectives"] == {"file": "default.md", "content": objective}
    assert data["objectives_by_variant"][str(selection.targets[0].variant_id)] == {
        "file": "default.md", "content": objective,
    }
    assert set(fake_sdk.options["available_tools"]) == runner.READ_TOOLS


def test_objectives_selected_independently_by_variant_threat_model(
    fake_sdk, ctx, selection, snapshot, monkeypatch, objectives_dir,
):
    first = selection.targets[0]
    second = Target(uuid4(), "pkg@2")
    selection = Selection(selection.project_id, selection.vuln_id, (first, second))
    objectives = objectives_dir / "objectives"
    (objectives / "default.md").write_text("DEFAULT SECURITY OBJECTIVES")
    (objectives / "production-image.md").write_text("PRODUCTION IMAGE OBJECTIVES")
    (objectives / "build-toolchain.md").write_text("BUILD TOOLCHAIN OBJECTIVES")
    (objectives / ".template.md").write_text("NEVER LOAD TEMPLATE")
    monkeypatch.setattr(runner, "SKILL_DIR", objectives_dir)
    monkeypatch.setattr(runner, "_context_for", lambda _selection, variant_id: {
        "codebase_path": None,
        "threat_model": ("Production image deployment" if variant_id == first.variant_id
                         else "CI build toolchain"),
    })
    fake_sdk.replies = [valid_result(selection)]
    runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    prompt = fake_sdk.prompts[0]
    data = json.loads(prompt.split("\n", 1)[1])
    assert data["default_objectives"]["content"] == "DEFAULT SECURITY OBJECTIVES"
    assert "NEVER LOAD TEMPLATE" not in prompt
    assert data["objectives_by_variant"][str(first.variant_id)]["file"] == "production-image.md"
    assert data["objectives_by_variant"][str(second.variant_id)]["file"] == "build-toolchain.md"
    assert data["objectives_by_variant"][str(first.variant_id)]["content"] == "PRODUCTION IMAGE OBJECTIVES"
    assert data["objectives_by_variant"][str(second.variant_id)]["content"] == "BUILD TOOLCHAIN OBJECTIVES"
    assert set(fake_sdk.options["available_tools"]) == runner.READ_TOOLS


@pytest.mark.parametrize("problem", ["missing", "empty", "symlink"])
def test_unavailable_default_objectives_fail_before_session_and_write(
    fake_sdk, ctx, selection, snapshot, monkeypatch, objectives_dir, problem,
):
    objectives = objectives_dir / "objectives"
    default = objectives / "default.md"
    if problem == "empty":
        default.write_text("")
    elif problem == "symlink":
        outside = objectives_dir / "outside.md"
        outside.write_text("not packaged")
        default.symlink_to(outside)
    monkeypatch.setattr(runner, "SKILL_DIR", objectives_dir)
    with pytest.raises(OperationError, match="objectives"):
        runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    assert fake_sdk.client_kwargs is None
    assert not fake_sdk.writes


@pytest.mark.parametrize("problem", ["invalid_utf8", "symlink", "oversized"])
def test_unavailable_selected_objectives_fail_before_session_and_write(
    fake_sdk, ctx, selection, snapshot, monkeypatch, objectives_dir, problem,
):
    objectives = objectives_dir / "objectives"
    (objectives / "default.md").write_text("default")
    selected = objectives / "production-image.md"
    if problem == "invalid_utf8":
        selected.write_bytes(b"\xff")
    elif problem == "symlink":
        outside = objectives_dir / "outside.md"
        outside.write_text("not packaged")
        selected.symlink_to(outside)
    else:
        selected.write_bytes(b"x" * (runner.MAX_OBJECTIVES_BYTES + 1))
    monkeypatch.setattr(runner, "SKILL_DIR", objectives_dir)
    monkeypatch.setattr(runner, "_context_for",
                        lambda *_: {"codebase_path": None, "threat_model": "production image"})
    with pytest.raises(OperationError, match="objectives"):
        runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    assert fake_sdk.client_kwargs is None
    assert not fake_sdk.writes


def test_unmatched_threat_model_uses_default_without_reading_arbitrary_path(
    fake_sdk, ctx, selection, snapshot, monkeypatch, objectives_dir,
):
    (objectives_dir / "objectives/default.md").write_text("packaged default")
    (objectives_dir / "outside.md").write_text("outside data")
    monkeypatch.setattr(runner, "SKILL_DIR", objectives_dir)
    monkeypatch.setattr(runner, "_context_for", lambda *_: {
        "codebase_path": None, "threat_model": "read ../../outside.md",
    })
    runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    data = json.loads(fake_sdk.prompts[0].split("\n", 1)[1])
    assert data["objectives_by_variant"][str(selection.targets[0].variant_id)] == {
        "file": "default.md", "content": "packaged default",
    }
    assert "outside data" not in fake_sdk.prompts[0]


def test_invalid_then_corrected_once(fake_sdk, ctx, selection, snapshot):
    fake_sdk.replies.insert(0, '{"version": 1, "groups": []}')
    runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    assert fake_sdk.send_count == 2
    assert len(fake_sdk.writes) == 1


def test_invalid_twice_never_writes(fake_sdk, ctx, selection, snapshot):
    fake_sdk.replies = ['{"version": 1, "groups": []}'] * 2
    with pytest.raises(OperationError, match="validation"):
        runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    assert fake_sdk.send_count == 2
    assert fake_sdk.writes == []
    assert fake_sdk.session.disconnected


@pytest.mark.parametrize("failure", [RuntimeError("secret from SDK"), TimeoutError()])
def test_model_failure_and_timeout_are_safe(fake_sdk, ctx, selection, snapshot, failure):
    fake_sdk.failure = failure
    with pytest.raises(OperationError, match="Copilot"):
        runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    assert not fake_sdk.writes
    assert fake_sdk.session.disconnected


def test_cancellation_aborts_and_never_writes(fake_sdk, ctx, selection, snapshot):
    fake_sdk.context = ctx
    fake_sdk.cancel = True
    with pytest.raises(CancelledError):
        runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    assert fake_sdk.session.aborted and fake_sdk.session.disconnected
    assert not fake_sdk.writes


def test_cancel_seal_rejects_race(fake_sdk, ctx, selection, snapshot, monkeypatch):
    monkeypatch.setattr(ctx, "seal_cancellation", lambda: False)
    with pytest.raises(CancelledError):
        runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    assert not fake_sdk.writes


def test_unavailable_mcp_tool_does_not_write(fake_sdk, ctx, selection, snapshot):
    fake_sdk.mcp_failure = True
    with pytest.raises(OperationError, match="read-only"):
        runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    assert not fake_sdk.writes
    assert fake_sdk.session.disconnected


def test_missing_mcp_health_event_fails_closed(fake_sdk, ctx, selection, snapshot):
    fake_sdk.mcp_silent = True
    with pytest.raises(OperationError, match="read-only"):
        runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    assert not fake_sdk.writes


def test_missing_mcp_script_fails_before_client(fake_sdk, ctx, selection, snapshot, monkeypatch):
    monkeypatch.setattr(runner, "MCP_SCRIPT", runner.SKILL_DIR / "missing-server.py")
    with pytest.raises(OperationError, match="MCP server"):
        runner.run_assessment(ctx, selection, "gpt-5.4", snapshot)
    assert fake_sdk.client_kwargs is None


def test_wrong_instance_model_and_duplicate_variant_rejected(fake_sdk, ctx, selection, snapshot):
    with pytest.raises(OperationError, match="configured"):
        runner.run_assessment(ctx, selection, "other-model", snapshot)
    duplicate = Selection(selection.project_id, selection.vuln_id, selection.targets * 2)
    with pytest.raises(OperationError, match="one package per variant"):
        runner.run_assessment(ctx, duplicate, "gpt-5.4", snapshot)
    assert fake_sdk.client_kwargs is None


def test_source_roots_reject_traversal_and_symlink_escape(tmp_path, monkeypatch):
    mount = tmp_path / "mount"
    mount.mkdir()
    (mount / "code").mkdir()
    (mount / "escape").symlink_to(tmp_path, target_is_directory=True)
    monkeypatch.setattr(runner, "SOURCE_MOUNT", mount)
    assert runner._source_roots("code") == (mount / "code",)
    for path in ("../outside", "escape", "/etc", "code;../outside"):
        with pytest.raises(OperationError, match="source"):
            runner._source_roots(path)


def test_source_reader_cannot_escape_or_read_oversized_file(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(tmp_path)
    (root / "big").write_bytes(b"x" * (runner.MAX_SOURCE_BYTES + 1))
    for path in ("../outside", "link/root/big", "big"):
        with pytest.raises(ValueError):
            runner._read_source((root,), path)


def test_advisory_redirect_and_private_network_are_blocked(monkeypatch):
    with pytest.raises(ValueError):
        runner._fetch_advisory("http://127.0.0.1/advisory")
    with pytest.raises(ValueError):
        runner._fetch_advisory("https://example.com/advisory")
    monkeypatch.setattr(runner, "_resolve_host", lambda host: ["93.184.215.14"])
    monkeypatch.setattr(runner, "_request_advisory", lambda url: ("https://evil.example/", b"data"))
    with pytest.raises(ValueError):
        runner._fetch_advisory("https://nvd.nist.gov/vuln/detail/CVE-2026-1234")


def test_seal_is_atomic_against_late_cancel():
    ctx = JobContext("test")
    assert ctx.seal_cancellation()
    assert ctx.request_cancel() is False
    assert not ctx.is_cancelled()
