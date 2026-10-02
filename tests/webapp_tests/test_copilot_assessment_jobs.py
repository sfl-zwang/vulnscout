# Copyright (C) 2026 Savoir-faire Linux, Inc.
# SPDX-License-Identifier: GPL-3.0-only

"""HTTP scheduling and cancellation of scoped Copilot assessments."""

import threading
import time
from uuid import UUID, uuid4

import pytest

from src.controllers import copilot_settings
from src.controllers.job_context import CancelledError
from src.controllers.operation_registry import registry
from src.extensions import db
from src.models.assessment import Assessment
from src.models.finding import Finding
from src.models.observation import Observation
from src.models.package import Package
from src.models.project import Project
from src.models.scan import Scan
from src.models.variant import Variant
from src.models.vulnerability import Vulnerability


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("VULNSCOUT_AGENT_ENABLED", "1")
    monkeypatch.setenv("COPILOT_MODEL", "gpt-5.4")
    monkeypatch.delenv("VULNSCOUT_MCP_SERVER_PATH", raising=False)
    monkeypatch.setattr(copilot_settings, "read_token", lambda: "test-token")

    async def probe(_token, _model):
        return {}, ["gpt-5.4"]

    monkeypatch.setattr(copilot_settings, "_probe", probe)
    monkeypatch.setattr(copilot_settings, "_probe_read_tools", lambda: True)
    from src.bin.webapp import create_app

    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    app = create_app()
    app.config.update(TESTING=True, SCAN_FILE=str(scan_file))
    with app.app_context():
        db.create_all()
        project = Project.create("assessment-test")
        variant = Variant.create("default", project.id)
        package = Package.create("openssl", "3.0.0")
        Vulnerability.create_record(id="CVE-2026-1234")
        finding = Finding.create(package.id, "CVE-2026-1234")
        scan = Scan.create("observed", variant.id)
        Observation.create(finding.id, scan.id)
        scope = {
            "project_id": str(project.id), "vuln_id": "CVE-2026-1234",
            "targets": [{"variant_id": str(variant.id), "package": package.string_id}],
        }
        registry.clear()
        yield app.test_client(), scope, finding
        registry.clear()
        db.drop_all()


def wait_for(op_id, status):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        operation = registry.get(op_id)
        if operation and operation["status"] == status:
            return operation
        time.sleep(0.01)
    pytest.fail(f"operation never reached {status}: {registry.get(op_id)}")


def test_local_only_opt_in(client, monkeypatch):
    web, scope, _ = client
    monkeypatch.delenv("VULNSCOUT_AGENT_ENABLED")
    assert web.post("/api/copilot-assessments", json=scope).status_code == 404
    monkeypatch.setenv("VULNSCOUT_AGENT_ENABLED", "1")
    for kwargs in (
        {"environ_overrides": {"REMOTE_ADDR": "192.0.2.1"}},
        {"headers": {"Host": "example.org"}},
        {"headers": {"Origin": "https://example.org"}},
    ):
        assert web.post("/api/copilot-assessments", json=scope, **kwargs).status_code == 403


@pytest.mark.parametrize("change", [
    {"project_id": "invalid"}, {"targets": []},
    {"targets": [{"variant_id": "invalid", "package": "openssl@3.0.0"}]},
    {"replace_pending": "true"}, {"unknown": True},
])
def test_malformed_scope(client, change):
    web, scope, _ = client
    assert web.post("/api/copilot-assessments", json={**scope, **change}).status_code == 400


def test_duplicate_and_foreign_targets(client):
    web, scope, _ = client
    duplicate = {**scope, "targets": scope["targets"] * 2}
    assert web.post("/api/copilot-assessments", json=duplicate).status_code == 400
    foreign = {**scope, "project_id": str(uuid4())}
    assert web.post("/api/copilot-assessments", json=foreign).status_code == 400


def test_missing_readiness(client, monkeypatch):
    web, scope, _ = client
    monkeypatch.setattr(copilot_settings, "check_readiness",
                        lambda: {"ready": False, "errors": {"credential": "Missing token", "model": "Missing model"}})
    response = web.post("/api/copilot-assessments", json=scope)
    assert response.status_code == 503
    assert "credential" in response.get_json()["errors"]


def test_missing_packaged_mcp_rejects_start_even_with_env_path(client, monkeypatch, tmp_path):
    web, scope, _ = client
    alternative = tmp_path / "server.py"
    alternative.write_text("# unrelated script\n")
    monkeypatch.setenv("VULNSCOUT_MCP_SERVER_PATH", str(alternative))
    monkeypatch.setattr(copilot_settings, "MCP_SCRIPT", tmp_path / "missing-server.py")
    response = web.post("/api/copilot-assessments", json=scope)
    assert response.status_code == 503
    assert "mcp" in response.get_json()["errors"]
    assert registry.active() == []


def test_pending_requires_explicit_acknowledgement(client, monkeypatch):
    web, scope, finding = client
    with web.application.app_context():
        Assessment.create(status="affected", targets=[
            (UUID(scope["targets"][0]["variant_id"]), finding.id)], origin="ai")
    response = web.post("/api/copilot-assessments", json=scope)
    assert response.status_code == 409
    assert "pending" in response.get_json()["error"].lower()
    assert registry.active() == []
    monkeypatch.setattr("src.routes.copilot_assessments.queue.submit", lambda *args: None)
    assert web.post("/api/copilot-assessments", json={**scope, "replace_pending": True}).status_code == 202


def test_queued_status_and_duplicate_scope(client, monkeypatch):
    web, scope, _ = client
    monkeypatch.setattr("src.routes.copilot_assessments.queue.submit", lambda *args: None)
    response = web.post("/api/copilot-assessments", json=scope)
    assert response.status_code == 202
    op_id = response.get_json()["op_id"]
    op = next(op for op in web.get("/api/operations").get_json()["operations"] if op["op_id"] == op_id)
    assert op["status"] == "queued" and op["kind"] == op["lane"] == "assessment"
    assert op["cancellable"] is True
    assert web.post("/api/copilot-assessments", json=scope).status_code == 409
    assert web.post(
        f"/api/operations/{op_id}/cancel",
        environ_overrides={"REMOTE_ADDR": "192.0.2.1"},
    ).status_code == 403


def test_queued_job_keeps_validated_model_after_settings_change(client, monkeypatch):
    web, scope, _ = client
    queued = []
    captured = []
    monkeypatch.setattr("src.routes.copilot_assessments.queue.submit",
                        lambda _op_id, _lane, work, context: queued.append((work, context)))
    monkeypatch.setattr("src.routes.copilot_assessments.run_assessment",
                        lambda _ctx, _selection, model, _snapshot: captured.append(model))
    assert web.post("/api/copilot-assessments", json=scope).status_code == 202
    monkeypatch.setenv("COPILOT_MODEL", "other-model")
    queued[0][0](queued[0][1])
    assert captured == ["gpt-5.4"]


def test_completion_exposes_assessment_ids(client, monkeypatch):
    web, scope, _ = client
    def run(ctx, selection, model, snapshot):
        assert selection.vuln_id == scope["vuln_id"]
        assert model == "gpt-5.4"
        assert ctx.seal_cancellation()
        ctx.set_result({"assessment_ids": ["assessment-1"]})
    monkeypatch.setattr("src.routes.copilot_assessments.run_assessment", run)
    op_id = web.post("/api/copilot-assessments", json=scope).get_json()["op_id"]
    assert wait_for(op_id, "done")["result"] == {"assessment_ids": ["assessment-1"]}


def test_assessment_lane_queues_and_cancels_before_start(client, monkeypatch):
    web, scope, finding = client
    with web.application.app_context():
        variant = Variant.create("second", UUID(scope["project_id"]))
        scan = Scan.create("second observation", variant.id)
        Observation.create(finding.id, scan.id)
        other = {**scope, "targets": [
            {"variant_id": str(variant.id), "package": scope["targets"][0]["package"]},
        ]}
    running = threading.Event()
    release = threading.Event()
    calls = []

    def run(ctx, selection, model, snapshot):
        calls.append(selection.targets[0].variant_id)
        running.set()
        assert release.wait(5)

    monkeypatch.setattr("src.routes.copilot_assessments.run_assessment", run)
    first = web.post("/api/copilot-assessments", json=scope).get_json()["op_id"]
    assert running.wait(5)
    second = web.post("/api/copilot-assessments", json=other).get_json()["op_id"]
    assert registry.get(second)["status"] == "queued"
    assert web.post(f"/api/operations/{second}/cancel").status_code == 200
    assert wait_for(second, "cancelled")["result"] is None
    release.set()
    assert wait_for(first, "done")["status"] == "done"
    assert calls == [UUID(scope["targets"][0]["variant_id"])]


def test_cancel_before_write_and_during_commit(client, monkeypatch):
    web, scope, _ = client
    started = threading.Event()
    proceed = threading.Event()

    def before_write(ctx, selection, model, snapshot):
        started.set()
        assert proceed.wait(5)
        ctx.check_cancelled()
        if not ctx.seal_cancellation():
            raise CancelledError()
        ctx.set_result({"assessment_ids": ["committed"]})

    monkeypatch.setattr("src.routes.copilot_assessments.run_assessment", before_write)
    op_id = web.post("/api/copilot-assessments", json=scope).get_json()["op_id"]
    assert started.wait(5)
    assert web.post(f"/api/operations/{op_id}/cancel").status_code == 200
    proceed.set()
    assert wait_for(op_id, "cancelled")["result"] is None

    sealed = threading.Barrier(2, timeout=5)
    committed = threading.Event()

    def during_commit(ctx, selection, model, snapshot):
        assert ctx.seal_cancellation()
        sealed.wait()
        assert committed.wait(5)
        ctx.set_result({"assessment_ids": ["committed"]})

    monkeypatch.setattr("src.routes.copilot_assessments.run_assessment", during_commit)
    next_op = web.post("/api/copilot-assessments", json=scope).get_json()["op_id"]
    sealed.wait()
    assert web.post(f"/api/operations/{next_op}/cancel").status_code != 200
    assert registry.get(next_op)["cancellable"] is False
    committed.set()
    assert wait_for(next_op, "done")["result"]["assessment_ids"] == ["committed"]
