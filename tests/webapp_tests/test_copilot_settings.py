import json
import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest


@pytest.fixture
def client(monkeypatch, tmp_path):
    import copilot
    import httpx

    class AvailableClient:
        def __init__(self, **kwargs):
            assert kwargs["github_token"] == "github_pat_test"
            assert kwargs["use_logged_in_user"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def get_auth_status(self):
            return SimpleNamespace(isAuthenticated=True)

        async def list_models(self):
            return [SimpleNamespace(id="gpt-5.4")]

    monkeypatch.setattr(copilot, "CopilotClient", AvailableClient)
    monkeypatch.setattr(httpx, "get", lambda *_args, **_kwargs: httpx.Response(200, json=[]))
    monkeypatch.setenv("FLASK_SQLALCHEMY_DATABASE_URI", "sqlite:///:memory:")
    monkeypatch.setenv("VULNSCOUT_AGENT_ENABLED", "1")
    monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(tmp_path))
    monkeypatch.setenv("VULNSCOUT_CONFIG", str(tmp_path / "config.env"))
    monkeypatch.delenv("COPILOT_MODEL", raising=False)
    monkeypatch.delenv("VULNSCOUT_MCP_SERVER_PATH", raising=False)
    scan_file = tmp_path / "scan_status.txt"
    scan_file.write_text("__END_OF_SCAN_SCRIPT__")
    from src.bin.webapp import create_app
    from src.extensions import db

    app = create_app()
    app.config.update(TESTING=True, SCAN_FILE=str(scan_file))
    with app.app_context():
        db.create_all()
        yield app.test_client()
        db.drop_all()


def test_token_stays_private_and_survives_read(client, tmp_path, caplog):
    from src.controllers.event_bus import operation_events

    previous_seq = operation_events.seq
    with caplog.at_level(logging.DEBUG):
        response = client.put("/api/config/copilot", json={
            "token": "github_pat_test", "model": "gpt-5.4"})
        assert response.status_code == 200
        assert "github_pat_test" not in response.get_data(as_text=True)
        assert "github_pat_test" not in client.get("/api/config/copilot").get_data(as_text=True)
    token_file = tmp_path / "copilot-token"
    assert token_file.stat().st_mode & 0o777 == 0o600
    assert token_file.read_text() == "github_pat_test"
    assert "github_pat_test" not in (tmp_path / "config.env").read_text()
    assert "github_pat_test" not in caplog.text
    events = operation_events.replay_since(previous_seq)
    assert events is not None
    assert "github_pat_test" not in json.dumps(list(events))
    from src.controllers.copilot_settings import read_token

    assert read_token() == "github_pat_test"
    assert client.get("/api/config/copilot").get_json()["has_token"] is True
    assert client.get("/api/config").get_json()["copilot_model"] == "gpt-5.4"


def test_delete_removes_only_the_token(client, tmp_path):
    client.put("/api/config/copilot", json={"token": "github_pat_test", "model": "gpt-5.4"})
    response = client.delete("/api/config/copilot")
    assert response.status_code == 200
    assert response.get_json()["has_token"] is False
    assert not (tmp_path / "copilot-token").exists()
    assert client.get("/api/config").get_json()["copilot_model"] == "gpt-5.4"


def test_missing_token_does_not_use_ambient_login(client, monkeypatch, tmp_path):
    monkeypatch.setenv("GH_TOKEN", "ambient_secret")
    response = client.post("/api/config/copilot/check")
    assert response.status_code == 200
    assert response.get_json()["ready"] is False
    assert "credential" in response.get_json()["errors"]
    assert "ambient_secret" not in response.get_data(as_text=True)
    assert not (tmp_path / "copilot-token").exists()


@pytest.mark.parametrize("bad", ["a; touch leaked", "a\nINJECTED=x", "../model", "a" * 129, 123])
def test_bad_model_rejected_without_config_write(client, tmp_path, bad):
    response = client.put("/api/config/copilot", json={"token": "secret", "model": bad})
    assert response.status_code == 400
    assert not (tmp_path / "copilot-token").exists()
    assert not (tmp_path / "config.env").exists()
    assert client.patch("/api/config", json={"copilot_model": bad}).status_code == 400


def test_symlink_and_invalid_secret_files_are_rejected(client, tmp_path):
    target = tmp_path / "elsewhere"
    target.write_text("other-secret")
    (tmp_path / "copilot-token").symlink_to(target)
    assert client.get("/api/config/copilot").status_code == 500
    assert client.put("/api/config/copilot", json={"token": "new-secret"}).status_code == 500
    assert client.delete("/api/config/copilot").status_code == 500
    assert target.read_text() == "other-secret"
    (tmp_path / "copilot-token").unlink()
    (tmp_path / "copilot-token").write_text("insecure")
    assert client.get("/api/config/copilot").status_code == 500
    assert client.put("/api/config/copilot", json={"token": "new-secret"}).status_code == 500


@pytest.mark.parametrize("method,path", [
    ("get", "/api/config/copilot"), ("put", "/api/config/copilot"),
    ("delete", "/api/config/copilot"), ("post", "/api/config/copilot/check"),
])
def test_every_sensitive_endpoint_enforces_local_access(client, monkeypatch, method, path):
    send = getattr(client, method)
    assert send(path, environ_overrides={"REMOTE_ADDR": "192.0.2.1"}).status_code == 403
    assert send(path, headers={"Host": "example.org"}).status_code == 403
    if method != "get":
        assert send(path, headers={"Origin": "https://example.org"}).status_code == 403
    monkeypatch.delenv("VULNSCOUT_AGENT_ENABLED")
    assert send(path).status_code == 404


def test_model_patch_uses_same_access_guard(client, monkeypatch):
    assert client.patch("/api/config", json={"copilot_model": "gpt-5.4"},
                        headers={"Origin": "https://example.org"}).status_code == 403
    monkeypatch.delenv("VULNSCOUT_AGENT_ENABLED")
    assert client.patch("/api/config", json={"copilot_model": "gpt-5.4"}).status_code == 404


def test_check_reports_independent_failures_without_leaking_token(client, tmp_path, monkeypatch):
    import copilot
    from src.controllers import copilot_settings

    instances = []

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["github_token"] == "github_pat_test"
            assert kwargs["use_logged_in_user"] is False
            instances.append(self)
            self.closed = False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            self.closed = True

        async def get_auth_status(self):
            return SimpleNamespace(isAuthenticated=True)

        async def list_models(self):
            return [SimpleNamespace(id="gpt-5.4"), SimpleNamespace(id="other-model")]

    client.put("/api/config/copilot", json={"token": "github_pat_test", "model": "gpt-5.4"})
    monkeypatch.setattr(copilot_settings, "MCP_SCRIPT", tmp_path / "missing-server.py")
    monkeypatch.setattr(copilot, "CopilotClient", FakeClient)
    response = client.post("/api/config/copilot/check")
    assert response.status_code == 200
    assert response.get_json()["ready"] is False
    assert "mcp" in response.get_json()["errors"]
    assert "authentication" not in response.get_json()["errors"]
    assert "model" not in response.get_json()["errors"]
    assert instances[-1].closed is True
    assert "github_pat_test" not in response.get_data(as_text=True)
    assert "github_pat_test" not in (tmp_path / "config.env").read_text()


def test_check_model_unavailable_and_auth_failure_close_client(client, monkeypatch, tmp_path):
    import copilot

    instances = []

    class FakeClient:
        def __init__(self, **kwargs):
            assert kwargs["use_logged_in_user"] is False
            self.closed = False
            instances.append(self)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            self.closed = True

        async def get_auth_status(self):
            return SimpleNamespace(isAuthenticated=False)

        async def list_models(self):
            return [SimpleNamespace(id="other-model")]

    client.put("/api/config/copilot", json={"token": "github_pat_test", "model": "gpt-5.4"})
    monkeypatch.setattr(copilot, "CopilotClient", FakeClient)
    response = client.post("/api/config/copilot/check")
    assert {"authentication", "model"} <= response.get_json()["errors"].keys()
    assert instances[-1].closed is True


def test_check_runtime_exception_is_safe(client, monkeypatch):
    import copilot

    class BrokenClient:
        def __init__(self, **kwargs):
            assert kwargs["use_logged_in_user"] is False

        async def __aenter__(self):
            raise RuntimeError("github_pat_test")

        async def __aexit__(self, *_):
            pass

    client.put("/api/config/copilot", json={"token": "github_pat_test", "model": "gpt-5.4"})
    monkeypatch.setattr(copilot, "CopilotClient", BrokenClient)
    response = client.post("/api/config/copilot/check")
    assert response.get_json()["ready"] is False
    assert "runtime" in response.get_json()["errors"]
    assert "github_pat_test" not in response.get_data(as_text=True)


def test_rejects_model_not_available_to_token(client, monkeypatch, tmp_path):
    import copilot

    class MissingModel:
        def __init__(self, **kwargs):
            assert kwargs["use_logged_in_user"] is False

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            pass

        async def get_auth_status(self):
            return SimpleNamespace(isAuthenticated=True)

        async def list_models(self):
            return [SimpleNamespace(id="other-model")]

    monkeypatch.setattr(copilot, "CopilotClient", MissingModel)
    response = client.put("/api/config/copilot", json={"token": "github_pat_test", "model": "gpt-5.4"})
    assert response.status_code == 400
    assert not (tmp_path / "copilot-token").exists()
    assert not (tmp_path / "config.env").exists()


def test_valid_model_patch_requires_token_and_available_model(client, tmp_path):
    assert client.patch("/api/config", json={"copilot_model": "gpt-5.4"}).status_code == 400
    assert client.put("/api/config/copilot", json={"token": "github_pat_test"}).status_code == 200
    assert client.patch("/api/config", json={"copilot_model": "gpt-5.4"}).status_code == 200
    assert "COPILOT_MODEL=gpt-5.4" in (tmp_path / "config.env").read_text()


def test_readiness_succeeds_with_runtime_skill_and_mcp(client):
    from src.controllers import copilot_settings
    from src.controllers.copilot_assessment_runner import MCP_SCRIPT

    assert copilot_settings.MCP_SCRIPT == MCP_SCRIPT
    assert MCP_SCRIPT.is_file()
    assert client.put("/api/config/copilot", json={
        "token": "github_pat_test", "model": "gpt-5.4"}).status_code == 200
    response = client.post("/api/config/copilot/check")
    assert response.get_json() == {
        "ready": True, "errors": {}, "available_models": ["gpt-5.4"]}
    assert response.headers["Cache-Control"] == "no-store"


def test_readiness_probes_read_only_api_without_credentials(client, monkeypatch):
    import httpx
    calls = []

    def get(url, **kwargs):
        calls.append((url, kwargs))
        return httpx.Response(200, json=[])

    monkeypatch.setattr(httpx, "get", get)
    monkeypatch.setenv("VULNSCOUT_AGENT_API_URL", "http://localhost:7275")
    assert client.put("/api/config/copilot", json={
        "token": "github_pat_test", "model": "gpt-5.4"}).status_code == 200
    response = client.post("/api/config/copilot/check")
    assert response.get_json() == {
        "ready": True, "errors": {}, "available_models": ["gpt-5.4"]}
    assert calls == [("http://localhost:7275/api/projects",
                      {"timeout": 2.0, "follow_redirects": False})]


def test_readiness_reports_unavailable_read_tools(client, monkeypatch):
    import httpx
    monkeypatch.setenv("VULNSCOUT_AGENT_API_URL", "http://localhost:1")

    def unavailable(*_args, **_kwargs):
        raise httpx.ConnectError("private credential must not be shown")

    monkeypatch.setattr(httpx, "get", unavailable)
    assert client.put("/api/config/copilot", json={
        "token": "github_pat_test", "model": "gpt-5.4"}).status_code == 200
    response = client.post("/api/config/copilot/check")
    data = response.get_json()
    assert data["ready"] is False
    assert data["available_models"] == ["gpt-5.4"]
    assert "VULNSCOUT_AGENT_API_URL" in data["errors"]["mcp"]
    assert "private credential" not in response.get_data(as_text=True)
    assert "github_pat_test" not in response.get_data(as_text=True)


@pytest.mark.parametrize("status,payload", [(503, []), (200, {"error": "wrong service"})])
def test_readiness_rejects_non_read_tool_response(client, monkeypatch, status, payload):
    import httpx

    monkeypatch.setattr(httpx, "get",
                        lambda *_args, **_kwargs: httpx.Response(status, json=payload))
    assert client.put("/api/config/copilot", json={
        "token": "github_pat_test", "model": "gpt-5.4"}).status_code == 200
    data = client.post("/api/config/copilot/check").get_json()
    assert data["ready"] is False
    assert set(data) == {"ready", "errors", "available_models"}
    assert set(data["errors"]) == {"mcp"}
    assert data["available_models"] == ["gpt-5.4"]


def test_readiness_rejects_missing_packaged_mcp_even_with_env_path(client, tmp_path, monkeypatch):
    from src.controllers import copilot_settings

    alternative = tmp_path / "server.py"
    alternative.write_text("# unrelated script\n")
    monkeypatch.setenv("VULNSCOUT_MCP_SERVER_PATH", str(alternative))
    monkeypatch.setattr(copilot_settings, "MCP_SCRIPT", tmp_path / "missing-server.py")
    assert client.put("/api/config/copilot", json={
        "token": "github_pat_test", "model": "gpt-5.4"}).status_code == 200
    response = client.post("/api/config/copilot/check")
    assert response.get_json()["ready"] is False
    assert "mcp" in response.get_json()["errors"]


def test_cache_directory_symlink_does_not_redirect_secret(client, tmp_path, monkeypatch):
    actual = tmp_path / "actual"
    actual.mkdir()
    link = tmp_path / "redirect"
    link.symlink_to(actual, target_is_directory=True)
    monkeypatch.setenv("VULNSCOUT_CACHE_DIR", str(link))
    assert client.put("/api/config/copilot", json={"token": "github_pat_test"}).status_code == 500
    assert client.get("/api/config/copilot").status_code == 500
    assert client.delete("/api/config/copilot").status_code == 500
    assert list(actual.iterdir()) == []


def test_invalid_existing_secret_does_not_change_model(client, tmp_path):
    (tmp_path / "copilot-token").write_text("untrusted")
    response = client.put("/api/config/copilot", json={
        "token": "github_pat_test", "model": "gpt-5.4"})
    assert response.status_code == 500
    assert not (tmp_path / "config.env").exists()


def test_token_save_failure_preserves_active_and_persisted_model(client, tmp_path, monkeypatch):
    from src.controllers import copilot_settings

    assert client.put("/api/config/copilot", json={
        "token": "github_pat_test", "model": "gpt-5.4"}).status_code == 200
    config_file = tmp_path / "config.env"
    original_config = config_file.read_text()
    assert "COPILOT_MODEL=gpt-5.4" in original_config

    monkeypatch.setattr(copilot_settings, "model_access_error", lambda *_: None)

    def fail_save(_token):
        raise OSError("credential store unavailable")

    monkeypatch.setattr(copilot_settings, "save_token", fail_save)
    response = client.put("/api/config/copilot", json={
        "token": "github_pat_new", "model": "other-model"})

    assert response.status_code == 500
    assert config_file.read_text() == original_config
    assert client.get("/api/config").get_json()["copilot_model"] == "gpt-5.4"
    assert client.get("/api/config/copilot").get_json()["model"] == "gpt-5.4"
    assert copilot_settings.read_token() == "github_pat_test"


@pytest.mark.parametrize("previous_token", [True, False])
def test_model_write_failure_restores_previous_credentials_and_model(
    client, tmp_path, monkeypatch, caplog, previous_token,
):
    from src.controllers import copilot_settings
    from src.routes import config

    assert client.put("/api/config/copilot", json={
        "token": "github_pat_test", "model": "gpt-5.4"}).status_code == 200
    if not previous_token:
        assert client.delete("/api/config/copilot").status_code == 200
    config_file = tmp_path / "config.env"
    original_config = config_file.read_text()
    monkeypatch.setattr(copilot_settings, "model_access_error", lambda *_: None)
    monkeypatch.setattr(config, "_write_config_key", lambda *_: False)

    with caplog.at_level(logging.DEBUG):
        response = client.put("/api/config/copilot", json={
            "token": "github_pat_new", "model": "other-model"})

    assert response.status_code == 500
    assert copilot_settings.read_token() == ("github_pat_test" if previous_token else None)
    assert (tmp_path / "copilot-token").exists() is previous_token
    assert config_file.read_text() == original_config
    assert client.get("/api/config").get_json()["copilot_model"] == "gpt-5.4"
    assert client.get("/api/config/copilot").get_json()["model"] == "gpt-5.4"
    for secret in ("github_pat_test", "github_pat_new"):
        assert secret not in response.get_data(as_text=True)
        assert secret not in caplog.text


def test_failed_put_cannot_resurrect_concurrent_delete(client, tmp_path, monkeypatch):
    from src.controllers import copilot_settings
    from src.routes import config

    assert client.put("/api/config/copilot", json={
        "token": "github_pat_test", "model": "gpt-5.4"}).status_code == 200
    monkeypatch.setattr(copilot_settings, "model_access_error", lambda *_: None)
    model_write_started = threading.Event()
    allow_model_write_failure = threading.Event()
    delete_started = threading.Event()
    delete_finished = threading.Event()

    def fail_model_write(key, value):
        assert (key, value) == ("COPILOT_MODEL", "other-model")
        model_write_started.set()
        assert allow_model_write_failure.wait(timeout=5)
        return False

    monkeypatch.setattr(config, "_write_config_key", fail_model_write)

    def put():
        with client.application.test_client() as request_client:
            return request_client.put("/api/config/copilot", json={
                "token": "github_pat_new", "model": "other-model"})

    def delete():
        delete_started.set()
        with client.application.test_client() as request_client:
            try:
                return request_client.delete("/api/config/copilot")
            finally:
                delete_finished.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        put_result = executor.submit(put)
        try:
            assert model_write_started.wait(timeout=5)
            delete_result = executor.submit(delete)
            assert delete_started.wait(timeout=5)
            assert not delete_finished.wait(timeout=0.2)
        finally:
            allow_model_write_failure.set()
        assert put_result.result(timeout=5).status_code == 500
        assert delete_result.result(timeout=5).status_code == 200

    assert copilot_settings.read_token() is None
    assert not (tmp_path / "copilot-token").exists()
    assert client.get("/api/config").get_json()["copilot_model"] == "gpt-5.4"


def test_model_patch_finishes_before_concurrent_delete(client, monkeypatch, tmp_path):
    from src.controllers import copilot_settings

    assert client.put("/api/config/copilot", json={"token": "github_pat_test"}).status_code == 200
    model_check_started = threading.Event()
    allow_model_check = threading.Event()
    delete_started = threading.Event()
    delete_finished = threading.Event()

    def check_model(_token, _model):
        model_check_started.set()
        assert allow_model_check.wait(timeout=5)
        return None

    monkeypatch.setattr(copilot_settings, "model_access_error", check_model)

    def patch():
        with client.application.test_client() as request_client:
            return request_client.patch("/api/config", json={"copilot_model": "gpt-5.4"})

    def delete():
        delete_started.set()
        with client.application.test_client() as request_client:
            try:
                return request_client.delete("/api/config/copilot")
            finally:
                delete_finished.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        patch_result = executor.submit(patch)
        try:
            assert model_check_started.wait(timeout=5)
            delete_result = executor.submit(delete)
            assert delete_started.wait(timeout=5)
            assert not delete_finished.wait(timeout=0.2)
        finally:
            allow_model_check.set()
        assert patch_result.result(timeout=5).status_code == 200
        assert delete_result.result(timeout=5).status_code == 200

    assert copilot_settings.read_token() is None
    assert "COPILOT_MODEL=gpt-5.4" in (tmp_path / "config.env").read_text()
