import logging
from types import SimpleNamespace

import pytest


@pytest.fixture
def client(monkeypatch, tmp_path):
    import copilot

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


def test_readiness_succeeds_with_runtime_skill_and_mcp(client, tmp_path, monkeypatch):
    mcp = tmp_path / "run_server.py"
    mcp.write_text("# test MCP entry point\n")
    monkeypatch.setenv("VULNSCOUT_MCP_SERVER_PATH", str(mcp))
    assert client.put("/api/config/copilot", json={
        "token": "github_pat_test", "model": "gpt-5.4"}).status_code == 200
    response = client.post("/api/config/copilot/check")
    assert response.get_json() == {
        "ready": True, "errors": {}, "available_models": ["gpt-5.4"]}
    assert response.headers["Cache-Control"] == "no-store"


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
