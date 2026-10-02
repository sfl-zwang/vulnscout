"""Instance Copilot credentials and headless assessment readiness."""

import asyncio
import logging
import os
import re
import secrets
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from mcp import ClientSession, StdioServerParameters, types
from mcp.client.stdio import stdio_client


_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
logger = logging.getLogger(__name__)
MCP_SCRIPT = Path(__file__).resolve().parents[2] / "vulnscout_mcp/server.py"
READ_MCP = (
    "get_vulnerability", "get_merged_context", "get_project_context",
    "get_custom_assessment", "list_custom_assessments", "get_assessment",
    "list_assessments_by_vuln",
)


def valid_model(model: object) -> bool:
    return isinstance(model, str) and bool(_MODEL_ID.fullmatch(model))


def configured_model() -> str:
    value = os.getenv("COPILOT_MODEL", "")
    return value if valid_model(value) else ""


def _secret_path() -> Path:
    cache = Path(os.getenv("VULNSCOUT_CACHE_DIR", "/cache/vulnscout"))
    if cache.is_symlink():
        raise ValueError("Invalid Copilot cache directory.")
    return cache / "copilot-token"


def _check_existing(path: Path) -> bool:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
        raise ValueError("Invalid Copilot credential file.")
    return True


def read_token() -> str | None:
    path = _secret_path()
    if not _check_existing(path):
        return None
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600:
            raise ValueError("Invalid Copilot credential file.")
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            fd = -1
            value = stream.read(4097)
        if not value or len(value) > 4096 or "\n" in value or "\r" in value:
            raise ValueError("Invalid Copilot credential file.")
        return value
    finally:
        if fd != -1:
            os.close(fd)


def save_token(value: str) -> None:
    if not isinstance(value, str) or not value or len(value) > 4096 or "\n" in value or "\r" in value:
        raise ValueError("Invalid Copilot credential.")
    path = _secret_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ValueError("Invalid Copilot cache directory.")
    _check_existing(path)
    temporary = path.parent / f".copilot-token-{secrets.token_hex(16)}"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.flush()
            os.fsync(stream.fileno())
        _check_existing(path)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def remove_token() -> None:
    path = _secret_path()
    if _check_existing(path):
        path.unlink()


def model_access_error(token: str, model: str) -> str | None:
    try:
        errors, _ = asyncio.run(_probe(token, model))
    except Exception:
        return "Could not verify Copilot model availability."
    return errors.get("authentication") or errors.get("model")


async def _probe_mcp_tools(base_url: str) -> bool:
    params = StdioServerParameters(
        command=sys.executable, args=[str(MCP_SCRIPT)], env={"VULNSCOUT_BASE_URL": base_url},
    )
    async with asyncio.timeout(8):
        with open(os.devnull, "w") as errlog:
            async with stdio_client(params, errlog=errlog) as (read, write):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    names: set[str] = set()
                    cursor = None
                    while True:
                        result = await session.list_tools(
                            params=types.PaginatedRequestParams(cursor=cursor) if cursor else None,
                        )
                        names.update(tool.name for tool in result.tools)
                        cursor = result.next_cursor
                        if not cursor:
                            return set(READ_MCP) <= names


def _probe_read_tools() -> bool:
    base_url = os.getenv("VULNSCOUT_AGENT_API_URL", "http://localhost:7275").rstrip("/")
    try:
        parsed = urlsplit(base_url)
        if (parsed.scheme not in ("http", "https") or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment):
            return False
        response = httpx.get(f"{base_url}/api/projects", timeout=2.0, follow_redirects=False)
        if response.status_code != 200 or not isinstance(response.json(), list):
            return False
        return asyncio.run(_probe_mcp_tools(base_url))
    except (httpx.HTTPError, ValueError, OSError, TimeoutError, ExceptionGroup) as error:
        logger.warning("Read-only MCP preflight failed (%s)", type(error).__name__)
        return False


async def _probe(token: str, model: str) -> tuple[dict[str, str], list[str]]:
    from copilot import CopilotClient

    errors: dict[str, str] = {}
    available_models: list[str] = []
    async with CopilotClient(github_token=token, use_logged_in_user=False) as client:
        try:
            auth = await client.get_auth_status()
            if not auth.isAuthenticated:
                errors["authentication"] = "Configured Copilot token was not authenticated."
        except Exception:
            errors["authentication"] = "Could not verify configured Copilot authentication."
        try:
            models = await client.list_models()
            available_models = [item.id for item in models if valid_model(item.id)]
            if model and model not in available_models:
                errors["model"] = "Selected Copilot model is unavailable to this identity."
        except Exception:
            errors["model"] = "Could not retrieve available Copilot models."
    return errors, available_models


def check_readiness() -> dict:
    errors: dict[str, str] = {}
    available_models: list[str] = []
    try:
        token = read_token()
    except (OSError, ValueError, UnicodeError):
        token = None
        errors["credential"] = "Copilot credential file is missing or invalid."
    if not token and "credential" not in errors:
        errors["credential"] = "Configure a Copilot token first."
    model = configured_model()
    if not model:
        errors["model"] = "Select a valid Copilot model."
    skill = Path(__file__).resolve().parents[2] / ".github/skills/cve-assessment/SKILL.md"
    if not skill.is_file():
        errors["skill"] = "The cve-assessment skill is not installed."
    if not MCP_SCRIPT.is_file():
        errors["mcp"] = "The packaged VulnScout MCP server script is unavailable."
    elif not _probe_read_tools():
        errors["mcp"] = (
            "VulnScout read-only MCP tools are unavailable. Check VULNSCOUT_AGENT_API_URL "
            "and the packaged MCP server."
        )
    if token:
        try:
            probe_errors, available_models = asyncio.run(_probe(token, model))
            errors.update(probe_errors)
        except Exception:
            errors["runtime"] = "Could not start the local Copilot runtime. Verify SDK setup and network access."
    return {"ready": not errors, "errors": errors, "available_models": available_models}
