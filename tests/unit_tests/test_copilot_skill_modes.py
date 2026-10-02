"""Deployment and instruction checks for the headless assessment mode."""

import os
from pathlib import Path
import subprocess
import tempfile

import pytest


ROOT = Path(__file__).resolve().parents[2]


def test_skill_has_both_modes():
    text = (ROOT / ".github/skills/cve-assessment/SKILL.md").read_text()
    headless = text.split("### Headless output-only mode", 1)[1].split("\n---", 1)[0]
    interactive = text.split("## Phase 5: VulnScout Assessment Submission & Revision", 1)[1]
    assert "output_only=true" in headless
    assert "no MCP writes" in headless
    assert "no questions" in headless
    assert "no code fences" in headless
    assert "execution error" in headless
    assert "every selected pair" in headless
    assert '"version": 1' in text
    for key in ("targets", "variant_id", "package", "status", "justification",
                "status_notes", "impact_statement", "workaround", "responses",
                "confidence", "evidence"):
        assert f'"{key}"' in headless
    assert "vulnscout-write_assessment" in interactive
    assert "vulnscout-update_ai_assessment" in interactive
    assert "/scan/project-source" in headless
    assert "symlinks" in headless
    assert "default_objectives" in headless
    assert "objectives_by_variant" in headless
    assert "read-only prompt data" in headless


def test_image_packages_skill_server_and_runtime():
    text = (ROOT / "Dockerfile").read_text()
    assert "COPY requirements/mcp.txt /scan/mcp.txt" in text
    assert "pip3 install --no-cache-dir -r /scan/mcp.txt --break-system-packages" in text
    assert "COPY .github/skills/cve-assessment /scan/.github/skills/cve-assessment" in text
    assert "COPY vulnscout_mcp /scan/vulnscout_mcp" in text
    assert "RUN python3 -m copilot download-runtime" in text
    assert (ROOT / "vulnscout_mcp/server.py").is_file()


def test_optional_source_root_is_read_only_and_checked():
    text = (ROOT / "vulnscout").read_text()
    assert '[[ -n "${VULNSCOUT_SOURCE_ROOT:-}" ]]' in text
    assert '[[ -d "$VULNSCOUT_SOURCE_ROOT" ]]' in text
    assert '"$VULNSCOUT_SOURCE_ROOT:/scan/project-source:ro,Z"' in text
    assert "container_has_source_mount" in text
    assert text.index('[[ -d "$VULNSCOUT_SOURCE_ROOT" ]]', text.index("do_start() {")) < text.index(
        'call_container_engine rm -f "$CONTAINER_NAME"', text.index("do_start() {"))
    assert "-p 127.0.0.1:7275:7275" in text


def test_copilot_docs_verify_loopback_and_use_disposable_volume():
    text = (ROOT / "doc/source/ai-assessments.md").read_text()
    assert '.HostConfig.PortBindings "7275/tcp"' in text
    assert "127.0.0.1:7275" in text
    assert "28.0.0" in text
    assert "same layer-2 network" in text
    assert "separately proven" in text
    assert "volume=$(docker volume create)" in text
    assert 'docker volume rm "$volume"' in text
    assert "docker volume create vulnscout-copilot-doc-smoke" not in text
    readme = (ROOT / "README.adoc").read_text()
    assert "Docker server >=28.0.0" in readme
    assert "separately proven" in readme


@pytest.mark.parametrize(
    ("engine", "version", "enabled", "command", "allowed"),
    [
        ("docker", "27.5.1", True, "--start", False),
        ("docker", "27.5.1", True, "--restart", False),
        ("docker", "27.5.1", True, "--refresh-vulnerability-data", False),
        ("docker", "28.0.0-rc1", True, "--start", False),
        ("docker", "unknown", True, "--start", False),
        ("docker", "28.0.0", True, "--start", True),
        ("docker", "29.1.0", True, "--refresh-vulnerability-data", True),
        ("docker", "27.5.1", False, "--start", True),
        ("podman", "27.5.1", True, "--start", True),
    ],
)
def test_docker_version_gate_for_agent(engine, version, enabled, command, allowed):
    with tempfile.TemporaryDirectory(dir=ROOT) as workdir:
        work = Path(workdir)
        bin_dir = work / "bin"
        bin_dir.mkdir()
        executable = bin_dir / engine
        executable.write_text("""#!/bin/bash
set -euo pipefail
printf '%s\\n' "$*" >> "$VULNSCOUT_TEST_LOG"
case "$1" in
  version)
    [[ "$VULNSCOUT_TEST_VERSION" != unknown ]] || exit 1
    echo "$VULNSCOUT_TEST_VERSION" ;;
  ps) echo vulnscout ;;
  inspect)
    if [[ "$*" == *'.HostConfig.PortBindings'* ]]; then
      echo 127.0.0.1:7275
    fi ;;
  rm|run|exec) : ;;
  *) exit 99 ;;
esac
""")
        executable.chmod(0o755)
        cache = work / "build" / "cache"
        cache.mkdir(parents=True)
        (cache / "config.env").write_text(
            f"VULNSCOUT_AGENT_ENABLED={int(enabled)}\n"
        )
        log = work / "calls.log"
        env = os.environ.copy()
        env.update(
            PATH=f"{bin_dir}:/usr/bin:/bin",
            VULNSCOUT_BUILD_DIR=str(work / "build"),
            VULNSCOUT_TEST_LOG=str(log),
            VULNSCOUT_TEST_VERSION=version,
        )
        env.pop("VULNSCOUT_AGENT_ENABLED", None)
        result = subprocess.run(
            [str(ROOT / "vulnscout"), command],
            env=env, capture_output=True, text=True,
        )
        assert (result.returncode == 0) == allowed, result.stderr
        calls = log.read_text().splitlines() if log.exists() else []
        assert any(line.startswith("version ") for line in calls) == (engine == "docker" and enabled)
        if not allowed:
            assert "Docker server >=28.0.0" in result.stderr
            assert not any(line.startswith(("rm ", "run ")) for line in calls), calls
        elif command in ("--start", "--restart"):
            assert any(line.startswith("run -d ") for line in calls), calls


@pytest.mark.parametrize(
    ("mounted", "read_write", "requested", "restart"),
    [
        ("source-a", False, "source-a", False),
        ("source-a", False, "source-b", True),
        ("source-a", False, None, True),
        ("source-a", True, "source-a", True),
        (None, False, None, False),
        (None, False, "source-a", True),
    ],
)
def test_running_container_source_mount_state(mounted, read_write, requested, restart):
    with tempfile.TemporaryDirectory(dir=ROOT) as workdir:
        work = Path(workdir)
        for name in ("source-a", "source-b"):
            (work / name).mkdir()
        bin_dir = work / "bin"
        bin_dir.mkdir()
        podman = bin_dir / "podman"
        podman.write_text("""#!/bin/bash
set -euo pipefail
printf '%s\\n' "$*" >> "$VULNSCOUT_TEST_LOG"
case "$1" in
  ps) echo vulnscout ;;
  inspect)
    if [[ "$*" == *'.HostConfig.PortBindings'* ]]; then
      echo 127.0.0.1:7275
    elif [[ -n "${VULNSCOUT_TEST_MOUNT:-}" ]]; then
      if [[ "$*" == *'.RW'* ]]; then
        echo "$VULNSCOUT_TEST_MOUNT $VULNSCOUT_TEST_RW"
      else
        echo "$VULNSCOUT_TEST_MOUNT"
      fi
    fi ;;
  rm|run) : ;;
  exec) : ;;
  *) exit 99 ;;
esac
""")
        podman.chmod(0o755)
        log = work / "calls.log"
        env = os.environ.copy()
        env.update(
            PATH=f"{bin_dir}:/usr/bin:/bin",
            VULNSCOUT_BUILD_DIR=str(work / "build"),
            VULNSCOUT_TEST_LOG=str(log),
            VULNSCOUT_TEST_MOUNT=str(work / mounted) if mounted else "",
            VULNSCOUT_TEST_RW="true" if read_write else "false",
        )
        env.pop("VULNSCOUT_SOURCE_ROOT", None)
        if requested:
            env["VULNSCOUT_SOURCE_ROOT"] = str(work / requested)
        result = subprocess.run(
            [str(ROOT / "vulnscout"), "--refresh-vulnerability-data"],
            env=env, capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr
        calls = log.read_text().splitlines()
        removed = [line for line in calls if line.startswith("rm -f ")]
        runs = [line for line in calls if line.startswith("run -d ")]
        assert bool(removed) == bool(runs) == restart, calls
        if restart:
            mount_arg = f"{work / requested}:/scan/project-source:ro,Z" if requested else "/scan/project-source:"
            assert (mount_arg in runs[0]) == bool(requested), runs
            assert "-p 127.0.0.1:7275:7275" in runs[0]


@pytest.mark.parametrize(
    ("binding", "restart"),
    [
        ("0.0.0.0:7275", True),
        ("127.0.0.1:8484", True),
        ("", True),
        ("127.0.0.1:7275", False),
    ],
)
def test_running_container_replaces_unsafe_port_binding(binding, restart):
    with tempfile.TemporaryDirectory(dir=ROOT) as workdir:
        work = Path(workdir)
        source = work / "source"
        source.mkdir()
        bin_dir = work / "bin"
        bin_dir.mkdir()
        podman = bin_dir / "podman"
        podman.write_text("""#!/bin/bash
set -euo pipefail
printf '%s\\n' "$*" >> "$VULNSCOUT_TEST_LOG"
case "$1" in
  ps) echo vulnscout ;;
  inspect)
    if [[ "$*" == *'.HostConfig.PortBindings'* ]]; then
      printf '%s\\n' "$VULNSCOUT_TEST_BINDING"
    elif [[ "$*" == *'.RW'* ]]; then
      printf '%s false\\n' "$VULNSCOUT_SOURCE_ROOT"
    else
      printf '%s\\n' "$VULNSCOUT_SOURCE_ROOT"
    fi ;;
  rm|run|exec) : ;;
  *) exit 99 ;;
esac
""")
        podman.chmod(0o755)
        log = work / "calls.log"
        env = os.environ.copy()
        env.update(
            PATH=f"{bin_dir}:/usr/bin:/bin",
            VULNSCOUT_BUILD_DIR=str(work / "build"),
            VULNSCOUT_TEST_LOG=str(log),
            VULNSCOUT_TEST_BINDING=binding,
            VULNSCOUT_SOURCE_ROOT=str(source),
        )
        result = subprocess.run(
            [str(ROOT / "vulnscout"), "--refresh-vulnerability-data"],
            env=env, capture_output=True, text=True,
        )
        assert result.returncode == 0, result.stderr
        calls = log.read_text().splitlines()
        removed = [line for line in calls if line.startswith("rm -f ")]
        runs = [line for line in calls if line.startswith("run -d ")]
        assert bool(removed) == bool(runs) == restart, calls
        if restart:
            assert "-p 127.0.0.1:7275:7275" in runs[0]
            assert f"{source}:/scan/project-source:ro,Z" in runs[0]
            assert f"{work / 'build' / 'cache'}:/cache/vulnscout:Z" in runs[0]
            assert f"{work / 'build' / 'outputs'}:/scan/outputs:Z" in runs[0]


def test_invalid_source_root_does_not_remove_running_container():
    with tempfile.TemporaryDirectory(dir=ROOT) as workdir:
        work = Path(workdir)
        bin_dir = work / "bin"
        bin_dir.mkdir()
        podman = bin_dir / "podman"
        podman.write_text("""#!/bin/bash
printf '%s\\n' "$*" >> "$VULNSCOUT_TEST_LOG"
case "$1" in
  ps) echo vulnscout ;;
  inspect) echo "$VULNSCOUT_SOURCE_ROOT" ;;
  *) exit 99 ;;
esac
""")
        podman.chmod(0o755)
        log = work / "calls.log"
        env = os.environ.copy()
        env.update(
            PATH=f"{bin_dir}:/usr/bin:/bin",
            VULNSCOUT_TEST_LOG=str(log),
            VULNSCOUT_SOURCE_ROOT=str(work / "missing"),
        )
        result = subprocess.run(
            [str(ROOT / "vulnscout"), "--refresh-vulnerability-data"],
            env=env, capture_output=True, text=True,
        )
        assert result.returncode != 0
        assert "Source root not found" in result.stderr
        assert not log.exists()
