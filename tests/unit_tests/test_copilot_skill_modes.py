"""Deployment and instruction checks for the headless assessment mode."""

from pathlib import Path


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
