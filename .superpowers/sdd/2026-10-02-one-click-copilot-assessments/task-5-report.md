# Task 5 report — scoped Copilot assessment runner

**Status: DONE_WITH_CONCERNS**

**Code/test commit:** `850557d4 feat: run scoped Copilot assessments` (contains the requested Co-authored-by trailer).

## Delivered

- `run_assessment(ctx, selection, model, expected_snapshot)` rejects absent/invalid credentials before constructing a client, requires the configured instance model, and uses `CopilotClient(github_token=token, use_logged_in_user=False, mode="empty")`.
- The session uses the packaged assessment skill in output-only mode. Its only available tools are audited read-only VulnScout MCP tools and three bounded custom tools: `read_project_file`, `search_project_text`, and `fetch_advisory`. Permission requests for everything else are denied. Config discovery, host git operations, and file hooks are disabled. No token is put in the MCP environment or included in errors/logs.
- Configured source roots must resolve within `/scan/project-source`; source reads reject relative traversal and symlink escapes, use no-follow file descriptors, and limit size. Searches bound directory/file counts and results. Advisory fetches require HTTPS and allowlisted hosts, reject non-public DNS answers, connect to a pinned public IP with host-verified TLS, and revalidate redirects and response sizes.
- The SDK must emit a connected status for the local MCP server; failure or missing health status fails closed before persistence. A first invalid candidate prompts exactly one correction. Invalid follow-up results do not write. Worker cancellation aborts and disconnects the session; the hook is cleared on exit.
- Cancellation is atomically sealed before `save_candidates` writes pending AI assessments. The queue declines cancellation after sealing. The writer's SQLite transaction check now explicitly rejects a missing driver connection; this also resolves the existing mypy error in the Task 3 writer.
- Fake SDK tests cover missing token despite ambient login, scoped success, correction, twice-invalid output, SDK failure/timeout, cancellation, sealed cancellation, source traversal/symlink/size, advisory redirect/private-host rejection, missing or failed MCP, missing MCP health signal, and wrong model/duplicate variant.

## Exact validation commands and outputs

Initial red test, before creating the runner:

```console
$ python -m pytest -q tests/unit_tests/test_copilot_assessment_runner.py
ImportError: cannot import name 'copilot_assessment_runner' from 'src.controllers'
ERROR tests/unit_tests/test_copilot_assessment_runner.py
1 error in 0.31s
```

First implementation run identified a missing MCP path in the fake fixture (7 failed, 5 passed). The next run identified that the cancellation hook needed to complete its scheduled abort before disconnect (1 failed, 11 passed). The targeted queue test initially lacked `LANE_UPLOAD` in its import (1 failed, 119 passed); the import was fixed. The initial mypy run reported a new SDK config dictionary invariance error and a pre-existing nullable driver connection error in the writer; both were fixed.

Final validation, run after the fail-closed MCP health change:

```console
$ python -m pytest -q tests/unit_tests/test_copilot_assessment_runner.py tests/unit_tests/test_operation_primitives.py tests/unit_tests/test_copilot_assessment_contract.py tests/integration_tests/test_copilot_assessment_write.py tests/webapp_tests/test_operation_queue.py && python -m mypy --config-file tox.ini src --check-untyped-defs && git --no-pager diff --check
........................................................................ [ 59%]
.................................................                        [100%]
121 passed in 4.65s
Success: no issues found in 149 source files
```

Checked the pinned SDK locally: `copilot.__version__ == "1.0.14"`, including `CopilotClient`'s `mode` and token arguments, `create_session`'s skill/tool/MCP/permission options, `send_and_wait(..., timeout=...)`, `CopilotSession.abort()`, and `copilot.tools.define_tool`. Checked that all seven allowed MCP read tool names occur in the packaged server registration.

## Concerns / handoff

- No real-token SDK session or deployed `/scan` container run was available here. The tests exercise the actual SDK's `define_tool` decorator and fake client/session transport, but the first live run should verify that SDK 1.0.14 reports the VulnScout MCP connection as `connected`; absent health notifications deliberately cause a safe failure rather than a write.
- Task 6 must pass the validated selection, configured model, and pre-write pending snapshot, and keep the existing human approval flow; no job/HTTP API is added by this task.
