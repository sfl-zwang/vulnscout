# AI Assessments

VulnScout can accept **AI-written vulnerability assessments**. An AI agent
researches a CVE, decides on a VEX status, and submits the assessment to
VulnScout, where it is stored as **pending review**. A pending AI assessment is
never treated as official — it does **not** affect a vulnerability's status and
is **not** included in the exported VEX — until a human reviewer explicitly
**approves** it in the web interface.

This page describes how to set up and use that workflow, as well as how to
request an AI second opinion on existing user-authored assessments.

---

## Assess with Copilot from the web interface

The **Assess with Copilot** button runs the packaged Copilot SDK and
`cve-assessment` skill inside the VulnScout container. No separate Copilot CLI
or host-side MCP setup is needed for this button. This is distinct from the
external-agent workflow described below.

1. For Docker, verify the **server** is version **28.0.0 or newer** with
   `docker version --format '{{.Server.Version}}'` before enabling the agent.
   Docker versions older than 28.0.0 can make ports published to loopback
   reachable by hosts on the same layer-2 network (see Docker's
   [port-publishing documentation](https://docs.docker.com/engine/network/port-publishing/#publishing-ports)).
   The wrapper refuses to
   start or reuse an agent-enabled container on older or unrecognized Docker
   server versions; ordinary VulnScout without the agent remains available.
   If you cannot upgrade, do not enable localhost-only agent/Copilot endpoints
   unless you have separately proven network isolation; the wrapper has
   no override for this safety check.

   Run `./vulnscout --config VULNSCOUT_AGENT_ENABLED 1`, then invoke
   `./vulnscout --start` to apply the setting. The wrapper publishes port
   7275 on **127.0.0.1 only** and recreates already-running containers
   with a legacy all-interface binding when invoked for a command that
   uses the container (for example, `./vulnscout --serve`). Verify the
   active binding **and the Docker server version** before trusting a Docker
   bridge client:

   ```bash
   docker inspect vulnscout --format \
     '{{range index .HostConfig.PortBindings "7275/tcp"}}{{.HostIp}}:{{.HostPort}}{{println}}{{end}}'
   # Must print exactly: 127.0.0.1:7275
   ```

   If the output differs, restart with `./vulnscout --restart` and verify
   again. A host firewall's INPUT rules alone (including UFW) may not
   restrict Docker-published ports; do not trust the bridge gateway while
   the port is exposed on other interfaces. Docker's default bridge
   presents requests from the host as its gateway address (often
   `172.17.0.1`); set
   `./vulnscout --config VULNSCOUT_AGENT_TRUSTED_CLIENTS 172.17.0.1`
   **only after confirming Docker >=28.0.0 and verifying loopback binding**
   (or separately proving network isolation). Find your actual gateway with
   `docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}'`
   and substitute it if different. Restart to apply the new setting.
   Open `http://localhost:7275` (not a remote host or alternate hostname).
   Without a trusted bridge gateway, even host-local requests may receive
   HTTP 403. This Docker-specific version check does not apply to Podman;
   verify Podman's published port and network isolation before trusting its
   gateway.
2. In **Settings → Copilot**, save a supported GitHub personal access token
   (a classic `ghp_` token or fine-grained `github_pat_` token) from an
   identity with Copilot access. A fine-grained token needs **Copilot Requests**
   permission. The token is stored in the mounted cache at
   `/cache/vulnscout/copilot-token`, not in `config.env`, and survives container
   restarts as long as that cache volume is retained. Treat the cache as a
   secret. Use **Check connection** to inspect authentication and available
   models, then select and save a model in Settings.
3. Open a vulnerability, click **Assess with Copilot**, choose one observed
   package for each selected variant, and start. Historical findings may be
   selected. If a variant already has a pending AI assessment, explicitly
   acknowledge that it will be replaced (even if it covers a different
   package). Multiple variants can be assessed together, but only **one
   package per variant** can be selected per request.
4. Follow progress in the operation queue. A queued or running assessment
   can be cancelled **until the final write begins**; cancellation cannot undo
   an assessment already saved. Results are pending human review: approve or
   reject them in the vulnerability panel as described below. Completed job
   history is kept in memory for one hour, not indefinitely or across server
   restarts.

**Check connection** inspects setup, authentication, model availability, API
reachability and the packaged MCP server's required read-only tools through
a bounded local handshake. It does **not** make a billable
assessment/model-inference call and cannot guarantee a later assessment
succeeds. The runner repeats this preflight before its first model call;
if the tools are unavailable then, no model usage is incurred. Otherwise,
running an assessment uses your Copilot subscription/allowance and may incur
usage charges according to your GitHub plan and selected model.

Source inspection is optional and **opt-in**: set
`VULNSCOUT_SOURCE_ROOT=/absolute/path/to/project` in the host environment
before starting `./vulnscout --serve`. The wrapper mounts that existing host
directory read-only at `/scan/project-source`; refer to paths *inside* that
mount in variant context (`codebase_path`). Without this setting, host project
sources are not mounted. Changing it while the container is running causes
the wrapper to restart the container with the requested mount.

To smoke-test a locally built image without a real token:

```bash
docker build -t vulnscout:copilot-plan-smoke .
docker run --rm --entrypoint sh vulnscout:copilot-plan-smoke -c \
  'test -f /scan/.github/skills/cve-assessment/SKILL.md &&
   test -f /scan/vulnscout_mcp/server.py &&
   test -x /root/.cache/github-copilot-sdk/cli/1.0.85/prebuilds/linuxmusl-x64/copilot-runtime &&
   python3 -c "from copilot import CopilotClient" &&
   test ! -e /scan/project-source'

# A disposable volume simulates two container starts; this is NOT a real token.
volume=$(docker volume create)
docker run --rm -v "$volume:/cache/vulnscout" \
  --entrypoint python3 vulnscout:copilot-plan-smoke -c \
  'from src.controllers.copilot_settings import save_token; save_token("synthetic-smoke-not-a-real-token")'
docker run --rm -v "$volume:/cache/vulnscout" \
  --entrypoint python3 vulnscout:copilot-plan-smoke -c \
  'from src.controllers.copilot_settings import read_token; import os, stat; assert read_token() == "synthetic-smoke-not-a-real-token"; assert stat.S_IMODE(os.stat("/cache/vulnscout/copilot-token").st_mode) == 0o600'
docker volume rm "$volume"

# Explicit project mount is read-only; no project directory is mounted above.
container=$(docker create --entrypoint sh \
  -v "$PWD:/scan/project-source:ro" vulnscout:copilot-plan-smoke -c true)
docker inspect "$container" --format \
  '{{range .Mounts}}{{if eq .Destination "/scan/project-source"}}{{.RW}}{{end}}{{end}}'
docker rm "$container"
```

The binary location above is for the currently pinned SDK/runtime and may
change on upgrade; `docker inspect` should print `false`. With a real token,
use **Check connection** before starting an assessment, then approve or reject
the pending result; this smoke test does not perform live inference. After
enabling the local endpoints, `curl -i -X POST
http://localhost:7275/api/config/copilot/check` should return HTTP 200
(possibly with `ready: false` until the credential and model are set).
HTTP 403 from the host indicates that the Docker bridge gateway has not been
trusted; do not work around this by allowing arbitrary remote addresses.

---

## How it works

Three pieces work together:

- **VulnScout** — runs the API and web interface, stores assessments, and
  provides the review UI.
- **vulnscout_mcp** — an [MCP](https://modelcontextprotocol.io)
  (Model Context Protocol) server that exposes VulnScout's assessment and
  variant-context APIs as tools an AI agent can call.
- **cve-assessment skill** — an agent skill (shipped in this repository under
  `.github/skills/cve-assessment/`) that guides the agent through researching a
  CVE and submitting the result via the MCP tools.
- **assessment-review skill** — an agent skill under
  `.github/skills/assessment-review/` that independently reviews existing
  user-authored assessments, without changing them.

```
CVE / GHSA id
    ↓
AI agent + cve-assessment skill
    ↓  (calls MCP tools)
vulnscout_mcp  ──HTTP──▶  VulnScout API
    ↓
Pending AI assessment (origin = "ai")
    ↓
Human review in the web UI  ──▶  Approve (becomes official) / Reject (deleted)
```

A vulnerability has at most one pending AI assessment per variant. Submitting a
new AI assessment **replaces** the pending one on the same variant(s), without
any confirmation. If the old pending assessment also covered other variants, it
keeps those and only loses the overlapping ones. Approved assessments are never
replaced.

---

## Prerequisites

- A running VulnScout instance, reachable over HTTP (see
  [Getting Started](getting-started.md)). By default the API is served at
  `http://localhost:7275`.
- Python 3.10+ on the host that runs the MCP server.
- A clone of this `vulnscout` repository (the MCP server is vendored under
  `vulnscout_mcp/`).
- An MCP-capable agent client — either the **GitHub Copilot CLI** or
  **VS Code** with the GitHub Copilot extension.

---

## Step 1 — Configure the vulnscout_mcp server

`vulnscout_mcp` speaks MCP over stdio and is launched as a subprocess by the
agent client — there is no port or daemon to manage yourself. Its
`vulnscout_mcp/run_server.py` launcher is self-bootstrapping: on first run it
creates a local `venv/`, installs runtime dependencies from
`requirements/mcp.txt`, and then starts the server.

The server reads a single environment variable:

| Environment variable | Default                 | Description                          |
| -------------------- | ----------------------- | ------------------------------------ |
| `VULNSCOUT_BASE_URL` | `http://localhost:7275` | Base URL of the VulnScout API server |

### GitHub Copilot CLI

Add the server from the terminal:

```bash
copilot mcp add vulnscout \
  --env VULNSCOUT_BASE_URL=http://localhost:7275 \
  -- python3 /path/to/vulnscout/vulnscout_mcp/run_server.py
```

Or run `/mcp add` in interactive mode and fill in the form (**Type:** STDIO,
**Command:** `python3 /path/to/vulnscout/vulnscout_mcp/run_server.py`,
**Environment Variables:** `{"VULNSCOUT_BASE_URL":"http://localhost:7275"}`).

Equivalently, edit `~/.copilot/mcp-config.json` directly:

```json
{
  "mcpServers": {
    "vulnscout": {
      "type": "local",
      "command": "python3",
      "args": ["/path/to/vulnscout/vulnscout_mcp/run_server.py"],
      "env": {
        "VULNSCOUT_BASE_URL": "http://localhost:7275"
      },
      "tools": ["*"]
    }
  }
}
```

### VS Code (GitHub Copilot extension)

Add a server entry to your workspace `.vscode/mcp.json` (or run
**MCP: Add Server** from the Command Palette and choose **Workspace** or
**Global**):

```json
{
  "servers": {
    "vulnscout": {
      "type": "stdio",
      "command": "python3",
      "args": ["/path/to/vulnscout/vulnscout_mcp/run_server.py"],
      "env": {
        "VULNSCOUT_BASE_URL": "http://localhost:7275"
      }
    }
  }
}
```

### Available MCP tools

Once configured, the agent can call these tools (prefixed with `vulnscout-`):

| Tool                       | Description                                                  |
| -------------------------- | ----------------------------------------------------------- |
| `write_assessment`         | Create a VEX assessment for a CVE on one or more packages   |
| `update_ai_assessment`     | Revise the content of an existing pending AI assessment (its targets cannot change) |
| `get_assessment`           | Retrieve a single VEX assessment by ID                      |
| `list_assessments_by_vuln` | List all VEX assessments recorded for a CVE                 |
| `has_ai_assessment`        | Check whether a pending AI assessment exists for a variant (informational; a new write replaces it automatically) |
| `get_vulnerability`        | Retrieve a vulnerability with variant-scoped details        |
| `find_project_id` / `find_variant_id` | Resolve a project / variant by name             |
| `list_variants`            | List every variant across all projects                      |
| `get_merged_context`       | Fetch the merged project + variant context (project description plus variant description, environment, threat model, risks, other info) |
| `get_project_context` / `update_project_context` | Read / replace a project's description |
| `update_variant_context`   | Replace a variant's context fields (description, environment, threat model, risks, other info) — full replacement, not a partial update |
| `get_custom_assessment`    | Fetch one user-authored assessment and its per-target reviews |
| `list_custom_assessments`  | List user-authored assessments, optionally scoped to a project variant |
| `write_assessment_review`  | Record an AI second opinion for one (variant, package) target |

---

## Step 2 — Use the cve-assessment skill

The `cve-assessment` skill lives in this repository at
`.github/skills/cve-assessment/`. An MCP-capable agent that has access to this
repository will discover the skill automatically and invoke it when you ask it
to assess a CVE.

Invoke it by describing the CVE and (optionally) the project context, for
example:

```
Assess CVE-2024-XXXXX for project "my-product", variant "production".
```

The skill resolves platform context using three tiers:

1. **MCP fetch** — if you provide a `project_name` (and optionally one or more
   variant names), the skill fetches each variant's context from VulnScout via
   the MCP tools. The resolved `variant_id`s are required to submit the
   assessment.
2. **Inline context** — if you describe the platform (package manager, build
   system, deployment environment) directly in the prompt, the skill uses that.
3. **Default fallback** — otherwise it proceeds with generic default
   objectives and no extra context.

The skill then researches the vulnerability, evaluates it against the project's
security objectives, assigns a status, and submits it via
`vulnscout-write_assessment` as a pending AI assessment.

### Assessing several variants at once

The skill can assess more than one variant of a project in a single run:

- **Named variants** — list them in the prompt (for example, *variants
  "production" and "staging"*) and only those are assessed.
- **No variants named** — every variant of the project is assessed. This
  requires a `project_name`; the skill never guesses a project.

The CVE research is done once, but the component analysis and confidence score
are done **per variant**, using each variant's own context, because the same CVE
can have a different verdict in different variants. Variants that end up with
the same status and justification are then submitted together as **one
multi-target assessment**, not one assessment per variant. Variants with a
different verdict get their own assessment. The skill finishes with a summary of
every group, the assessment ids, any skipped variants, and any pending AI
assessments it replaced.

```{note}
The skill's **security objectives profiles** and **report templates** are
customizable. See `.github/skills/cve-assessment/objectives/README.md` and the
`.github/skills/cve-assessment/report-templates/` directory for details.
```

---

## Step 3 — Review AI assessments in the web interface

Pending AI assessments must be reviewed by a human before they become official.

1. Open the assessed vulnerability in the VulnScout web interface.
2. A pending AI assessment appears in a highlighted panel **above** the normal
   assessment timeline, labelled **"AI-generated · Pending review"**. It shows
   the same details as a normal assessment (status, justification, impact
   statement, notes, packages, and variant).
3. Click **Edit** on the vulnerability modal to enter editing mode — the
   **Approve** / **Reject** buttons only appear on the panel once editing mode
   is active.
4. Use the panel's action buttons:
   - **Approve** — promotes the assessment to an official (`custom`)
     assessment. It now affects the vulnerability's status and is included in
     the OpenVEX export.
   - **Reject** — deletes the pending AI assessment.

Until it is approved, a pending AI assessment has no effect on the
vulnerability's status, on scan history/diffs, or on any exported VEX.

---

## Step 4 — AI review of custom assessments

This is a separate workflow from approving a pending AI assessment. Ask an
agent with access to this repository and the `assessment-review` skill to
review an existing **user-authored** assessment (`origin = "custom"`). The
skill does not review scan-imported assessments or pending AI suggestions.
For example:

```
Review assessment assessment:<uuid>.
Review custom assessments for project "my-product", variant "production".
Review all custom assessments.
```

You can copy an assessment ID from the **Review** page; the tool accepts a
bare UUID or a copied `assessment:<uuid>` (and `group:<uuid>` for a
multi-target assessment). If you specify a project without a variant, the
skill uses its `"default"` variant. With no scope, it lists custom assessments
across all variants; larger scopes are paginated. By default, it skips targets
with a current review and revisits unreviewed or stale targets.

The agent independently derives a conclusion for **each (variant, package)
target**, then saves a separate review for each one via
`vulnscout-write_assessment_review`. An assessment covering multiple targets
can therefore have different review verdicts for different targets. Each
write supplies the target's `variant_id` and `package` and the
`assessment_fingerprint` obtained when the assessment was read. If the
authored content changed meanwhile, the write is rejected: fetch the updated
assessment and review it again rather than reusing the old conclusion.
Re-reviewing a target replaces only that target's previous review; **no review
changes the underlying assessment**.

The **Review** page's **AI review** column and filter show which targets
agree (✓), differ (⚠), are stale (⚠ stale), or have no review (—).
Multi-target rows show counts for each state. Open the vulnerability detail
modal to read each target's AI review and rationale (`why:`). A stale review
warns that the assessment was edited after the review was generated; in edit
mode, **Discard review** removes a target's review without changing the
assessment.

---

## Troubleshooting

- **The agent cannot reach VulnScout** — verify that VulnScout is running and
  that `VULNSCOUT_BASE_URL` in the MCP configuration points to the correct API
  URL (default `http://localhost:7275`).
- **Submission is blocked with a missing `variant_id`** — the skill needs a
  `variant_id` to submit. Provide a `project_name`/`variant_name` (so it can be
  resolved via MCP) or a `variant_id` UUID directly in the prompt.
- **A pending AI assessment disappeared, or now covers fewer variants** —
  this is expected. A new AI assessment replaces the pending one on the same
  variant(s); if the old one also covered other variants, it keeps those. Approve
  an assessment first if you want to keep it, since approved assessments are
  never replaced.
- **409 Conflict on submission** — you are running a VulnScout version from
  before AI assessments replaced each other. Upgrade VulnScout, or approve or
  reject the existing pending assessment first.
- **Review rejected because its assessment fingerprint changed** — the
  user-authored assessment was edited since the agent read it. Fetch the
  updated assessment and independently review the affected targets again.
