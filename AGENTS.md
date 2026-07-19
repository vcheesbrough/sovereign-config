# Agent guide — Sovereign Config

This file holds the **sovereign-config-specific** working rules. The
machine-global rules common to every repo — Kanban/bored workflow, iteration &
versioning defaults, branching & git safety, CI-after-push, PR self-review +
comment loop, test coverage, and MCP/secrets discipline — live in the shared
**agent-shared baseline**, imported on this machine via `~/.codex/AGENTS.md` and
`~/.claude/CLAUDE.md`. **Read that baseline first;** this file only records what
is specific to sovereign-config or overrides the baseline.

If a sovereign-config rule changes, change it here — there is no parallel copy.
Cross-repo rules change in `agent-shared`, not here.

Project architecture, stack, and deployment details belong in `README.md` and
project documentation; this file defines the repo-specific collaboration rules.

---

## Repository context

| Item | Value |
| --- | --- |
| **Remote / `gh` repo** | `vcheesbrough/sovereign-config` |
| **Trunk** | `main` |
| **Kanban board** | `https://bored.desync.link/boards/sovereign-config` |

### Bootstrap exception

This repository was initialized directly on `main`. The initial commit that
creates this file and establishes the default branch is allowed on `main`.
After initialization, follow the baseline feature-branch workflow (§2–§3).

---

## 1. CI after every push (repo specifics)

Run the **`ci-watch`** skill (baseline §4) with `OWNER=vcheesbrough`,
`REPO=sovereign-config`. Repo specifics:

- **Deployment smoke check** (post-pipeline, not part of `ci-watch`): for a
  successful development deployment, directly
  call its public native gRPC `System.GetVersion` endpoint **after** the
  pipeline completes — do **not** embed this check in the pipeline. Verify
  `grpc-status: 0` and report the returned application and protocol versions.
  Treat any other response as a deployment failure and fix it before reporting
  completion.

---

## 2. Repository safety (repo specifics)

In addition to baseline §3 (git safety) and §7 (MCP/secrets):

- Use `apply_patch` for manual file edits.
- **Pin container images by digest.** Do not introduce cloud dependencies,
  telemetry, update checks, or undeclared outbound connections.
- Never log or expose configuration secrets, OIDC tokens, Authentik
  credentials, provider URLs, or connection credentials.

---

*Kanban workflow and automated test coverage follow the agent-shared baseline
unchanged — see baseline §1 and §6. Start a card with the **`start-iteration`**
skill (baseline §2). PR self-review + comment loop: run the **`pr-review-loop`**
skill (baseline §5). Skill parameters for this repo: `OWNER=vcheesbrough`,
`REPO=sovereign-config`.*
