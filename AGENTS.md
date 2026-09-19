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

## 3. Protocol Compatibility

Compatibility is a **supported range**, negotiated at connect through the native
gRPC `System.GetVersion` endpoint: the server advertises every version it
serves, and the client picks the highest both speak. Clients (cli/mcp/provider)
are likely running an **earlier** protocol version than the server, and that is
explicitly supported — a server upgrade alone must never break them.

**The full procedure for introducing and retiring a protocol version is
`## Protocol versioning` in `README.md`.** Read it before changing anything in
`proto/`. The rules below are the agent-facing summary, not a second copy.

- **Any protocol change requires explicit permission, requested up front.**
  Raise it as the first thing when planning or estimating the work — before
  implementation, while there is still a decision to make. Never let a protocol
  change surface mid-implementation or be discovered in the diff. This covers a
  behaviour change to an existing endpoint as much as a signature change.
- Treat a card's "no protocol change / client-side only" scope as a **claim to
  verify**, not an assumption. If the work turns out to need one, stop and ask.
- A protocol version defines not only signatures/datatypes but also the **key
  behaviour** of endpoints. Earlier behaviour contracts cannot be broken without
  a protocol version change.
- **Edits to an existing `proto/sovereign/config/vN/` package are additive
  only** — a new field with an unused number, a new message, a new RPC. Anything
  else is a new package served alongside the old one, never an edit in place.
- **Never change the `GetVersionResponse.protocol_version` echo semantics.** It
  returns the version the client *requested*; echoing the server's newest
  instead would fail every already-deployed client the day a newer version
  ships. Its regression tests are named in the README section.
- Breaking changes are a **last resort** and must be avoided wherever possible.
  If unavoidable: document it and communicate it to all clients.
- New protocol versions may be added, but **the server must continue to support
  older versions.** A version is retired only once the
  `outcome="authenticated"` series of
  `sovereign_config_protocol_requests_total` has read zero for it across a full
  deployment cycle — the provider does not cache, so a client on a retired
  version fails on its next load with no fallback. Gate on `authenticated`, never
  `attempted`: the endpoint is public, so unauthenticated traffic can hold the
  latter above zero indefinitely.
- Remember the converse: a change can break clients **without** being a protocol
  change (releases 2.15.0 and 2.18.0 both did). Negotiation does not protect
  against that class.

*Kanban workflow and automated test coverage follow the agent-shared baseline
unchanged — see baseline §1 and §6. Start a card with the **`start-iteration`**
skill (baseline §2). PR self-review + comment loop: run the **`pr-review-loop`**
skill (baseline §5). Skill parameters for this repo: `OWNER=vcheesbrough`,
`REPO=sovereign-config`.*
