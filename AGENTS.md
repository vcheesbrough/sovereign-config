# Agent guide - Sovereign Config

This file is the single source of truth for AI agents and assistants working in this repo. It inherits the Bored working rules, adapted for Sovereign Config. Project architecture, stack, and deployment details belong in `README.md` and project documentation; this file defines the collaboration rules.

If a rule changes, change it here. There is no parallel copy.

---

## 1. Kanban workflow

When this project uses Kanban cards as the task queue:

1. Work on one card at a time unless the user explicitly requests otherwise.

2. Start work by moving the selected card to **In Progress** using the Bored MCP. Resolve a card number with `get_card_by_number` when needed.

3. Cards have no separate title: the board uses the first markdown `#` heading in `body`.
   - Todo cards use a plain descriptive heading only.
   - When work starts, update the heading to `# Iteration N - ...`.
   - Unless the user states otherwise, `N` is the next iteration and matches the workspace semver minor component (`1.N.x`) at the start of work.
   - Use one iteration prefix only.

4. Compare every card with the current source tree before implementing it. Replan and update the card when scope, acceptance criteria, files, or out-of-scope details drift. Preserve the iteration heading after it is set.

5. After the iteration is fixed, implement on `feat/iteration-N-short-slug` from `main`. Never stack feature branches; every iteration branch starts from `main`.

6. Move a card to **Done** through Bored MCP only after its PR is merged.

### Bored MCP only

- Use Bored MCP for all board, column, and card reads and writes.
- The url to the board in bored is https://bored.desync.link/boards/sovereign-config
- Do not use the Bored HTTP API, curl, scripts, or ad-hoc clients unless MCP is unavailable. State the failure once before using a minimal fallback.
- Default board service: `https://bored.desync.link` with scope `bored:prod:access`, unless the user instructs otherwise.

### Bootstrap exception

This repository is being initialized directly on `main`. The initial commit that creates this file and establishes the default branch is allowed on `main`. After initialization, follow the feature-branch workflow above.

---

## 2. CI after every push

When this repository has CI configured and a commit is pushed, monitor the pipeline through completion for that commit. Do not report a pending status as the final result.

1. Obtain the pushed SHA with `git rev-parse HEAD`.
2. Check the GitHub commit status for `vcheesbrough/sovereign-config` using `gh api` and expect `success`.
3. If a check fails, reproduce its documented commands locally, make a narrow fix, commit, push, and monitor the new commit until green.

Do not invent CI outcomes. If GitHub CLI is unavailable or a status remains pending, state that clearly and ask whether to wait or use the CI UI.

---

## 3. MCP obligations

- First response to an MCP failure: follow the documented canonical fix for that MCP integration before improvising configuration changes.
- Batch related configuration edits and give one explicit reload boundary: MCP reload or full client restart.
- Never paste secrets from local MCP configuration, environment files, or credential stores into chat.
- Keep local stdio MCP credentials out of tool arguments, logs, and source control.

---

## 4. Pull request comment loop

When the user asks to raise a PR, or the current branch has unresolved review comments:

1. Open or identify the PR, then retrieve unresolved review threads with GitHub GraphQL.
2. Present one thread at a time with its file/line, author, complete comment body, analysis, and concrete options including ignore/push back.
3. The user makes every decision. Do not change code for a review comment without explicit approval.
4. Apply approved changes locally and run focused checks, but accumulate the batch before committing.
5. Reply on the PR thread with the chosen resolution and resolve it only when the user selected a fix or explicit rejection.
6. Make one commit for the completed review batch, push it, and monitor CI to completion.

Never force-push for review work. Leave threads open when the user chooses further discussion.

---

## 5. Self-review for PRs opened by an agent

Do not open reviews as draft initially, there is a background agent that observes public PR and starts posting review comments after a few minutes.
After opening a PR, review the diff before treating it as complete. Check correctness, security, OWASP concerns, tests, versioning, and deployment behavior. Post the result as a PR review when the project review workflow is configured.

Surface findings to the user and use the pull request comment loop for every resulting change decision.

---

## 6. Repository safety

- Do not revert user changes or use destructive Git commands unless explicitly instructed.
- Keep changes scoped to the active card and preserve unrelated worktree changes.
- Use `apply_patch` for manual file edits.
- Pin container images by digest. Do not introduce cloud dependencies, telemetry, update checks, or undeclared outbound connections.
- Never log or expose configuration secrets, OIDC tokens, Authentik credentials, provider URLs, or connection credentials.
