# SESAME: saved Claude session handoff

Prepared 2026-10-09T04:03:04.326456+00:00. Canonical project root: `/Volumes/ANNEX/Users/iyor/Library/CloudStorage/Google Drive/myOrganizations/DELMA/SESAME`. This document contains all retained non-release session handoffs associated with this project, followed by their related subagent outcome excerpts. It can be used without the central archive or the original Claude history.

This is a historical continuation record. Test results, completion claims, branches and commits retain their original scope; they have not been rerun or established as integrated by this handoff task. Original Claude sessions, project code, settings, memories, skills and authentication are untouched. No build, commit, push, checkout or process stop was performed.

<a id="resume-current-work"></a>

## Resume current work

1. Read the current repository instructions and queue before selecting a saved task.
2. Check current Git status, ownership and commit inclusion. Preserve ongoing work and shared build-lane limits.
3. Use the session-specific next steps below, resolving later session outcomes before reopening old findings.

Read AGENTS.md and CLAUDE.md plus the current project plan/queue. Saved work may already be integrated or superseded; the current checkout is the source of truth.

Coverage: 1 session records, including 0 metadata-only records, and 1 subagent outcome supplements. Dropbox and Google Drive aliases were resolved to this same canonical root; no duplicate project root was created.

## Session index

| Saved session | Retained identity |
|---|---|
| [SESAME SESAME Yon controllers and FIX8 follow-ups](#session-9961e082-f7fb-4f69-8be6-c703256a9584) | `9961e082-f7fb-4f69-8be6-c703256a9584` |

<a id="repository-snapshot"></a>

## Repository snapshot


Checked 2026-10-09T03:43:36.354325+00:00. Read-only Git metadata was used with optional locks disabled; no builds, tests, commits or source mutations. Tracked status excludes untracked files. This snapshot may change with ongoing work.

### /Volumes/ANNEX/Users/iyor/Library/CloudStorage/Google Drive/myOrganizations/DELMA/SESAME

Checked 2026-10-09T03:43:36.354325+00:00. Git HEAD `ef40cef815040ef0d61ad9c649641d44972cfdb1`; branch `main`. 2 tracked status entries; see the project repository snapshot. Untracked files were not scanned.

Repository root: `/Volumes/ANNEX/Users/iyor/Library/CloudStorage/Google Drive/myOrganizations/DELMA/SESAME`. Latest commit: `ef40cef 2026-10-04T13:08:15-04:00 docs: record the public call allowlist`.

Tracked status at inspection:

```text
M AGENTS.md
 M CLAUDE.md
```


## Saved session details

<a id="session-9961e082-f7fb-4f69-8be6-c703256a9584"></a>

## SESAME SESAME Yon controllers and FIX8 follow-ups

Reorganize SESAME for Yon and expose SDK functionality through controllers.

### Session identity and chronology

- Claude session ID: `9961e082-f7fb-4f69-8be6-c703256a9584`.
- Last retained event: 2026-10-04T22:15:54.745Z. File modification timestamps may be later than conversation events.
- Historical branches: `main`.
- Source copies: 1.
- Desktop session identities: `local_78db88ec-69e5-41a7-b53e-cefe13405da4`.

### Reported progress and decisions

Latest report: FIX8-HOSTGO landed as 67f908e, then FIX8-SDK-A as 77120d5. SDK-A fixed per-call deadlines for Go/TypeScript/Python/Ruby/Dart and Dart process groups. SDK-B was queued when weekly limits stopped the coordinator.

### Reported tests and qualification

Historical HOSTGO gate: 660 mirrored engine tests with 24 opt-in skips, all 34 Go packages, 3/3 no-listener checks with real FYLO, and SDK verification for all 10 languages. SDK-A reported the full gate green. These are historical transcript reports, not freshly executed checks.

### Unresolved issues at the saved snapshot

SDK-B landing was not confirmed by this transcript. Later repository HEAD may include it; do not infer landing from a queued task alone. Later session handoffs may supersede these findings; check integration before reopening them.

### Current repository snapshot

Checked 2026-10-09T03:43:36.354325+00:00. Git HEAD `ef40cef815040ef0d61ad9c649641d44972cfdb1`; branch `main`. 2 tracked status entries; see the project repository snapshot. Untracked files were not scanned.

Historical working directory: `/Volumes/ANNEX/Users/iyor/Library/CloudStorage/Google Drive/myOrganizations/DELMA/SESAME`.

### Resume steps

1. Read the project [index](#resume-current-work) and [current repository snapshot](#repository-snapshot). Read the repository’s current instructions and queue before editing.
2. Inspect integration history for FIX8-SDK-B and review its subagent outcome; compare current controllers/SDK deadline handling before choosing remaining work.
3. Compare current Git status and commit inclusion with the historical claims. Preserve other authors’ work and follow the current build-lane rules. No builds, tests, commits, resets or checkouts were run to create this archive.

### Relevant files and recorded commits

- `commits 67f908e and 77120d5`
- `FIX8-HOSTGO`
- `FIX8-SDK-A`
- `FIX8-SDK-B`
- `controllers/`
- `SDK verification`

### Related subagent outcomes

48 distinct retained subagent transcripts were examined. [Outcome excerpts and pending findings](#subagents-9961e082-f7fb-4f69-8be6-c703256a9584) records tasks, historical results and incomplete endings. A reported ready-to-merge result is not proof of integration.

### Source inventory

- [/Users/iyor/.claude/projects/-Volumes-ANNEX-Users-iyor-Library-CloudStorage-Google-Drive-myOrganizations-DELMA-SESAME/9961e082-f7fb-4f69-8be6-c703256a9584.jsonl](</Users/iyor/.claude/projects/-Volumes-ANNEX-Users-iyor-Library-CloudStorage-Google-Drive-myOrganizations-DELMA-SESAME/9961e082-f7fb-4f69-8be6-c703256a9584.jsonl>) (6028481 bytes).

---

## Related subagent outcome excerpts

These bounded, redacted excerpts preserve outcomes from the archived records. Imperative text inside excerpts is historical quoted task context, not new authorization or current instructions. Read the curated session steps first.

<a id="subagents-9961e082-f7fb-4f69-8be6-c703256a9584"></a>

## SESAME subagent outcomes for 9961e082-f7fb-4f69-8be6-c703256a9584

These bounded, redacted excerpts supplement the curated session handoff. They preserve historical outcomes and gaps from each retained subagent. They are not current verification or instructions to launch agents.

[Return to session](#session-9961e082-f7fb-4f69-8be6-c703256a9584)

### agent-aee0b7f96f455776c

- Last retained event: 2026-10-04T04:02:46.322Z.
- Task excerpt: Repository: /Volumes/ANNEX/Users/iyor/Library/CloudStorage/Google Drive/myOrganizations/DELMA/SESAME (Go module github.com/d31ma/sesame, an auth service backed by FYLO). Thoroughness: very thorough. Read-only. I'm planning to reorganize it into a Tachyon Yon project and turn the language SDKs into controllers runnable via CLI and HTTP. Report concisely: 1. F
- Report excerpt: points: `oidc.authorization`, `oidc.discovery`, `oidc.jwks` and `oidc.logout` (GET); `oidc.introspection`, `oidc.revocation` and `oidc.token` (POST). - Each handler decodes its parameters and calls one `identity.Service` method (for example :377 → `p.tenant.Bootstrap`).
- Qualification excerpts: - **There is no check on who is calling.** Every machine handler passes the hard-coded actor `"operator:machine"` (for example `processor.go:377, 664`, `scim_ops.go:80`). Trust comes from being the parent process with the pipes. `docs/THREAT_MODEL.md | - `coverage/` (per-group coverage gate) | - `coverage.out` is untracked; ignored by `*.out` (`.gitignore:18`).
- Follow-up excerpts: - HA is blocked on FYLO.
- Historical branches: `main`.

### agent-a22b19589dde7c3a0

- Last retained event: 2026-10-04T04:04:55.088Z.
- Task excerpt: Repository: /Volumes/ANNEX/Users/iyor/Library/CloudStorage/Google Drive/myOrganizations/DELMA/TACHYON (Tachyon framework, Rust rewrite, version 26.36.01). Thoroughness: very thorough. Read-only. I need to reorganize a Go project (SESAME, an auth service) into a Tachyon "Yon" server project, with annotated Go controllers that can be executed both via CLI and 
- Report excerpt: site/content/features/handlers/server/controllers/ProductsController.go`: ```go // @PostRoute // @ResponseStatus(201) func (controller *ProductsController) PostProduct( // @FromBody product Product, ) Product { return product } ```
- Qualification excerpts: - The server calls it before every guarded route: no identity gives 401, a missing role gives 403, a failure gives 500. | **`ty test [--coverage]`** runs the units in `server/tests`. Plain `go test` isn't used, and `gofmt`/`go vet` can read the files but can't type-check them because framework types are generated. Verbatim test unit from `$T/crates/tachyon-core/tests/fi | **Coverage** (ADR 0070) fails when any public method of an annotated type was never called by a test.
- Historical branches: `main`.

### agent-aef095ba6bf5d3d68

- Last retained event: 2026-10-04T04:52:28.406Z.
- Task excerpt: You are agent SESAME-ENGINE-ACTOR in the SESAME swarm. Your worktree: /Volumes/ANNEX/build/worktrees/SESAME-ENGINE-ACTOR (branch swarm/sesame-engine-actor). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-ENGINE-ACTOR.env &&`. First read, in full: /Volumes/ANNEX/build/sesame-swarm/SWARM/COMMON-PROMPT.md, BRIEF.md and QUEUE.md (sa
- Report excerpt: All env-induced. Rerunning the gate with `FYLO_BINARY` unset (as the baseline ran).
- Qualification excerpts: - **Error-wrapping change in `internal/application/identity`:** 74 `"%w: %v"` storage-failure wraps became `"%w: %w"`. The text is identical; the typed refusal now survives the wrap. | - Recorded actor, version advertisement, schema drift tests and the identity checks failed first, then passed. | - The env file `/Volumes/ANNEX/build/worktrees/SESAME-ENGINE-ACTOR.env` exports `FYLO_BINARY`. With it set, `internal/platform/cli` (`storage_test.go:53`, `run_test.go:61`, `saml_test.go:54`), `clients/go/sesame` and `test/blackbox` fail. They pass w
- Follow-up excerpts: **Out of scope**
- Historical branches: `main`.

### agent-a60289edbf47a50f7

- Last retained event: 2026-10-04T04:53:52.401Z.
- Task excerpt: You are agent TY-INVOKE-ARGS, working in the TACHYON repo on behalf of the SESAME swarm coordinator ("main"). Your worktree: /Volumes/ANNEX/build/worktrees/TY-INVOKE-ARGS (branch swarm/ty-invoke-args, based on TACHYON swarm/integration d591d886). Start every shell command with `source /Volumes/ANNEX/build/worktrees/TY-INVOKE-ARGS.env &&`. Follow TACHYON's ow
- Report excerpt: Red for the right reasons (body not bound: `item` undefined; `--target` missing). Now the implementation.
- Qualification excerpts: - **Red** (log in `/Volumes/ANNEX/build/sesame-swarm/TY-INVOKE-ARGS/red.log`): all 4 cases failed. With no `@FromBody` value the controller crashed with a 500 (TY2201 "Cannot read properties of undefined"). The two cases using `--target` failed becau | - **Green:** 4/4 pass. The existing `phase2_cli` tests (8/8) and the `tachyon-core` server unit tests (43/43) still pass. | - **Other checks:** clippy with `-D warnings` on `tachyon-core` and `tachyon-cli` is clean, the `tachyon-contracts` policy tests pass, and cohesion-scan reports 0 for the new file. Both browser gates pass, and `build-content --check` matches.
- Historical branches: `main`.

### agent-a7ec63e207aae007c

- Last retained event: 2026-10-04T05:46:23.222Z.
- Task excerpt: You are agent SESAME-FOUNDATION in the SESAME swarm. Your worktree: /Volumes/ANNEX/build/worktrees/SESAME-FOUNDATION (branch swarm/sesame-foundation). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-FOUNDATION.env &&`. First read, in full: /Volumes/ANNEX/build/sesame-swarm/SWARM/COMMON-PROMPT.md, BRIEF.md and QUEUE.md (same folde
- Report excerpt: **SESAME-FOUNDATION: ready to merge.** Branch `swarm/sesame-foundation` is 8 commits on top of `swarm/integration` 4a0b1d7, from `2827fc8` to `6ad635d`. The full log is in `/Volumes/ANNEX/build/sesame-swarm/SESAME-FOUNDATION/PROGRESS.md`.
- Qualification excerpts: - **SDK:** whenever the context ends, `StartWhenAvailable`'s error wraps the context error. If the last attempt saw the lock, the error also wraps `ErrDeploymentLocked`. Any other failure still returns at once. | - A new Yon test with a 1 ms wait checks that an engine which cannot start in time gives the busy error. It failed before the fix and passes after. | - 20 repeated runs with `-race` on one CPU now pass.
- Follow-up excerpts: **Out of scope, for you or other slices:**
- Historical branches: `main`.

### agent-ad7534a0012542019

- Last retained event: 2026-10-04T06:03:22.201Z.
- Task excerpt: You are agent SESAME-CTRL-DIRECTORY in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-CTRL-DIRECTORY (branch swarm/sesame-ctrl-directory, based on the FOUNDATION head 6ad635d, which is about to land on swarm/integration). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-CTRL-DIRECTORY.env &&`. Read in full first
- Report excerpt: While the gate runs, logging the rebase and the first gate attempt.
- Qualification excerpts: - Each unit first failed to compile (TY2004, undefined service or controller), then passed: 53 cases across 6 units. | - I checked the cross-tenant cases by switching off the tenant comparison in a scratch copy: 5 of them failed. Without the host check, an admin of one tenant really could remove a member from another tenant's group. | **Gate:** exit 0 (`GATE go packages ok: 30`, `ty bundle` and `ty test --coverage` pass). The first attempt was killed by my own 10-minute limit after a long wait for the lock. It had also hit a known environment problem: the Go SDK tests (`server/pac
- Follow-up excerpts: **Out of scope:**
- Historical branches: `main`.

### agent-ac285bee6b99782d1

- Last retained event: 2026-10-04T06:20:13.903Z.
- Task excerpt: You are agent SESAME-CTRL-AUTHN in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-CTRL-AUTHN (branch swarm/sesame-ctrl-authn, based on the FOUNDATION head 6ad635d, which is about to land on swarm/integration). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-CTRL-AUTHN.env &&`. [REDACTED sensitive line] This fam
- Report excerpt: Port belongs to CTRL-OIDC's probe; I'll use another port.
- Qualification excerpts: **Remaining security gaps** (in the docs, for the REVIEW pass): | **Tests:** 55 cases pass on my units plus `SesameErrorHandlerTest`. They cover replay, out-of-order steps, closed and unknown logins, stale sessions, cross-principal and cross-tenant attempts, and passkeys built from real WebAuthn data. Login expiry  | - I broke the code twice on purpose to check the tests. With the passkey ownership check removed, the intruder test failed. With the tenant check bypassed, the 3 cross-tenant tests failed.
- Historical branches: `main`.

### agent-a7f7263c38b83d43c

- Last retained event: 2026-10-04T06:33:25.875Z.
- Task excerpt: You are agent SESAME-CTRL-OIDC in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-CTRL-OIDC (branch swarm/sesame-ctrl-oidc, based on the FOUNDATION head 7708370, which is landing on swarm/integration now). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-CTRL-OIDC.env &&`. Read in full first: /Volumes/ANNEX/build
- Report excerpt: The gate is running in the background under MAC-LOCK; I'll wait for it to finish.
- Qualification excerpts: **SESAME-CTRL-OIDC: ready to merge** at `4a181cd`, branch `swarm/sesame-ctrl-oidc`, rebased on swarm/integration `dddd0ab`. The full gate passed under MAC-LOCK (`GATE go packages ok: 30`, `gate exit=0`). | - Most code was written before its tests, so the tests passed on first run. Real red failures came only from wrong expectations (`client_not_found`, `awaiting_authentication`, `consent_not_found`), recorded in PROGRESS.md. To show the tests can fail,
- Follow-up excerpts: **Out of scope, under FOR COORDINATOR in PROGRESS.md**
- Historical branches: `main`.

### agent-ab4e4acd10ee67743

- Last retained event: 2026-10-04T06:36:41.480Z.
- Task excerpt: You are agent SESAME-CTRL-FEDERATION in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-CTRL-FEDERATION (branch swarm/sesame-ctrl-federation, based on swarm/integration 6f82ea0, which contains FOUNDATION and ENGINE-ACTOR). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-CTRL-FEDERATION.env &&`. Read in full firs
- Report excerpt: SESAME-CTRL-FEDERATION is ready to merge. Branch `swarm/sesame-ctrl-federation` has 5 commits on `swarm/integration` dddd0ab, and the full gate passed (`GATE go packages ok: 30`, `gate exit=0`).
- Qualification excerpts: - **Not tested:** login expiry (15 min) can't be reached without clock control, so only the engine's own tests cover it. | - **Guard checks:** `ty test` can't reach the guard, so I checked these with `ty serve` and curl: 401/403 from the guard, 405 on `login-exchange`, the challenge header and `Authorization` both pass through, a token in the body gets 400 and a token in | - **Narrow checks:** `ty bundle` built 60 routes. My 8 test units plus `SesameErrorHandlerTest` gave 70 passed, 0 failed.
- Follow-up excerpts: - **Not tested:** login expiry (15 min) can't be reached without clock control, so only the engine's own tests cover it. | **Out of scope:** `sesame help` doesn't list the existing `federation`, `saml` and `provisioning` command groups (`internal/platform/cli/run.go:73-77`).
- Historical branches: `main`.

### agent-a918cd42ccfe61be3

- Last retained event: 2026-10-04T07:40:00.773Z.
- Task excerpt: You are agent SESAME-ACTOR-WIRE in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-ACTOR-WIRE (branch swarm/sesame-actor-wire, based on swarm/integration 24fbc0b: FOUNDATION, ENGINE-ACTOR, CTRL-DIRECTORY, CTRL-AUTHN landed; CTRL-FEDERATION is landing and CTRL-OIDC is gating, so rebase on swarm/integration before your final gate). Start ever
- Report excerpt: ACTOR-WIRE is **ready to merge**: head `a9c1a54` on `swarm/sesame-actor-wire`, rebased on integration `8ccd9e3`. The full gate under MAC-LOCK passed on that head (`GATE go packages ok: 30`, `gate exit=0`).
- Qualification excerpts: ACTOR-WIRE is **ready to merge**: head `7ef0836`, based on integration `8ccd9e3`. The full gate under MAC-LOCK passed on that head (`GATE go packages ok: 30`, `gate exit=0`). | **Landing failure fixed (`TestBusyEngineIsReportedToTheErrorHandler`)** | - **Proof:** `abandoned_engine_test.go` covers an abandoned start and a kill on `Close`. Both were red (a leftover process wrote its marker) and are green now. The slow-FYLO repro went from 8 of 8 leaks to 0. The two affected Yon test units passed 3 
- Follow-up excerpts: **Out of scope / notes**
- Historical branches: `main`.

### agent-a381ca8ebba68ed04

- Last retained event: 2026-10-04T07:58:08.251Z.
- Task excerpt: You are agent SESAME-SDK-RETIRE in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-SDK-RETIRE (branch swarm/sesame-sdk-retire, based on swarm/integration 8ccd9e3: FOUNDATION, ENGINE-ACTOR and all four controller families have landed; ACTOR-WIRE is still running in server/** and internal/application/identity/**). Start every shell command wi
- Report excerpt: I've finished the work, but it is **ready pending ACTOR-WIRE**: it can't land yet. Following your instruction, I stopped before the final gate. On your signal I'll `git rebase swarm/integration` and run the one MAC-LOCK gate.
- Qualification excerpts: **Gate:** not run yet, by design. | - **The two coverage entries now pass.** `POST /api/v1/grant/revoke` and `POST /api/v1/session/revoke-by-id` match ACTOR-WIRE's routes. `go test ./test/contract` passes in full. | - **Gate:** passed under MAC-LOCK, 03:49 to 03:55, with no wait for the lock: `GATE go packages ok: 30`, `gate exit=0`. That covers gofmt, vet, build, `go test -race`, `server/packages`, `ty bundle` and `ty test --coverage`.
- Follow-up excerpts: **Out of scope, left stale:** | **Out of scope:** none left. The only remaining `clients/` mentions are intentional: changelog history, the project plan and ADR records, the migration guidance, and the test's list of retired names. The full CHANGELOG entry and the proposed text for
- Historical branches: `main`.

### agent-aad83c8e79592dfd3

- Last retained event: 2026-10-04T08:28:10.802Z.
- Task excerpt: You are agent SESAME-REVIEW-SECURITY, the Security Architect for the SESAME Yon migration. READ-ONLY review: do not commit fixes; your deliverable is a findings report. Worktree (a scratch copy of swarm/integration 0a75541, safe to run builds/servers in): /Volumes/ANNEX/build/worktrees/SESAME-REVIEW-SECURITY. Start every shell command with `source /Volumes/A
- Report excerpt: simultaneous requests with a 1 s wait gave 6 answers and 14 `503`s. Every request holds the single FYLO root. - **Impact.** Any anonymous client can starve sign-in, token, introspection and revocation for every tenant at a few requests per second. Throttling of public login steps also depends on the proxy. - **Mitigation.** Accept this as preview residual risk only if `docs/YON.md` states as requirements: - Never expose `ty` directly. - Put a rate-limiting reverse proxy in front of every route. - Apply per-IP limits on public routes: `authn/*`, `session/verify`, `/oidc/*`, `pushed-author
- Qualification excerpts: - **Fail closed:** | - The narrow actor tests pass. The `server/packages` tests pass with `FYLO_BINARY` unset; with it set, eight tests fail only because the review environment exports it. | - **Recent sign-in:** a session older than 10 minutes gets 403 on self-service authenticator changes; a fresh one passes.
- Follow-up excerpts: **BLOCKED.**
- Historical branches: `main`.

### agent-a6d52f302e8e2c104

- Last retained event: 2026-10-04T08:29:35.154Z.
- Task excerpt: You are agent SESAME-REVIEW-QUALITY: Codebase Steward + Senior QA Engineer + Principal Improvement Advisor for the SESAME Yon migration. READ-ONLY review: do not commit; your deliverable is a findings report. Worktree (a scratch copy of swarm/integration 0a75541, safe to build and run servers in): /Volumes/ANNEX/build/worktrees/SESAME-REVIEW-QUALITY. Start e
- Report excerpt: Now the controllers using these, to understand semantics.
- Qualification excerpts: - `@Allow` is skipped | - **T1 [Low, pre-existing]** Go tests fail when `FYLO_BINARY` is exported (`environment_test.go:126` and seven others; `TestStorageOptionsResolveFromTheEnvironment`; `TestCompiledBinaryVersionAndMachineContract`). The tests should set their own envir | - **G2** An `@IdentityProvider` failure is always a plain 500; it cannot answer 503 with `Retry-After`.
- Historical branches: `main`.

### agent-afe7f54cf968c9a81

- Last retained event: 2026-10-04T08:51:13.730Z.
- Task excerpt: You are agent SESAME-FIX-TESTS (Senior QA Engineer) in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-FIX-TESTS (branch swarm/sesame-fix-tests, on swarm/integration 0a75541). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-FIX-TESTS.env &&` (note: that env exports FYLO_BINARY — that is exactly the T1 problem yo
- Report excerpt: Meanwhile, I'll log the I-2 slice and coordinator notes in PROGRESS.md.
- Qualification excerpts: - **Red, with FYLO_ROOT, SESAME_DEPLOYMENT, SESAME_BINARY, SESAME_ISSUER and the secret variables also exported:** `TestStartWithNoOptionsUsesTheEnvironment` failed too. `TestDeploymentLifecycleNeverLeaksKeyMaterial` was worse than a failure: it ran  | - **Green:** with all those variables set to junk values, `go test ./...` passes 30 packages and `server/packages` passes. Nothing was written into the junk deployment path. | **Gate:** passed under MAC-LOCK (exit 0) from 04:41:15 to 04:48:09: vet, build, `go test -race` (30 packages), `server/packages`, `ty bundle` and `ty test --coverage`.
- Historical branches: `main`.

### agent-ae9def76287cc453a

- Last retained event: 2026-10-04T09:29:31.440Z.
- Task excerpt: You are agent SESAME-FIX-CORE (Junior Software Engineer) in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-FIX-CORE (branch swarm/sesame-fix-core, on swarm/integration 0a75541). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-FIX-CORE.env &&`. Read first: /Volumes/ANNEX/build/sesame-swarm/SWARM/{COMMON-PROMPT,B
- Report excerpt: Good: the gate is running on c8524b9. I'll wait for its completion notification.
- Qualification excerpts: - **Checked against real request handling** with ty `d070022f` (the build that passes request bodies and cookies into controllers; bf098bfc does not): the prefixed cookie reaches the engine (404) and the old name gets 400; `lifetime_seconds` gets 400 | - ty bf098bfc's `handler invoke` passes no arguments to controllers, so cookie and body checks need `d070022f`. | - `handler invoke` ignores a `YON_APPLICATION_JSON` passed with `--allow-env`; only a `.env` file worked.
- Follow-up excerpts: **Out of scope:**
- Historical branches: `main`.

### agent-a1e67bcb2903c5744

- Last retained event: 2026-10-04T09:55:20.604Z.
- Task excerpt: You are agent SESAME-SMOKE (Senior QA Engineer) in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-SMOKE (branch swarm/sesame-smoke, on swarm/integration f4c8b3d). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-SMOKE.env &&`. Read first: /Volumes/ANNEX/build/sesame-swarm/SWARM/{COMMON-PROMPT,BRIEF,QUEUE}.md (se
- Report excerpt: **SESAME-SMOKE: ready to merge.** Commit `dab3308` is on `swarm/sesame-smoke`. The smoke test passes when run alone (niced) and under MAC-LOCK, and the full gate passed under MAC-LOCK.
- Qualification excerpts: **gate.sh invocation.** Add this inside the `if [ -f server/application.json ]` block, after the `ty test` line. gate.sh unsets `FYLO_BINARY`, so the FYLO path is passed explicitly: | bash tools/yon-smoke/smoke.sh $log.sesame "$(command -v fylo)" >$log.smoke 2>&1 || { echo "GATE yon smoke FAILED"; grep -E '^FAIL' $log.smoke | head -5; fail=1; } | - **Admin routes:** the sessions are seconds old, so a recent-sign-in rule passes. If admin routes start requiring step-up or aal2, `sign_in` would need a TOTP step.
- Follow-up excerpts: **Out of scope.** A busy engine during the identity check still answers 500 rather than 503 (security review LOW-7). The smoke test does not assert it.
- Historical branches: `main`.

### agent-a26d500f21c2a427d

- Last retained event: 2026-10-04T10:05:35.437Z.
- Task excerpt: You are agent SESAME-FIX-FED (Junior Software Engineer) in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-FIX-FED (branch swarm/sesame-fix-fed, on swarm/integration 0a75541). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-FIX-FED.env &&`. Read first: /Volumes/ANNEX/build/sesame-swarm/SWARM/{COMMON-PROMPT,BRIEF
- Report excerpt: Now swap the interim check for `Privileged: true` and drop the extra fields.
- Qualification excerpts: - Red: the host error test failed with `undefined: RedirectNotAllowedError`, and the new units ran 21 passed / 13 failed. For example, the attacker URL was not refused, and a stale admin got 500 or 400 instead of 403. | - Green: the 12 affected units pass (85 passed, 0 failed) after the rebase. `ty bundle --no-incremental` is clean and `go test ./test/contract` is ok. | - unsafe entries fail closed;
- Follow-up excerpts: **Out of scope:** the engine still uses whatever URL the caller sends, at `internal/application/identity/saml.go:257-345` and `internal/application/identity/federation.go:468`. Fixing that needs an ADR.
- Historical branches: `main`.

### agent-a67273cb4f4455a53

- Last retained event: 2026-10-04T10:47:45.121Z.
- Task excerpt: You are agent SESAME-FIX-DOCS (Senior Technical Writer) in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-FIX-DOCS (branch swarm/sesame-fix-docs, on swarm/integration c8524b9). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-FIX-DOCS.env &&`. Read first: /Volumes/ANNEX/build/sesame-swarm/SWARM/{COMMON-PROMPT,BR
- Report excerpt: Now the FOR COORDINATOR section with the CLAUDE.md/AGENTS.md replacement text.
- Qualification excerpts: FIX-DOCS is ready to merge: branch `swarm/sesame-fix-docs` at b3005b8, 16 commits on `swarm/integration` 0fe1702 (which already has SMOKE and FIX-FED). The full gate under MAC-LOCK passed (`GATE go packages ok: 30`, `GATE yon smoke: 37 checks ok`, `g | - **Example host cookie:** `examples/hostserver/oidc.go` now uses `__Secure-sesame_interaction`. Its clearing cookies also set `Secure`, without which a browser ignores the deletion. The prefix adds no new HTTPS requirement, because the cookie was al | **Tachyon gap (new):** `ty serve` with bf098bfc, when started by name, looks `ty` up on `PATH` again. With `/Users/iyor/.local/bin` (which holds fylo, chex and an older `ty`) first on `PATH`, it fails with TY1002. Starting it by absolute path works, 
- Historical branches: `main`.

### agent-a2dae7a4ade92229f

- Last retained event: 2026-10-04T11:07:59.012Z.
- Task excerpt: You are agent SESAME-REREVIEW, the Security Architect re-validating the review fixes for the SESAME Yon migration. READ-ONLY: do not commit; deliverable is a findings report in your final message (subagents cannot write report files; the coordinator saves it). Worktree (scratch copy of swarm/integration 0fe1702; safe to build and run servers in): /Volumes/AN
- Report excerpt: ll 25 variants, and the engine never started: - the attacker URL - trailing slash, host / scheme / path case - query, empty `?`, fragment - userinfo in both positions, `:443` and `:8443`, trailing-dot host - punycode, IDN, percent-encoded path and host, `..` segments - leading or trailing space, `\n`, `\t` - `http`, empty string, backslash - `federation/login-start` gave the same result for 12 variants, and for the SAML URL used as `redirect_uri`. - Duplicate keys: `[listed, evil]` gave 400; `[evil, listed]` reached the engine with the listed value. That is safe because the host 
- Follow-up excerpts: 3. **INFO: unexplained intermittent 400 on interaction-get.** Three wrong-secret calls within one minute answered `400 invalid_request` instead of 404. I could not reproduce it in 50 more tries with the same inputs, so it looks time-related, not inpu | **SIGN-OFF:** HIGH-1, HIGH-2, MED-1, MED-2, MED-3, LOW-1/S1, LOW-3/S2, LOW-6 and LOW-8 are verified fixed. New finding 1 is LOW and should be fixed in a follow-up; it does not block this sign-off.
- Historical branches: `main`.

### agent-ad813306907e49a07

- Last retained event: 2026-10-04T11:27:06.309Z.
- Task excerpt: You are agent SESAME-FIX-TIDY (Junior Software Engineer + Codebase Steward) in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-FIX-TIDY (branch swarm/sesame-fix-tidy, on swarm/integration 0fe1702: all review fixes landed). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-FIX-TIDY.env &&`. Read first: /Volumes/ANN
- Report excerpt: Nothing else lists privileged routes. Final gate under the lock.
- Qualification excerpts: - **aa30d3f, smoke.sh PATH (item 4):** the script now makes a `fylo-tools` folder in its temp dir with links to `fylo` and `chex` only. `chex` is taken from beside fylo, then from PATH, and setup fails if neither has it. That folder is put in front o | - I could not reproduce the TY1002 failure. The old script also passed 37/37, because it already starts `ty` by absolute path. What I did show is that the old PATH resolves `ty` to the older copy and the new PATH resolves it to `SWARM/bin/ty`. | `go test` 30 packages ok, `server/packages` ok, `ty bundle` ok, `ty test --coverage` ok, smoke 37 checks ok, exit 0. While working I ran every test unit in five small groups (297 passed); `ty test` has no filter option, so each group ran on a temp co
- Follow-up excerpts: - **cd4b116, follow-up fix:** `oidc-client/register` now requires a recent sign-in. The access annotation is still `@Allow(Administrator)`. | **Out of scope:** `AdministratorRecentSignInTest.go:148` (`scimClient`) duplicates the new `ScimRegisterRequest`. I left it alone.
- Historical branches: `main`.

### agent-a829ca2007def3ad0

- Last retained event: 2026-10-04T11:56:55.988Z.
- Task excerpt: You are agent SESAME-FIX-INTERACTION in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-FIX-INTERACTION (branch swarm/sesame-fix-interaction, on swarm/integration 421d5f2). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-FIX-INTERACTION.env &&`. Read first: /Volumes/ANNEX/build/sesame-swarm/SWARM/{COMMON-PROMPT,
- Report excerpt: The gate is queued behind three other agents (SESAME-FIX-TIDY, LUA-YON-FIXES, CPP-TAC). I'll wait for the background notification.
- Qualification excerpts: - 55 projection updates that fail right after a durable ledger write and are returned as-is (e.g. `identity/authentication.go:84`). | - 36 random ID/secret generation failures (e.g. `oidcflow.go:182`). | Ledger write failures are already wrapped correctly (73 of 76 sites). I didn't change the default because it is also the intended 400 answer for dozens of plain domain validation errors. A follow-up slice would first need a typed validation error in 
- Follow-up excerpts: - **Other operations have the same problem; not fixed.** All 51 machine call sites of `tenantErrorResponse` (direct or through the other error mappers) share the default branch. Genuinely internal errors reach it and answer 400 with internal text: | Ledger write failures are already wrapped correctly (73 of 76 sites). I didn't change the default because it is also the intended 400 answer for dozens of plain domain validation errors. A follow-up slice would first need a typed validation error in 
- Historical branches: `main`.

### agent-a84298e3a018bdde7

- Last retained event: 2026-10-04T13:40:34.091Z.
- Task excerpt: Read-only research in the SESAME integration worktree /Volumes/ANNEX/build/worktrees/SESAME-INTEGRATION (branch swarm/integration, head d54c91c). Thoroughness: very thorough. Cite file:line. 1. Inventory EVERY place that queries FYLO ("FYLO table queries"): the engine (internal/adapters/fylo/**, internal/adapters/fylo/securityledger, internal/application/** 
- Report excerpt: horize.decide` for `sesame:administer` and returns roles | EngineService | | `RecentSignInService` | 10-minute `IssuedAt` window check | none | | `TenantCallService` | Admin / same-tenant / owned-record / caller gates around engine calls | Caller, Engine, Administrator, RecentSignIn | | `PrincipalTenantService` | Builds the `principal.get` lookup for the owner check | TenantCallService | | `StandardsDispatchService` | Translates `http.Request` to `StandardsRequest`; body cap, single headers, discovery endpoints | Engine, StandardsRefusal | | `StandardsAnswerService` | Validates the engine resp
- Qualification excerpts: - The ownership check is `requireOwned`/`credentialIdentifiers` (:192–205), with a failure-threading helper `afterwards` (:207). | - The failure-threading pattern (`if failure != nil { return failure }`) repeated everywhere. | - No other gate tools reference it (`tools/coverage`, `crap`, `production-evidence`).
- Historical branches: `main`.

### agent-a3448864827d3f595

- Last retained event: 2026-10-04T13:43:38.693Z.
- Task excerpt: Read-only research in the TACHYON repo at its latest integration head. Use `git -C "/Volumes/ANNEX/Users/iyor/Library/CloudStorage/Google Drive/myOrganizations/DELMA/TACHYON" show a7ccbfff:<path>` (or the worktree /Volumes/ANNEX/build/worktrees/INTEGRATION if it is at a7ccbfff — check with `git -C /Volumes/ANNEX/build/worktrees/INTEGRATION log -1 --format=%h
- Report excerpt: **Format.** A remote is an annotated, bodiless contract, not a JSON or config file. It is an `@HTTPClient` with `@GetRequest`/`@PostRequest`/`@PutRequest`/`@PatchRequest`/`@DeleteRequest` methods, or `@Gateway` methods. - ADR 0088 makes `remotes/` canonical; `clients/` stays an alias, and a duplicate class across both folders is an error. - `docs/REMOTES_MIGRATION.md`: `ty migrate fix --write` moves files from `clients/`. - Parameter markers: `@PathVariable`, `@RequestParam("page")`, `@RequestHeader("X-Tenant")`, `@RequestBody`. - Options: `@HTTPClient("/api")` or `{"path","adapter","setup"}`.
- Qualification excerpts: | Imported-utility coverage | `7954f82c`, ADR 0070 amendment | Tac JS/TS units only. Go and other units already compose utils and record coverage. |
- Follow-up excerpts: - OpenAPI is explicitly out of scope (`docs/PARITY_LEDGER.md:105`).
- Historical branches: `main`.

### agent-a7d5a8c369024ccea

- Last retained event: 2026-10-04T14:14:13.236Z.
- Task excerpt: You are agent SESAME-RELOCATE in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-RELOCATE (branch swarm/sesame-relocate, on swarm/integration d54c91c). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-RELOCATE.env &&`. Read first: /Volumes/ANNEX/build/sesame-swarm/SWARM/{COMMON-PROMPT,BRIEF,QUEUE}.md (Wave 6 sect
- Report excerpt: **Ready to merge.** The Yon project now lives under `app/`, and the head is 0808157 on `swarm/sesame-relocate`. I sent main "ready for gate" with that SHA.
- Qualification excerpts: - ADR 0007 gets a "Location" section recording `app/` as the Yon root by Samuel's direction, passed to `ty` explicitly. | - Docs now show `ty serve app`, `ty bundle app`, `ty test app --coverage` and `ty handler invoke --project app …` (I checked that `--project app` works). | - **.gitignore is unchanged.** Its existing unanchored `.env`, `dist/` and `.tachyon/` entries already ignore `app/.env`, `app/dist` and `app/.tachyon`; `git check-ignore` confirms it. `ty` writes coverage to `.tachyon/coverage`.
- Follow-up excerpts: **Out of scope:** `CONTRIBUTING.md:20`, and the validation block in CLAUDE.md and AGENTS.md, still run `gofmt -w cmd internal clients test`, but `clients/` is retired.
- Historical branches: `main`.

### agent-a30882dcecca64c4c

- Last retained event: 2026-10-04T14:42:19.617Z.
- Task excerpt: You are agent SESAME-REMOTES-CORE in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-REMOTES-CORE (branch swarm/sesame-remotes-core, on swarm/integration d54c91c). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-REMOTES-CORE.env &&` (ty on PATH is now a7ccbfff, the latest TACHYON build). Read first: /Volumes/ANN
- Report excerpt: Now the docs pointer section. Let me look at docs/SDK_DISTRIBUTION.md.
- Qualification excerpts: - `tools/remotes/generator_test.go`: 12 tests, 100% statement coverage. Red: the happy-path test found a real panic, `Words.Camel` on an empty name ("index out of range"); fixed. | - SESAME ran from a copy of `app/` under `ty serve` (disposable deployment, free port). Throwaway Go and TypeScript consumer projects used the copied `remotes/<language>/server`. `ty bundle` passed for both. | - **B.** An adapter cannot pass the upstream HTTP status to the caller. Go collapses every error to `adapter`; JS passes a thrown `BehaviorError` through. The `{status, body}` envelope works around this.
- Follow-up excerpts: **Out of scope:** none found. CHANGELOG text and an optional README line are under FOR COORDINATOR in PROGRESS.md.
- Historical branches: `main`.

### agent-a610c6c5974899bb1

- Last retained event: 2026-10-04T15:40:03.887Z.
- Task excerpt: You are agent SESAME-REMOTES-LANGS-A in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-REMOTES-LANGS-A (branch swarm/sesame-remotes-langs-a, on swarm/integration bbad225; Yon project root app/). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-REMOTES-LANGS-A.env &&` (ty a7ccbfff on PATH; Python 3.14, Java 21, k
- Report excerpt: Now log Rust, gaps, and coordinator notes; then stop SESAME and clean up before the gate.
- Qualification excerpts: **End-to-end method, same for every language.** SESAME ran with `ty serve` from a copy of `app/`. Each language had a throwaway consumer built from the generated `remotes/<language>/server`, and `ty bundle` passed for each. | - HTTPS was not tested end to end. The sandbox has no DNS, and a local TLS server would need a trusted CA added to the trust store. REMOTES-CORE had the same limit. | | Rust | 82396fd | Same-host only (loopback http). Uses a standard-library TCP connection through `HTTP_PROXY`. Every other origin, https included, is refused before connecting: a counting listener saw 0 connections for an https origin and 1 for the 
- Follow-up excerpts: - HTTPS was not tested end to end. The sandbox has no DNS, and a local TLS server would need a trusted CA added to the trust store. REMOTES-CORE had the same limit. | **Out of scope.** CHANGELOG text and the `docs/SDK_DISTRIBUTION.md` language list are under FOR COORDINATOR in PROGRESS.md; Rust is listed there as development-only.
- Historical branches: `main`.

### agent-a43b9a5e6e700ace9

- Last retained event: 2026-10-04T15:44:19.421Z.
- Task excerpt: You are agent SESAME-REMOTES-LANGS-B in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-REMOTES-LANGS-B (branch swarm/sesame-remotes-langs-b, on swarm/integration bbad225; Yon project root app/). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-REMOTES-LANGS-B.env &&` (ty a7ccbfff on PATH; .NET 9, PHP 8.4, Ruby 4
- Report excerpt: Now the final e2e across all four languages with the committed files.
- Qualification excerpts: - The PHP helper uses PHP's built-in stream wrapper because the ANNEX PHP has no cURL. That wrapper ignores proxy settings, so like Ruby it passes Tachyon's proxy explicitly. | - **B′:** the error code for a failed call is `ADAPTER_FAILED` in C# and Dart but `adapter` in PHP, Ruby and Go. | - **I:** ADR 0068 says Ruby and "PHP with cURL" honour the guard's proxy. In practice Ruby skips the proxy for loopback, and PHP's stream wrapper never uses one. Direct connections from a handler are not blocked. The SESAME helpers work around this; 
- Follow-up excerpts: - **I:** ADR 0068 says Ruby and "PHP with cURL" honour the guard's proxy. In practice Ruby skips the proxy for loopback, and PHP's stream wrapper never uses one. Direct connections from a handler are not blocked. The SESAME helpers work around this;  | **Out of scope:** CHANGELOG text, the README line and an exact edit for `docs/SDK_DISTRIBUTION.md:58-59` are under `## FOR COORDINATOR` in PROGRESS.md.
- Historical branches: `main`.

### agent-a0e89f61c2a6db13a

- Last retained event: 2026-10-04T16:05:34.577Z.
- Task excerpt: You are agent SESAME-LAYERING in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-LAYERING (branch swarm/sesame-layering, on swarm/integration 0808157; the Yon project root is app/). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-LAYERING.env &&` (ty on PATH = a7ccbfff). Read first: /Volumes/ANNEX/build/sesame-s
- Report excerpt: Meanwhile I'll update the progress log with evidence, gaps, and coordinator notes.
- Qualification excerpts: - **Responses, statuses, error codes:** `ty test --coverage` gave the same 299 passing cases before and after all code changes (`EngineServiceTest` is renamed `EngineHelperTest`). Every new class shows as called in coverage. Smoke output is identical | - **Audit actor attribution:** all 10 `ActorAttributionTest` cases pass, as before. | - **Structure:** no file-level variables, one type per file, and no helpers or utilities named in controllers apart from the identity provider's wiring (gap D). No helper depends on a service. The ≤4 params / ≤5 deps limits are checked by the bundle 
- Follow-up excerpts: **Out of scope:** `docs/THREAT_MODEL.md:182` names `TenantCallService`, which still exists, so I left it alone. Changelog text for you is under `## FOR COORDINATOR` in the progress log.
- Historical branches: `main`.

### agent-a89ec73881269838c

- Last retained event: 2026-10-04T16:36:18.894Z.
- Task excerpt: You are agent SESAME-RECHECK-LAYERS, Security Architect. READ-ONLY review (no commits); final message = the report (the coordinator saves it). Worktree (scratch copy of swarm/integration 1151a19, Yon root app/; safe to build/run servers in): /Volumes/ANNEX/build/worktrees/SESAME-RECHECK-LAYERS. Start every shell command with `source /Volumes/ANNEX/build/work
- Report excerpt: d again in the service path: VERIFIED** - `invoke-all.sh` used an acme member session against all 32 `@Allow(Administrator)` routes through `handler invoke`. Every body named the member's own tenant and valid targets, so a missing gate would have written. - The route families were authenticator-for-principal, federation, grant, group, oidc-client, oidc refresh-family, principal, role, saml, scim, session, system and tenant. - Result: **32/32 `403 {"code":"administrator_required"}`**, and the fylo-root sha snapshot was identical before and after. - Code path: `TenantCallService.administrator` c
- Qualification excerpts: - **Fail closed:** an `http://` allowlist entry gave 500 `internal_error` with no engine call, the same as baseline. | - `go test -count=1 ./test/contract` passed. | - **LOW (hardening, not a regression):** `PublicCallService.Call` passes any `EngineCall` straight to the engine without an actor. The engine then runs it as `operator:machine`.
- Historical branches: `main`.

### agent-af1855b8b822d0a9c

- Last retained event: 2026-10-04T16:55:08.500Z.
- Task excerpt: You are agent SESAME-FIX-PUBLIC in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-FIX-PUBLIC (branch swarm/sesame-fix-public, on swarm/integration 1b4d5a5; Yon root app/). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-FIX-PUBLIC.env &&` (ty a7ccbfff). Read: /Volumes/ANNEX/build/sesame-swarm/SWARM/COMMON-PROMP
- Report excerpt: **SESAME-FIX-PUBLIC: ready to merge.** Branch `swarm/sesame-fix-public` is two commits on top of 1b4d5a5: c2d0f22 (the fix) and 6b3ab1a (the contract test).
- Qualification excerpts: - `TestEveryRoutedPublicOperationStillReachesTheEngine`: drives all 17 public controller routes and expects zero refusals. Removing `session.verify` from the list makes it fail ("expected: <0> but was: <1>"). | - Green: 3 passed. The related units (Authn, System, Token, Session, Oidc, Federation, Saml, the two login tests, ActorAttribution, SesameErrorHandler) gave 113 passed, 0 failed. | **Gate:** one full run under MAC-LOCK at 6b3ab1a returned `gate exit=0`. That covers gofmt, vet, build, `go test -race` (31 packages), `app/server/packages`, `ty bundle`, `ty test --coverage`, and the smoke test (37 checks ok). Along the way `ty bund
- Follow-up excerpts: **Out of scope, left for you:**
- Historical branches: `main`.

### agent-a03f5200e31d241d6

- Last retained event: 2026-10-04T18:23:47.772Z.
- Task excerpt: Read-only. SESAME integration worktree: /Volumes/ANNEX/build/worktrees/SESAME-INTEGRATION (branch swarm/integration = local main ef40cef). Thoroughness: very thorough. Cite file:line. For EVERY tracked top-level entry (`git ls-files | cut -d/ -f1 | sort -u`, plus second-level folders of internal/, test/, tools/, app/server/, remotes/, docs/, api/, examples/,
- Report excerpt: rationRedirectAllowlist, SamlConsumerAllowlist, SamlLogin, ScimBearer, ScimGroup, ScimUser. - **How they run:** `ty test app --coverage` (gate.sh:22; `app/package.json` "test"). Not run in GitHub CI (comment at ci.yml:73-76).
- Qualification excerpts: - **How they run:** `ty test app --coverage` (gate.sh:22; `app/package.json` "test"). Not run in GitHub CI (comment at ci.yml:73-76). | - :54 `./internal/...`, :55 `./tools/coverage` | - **Build targets passed to `go build` by string:** `./cmd/sesame`, `./internal/adapters/fylo/testdata/fakefylo` (10+ sites), `./examples/hostserver`.
- Historical branches: `main`.

### agent-a7632fe664f249761

- Last retained event: 2026-10-04T18:27:00.192Z.
- Task excerpt: Read-only research plus throwaway experiments (only under /Volumes/ANNEX/tmp/sesame-layout2-probe, delete afterwards). TACHYON latest integration head is 12fe0cb4: source worktree /Volumes/ANNEX/build/worktrees/INTEGRATION (verify it is at 12fe0cb4), built binary /Volumes/ANNEX/build/ty-by-commit/12fe0cb4/ty. Use `source /Volumes/ANNEX/toolchains/env.sh` for
- Report excerpt: t 0, silently staged | | (c2) project-root `test/` | "No test units found", exit 0 | exit 0 |
- Qualification excerpts: - `go test ./...` passed except 6 tests that read `../../../api/...` repo-root fixtures. | - Probe: `sdk/go` (with its own `go.mod`, a secret-looking constant and an undeclared URL), `tools/gen/run.js` (with `eval`), a `ToolTest.go` and `docs/` were all ignored. Bundle and test both passed. | - A separate module `example.com/other` importing `example.com/probe/engine/internal/keys` failed with that error.
- Historical branches: `main`.

### agent-a0b1bb9cca1c52576

- Last retained event: 2026-10-04T18:31:37.119Z.
- Task excerpt: You are agent SESAME-SDK-MOVE in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-SDK-MOVE (branch swarm/sesame-sdk-move, on swarm/integration ef40cef = local main). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-SDK-MOVE.env &&`. Read first, fully: /Volumes/ANNEX/build/sesame-swarm/SWARM/{COMMON-PROMPT,BRIEF,QU
- Report excerpt: I've stopped as you asked. I changed no files, so there was nothing to commit and I did not make the WIP commit.
- Qualification excerpts: - **Not done:** I did not run `git mv`, change the generator's output folder, split any helper, regenerate anything, run any `ty bundle`/`test`/`migrate check`, run the end-to-end check, write a CHANGELOG entry or run the gate. | - Nullable injected fields fail with TY1331. | 7. **Every adapter error collapses to one generic code.** Go, PHP, Ruby and Python report `adapter`; C# and Dart report `ADAPTER_FAILED`; JS/TS pass a thrown `BehaviorError` through. Any status or error code must therefore travel inside the returned 
- Follow-up excerpts: - **Out of scope:** nothing.
- Historical branches: `main`.

### agent-a0e7fe5bbb6eccc84

- Last retained event: 2026-10-04T18:44:35.507Z.
- Task excerpt: Research with throwaway experiments only (under /Volumes/ANNEX/tmp/sesame-noserver-audit; delete after; no repository edits). SESAME at /Volumes/ANNEX/build/worktrees/SESAME-INTEGRATION (= local main ef40cef). TACHYON latest: source /Volumes/ANNEX/build/worktrees/INTEGRATION (12fe0cb4), ty binary /Volumes/ANNEX/build/sesame-swarm/ty/ty-12fe0cb4. Toolchains: 
- Report excerpt: kage declarations, or relative file references; keep ordinary dependency imports in the entry point." (`:1524-1531`). `process.getBuiltinModule('node:child_process')` passes. `ty test` ran it on Node v24.21.0, and Bun also supports it. | | TypeScript | works with a workaround | Same TY2101 and the same workaround. | | Python | works | `asyncio.create_subprocess_exec`; helpers may import only json/os/asyncio/typing/models (`:1243`). Also verified through `ty handler invoke`, reading `yon.sesame.binary` and `yon.sesame.deployment` from `YON_APPLICATION_JSON`. | | Java | works | `ProcessBuilder` 
- Qualification excerpts: - **Config path:** the `sesame` key in `application.json` arrives as `yon.sesame.*` (`EngineSettingsHelper.go:18`). `ty test` gets no snapshot (ADR 0007 gap 5), so tests must pass the paths explicitly. | **`@Gateway({"command":[...]})` does not fit.** I tested `["sesame","exec","--loop"]` with `SESAME_DEPLOYMENT` passed through `server.environment`. It reached the engine, which answered `invalid_request: request does not match the machine protocol sc | - **Single writer:** a second engine on the same deployment failed live with `EROOTLOCKED: FYLO root already has a live exclusive owner (pid …)`.
- Follow-up excerpts: 10. In-process is blocked by `internal/`, and FYLO is always a child process.
- Historical branches: `main`.

### agent-abd644557fca3c3b9

- Last retained event: 2026-10-04T18:56:01.847Z.
- Task excerpt: You are agent SESAME-ENGINE-MOVE in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-ENGINE-MOVE (branch swarm/sesame-engine-move, on swarm/integration ef40cef = local main). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-ENGINE-MOVE.env &&`. Read first, fully: /Volumes/ANNEX/build/sesame-swarm/SWARM/{COMMON-PRO
- Report excerpt: SESAME-ENGINE-MOVE is **ready to merge**: branch `swarm/sesame-engine-move` (4 commits on ef40cef, head `3d1dec0`). The full gate ran under MAC-LOCK with my adjusted gate copy and exited 0. Security finding first: ty's Go handler build does not enforce Go's internal-package rule, so the new contract test is the only thing keeping Yon roles out of engine internals.
- Qualification excerpts: - **Coverage floors:** all four groups pass. | - **Workflows:** `ci.yml` now runs the root module and the engine module (tests, vet, race, staticcheck, govulncheck, adversarial suite, coverage, cross-build). `release.yml` builds from the engine module with `GOWORK=off`; I checked locally that the | - **G2 (minor):** `ty handler invoke` reports any handler failure only as the app's 500 body, so you can't tell why it failed without logs.
- Follow-up excerpts: - **Out of scope, for TESTS-MIRROR/DOCS:**
- Historical branches: `main`.

### agent-aa353fd8629575b06

- Last retained event: 2026-10-04T19:16:17.877Z.
- Task excerpt: You are agent SESAME-RETIRE-HTTP in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-RETIRE-HTTP (branch swarm/sesame-retire-http, on swarm/integration 3d1dec0: engine now lives in the module app/server/packages). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-RETIRE-HTTP.env &&` (ty 12fe0cb4). Read fully first:
- Report excerpt: Before the gate, I'll write up PROGRESS (so an interrupted run resumes), then run the gate under the lock in the background.
- Qualification excerpts: SESAME-RETIRE-HTTP: **ready to merge.** The HTTP host is gone, the full gate passed under MAC-LOCK with my adjusted gate copy (exit 0), and nothing that remains opens a listener. | - Green: `TestOnlyTheEnginePublicPackageIsImportedFromOutsideTheEngine` and `TestEngineImportScanReportsAnInternalImportFromAHandlerFile` both pass.
- Historical branches: `main`.

### agent-a26600be656656bee

- Last retained event: 2026-10-04T19:38:55.910Z.
- Task excerpt: You are agent SESAME-SDK-CORE in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-SDK-CORE (branch swarm/sesame-sdk-core, on swarm/integration ef40cef). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-SDK-CORE.env && export PATH=/Volumes/ANNEX/build/sesame-swarm/ty-candidate-bin:$PATH` — no wait: use the latest t
- Report excerpt: Now move the contract test to tests/contract with self-contained helpers.
- Qualification excerpts: - `ty test --coverage`, failing when fewer units run than exist; | go run ./tools/sdk/verify -sesame $log.sesame -fylo "$(command -v fylo || echo /Users/iyor/.local/bin/fylo)" -ty "$(command -v ty)" >$log.sdk 2>&1 || { echo "GATE sdk verify FAILED"; grep -E 'FAIL|TY[0-9]{4}|error|outlived|ran [0-9]+ test unit' $log. | echo "GATE sdk verify: $(grep -c 'test unit(s) passed' $log.sdk) language(s), $(grep -c 'probe route reached' $log.sdk) probe(s)"
- Follow-up excerpts: **Out of scope, for you:** text for the `docs/YON.md` "Tachyon helpers" placeholder, plus CHANGELOG, README.md, SDK_DISTRIBUTION.md and ADR 0008 notes, is under FOR COORDINATOR in PROGRESS. `tests/sdk/go/go.mod` is a sentinel that keeps package-less 
- Historical branches: `main`.

### agent-a60102217ff0f1f59

- Last retained event: 2026-10-04T19:54:17.955Z.
- Task excerpt: You are agent SESAME-TESTS-MIRROR in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-TESTS-MIRROR (branch swarm/sesame-tests-mirror, on swarm/integration 647c9a4: no server; app/server/packages = the engine module github.com/d31ma/sesame/app/server/packages with vendor/; root module github.com/d31ma/sesame holds test/, tools/, examples/). S
- Report excerpt: r` at `3d6d9df`, rebased onto `swarm/integration` `f22eddf` (SDK-CORE's commits) with no conflicts. I didn't touch any SDK-CORE files.
- Qualification excerpts: - `.github/workflows/ci.yml`: names check, engine tests, vet, race, the adversarial suite and coverage now go through the runner. `staticcheck` and `govulncheck` take no overlay, so in the engine module they check production code only; this is docume | - Docs: `README.md` (testing section, repository layout, coverage table), `CONTRIBUTING.md`, `docs/ENGINEERING_STANDARDS.md`, `docs/YON.md`, ADR 0007, and test path references in the other docs, `api/machine/v1/README.md`, website comments and one co | GATE testmirror: 652 tests ran (0 failed, 24 skipped)
- Follow-up excerpts: **Out of scope, for you**
- Historical branches: `main`.

### agent-ae0b9017d30822866

- Last retained event: 2026-10-04T20:17:30.846Z.
- Task excerpt: You are agent SESAME-DOCS8 (Senior Technical Writer + Codebase Steward) in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-DOCS8 (branch swarm/sesame-docs8, on swarm/integration 3d6d9df). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-DOCS8.env &&`. Read fully first: /Volumes/ANNEX/build/sesame-swarm/SWARM/{COM
- Report excerpt: Lock is held; running the gate through the FIFO lock in the background.
- Qualification excerpts: Ready to merge: branch `swarm/sesame-docs8` is 4 commits on top of `swarm/integration` 3d6d9df, and the full gate passed under MAC-LOCK. | **Gate:** exit 0. All 652 mirrored test names match the list and all ran (0 failed, 24 skipped), 34 Go packages ok, and SDK verify passed for 3 languages with 3 probes. `go test ./tests/contract/` passed after every doc batch. The last commit (961024 | - Checked and kept: `tools/coverage`, `infra/amplify`, `api/*`, `examples/hostserver`, `go.work`.
- Follow-up excerpts: **Out of scope:**
- Historical branches: `main`.

### agent-a58d9a83e75b7fe3a

- Last retained event: 2026-10-04T20:22:24.485Z.
- Task excerpt: You are agent SESAME-SDK-LANGS-B in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-SDK-LANGS-B (branch swarm/sesame-sdk-langs-b, on swarm/integration f22eddf). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-SDK-LANGS-B.env &&` (ty 12fe0cb4 on PATH; Ruby 4.0, Dart 3.13, Rust 1.97 via /Volumes/ANNEX/toolchains/e
- Report excerpt: Meanwhile, I'll write the gaps and coordinator notes into the progress log.
- Qualification excerpts: - With the EROOTLOCKED retry off (Ruby), the busy and wait cases fail. | - **T5:** `ty test` passes no settings snapshot to units. | **Longest wait:** none for the lock. The gate itself took 2 min 45 s. The slowest loop while building was a Dart mutation run that hung until the 30 s unit deadline. That exposed a real bug, now fixed: an open stderr reader kept the Dart unit alive w
- Follow-up excerpts: **Out of scope:** the CHANGELOG entry and edits to `docs/YON.md`, README, `docs/SDK_DISTRIBUTION.md` and ADR 0008 are drafted under "FOR COORDINATOR" in `/Volumes/ANNEX/build/sesame-swarm/SESAME-SDK-LANGS-B/PROGRESS.md`.
- Historical branches: `main`.

### agent-ab866d84f2ae4ac71

- Last retained event: 2026-10-04T20:33:31.178Z.
- Task excerpt: You are agent SESAME-SDK-LANGS-A in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-SDK-LANGS-A (branch swarm/sesame-sdk-langs-a, on swarm/integration f22eddf). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-SDK-LANGS-A.env &&` (ty 12fe0cb4 on PATH; Java 21, kotlinc, .NET 9, PHP 8.4 via /Volumes/ANNEX/toolchain
- Report excerpt: My gate got the lock at 16:29:40 (wait was about 10 minutes) and is running.
- Qualification excerpts: The gate passed. Recording it and doing a final check of the branch. | **Ready to merge.** Branch `swarm/sesame-sdk-langs-a` has 5 commits on top of `swarm/integration` 3d6d9df (rebased after TESTS-MIRROR landed). The full gate passed under MAC-LOCK: testmirror 652 tests ran with 0 failed and 24 skipped, 34 Go packages  | - **Coverage:** 90/90, 89/89, 90/90 and 88/88 public methods. `tests/contract` and `tools/sdk` tests pass.
- Historical branches: `main`.

### agent-a3f0bceff563dc22a

- Last retained event: 2026-10-04T21:01:44.850Z.
- Task excerpt: You are agent SESAME-FOLLOWUPS8 in the SESAME swarm. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-FOLLOWUPS8 (branch swarm/sesame-followups8, on swarm/integration 3151cfd: no server; engine module app/server/packages; 10 SDK languages in app/sdk; tests/ mirror). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-FOLLOWUPS8.env &&
- Report excerpt: Nothing else to update. Running the full gate under MAC-LOCK.
- Qualification excerpts: - **(e) Manifest comment:** `tests/contract/manifest_comment_test.go` failed and now passes. Only the comment line in `operations.json` changed; the operation list and every other key are identical. | I also added the per-language cleanup table and the SDK-LANGS-A/B Tachyon gaps to ADR 0008. `go test ./tests/contract/` passed after each docs batch. | **Gate (MAC-LOCK):** testmirror ran 652 of 652 test names (0 failed, 24 skipped); 34 Go packages passed; SDK verify passed for 10 languages with 10 probes; exit 0. The log is at `/Volumes/ANNEX/build/sesame-swarm/SESAME-FOLLOWUPS8/gate.log`.
- Follow-up excerpts: **Out of scope / for coordinator:** REVIEW should look at the host consent fix (item b), since it is security-relevant. CHANGELOG, README, dependabot, CONTRIBUTING and facts.js are coordinator-only files; I edited them because this task assigned them
- Historical branches: `main`.

### agent-a6f9e0c4764a2bc4e

- Last retained event: 2026-10-04T21:15:16.327Z.
- Task excerpt: READ-ONLY security code review (do not edit or commit anything). Repo worktree: /Volumes/ANNEX/build/worktrees/SESAME-REVIEW8. Prefix every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-REVIEW8.env &&`. Review the generated SESAME SDK engine helpers for these languages: Go, TypeScript, Python, Java, Kotlin. Files: app/sdk/<lang>/server/hel
- Report excerpt: capped at limit+1 (`:153`), so at most 1,048,576 bytes. - TypeScript: the partial buffer is checked after each chunk (`:191`, `:197`). - Python: StreamReader `limit=1048577` (`:143`). `readline` turns an overrun into `ValueError`, which is caught at `:187`. Content up to limit+1 is accepted (1 byte over), and flow control caps memory at about 2× the limit. - Java and Kotlin: byte-by-byte loop capped at limit+1 (Java `:265`, Kotlin `:243`), not an unbounded `readLine`. - Go package: Scanner capped at `1<<20` (`client.go:165`).
- Qualification excerpts: | 9. Generated files match templates | Pass | Pass | Pass | Pass | Pass | n/a | | - **Cleanup (row 6):** every helper ends the engine on a failed handshake (Go `:115-116`, TypeScript `:123`, Python `:127`, Java `:159`, Kotlin `:150`) and on a bad or oversized response. An oversized request writes nothing, so no cleanup is needed.  | - **Templates (row 9):** `TestCommittedSDKMatchesTheGenerator` (`tests/contract/sdk_test.go:34`) passes. A spot diff of each engine-helper template differs only in the `{{.ProtocolVersion}}` placeholder.
- Historical branches: `main`.

### agent-a1f65fff61e1d0914

- Last retained event: 2026-10-04T21:17:15.027Z.
- Task excerpt: READ-ONLY security code review (do not edit or commit anything). Repo worktree: /Volumes/ANNEX/build/worktrees/SESAME-REVIEW8. Prefix every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-REVIEW8.env &&`. Review the generated SESAME SDK engine helpers for these languages: C#, PHP, Ruby, Dart, Rust. Files: app/sdk/<lang>/server/helpers/Sesame
- Report excerpt: group id could be reused in that microsecond gap. During a busy wait this happens up to about 400 times per call (20 s at 50 ms per retry). The odds are tiny. Fix: check or signal the group while the engine is still unreaped (`waitid(..., WNOWAIT)`), or accept and document the risk. - **L2. Up to 4 KiB of the engine's error output (stderr) ends up in error messages**: Rust `:156`, Dart `:176`, C# `:152`, PHP `:153`, Ruby `:148`. PHP also puts the binary path in its message (`:134`); C# and Ruby include the operating-system error text. `docs/YON.md:109-110` says to "keep it out of anything user
- Qualification excerpts: | 7 one request at a time, id checked | Pass (lock, `:260`) | Pass (single-threaded; no lock under fibers or coroutines) | Pass (mutex) | Pass (`_turn` chain; `close` not queued but safe) | Pass (mutex) | | | 8 no network code, no listener, no cross-language references, header on every file | Pass | Pass | Pass | Pass | Pass | | | 9 no shell, encoder-built JSON, timeouts bounded | Shell/JSON pass; timeouts fail (M1, M3) | Shell/JSON pass (`proc_open` array); timeouts fail (M1) | Shell/JSON pass (multi-argument `spawn`); timeouts fail (M1) | Shell/JSON pass; timeouts fail (M1
- Historical branches: `main`.

### agent-af268254ad6bbfa4c

- Last retained event: 2026-10-04T21:21:09.310Z.
- Task excerpt: You are agent SESAME-REVIEW8, Security Architect + Senior QA + Codebase Steward. READ-ONLY review: no commits; your final message is the report (the coordinator saves it). Worktree (scratch copy of swarm/integration 1ecb25f; safe to build and run things in; stop everything you start): /Volumes/ANNEX/build/worktrees/SESAME-REVIEW8. Start every shell command w
- Report excerpt: startup capture, so `wrap()` never sees `EROOTLOCKED`. - `StartWhenAvailable` therefore fails at once instead of waiting. The reference host passes `os.Stderr`, so anyone copying it gets this. - Separately, `StartWhenAvailable` never stops if given `context.Background()`. - Fix: `io.MultiWriter(options.Stderr, startup)`, and document or enforce a deadline.
- Qualification excerpts: - Engine `code`, `message` and `retryable` pass through unchanged. | 4. **Trust-model docs.** README, YON.md, THREAT_MODEL, the CHANGELOG and ADR 0008 say the pipe holder is trusted and must authenticate, call `authorize.decide` and pass the actor. They list the retired host rules as the application's job and present  | - The boundary test and `TestEngineModuleHoldsNoTestSource` pass, and the gopls limitation is documented (`README.md:243`).
- Historical branches: `main`.

### agent-af0ab9ddb3afa28b6

- Last retained event: 2026-10-04T21:55:46.241Z.
- Task excerpt: You are agent SESAME-FIX8-HOSTGO (Junior Software Engineer, security-critical). Worktree: /Volumes/ANNEX/build/worktrees/SESAME-FIX8-HOSTGO (branch swarm/sesame-fix8-hostgo, on swarm/integration 1ecb25f). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-FIX8-HOSTGO.env &&`. Read first: /Volumes/ANNEX/build/sesame-swarm/SWARM/{COMM
- Report excerpt: Meanwhile, I'll write the coordinator notes in PROGRESS.
- Qualification excerpts: - **Host:** 5 authorize tests (forged header → 401; live session → 200; wrong secret, revoked session → 401; other tenant → 403), plus healthz ×2, exact error body, session cookie prefix, Host header ignored, DPoP refused without an origin, origin va | **Gate:** exit 0. 660/660 test names; 660 mirrored tests ran with 0 failed and 24 skipped; 34 Go packages ok; real-FYLO no-listener test 3/3 passed; SDK verify passed for all 10 languages with 10 probes. | - After the engine exits on a read error, `Client.Request` in `client.go` doesn't mark the client closed (the `scan.err != nil` branch). Later calls fail on a dead pipe instead of "client is closed". Not a security issue.
- Follow-up excerpts: **Out of scope / for the coordinator** (also under `## FOR COORDINATOR` in PROGRESS.md, with the CHANGELOG text):
- Historical branches: `main`.

### agent-a0e0c2428a2cb4eb4

- Last retained event: 2026-10-04T22:02:34.348Z.
- Task excerpt: You are agent SESAME-FIX8-SDK-A. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-FIX8-SDK-A (branch swarm/sesame-fix8-sdk-a, on swarm/integration 1ecb25f). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-FIX8-SDK-A.env &&` (ty 12fe0cb4). Read first: /Volumes/ANNEX/build/sesame-swarm/SWARM/{COMMON-PROMPT,WAVE8,QUEUE}.md (REVIEW8/F
- Report excerpt: Meanwhile, I'll write the coordinator notes into PROGRESS.
- Qualification excerpts: - Removing the close fix makes the close test fail in all five languages. | - Consequence: once the engine has exited normally, its group is no longer signalled. The real engine stops FYLO before it exits (the close test with the real engine passes). | - **Go pipe leak on spawn error:** fixed. With the file-descriptor limit lowered on a scratch copy, the old code went from 6 to 10 open descriptors after a failed spawn; the new code stays at 6.
- Historical branches: `main`.

### agent-ac96f5d0aa0c65540

- Last retained event: 2026-10-04T22:03:07.038Z.
- Task excerpt: You are agent SESAME-FIX8-SDK-B. Worktree: /Volumes/ANNEX/build/worktrees/SESAME-FIX8-SDK-B (branch swarm/sesame-fix8-sdk-b, on swarm/integration 1ecb25f). Start every shell command with `source /Volumes/ANNEX/build/worktrees/SESAME-FIX8-SDK-B.env &&` (ty 12fe0cb4). Read first: /Volumes/ANNEX/build/sesame-swarm/SWARM/{COMMON-PROMPT,WAVE8,QUEUE}.md (REVIEW8/F
- Report excerpt: FIX8-SDK-B is ready to merge: M1 and every helper LOW assigned to me are fixed in all five languages, and the full gate under MAC-LOCK passed. Branch `swarm/sesame-fix8-sdk-b` has 5 commits on `swarm/integration` 1ecb25f.
- Qualification excerpts: - **Wait boundary:** the negative-sleep window cannot be triggered on demand, so that test passes before and after the fix. The clamp itself is the fix. | - `tests/contract` and `tools/sdk` pass. | - **Gate (head 8c3985b):** 652 mirrored tests (0 failed, 24 skipped), 34 Go packages ok, no-listener check 3 passed, sdk verify 10 languages and 10 probes, exit 0.
- Follow-up excerpts: **Out of scope:**
- Historical branches: `main`.


---

## Backup and remaining recovery gaps

The central backup is at `/Users/iyor/Documents/Codex/2026-10-08/task-2/Claude Handoffs 2026-10-09`; it also retains Cowork and unassigned utility records and the OVERWATCH metadata handoff. OVERWATCH has no verified current project root. FYLO, CHEX, TTID, OVERWATCH and an older Tachyon Desktop record have no matching recovered conversation transcript; no implementation progress can be reconstructed from their metadata alone.

No Claude history has been deleted. Any subsequent cleanup needs its separately resolved scope and writer/synchronization checks. Project-root copies may synchronize with the canonical project storage; the central backup is outside the inventoried Claude stores.
