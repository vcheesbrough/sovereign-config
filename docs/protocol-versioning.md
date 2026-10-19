# Protocol versioning

Applications embedding `sovereign-config-provider` are deployed independently of the server and are expected to lag it. A server upgrade must therefore never break them. This document is the whole procedure for introducing and retiring a protocol version; it is self-contained and needs no reading of source.

## How negotiation works

1. The client calls the **handshake** — `/sovereign.config.Handshake/Negotiate` — sending every protocol version it speaks. The handshake is the one operation that is **not versioned and not routed by version**, and the only one a client may call before a version is agreed.
2. The client's list exists for the server's **usage records only**. The server never filters or reorders its answer by it, never rejects on it, and treats it as untrusted input: it is counted under compiled-in labels, bounded in how much is examined, and can never mint a metric label of its own.
3. The server answers with **every version it serves, most preferred first**, whatever the client asked for, and **never rejects**. Each version may carry a `deprecation_date` — an RFC 3339 UTC timestamp before which the server does not expect to retire it. That is a statement of intent, not a guarantee: a version may be served well past it, and a security flaw may retire one before it.
4. The client selects the first version in the **server's** order that it also speaks, passing over a version carrying a deprecation date while one without is still to come. A selected deprecation date **warns and never fails** — the CLI to stderr, the MCP `status` tool in its output, the provider and broker through `tracing`, the browser in the header slot it already uses to report trouble with the service. With no version in common the client aborts with a bounded incompatible-protocol error that **names both lists**, so an operator can tell which end has to move.
5. **Every RPC that follows travels on the negotiated version's routes.** A client is opened as a connection that can do nothing but negotiate; naming the negotiated version is the only way to obtain one that can carry configuration traffic. What an operator is shown is read back off that transport, so a reported version and a dialled route cannot disagree.
6. If a later call fails with the **version-not-served** error, the client repeats the handshake **once**, selects again, obtains a *new* transport, and retries that call. The rejected call never executed, so the retry is safe. It logs the change of version. If nothing is in common, or the retry fails the same way, it aborts.

**The handshake's shape is fixed, forever.** It can never be versioned, because it is the operation that tells a client which versions exist. It never gains, loses, retypes or repurposes a member. Anything a client needs beyond the list of served versions belongs in a versioned operation — which is why the service's release version is read from `System.GetVersion` on the negotiated route rather than from the handshake.

The handshake is **unauthenticated**, and this is the recorded reason: a client has no token before it has negotiated, `System.GetVersion` already publishes the same list to anyone, and leaving the handshake outside authentication keeps each protocol version free to change its own authentication scheme. The cost is that the served list and the client lists sent to it are public, which is what the untrusted-input handling in step 2 exists for.

### Reaching a server that has no handshake

Every server up to 2.27 authenticates **before** it routes, and exempts only the health probes and `<served>.System/GetVersion`. A handshake call carries no token, so such a server refuses it `UNAUTHENTICATED` — the request never reaches the router that would have said `UNIMPLEMENTED`. **Detecting a pre-handshake server is therefore not "`UNIMPLEMENTED`"**, and the obvious test fixture lies about this: a bare router with no authentication in front of it answers `UNIMPLEMENTED`, while a real deployed server answers `UNAUTHENTICATED`.

On either answer the client falls back to `GetVersion` on `ProtocolVersion::LEGACY`'s own route, which those servers do exempt. If it answers, the server serves exactly that version. A handshake failure of any other kind — `UNAVAILABLE`, say — is reported as itself, and a fallback that also fails reports the fallback's failure. A server that *has* the handshake never answers it `UNAUTHENTICATED`, so the fallback cannot mask a genuine authentication problem.

## The rule that makes this work

**Adding a protocol version must never change what an existing version's clients see.**

`GetVersionResponse.protocol_version` is why. Clients compiled before `supported_protocol_versions` existed ignore that field entirely and compare the echoed `protocol_version` against the single version they were built with. If the server ever echoed *its own preferred* version instead of the requested one, every one of those clients would fail on the day a newer version shipped — and they are already deployed, so they cannot be fixed retroactively. That is the fleet-wide outage this mechanism exists to prevent. **Never change the echo semantics.**

The echo falls back to the server's preferred version only when the requested version is not served at all. A client asking for a version it speaks can never observe that fallback.

`v3` also advertises its `supported_protocol_versions` **oldest first**, while the handshake reports **most preferred first**. The two orders are opposite on purpose: `v3` has advertised oldest-first since the field was added and a `v3` client is entitled to that order, so changing it would be a `v3` behaviour change and therefore a new version. `v4`, a new contract, reports most preferred first, as the handshake does. Both keep the echo.

The regression tests that protect this are `a_server_newer_than_this_build_still_connects`, `a_client_compiled_without_the_supported_set_still_decodes_and_negotiates`, and the echo tests in `system.rs`. Do not weaken them.

## The version-not-served error

A request on a **version-shaped route naming a version this server does not serve** — retired, or never existed — is answered by a catch-all with `FAILED_PRECONDITION` plus two fixed metadata keys: one naming the kind (`version-not-served`), one echoing the version asked for. A client identifies it by the **marker, never by the status code**, which is shared with failures that are not about versions.

A mistyped service or method on a *served* version stays `UNIMPLEMENTED`. Keeping those two apart is the point: a retired version is something a session can recover from by re-handshaking, and a typo is not.

Two placement decisions are load-bearing, and `auth::grpc_service_layer` is what pins them:

- the catch-all sits **inside** the gRPC-Web layer, so a browser receives an answer it can decode. Outside it, a retirement would reach the browser as an undecodable transport failure with no version in it;
- it sits **outside** authentication, because an unserved version has no authentication scheme left to apply, and a client whose credentials also expired while it was away should still be told what actually broke.

Both are asserted in `crates/sovereign-config-server/src/protocol/serving_tests.rs`.

## What forces a new version, and what does not

A new version **is** required for:

- renaming, renumbering, retyping, removing or repurposing an existing field;
- changing what an existing RPC does — the behaviour of a call is part of the contract, not just its signature;
- **adding any field or RPC, even an optional one**;
- **changing the set of values an existing field may carry** — a wider or narrower grammar, letter case, range, or a new enumeration member.

The last two were relaxed until 2.28.0, which is what releases 2.15.0 (path grammar) and 2.18.0 (path letter case) are this repository's own evidence against: both were additive to the `v3` contract, both shipped without a version bump, and both broke older clients, because a client validates what it was built to expect and one unexpected value fails the whole response carrying it.

A new version is **not** required for bug fixes or performance improvements that change no API shape and no substantive behaviour.

**Exceptions are approved before implementation and recorded**, with the reason and who they can affect — a rule with an unrecorded exception reads as a rule that is negotiable. There have been three:

- release 2.25.0 widened `GetVersion` itself in place, because the negotiation mechanism could not otherwise be introduced without the flag day it exists to remove. It is recorded under [2.25.0 widens `GetVersion`](upgrading.md#2250-widens-getversion). Treat it as the bootstrap of this mechanism, not as precedent.
- release 2.29.0 made `RevealSecret` fail closed when its audit record cannot be written, because recording confined to one version would make every other version a way around the audit trail. It is recorded under [2.29.0 makes `RevealSecret` fail closed on an audit fault](upgrading.md#2290-makes-revealsecret-fail-closed-on-an-audit-fault). It is not precedent for other behaviour changes either: its justification is specific to a record that must not be bypassable.
- release 2.42.0 repaired, once, the `actor_name` and narrative of past audit events by access URLs, which until then had recorded no name, because the rows are shared by every version and the alternative was keeping the bug in the trail for good. Its approval came during review rather than before implementation, which this document's rule asks for, and the record says so. It is recorded under [2.42.0 repairs past managed actor names](upgrading.md#2420-repairs-past-managed-actor-names). It is not precedent for rewriting history: the originals are kept beside every repaired row.

Note the converse: a change can break clients *without* being a protocol change. 2.26.0 and 2.28.0 both changed the client crates' API without touching any wire contract. Version negotiation does not protect against that class; see [Upgrade](upgrading.md) for how those were sequenced.

## Served versions

| Version | Preference | What it is |
| --- | --- | --- |
| `v4` | first | `v3`'s whole surface plus the `Audit` service. Validates a request's shape before authorizing it. |
| `v3` | second | The original surface. No announced retirement. |

`v4` differs from `v3` in exactly three ways, each recorded in `proto/sovereign/config/v4/service.proto`:

- **`Audit.QueryAuditTrail`** reads the [audit trail](audit-trail.md) back. `v3` has no such service.
- **A malformed request is refused before it is authorized.** A `PutValue` with no content or with a NUL in it, a `ReplaceSubTree` entry with no content, and a managed connection with an empty, unknown or unspecified permission are `INVALID_ARGUMENT` on `v4` whoever sends them. `v3` authorizes first and reports the caller's missing grant instead — `v3`'s order, which cannot change. The wording of each refusal is the same on both.
- **`GetVersion` lists the served versions most preferred first**, where `v3` lists them oldest first.

## Introducing a new version

Each version is its own protobuf package, because the gRPC route path embeds the package name — `/sovereign.config.v3.System/GetVersion`. Distinct packages mean distinct routes, so two versions serve concurrently on one router with no dispatch ambiguity. This is proven end to end by `test-consumers/sovereign-config-proto-testversion`, a dev-only package registered alongside `v3` in the server's own tests; read those tests if you want to see the mechanism working before you rely on it.

The handshake is **not** part of this. It lives outside every version in `proto/sovereign/config/handshake.proto` and `crates/sovereign-config-server/src/handshake.rs`, has no shim, and is never copied or edited when a version is added.

To add `vN`:

1. Add `proto/sovereign/config/vN/service.proto` with `package sovereign.config.vN`, starting from the previous version's file. Make the breaking change there, and only there.
2. Compile it in `crates/sovereign-config-proto/build.rs` and expose it as a `vN` module in that crate's `lib.rs`, alongside `v3`.
3. Write the `vN` ↔ core mapping shims beside `crates/sovereign-config-server/src/values/v3.rs` and `managed/v3.rs`, point each at the `vN` generated types, and add its `mod` line and re-export in `values.rs` / `managed.rs`. **This layer must be only the proto↔core translation, plus that version's own basic validation.** Domain types in `sovereign-config-core` stay version-free, so a second version is a translation shim over one implementation rather than a forked server. If you find yourself duplicating logic rather than mapping types, the change belongs in the shared implementation (`service.rs`) or in core, not in the shim.

   **Share adapter code, do not copy it and never chain it.** Because every added field or RPC is now a new version, most of a new version is unchanged from the one before — so an operation whose wire shape is identical in both has one adapter referenced by both shims. Generated types differ per package, so the adapter is a macro in each module's `shim.rs`: a version's `vN.rs` imports its generated package as `proto` and invokes it, and adds only what that version alone has, as `audit/v4.rs` does. An operation whose shape *does* change gets its own adapter for that operation rather than a branch in the shared one. A shim must never call another version's shim, or retiring a version would mean untangling the ones built on it.

   **Each version chooses its own basic validation**, as a policy passed to that macro. `v3` passes `Deferred`: input it cannot translate, such as an unset oneof, goes down as `None` for the shared implementation to reject after it authorizes, which is the order `v3` has always failed in and so the order it keeps. From `v4` on the policy is `Upfront`: the shim refuses a malformed request before the shared implementation is called, with the shared implementation's own wording. A managed-connection refusal is counted through the shared implementation, so the operation metric sees it like any other.

   And the shared implementation **never branches on the version**: the `CallContext` it receives may record which version a call arrived on, but an implementation that behaves differently per version is a forked server with extra steps. `System` stays per-version (`system.rs`), because `GetVersion`'s echo is version-specific by nature.
4. Register the `vN` services on the router in `crates/sovereign-config-server/src/main.rs`, **leaving every existing `add_service` line in place.** Construct each `vN` shim over the same `Arc` of the shared implementation the `v3` line uses — one implementation, however many versions.
5. Teach the **clients** to dial `vN`:
   - Add `VN` to `ProtocolVersion` in `crates/sovereign-config-core/src/status.rs`, declared **before** the existing variants — the list is preference order, most preferred first. This says only that clients in this workspace can *speak* `vN`; it advertises nothing.
   - **The workspace now fails to compile**, in `crates/sovereign-config-native/src/transport/mod.rs` and `crates/sovereign-config-web/src/transport/mod.rs`. Each selects its routes with an exhaustive `match` on `ProtocolVersion`, so a version with no dialer is a non-exhaustive-patterns error naming the transport that cannot speak it.
   - Fix it by writing the dialers: add `transport/vN.rs` in each crate invoking that crate's `transport/adapter.rs` macro over the `vN` stubs (native) or messages and route label (browser), and add the `ProtocolVersion::VN` arm. **These modules must be only the proto↔core translation**, and share adapter code for the same reason step 3 gives on the server side. A version without an operation another has still implements its client trait, answering with a bounded error and dialling nothing, as `v3`'s `AuditTransport` does.

   The order is deliberate: declaring the version first is what produces the compile error, and the compile error is what stops the version being declared without dispatch. Do not work around it by returning an older version's dialer — a version negotiated and reported while its traffic travels on an older version's routes makes `sovereign_config_protocol_requests_total` read backwards, showing the version actually carrying the traffic as idle and the unused one as busy. Since that counter is the retirement gate below, the result is a gate that says it is safe to delete the version everything is using.

   `crates/sovereign-config-native/tests/protocol_dispatch.rs` then checks, for every version in `ProtocolVersion::ALL`, that each RPC reaches a route naming that version — asserted on what the server received. It covers `vN` the moment `vN` is declared; there is no list in it to extend. The browser's equivalent is `every_route_the_browser_dials_names_the_version_it_speaks`.
6. Add `vN` to `SERVED_PROTOCOL_VERSIONS` and `SERVED_PROTOCOL_LABELS` in `crates/sovereign-config-server/src/system.rs`, `vN` **first** — that list is the server's preference order, and the handshake reports it verbatim. Do this **last**: it advertises the version to clients, so the services implementing it must already be registered.

Two things you do *not* have to edit, because they derive from `SERVED_PROTOCOL_VERSIONS` and would be easy to miss:

- **The unauthenticated-RPC allowlist.** `GetVersion` is called before any token exists by every client that predates the handshake, so it must stay unauthenticated on every served version. `is_operational_rpc` in `crates/sovereign-config-server/src/auth.rs` matches `/sovereign.config.<served>.System/GetVersion` against the served set rather than listing paths, so step 6 exempts `vN` automatically. The handshake route is exempt by name, and is not version-derived because it names no version.
- **The per-version metric label**, which comes from `SERVED_PROTOCOL_LABELS` in the same step.

Deploy the server before any client change. Clients now negotiate `vN` automatically; clients that have not been rebuilt continue on the version they were built for.

## Retiring a version

**Announce it first.** Set a `deprecation_date` on the version in `SERVED_PROTOCOL_VERSIONS` and ship that, so clients selecting it warn their operators and clients that can move to a non-deprecated version do so on their own. The date is a statement of intent, not a commitment: it binds nothing, and a security flaw may retire a version before it.

**Then confirm no real consumer still speaks the version.** The gate is the **authenticated** series:

```
sovereign_config_protocol_requests_total{version="v3",outcome="authenticated"}
```

A version may be retired only once that series has been flat at zero across an observation window long enough to cover the slowest-moving consumer — at minimum a full deployment cycle of every application that embeds the provider. `sovereign_config_protocol_client_versions_total` is the companion view: it counts the versions clients *say* they speak in their handshake lists, so it shows a fleet becoming ready for a retirement before the request series goes quiet.

**Check how much metric history you actually have before reading the gate.** "Flat at zero across a full deployment cycle" is a claim about a window, and it can only be made over samples that still exist. Metric retention is set by the platform, not by this product (the project's own keeps one day; see [Project deployment](project-deployment.md#telemetry-platform)), and a consumer that loads configuration at startup and restarts weekly is invisible six days in seven — so a one-day window says almost nothing about a monthly deployment cycle. Either raise retention to cover the observation window, or alert on any authenticated traffic for the version after cutover, since an alert's firing history does not depend on how long samples are kept.

**Use the [audit trail](audit-trail.md) to explain the metric, not to replace it.** The trail records the identity *and* the protocol version on every hooked call and keeps them for a year, so it is what names the consumer to chase when the gate will not go quiet; every application that embeds the provider begins a load with a plain read, so none of them can stay on an old version without appearing there. The metric stays the gate all the same: it is counted in the authentication layer for every authenticated RPC by construction, including calls nobody thought to audit, while the trail covers the calls that were hooked and records reads on a best-effort basis. In practice the two agree. If they do not, that is a finding to understand before retiring anything.

Gate on `authenticated`, **not** on `attempted`. The gRPC endpoint is public, so `outcome="attempted"` counts everything whose route names the version before authentication runs — including an internet scanner, or a decommissioned application whose credentials were revoked months ago but whose process still retries. None of those breaks when the version is retired, yet any of them can hold `attempted` above zero indefinitely; gating on it would mean never retiring anything, or learning to ignore the counter. Nothing unauthenticated can move `authenticated`. A non-zero `attempted` with `authenticated` at zero is worth a look in the logs, but it is not a reason to keep the version.

This is a precondition, not a courtesy. The provider does not cache: it holds no last-known-good configuration, by deliberate design, because retaining one would keep revealed secrets in process memory for the application's lifetime. An application still speaking a version you delete therefore fails on its next configuration load — it re-handshakes once, and if nothing is left in common, that is the end of it.

Once the authenticated series reads zero:

1. Delete `proto/sovereign/config/v3/` and its entry in `crates/sovereign-config-proto/build.rs` and `lib.rs`.
2. Delete the `v3` mapping shims — `crates/sovereign-config-server/src/values/v3.rs` and `crates/sovereign-config-server/src/managed/v3.rs` — with their `mod` lines and re-exports, and `SystemService` in `system.rs`. The shared implementations and adapters beside them (`service.rs`, `shim.rs`) are untouched: they never knew `v3` existed. Once no version uses the `Deferred` validation policy, delete it too.
3. Delete the `v3` client dialers — `crates/sovereign-config-native/src/transport/v3.rs` and `crates/sovereign-config-web/src/transport/v3.rs` — with their `mod` lines and their arm of each `dialer` and `routes` match.
4. Delete the `v3` `add_service` lines in `crates/sovereign-config-server/src/main.rs`. **Its routes now fall to the catch-all**, which answers them version-not-served; there is nothing else to remove for dispatch.
5. Remove `V3` from `ProtocolVersion`, `SERVED_PROTOCOL_VERSIONS` and `SERVED_PROTOCOL_LABELS`, and repoint `ProtocolVersion::LEGACY` if it named `V3`.
6. Update `SYSTEM_SERVICE_NAME` in `main.rs`, which the container health probe asks for by name, and drop `v3`'s `System` from `serving_health_service`.

With `v4` served, `v3` is the first version that *can* be retired: every client built from 2.31.0 on already speaks `v4`, so its authenticated series falls as consumers are rebuilt. It has no announced date.

Steps 3 and 5 hold each other honest: removing the variant while a dialer still names it is a compile error in that dialer, and removing the dialer while the variant remains is a non-exhaustive `match`. `LEGACY` is checked the same way. A retired version leaves no orphan in either direction.

Announce the retirement to every consuming repository before it ships. A client outside the supported range fails with a bounded incompatible-protocol error naming both lists at connect, which is a clear error but not a recoverable one.
