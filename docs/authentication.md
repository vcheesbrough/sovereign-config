# Authentication and access control

Sovereign Config delegates identity to an OIDC identity provider. Every request carries an access token issued by it, the server verifies that token locally against the provider's published keys, and authorization comes from grants signed into the token. The server holds no users, passwords, roles or sessions of its own.

This document is what holds whichever identity provider a deployment uses: choosing one, [the realm contract](#the-realm-contract) any of them must meet, how requests are authenticated, credential rotation, and managed application connections (access URLs). How a particular provider is set up to meet the contract is that provider's chapter:

| Provider | `SOVEREIGN_CONFIG_IDENTITY_PROVIDER` | Chapter | Setup file |
| --- | --- | --- | --- |
| Authentik 2026.5.2 or newer | `authentik` (the default) | [Authentik](authentik.md) | `authentik/blueprint.yaml`, `authentik/blueprint-dev.yaml` |

## Choosing the identity provider

`SOVEREIGN_CONFIG_IDENTITY_PROVIDER` names the provider the server starts with. Unset or blank means `authentik`, so a deployment that predates the variable needs no change. A name the server does not have fails startup, listing the names it has. The chosen provider then reads and validates its own variables — its chapter lists them — and a missing or invalid one fails startup by name, quoting no value.

**A deployment has one identity provider for life.** The accounts behind access URLs and the subjects in the audit trail are the provider's own identifiers, and mean nothing to another. The first `migrate` records the provider's name in the database, and a later `migrate` or server start under a different name fails rather than orphan them. Moving a deployment to another provider is a migration of those values, not a setting, and is not supported in place.

What the server takes from the provider, once, at startup:

- **Managed accounts** — creating, granting, renaming, re-keying and deleting the service account behind each access URL.
- **Verification rules** — the exact issuer its tokens carry, where its signing keys are published, the audience, and which claims hold the scopes, the grants and the display name. The server applies them to every request itself; the provider is never called to verify a token.
- **The login description** — the issuer and client id handed to clients, in every connection URL and in the web UI's `/app-config.js`.

Clients sign in against the provider themselves, with standard OIDC: discovery, authorization code with PKCE (web UI), the device flow (CLI and MCP server) and client credentials (applications holding an access URL). The server proxies no login and issues no token.

## The realm contract

What an identity provider's realm, tenant or application must provide for Sovereign Config to work with it. The terms come from two places that a provider cannot change: what the server verifies, and what the clients already deployed do. A provider that cannot meet one is not supported by configuration alone.

**Tokens**

- Access tokens are **JWTs signed with `RS256`**, naming their key by `kid`, with the keys published as a JWK set at an HTTPS URL. Opaque tokens are not supported: nothing is introspected.
- An access token carries `iss`, `aud` (a string or an array containing the server's audience), a non-empty `sub`, and `exp`. `sub` is stable for an identity: the audit trail records access under it.
- An access token carries the scope **`sovereign-config`** in a claim holding the granted scopes as one space-separated string. **An ID token must not carry that claim**: it is how the server tells the two apart when both are signed by the same key for the same audience.
- An access token carries the identity's **grants**: an array of `{"prefix": "<absolute path>", "permissions": ["read" | "write" | "manage", …]}`, as a JSON array or as a string holding one. Every prefix must be a valid path and every permission one of those three; a token with a grant that is not is refused whole.
- An access token may carry a **display name** for the audit trail. For a managed account it is the account's name followed by ` (access URL)`, so an access URL never reads as a person.
- **Access tokens live at most five minutes**; that bounds how long a revocation takes to reach a token already issued. **Refresh tokens live eight hours**, which is what the web UI assumes of a stored session.

**Clients**

Deployed clients ask for these by name and cannot be reconfigured from the server:

- The scopes `openid`, `sovereign-config` and `offline_access` (CLI and MCP server); additionally `profile` and `email` (web UI), and `telemetry:write` where client telemetry is on; `sovereign-config` alone (applications).
- **The issuer handed to clients ends with `/`** and serves discovery at `<issuer>.well-known/openid-configuration`: clients refuse a connection URL whose issuer does not end with `/`, and find discovery by appending to it. It need not be spelled as tokens spell `iss` — the verification rules carry that separately — so a provider whose `iss` has no trailing slash is usable as long as it also answers discovery under the slashed form.
- The discovery document's `token_endpoint`, `authorization_endpoint` and `device_authorization_endpoint` are **on the issuer's own origin**; clients refuse any other.
- The **device authorization grant** for the CLI and MCP server's client, **authorization code with PKCE** for a public web client with the exact callback `<SOVEREIGN_CONFIG_PUBLIC_ORIGIN>/auth/callback`, and **rotating refresh tokens** for both.
- Client ids hold only ASCII letters, digits, `-`, `.`, `_` and `~`: what a connection URL can carry.

**Managed accounts (access URLs)**

- The provider can create a non-expiring service account with one credential, attach a grant to it that reaches its tokens, rename it, replace its credential so that the old one stops working at once, and delete it.
- The account authenticates with the **client-credentials grant**, sending `client_id` and `client_secret` as form fields, and **receives no refresh token**.
- A version-1 connection URL carries the credential as `<account username>:<secret>`, and a client presents the standard base64 of exactly that as `client_secret`. So the secret the provider registers for the account must be the one that string authenticates: for a provider with plain client secrets, the registered secret is that base64 string itself.

`crates/sovereign-config-identity` is the contract in code: the managed-account trait and its conformance suite, the verification rules, and the terms above that the server relies on (`contract`). A provider's crate implements the first, supplies the second, and holds its setup file to the third.

## Configuration grants

Authorization lives in the identity provider: a grant is a permission — `read`, `write` or `manage` — on a path prefix, attached to a user, a service account or a group there, and signed into that identity's access tokens. The server independently evaluates `read`, `write`, or `manage` for every operation against the token's grants; no role or group name is sent to or expanded by the server. The `/` prefix is the global root, and every prefix must be absolute, for example `/apps/example`.

Who may sign in at all is the provider's decision too, and separate from grants. Authentik's blueprints admit only each environment's admins group, the operator group that also grants everything, and its connections group of managed accounts ([Who may sign in](authentik.md#who-may-sign-in)).

After changing grants, a change reaches a principal with its next access token, within five minutes (see [Request authentication](#request-authentication)). Sovereign Config rejects malformed, non-canonical, or unknown grants. It never seeds users or authorization state and PostgreSQL contains no ACL, grant, token, or session records. The one thing it does record is the [audit trail](audit-trail.md), which holds no authorization state: it says what each identity did, never what it may do.

Where grants are assigned in a particular provider is in its chapter ([Authentik](authentik.md#configuration-grants)).

## Request authentication

Every non-operational RPC requires exactly one Bearer token, a JWT access token issued by this environment's provider. Sovereign Config verifies it itself, without calling the provider: it requires an `RS256` JOSE header naming a `kid`, checks the signature against that key in the issuer's JWKS, and requires `exp` (and `nbf`/`iat` when present) to hold within a fixed 30-second allowance for clock skew. It then accepts only the configured environment issuer and audience, the exact `sovereign-config` scope, a non-empty subject, and valid grants, each read from the claim the provider's verification rules name. The scope requirement is also what refuses an ID token, which the realm contract has carry no scope claim. Tokens must never cross environments: each server accepts only its own environment's issuer and audience.

Keys come only from the location the provider's verification rules name — never from a token's `jku`, `x5u` or embedded `jwk` header, and never through a redirect. They are loaded at startup and re-read every ten minutes; a token naming a key not in the cache prompts one re-read, at most once every ten seconds per issuer, with concurrent misses sharing it. A re-read replaces the cached set, so a key the provider stops publishing stops being trusted within ten minutes; a failed re-read keeps the last good set. The JWKS response is bounded to 64 KiB, and one fetch has three seconds. Tokens, claims, subjects, grants and provider URLs are not logged.

A token that is malformed, signed by no published key, outside its validity window, or carrying the wrong claims returns gRPC `UNAUTHENTICATED`. `UNAVAILABLE` means only that a token names a key this server has not cached and cannot fetch: an unreachable provider does not affect tokens whose key is already cached. The server starts and serves while the provider is unreachable, retrying the keys every fifteen seconds; until they load, authenticated calls return `UNAVAILABLE`.

**Revocation takes effect when the token expires, not on the next request.** That is the deliberate price of not waiting on a round-trip to the provider for every call (about 38 ms against Authentik, nearly all of an authenticated RPC's median). Access tokens live five minutes, so that is the longest any of these takes to reach a token already issued: rotating or revoking an access URL, changing a user's or group's grants or group membership, and disabling a user or ending their session at the provider. Each takes effect at once for the *next* token — the old URL or password can mint none, and a new token carries the new grants. It is not a protocol change: requests, responses and status codes are unchanged, and a client refreshes its token exactly as before.

Browser and human CLI sessions: browser access tokens remain only in WASM memory; the rotating refresh credential is held in tab-scoped session storage so a reload can obtain a fresh access token without persisting a long-lived login across browser sessions. Logout, refresh expiry, or refresh rejection clears the browser session. Keep all tokens out of shell history and logs.

## Credential rotation

Request authentication holds no credential: the JWKS is public, so there is nothing to rotate on that path, and no maintenance window. Rotating the provider's signing key is picked up on its own — the first token signed by the new key prompts a JWKS re-read — but tokens signed by the old key stop verifying at the next re-read after the provider stops publishing it. One narrow window remains: if another token naming an unknown key prompted a re-read in the ten seconds before the swap, a genuine token signed by the new key is refused `UNAUTHENTICATED` until those ten seconds pass. The scheduled re-read never opens that window. Swap the signing key when a five-minute burst of re-authentication is acceptable.

The credential the server holds for managing accounts at the provider is the provider's own, and rotating it is in its chapter ([Authentik](authentik.md#what-is-specific-to-authentik-at-run-time)).

## Managed application connections (Access URLs)

A caller holding `manage` on a configuration root can provision a named machine connection — an **access URL**, as the administration UI calls it — and chooses which of `read`, `write`, and `manage` it grants on that root. At least one permission is required, and a caller can grant only permissions it itself holds on the root, so a manage-only operator cannot mint a write-capable URL. Sovereign Config creates a dedicated service account at the identity provider whose only grant is `{"prefix": "<root>", "permissions": [<selected>]}` — for example `["read"]` or `["read","write"]` — and returns one canonical version-1 connection URL carrying the account's one credential. The unchanged CLI accepts that URL on stdin through `profile add`/`profile update` and uses client credentials to operate within the encoded root, and each RPC is authorized against the URL's exact grant: a `read`-only URL can only read; a `write`-capable URL can additionally put and delete values within its root; a `manage`-capable URL can administer access URLs under its root. Value mutation therefore needs `write` (a `manage`-only URL cannot put or delete values), and JSON subtree replacement needs both `write` and `manage`.

The complete URL is a secret and is returned exactly once, by creation and by successful rotation. Sovereign Config stores only non-secret lifecycle metadata — the opaque connection ID, display name, canonical root, selected permission set, the provider's opaque identifiers, and bounded state — and can never re-reveal a URL. A lost URL must be replaced by rotation, which preserves the connection's permissions and invalidates the previous URL immediately: it can obtain no new token. An access token already obtained with it stays valid until it expires, at most five minutes later (see [Request authentication](#request-authentication)); revocation is bounded the same way.

An interrupted rotation is reported as ambiguous: no URL is returned, the connection is marked `rotation_unknown`, and the previous URL is never claimed to be still valid. A further rotation is refused while the earlier attempt could still be in flight, then permitted once that lease expires so the credential can be overwritten with a known fresh value. Revocation deletes the service account and removes the metadata row only after the provider confirms that no credential for it survives; a partial failure stays visible as recoverable state rather than silently orphaning a usable credential.

Each service account's username at the provider embeds a slug of its display name so an operator can recognize it there, with the opaque connection ID appended to guarantee uniqueness even when two connections share a display name. The provider may also add the accounts to a group. That carries no grant, but a provider may admit accounts to the application only through it, as Authentik's blueprints do, so a failure fails the create like any other provisioning step: the account is deleted and no access URL is returned.

The identity the server manages accounts with is isolated from the browser and from request authentication, and is as narrow as the provider allows ([Authentik](authentik.md#what-is-specific-to-authentik-at-run-time)). Browser code reaches only same-origin gRPC-Web; the provider's administration endpoint and credential are absent from every browser response and built asset.
