# Authentication and access control

Sovereign Config delegates identity to [Authentik](https://goauthentik.io/). Every request carries an OIDC access token issued by an Authentik provider, the server verifies it locally against the provider's published keys, and authorization comes from grants signed into that token. The server holds no users, passwords, roles or sessions of its own. This document covers setting up Authentik, granting access, how requests are authenticated, credential rotation, and managed application connections (access URLs).

## Blueprints

The repository ships two isolated Authentik blueprints, one per environment, that create every Authentik object the service relies on:

| Environment | Blueprint | Application and issuer provider | Audience |
| --- | --- | --- | --- |
| Production | `authentik/blueprint.yaml` | `sovereign-config` | `sovereign-config` |
| Development | `authentik/blueprint-dev.yaml` | `sovereign-config-dev` | `sovereign-config-dev` |

Each environment has one public issuing provider shared by the browser, the human CLI and MCP server, and managed application connections. It permits authorization-code, device-code, refresh-token, and client-credentials grants, uses an exact same-origin browser callback through `SOVEREIGN_CONFIG_BROWSER_REDIRECT_URI` or `SOVEREIGN_CONFIG_DEV_BROWSER_REDIRECT_URI`. Tokens must never cross environments: each server accepts only its own environment's issuer and audience. Each blueprint also deletes the confidential `sovereign-config-introspection[-dev]` provider earlier releases introspected tokens through; nothing uses it since access tokens are verified locally (see [Request authentication](#request-authentication)). Wildcard and first-use registration are not allowed.

Both blueprints own the authenticated `sovereign-config-device-code` Stage Configuration flow and assign it to the exact brand selected by `AUTHENTIK_BRAND_DOMAIN` or `AUTHENTIK_DEV_BRAND_DOMAIN`. Supply the domain of the brand active for the Authentik public hostname; do not point this at a different tenant or create a second active brand accidentally. Apply an environment's blueprint before starting that environment's server, and never apply one environment's blueprint to the other's deployment.

Authentik 2026.5.2 or newer is required. That version includes configurable grant allowlists along with the device-authorization scope clipping fix needed by this design. Check the instance's version before applying a blueprint.

The issuing providers use the selected Authentik signing certificate, five-minute access tokens, and rotating refresh tokens bounded to eight hours. Browser and human CLI clients request `openid sovereign-config offline_access`. Browser access tokens remain only in WASM memory; the rotating refresh credential is held in tab-scoped session storage so a reload can obtain a fresh access token without persisting a long-lived login across browser sessions. Logout, refresh expiry, or refresh rejection clears the browser session. Use authorization code with PKCE or device flow and keep all tokens out of shell history and logs.

## Applying a blueprint

The blueprints carry `${VARIABLE}` placeholders, which Authentik's own blueprint import does not expand. Substitute them before importing (for example with `envsubst`, or a tool that does it for you, as the project's own pipeline does with `woodpecker-plugin-authentik-blueprint`). An unsubstituted file imports the literal placeholder text as the browser redirect URI and as the manager token's key:

| Production variable | Development variable | Value |
| --- | --- | --- |
| `SOVEREIGN_CONFIG_BROWSER_REDIRECT_URI` | `SOVEREIGN_CONFIG_DEV_BROWSER_REDIRECT_URI` | The web UI's exact callback: `<SOVEREIGN_CONFIG_PUBLIC_ORIGIN>/auth/callback`. |
| `AUTHENTIK_BRAND_DOMAIN` | `AUTHENTIK_DEV_BRAND_DOMAIN` | The domain of the brand active for the Authentik public hostname. |
| `AUTHENTIK_SOVEREIGN_CONFIG_MANAGER_API_TOKEN` | `AUTHENTIK_SOVEREIGN_CONFIG_DEV_MANAGER_API_TOKEN` | The connection-manager API token's key. The same value is given to the server as its manager API token (see [the README](../README.md#configuration-reference)). Generate it once, store it as a secret, and reuse it on every apply. |

The issuer the server is configured with (`SOVEREIGN_CONFIG_OIDC_ISSUER`) is the provider's per-application issuer, `https://<authentik-host>/application/o/<application>/`, and the audience (`SOVEREIGN_CONFIG_OIDC_AUDIENCE`) is the provider's client id — `sovereign-config` or `sovereign-config-dev`. Access URLs name the same client, through which their service accounts authenticate. `SOVEREIGN_CONFIG_MANAGER_CLIENT_ID` names that client separately and defaults to the audience. With Authentik it must equal the audience, and the server refuses to start otherwise, because a token minted through another client would carry that client's id as its `aud`.

## Authentik objects by environment

Every Authentik object this application relies on is created by that environment's blueprint, and **the two environments share nothing that carries authorization**. Each name below exists in exactly one environment; a principal added to a production object has no development access and vice versa. The only objects both blueprints own are the `sovereign-config-device-code` flow and the brand assignment that references it, which are identical in each and carry no permissions.

Nothing here is created by Sovereign Config itself except the per-connection service accounts noted at the end of each table — the server never seeds users, groups, roles, or authorization state.

### Production — `authentik/blueprint.yaml`

| Object | Authentik kind | Purpose | Confers permission? |
| --- | --- | --- | --- |
| `sovereign-config-production-config-contributor` | Group | The contributor group. Carries the attribute `sovereign_config_prod_grants` set to `[{prefix: "/", permissions: [read, write, manage]}]`, so its members hold every permission on the whole production tree. **Add human operators here.** | Yes — through its grant attribute, not through the group name |
| `sovereign-config-connections` | Group | Organizational only. Every managed access-URL service account Sovereign Config provisions is added here so an operator can browse them together in Authentik. Carries no roles and no attributes. Named by `SOVEREIGN_CONFIG_MANAGER_GROUP`; membership failure is best-effort and never blocks a connection. | No — deliberately none |
| `sovereign-config-connection-manager` | Group | Binds the RBAC role of the same name to the connection-manager service account, which is its only member. Not for human membership. | Yes — Authentik RBAC, via its role |
| `sovereign-config-connection-manager` | RBAC role | Global `authentik_core.add_user`, `add_token`, `view_token`, and `view_group` — metadata only. `view_token_key` is deliberately never granted, so no token key is ever readable, and the role is not a superuser and has no Admin UI access. | Yes — global, narrow |
| `sovereign-config-connection-manager-objects` | Initial-permissions policy | Attaches object-level `view_user`, `change_user`, `delete_user`, `view_token`, and `set_token_key` to the role above **for the objects it creates only**, so it cannot read, change, or delete an unrelated user or token. | Yes — per object created |
| `sovereign-config-connection-manager` | Service account (user) | The connection-manager identity, in `goauthentik.io/service-accounts`, a member of the manager group above. Isolated from the browser and from request authentication, which needs no credential. | Through its group |
| `sovereign-config-connection-manager-api` | Token (`intent: api`, non-expiring) | The API token that identity authenticates with. Supplied to the server as `MANAGER_API_TOKEN_FILE` / `SOVEREIGN_CONFIG_MANAGER_API_TOKEN`. | Acts as the service account |
| `sovereign_config_prod_grants` | User/group attribute | The direct grant attribute for this environment, named to the server by `SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE`. Set it on a user, a service account, or any group for access narrower than the contributor group. | Yes — this is where production authorization actually lives |
| `sovereign-config production grants` | OAuth2 scope mapping (scope `sovereign-config`) | Reads `sovereign_config_prod_grants` from the requesting user **and every group they belong to**, deduplicates, and emits the common `sovereign_config_grants` claim. | Emits the claim the server evaluates |
| `sovereign-config production telemetry` | OAuth2 scope mapping (scope `telemetry:write`) | Adds no claim; being granted the scope is what the client-telemetry ingest requires. Only the web UI requests it. | Only to send web UI telemetry |
| `<display-name-slug>-<connection-id>` | Service accounts (created at runtime) | One per managed access URL, created by the connection manager, granted exactly `{"prefix": "<root>", "permissions": [...]}` in `sovereign_config_prod_grants`, and added to `sovereign-config-connections`. | Yes — exactly the grant it was minted with |

### Development — `authentik/blueprint-dev.yaml`

| Object | Authentik kind | Purpose | Confers permission? |
| --- | --- | --- | --- |
| `sovereign-config-development-config-contributor` | Group | The development contributor group. Carries `sovereign_config_dev_grants` set to `[{prefix: "/", permissions: [read, write, manage]}]`. | Yes — through its grant attribute |
| `sovereign-config-dev-connections` | Group | Browsing group for development managed access-URL service accounts. No roles, no attributes. Named by `SOVEREIGN_CONFIG_MANAGER_GROUP` in the development deployment. | No — deliberately none |
| `sovereign-config-dev-connection-manager` | Group | Binds the development RBAC role to the development connection-manager service account, its only member. | Yes — Authentik RBAC, via its role |
| `sovereign-config-dev-connection-manager` | RBAC role | Same narrow global permissions as production: `add_user`, `add_token`, `view_token`, `view_group`. No `view_token_key`, not a superuser. | Yes — global, narrow |
| `sovereign-config-dev-connection-manager-objects` | Initial-permissions policy | Same per-object `view`/`change`/`delete_user`, `view_token`, `set_token_key` attachment as production. | Yes — per object created |
| `sovereign-config-dev-connection-manager` | Service account (user) | The development connection-manager identity. | Through its group |
| `sovereign-config-dev-connection-manager-api` | Token (`intent: api`, non-expiring) | Its API token, supplied to the development deployment as `MANAGER_API_TOKEN_FILE` / `SOVEREIGN_CONFIG_MANAGER_API_TOKEN`. | Acts as the service account |
| `sovereign_config_dev_grants` | User/group attribute | The development direct grant attribute, named by `SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE`. | Yes — this is where development authorization lives |
| `sovereign-config development grants` | OAuth2 scope mapping (scope `sovereign-config`) | Reads `sovereign_config_dev_grants` from the user and their groups and emits the same `sovereign_config_grants` claim. | Emits the claim the server evaluates |
| `sovereign-config development telemetry` | OAuth2 scope mapping (scope `telemetry:write`) | As in production, for the development ingest. | Only to send web UI telemetry |
| `<display-name-slug>-<connection-id>` | Service accounts (created at runtime) | One per development managed access URL, granted in `sovereign_config_dev_grants` and added to `sovereign-config-dev-connections`. | Yes — exactly the grant it was minted with |

The environment-specific names the server must be told about are exactly two, and both must match the blueprint that was applied to the same Authentik instance:

| Deployment variable | Production | Development |
| --- | --- | --- |
| `SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE` | `sovereign_config_prod_grants` | `sovereign_config_dev_grants` |
| `SOVEREIGN_CONFIG_MANAGER_GROUP` | `sovereign-config-connections` | `sovereign-config-dev-connections` |

Note that the production connection-manager objects carry **no** environment word in their names (`sovereign-config-connection-manager`, `sovereign-config-connections`) while their development counterparts are infixed with `-dev-`, whereas the contributor groups spell both environments out in full (`-production-` / `-development-`). Read the name, not the pattern.

## Configuration grants

Each blueprint creates an environment-specific contributor group that bundles global `read`, `write`, and `manage` grants — `sovereign-config-production-config-contributor` against `sovereign_config_prod_grants`, and `sovereign-config-development-config-contributor` against `sovereign_config_dev_grants`.

Add a user or service account only to the contributor groups required for that environment. Group membership is an Authentik administration convenience, not a Sovereign Config role: the environment's scope mapping emits the existing granular `sovereign_config_grants` claim, and the server independently evaluates `read`, `write`, or `manage` for every operation. No contributor role name is sent to or expanded by the server.

For narrower access, place grants in the environment-specific direct grant attribute on a user, service account, or another group. For example, this development-only attribute permits reading one subtree without write or manage:

```yaml
sovereign_config_dev_grants:
  - prefix: /apps/example
    permissions:
      - read
```

Use `sovereign_config_prod_grants` for the equivalent production assignment. The `/` prefix is the global root. Every direct grant prefix must be absolute, for example `/apps/example`; after changing grants, obtain a new access token — a change reaches a principal with its next token, within five minutes (see [Request authentication](#request-authentication)). Each environment's `sovereign-config` scope mapping combines and deduplicates only its own direct and group grants before emitting the common granular claim, so the same principal can have different development and production permissions. Sovereign Config rejects malformed, non-canonical, or unknown grants. It never seeds users or authorization state and PostgreSQL contains no ACL, grant, token, or session records. The one thing it does record is the [audit trail](audit-trail.md), which holds no authorization state: it says what each identity did, never what it may do.

When upgrading from the shared `sovereign-config grants` scope mapping, apply both environment blueprints before deleting that legacy mapping manually. Neither blueprint deletes it because development and production can be migrated at different times.

## Request authentication

Every non-operational RPC requires exactly one Bearer token, a JWT access token issued by this environment's provider. Sovereign Config verifies it itself, without calling Authentik: it requires an `RS256` JOSE header naming a `kid`, checks the signature against that key in the issuer's JWKS, and requires `exp` (and `nbf`/`iat` when present) to hold within a fixed 30-second allowance for clock skew. It then accepts only the configured environment issuer and audience, the exact `sovereign-config` scope, a non-empty subject, and valid `sovereign_config_grants` — the same claims introspection used to return, since Authentik signs them into the access token. The `scope` requirement is also what refuses an ID token: Authentik signs ID tokens with the same key, issuer, audience and grants, but adds `scope` only to access tokens.

Keys come only from `<SOVEREIGN_CONFIG_OIDC_ISSUER>jwks/`, the `jwks_uri` Authentik's discovery document names for a per-provider issuer — never from a token's `jku`, `x5u` or embedded `jwk` header, and never through a redirect. They are loaded at startup and re-read every ten minutes; a token naming a key not in the cache prompts one re-read, at most once every ten seconds per issuer, with concurrent misses sharing it. A re-read replaces the cached set, so a key Authentik stops publishing stops being trusted within ten minutes; a failed re-read keeps the last good set. The JWKS response is bounded to 64 KiB, and one fetch has three seconds. Tokens, claims, subjects, grants and provider URLs are not logged.

A token that is malformed, signed by no published key, outside its validity window, or carrying the wrong claims returns gRPC `UNAUTHENTICATED`. `UNAVAILABLE` means only that a token names a key this server has not cached and cannot fetch: an unreachable Authentik does not affect tokens whose key is already cached. The server starts and serves while Authentik is unreachable, retrying the keys every fifteen seconds; until they load, authenticated calls return `UNAVAILABLE`.

**Revocation takes effect when the token expires, not on the next request.** That is the deliberate price of not waiting on an Authentik round-trip for every call (about 38 ms, nearly all of an authenticated RPC's median). Access tokens live five minutes, so that is the longest any of these takes to reach a token already issued: rotating or revoking an access URL, changing a user's or group's grants or group membership, and disabling a user or ending their session in Authentik. Each takes effect at once for the *next* token — the old URL or password can mint none, and a new token carries the new grants. It is not a protocol change: requests, responses and status codes are unchanged, and a client refreshes its token exactly as before.

## Credential rotation

Request authentication holds no credential: the JWKS is public, so there is nothing to rotate on that path, and no maintenance window. Rotating the provider's signing key in Authentik is picked up on its own — the first token signed by the new key prompts a JWKS re-read — but tokens signed by the old key stop verifying at the next re-read after Authentik stops publishing it. One narrow window remains: if another token naming an unknown key prompted a re-read in the ten seconds before the swap, a genuine token signed by the new key is refused `UNAUTHENTICATED` until those ten seconds pass. The scheduled re-read never opens that window. Swap the signing key when a five-minute burst of re-authentication is acceptable.

Rotating the connection-manager API token: update the environment's blueprint secret and the `MANAGER_API_TOKEN_FILE` contents together, apply the blueprint, then redeploy. Only managed-connection operations are affected while the two disagree; configuration reads and writes do not use it. Verify by listing managed connections after redeployment.

## Managed application connections (Access URLs)

A caller holding `manage` on a configuration root can provision a named machine connection — an **access URL**, as the administration UI calls it — and chooses which of `read`, `write`, and `manage` it grants on that root. At least one permission is required, and a caller can grant only permissions it itself holds on the root, so a manage-only operator cannot mint a write-capable URL. Sovereign Config creates a dedicated Authentik service account whose only grant is `{"prefix": "<root>", "permissions": [<selected>]}` — for example `["read"]` or `["read","write"]` — discovers its single non-expiring app password, and returns one canonical version-1 connection URL. The unchanged CLI accepts that URL on stdin through `profile add`/`profile update` and uses client credentials to operate within the encoded root, and each RPC is authorized against the URL's exact grant: a `read`-only URL can only read; a `write`-capable URL can additionally put and delete values within its root; a `manage`-capable URL can administer access URLs under its root. Value mutation therefore needs `write` (a `manage`-only URL cannot put or delete values), and JSON subtree replacement needs both `write` and `manage`.

The complete URL is a secret and is returned exactly once, by creation and by successful rotation. Sovereign Config stores only non-secret lifecycle metadata — the opaque connection ID, display name, canonical root, selected permission set, opaque Authentik identifiers, and bounded state — and can never re-reveal a URL. A lost URL must be replaced by rotation, which preserves the connection's permissions and invalidates the previous URL immediately: it can obtain no new token. An access token already obtained with it stays valid until it expires, at most five minutes later (see [Request authentication](#request-authentication)); revocation is bounded the same way.

An interrupted rotation is reported as ambiguous: no URL is returned, the connection is marked `rotation_unknown`, and the previous URL is never claimed to be still valid. A further rotation is refused while the earlier attempt could still be in flight, then permitted once that lease expires so the credential can be overwritten with a known fresh value. Revocation deletes the Authentik service account and removes the metadata row only after deletion is confirmed by the app password's absence, since Authentik denies at the permission layer before object lookup once the manager holds no remaining visible account, so "gone" and "not permitted" cannot be told apart on the user object itself; a partial failure stays visible as recoverable state rather than silently orphaning a usable credential.

Each service account's Authentik username embeds a slug of its display name so an operator can recognize it directly in Authentik, with the opaque connection ID appended to guarantee uniqueness even when two connections share a display name. It is also added to the configured `SOVEREIGN_CONFIG_MANAGER_GROUP` group purely for browsing; group membership carries no permissions, and its failure is best-effort and never blocks or rolls back a connection.

The connection-manager identity is isolated from the browser and from request authentication. It holds global `add_user`, `add_token`, `view_token`, and `view_group` — no key or user content is exposed by any of these, only metadata needed to discover and label an account it created — plus object-level `view`/`change`/`delete` on the users and `set_key` on the tokens it creates. It is not a superuser, cannot view any token key, and cannot touch unrelated Authentik objects. Browser code reaches only same-origin gRPC-Web; the Authentik administration endpoint and token are absent from every browser response and built asset.
