# Authentik

[Authentik](https://goauthentik.io/) is the identity provider Sovereign Config ships with, selected by `SOVEREIGN_CONFIG_IDENTITY_PROVIDER=authentik` or by leaving that variable unset. This chapter is how an Authentik instance is set up to meet [the realm contract](authentication.md#the-realm-contract): the blueprints that do it, the objects they create, where grants are assigned, and the variables the server reads. What holds for every identity provider — how a request is authenticated, what an access URL is — is in [Authentication and access control](authentication.md).

## How Authentik meets the realm contract

| Contract term | In Authentik |
| --- | --- |
| Signed JWT access tokens, keys published as a JWK set | The application's provider signs with the selected certificate (`RS256`). The server reads the keys from `<issuer>jwks/`, the `jwks_uri` Authentik's discovery document names for a per-provider issuer. |
| Issuer handed to clients ends with `/` and serves discovery | `https://<authentik-host>/application/o/<application>/`, with `issuer_mode: per_provider`. Tokens carry the same string as `iss`. |
| Audience | The provider's client id. Authentik gives a token the id of the client it was minted through as its `aud`, so the web UI's client, the CLI's client and the client access URLs name are all this one. |
| Scope `sovereign-config`, and the scope claim | The environment's grants scope mapping is the `sovereign-config` scope. Authentik writes the space-separated `scope` claim into access tokens only, which is what tells them from ID tokens. |
| Grants claim | `sovereign_config_grants`, an array, emitted by the grants scope mapping from the environment's grant attribute on the user and on every group they belong to. |
| Display name | `preferred_username`, signed by the same mapping so that clients that never request `profile` still carry it; `username` is read as a fallback. A managed account's is its connection's name followed by ` (access URL)`. |
| Device flow, authorization code with PKCE, refresh, client credentials | One public provider per environment permits all four. |
| Token lifetimes | `access_token_validity: minutes=5`, `refresh_token_validity: hours=8`. |
| A managed account's secret | A service account's app password. Authentik accepts the base64 of `<username>:<app password>` as `client_secret` for the application's client, which is exactly what a version-1 connection URL makes a client present. A client-credentials grant returns no refresh token. |
| Managed accounts | Service accounts created, renamed and deleted by the connection-manager identity through Authentik's API, on the issuer's origin. |

`crates/sovereign-config-authentik/tests/blueprints.rs` holds the blueprints to the terms the server relies on, and its conformance suite checks that a credential it returns obtains a token carrying the grant it set.

## Blueprints

The repository ships two isolated Authentik blueprints, one per environment, that create every Authentik object the service relies on:

| Environment | Blueprint | Application and issuer provider | Audience |
| --- | --- | --- | --- |
| Production | `authentik/blueprint.yaml` | `sovereign-config` | `sovereign-config` |
| Development | `authentik/blueprint-dev.yaml` | `sovereign-config-dev` | `sovereign-config-dev` |

Each environment has one public issuing provider shared by the browser, the human CLI and MCP server, and managed application connections. It permits authorization-code, device-code, refresh-token, and client-credentials grants, uses an exact same-origin browser callback through `SOVEREIGN_CONFIG_BROWSER_REDIRECT_URI` or `SOVEREIGN_CONFIG_DEV_BROWSER_REDIRECT_URI`. Tokens must never cross environments: each server accepts only its own environment's issuer and audience. Each blueprint also deletes the confidential `sovereign-config-introspection[-dev]` provider earlier releases introspected tokens through; nothing uses it since access tokens are verified locally (see [Request authentication](authentication.md#request-authentication)). Wildcard and first-use registration are not allowed.

### Who may sign in

Each blueprint binds its application to two groups, with policy engine mode `any`, so a member of either may sign in and nobody else can:

| Order | Group | Who it admits |
| --- | --- | --- |
| 0 | `sovereign-config-admins` / `sovereign-config-dev-admins` | Operators. The environment's admins group, which the blueprint creates and which also grants its members everything ([Configuration grants](#configuration-grants)). It is the only way a person signs in. |
| 1 | `sovereign-config-connections` / `sovereign-config-dev-connections` | Managed accounts, which the server adds to the group named by `SOVEREIGN_CONFIG_MANAGER_GROUP` when it creates an access URL. |

Both bindings are enabled, not negated, with a 30-second timeout and a failure result of "deny". The blueprint creates both groups before binding them, so every reference resolves. A binding is identified by its application and group, so applying a blueprint to an instance that already holds these bindings, with these values, changes nothing. What a principal may do is still only its grants claim: the admins group admits its members and grants them everything through its grant attribute; the connections group admits its members and grants nothing, each managed account carrying only its own grant. Being admitted is what lets a credential obtain a token at all, which is why the server fails a create whose account it cannot add to the connections group.

A managed account can also complete the browser sign-in, as well as the client-credentials grant its access URL uses, if the instance's password stage accepts app passwords (`authentik.core.auth.TokenBackend` among its backends, as in the reference deployment). That admits it to the web UI with nothing more than its own grant.

Both blueprints own the authenticated `sovereign-config-device-code` Stage Configuration flow and assign it to the exact brand selected by `AUTHENTIK_BRAND_DOMAIN` or `AUTHENTIK_DEV_BRAND_DOMAIN`. Supply the domain of the brand active for the Authentik public hostname; do not point this at a different tenant or create a second active brand accidentally. An environment's blueprint is applied before that environment's server starts, by its `migrate` (below), and `migrate` refuses to apply one environment's blueprint to the other's deployment.

Authentik 2026.5.2 or newer is required. That version includes configurable grant allowlists along with the device-authorization scope clipping fix needed by this design. `migrate` checks the instance's version, and that its API has every surface the connection manager calls, before it applies anything.

The issuing providers use the selected Authentik signing certificate, five-minute access tokens, and rotating refresh tokens bounded to eight hours. Browser and human CLI clients request `openid sovereign-config offline_access`. Browser access tokens remain only in WASM memory; the rotating refresh credential is held in tab-scoped session storage so a reload can obtain a fresh access token without persisting a long-lived login across browser sessions. Logout, refresh expiry, or refresh rejection clears the browser session. Use authorization code with PKCE or device flow and keep all tokens out of shell history and logs.

## Applying a blueprint

`sovereign-config-server migrate` applies the blueprint, as the last of its steps (#615; [the README](../README.md#4-configure-and-start)). Both blueprints are compiled into the image, so the one a release applies is the one it was built with, and nothing outside the image keeps a copy. With `SOVEREIGN_CONFIG_AUTHENTIK_BLUEPRINT` set to `production` or `development`, `migrate`:

1. reads the Authentik version and refuses to apply anything older than 2026.5.2, or an API schema missing a surface the connection manager calls;
2. fills the blueprint's placeholders from its own settings (below);
3. creates the managed blueprint instance `sovereign-config` (production) or `sovereign-config-dev` (development) the first time, and replaces its content after that, then asks Authentik to apply it and waits up to five minutes for the outcome. `successful` and `warning` pass, `error` and `orphaned` fail `migrate`, and the deploy with it.

Re-applying an unchanged blueprint changes nothing, so this runs on every deploy. An older release's `migrate` re-applies its own blueprint, which resets the fields that blueprint sets and deletes nothing it does not name. The issuer must name the blueprint's own application (`/application/o/sovereign-config/` or `/application/o/sovereign-config-dev/`), so a deployment cannot apply the other environment's blueprint.

`migrate` needs an Authentik API token allowed to manage blueprints, `SOVEREIGN_CONFIG_AUTHENTIK_ADMIN_TOKEN` (or `_FILE`). It is the only container given one. The server holds only the connection manager's token.

To apply a blueprint yourself instead, leave `SOVEREIGN_CONFIG_AUTHENTIK_BLUEPRINT` unset, and `migrate` leaves Authentik alone. Authentik's own blueprint import does not expand the `${VARIABLE}` placeholders, so substitute them before importing (for example with `envsubst`). An unsubstituted file imports the literal placeholder text as the browser redirect URI and as the manager token's key. `migrate` fills them like this:

| Production variable | Development variable | Value |
| --- | --- | --- |
| `SOVEREIGN_CONFIG_BROWSER_REDIRECT_URI` | `SOVEREIGN_CONFIG_DEV_BROWSER_REDIRECT_URI` | The web UI's exact callback: `<SOVEREIGN_CONFIG_PUBLIC_ORIGIN>/auth/callback`. |
| `AUTHENTIK_BRAND_DOMAIN` | `AUTHENTIK_DEV_BRAND_DOMAIN` | The domain of the brand active for the Authentik public hostname: `migrate` takes the issuer's host. |
| `AUTHENTIK_SOVEREIGN_CONFIG_MANAGER_API_TOKEN` | `AUTHENTIK_SOVEREIGN_CONFIG_DEV_MANAGER_API_TOKEN` | The connection-manager API token's key. The same value is given to the server as its manager API token (see [the README](../README.md#configuration-reference)). Generate it once, store it as a secret, and reuse it on every apply. |

The issuer the server is configured with (`SOVEREIGN_CONFIG_OIDC_ISSUER`) is the provider's per-application issuer, `https://<authentik-host>/application/o/<application>/`, and the audience (`SOVEREIGN_CONFIG_OIDC_AUDIENCE`) is the provider's client id — `sovereign-config` or `sovereign-config-dev`. Access URLs name the same client, through which their service accounts authenticate. `SOVEREIGN_CONFIG_MANAGER_CLIENT_ID` names that client separately and defaults to the audience. With Authentik it must equal the audience, and the server refuses to start otherwise, because a token minted through another client would carry that client's id as its `aud`.

## Server variables

Authentik's own variables, which `sovereign-config-authentik` reads and validates at startup. An invalid one fails startup by name, quoting no value.

| Variable | Required | Purpose |
| --- | :---: | --- |
| `SOVEREIGN_CONFIG_OIDC_ISSUER` | ✅ | The provider's per-application issuer, `https://<authentik-host>/application/o/<application>/`, in canonical form. The Authentik administration origin is derived from it, so the API and issuer origins can never diverge. |
| `SOVEREIGN_CONFIG_OIDC_AUDIENCE` | ✅ | The `aud` every access token must carry: the provider's client id, `sovereign-config` or `sovereign-config-dev`. It is also the client id the web UI signs in through and the one access URLs name, so it may hold only ASCII letters, digits, `-`, `.`, `_` and `~`. |
| `SOVEREIGN_CONFIG_MANAGER_API_TOKEN` / `_FILE` | ✅ | The connection-manager API token. |
| `SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE` | ✅ | The user and group attribute that carries this environment's grants, matching the blueprint's scope mapping (`sovereign_config_prod_grants` or `sovereign_config_dev_grants`). |
| `SOVEREIGN_CONFIG_MANAGER_GROUP` | ✅ | The group each access URL's service account is added to. It carries no grant, but it gates sign-in ([Who may sign in](#who-may-sign-in)), so a create whose account cannot be added to it fails. It must match the blueprint (`sovereign-config-connections` or `sovereign-config-dev-connections`). |
| `SOVEREIGN_CONFIG_MANAGER_CLIENT_ID` | — | The OAuth client id every access URL names. Unset means the audience. With Authentik it must equal the audience, because a token minted through another client would carry that client's id as its `aud` and be refused; any other value fails startup. Leave it unset. |

`migrate` reads these as well, when a blueprint is selected ([Applying a blueprint](#applying-a-blueprint)):

| Variable | Required | Purpose |
| --- | :---: | --- |
| `SOVEREIGN_CONFIG_AUTHENTIK_BLUEPRINT` | — | `production` or `development`. Unset, `migrate` applies no blueprint and needs none of the rest. |
| `SOVEREIGN_CONFIG_AUTHENTIK_ADMIN_TOKEN` / `_FILE` | with a blueprint | An Authentik API token allowed to manage blueprints and read the version and schema. Never given to the server. |
| `SOVEREIGN_CONFIG_OIDC_ISSUER` | with a blueprint | As above. It must name the blueprint's application. |
| `SOVEREIGN_CONFIG_PUBLIC_ORIGIN` | with a blueprint | The origin the web UI's redirect URI is built from. |
| `SOVEREIGN_CONFIG_MANAGER_API_TOKEN` / `_FILE` | with a blueprint | The key the blueprint gives the connection manager's token. |

## Authentik objects by environment

Every Authentik object this application relies on is created by that environment's blueprint, and **the two environments share nothing that carries authorization**. Each name below exists in exactly one environment; a principal added to a production object has no development access and vice versa. The only objects both blueprints own are the `sovereign-config-device-code` flow and the brand assignment that references it, which are identical in each and carry no permissions.

Nothing here is created by Sovereign Config itself except the per-connection service accounts noted at the end of each table — the server never seeds users, groups, roles, or authorization state. Each application admits only its own environment's admins and connections groups, so a person signs in to an environment only through that environment's admins group.

### Production — `authentik/blueprint.yaml`

| Object | Authentik kind | Purpose | Confers permission? |
| --- | --- | --- | --- |
| `sovereign-config-admins` | Group | The operator group (named `sovereign-config-production-config-contributor` before 2.59). Carries the attribute `sovereign_config_prod_grants` set to `[{prefix: "/", permissions: [read, write, manage]}]`, so its members hold every permission on the whole production tree, and the application's order-0 binding admits its members to sign in. **Add human operators here.** | Yes — through its grant attribute, not through the group name; also gates sign-in |
| `sovereign-config-connections` | Group | Every managed access-URL service account Sovereign Config provisions is added here. Carries no roles and no attributes, but the application admits managed accounts only through it, so a create whose account cannot be added fails and the account is deleted. Named by `SOVEREIGN_CONFIG_MANAGER_GROUP`. | No grant; gates sign-in |
| `sovereign-config-admins` → `sovereign-config`, order 0 | Policy binding | Admits members of `sovereign-config-admins` (operators) to the application. | Gates sign-in |
| `sovereign-config-connections` → `sovereign-config`, order 1 | Policy binding | Admits members of `sovereign-config-connections` (managed accounts) to the application. | Gates sign-in |
| `sovereign-config-connection-manager` | Group | Binds the RBAC role of the same name to the connection-manager service account, which is its only member. Not for human membership. | Yes — Authentik RBAC, via its role |
| `sovereign-config-connection-manager` | RBAC role | Global `authentik_core.add_user`, `add_token`, `view_token`, and `view_group` — metadata only. `view_token_key` is deliberately never granted, so no token key is ever readable, and the role is not a superuser and has no Admin UI access. | Yes — global, narrow |
| `sovereign-config-connection-manager-objects` | Initial-permissions policy | Attaches object-level `view_user`, `change_user`, `delete_user`, `view_token`, and `set_token_key` to the role above **for the objects it creates only**, so it cannot read, change, or delete an unrelated user or token. | Yes — per object created |
| `sovereign-config-connection-manager` | Service account (user) | The connection-manager identity, in `goauthentik.io/service-accounts`, a member of the manager group above. Isolated from the browser and from request authentication, which needs no credential. | Through its group |
| `sovereign-config-connection-manager-api` | Token (`intent: api`, non-expiring) | The API token that identity authenticates with. Supplied to the server as `MANAGER_API_TOKEN_FILE` / `SOVEREIGN_CONFIG_MANAGER_API_TOKEN`. | Acts as the service account |
| `sovereign_config_prod_grants` | User/group attribute | The direct grant attribute for this environment, named to the server by `SOVEREIGN_CONFIG_MANAGER_GRANTS_ATTRIBUTE`. Set it on a user, a service account, or any group for access narrower than the admins group. | Yes — this is where production authorization actually lives |
| `sovereign-config production grants` | OAuth2 scope mapping (scope `sovereign-config`) | Reads `sovereign_config_prod_grants` from the requesting user **and every group they belong to**, deduplicates, and emits the common `sovereign_config_grants` claim. | Emits the claim the server evaluates |
| `sovereign-config production telemetry` | OAuth2 scope mapping (scope `telemetry:write`) | Adds no claim; being granted the scope is what the client-telemetry ingest requires. Only the web UI requests it. | Only to send web UI telemetry |
| `<display-name-slug>-<connection-id>` | Service accounts (created at runtime) | One per managed access URL, created by the connection manager, granted exactly `{"prefix": "<root>", "permissions": [...]}` in `sovereign_config_prod_grants`, and added to `sovereign-config-connections`. | Yes — exactly the grant it was minted with |

### Development — `authentik/blueprint-dev.yaml`

| Object | Authentik kind | Purpose | Confers permission? |
| --- | --- | --- | --- |
| `sovereign-config-dev-admins` | Group | The development operator group (named `sovereign-config-development-config-contributor` before 2.59). Carries `sovereign_config_dev_grants` set to `[{prefix: "/", permissions: [read, write, manage]}]`, and the development application's order-0 binding admits its members to sign in. | Yes — through its grant attribute; also gates sign-in |
| `sovereign-config-dev-connections` | Group | Every development managed access-URL service account is added here. No roles, no attributes; the application admits managed accounts only through it. Named by `SOVEREIGN_CONFIG_MANAGER_GROUP` in the development deployment. | No grant; gates sign-in |
| `sovereign-config-dev-admins` → `sovereign-config-dev`, order 0 | Policy binding | Admits members of `sovereign-config-dev-admins` (development operators) to the development application. | Gates sign-in |
| `sovereign-config-dev-connections` → `sovereign-config-dev`, order 1 | Policy binding | Admits development managed accounts to the development application. | Gates sign-in |
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

Note that the production connection-manager objects carry **no** environment word in their names (`sovereign-config-connection-manager`, `sovereign-config-connections`) while their development counterparts are infixed with `-dev-`; the admins groups follow the same pattern (`sovereign-config-admins`, `sovereign-config-dev-admins`). Read the name, not the pattern.

## Configuration grants

Each blueprint creates an environment-specific admins group, the operator group, that bundles global `read`, `write`, and `manage` grants — `sovereign-config-admins` against `sovereign_config_prod_grants`, and `sovereign-config-dev-admins` against `sovereign_config_dev_grants`. It is also the application's sign-in gate for people ([Who may sign in](#who-may-sign-in)): a person outside it cannot sign in to that environment at all, whatever grants they hold elsewhere.

Add a user or service account only to the admins groups required for that environment. Beyond admitting its members to sign in, group membership is not a Sovereign Config role: the environment's scope mapping emits the existing granular `sovereign_config_grants` claim, and the server independently evaluates `read`, `write`, or `manage` for every operation. No group name is sent to or expanded by the server.

For narrower access, place grants in the environment-specific direct grant attribute on a user, service account, or another group. For example, this development-only attribute permits reading one subtree without write or manage:

```yaml
sovereign_config_dev_grants:
  - prefix: /apps/example
    permissions:
      - read
```

Use `sovereign_config_prod_grants` for the equivalent production assignment. The `/` prefix is the global root. Every direct grant prefix must be absolute, for example `/apps/example`; after changing grants, obtain a new access token — a change reaches a principal with its next token, within five minutes (see [Request authentication](authentication.md#request-authentication)). Each environment's `sovereign-config` scope mapping combines and deduplicates only its own direct and group grants before emitting the common granular claim, so the same principal can have different development and production permissions. Sovereign Config rejects malformed, non-canonical, or unknown grants. It never seeds users or authorization state and PostgreSQL contains no ACL, grant, token, or session records. The one thing it does record is the [audit trail](audit-trail.md), which holds no authorization state: it says what each identity did, never what it may do.

When upgrading from the shared `sovereign-config grants` scope mapping, apply both environment blueprints before deleting that legacy mapping manually. Neither blueprint deletes it because development and production can be migrated at different times.

## What is specific to Authentik at run time

- **Signing-key rotation.** Rotating the provider's signing certificate in Authentik is picked up as [Credential rotation](authentication.md#credential-rotation) describes; nothing is configured on the server.
- **The connection-manager API token.** To rotate it, change the `MANAGER_API_TOKEN_FILE` contents and redeploy with `--force-recreate` (Compose does not recreate a container when only a secret file changes): `migrate` sets the new key in Authentik, then the server starts with it. Only managed-connection operations are affected while the two disagree; configuration reads and writes do not use it. Verify by listing managed connections after redeployment.
- **Revoking an access URL.** Revocation deletes the service account and removes the connection only after deletion is confirmed by the app password's absence: Authentik denies at the permission layer before object lookup once the manager holds no remaining visible account, so "gone" and "not permitted" cannot be told apart on the user object itself.
- **The connection manager's reach.** It holds global `add_user`, `add_token`, `view_token`, and `view_group` — no key or user content is exposed by any of these, only metadata needed to discover and label an account it created — plus object-level `view`/`change`/`delete` on the users and `set_key` on the tokens it creates. It is not a superuser, cannot view any token key, and cannot touch unrelated Authentik objects.
- **Account names.** Each service account's Authentik username embeds a slug of its connection's display name, with the opaque connection ID appended, and the account is added to the `SOVEREIGN_CONFIG_MANAGER_GROUP` group, which admits it to sign in ([Who may sign in](#who-may-sign-in)). That step is required: if it fails, the create fails as any other provisioning step's failure does and the account is deleted, rather than returning an access URL that cannot obtain a token.
