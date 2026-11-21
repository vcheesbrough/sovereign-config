# Calling v6 with curl

Protocol `v6` is served over the [Connect protocol](https://connectrpc.com/docs/protocol). Every operation is a plain HTTP `POST` with a JSON body, so any HTTP client can call it without generated code. This page covers what a hand-written client needs. The schema is [`proto/sovereign/config/v6/service.proto`](../proto/sovereign/config/v6/service.proto), and the rules behind it are in [Protocol versioning](protocol-versioning.md).

## A call

```sh
curl -sS https://config.example.com/sovereign.config.v6.Configuration/GetSubTree \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"path": "/apps/api"}'
```

```json
{"values":[{"path":"/apps/api/api_key","maskedSecret":{},"classification":"VALUE_CLASSIFICATION_SECRET"},{"path":"/apps/api/log_level","plainValue":"debug","classification":"VALUE_CLASSIFICATION_PLAIN"}]}
```

- **The route** is `/sovereign.config.v6.<Service>/<Method>`, with the service and method named as in the `.proto` file.
- **The method** is always `POST`. Nothing travels in the URL: paths, values and tokens go in the body or in headers.
- **`Content-Type`** must be `application/json` (or `application/proto` for the binary encoding). `curl -d` sends `application/x-www-form-urlencoded` unless told otherwise. That request gets a 400 with a JSON error saying how to call.
- **The token** is an access token from the identity provider ([Authentication](authentication.md)). `System.GetVersion` and the handshake need none.
- **A deadline** may be sent as `Connect-Timeout-Ms: <milliseconds>`. A call that outlives it fails `deadline_exceeded`.
- **The size limit** is 4 MiB per request body. Over it, the answer is `resource_exhausted`.
- **HTTP/1.1 is enough.** No HTTP/2, no h2c and no gRPC framing is needed.

## Negotiating first

A client that runs for more than one call should negotiate first, as every client in this repository does:

```sh
curl -sS https://config.example.com/sovereign.config.Handshake/Negotiate \
  -H 'Content-Type: application/json' -d '{"clientProtocolVersions": ["v6"]}'
```

```json
{"servedProtocolVersions":[{"protocolVersion":"v6"},{"protocolVersion":"v5","deprecationDate":"2027-01-01T00:00:00Z"},{"protocolVersion":"v4","deprecationDate":"2027-01-01T00:00:00Z"},{"protocolVersion":"v3","deprecationDate":"2027-01-01T00:00:00Z"}]}
```

Select the first version in the server's order that you speak. If it carries a `deprecationDate`, warn whoever operates the client, and never fail because of it. The handshake's JSON names never change: `clientProtocolVersions`, `servedProtocolVersions`, `protocolVersion` and `deprecationDate`.

## Reading answers

The JSON is protobuf's standard JSON mapping. `v6` fixed the parts that are awkward from a script; these are the parts it kept.

- **Field names are `lowerCamelCase`** (`createdAt`, `plainValue`). A request may also use the `.proto` names (`plain_value`). From `v6` on, these names are part of the contract and change only with a new protocol version.
- **A field at its default value is absent.** An empty list, `0`, `false`, an empty string or an unset choice is left out, not sent as `[]`, `0` or `""`. Read an absent field as its default. A subtree with nothing in it answers `{}`.
- **An unknown field is ignored**, in a request as in an answer. Expect answers from a later server to carry fields you have never seen.
- **Enum values are names, with their type's prefix**: `VALUE_CLASSIFICATION_SECRET`, `AUDIT_EVENT_KIND_SECRET_REVEALED`, `MANAGED_PERMISSION_READ`. A request may also give the number.
- **A secret is shown as `"maskedSecret": {}`**, never as its value. `RevealSecret` returns the value.
- **A value is one of several fields.** `PutValueRequest` takes exactly one of `plainValue` and `secretValue`. Each `ReplaceSubTree` entry takes exactly one of `plainValue` and `preserveSecret` (`{}`). Sending two is `invalid_argument`.
- **Counts are JSON numbers**: `valueCount`, `deletedCount`, `totalCount`, `matchCount`.
- **An audit event's `id` is a string.** It is opaque: compare it, never do arithmetic on it.
- **Timestamps are RFC 3339 in UTC** with up to six fraction digits (microseconds), for example `2026-11-19T17:30:14.818459Z`. A request may send any RFC 3339 timestamp.

## Errors

A refused call answers a non-2xx status with a JSON body:

```json
{"code":"permission_denied","message":"configuration operation is not permitted"}
```

- **Act on `code`, never on `message`.** The message is for people and may change in any release. The codes and their HTTP statuses are in [`test-contracts/transport.json`](../test-contracts/transport.json).
- **`unauthenticated`** (401): no token, or one that has expired. Get a new token and retry.
- **`version-not-served`**: the answer carries the header `sovereign-config-error-kind: version-not-served` and the code `failed_precondition`. The server no longer serves `v6`, or the call used the wrong transport. Negotiate again and select again. The header, not the code, is what identifies it: `failed_precondition` is also used for failures that are not about versions.
- **Retries.** `unavailable` and `deadline_exceeded` are safe to retry after a pause. Anything else will fail the same way again.

## Calling v3–v5 this way

You can't. `v3`–`v5` are served over native gRPC and gRPC-Web only, and a Connect call on one of their routes gets the version-not-served answer. Every version names its transport, and Connect is `v6`'s.
