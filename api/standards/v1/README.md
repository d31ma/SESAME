# SESAME Host-Adapter Contract v1

`standards.dispatch` is the framework-neutral boundary between a host
application's public HTTP routes and SESAME's protocol implementation. The
host retains its listener, TLS, routing, middleware, rate limits, and user
experience. The SESAME binary validates the wire request and returns bounded
HTTP instructions or an external-interaction action.

The contract version is independent of machine protocol v1. Every request sets
`contract_version` to `"1"`, and every successful dispatch result echoes it.

## Request

```json
{
  "contract_version": "1",
  "endpoint": "oidc.token",
  "method": "POST",
  "query": {},
  "form": {
    "grant_type": ["authorization_code"],
    "code": ["..."],
    "redirect_uri": ["https://app.example/callback"],
    "code_verifier": ["..."]
  },
  "authorization": "Basic ...",
  "dpop": "...",
  "http_uri": "https://id.example/token"
}
```

`query` and `form` are multimaps, not scalar maps. An adapter must preserve
every value so SESAME can reject duplicated OAuth parameters. Never use a
framework accessor that silently keeps only the first or last value.

Only two request headers cross the contract:

- `authorization`: the complete Authorization field, used for HTTP Basic
  client authentication;
- `dpop`: the complete DPoP proof field.

`http_uri` is required when `dpop` is present and must be the public absolute
URI actually served, without query or fragment. Trusted-proxy normalization is
the host's responsibility.

The envelope accepts no arbitrary header bag, cookies, remote address, or
framework object. It is bounded to 64 names and 64 total values per multimap,
128 KiB of serialized JSON overall, 128-byte names, and 16 KiB decoded values.
The schema records the cross-property value limit with the required
`x-maxTotalItems` extension because standard JSON Schema cannot sum array items
across dynamically named properties.

## Endpoints

| Endpoint | Method | Input | Result |
| --- | --- | --- | --- |
| `oidc.discovery` | GET | optional `endpoints` host route paths | JSON provider metadata |
| `oidc.jwks` | GET | none | public JWKS |
| `oidc.authorization` | GET | query | `interaction` action or redacted OAuth error |
| `oidc.token` | POST | form, optional Authorization and DPoP | token JSON or OAuth error |
| `oidc.introspection` | POST | form and optional Authorization | introspection JSON or OAuth error |
| `oidc.revocation` | POST | form and optional Authorization | empty success or OAuth error |
| `oidc.logout` | GET | query | signed-out JSON, validated redirect, or OAuth error |

An unknown endpoint is a contract error. A known endpoint with the wrong method
returns status 405 and an `allow` response header.

## Response

An ordinary response contains:

```json
{
  "contract_version": "1",
  "status": 400,
  "headers": {
    "cache-control": "no-store",
    "content-type": "application/json",
    "pragma": "no-cache",
    "x-content-type-options": "nosniff"
  },
  "body": {
    "error": "invalid_request"
  }
}
```

The only response headers in v1 are `allow`, `cache-control`, `content-type`,
`location`, `pragma`, `www-authenticate`, and `x-content-type-options`.
Adapters must reject any other header, a status outside 200-599, a response
version they do not support, or a value containing CR/LF.

A validated authorization request returns an action instead of an HTTP body:

```json
{
  "contract_version": "1",
  "status": 200,
  "headers": {
    "cache-control": "no-store",
    "pragma": "no-cache"
  },
  "action": {
    "kind": "interaction",
    "interaction_id": "...",
    "interaction_secret": "...",
    "client_id": "...",
    "client_name": "...",
    "scopes": ["openid"],
    "expires_at": "..."
  }
}
```

The host renders its own login or consent experience. The interaction secret
is bearer-equivalent: keep it in an encrypted server-side session or an
HttpOnly, Secure cookie; never log it, put it in a URL, or expose it to
browser JavaScript.

The normative schema is
[`host-adapter.schema.json`](host-adapter.schema.json). Architectural rationale
and compatibility rules are in
[`docs/rfcs/0002-host-adapter-contract-v1.md`](../../../docs/rfcs/0002-host-adapter-contract-v1.md).
