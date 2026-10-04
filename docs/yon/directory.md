# Directory and authorization routes

These routes serve SESAME's principals, roles, grants, groups and
authorization decisions over HTTP through the Yon host. Read
[docs/YON.md](../YON.md) first: it explains the `Sesame-Session` header, the
`Administrator` role and the error answers that every route shares.

Every route is `POST`, takes the operation's JSON parameters as its body and
answers the operation's JSON result. The shapes are the machine protocol's
(`api/machine/v1/README.md`). A body with a field the route does not declare
is refused with `400` before SESAME runs.

## Routes

| Route | Operation | Who may call | Tenant isolation |
| --- | --- | --- | --- |
| `POST /api/v1/principal/create` | `principal.create` | an administrator | the body's `tenant_id` must be the caller's tenant |
| `POST /api/v1/principal/get` | `principal.get` by `principal_id` alone | an administrator | the principal is loaded, then refused unless it is in the caller's tenant; a `principal_id` named with `tenant_id` or an identifier field is refused with `400 {"code":"invalid_request"}` before SESAME runs |
| `POST /api/v1/principal/get` | `principal.get` by `tenant_id`, `identifier_namespace`, `identifier_value` | an administrator | the body's `tenant_id` must be the caller's tenant, checked before the lookup |
| `POST /api/v1/principal/suspend` | `principal.suspend` | an administrator, signed in within 10 minutes | the principal is loaded, then refused unless it is in the caller's tenant; nothing is suspended otherwise |
| `POST /api/v1/role/create` | `role.create` | an administrator | the body's `tenant_id` must be the caller's tenant |
| `POST /api/v1/grant/create` | `grant.create` | an administrator, signed in within 10 minutes | the body's `tenant_id` must be the caller's tenant; SESAME then refuses a role, principal or group of another tenant (`role_not_found`, `principal_not_found`, `group_not_found`) |
| `POST /api/v1/grant/revoke` | `grant.revoke` | an administrator | the caller is sent as the request's actor; SESAME refuses a grant of another tenant with `403 {"code":"actor_tenant_mismatch"}` and revokes nothing |
| `POST /api/v1/group/create` | `group.create` | an administrator | the body's `tenant_id` must be the caller's tenant |
| `POST /api/v1/group/member-add` | `group.member_add` | an administrator, signed in within 10 minutes | the principal must be in the caller's tenant; SESAME then refuses a group of another tenant (`403 {"code":"actor_tenant_mismatch"}`) |
| `POST /api/v1/group/member-remove` | `group.member_remove` | an administrator | as `member-add` |
| `POST /api/v1/authorize/decide` | `authorize.decide` | any signed-in principal, about itself | the caller's own session supplies the tenant, the principal and the session |
| `POST /api/v1/authorize/decide-batch` | `authorize.decide_batch` | any signed-in principal, about itself | as `decide`, for every question in the batch |

`POST /api/v1/tenant/get` is described in [docs/YON.md](../YON.md).

A refusal for another tenant answers `403 {"code":"tenant_mismatch"}`. An
anonymous caller, or a session that is unknown, expired or revoked, gets `401`,
and a signed-in principal that is not an administrator gets `403` on the
administrator routes. Those two answers come from `ty`'s route guard as plain
text, not JSON; when the engine is busy during the guard's identity check, the
guard answers a plain-text `500` without `Retry-After` (see
[Errors](../YON.md#errors)). Every administrator route also decides the
`Administrator` role again inside its own call, so a caller that reaches the
controller without the route guard (for example through `ty handler invoke`)
is still refused with `403 {"code":"administrator_required"}`. Routes marked
"signed in within 10 minutes" change credentials or privileges: a session
issued longer ago is refused with `403 {"code":"reauthentication_required"}`
and nothing changes; sign in again and retry. Revoking a grant and removing a
group member only reduce access, so an older administrator session may still
do them.

## Why each route is guarded this way

**Administration.** Creating and suspending principals, defining roles and
groups, granting roles and changing group membership change who may do what in
a tenant. They are tenant administration, so they need the `Administrator`
role: SESAME must allow the caller `sesame:administer` on `sesame:tenant` in its
own tenant. The role alone is not enough, because an administrator of one
tenant must never reach another. Each route therefore checks the tenant of the
record it acts on against the tenant of the caller's session, before the
operation runs.

**Operations that name no tenant.** `principal.get` by id,
`principal.suspend`, `group.member_add` and `group.member_remove` carry no
`tenant_id`. The host first loads the named principal and refuses it unless it
belongs to the caller's tenant. For group membership SESAME also protects the
group: the caller is the request's actor, so a group of another tenant answers
`403 {"code":"actor_tenant_mismatch"}`, whatever its members.

`grant.revoke` takes only `grant_id`, and SESAME offers no way to read a
grant's tenant first. Its isolation is SESAME's own: every route that acts for
a signed-in caller sends that caller as the request's actor (see
[ADR 0007](../adr/0007-sesame-ships-a-yon-host-project.md)), and SESAME
refuses a write that would record an event in another tenant with
`403 {"code":"actor_tenant_mismatch"}` before anything is written. Revoking an
unknown or already revoked grant answers `404 {"code":"grant_not_found"}`.

Asking for a principal of another tenant by id answers `403`, while an id that
does not exist answers `404`, so an administrator can learn that some other
tenant holds a given principal id. Principal ids are sortable identifiers,
not secrets, but other tenants are never shown them, and the answer reveals
nothing else about the principal. Lookups by identifier, whose values are e-mail addresses and other
names a caller could guess, are checked before the lookup runs, so they never
reveal whether an identifier exists in another tenant.

**Authorization decisions are self-service.** `authorize.decide` and
`authorize.decide_batch` answer for the caller only. The body names the
`action`, `resource`, optional `context` and optional `policy_version`; it
cannot name a tenant, a principal or a session (`400`). The host fills those in
from the caller's own `Sesame-Session`, and SESAME verifies that session again
while deciding. This is the safer of the two possible designs:

- An administrator form, which names any principal of the tenant, would let a
  caller map other principals' permissions. No route needs it today.
- Deciding from the caller's session lets SESAME derive the `session.assurance`
  attribute, so a permission that requires multi-factor authentication works.
  A caller cannot supply a `session.` attribute itself: SESAME refuses it with
  `400 {"code":"invalid_request"}`.

A resource server that needs a decision for its signed-in user forwards that
user's `Sesame-Session` header.

```bash
curl -X POST http://127.0.0.1:8080/api/v1/authorize/decide \
  -H 'Content-Type: application/json' \
  -H "Sesame-Session: $SESSION" \
  -d '{"action":"doc:read","resource":"file:a"}'
```

## Not routed

| Operation | Why |
| --- | --- |
| `tenant.bootstrap` | Creates a tenant. That is a deployment-wide capability, not the administration of one tenant, and no tenant administrator may hold it. Use `sesame tenant bootstrap` on the command line. |
| `admin.bootstrap` | Creates the first administrator of a tenant. Before it runs nobody can sign in, so there is no caller to check; over HTTP it would let anyone make themselves an administrator. Use `sesame admin bootstrap` on the command line. |

## Tests

`app/server/tests/` holds one unit per controller and one for
`PrincipalTenantService`. They run against a real engine and cover the happy
paths, a tenant other than the caller's, anonymous and revoked sessions,
malformed requests, conflicts and stale policy versions. `ty test` calls
controllers directly, so it cannot reach the server's role check; the
administrator-only and signed-in-only answers (`401`, `403`) and the `400` for
undeclared fields were checked against `ty serve`.
