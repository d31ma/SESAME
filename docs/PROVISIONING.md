# SCIM 2.0 provisioning

SESAME can act as a SCIM 2.0 service provider, so an external directory —
Okta, Entra ID, or anything speaking RFC 7644 — pushes users into a tenant and
deactivates them when they leave.

This document is for the operator and the host application. Part of what makes
provisioning safe is not enforceable by SESAME and has to be done by whoever
runs it; that part is in [The host's obligations](#the-hosts-obligations).

## Why this is the most privileged surface you will configure

A provisioning client can create principals and change their identifiers.
Identifiers are how a person signs in. A directory that can rewrite them can
redirect an account, and a directory that can create them can create an
account that looks like anyone.

Treat a provisioning token the way you would treat an administrator
credential, because in effect it is one.

## Setting up a directory

SESAME opens no port. The host exposes the `/scim/v2` routes and carries each
request to the engine, which is ADR 0003's standards-dispatch boundary.

```bash
sesame provisioning client-register \
  --tenant-id tnt_... \
  --name "Okta production"
```

The bearer token is printed **once**. It is stored as a SHA-256 digest, so
there is nothing to print later — not to you, not to an administrator, not
through any operation. Put it into the directory's configuration immediately
and do not keep a copy.

### Identifier namespace

A SCIM `userName` claims a SESAME identifier. Which namespace it claims is a
per-client setting, defaulting to `email`:

```bash
sesame provisioning client-register ... --identifier-namespace login_name
```

SCIM does not require `userName` to be an email. The default matches what
federation uses, so a person provisioned by the directory and the same person
signing in through an external identity provider converge on one principal
instead of becoming two. If your directory sends a login name rather than an
address, set this — and set it before the first sync, because changing it
later leaves the already-provisioned users claiming the old namespace.

### Group management

`--can-manage-groups` is a separate grant and defaults to off.

Group membership drives authorization decisions in SESAME. A directory that
can move people between groups can grant privilege, which makes a routine
directory sync a privilege-granting operation. A client that only needs to
create and deactivate people should not have it.

Every Group operation checks it, in one place beside the state it protects
rather than per handler. A client without the grant is refused with
`provisioning_forbidden`.

## Rotating and revoking

```bash
# Replace a leaked token. The old one stops working immediately.
sesame provisioning client-rotate-token --tenant-id tnt_... --scim-client-id scm_...

# Stop this directory entirely.
sesame provisioning client-disable --tenant-id tnt_... --scim-client-id scm_... \
  --reason "decommissioned"
```

Rotation has **no overlap window**. The previous token is dead the moment the
replacement is minted. An overlap would be convenient during a reconfiguration
and is exactly what someone holding the leaked token would use, so the
trade-off is resolved in favour of the leak.

Rotation is the remedy that keeps the directory working; disabling is the one
that does not. If a token leaked, rotate. If the directory itself is no longer
trusted, disable.

## What the operations do

| SCIM request | SESAME operation | Effect |
| --- | --- | --- |
| `POST /Users` | `scim.user_create` | creates a principal and claims its identifier |
| `GET /Users/{id}` | `scim.user_get` | one user |
| `GET /Users?filter=…` | `scim.user_list` | filtered, paginated |
| `PATCH /Users/{id}` | `scim.user_patch` | bounded replace |
| `DELETE /Users/{id}` | `scim.user_deprovision` | **suspends**; see below |
| `POST /Groups` | `scim.group_create` | creates a SESAME group |
| `GET /Groups/{id}` | `scim.group_get` | one group with its members |
| `GET /Groups?filter=…` | `scim.group_list` | filtered on `displayName`, paginated |
| `PATCH /Groups/{id}` | `scim.group_patch` | membership and displayName changes |
| `DELETE /Groups/{id}` | `scim.group_deprovision` | **empties**; see below |

Every resource operation carries the bearer token as a parameter. The engine
always authenticates, so a host cannot forget to, and a SCIM request stays one
round trip.

### DELETE suspends, it does not erase

Deleting a principal would delete the subject of every audit record naming it.
An operator investigating what a departed employee did would find a dangling
identifier and no account behind it.

Deprovisioning therefore suspends, through the same path an administrator's
suspension uses — so sessions stop the same way, and revocation is durable
across restart. The user stays readable and reports `active: false`, which is
what a reconciling directory expects.

### PATCH can deactivate but never reactivate

`active: false` suspends. `active: true` does **not** reinstate.

A directory setting `active: true` on a principal an administrator suspended
would undo a human decision with a sync. Reactivation is an administrative
action; a directory cannot perform one.

### POST is a create, and a claimed userName is a conflict

A `userName` already claimed returns a conflict, not an update. Merging a POST
into an existing principal would let a directory capture an account somebody
already has. Directories reconcile against this — the conflict is reported
distinctly so the provider stops retrying and switches to PATCH.

### An absent `active` means active

RFC 7643 says so. If SESAME read absence as "deactivate", every directory that
syncs users without that attribute would suspend its entire population on the
first push.

### Groups grant privilege

A provisioned group is created through the same command an administrator uses,
so an authorization decision cannot tell whether a group arrived by sync or by
hand. That is the point — a group that did not drive decisions would make the
sync decorative — and it is also why `--can-manage-groups` is a separate
grant.

**Group PATCH accepts both removal dialects.** Directories disagree: some send
`remove` with `path: "members"` and a value list, others send `remove` with
`path: members[value eq "..."]`. Supporting one works with half the market, so
SESAME reads both. The value path is matched as one literal shape — exactly
`members[value eq "X"]`, no other attribute, operator, or conjunction — rather
than evaluated as an expression.

**Membership changes are idempotent.** A directory reconciles by re-sending the
whole desired state, so adding somebody already in the group is the common
case and appends no event. Removing a non-member is likewise a no-op.

**A member must belong to the same tenant.** A directory naming an arbitrary
principal identifier would otherwise put somebody else's user into a group
that carries a role here.

**`DELETE /Groups/{id}` empties the group rather than deleting it.** Deleting
would remove the subject of every grant naming it. Emptying achieves what a
directory means — nobody holds this group's privilege any more — while leaving
the group and its grants readable, so an operator can see what access was
removed and reinstate it deliberately.

**A re-synced group name is idempotent.** Provisioning a group whose
`displayName` already exists returns the existing group rather than creating a
second one, because two groups named alike is a privilege confusion an
operator cannot see.

## What is bounded, and why

Two parts of SCIM are implemented as deliberate subsets. Both **refuse with a
reason** rather than partially honouring a request.

**PATCH** supports `replace` on `active`, `userName`, `displayName`, and
`externalId`. RFC 7644's full path grammar allows filters inside paths —
`members[value eq "x"]` — which means running an expression evaluator against
attacker-influenced input to decide what identity state to mutate. `id` is not
patchable at all: reassigning it would let one synced user become another.

**Filters** support exactly `attribute eq "value"` on `userName` and
`externalId`. Compound expressions, `co`, `sw`, `pr`, and value paths are
refused.

A filter is not a convenience here. During a reconcile a directory uses the
result to decide who still exists — so a filter parsed loosely returns the
wrong users, and the directory deactivates people who should not have been
touched. Refusing is the safe failure.

If your directory sends something outside these subsets, the error names what
SESAME will not act on, so it can be fixed in the provider's configuration.

## The host's obligations

SESAME cannot enforce these from the far side of a pipe.

- **Carry the `Authorization` header through unchanged**, and pass the token to
  the engine. Do not attempt to validate it yourself — the engine is the only
  thing that can, and a host that decides a token looks fine has made an
  authentication decision it is not equipped to make.
- **Do not log the token.** It appears in the `Authorization` header of every
  provisioning request; make sure your request logging excludes it.
- **Bound request bodies.** SESAME refuses payloads above 64 KiB, but only
  after the host has read them.
- **Map the engine's error codes to SCIM status codes.** `scim_user_conflict`
  is a 409 and directories reconcile against it; collapsing it into a 500
  leaves a provider retrying a create forever. `provisioning_denied` is a 401,
  `scim_user_not_found` and `scim_group_not_found` are 404s,
  `provisioning_forbidden` a 403, and `scim_unsupported` a 400.

## Auditing

Every provisioning action appends to the security ledger:
`scim_client.registered`, `scim_client.token_rotated`,
`scim_client.disabled`, `scim.user_provisioned`, `scim.user_updated`, and
`scim.user_deprovisioned`.

Group membership changes append the ordinary `group.member_added` and
`group.member_removed` events, and a provisioned group appends
`group.created` — the same events an administrator's change appends, so an
investigation reads one timeline.

A provisioned principal also appends the ordinary `principal.created` and
`principal.suspended` events, so an investigation reads one timeline whether a
change came from a directory or an administrator.

## What is not implemented

Named so nobody infers them from the presence of the rest:

- **PUT.** Full-resource replace is not implemented; use PATCH.
- **Nested groups.** A group cannot be a member of another group; only
  principals may be members.
- **`externalId` on groups.** Accepted and ignored; groups are matched by
  `displayName`.
- **`/Schemas`, `/ResourceTypes`, `/ServiceProviderConfig`.** Discovery
  endpoints are not served, so a directory that probes them before syncing
  will need its schema configured manually.
- **Bulk operations** and the `/Me` endpoint.
- **`sortBy` / `sortOrder`.** Lists are ordered by principal identifier.
