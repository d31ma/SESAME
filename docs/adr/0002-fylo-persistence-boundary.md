# ADR 0002: FYLO Persistence Boundary

- Status: Accepted
- Date: 2026-07-23
- Accepted: 2026-07-26

## Context

FYLO is filesystem-first, has no remote server protocol, performs transactions
within one collection, and does not provide cross-collection transactions,
distributed coordination, uniqueness constraints, or active replication. Its
indexes are derived and its built-in encrypted equality indexes reveal
frequency. The configured field cipher is process-global.

Identity operations require race-safe uniqueness, single-use codes, rotating
refresh tokens, durable revocation, audit evidence, and deterministic recovery.

## Decision

For v1:

1. Run one authoritative SESAME writer per FYLO root.
2. Hold an exclusive SESAME writer lease for the lifetime of the process and
   refuse to start a second writer.
3. Store accepted state transitions in one append-only `security_events`
   collection.
4. Treat each event as both the authoritative transition and its audit evidence.
5. Build current identity, identifier, session, token-family, and policy state as
   in-memory projections.
6. Persist periodic projection snapshots as derived data with an event cursor
   and integrity digest; verify and replay from the cursor on startup.
7. Serialize commands that can conflict, including identifier claims,
   authorization-code redemption, refresh-token rotation, recovery, and
   privilege changes.
8. Store recoverable secrets in application-level envelopes. Keep key-encryption
   keys, peppers, and signing roots outside FYLO.
9. Use random public IDs and token material in event payloads. TTIDs order
   records; they are not credentials or security clocks.
10. Export a hash-chained audit stream to an independently administered,
    append-only target for tamper evidence.

## Event Shape

Every security event carries:

```json
{
  "event_id": "cryptographically-random-public-id",
  "tenant_id": "tenant-public-id",
  "sequence_id": "fylo-ttid",
  "aggregate_type": "principal",
  "aggregate_id": "principal-public-id",
  "event_type": "principal.identifier_claimed",
  "schema_version": 1,
  "occurred_at": "trusted-utc-timestamp",
  "actor": {},
  "correlation_id": "request-correlation-id",
  "idempotency_key_hash": "keyed-hash",
  "public": {},
  "sealed": {},
  "previous_event_digest": "digest",
  "event_digest": "digest"
}
```

No secret or unnecessary personal data belongs in `public`. `sealed` uses a
random data-encryption key wrapped by the deployment key boundary. Erasure and
credential replacement can cryptographically destroy the relevant wrapped key
without rewriting the append-only event.

## Why an Event Ledger

- One append can durably represent the state transition and its audit record,
  avoiding unsafe cross-collection dual writes.
- A single writer can make uniqueness and one-time-use decisions against a
  current projection before appending.
- Crash recovery replays acknowledged facts instead of trying to infer which of
  several collections committed.
- Derived indexes and snapshots align with FYLO's “documents are truth,
  indexes are accelerators” model.

## Costs and Risks

- Active-active writers are prohibited.
- Startup time grows with the event history unless verified snapshots work.
- Event schemas require disciplined versioning and upcasters.
- Immutable encrypted history requires careful key lifecycle and crypto-erasure.
- High-volume session and token events can exceed FYLO's practical throughput;
  the viability benchmark must establish supported limits.
- A privileged filesystem administrator can bypass local WORM permissions, so
  external audit anchoring is required for tamper evidence.

## Required FYLO Evolution for HA

Do not claim active-active or zero-downtime failover until FYLO or an approved
FYLO-native coordination layer provides:

- conditional append or compare-and-swap;
- durable unique-key reservations;
- an ordered change feed with resumable offsets;
- leader fencing or consensus-safe writer leases;
- replication with documented consistency and recovery semantics;
- snapshot reads or transactions across the required security state;
- per-tenant or per-record encryption-key rotation.

## Acceptance Gate

The proving ground must demonstrate:

- no duplicate identifier claims under concurrent registration attempts;
- exactly one successful redemption of a code or refresh token;
- correct recovery across forced termination before, during, and after append;
- verified snapshot replay with corruption detection;
- durable revocation before success is returned;
- backup/restore followed by equivalent authorization decisions;
- measured throughput and bounded queue latency on reference hardware.
