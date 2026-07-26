# FYLO Viability Evidence

## Purpose and Scope

SESAME's architecture depends on FYLO, so Phase 1 proves the storage and process
behaviour needed by security state before production identity code is built.
`internal/proving/fylo` and `tools/fylo-viability` are a disposable proving
ground, not the production persistence layer, and are excluded from release
archives.

Every run creates mode-`0700` temporary roots and removes only paths it created
under the operating system's temporary directory. The tool accepts no
operator-owned data root.

Passing one development candidate is evidence about that exact binary on that
machine. It is not a release, production-readiness, sustained-capacity, S3
restore, or cross-platform support claim.

## Experiment Profiles

The `lifecycle` profile is the fast default. It proves:

- one supervised persistent `fylo exec --loop` process;
- a side-effect-free handshake and exact runtime, protocol, native target,
  CHEX/TTID, capability, and framing validation;
- independently bounded request, response, and diagnostic buffers;
- root-wide exclusive ownership and typed `EROOTLOCKED` contention;
- request/operation correlation and fail-closed protocol decoding;
- collection creation, write/read, rebuild, clean restart, and
  read-after-restart.

The `full` profile includes `lifecycle` and exercises every locally executable
Phase 1 slice:

- 1,000 simultaneous claims of one normalized identifier with exactly one
  winner;
- 1,000 simultaneous redemptions of one authorization code and one refresh
  token, each with exactly one winner;
- an append-only, SHA-256 hash-chained security-event ledger and deterministic
  projection replay;
- bounded cursor-paged retrieval of the complete event ledger, forced across
  multiple pages, with paged/unpaged equivalence, duplicate-page detection,
  and typed `EINVALIDCURSOR` rejection of a synthetic invalid cursor;
- an authoritative revocation event whose deny state survives replay, index
  rebuild, restore, and migration;
- HMAC-SHA-256 verified snapshots and rejection of a modified snapshot;
- v1-to-v2 event upcasting with equivalent security decisions;
- forced process death before append, after FYLO append but before SESAME
  acknowledgement, and after snapshot but before caller acknowledgement;
- exclusive-root lease recovery after forced process death;
- destruction and rebuild of derived indexes from authoritative documents;
- cold local backup/restore into a distinct root with equivalent decisions;
- fail-closed detection of a corrupted authoritative event document;
- a capacity-64 admission queue under 1,000 simultaneous mixed identifier,
  authorization-code, and refresh-token submissions;
- cancellation without killing a healthy child, child restart, p50/p95/p99
  latency, heap delta, and goroutine delta.

The adapter's fake-runtime suite separately injects blocked operations,
timeouts, malformed and duplicate JSON, oversized output, request mismatches,
stderr flooding, and uncooperative shutdown. Those behaviours cannot be safely
requested from an ordinary production FYLO process.

## Reproducing a Run

Run the fast lifecycle profile:

```bash
go run ./tools/fylo-viability \
  --profile lifecycle \
  --binary /absolute/path/to/fylo \
  --expected-runtime-version 26.30.06
```

Run the complete local Phase 1 profile:

```bash
go run ./tools/fylo-viability \
  --profile full \
  --binary /absolute/path/to/fylo \
  --expected-runtime-version 26.30.06 \
  --timeout 5m
```

For a locally compiled candidate, the development-build exception and native
target must be explicit:

```bash
go run ./tools/fylo-viability \
  --profile full \
  --binary /absolute/path/to/local/fylo \
  --expected-runtime-version 26.30.06 \
  --expected-build-target macos-arm64 \
  --allow-development-build \
  --timeout 5m
```

The equivalent opt-in integration test is:

```bash
SESAME_FYLO_INTEGRATION=1 \
SESAME_FYLO_PROFILE=full \
SESAME_FYLO_ALLOW_DEVELOPMENT=1 \
SESAME_FYLO_BUILD_TARGET=macos-arm64 \
FYLO_BINARY=/absolute/path/to/local/fylo \
go test -count=1 ./test/fylo
```

The tool emits one JSON report to stdout, writes failures to stderr, and exits
nonzero if any assertion fails. Its default timeout is five minutes. Ordinary
`go test ./...` deliberately skips the external-runtime test. CI must not
download or claim compatibility with an unpinned FYLO executable.

One intermittent failure is under observation: on roughly one run in four,
the interrupted-upgrade leg's first start of the locally built next-version
candidate fails with `read FYLO handshake response: EOF` after about nine
seconds, and passes on every rerun. It has not reproduced in a shell harness
(0/15 immediate restarts after `SIGKILL` of an exclusive-root owner) or in
four consecutive clean-cache suite runs. The adapter now attaches the child's
exit status and stderr tail to handshake failures, so the next occurrence
will carry the runtime's own account. Do not treat this leg as flaky-by-design:
if it recurs with diagnostics, file the evidence upstream.

The same opt-in suite also proves the production tenant-bootstrap slice:
bootstrap, forced process death, replay, derived-index rebuild, and cold
restore into a distinct root. Setting `SESAME_FYLO_NEXT_BINARY`,
`SESAME_FYLO_NEXT_VERSION`, and optionally
`SESAME_FYLO_NEXT_ALLOW_DEVELOPMENT=1` additionally exercises an interrupted
upgrade: the pinned binary writes and dies without a clean shutdown, and the
next candidate binary must replay the identical tenant decisions and continue
the same hash chain.

## Current Release Candidate

On 2026-07-25, the full profile passed ten consecutive runs against the signed
FYLO v26.30.06 release binary recorded in
[the native evidence matrix](NATIVE_MATRIX.md). Both sides were native: the
FYLO process is the released `macos-arm64` artifact and the SESAME harness was
built for and executed as native `darwin/arm64`, replacing the earlier
mixed-architecture development evidence. No development-build exception was
required. The runs observed:

- runtime `26.30.06`, protocol `1`, build kind `release`, and commit
  `39f57b5cf3120c9b9b3b4ead9e749b47b76ac4f0`, agreeing exactly with the
  GitHub-signed build attestation for the downloaded artifact. That
  attestation covers all fifteen release assets in one statement, and the
  `fylo-macos-arm64` subject digest matches the binary in use;
- exactly 1 winner and 999 rejections for identifier, authorization-code, and
  refresh-token races;
- 69 durable security events after the mixed admission sample;
- successful hash-chain verification, snapshot verification, snapshot-tamper
  rejection, revocation enforcement, replay equivalence, migration
  equivalence, and end-to-end decision equivalence;
- successful recovery at all three SESAME acknowledgement boundaries, after
  root lease release, after index loss, and after cold local restore;
- fail-closed authoritative-event corruption detection;
- exactly 64 accepted and 936 saturated mixed submissions per run;
- complete ledger retrieval through 5 bounded cursor pages of at most 16
  events, byte-equivalent to the unpaged result, with a synthetic invalid
  cursor rejected as typed `EINVALIDCURSOR` in every run;
- admitted-operation latency across the ten runs of p50 10.6–10.8 ms, p95
  11.5–12.4 ms, and p99 12.4–17.6 ms.

The opt-in `go test ./test/fylo` full-profile suite also passed against the
same release binary. Earlier development-candidate evidence from 2026-07-23,
including the fixed cancellation race and its 20 race-detector repetitions,
remains recorded in version control history.

These latency values are smoke evidence from disposable runs, not a supported
capacity limit or benchmark. Release qualification requires reproducible
workloads, reference hardware, disk growth, and soak results.

## Evaluated and Declined: FYLO At-Rest Field Encryption

FYLO encrypts schema-declared `$encrypted` fields with AES-GCM under a
process-global key. SESAME evaluated it as an at-rest pepper for Argon2id
password verifiers, which would make a stolen data root useless for offline
cracking.

On v26.30.05 the blocker was that a process which had not first written to the
collection received stored ciphertext with `ok:true` and no error, even with
the correct key. SESAME's startup replay is read-only, so every restart would
have read ciphertext. That was reported as FYLO
[#84](https://github.com/d31ma/FYLO/issues/84) and shipped fixed in v26.30.06.

Re-measured directly against the released v26.30.06 binary, writing one
`$encrypted` field in one process and then reading it in fresh processes:

- the field is genuinely encrypted at rest — the plaintext appears nowhere
  under the data root, and the stored value is a self-identifying `v2.`-prefixed
  ciphertext;
- **a fresh read-only process with the correct key decrypts correctly**, with
  no prior write. This is the #84 fix and it removes the blocker;
- a fresh process with a *wrong* key now fails closed with a typed
  `EDECRYPTFAILED` error rather than silently returning ciphertext. That is a
  distinct improvement over v26.30.05, where a wrong key was indistinguishable
  from a correct one on the response;
- a process with *no* key configured still receives the `v2.` ciphertext with
  `ok:true`. That is defensible — nothing was asked to be decrypted — but it
  means a SESAME deployment that lost its encryption key would read ciphertext
  rather than fail at the storage layer. SESAME's hash chain would refuse to
  open such a ledger, and the deployment loader already fails closed on a
  missing key file, so the fail-closed behaviour would come from SESAME rather
  than from FYLO.

Schema layout, for whoever adopts this: schemas live at
`$FYLO_SCHEMA/<collection>/manifest.json` plus
`history/v<N>.schema.json`, and encrypted fields are named in a top-level
`$encrypted` array using `/` as the nesting separator (`payload/verifier`). A
dotted path is silently accepted and never matches, which is the kind of
failure that looks like working encryption.

### Decision: declined, on 2026-07-25

The #84 fix removes the blocker, but SESAME still does not adopt FYLO field
encryption. The reasons are about fit, not quality:

1. **It would not cover the data it appears to cover.** SESAME writes snapshot
   state as one opaque MAC-verified JSON *string* field. Every password
   verifier, sealed TOTP secret, and session digest lives inside that string.
   A `$encrypted` declaration on the event collection's `payload/verifier`
   encrypts verifiers in events and leaves the identical values in cleartext
   inside every snapshot. That is not defence in depth; it is the appearance
   of it, which is worse than knowingly having neither.
2. **SESAME already owns an equivalent primitive that fits better.**
   `internal/domain/authenticator/sealed.go` is AES-256-GCM under a
   permission-checked deployment key, already used for TOTP shared secrets. It
   seals a chosen value wherever that value goes — including inside snapshot
   state — and it fails closed with `ErrNoSealingKey`. FYLO's equivalent fails
   *open*: a process with no key configured receives ciphertext with
   `ok:true`, so the fail-closed behaviour would have to come from SESAME
   anyway.
3. **The cost is real and the gain is zero.** Adopting it adds a third
   deployment key, external per-collection schema files, a process-global
   environment variable carrying key material into a subprocess, and a
   silently-ignored dotted-path footgun — to obtain a capability SESAME
   already has.

Password verifiers therefore continue to rest on Argon2id alone. That is the
documented OWASP construction and remains the sound primary control.

Sealing verifiers with SESAME's own facility is available and would be a
genuine improvement, but it is a separate decision with a real cost: losing
that key would make every password unverifiable, where losing it today only
disables TOTP. It needs a rotation and recovery design before it is taken.

The adapter retains its `SchemaDir`/`EncryptionKey` configuration, now purely
so this evaluation stays cheap to redo.

## Promoted FYLO Contract

The gaps SESAME filed as FYLO
[#68](https://github.com/d31ma/FYLO/issues/68) through
[#75](https://github.com/d31ma/FYLO/issues/75) shipped in FYLO v26.30.05 and
were closed by
[FYLO PR #76](https://github.com/d31ma/FYLO/pull/76). SESAME enforces:

- `handshake` supplies stable runtime, build, dependency, framing, and
  capability identity, including the release commit;
- `--exclusive-root` provides crash-safe root ownership and fencing;
- `--max-request-bytes` and `--max-response-bytes` establish the exact bounded
  NDJSON contract.

The release additionally provides cursor-based `findDocs`/`findDeletedDocs`
pagination, whole-root backup/verify/restore through the standalone binary,
Windows NTFS backup parity, a live S3-compatible backup/restore release gate,
and signed provenance with an SPDX SBOM. SESAME now requires the advertised
`queryPagination` capability (version 1, `ttid-binary-ascending` ordering,
restart-from-first-page policy) in its fail-closed handshake validation and
retrieves the security-event ledger exclusively through bounded cursor pages.
The binary backup surface is not yet consumed; adopting it requires
provisioned object storage and is tracked Phase 2 work.

SESAME fails closed when any handshake field differs from its configured
contract. Development builds require an explicit exception and are reported as
such. The pinned release candidate is FYLO v26.30.06
(`fylo-macos-arm64` SHA-256
`ae39a2b66ea9771766f3f3d6b3d0d1b01e1b3842a45aa0389535109b91bdee50`), verified
against the release `SHA256SUMS` and its signed GitHub attestation before use.

## Remaining External Evidence

The immutable-release, commit-identity, and provisioned-S3 rows are satisfied
by FYLO v26.30.06: the artifact is signed and attested, the handshake reports
the release commit, and FYLO's release workflow now gates every release on a
live S3-compatible backup/verify/restore/corruption run. The Phase 1 exit gate
remains open until:

- the full profile passes for every claimed OS, architecture, and filesystem
  using the exact packaged SESAME/FYLO/CHEX/TTID set; only macOS arm64 has
  native release evidence today, and SESAME itself has no packaged release
  artifact yet;
- FYLO's own release evidence proves process death during each internal
  transaction phase. SESAME can kill at its acknowledgement boundaries but the
  public machine binary exposes no transaction failpoint;
- longer mixed-load, disk-growth, and soak tests establish documented supported
  limits.

Until those rows are complete, macOS arm64 is release-candidate evidence and no
native target is promoted to production support.
