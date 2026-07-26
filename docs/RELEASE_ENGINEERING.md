# SESAME Release Engineering

## Support Vocabulary

- **Buildable**: the Go compiler emits an artifact for the target.
- **Native-tested**: core tests pass on that target's operating system and
  architecture.
- **Preview**: distributed for evaluation with documented missing production
  gates.
- **Supported**: package, contract, security, crash, restore, upgrade, rollback,
  soak, and SDK interoperability gates pass on native infrastructure.

Never use these labels interchangeably. Cross-compilation proves only
buildability.

## Planned Matrix

| OS | Architecture | Planned tier | Current dependency constraint |
| --- | --- | --- | --- |
| Linux | amd64 | production candidate | requires pinned FYLO/CHEX/TTID Linux x64 set |
| Linux | arm64 | production candidate | requires complete native ARM64 runtime validation |
| macOS | amd64 | candidate | requires signing/notarization and native recovery |
| macOS | arm64 | candidate | requires signing/notarization and native recovery |
| Windows | amd64 | preview | FYLO backup/restore parity blocks production |
| Windows | arm64 | unsupported | no matching proven FYLO/CHEX/TTID release set |

Other Go ports are considered only when FYLO, CHEX, and TTID have a matching
supported artifact set and maintainers can provide native validation.

## Automated Release Workflow

`.github/workflows/release.yml` runs on every `v*` tag with pinned actions:
it tests, cross-compiles the planned matrix, writes `SHA256SUMS`, generates
an SPDX SBOM, signs GitHub build attestations for every executable, verifies
those attestations before upload, and publishes the release. Consumers verify
artifacts with `shasum -c SHA256SUMS` and
`gh attestation verify <asset> --repo d31ma/sesame`. These artifacts prove
buildability and integrity only; the platform-matched FYLO/CHEX/TTID bundle,
signing/notarization, and native promotion gates below remain manual
requirements before any support claim.

## Release Archive

Each archive contains the platform-matched SESAME, FYLO, CHEX, and TTID
executables, third-party licenses, install notes, and a machine-readable
manifest. The manifest records:

- SESAME version and commit;
- Go version and build settings;
- target OS and architecture;
- FYLO version and machine protocol version;
- CHEX and TTID versions;
- digest for every executable;
- source-date/build timestamp policy;
- contract schema version;
- minimum/maximum compatible SDK protocol;
- checksums for every file.

Artifacts use deterministic names such as:

```text
sesame_<version>_linux_amd64.tar.gz
sesame_<version>_linux_arm64.tar.gz
sesame_<version>_darwin_amd64.tar.gz
sesame_<version>_darwin_arm64.tar.gz
sesame_<version>_windows_amd64.zip
```

## Build Requirements

- pin the current supported Go security patch;
- prefer `CGO_ENABLED=0`;
- build with trimmed paths and deterministic version metadata;
- generate checksums, SBOM, and signed provenance;
- sign platform artifacts through documented project identities;
- pin CI actions and verify downloaded tool/FYLO digests;
- build in clean, ephemeral environments;
- compare reproducible outputs on at least two independent builders where
  platform signing does not intentionally change bytes;
- retain release inputs and evidence.

## Native Validation

Every supported target must pass:

- archive extraction and executable discovery from paths with spaces and Unicode;
- `init`, `doctor`, `version`, `exec --loop`, EOF shutdown, cancellation, and
  forced child-process termination;
- FYLO/CHEX/TTID sibling discovery, version/digest/protocol mismatch, crash, and
  restart;
- local filesystem locking and second-writer rejection;
- event append, snapshot, corruption detection, rebuild, backup, and restore;
- clean install, upgrade from every supported minor line, rollback where safe,
  and uninstall without deleting data;
- CLI, NDJSON, host-framework-adapter, and standards-dispatch black-box
  contracts;
- all support-tier SDK interoperability;
- file permission/ACL behavior;
- parent/child signal and process-reaping behavior native to the OS;
- load and soak evidence on reference hardware.

Container tests do not replace host-native filesystem or process tests.
Emulation does not replace native architecture tests for a production claim.

## Restore, Upgrade, Rollback, and Soak Evidence

`tools/production-evidence` runs these gates against private temporary
deployments and emits one machine-readable report. Its smoke profile is useful
while developing the harness but is never release evidence. Its release
profile refuses:

- a soak shorter than 72 hours;
- missing, identical, or development previous/current SESAME artifacts;
- FYLO without immutable release identity;
- an unnamed reference environment;
- observational latency, heap, goroutine, or disk-growth metrics without
  explicit pass/fail thresholds.

The restore stage verifies both an applicable allow and a durable revoked deny
after cold-copying a stopped complete deployment. The compatibility stage
creates stored data with the actual previous binary, verifies it with the
current binary, writes through the current binary, and reopens with the
previous binary. The soak mixes public-SDK decisions with durable writes and
records child-process and deployment growth. See
[Production Evidence](PRODUCTION_EVIDENCE.md) for the contract, commands,
current smoke observation, and remaining remote-backup boundary.

## FYLO Runtime Pairing Policy

SESAME supports an exact FYLO/CHEX/TTID release set by default. Startup fails
closed when:

- the executable is missing or has the wrong architecture;
- its version or machine protocol is outside the approved range;
- its digest differs from the release manifest when bundled verification is
  enabled;
- the data root or filesystem is unsupported;
- required recovery readiness checks fail.

Upgrading any member of the FYLO runtime set requires the full storage, schema,
identifier, crash, backup/restore, migration, and performance gate. A
user-supplied executable path is advanced configuration and does not widen the
supported version range.

## SDK Releases

SDKs use independent semantic versions but publish:

- supported SESAME versions;
- supported contract/protocol versions;
- supported language/runtime versions;
- package checksum/signature/provenance where the registry allows;
- generated-code source schema;
- lifecycle and security-support policy.

An SDK release is blocked unless its ecosystem-native test suite and the shared
contract corpus pass against the oldest and newest compatible SESAME binaries.

## Promotion Gates

### Developer Preview

- core contract works on at least Linux amd64;
- no production or standards-conformance claim;
- known data-loss, recovery, and compatibility gaps are explicit.

### Security Preview

- candidate native matrix passes;
- restore and upgrade drills pass;
- OIDC conformance and adversarial tests pass for claimed profiles;
- SDK compatibility matrix is published;
- SBOM, provenance, checksums, and signatures are verifiable;
- threat model has no unowned critical finding.

### v1.0 Supported

- independent security assessment completed;
- 72-hour `production-evidence --profile release` run passes on production
  targets under reviewed explicit limits;
- every supported stored-data version has an upgrade fixture;
- recovery time/objectives and performance limits are measured;
- disclosure, support, compatibility, deprecation, and release policies are
  published;
- production-supported platforms have no missing backup/restore gate.

## Release Failure Policy

If a platform-specific gate fails, do not delay security fixes for healthy
targets and do not mislabel the failed target. Remove or downgrade that target's
support tier, publish the reason, and restore it only after the native gate
passes. Never skip a storage, recovery, protocol, or security test merely to
keep a matrix green.
