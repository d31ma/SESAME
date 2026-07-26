# FYLO Native Evidence Matrix

This matrix records evidence for exact FYLO/CHEX/TTID candidate sets. A green
cross-build is not native evidence. Each supported row must run on the named
operating system, architecture, and filesystem using the packaged artifacts
that would ship with SESAME.

## Current Evidence

| Date | Host | Filesystem | FYLO identity | Artifact SHA-256 | Profile | Result | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-07-25 | macOS 26.5.2 arm64, Apple M4, 16 GiB; SESAME harness native `darwin/arm64` | local default filesystem | runtime 26.30.06, protocol 1, target `macos-arm64`, `release`, commit `39f57b5cf3120c9b9b3b4ead9e749b47b76ac4f0`, CHEX/TTID 26.28.02 | `ae39a2b66ea9771766f3f3d6b3d0d1b01e1b3842a45aa0389535109b91bdee50` | `full` profile, 10 consecutive native runs plus the opt-in integration suite with and without the development-build exception, checksum and signed-attestation verification before use | pass | native release-candidate evidence; SESAME packaged artifact still pending |
| 2026-07-24 | macOS 26.5.2 arm64, Apple M4, 16 GiB; SESAME harness native `darwin/arm64` | local default filesystem | runtime 26.30.05, protocol 1, target `macos-arm64`, `release`, commit `f30ee792d7cd408be6b8b157e84a113d2877af72`, CHEX/TTID 26.28.02 | `6fe196da20baa703a4da79b7add072f6998ce24effa1e84b8d508350048ad8f5` | `full` profile including bounded cursor-paged ledger retrieval, 10 consecutive native runs plus one opt-in integration-test run, checksum and signed-attestation verification before use | pass | native release-candidate evidence; SESAME packaged artifact still pending |
| 2026-07-23 | macOS 26.5.2 arm64, Apple M4, 16 GiB; SESAME harness `darwin/amd64` under translation | local default filesystem | runtime 26.30.04, protocol 1, target `macos-arm64`, `development-compiled`, commit `unknown`, CHEX/TTID 26.28.02 | `5d34a355a502ba2e3c69ac7015a8707b65c1213eef588befbb5300b360b21a47` | finalized `full` profile, 10 consecutive integration runs plus one recorded JSON report | pass | superseded by the 2026-07-24 release-candidate row |

Across the ten 2026-07-25 v26.30.06 runs, admitted mixed-operation latency
ranged over p50 10.6–10.8 ms, p95 11.5–12.4 ms, and p99 12.4–17.6 ms. The ten
preceding v26.30.05 runs ranged over p50 10.7–11.1 ms, p95 12.2–13.4 ms, and
p99 13.5–21.2 ms; the two sets overlap, so this is not evidence of a
regression or an improvement in either direction.
Run duration varies because it includes FYLO process startup and teardown;
these numbers are not a capacity commitment.

## Candidate Coverage

| Target | Release tier under consideration | Native full profile | FYLO transaction crash evidence | Native backup/restore | Promotion state |
| --- | --- | --- | --- | --- | --- |
| macOS arm64 | production candidate | passed natively against the signed FYLO v26.30.06 release artifact | pending FYLO release evidence | cold local restore passed; live S3 gate now enforced by FYLO's own release workflow | production-evidence smoke passed; blocked on a packaged SESAME artifact, distinct-version upgrade/rollback, transaction crash evidence, remote deployment restore, and 72-hour limits |
| macOS amd64 | production candidate | pending; FYLO v26.30.06 ships `fylo-macos-x64` | pending | pending | unsupported |
| Linux arm64 | production candidate | pending; FYLO v26.30.06 ships `fylo-linux-arm64` | pending | pending | unsupported |
| Linux amd64 | production candidate | pending; FYLO v26.30.06 ships `fylo-linux-x64` | pending | pending | unsupported |
| Windows amd64 | preview candidate | pending; FYLO v26.30.06 ships `fylo-windows-x64.exe` | pending | FYLO NTFS parity shipped in v26.30.05; SESAME-side run pending | unsupported |
| Windows arm64 | not initially planned | pending artifact | pending | pending | unsupported |

## Evidence Required Per Row

- exact SESAME, FYLO, CHEX, and TTID versions, immutable commits, checksums, and
  signatures;
- host OS/build, architecture, filesystem, CPU, memory, and storage class;
- lifecycle and full-profile JSON reports;
- FYLO-native internal transaction crash/recovery results;
- local and platform-supported remote backup/restore results;
- package manifest verification, install, upgrade, rollback, and uninstall;
- mixed workload parameters, p50/p95/p99, allocation/goroutine/disk growth, and
  soak duration;
- known limitations and the person or automation that attested the run.
