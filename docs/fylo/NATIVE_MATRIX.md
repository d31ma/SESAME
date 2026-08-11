# FYLO Native Evidence Matrix

This matrix records evidence for exact FYLO/CHEX/TTID candidate sets. A green
cross-build is not native evidence. Each supported row must run on the named
operating system, architecture, and filesystem using the packaged artifacts
that would ship with SESAME.

## Current Evidence

| Date | Host | Filesystem | FYLO identity | Artifact SHA-256 | Profile | Result | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-08-11 | macOS 26.5.2 arm64, Apple M4, 16 GiB; SESAME harness `darwin/amd64` under Rosetta 2 | local APFS | runtime 26.33.02, protocol 1, target `macos-x64`, `release`, commit `e236162508f6789f980fa7ca136a6671938030cb`, CHEX 26.32.02, TTID 26.32.03 | `551e72291a7085536f5de360807dbe93a149826f2c0e6bbd7fe56b2e34abc545` | lifecycle, 10 consecutive `full` profiles, opt-in FYLO integration, and TLS/OIDC host interoperability; checksum and GitHub attestation verified before use | pass | translated x64 compatibility evidence only; native x64 hardware and the release package gate remain pending |
| 2026-08-10 | macOS 26.5.2 arm64, Apple M4, 16 GiB; SESAME harness `darwin/amd64` under Rosetta 2 | local APFS | runtime 26.33.01, protocol 1, target `macos-x64`, `release`, commit `ce95fbceca4981b20ce0c37fbd89acf9fd79215b`, CHEX 26.32.02, TTID 26.32.03 | `ff7ac0ba8ff401efdbe4286fbe93f43f8bff218ef5d0e1e021eb1ae678cb2bd7` | lifecycle, one qualification plus 10 consecutive `full` profiles, opt-in FYLO integration, and TLS/OIDC host interoperability; checksum and GitHub attestation verified before use | pass | translated x64 compatibility evidence only; native x64 hardware and the release package gate remain pending |
| 2026-08-03 | macOS 26.5.2 arm64, Apple M4, 16 GiB; SESAME harness native `darwin/arm64` | local default filesystem | runtime 26.31.06, protocol 1, target `macos-arm64`, `release`, commit `7724c3915d12ae4fa7cd5cea4f9830adf5bbb6b3`, CHEX/TTID 26.28.02 | `0eaa740eaf536c1fe5fe8d9eb24a42469b40566593a3641ffa693fc68b111a66` | `full` profile, 10 consecutive native runs, plus the opt-in integration and interoperability suites; checksum and signed-attestation verification before use | pass | first Rust-native release. Functionally equivalent, but p50 latency moved 11.0ms -> 159.7ms (FYLO #96) and a downgrade to 26.30.06 silently hides documents (FYLO #95) |
| 2026-07-25 | macOS 26.5.2 arm64, Apple M4, 16 GiB; SESAME harness native `darwin/arm64` | local default filesystem | runtime 26.30.06, protocol 1, target `macos-arm64`, `release`, commit `39f57b5cf3120c9b9b3b4ead9e749b47b76ac4f0`, CHEX/TTID 26.28.02 | `ae39a2b66ea9771766f3f3d6b3d0d1b01e1b3842a45aa0389535109b91bdee50` | `full` profile, 10 consecutive native runs plus the opt-in integration suite with and without the development-build exception, checksum and signed-attestation verification before use | pass | native release-candidate evidence; SESAME packaged artifact still pending |
| 2026-07-24 | macOS 26.5.2 arm64, Apple M4, 16 GiB; SESAME harness native `darwin/arm64` | local default filesystem | runtime 26.30.05, protocol 1, target `macos-arm64`, `release`, commit `f30ee792d7cd408be6b8b157e84a113d2877af72`, CHEX/TTID 26.28.02 | `6fe196da20baa703a4da79b7add072f6998ce24effa1e84b8d508350048ad8f5` | `full` profile including bounded cursor-paged ledger retrieval, 10 consecutive native runs plus one opt-in integration-test run, checksum and signed-attestation verification before use | pass | native release-candidate evidence; SESAME packaged artifact still pending |
| 2026-07-23 | macOS 26.5.2 arm64, Apple M4, 16 GiB; SESAME harness `darwin/amd64` under translation | local default filesystem | runtime 26.30.04, protocol 1, target `macos-arm64`, `development-compiled`, commit `unknown`, CHEX/TTID 26.28.02 | `5d34a355a502ba2e3c69ac7015a8707b65c1213eef588befbb5300b360b21a47` | finalized `full` profile, 10 consecutive integration runs plus one recorded JSON report | pass | superseded by the 2026-07-24 release-candidate row |

Across the ten consecutive 2026-08-11 v26.33.02 x64 runs, admitted
mixed-operation latency ranged over p50 18.2–21.0 ms, p95 22.5–28.7 ms, and
p99 26.2–38.9 ms. The preceding v26.33.01 x64 runs ranged over
17.2–18.2/19.6–22.0/20.2–32.0 ms. Both confirm FYLO #96's fix under
translation, but neither is a native x64 benchmark. Across the ten 2026-08-03
v26.31.06 native arm64 runs,
the corresponding medians were 159.7/188.2/202.8 ms. Across the ten 2026-07-25
v26.30.06 runs, admitted mixed-operation latency
ranged over p50 10.6–10.8 ms, p95 11.5–12.4 ms, and p99 12.4–17.6 ms. The ten
preceding v26.30.05 runs ranged over p50 10.7–11.1 ms, p95 12.2–13.4 ms, and
p99 13.5–21.2 ms; the two sets overlap, so this is not evidence of a
regression or an improvement in either direction.
Run duration varies because it includes FYLO process startup and teardown;
these numbers are not a capacity commitment.

## Candidate Coverage

| Target | Release tier under consideration | Native full profile | FYLO transaction crash evidence | Native backup/restore | Promotion state |
| --- | --- | --- | --- | --- | --- |
| macOS arm64 | production candidate | latest native evidence is signed FYLO v26.31.06; v26.33.02 native rerun pending | FYLO release qualification covers internal crash phases; SESAME package evidence pending | cold local restore passed; external filesystem-snapshot drill pending | blocked on a packaged SESAME artifact, distinct-version upgrade/rollback, v26.33.02 native rerun, remote restore, and 72-hour limits |
| macOS amd64 | production candidate | v26.33.02 full profile and integration pass under Rosetta 2; native x64 hardware pending | FYLO release evidence available; SESAME package evidence pending | cold local restore passed under translation | unsupported |
| Linux arm64 | production candidate | pending; FYLO v26.33.02 ships `fylo-linux-arm64` | pending | pending | unsupported |
| Linux amd64 | production candidate | pending; FYLO v26.33.02 ships `fylo-linux-x64` | pending | pending | unsupported |
| Windows amd64 | preview candidate | pending; FYLO v26.33.02 ships `fylo-windows-x64.exe` | pending | FYLO filesystem recovery parity shipped; SESAME-side run pending | unsupported |
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
