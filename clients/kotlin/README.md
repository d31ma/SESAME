# SESAME Kotlin client

A thin client that owns a local `sesame exec --loop` subprocess and speaks the
versioned NDJSON machine protocol over stdin/stdout. It never opens a network
connection: SESAME has no port.

The shim owns transport, framing, request correlation, and typed errors. It
never implements identity, authentication, or authorization semantics — those
stay in the SESAME executable, so every client answers identically.

This is a **server-side** client for JVM backends such as Ktor and Spring
Boot. It has no Android or WebView variant: SESAME has no embeddable engine,
and an on-device copy could never be authoritative for shared security state.

## Contract test

The suite runs the same scenario every SESAME SDK runs, against real compiled
binaries rather than a mock: system operations, tenant and principal
lifecycle, identifier conflict, default-deny authorization through grant and
revocation, password login, session verification and revocation, and the
enumeration check that an unknown identifier is indistinguishable from a
known one.

```bash
cd clients/kotlin
kotlinc Sesame.kt ContractTest.kt -include-runtime -d sesame-kotlin-contract.jar
java -jar sesame-kotlin-contract.jar
```

Dependencies: `kotlin-stdlib`, which is the language runtime rather than a
third-party library, and nothing else. The shim carries a small JSON
reader and writer rather than a serialization library; it handles the
protocol's shapes and rejects the rest, including duplicate object keys.

## Installing

There is no package registry. Download the client bundle from
[the release](https://github.com/d31ma/sesame/releases):

```bash
curl -fsSL https://github.com/d31ma/sesame/releases/latest/download/sesame-clients.tar.gz | tar -xz
```

Copy `kotlin/Sesame.kt` into `ma/del/sesame/` in your source tree:

```kotlin
import ma.del.sesame.Client
```

This is the one shim with a runtime dependency: `kotlin-stdlib`, which is the
language runtime and which any Kotlin project already has.

Every command above is exercised by `tools/verify-sdk-install.sh`, which
extracts the release tarball, copies the shim into a throwaway project, and
runs code against it. [docs/SDK_DISTRIBUTION.md](../../docs/SDK_DISTRIBUTION.md)
covers verification and what this model costs.

The client spawns a SESAME executable; the file does not carry one. Releases
publish native binaries alongside the client bundle.
