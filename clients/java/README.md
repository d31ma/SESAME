# SESAME java client

A thin client that owns a local `sesame exec --loop` subprocess and speaks
the versioned NDJSON machine protocol over stdin/stdout. It never opens a
network connection: SESAME has no port.

The shim owns transport, framing, request correlation, and typed errors. It
never implements identity, authentication, or authorization semantics — those
stay in the SESAME executable, so every client answers identically.

## Contract test

The suite runs the same scenario every SESAME SDK runs, against real compiled
binaries rather than a mock: system operations, tenant and principal
lifecycle, identifier conflict, default-deny authorization through grant and
revocation, password login, session verification and revocation, and the
enumeration check that an unknown identifier is indistinguishable from a
known one.

```bash
cd clients/java
javac -d build Sesame.java SesameContractTest.java
java -cp build ma.del.sesame.SesameContractTest
```

Dependencies: the JDK only. The harness is plain `main`, because adding JUnit
would contradict the shim's dependency-free promise.

## Installing

There is no package registry. Download the client bundle from
[the release](https://github.com/d31ma/sesame/releases):

```bash
curl -fsSL https://github.com/d31ma/sesame/releases/latest/download/sesame-clients.tar.gz | tar -xz
```

Copy `java/Sesame.java` into `ma/del/sesame/` in your source tree:

```java
import ma.del.sesame.Sesame;
```

Every command above is exercised by `tools/verify-sdk-install.sh`, which
extracts the release tarball, copies the shim into a throwaway project, and
runs code against it. [docs/SDK_DISTRIBUTION.md](../../docs/SDK_DISTRIBUTION.md)
covers verification and what this model costs.

The client spawns a SESAME executable; the file does not carry one. Releases
publish native binaries alongside the client bundle.
