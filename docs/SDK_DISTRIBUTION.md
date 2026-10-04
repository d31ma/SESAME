# Distribution

A SESAME release ships the `sesame` engine for each built platform, a
`SHA256SUMS` file, an SPDX SBOM and a signed build attestation for every
binary. There is no client bundle. Applications reach SESAME in one of three
ways, and all three end at the same engine, which makes every security
decision.

| Way | For | What you take from SESAME |
| --- | --- | --- |
| HTTP through the Yon host | any language that can send an HTTP request | the engine binary and this repository's Yon project (`app/`), served by `ty` |
| The Go package | Go applications that host the engine themselves | `github.com/d31ma/sesame/app/server/packages/sesame` |
| The machine protocol | any language that spawns the engine itself | the engine binary; you write the NDJSON transport |

## Get the engine

Download the binary for your platform from
[the release](https://github.com/d31ma/sesame/releases) and verify it:

```bash
gh attestation verify sesame-linux-amd64 --repo d31ma/sesame
```

The release workflow verifies those attestations itself before publishing.
`go install github.com/d31ma/sesame/cmd/sesame@<version>` builds the same
engine from source.

## HTTP through the Yon host

`app/` is a Tachyon Yon project. `ty serve app` answers
`POST /api/v1/<family>/<operation>` for every operation that may safely leave
the machine, and the OpenID provider's standard endpoints under `/oidc`.
Callers sign in with the `Sesame-Session` header. Start with
[the Yon operator guide](YON.md); the route families are described in
[directory](yon/directory.md), [authentication](yon/authn.md),
[OAuth and OpenID Connect](yon/oidc.md) and
[federation, SAML and SCIM](yon/federation.md).
[ADR 0007](adr/0007-sesame-ships-a-yon-host-project.md) records why the host
works this way.

`api/machine/v1/operations.json` records, for every operation, how it is
reached over HTTP: `routed` (its RPC routes), `standard_endpoint` (served only
by a standard protocol route), `command_line_only` (`tenant.bootstrap`,
`admin.bootstrap`) or `not_routed_for_security`
(`federation.login_exchange`). `test/contract` checks that record against the
controllers' route annotations, so a route cannot appear or disappear without
the manifest saying so.

## SDK clients: Tachyon remotes

A Tachyon Yon application calls the Yon host through SESAME's generated
remotes instead of a hand-written HTTP client. `remotes/<language>/server/`
holds, for each language, one `@HTTPClient` contract per route family
(`SesameSystemClient`, `SesameAuthnClient`, ...), one `SesameSetup` and one
`SesameTransportHelper`, which owns SESAME's HTTPS origin (`sesame.origin`).
Each language's README covers copying them in, `outgoing.hosts`, the
authentication headers and the `{"status", "body"}` answer:
[Go](../remotes/go/README.md), [TypeScript](../remotes/typescript/README.md),
[Python](../remotes/python/README.md), [Java](../remotes/java/README.md),
[Kotlin](../remotes/kotlin/README.md), [C#](../remotes/csharp/README.md),
[PHP](../remotes/php/README.md), [Ruby](../remotes/ruby/README.md) and
[Dart](../remotes/dart/README.md). [Rust](../remotes/rust/README.md) is
same-host / development only: Rust Yon handlers have no TLS-capable HTTP
dependency at Tachyon a7ccbfff, so its transport accepts only a loopback `http`
origin. It is not a production-supported client.

`go run ./tools/remotes/generate` writes them from
`api/machine/v1/operations.json` and the templates in
`tools/remotes/templates/<language>/`; a new language is one new template
folder. `test/contract/remotes_test.go` fails when the committed files differ
from the generator's output, when a routed route has no remote method or more
than one, or when a remote names a route that the manifest does not list.

## The Go package

```bash
go get github.com/d31ma/sesame/app/server/packages@<commit>
```

```go
import "github.com/d31ma/sesame/app/server/packages/sesame"
```

It is its own module, `github.com/d31ma/sesame/app/server/packages`, standard
library only, and it is the transport the Yon controllers use. SESAME's CalVer
tags are not semantic import versions for a nested module, so Go resolves it
at a commit as a pseudo-version: use the commit of the release whose engine
you run. The package's
[README](../app/server/packages/README.md) covers its API.

Earlier releases published it as `github.com/d31ma/sesame/clients/go/sesame`.
Change that import path when you upgrade.

## The machine protocol

`sesame exec --loop` reads one NDJSON request per line on stdin and writes one
response per line on stdout. [The protocol reference](../api/machine/v1/README.md)
and its [RFC](rfcs/0001-machine-protocol-v1.md) define the framing, the
startup compatibility check and every operation. A host that must run an
operation the Yon host does not route, such as `federation.login_exchange`,
uses this or the Go package.

## Migrating from the retired language SDKs

Releases up to 26.33.02 shipped `sesame-clients.tar.gz` with one copy-in file
for Node.js, Python, Rust, Java, Kotlin, C#, PHP, Ruby and Dart. Those files are
no longer maintained or shipped. Each language moves to one of the ways above:

| Former SDK | Move to |
| --- | --- |
| Node.js / TypeScript (`sesame.mjs`) | HTTP through the Yon host with `fetch`, or spawn `sesame exec --loop` with `child_process` |
| Python (`sesame.py`) | HTTP through the Yon host with `urllib.request`, or spawn `sesame exec --loop` with `subprocess` |
| Rust (`sesame.rs`) | HTTP through the Yon host, or spawn `sesame exec --loop` with `std::process::Command` |
| Java (`Sesame.java`) | HTTP through the Yon host with `java.net.http.HttpClient`, or spawn `sesame exec --loop` with `ProcessBuilder` |
| Kotlin (`Sesame.kt`) | as Java |
| C# (`Sesame.cs`) | HTTP through the Yon host with `HttpClient`, or spawn `sesame exec --loop` with `System.Diagnostics.Process` |
| PHP (`sesame.php`) | HTTP through the Yon host with `curl` or streams, or spawn `sesame exec --loop` with `proc_open` |
| Ruby (`sesame.rb`) | HTTP through the Yon host with `Net::HTTP`, or spawn `sesame exec --loop` with `Open3` |
| Dart (`sesame.dart`) | HTTP through the Yon host with `dart:io` `HttpClient`, or spawn `sesame exec --loop` with `Process.start` |
| Go (`clients/go/sesame`) | the Go package at its new import path |

Over HTTP, the operation's parameters become the request body and its result
the answer body, with the shapes of the machine protocol. Two things change:
the caller signs in with `Sesame-Session` instead of passing identifiers the
engine trusts, and errors arrive as an HTTP status with `{"code":"<code>"}`.
Tenant administration needs a session whose principal holds the
`Administrator` role in that tenant. `tenant.bootstrap` and `admin.bootstrap`
stay on the command line.

Spawning `sesame exec --loop` keeps what the old files did: one subprocess per
host process, owning one deployment. Send `system.version` first and refuse an
engine whose `protocol_version` you do not speak, as the old files did.

## Version matching

`VERSION` at the repository root is the single source of truth, and the
release workflow refuses to build when it disagrees with the tag. Release
versions use UTC-derived CalVer in `YY.WW.DD` form. The machine protocol
version is a separate number, currently `1`; the Go package checks it against
the engine at startup and refuses a mismatch.

## How this is proven

- `go test ./test/contract` checks the operation manifest against the engine's
  dispatch table, the protocol reference and the Yon controllers.
- CI runs the Go package's contract scenario against a real compiled engine
  (`cd app/server/packages && go test ./...`).
- `ty test app --coverage` runs the Yon host's tests against a real engine. It runs
  in the local release gate, not in CI, until Tachyon publishes a `ty` release
  that CI can install; [docs/YON.md](YON.md#continuous-integration) tracks
  that.
