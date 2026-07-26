# SDK distribution

SESAME distributes its clients the way [FYLO](https://fylo.del.ma) does, and
for the same reason: each shim is a single dependency-free file, so the
simplest thing that works is to hand you the file.

**There is no package registry and no per-ecosystem package manifest.** Every
release ships `sesame-clients.tar.gz` alongside the engine binaries. You take
the one file for your language, drop it into your project, and call it.

## Get the engine

The clients spawn a SESAME executable and speak the machine protocol to it
over stdin/stdout. Download the binary for your platform from
[the release](https://github.com/d31ma/sesame/releases), and verify it:

```bash
gh attestation verify sesame-linux-amd64 --repo d31ma/sesame
```

## Get the client for your language

```bash
curl -fsSL https://github.com/d31ma/sesame/releases/latest/download/sesame-clients.tar.gz | tar -xz
# then copy e.g. clients/python/sesame.py into your project
```

| Language | File | Runtime dependencies |
| --- | --- | --- |
| Node/TS | `node/sesame.mjs` (+ `sesame.d.mts`) | none (stdlib) |
| Python | `python/sesame.py` | none (stdlib) |
| Rust | `rust/sesame.rs` | none (std) |
| Java | `java/Sesame.java` | none (JDK) |
| Kotlin | `kotlin/Sesame.kt` | `kotlin-stdlib` |
| C# | `csharp/Sesame.cs` | none (BCL) |
| PHP | `php/sesame.php` | none (ext-json) |
| Ruby | `ruby/sesame.rb` | none (stdlib) |
| Dart | `dart/sesame.dart` | none (SDK) |

The Java and Kotlin shims declare `package ma.del.sesame`, so they go in the
matching directory of your source tree. FYLO's equivalents sit in the default
package; SESAME's do not, because a default-package class cannot be imported
by a class that has a package, which would make the shim unusable in most real
projects.

### Go is the exception

Go is the one client not distributed as a file to copy. It lives inside the
engine's own module, so the tag resolves it like any other Go package:

```bash
go get github.com/d31ma/sesame/clients/go/sesame@v26.30.07
```

Vendoring it would be strictly worse than that. The consequence worth knowing:
importing it puts `golang.org/x/crypto` and `golang.org/x/sys` in your module
graph.

## Verifying what you downloaded

Every release carries `SHA256SUMS` covering the binaries and the client
tarball, and a signed build attestation for each:

```bash
gh attestation verify sesame-clients.tar.gz --repo d31ma/sesame
```

The release workflow verifies those attestations itself before publishing.

## Version matching

The client tarball is built from the same commit as the binaries in the same
release, so a client and the engine it talks to are paired by construction.
`VERSION` at the repository root is the single source of truth, and the
release workflow refuses to build when it disagrees with the tag.

Release versions use UTC-derived CalVer in `YY.WW.DD` form. Every SDK bundle
and the Go module tag share that SESAME release version. The machine protocol
version is a separate number, currently `1`, and every shim checks it against
the engine at startup and refuses a mismatch; see
[the machine protocol](../api/machine/v1/README.md).

## How this is proven

```bash
tools/package-clients.sh dist/sesame-clients.tar.gz   # what a release ships
tools/verify-sdk-install.sh                           # prove it can be used
```

The second builds the tarball via the first, extracts it, and for each of the
ten languages copies the shim into a throwaway project exactly as a developer
would, then compiles and runs code against it. CI runs it on every pull
request.

Packaging is a script rather than a `tar` line in each workflow because CI and
the release must produce identical archives, and because a naive `tar clients`
sweeps in whatever the contract tests last compiled — a release cut after
someone ran the C# suite would otherwise ship `.dll` and `.pdb` files inside a
bundle advertised as source. The packager excludes build output and then fails
if any compiled artifact survives.

That check matters more here than it would with registry packages. There is no
manifest declaring what a release contains, so nothing else stands between a
tag and a tarball that silently lacks someone's language. The release workflow
additionally asserts the archive contains every expected file before anything
is attested, so the two checks cover both directions: nothing missing, and
nothing compiled.

## What this costs

Being explicit about the trade:

- **No dependency resolver.** You copy a file; nothing tracks its version for
  you, and `npm outdated` will not tell you a new one exists. Upgrading means
  re-copying from a newer release.
- **No lockfile entry, no registry search, no registry vulnerability feed.**
  The shims have no third-party dependencies, so the surface those feeds watch
  is empty, but the tooling gap is real.
- **No transitive install.** A library that wants to depend on a SESAME client
  cannot express that as a dependency; it has to vendor the file too.

What it buys: one release, one version, one provenance chain, no publishing
credentials to hold or rotate, no package name that must keep meaning this
thing forever, and no per-ecosystem packaging toolchain in CI. The same model
FYLO runs, so a developer using both projects learns it once.

Registry publication is not foreclosed. The shims are ordinary source files;
adding manifests later is mechanical, and the cost of not having them is
listed above rather than hidden.

## Adding an eleventh SDK

`TestEveryClientIsAccountedFor` fails if a directory appears under `clients/`
that is neither in `distributedShims` nor the Go exception, so a new client
cannot arrive with no distribution story. Add the shim, add it to that list,
add a case to `tools/verify-sdk-install.sh`, add it to the release workflow's
archive-contents check, and add the row above.
