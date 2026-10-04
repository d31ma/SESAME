# Go Client

This folder is the native Go module of SESAME's Yon host project
([ADR 0007](../../docs/adr/0007-sesame-ships-a-yon-host-project.md)). The Yon
controllers use it as their engine transport, and Go host applications import
it directly. The Go client starts one local SESAME executable in persistent NDJSON
mode:

```go
client, err := sesame.Start(ctx, sesame.Options{Binary: "/opt/sesame/sesame"})
if err != nil {
    return err
}
defer client.Close()

if err := client.Ping(ctx); err != nil {
    return err
}
```

Import path:

```text
github.com/d31ma/sesame/server/packages/sesame
```

The client exposes typed methods for the complete machine-operation manifest,
including identity lifecycle, authentication, authorization, OIDC, federation,
SAML, SCIM, and the framework-neutral `StandardsDispatch` host boundary.
Security and protocol semantics remain in the SESAME executable.

Host frameworks translate their request object into `StandardsRequest` and
apply the returned `StandardsResponse`; see the
[host-adapter contract](../../api/standards/v1/README.md). The Go reference
translation is under
[`examples/hostserver`](../../examples/hostserver/standards.go).

A client owns its subprocess. In the initial topology, one host application
process owns one client, one SESAME subprocess, and one authoritative FYLO data
root. Do not create another client or application replica against that root.
SESAME does not open a network listener; the host application owns HTTP, TLS,
routing, and middleware.

## Installing

```bash
go get github.com/d31ma/sesame/server/packages@<commit>
```

Go is the one SESAME client not distributed as a file to copy. It is its own
module, `github.com/d31ma/sesame/server/packages`, and Go resolves it at a
commit as a pseudo-version. The module uses the Go standard library only, so
importing it adds nothing else to your module graph.
Earlier releases published it as `github.com/d31ma/sesame/clients/go/sesame`;
change that import path when you upgrade.
[docs/SDK_DISTRIBUTION.md](../../docs/SDK_DISTRIBUTION.md) covers verification
and what this model costs.

The client spawns a SESAME executable; the file does not carry one. Releases
publish native binaries alongside the client bundle.
