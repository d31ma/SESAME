# Go Client

The initial Go client starts one local SESAME executable in persistent NDJSON
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
github.com/d31ma/sesame/clients/go/sesame
```

The client currently exposes process liveness, version metadata, and the raw
typed request boundary. It does not expose authentication or authorization
operations because those contracts have not been implemented.

A client owns its subprocess. In the initial topology, one host application
process owns one client, one SESAME subprocess, and one authoritative FYLO data
root. Do not create another client or application replica against that root.
SESAME does not open a network listener; the host application owns HTTP, TLS,
routing, and middleware.

## Installing

```bash
go get github.com/d31ma/sesame/clients/go/sesame@v0.1.0
```

Go is the one SESAME client not distributed as a file to copy. It lives inside
the engine's own module, so the tag resolves it like any other Go package and
vendoring would be a downgrade. The consequence worth knowing: importing it
puts `golang.org/x/crypto` and `golang.org/x/sys` in your module graph.
Every command above is exercised by `tools/verify-sdk-install.sh`, which
extracts the release tarball, copies the shim into a throwaway project, and
runs code against it. [docs/SDK_DISTRIBUTION.md](../../docs/SDK_DISTRIBUTION.md)
covers verification and what this model costs.

The client spawns a SESAME executable; the file does not carry one. Releases
publish native binaries alongside the client bundle.
