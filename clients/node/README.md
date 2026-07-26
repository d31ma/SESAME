# SESAME Node Client

A thin Node client for a local SESAME process. It owns process lifecycle,
NDJSON framing, and typed transport errors; identity and authorization
semantics stay in the SESAME executable. Node standard library only.

```js
import { Client, ProtocolError } from './sesame.mjs'

const client = await Client.start({ binary: '/path/to/sesame', deployment: '/path/to/deployment' })
try {
    const admin = await client.adminBootstrap('acme', { namespace: 'email', value: 'admin@example.com' })
    const decision = await client.decide({
        tenant_id: admin.tenant.tenant_id,
        principal_id: admin.administrator.principal_id,
        action: 'doc:read',
        resource: 'project:alpha'
    })
    if (decision.decision !== 'allow') {
        console.log('denied:', decision.reason_code)
    }
} catch (error) {
    if (error instanceof ProtocolError) {
        console.error(error.code, error.retryable)
    }
    throw error
} finally {
    await client.close()
}
```

Start options: `binary`, `deployment`, `fyloBinary` with `fyloRoot`, and
`stderr`. Without storage options the child answers system operations and
returns `storage_not_configured` for the rest.

TypeScript declarations ship in `index.d.ts`. Errors carry a stable `code`
and `retryable` flag; see [the machine protocol](../../api/machine/v1/README.md).

Run the binary-backed contract suite from this directory with a Go toolchain
available:

```bash
node --test
```

## Installing

There is no package registry. Download the client bundle from
[the release](https://github.com/d31ma/sesame/releases):

```bash
curl -fsSL https://github.com/d31ma/sesame/releases/latest/download/sesame-clients.tar.gz | tar -xz
```

Copy `node/sesame.mjs` (and `sesame.d.mts` for TypeScript) into your project:

```js
import { Client } from './sesame.mjs'
```

Every command above is exercised by `tools/verify-sdk-install.sh`, which
extracts the release tarball, copies the shim into a throwaway project, and
runs code against it. [docs/SDK_DISTRIBUTION.md](../../docs/SDK_DISTRIBUTION.md)
covers verification and what this model costs.

The client spawns a SESAME executable; the file does not carry one. Releases
publish native binaries alongside the client bundle.
