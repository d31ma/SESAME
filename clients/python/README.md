# SESAME Python Client

A thin Python client for a local SESAME process. It owns process lifecycle,
NDJSON framing, and typed transport errors; identity and authorization
semantics stay in the SESAME executable. Python standard library only,
requires Python 3.11 or newer.

```python
from sesame import Client, ProtocolError

with Client("/path/to/sesame", deployment="/path/to/deployment") as client:
    admin = client.admin_bootstrap("acme", "email", "admin@example.com")
    decision = client.decide({
        "tenant_id": admin["tenant"]["tenant_id"],
        "principal_id": admin["administrator"]["principal_id"],
        "action": "doc:read",
        "resource": "project:alpha",
    })
    if decision["decision"] != "allow":
        print("denied:", decision["reason_code"])
```

Constructor options: the executable path plus `deployment`, or `fylo_binary`
with `fylo_root`. Without storage options the child answers system operations
and returns `storage_not_configured` for the rest.

`ProtocolError` carries a stable `code` and `retryable` flag; see
[the machine protocol](../../api/machine/v1/README.md).

Run the binary-backed contract suite from this directory with a Go toolchain
available:

```bash
python3 -m unittest -v test_contract
```

## Installing

There is no package registry. Download the client bundle from
[the release](https://github.com/d31ma/sesame/releases):

```bash
curl -fsSL https://github.com/d31ma/sesame/releases/latest/download/sesame-clients.tar.gz | tar -xz
```

Copy `python/sesame.py` next to your code:

```python
import sesame
```

Every command above is exercised by `tools/verify-sdk-install.sh`, which
extracts the release tarball, copies the shim into a throwaway project, and
runs code against it. [docs/SDK_DISTRIBUTION.md](../../docs/SDK_DISTRIBUTION.md)
covers verification and what this model costs.

The client spawns a SESAME executable; the file does not carry one. Releases
publish native binaries alongside the client bundle.
