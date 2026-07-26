# Configuration

SESAME is configured in three places, and it is worth knowing which is which:

1. **The deployment directory** — created by `sesame init`. It holds validated
   configuration and the private keys. This is the durable, authoritative
   configuration.
2. **Environment variables** — how a process finds that deployment. They point
   at configuration; they are not configuration themselves.
3. **Flags and SDK options** — a per-invocation override of the above.

The precedence is always the same: **an explicit flag or option wins, then the
environment, then the built-in default.** That ordering is deliberate. An
operator debugging one command on a host that already exports
`SESAME_DEPLOYMENT` has to be able to point it somewhere else without
unsetting anything, and silently preferring the environment would make the
flag they just typed a lie.

## Environment variables

| Variable | Replaces | Read by |
| --- | --- | --- |
| `SESAME_BINARY` | the SDK's `binary` option | the SDK shim |
| `SESAME_DEPLOYMENT` | `--deployment` | the engine and every `sesame` command |
| `FYLO_BINARY` | `--fylo-binary` | the engine and every `sesame` command |
| `FYLO_ROOT` | `--fylo-root` | the engine and every `sesame` command |

Only `SESAME_BINARY` is read by the shim, because the shim is what decides
which executable to run. Everything else is read by the engine out of the
environment it inherits, which is why all ten SDKs support it identically and
none of them had to implement it.

**Every** command reads them, `sesame init` and `sesame doctor` included.
Those two were once the exceptions and it was the wrong way round: `init` is
the command that decides what every later command will find, so an operator
who has already exported `SESAME_DEPLOYMENT` has no reason to expect to repeat
it there of all places.

An explicit flag always wins over the environment. That ordering is what makes
the environment safe to export: an operator debugging one command on a host
that already sets `SESAME_DEPLOYMENT` can point it somewhere else without
unsetting anything, and preferring the environment would make the flag they
just typed a lie.

`SESAME_DEPLOYMENT` and the `FYLO_*` pair are alternatives, exactly as their
flags are. Setting both is refused rather than silently resolved.

**The two FYLO settings keep FYLO's own names.** SESAME runs FYLO as a child
that inherits this environment and reads `FYLO_ROOT` itself, so one variable
configures both sides. A `SESAME_FYLO_ROOT` beside it would be two names for
one value and a way for them to disagree. The deployment and the engine binary
are SESAME's own concepts with no FYLO equivalent, so they keep the prefix.

One difference is deliberate: FYLO defaults `FYLO_ROOT` to `./.fylo-data`, and
SESAME does not adopt that default. A sensible fallback for a document store
invoked ad hoc is a bad one for an identity engine, which would otherwise
create a store in whatever directory it happened to start in. An unset root
stays unset, and `FYLO_BINARY` and `FYLO_ROOT` are still required together.

### What this buys you

One environment configures the CLI and the application together, and neither
needs a SESAME-specific argument:

```bash
export SESAME_BINARY=/usr/local/bin/sesame
export SESAME_DEPLOYMENT=/var/lib/sesame
```

```bash
sesame init --fylo-binary /usr/local/bin/fylo --issuer https://id.example.com
sesame doctor
sesame admin bootstrap --name acme \
  --identifier-namespace email --identifier-value admin@acme.example
```

Note which variable is *not* exported there. `FYLO_BINARY` in the environment
selects the deployment-less mode, so exporting it beside `SESAME_DEPLOYMENT`
is refused by every runtime command — see the exclusivity note above. `init`
records the FYLO path in the deployment's `config.json`, so passing it as a
flag once is all that is ever needed.

```python
from sesame import Client

with Client() as client:            # no paths in application code
    decision = client.decide({...})
```

The same program then moves between a laptop, a container, and CI by changing
its environment rather than its source.

## Failing closed on a bad deployment

A missing or uninitialised deployment is refused at startup, before any
request is served, and the refusal says which of the two problems it is —
because the remedies differ:

```
sesame exec: deployment directory /var/lib/sesame does not exist;
create it with: sesame init --deployment /var/lib/sesame --fylo-binary /path/to/fylo
```

```
/var/lib/sesame is not a SESAME deployment: no config.json;
initialise it with: sesame init --deployment /var/lib/sesame --fylo-binary /path/to/fylo
```

The first is usually a typo or a volume that did not mount. The second is a
directory that exists but was never initialised.

**The SDKs surface this message.** The engine writes it to stderr and exits;
each shim captures the first 4 KiB of that stream during startup and attaches
it to the error it raises, then stops capturing once the engine is up. Without
that, a developer whose volume failed to mount would see only "the process
exited" and would have no way to learn why. If you supply your own stderr
destination, you get the stream itself and the shim does not capture.

## Keys, hashing, and salting

**You do not supply key material.** `sesame init` generates it, and there is
no option or environment variable that accepts a key. Three keys live in
`<deployment>/keys/`, written `0600`, outside every FYLO document:

| File | Algorithm | Protects |
| --- | --- | --- |
| `signing.key` | ECDSA P-256 (ES256), PKCS#8 PEM | the tokens relying parties verify. Only the public half is ever published, through JWKS |
| `secrets.key` | AES-256-GCM | secrets that must be read back rather than only compared — TOTP shared secrets, federation client secrets |
| `snapshot.key` | HMAC-SHA-256 | projection snapshots, so a tampered snapshot fails closed instead of seeding a forged projection |

`sesame doctor` verifies these exist, are the right length, and are not
group- or world-readable. It refuses a deployment whose keys any other account
can read.

### Passwords have no key

This is the part worth stating plainly, because it is the usual source of
confusion: **passwords are not encrypted, and there is no password key or
pepper to configure.**

A password is hashed with **Argon2id**, and the salt is generated per password
from the system CSPRNG — 16 random bytes, never reused, never derived from the
identifier. Salt and parameters are stored with the hash in the standard PHC
string, so an operator can audit the cost of a stored credential without
SESAME running:

```
$argon2id$v=19$m=65536,t=1,p=4$<salt>$<hash>
```

Verification is constant-time, and a verifier produced with weaker parameters
than the current ones is flagged for rehash on the next successful login, so
raising the cost does not require a password reset.

There is deliberately no pepper. A pepper is a second secret that must be
present to verify any password, and it buys protection only in the one
scenario where an attacker has the database but not the key. Against that,
it costs a key whose loss locks out every user permanently, and one more thing
to rotate correctly. Argon2id with a strong memory cost is the defence that
carries its weight here.

### Why keys are not accepted from the environment

Key material in an environment variable is readable in `/proc`, in
`docker inspect`, in crash dumps, and in any log that dumps the environment on
error. SESAME therefore does not accept keys that way.

For a container or Kubernetes deployment, mount the key directory as a secret
volume and point `SESAME_DEPLOYMENT` at it. That gets key material from a
secret manager without ever putting it in the process environment.

Rotation of the signing key, and any form of external key management, are
**not implemented yet**. Neither is claimed.
