# OpenID Connect conformance

**SESAME is not OpenID certified.** No conformance profile has been submitted,
and nothing in this repository should be read as a certification claim. This
document is the runbook for getting there and an honest account of what has
actually been proven.

## What is proven today

`test/interop` drives the example host over real TLS as a relying party:
discovery and JWKS, the full authorization code flow with PKCE, ID-token claim
wiring, single-use codes, and refusal of an unregistered redirect URI. Run it
with:

```bash
SESAME_INTEROP=1 \
  SESAME_FYLO_ALLOW_DEVELOPMENT=1 SESAME_FYLO_BUILD_TARGET=macos-arm64 \
  FYLO_BINARY=/absolute/path/to/fylo \
  go test -count=1 -timeout 10m -run TestHostServer ./test/interop
```

That is a self-test, not a conformance run. It proves the target is worth
pointing a certification suite at; it does not prove any profile passes.

### What it found

Two defects, both invisible to every test that existed before it.

**`end_session_endpoint` never reached the engine.** RP-initiated logout has
been implemented since Phase 4, the domain advertised the field, and the Go SDK
offered a typed one — but the machine handler had no such parameter, so the
strict decoder refused the *entire* discovery call. A host that named its
logout route did not get a document missing one entry; it got no document at
all, and no deployment could publish `end_session_endpoint`. The manifest tests
could not see it because they check operation *names*, not parameter shapes.
`test/contract/discovery_test.go` now compares the two field sets directly.

**An explicit `--deployment` collided with an inherited `FYLO_BINARY`.** The
deployment directory and the bare binary/root pair are alternatives and
presenting both is refused — correctly. But the refusal fired on a combination
nobody chose: a host application passing `--deployment` broke on any machine
whose environment exported `FYLO_BINARY`. An explicit choice of one mode now
suppresses the other's variables.

## Preparing a conformance target

The suite needs a provider it can reach over HTTPS, with a client it can use
and a user it can log in as.

### 1. A certificate a suite will trust

`.local` cannot work: it is reserved for multicast DNS by RFC 6762, and the
CA/Browser Forum baseline requirements forbid a public CA from issuing for
reserved or internal names. There is no paid tier or flag that changes this.

Use a domain you own with a DNS-01 challenge. It proves control by a TXT record
and needs no inbound connection, so `id.example.com` can resolve to a host
nobody else can reach:

```bash
certbot certonly --manual --preferred-challenges dns -d id.example.com
```

A self-signed certificate works for the local self-test above and will not work
for a hosted conformance run, whose browser must trust your chain.

### 2. An issuer that matches the listener

The engine composes every advertised endpoint under the configured issuer and
refuses any that would leave that origin. The issuer must therefore be the URL
the suite actually reaches:

```bash
export SESAME_DEPLOYMENT=./deploy
sesame init --fylo-binary /path/to/fylo --issuer https://id.example.com
sesame doctor
```

### 3. The host, with a seeded client

```bash
go run ./examples/hostserver \
  --sesame /usr/local/bin/sesame \
  --addr 0.0.0.0:443 \
  --tls-cert /etc/letsencrypt/live/id.example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/id.example.com/privkey.pem \
  --seed-password 'a password you choose' \
  --seed-client-redirects 'https://localhost.emobix.co.uk:8443/test/a/sesame/callback'
```

The seeded client's ID and secret are printed as one JSON line on stdout. The
redirect URI above is the conformance suite's callback; take the exact value
from your test plan rather than copying it from here.

`--seed-password` and `--seed-client-redirects` exist for test runs. They are
deliberately explicit flags: a host that silently created a credentialed
account on every boot would be a bad example to copy.

## Running the suite

The OpenID Foundation's conformance suite is open source and runs in Docker. It
is a multi-container application — MongoDB, a Java server, and a proxy — and
these steps are from its own documentation rather than from a run performed
here:

1. Clone `openid-certification/conformance-suite` and start it with the
   published Docker Compose file.
2. Create a test plan for the profile you are claiming. Start with **Basic OP**;
   `Config OP` is the cheapest first signal because it only reads discovery.
3. Configure the plan with your issuer, the seeded client ID and secret, and
   the user credentials.
4. Run the plan and export the logs.

Certification is **self-certification**: you submit the exported logs, a signed
declaration, and a fee to the OpenID Foundation, which lists the result. Until
that submission is accepted, the honest statement is the one at the top of this
file.

## What SESAME does not implement

These bound which profiles can pass, and none of them is a defect:

- **No implicit or hybrid flow.** `oidc_client` has no grant-types field at
  all, so implicit cannot be enabled by configuration. Profiles that require
  it cannot pass and are not targets.
- **No dynamic client registration** and no request object (JAR).
- **No UserInfo endpoint.** Claims travel in the ID token.
- **ES256 only** for signing. There is no `alg` negotiation.
- **PKCE is mandatory** for every client, which is stricter than the base
  profile requires.

## Where the pieces are

| Piece | Location |
| --- | --- |
| Provider surface over TLS | `examples/hostserver` |
| Relying-party self-test | `test/interop/hostserver_test.go` |
| Discovery parameter guard | `test/contract/discovery_test.go` |
| Protocol reference | `api/machine/v1/README.md` |
