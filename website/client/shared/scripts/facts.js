// Single source of truth for every number and list the site quotes.
//
// A marketing site is where a project quietly starts overstating itself: one
// page says nine SDKs, another says ten, and a third claims a protocol that
// has never been run against a real implementation. Everything countable lives
// here so a change lands in one place, and so a claim can be checked against
// the repository rather than against another page.

// Language shims in clients/. Each is one dependency-free file that owns a
// SESAME subprocess over the NDJSON machine protocol.
export const SDK_LANGUAGES = [
  'Go',
  'Node.js',
  'Python',
  'Rust',
  'Java',
  'Kotlin',
  'C#',
  'PHP',
  'Ruby',
  'Dart',
]
export const SDK_COUNT = SDK_LANGUAGES.length

// Operations in api/machine/v1/operations.json — the canonical surface, held
// in agreement with the engine's dispatch table, the protocol reference, and
// every SDK's source by test/contract.
export const OPERATION_COUNT = 85

// Release targets built by .github/workflows/release.yml.
export const PLATFORMS = [
  { label: 'Linux', arches: 'x86-64 · arm64' },
  { label: 'macOS', arches: 'Apple silicon · Intel' },
  { label: 'Windows', arches: 'x86-64' },
]

export const GITHUB = 'https://github.com/d31ma/sesame'
export const LICENSE = 'Apache-2.0'

// What SESAME implements, and what it deliberately does not claim. Both halves
// are shown on the site; the second is the more important one.
export const PROVEN = [
  {
    area: 'OAuth 2.0 / OIDC provider',
    detail:
      'Authorization code flow with mandatory PKCE, rotating refresh families with reuse detection, discovery, introspection, revocation, consent, and RP-initiated logout.',
  },
  {
    area: 'Device grant, PAR, and DPoP',
    detail:
      'RFC 8628 for inputs a browser cannot reach, RFC 9126 to move the authorization request onto an authenticated back channel, and RFC 9449 to bind an access token to a key its holder proves per request.',
  },
  {
    area: 'Authentication',
    detail:
      'Argon2id passwords with a parameter-upgrade path, TOTP with durable replay prevention, single-use recovery codes, and WebAuthn passkeys with clone detection.',
  },
  {
    area: 'Authorization',
    detail:
      'Deterministic default-deny decisions over roles, grants, groups, and bounded context conditions, with stable reasons and a versioned policy snapshot.',
  },
  {
    area: 'Federation and provisioning',
    detail:
      'Inbound OIDC federation, SCIM 2.0 users and groups, and inbound SAML 2.0 with an in-tree XML canonicalizer that refuses every ambiguous document.',
  },
  {
    area: 'Durability',
    detail:
      'A hash-chained security ledger on FYLO with rebuildable projections, verified snapshots, and restart evidence run against a real FYLO runtime.',
  },
  {
    area: 'Ten drop-in clients',
    detail:
      'One dependency-free file per language, each holding the whole operation surface. A contract test resolves every operation against every shim, so a capability cannot ship in one language and quietly miss another.',
  },
]

// Built but not yet proven to an outside standard. Every entry here is
// something the code does and the evidence does not yet justify claiming, so
// each is closable by running something rather than by writing something.
//
// Two entries were removed deliberately: LDAP/proxy gateways and high
// availability are not built at all, so they belong in the roadmap rather than
// beside features. Both remain documented where an operator will actually hit
// them — the single-writer constraint under "Explicit v1 Limitations" in
// docs/THREAT_MODEL.md, and the gateways in ADR 0006 and the project plan.
//
// Neither column on the site is labelled — the second is drawn as provisional
// rather than captioned — so each entry's detail text is the only thing saying
// what is missing. Keep it plain.
export const NOT_CLAIMED = [
  {
    area: 'OpenID certification',
    detail:
      'The provider surface is driven over real TLS by a relying party in test/interop — discovery, PKCE, ID-token claims, single-use codes. Certification is self-certification against the OpenID Foundation suite, and that submission has not been made, so SESAME is not certified.',
  },
  {
    area: 'SAML interoperability',
    detail:
      'Proven end to end against a real Keycloak in test/interop — which is how a namespace defect no fixture had ever produced was found and fixed. Okta, Entra ID, Google Workspace, and Shibboleth are still unproven; treat any provider not listed as untested.',
  },
  {
    area: 'Production support',
    detail:
      'This is a developer preview. A repeatable restore, upgrade/rollback, and soak evidence runner exists, but no release has passed its 72-hour native gate or an independent security review. No version is supported for production use.',
  },
]
