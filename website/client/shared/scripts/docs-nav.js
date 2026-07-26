// The documentation map, in one place.
//
// The sidebar and the guide grid on /docs both render from this. They used to
// be separate lists, which is how a site ends up with a guide nobody can
// navigate to and a sidebar link to a page that was renamed.
//
// `test/contract/website_test.go` asserts every on-site href here resolves to
// a page that exists, so a broken link fails the build rather than a visitor.

const REPO = 'https://github.com/d31ma/sesame/blob/main'

export const DOCS_SECTIONS = [
  {
    title: 'Start',
    summary: 'Install, deployment, keys, and a first decision.',
    links: [
      {
        href: '/docs',
        title: 'Get started',
        text: 'From an empty directory to a first authorization decision, in six steps.',
      },
      {
        href: '/docs/concepts',
        title: 'Concepts',
        text: 'Tenant, principal, session, assurance, role, grant, decision — the nine words that mean something specific here.',
      },
      {
        href: `${REPO}/docs/CONFIGURATION.md`,
        title: 'Configuration and keys',
        text: 'Environment variables, the key boundary, and why passwords have no key or pepper to supply.',
        external: true,
      },
    ],
  },
  {
    title: 'Authentication',
    summary: 'Passwords, sessions, second factors, and tokens.',
    links: [
      {
        href: '/docs/authentication',
        title: 'Authentication and tokens',
        text: 'Turn a password into a session, and a session into a JWT. Includes why there is no password-to-JWT grant.',
      },
      {
        href: '/docs/mfa',
        title: 'MFA and step-up',
        text: 'TOTP enrolment and verification, recovery codes, and making a decision require a second factor.',
      },
      {
        href: '/docs/oauth-flows',
        title: 'Device grant, PAR, and DPoP',
        text: 'A device with no browser, an authorization request the browser cannot edit, and an access token that is not a bearer token.',
      },
    ],
  },
  {
    title: 'Authorization',
    summary: 'Default-deny decisions and where to enforce them.',
    links: [
      {
        href: '/docs/authorization',
        title: 'Authorization',
        text: 'Roles, grants, groups, conditions, batches, and trusted context you cannot supply yourself.',
      },
    ],
  },
  {
    title: 'Federation',
    summary: 'Bring identities in from somewhere else.',
    links: [
      {
        href: `${REPO}/docs/FEDERATION.md`,
        title: 'Inbound OIDC federation',
        text: 'Bring identities from an existing provider, including the host obligations SESAME cannot enforce.',
        external: true,
      },
      {
        href: `${REPO}/docs/SAML.md`,
        title: 'Inbound SAML 2.0',
        text: 'Signature verification, the wrapping defence, and an explicit list of what is not supported.',
        external: true,
      },
      {
        href: `${REPO}/docs/PROVISIONING.md`,
        title: 'SCIM 2.0 provisioning',
        text: 'Let a directory create, patch, and deprovision principals and group membership.',
        external: true,
      },
    ],
  },
  {
    title: 'Reference',
    summary: 'The compatibility surface and the security boundary.',
    links: [
      {
        href: '/docs/errors',
        title: 'Reason and error codes',
        text: 'Every code SESAME can return, what it means, and what to do about it.',
      },
      {
        href: `${REPO}/api/machine/v1/README.md`,
        title: 'Machine protocol reference',
        text: 'Every operation, its parameters, and its stable error codes — the canonical surface.',
        external: true,
      },
      {
        href: `${REPO}/docs/CONFORMANCE.md`,
        title: 'OpenID conformance',
        text: 'What is proven over TLS today, what a certification run needs, and why a .local domain can never have a public certificate.',
        external: true,
      },
      {
        href: `${REPO}/docs/THREAT_MODEL.md`,
        title: 'Threat model',
        text: 'What SESAME defends against, what it does not, and where the boundary sits.',
        external: true,
      },
    ],
  },
]

// Flattened, for the guide grid — which shows everything except the page a
// reader is already standing on.
export const DOCS_LINKS = DOCS_SECTIONS.flatMap((section) => section.links)
