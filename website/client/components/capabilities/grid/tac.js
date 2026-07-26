export default class extends Tac {
  capabilities = [
    {
      area: 'Authenticate',
      color: 'primary',
      title: 'Passkeys first, passwords properly',
      text: 'WebAuthn passkeys with sign-counter clone detection, Argon2id passwords with a parameter-upgrade path, TOTP, and single-use recovery codes. A code is spent durably, so a replay fails inside its own window and across a restart.',
    },
    {
      area: 'Authorize',
      color: 'primary',
      title: 'Decisions you can explain',
      text: 'Default deny over roles, grants, groups, and bounded context conditions. Every decision returns a stable reason and the policy version it was made under, so an audit answers "why" and not just "no".',
    },
    {
      area: 'Single sign-on',
      color: 'success',
      title: 'OIDC provider, with PKCE mandatory',
      text: 'Authorization code flow, rotating refresh families that revoke the whole family on reuse, discovery, introspection, revocation, consent, and RP-initiated logout. There is no grant-types field, so implicit and password can never be switched on.',
    },
    {
      area: 'Federate',
      color: 'success',
      title: 'Inbound OIDC and SAML 2.0',
      text: 'Bring identities from an existing provider. SAML verification refuses every ambiguous document rather than choosing between readings, which is what defeats signature wrapping.',
    },
    {
      area: 'Provision',
      color: 'success',
      title: 'SCIM 2.0 users and groups',
      text: 'A directory can create, patch, and deprovision principals and group membership. Reconciliation is idempotent, because directories re-send full state rather than diffs.',
    },
    {
      area: 'Account for',
      color: 'warning',
      title: 'A ledger, not a log file',
      text: 'Every security-relevant change is a hash-chained event on FYLO. Projections are rebuildable, snapshots are verified, and revocation survives a restart with a defined propagation bound.',
    },
  ]
}
