/** The machine protocol version this client speaks. */
export declare const PROTOCOL_VERSION: string

export interface StartOptions {
    binary?: string
    deployment?: string
    fyloBinary?: string
    fyloRoot?: string
    stderr?: 'ignore' | 'inherit' | 'pipe'
    /** Suppresses the protocol handshake. For tests only. */
    skipCompatibilityCheck?: boolean
}

/** Build metadata plus what the engine can be asked to do. */
export interface Info {
    name: string
    version: string
    commit: string
    built_at: string
    go_version: string
    os: string
    arch: string
    protocol_version: string
    operations: string[]
}

export interface Identifier {
    namespace: string
    value: string
}

export interface Tenant {
    tenant_id: string
    name: string
    status: string
}

export interface TenantBootstrapResult {
    tenant: Tenant
    created: boolean
}

export interface Principal {
    principal_id: string
    tenant_id: string
    kind: 'human' | 'workload'
    status: 'active' | 'suspended'
    identifier: { namespace: string; value: string }
}

export interface Permission {
    action: string
    resource: string
}

export interface Role {
    role_id: string
    tenant_id: string
    name: string
    permissions: Permission[]
}

export interface Group {
    group_id: string
    tenant_id: string
    name: string
}

export interface Grant {
    grant_id: string
    tenant_id: string
    principal_id?: string
    group_id?: string
    role_id: string
}

export interface AdminBootstrapResult {
    tenant: Tenant
    role: Role
    administrator: Principal
    grant: Grant
    created: boolean
}

export interface DecisionRequest {
    tenant_id: string
    principal_id: string
    action: string
    resource: string
}

export interface Decision {
    decision_id: string
    decision: 'allow' | 'deny'
    reason_code: string
    policy_version: number
}

export interface Status {
    status: string
    reason_code?: string
}

export class ProtocolError extends Error {
    code: string
    retryable: boolean
    details?: Record<string, unknown>
}

export class Client {
    static start(options?: StartOptions): Promise<Client>
    request<T = unknown>(operation: string, parameters?: Record<string, unknown>): Promise<T>

    ping(): Promise<Status>
    version(): Promise<Record<string, string>>
    setPassword(principalId: string, password: string): Promise<{ password_set: boolean }>
    authnBegin(tenantId: string, identifier: Identifier): Promise<AuthenticationResult>
    authnVerifyPassword(transactionId: string, password: string): Promise<AuthenticationResult>
    authnComplete(transactionId: string, lifetimeSeconds?: number): Promise<IssuedSession>
    sessionVerify(sessionId: string, secret: string): Promise<Session>
    sessionRevoke(sessionId: string, reason?: string): Promise<{ revoked: boolean }>
    readiness(): Promise<Status>
    metrics(): Promise<Record<string, unknown>>

    tenantBootstrap(name: string): Promise<TenantBootstrapResult>
    tenantGetByName(name: string): Promise<Tenant>
    tenantGetById(tenantId: string): Promise<Tenant>

    adminBootstrap(tenantName: string, identifier: Identifier): Promise<AdminBootstrapResult>

    principalCreate(tenantId: string, kind: 'human' | 'workload', identifier: Identifier): Promise<Principal>
    principalGetById(principalId: string): Promise<Principal>
    principalGetByIdentifier(tenantId: string, identifier: Identifier): Promise<Principal>
    principalSuspend(principalId: string): Promise<Principal>

    roleCreate(tenantId: string, name: string, permissions: Permission[]): Promise<Role>
    groupCreate(tenantId: string, name: string): Promise<Group>
    groupMemberAdd(groupId: string, principalId: string): Promise<{ member: boolean }>
    groupMemberRemove(groupId: string, principalId: string): Promise<{ member: boolean }>

    grantCreate(tenantId: string, principalId: string, roleId: string): Promise<Grant>
    grantCreateForGroup(tenantId: string, groupId: string, roleId: string): Promise<Grant>
    grantRevoke(grantId: string): Promise<{ revoked: boolean }>

    decide(request: DecisionRequest, policyVersion?: number): Promise<Decision>
    decideBatch(requests: DecisionRequest[], policyVersion?: number): Promise<Decision[]>

    oidcClientRegister(
        tenantId: string,
        name: string,
        clientType: 'confidential' | 'public',
        redirectUris: string[],
        scopes?: string[],
        audience?: 'first_party' | 'third_party',
        postLogoutRedirectUris?: string[]
    ): Promise<ClientRegistration>
    oidcClientGet(clientId: string): Promise<OIDCClient>
    oidcClientRotateSecret(clientId: string): Promise<string>
    oidcClientDisable(clientId: string, reason?: string): Promise<{ disabled: boolean }>

    authorize(request: AuthorizationRequest): Promise<StartedInteraction>
    interactionGet(interactionId: string): Promise<Interaction>
    interactionComplete(
        interactionId: string,
        interactionSecret: string,
        sessionId: string,
        sessionSecret: string
    ): Promise<AuthorizationResponse>

    tokenExchange(request: TokenRequest): Promise<TokenResponse>
    refreshFamilyRevoke(familyId: string, reason?: string): Promise<{ revoked: boolean }>
    refreshFamilyGet(familyId: string): Promise<RefreshFamily>

    consentGrant(
        sessionId: string,
        sessionSecret: string,
        clientId: string,
        scopes: string[]
    ): Promise<Consent>
    consentWithdraw(principalId: string, clientId: string): Promise<{ withdrawn: boolean }>
    consentGet(principalId: string, clientId: string): Promise<Consent>

    standardsDispatch(request: StandardsRequest): Promise<StandardsResponse>
    discovery(endpoints?: DiscoveryEndpoints): Promise<ProviderMetadata>
    signingKeys(): Promise<JWKS>
    introspect(clientId: string, clientSecret: string, token: string): Promise<Introspection>
    revoke(clientId: string, clientSecret: string, token: string): Promise<{ acknowledged: boolean }>
    logout(
        idTokenHint: string,
        postLogoutRedirectUri?: string,
        state?: string
    ): Promise<LogoutResult>

    passkeyRegisterBegin(principalId: string): Promise<PasskeyRegistrationRequest>
    passkeyRegisterFinish(
        principalId: string,
        attestationObject: Uint8Array,
        clientDataJson: Uint8Array
    ): Promise<Passkey>
    passkeyList(principalId: string): Promise<Passkey[]>
    passkeyRemove(credentialId: string): Promise<{ removed: boolean }>
    passkeyOptions(transactionId: string): Promise<PasskeyAuthenticationRequest>
    verifyPasskey(
        transactionId: string,
        credentialId: string,
        authenticatorData: Uint8Array,
        clientDataJson: Uint8Array,
        signature: Uint8Array
    ): Promise<AuthenticationResult>

    checkCompatibility(): Promise<Info>
    requireOperations(...operations: string[]): Promise<Info>

    close(): Promise<void>
}

/** A SESAME binary this client cannot speak to. */
export class IncompatibleEngineError extends Error {
    clientProtocolVersion: string
    engineProtocolVersion: string
    engineVersion: string
    missingOperations: string[]
}

/** A registered relying party. It never carries secret material. */
export interface OIDCClient {
    client_id: string
    tenant_id: string
    name: string
    client_type: 'confidential' | 'public'
    redirect_uris: string[]
    scopes: string[]
    audience: 'first_party' | 'third_party'
    post_logout_redirect_uris?: string[]
    disabled?: boolean
}

/** The secret is the only copy that will ever exist. */
export interface ClientRegistration {
    client: OIDCClient
    client_secret?: string
}

/** PKCE is required: the method must be S256. */
export interface AuthorizationRequest {
    client_id: string
    redirect_uri: string
    response_type: 'code'
    scopes: string[]
    state?: string
    nonce?: string
    code_challenge: string
    code_challenge_method: 'S256'
}

export interface StartedInteraction {
    interaction_id: string
    interaction_secret: string
    tenant_id: string
    client_id: string
    client_name: string
    scopes: string[]
    expires_at: string
}

export interface Interaction {
    interaction_id: string
    tenant_id: string
    client_id: string
    redirect_uri: string
    scopes: string[]
    status: string
    expires_at: string
}

export interface AuthorizationResponse {
    redirect_uri: string
    code: string
    state?: string
}

export interface TokenRequest {
    grant_type: 'authorization_code' | 'refresh_token'
    code?: string
    redirect_uri?: string
    client_id: string
    client_secret?: string
    code_verifier?: string
    refresh_token?: string
    /** May narrow the granted scopes on a refresh. It can never widen them. */
    scope?: string
}

/** refresh_token is present only when the grant carries offline_access, and
 *  it replaces the token that was presented. */
export interface TokenResponse {
    access_token: string
    id_token: string
    token_type: string
    expires_in: number
    scope: string
    refresh_token?: string
}

export interface RefreshFamily {
    family_id: string
    tenant_id: string
    client_id: string
    session_id: string
    started_at: string
    expires_at: string
    revoked?: boolean
    revoked_reason?: string
}

export interface Consent {
    principal_id: string
    client_id: string
    tenant_id: string
    scopes: string[]
    granted_at: string
    withdrawn?: boolean
}

/** Host route paths. The engine composes them under the configured issuer
 *  and refuses any that would leave that origin. */
export interface DiscoveryEndpoints {
    authorization_endpoint?: string
    token_endpoint?: string
    jwks_uri?: string
    introspection_endpoint?: string
    revocation_endpoint?: string
    end_session_endpoint?: string
}

export interface StandardsRequest {
    endpoint: 'oidc.authorization' | 'oidc.discovery' | 'oidc.introspection'
        | 'oidc.jwks' | 'oidc.logout' | 'oidc.revocation' | 'oidc.token'
    method: 'GET' | 'POST'
    query?: Record<string, string[]>
    form?: Record<string, string[]>
    authorization?: string
    dpop?: string
    http_uri?: string
    endpoints?: DiscoveryEndpoints
}

export interface StandardsInteraction {
    kind: 'interaction'
    interaction_id: string
    interaction_secret: string
    client_id: string
    client_name: string
    scopes: string[]
    expires_at: string
}

export interface StandardsResponse {
    contract_version: '1'
    status: number
    headers?: Record<string, string>
    body?: unknown
    action?: StandardsInteraction
}

export interface ProviderMetadata {
    issuer: string
    authorization_endpoint: string
    token_endpoint: string
    jwks_uri: string
    introspection_endpoint?: string
    revocation_endpoint?: string
    end_session_endpoint?: string
    scopes_supported: string[]
    response_types_supported: string[]
    grant_types_supported: string[]
    subject_types_supported: string[]
    id_token_signing_alg_values_supported: string[]
    code_challenge_methods_supported: string[]
    token_endpoint_auth_methods_supported: string[]
    claims_supported: string[]
}

export interface JWK {
    kty: string
    use: string
    alg: string
    kid: string
    crv: string
    x: string
    y: string
}

export interface JWKS {
    keys: JWK[]
}

/** Every field other than active is absent when the token is not active. */
export interface Introspection {
    active: boolean
    scope?: string
    client_id?: string
    sub?: string
    aud?: string
    iss?: string
    exp?: number
    iat?: number
    nbf?: number
    jti?: string
    token_type?: string
    sid?: string
    tenant_id?: string
}

export interface LogoutResult {
    redirect_uri?: string
    state?: string
    client_id: string
    principal_id: string
    session_id: string
    session_revoked: boolean
}

/** A registered credential: a public key and a counter, nothing private. */
export interface Passkey {
    credential_id: string
    principal_id: string
    tenant_id: string
    public_key: string
    sign_count: number
    user_verified: boolean
    registered_at: string
}

export interface PasskeyRegistrationRequest {
    principal_id: string
    challenge: string
    relying_party_id: string
    origin: string
    expires_at: string
}

export interface PasskeyAuthenticationRequest {
    transaction_id: string
    challenge: string
    relying_party_id: string
    origin: string
    credential_ids: string[]
}

export interface AuthenticationResult {
    transaction_id: string
    state: string
    assurance?: string
    failure_code?: string
    attempts_left: number
}

/** Returned once, at completion: session_secret is the only copy. */
export interface IssuedSession {
    session_id: string
    session_secret: string
    tenant_id: string
    principal_id: string
    expires_at: string
    assurance: string
}

export interface Session {
    session_id: string
    tenant_id: string
    principal_id: string
    status: string
    issued_at: string
    expires_at: string
    assurance: string
}
