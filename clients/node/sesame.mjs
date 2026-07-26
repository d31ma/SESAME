// A thin Node client for a local SESAME process.
//
// The client owns process lifecycle, NDJSON framing, timeouts, and typed
// transport errors. Identity and authorization semantics remain in the SESAME
// executable. Dependencies: Node standard library only.

import { spawn } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { createInterface } from 'node:readline'

export const PROTOCOL_VERSION = '1'

// Bounds what a failing engine can make the caller hold: generous enough for
// a refusal and its remedy, short of anything worth worrying about.
const STARTUP_DIAGNOSTICS_BYTES = 4096
const MAX_FRAME_BYTES = 1 << 20
const CLOSE_TIMEOUT_MS = 2000

/** Encode binary WebAuthn values for transport. */
function base64Url(value) {
    return Buffer.from(value).toString('base64url')
}

/**
 * A SESAME binary this client cannot speak to. It names both sides, because
 * the fix is always to change one of them.
 */
export class IncompatibleEngineError extends Error {
    constructor({ clientProtocolVersion, engineProtocolVersion, engineVersion, missingOperations = [] }) {
        super(
            engineProtocolVersion !== clientProtocolVersion
                ? `sesame engine ${engineVersion} speaks machine protocol "${engineProtocolVersion}"; ` +
                  `this client speaks "${clientProtocolVersion}"`
                : `sesame engine ${engineVersion} does not support ${missingOperations.length} ` +
                  `operation(s) this client requires: ${missingOperations.join(', ')}`
        )
        this.name = 'IncompatibleEngineError'
        this.clientProtocolVersion = clientProtocolVersion
        this.engineProtocolVersion = engineProtocolVersion
        this.engineVersion = engineVersion
        this.missingOperations = missingOperations
    }
}

/** A stable error returned by the SESAME machine interface. */
export class ProtocolError extends Error {
    constructor({ code, message, retryable, details }) {
        super(`sesame protocol error ${code}: ${message}`)
        this.name = 'ProtocolError'
        this.code = code
        this.retryable = Boolean(retryable)
        this.details = details
    }
}

/** Owns one long-lived local SESAME subprocess. */
export class Client {
    #child
    #pending = []
    #closed = false
    #exit

    constructor(child) {
        this.#child = child
        this.#exit = new Promise((resolve) => child.once('exit', resolve))

        const lines = createInterface({ input: child.stdout })
        lines.on('line', (line) => {
            const waiter = this.#pending.shift()
            if (!waiter) return
            try {
                waiter.resolve(decodeResponse(waiter.requestId, line))
            } catch (error) {
                waiter.reject(error)
            }
        })
        child.once('exit', () => {
            this.#closed = true
            while (this.#pending.length > 0) {
                this.#pending.shift().reject(new Error('sesame process exited'))
            }
        })
    }

    /**
     * Launch a SESAME subprocess in persistent machine mode. Pass
     * `deployment` for a directory created by `sesame init`, or
     * `fyloBinary`/`fyloRoot` together for storage without snapshots.
     */
    static async start({
        // SESAME_BINARY names the engine when no option does; an explicit option still wins.
        binary = process.env.SESAME_BINARY || 'sesame',
        deployment,
        fyloBinary,
        fyloRoot,
        stderr = 'ignore',
        skipCompatibilityCheck = false
    } = {}) {
        const args = ['exec', '--loop']
        if (deployment) args.push('--deployment', deployment)
        if (fyloBinary || fyloRoot) args.push('--fylo-binary', fyloBinary ?? '', '--fylo-root', fyloRoot ?? '')
        // With no caller-supplied destination the startup window of stderr is
        // captured so a refusal can explain itself, and the rest is dropped.
        // The engine reports a missing deployment or an unusable FYLO root
        // this way and then exits; discarding it would leave the caller with
        // nothing but a dead process.
        const capture = stderr === 'ignore'
        const child = spawn(binary, args, {
            stdio: ['pipe', 'pipe', capture ? 'pipe' : stderr]
        })
        let startupDiagnostics = ''
        if (capture) {
            child.stderr.on('data', (chunk) => {
                if (startupDiagnostics.length < STARTUP_DIAGNOSTICS_BYTES) {
                    startupDiagnostics += chunk.toString()
                }
            })
        }
        const client = new Client(child)
        // A mismatched engine is found here rather than partway through a
        // security flow that then cannot finish. system.version needs no
        // storage, so this works before a FYLO root is configured.
        if (!skipCompatibilityCheck) {
            try {
                await client.checkCompatibility()
            } catch (error) {
                await client.close()
                const diagnostic = startupDiagnostics.trim()
                if (diagnostic) error.message += `: ${diagnostic}`
                throw error
            }
        }
        // The engine is up; its diagnostics are the host's business from here.
        startupDiagnostics = ''
        if (capture) child.stderr.resume()
        return client
    }

    /** Fails unless the engine speaks this client's machine protocol. */
    async checkCompatibility() {
        const version = await this.version()
        if (version.protocol_version !== PROTOCOL_VERSION) {
            throw new IncompatibleEngineError({
                clientProtocolVersion: PROTOCOL_VERSION,
                engineProtocolVersion: version.protocol_version,
                engineVersion: version.version
            })
        }
        return version
    }

    /**
     * Fails unless the engine routes every named operation. Call it at startup
     * with what the application depends on: finding out here beats an
     * operation_not_found in the middle of a login.
     */
    async requireOperations(...operations) {
        const version = await this.version()
        const routed = new Set(version.operations ?? [])
        const missing = operations.filter((operation) => !routed.has(operation)).sort()
        if (missing.length > 0) {
            throw new IncompatibleEngineError({
                clientProtocolVersion: PROTOCOL_VERSION,
                engineProtocolVersion: version.protocol_version,
                engineVersion: version.version,
                missingOperations: missing
            })
        }
        return version
    }

    /** Send one operation and resolve its result. */
    request(operation, parameters = {}) {
        if (this.#closed) return Promise.reject(new Error('sesame client is closed'))

        const requestId = randomBytes(8).toString('hex')
        const frame = JSON.stringify({
            protocol_version: PROTOCOL_VERSION,
            request_id: requestId,
            operation,
            parameters
        })
        if (Buffer.byteLength(frame) > MAX_FRAME_BYTES) {
            return Promise.reject(new Error('sesame request exceeds the maximum frame size'))
        }

        return new Promise((resolve, reject) => {
            this.#pending.push({ requestId, resolve, reject })
            this.#child.stdin.write(frame + '\n', (error) => {
                if (error) reject(error)
            })
        })
    }

    ping = () => this.request('system.ping')
    version = () => this.request('system.version')
    readiness = () => this.request('system.readiness')
    metrics = () => this.request('system.metrics')

    // Authentication. The engine owns every transition; these methods only
    // carry the caller's inputs across the protocol boundary.
    setPassword = (principalId, password) =>
        this.request('authenticator.set_password', { principal_id: principalId, password })
    // Succeeds whether or not the identifier resolves, so the result never
    // reveals which identifiers exist.
    authnBegin = (tenantId, { namespace, value }) =>
        this.request('authn.begin', {
            tenant_id: tenantId,
            identifier_namespace: namespace,
            identifier_value: value
        })
    authnVerifyPassword = (transactionId, password) =>
        this.request('authn.verify_password', { transaction_id: transactionId, password })
    authnComplete = (transactionId, lifetimeSeconds = 0) =>
        this.request('authn.complete', {
            transaction_id: transactionId,
            lifetime_seconds: lifetimeSeconds
        })
    recoveryCodesIssue = (principalId) =>
        this.request('authenticator.recovery_codes_issue', { principal_id: principalId })
    authnVerifyRecoveryCode = (transactionId, code) =>
        this.request('authn.verify_recovery_code', { transaction_id: transactionId, code })
    totpEnroll = (principalId, issuer = 'SESAME') =>
        this.request('authenticator.totp_enroll', { principal_id: principalId, issuer })
    totpActivate = (principalId, code) =>
        this.request('authenticator.totp_activate', { principal_id: principalId, code })
    authnVerifyTotp = (transactionId, code) =>
        this.request('authn.verify_totp', { transaction_id: transactionId, code })
    sessionVerify = (sessionId, secret) =>
        this.request('session.verify', { session_id: sessionId, session_secret: secret })
    sessionRevoke = (sessionId, reason = '') =>
        this.request('session.revoke', { session_id: sessionId, reason })

    tenantBootstrap = (name) => this.request('tenant.bootstrap', { name })
    tenantGetByName = (name) => this.request('tenant.get', { name })
    tenantGetById = (tenantId) => this.request('tenant.get', { tenant_id: tenantId })

    adminBootstrap = (tenantName, { namespace, value }) =>
        this.request('admin.bootstrap', {
            tenant_name: tenantName,
            identifier_namespace: namespace,
            identifier_value: value
        })

    principalCreate = (tenantId, kind, { namespace, value }) =>
        this.request('principal.create', {
            tenant_id: tenantId,
            kind,
            identifier_namespace: namespace,
            identifier_value: value
        })
    principalGetById = (principalId) => this.request('principal.get', { principal_id: principalId })
    principalGetByIdentifier = (tenantId, { namespace, value }) =>
        this.request('principal.get', {
            tenant_id: tenantId,
            identifier_namespace: namespace,
            identifier_value: value
        })
    principalSuspend = (principalId) => this.request('principal.suspend', { principal_id: principalId })

    roleCreate = (tenantId, name, permissions) =>
        this.request('role.create', { tenant_id: tenantId, name, permissions })
    groupCreate = (tenantId, name) => this.request('group.create', { tenant_id: tenantId, name })
    groupMemberAdd = (groupId, principalId) =>
        this.request('group.member_add', { group_id: groupId, principal_id: principalId })
    groupMemberRemove = (groupId, principalId) =>
        this.request('group.member_remove', { group_id: groupId, principal_id: principalId })

    grantCreate = (tenantId, principalId, roleId) =>
        this.request('grant.create', { tenant_id: tenantId, principal_id: principalId, role_id: roleId })
    grantCreateForGroup = (tenantId, groupId, roleId) =>
        this.request('grant.create', { tenant_id: tenantId, group_id: groupId, role_id: roleId })
    grantRevoke = (grantId) => this.request('grant.revoke', { grant_id: grantId })

    decide = (request, policyVersion) =>
        this.request('authorize.decide', {
            ...request,
            ...(policyVersion === undefined ? {} : { policy_version: policyVersion })
        })
    decideBatch = (requests, policyVersion) =>
        this.request('authorize.decide_batch', {
            requests,
            ...(policyVersion === undefined ? {} : { policy_version: policyVersion })
        }).then((result) => result.decisions)

    // ---- OIDC relying parties -------------------------------------------
    //
    // An omitted audience is treated as third party, the stricter rule: such
    // a client needs recorded user consent before it receives a code.
    oidcClientRegister = (tenantId, name, clientType, redirectUris, scopes, audience, postLogoutRedirectUris) =>
        this.request('oidc_client.register', {
            tenant_id: tenantId,
            name,
            client_type: clientType,
            redirect_uris: redirectUris,
            scopes,
            audience,
            post_logout_redirect_uris: postLogoutRedirectUris
        })
    oidcClientGet = (clientId) => this.request('oidc_client.get', { client_id: clientId })
    oidcClientRotateSecret = (clientId) =>
        this.request('oidc_client.rotate_secret', { client_id: clientId }).then((r) => r.client_secret)
    oidcClientDisable = (clientId, reason) =>
        this.request('oidc_client.disable', { client_id: clientId, reason })

    // ---- The external interaction contract ------------------------------
    //
    // `authorize` validates the whole request before anything is shown to a
    // user. The returned secret authorizes completing that one interaction.
    authorize = (request) => this.request('oidc.authorize', request)
    interactionGet = (interactionId) =>
        this.request('oidc.interaction_get', { interaction_id: interactionId })
    interactionComplete = (interactionId, interactionSecret, sessionId, sessionSecret) =>
        this.request('oidc.interaction_complete', {
            interaction_id: interactionId,
            interaction_secret: interactionSecret,
            session_id: sessionId,
            session_secret: sessionSecret
        })

    // A refresh response carries a new refresh token that replaces the one
    // presented; continuing to use the old one revokes the whole family.
    // The device grant (RFC 8628). deviceAuthorize starts it; the person
    // types the user code elsewhere and approves or denies it there.
    dpopVerify = (accessToken, proof, method, uri) =>
        this.request('oidc.dpop_verify', {
            access_token: accessToken,
            dpop_proof: proof,
            http_method: method,
            http_uri: uri,
        })

    pushedAuthorize = (request) => this.request('oidc.pushed_authorize', request)
    deviceAuthorize = (clientId, scopes = []) =>
        this.request('oidc.device_authorize', { client_id: clientId, scopes })
    deviceLookup = (tenantId, userCode) =>
        this.request('oidc.device_lookup', { tenant_id: tenantId, user_code: userCode })
    deviceApprove = (tenantId, userCode, sessionId, sessionSecret) =>
        this.request('oidc.device_approve', {
            tenant_id: tenantId, user_code: userCode,
            session_id: sessionId, session_secret: sessionSecret
        })
    deviceDeny = (tenantId, userCode) =>
        this.request('oidc.device_deny', { tenant_id: tenantId, user_code: userCode })
    tokenExchange = (request) => this.request('oidc.token', request)
    refreshFamilyRevoke = (familyId, reason) =>
        this.request('oidc.refresh_family_revoke', { family_id: familyId, reason })
    refreshFamilyGet = (familyId) => this.request('oidc.refresh_family_get', { family_id: familyId })

    // ---- Consent ---------------------------------------------------------
    //
    // The session proves who is agreeing, so a caller cannot consent on
    // somebody else's behalf. Withdrawing also revokes that client's refresh
    // families for the principal.
    consentGrant = (sessionId, sessionSecret, clientId, scopes) =>
        this.request('oidc.consent_grant', {
            session_id: sessionId,
            session_secret: sessionSecret,
            client_id: clientId,
            scopes
        })
    consentWithdraw = (principalId, clientId) =>
        this.request('oidc.consent_withdraw', { principal_id: principalId, client_id: clientId })
    consentGet = (principalId, clientId) =>
        this.request('oidc.consent_get', { principal_id: principalId, client_id: clientId })

    // ---- Standards surfaces ----------------------------------------------
    //
    // Endpoint paths are the host's own; the engine composes them under the
    // configured issuer and refuses any that would leave that origin.
    discovery = (endpoints = {}) => this.request('oidc.discovery', endpoints)
    signingKeys = () => this.request('token.jwks')
    // Introspection reports live grant state, not just signature validity:
    // this is where a revoked session shows up.
    introspect = (clientId, clientSecret, token) =>
        this.request('oidc.introspect', { token, client_id: clientId, client_secret: clientSecret })
    revoke = (clientId, clientSecret, token) =>
        this.request('oidc.revoke', { token, client_id: clientId, client_secret: clientSecret })
    // The hint is required and may be expired; revoking its session also ends
    // every refresh grant resting on it.
    logout = (idTokenHint, postLogoutRedirectUri, state) =>
        this.request('oidc.logout', {
            id_token_hint: idTokenHint,
            post_logout_redirect_uri: postLogoutRedirectUri,
            state
        })

    // ---- Passkeys ---------------------------------------------------------
    //
    // Binary values cross the protocol as base64. A user-verified passkey
    // establishes MFA on its own, with no prior factor.
    passkeyRegisterBegin = (principalId) =>
        this.request('authenticator.passkey_register_begin', { principal_id: principalId })
    passkeyRegisterFinish = (principalId, attestationObject, clientDataJson) =>
        this.request('authenticator.passkey_register_finish', {
            principal_id: principalId,
            attestation_object: base64Url(attestationObject),
            client_data_json: base64Url(clientDataJson)
        })
    passkeyList = (principalId) =>
        this.request('authenticator.passkey_list', { principal_id: principalId }).then((r) => r.passkeys)
    passkeyRemove = (credentialId) =>
        this.request('authenticator.passkey_remove', { credential_id: credentialId })
    passkeyOptions = (transactionId) =>
        this.request('authn.passkey_options', { transaction_id: transactionId })
    verifyPasskey = (transactionId, credentialId, authenticatorData, clientDataJson, signature) =>
        this.request('authn.verify_passkey', {
            transaction_id: transactionId,
            credential_id: credentialId,
            authenticator_data: base64Url(authenticatorData),
            client_data_json: base64Url(clientDataJson),
            signature: base64Url(signature)
        })

    // Inbound OIDC federation. The engine performs no network I/O: register and
    // configure return the exact URL the host must fetch, and every document
    // the host brings back is validated in the engine as untrusted input.
    // SCIM 2.0 provisioning. Every resource operation carries the bearer token, so the engine always authenticates and a host cannot forget to.
    provisioningClientRegister = (tenantId, name, identifierNamespace = '', canManageGroups = false) =>
        this.request('scim.client_register', {
            tenant_id: tenantId,
            name,
            identifier_namespace: identifierNamespace,
            can_manage_groups: canManageGroups
        })
    provisioningClientDisable = (tenantId, scimClientId, reason = '') =>
        this.request('scim.client_disable', {
            tenant_id: tenantId,
            scim_client_id: scimClientId,
            reason
        })
    provisioningClientRotateToken = (tenantId, scimClientId) =>
        this.request('scim.client_rotate_token', {
            tenant_id: tenantId,
            scim_client_id: scimClientId
        })
    // SCIM Group provisioning. These require the client's can_manage_groups
    // grant: group membership drives authorization decisions.
    scimGroupCreate = (token, body) =>
        this.request('scim.group_create', { token, body })
    scimGroupGet = (token, resourceId) =>
        this.request('scim.group_get', { token, resource_id: resourceId })
    scimGroupList = (token, filter = '', startIndex = 1, count = 0) =>
        this.request('scim.group_list', {
            token,
            filter,
            start_index: startIndex,
            count
        })
    scimGroupPatch = (token, resourceId, body) =>
        this.request('scim.group_patch', { token, resource_id: resourceId, body })
    scimGroupDeprovision = (token, resourceId) =>
        this.request('scim.group_deprovision', { token, resource_id: resourceId })
    scimUserCreate = (token, body) =>
        this.request('scim.user_create', { token, body })
    scimUserGet = (token, resourceId) =>
        this.request('scim.user_get', { token, resource_id: resourceId })
    scimUserList = (token, filter = '', startIndex = 1, count = 0) =>
        this.request('scim.user_list', {
            token,
            filter,
            start_index: startIndex,
            count
        })
    scimUserPatch = (token, resourceId, body) =>
        this.request('scim.user_patch', { token, resource_id: resourceId, body })
    scimUserDeprovision = (token, resourceId) =>
        this.request('scim.user_deprovision', { token, resource_id: resourceId })

    providerRegister = (tenantId, name, issuer, clientId, clientSecret, scopes,
        subjectClaim = 'sub', emailClaim = '', linking = 'strict') =>
        this.request('federation.provider_register', {
            tenant_id: tenantId,
            name,
            issuer,
            client_id: clientId,
            client_secret: clientSecret,
            scopes,
            subject_claim: subjectClaim,
            email_claim: emailClaim,
            linking
        })
    samlProviderRegister = (tenantId, name, entityId, ssoUrl, certificates,
        identifierNamespace = 'email', linking = 'strict') =>
        this.request('saml.provider_register', {
            tenant_id: tenantId,
            name,
            entity_id: entityId,
            sso_url: ssoUrl,
            certificates,
            identifier_namespace: identifierNamespace,
            linking
        })
    samlProviderGet = (tenantId, providerId) =>
        this.request('saml.provider_get', { tenant_id: tenantId, provider_id: providerId })
    samlProviderDisable = (tenantId, providerId, reason = '') =>
        this.request('saml.provider_disable', {
            tenant_id: tenantId, provider_id: providerId, reason
        })
    samlLoginStart = (tenantId, providerId, consumerUrl) =>
        this.request('saml.login_start', {
            tenant_id: tenantId, provider_id: providerId, consumer_url: consumerUrl
        })
    samlLoginComplete = (tenantId, loginId, assertion) =>
        this.request('saml.login_complete', {
            tenant_id: tenantId, login_id: loginId, assertion
        })
    providerConfigure = (tenantId, providerId, discoveryDocument, keySetDocument) =>
        this.request('federation.provider_configure', {
            tenant_id: tenantId,
            provider_id: providerId,
            discovery_document: discoveryDocument,
            key_set_document: keySetDocument
        })
    providerDisable = (tenantId, providerId, reason = '') =>
        this.request('federation.provider_disable', {
            tenant_id: tenantId,
            provider_id: providerId,
            reason
        })
    providerGet = (tenantId, providerId) =>
        this.request('federation.provider_get', { tenant_id: tenantId, provider_id: providerId })
    federatedLoginStart = (tenantId, providerId, redirectUri) =>
        this.request('federation.login_start', {
            tenant_id: tenantId,
            provider_id: providerId,
            redirect_uri: redirectUri
        })
    federatedLoginExchange = (tenantId, loginId, state, code) =>
        this.request('federation.login_exchange', {
            tenant_id: tenantId,
            login_id: loginId,
            state,
            code
        })
    federatedLoginComplete = (tenantId, loginId, idToken) =>
        this.request('federation.login_complete', {
            tenant_id: tenantId,
            login_id: loginId,
            id_token: idToken
        })

    /** Ask the child to exit, forcing it after a bounded wait. */
    async close() {
        if (this.#closed) return
        this.#closed = true
        this.#child.stdin.end()
        const timer = setTimeout(() => this.#child.kill('SIGKILL'), CLOSE_TIMEOUT_MS)
        await this.#exit
        clearTimeout(timer)
    }
}

function decodeResponse(requestId, line) {
    let response
    try {
        response = JSON.parse(line)
    } catch {
        throw new Error(`sesame response is not JSON: ${line}`)
    }
    if (response.protocol_version !== PROTOCOL_VERSION) {
        throw new Error(`unsupported sesame protocol version ${response.protocol_version}`)
    }
    if (response.request_id !== requestId) {
        throw new Error(`sesame response request ID mismatch: expected ${requestId}`)
    }
    if (!response.ok) {
        if (!response.error) throw new Error('sesame failure response has no error')
        throw new ProtocolError(response.error)
    }
    return response.result
}
