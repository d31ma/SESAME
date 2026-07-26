<?php
// A thin PHP client for a local SESAME process.
//
// The client owns process lifecycle, NDJSON framing, and typed transport
// errors. Identity and authorization semantics remain in the SESAME
// executable. Dependencies: ext-json only.

declare(strict_types=1);

namespace Sesame;

/** A stable error returned by the SESAME machine interface. */
final class ProtocolError extends \RuntimeException
{
    // Named errorCode because Exception::$code is an inherited int and
    // SESAME's stable codes are strings.
    public function __construct(
        public readonly string $errorCode,
        string $message,
        public readonly bool $retryable = false,
    ) {
        parent::__construct("sesame protocol error {$errorCode}: {$message}");
    }
}

/**
 * A SESAME binary this client cannot speak to. It names both sides, because
 * the fix is always to change one of them.
 */
final class IncompatibleEngineError extends \RuntimeException
{
    /** @var list<string> */
    public array $missingOperations;

    /** @param list<string> $missingOperations */
    public function __construct(
        public string $clientProtocolVersion,
        public string $engineProtocolVersion,
        public string $engineVersion,
        array $missingOperations = [],
    ) {
        $this->missingOperations = $missingOperations;
        $message = $engineProtocolVersion !== $clientProtocolVersion
            ? sprintf(
                'sesame engine %s speaks machine protocol "%s"; this client speaks "%s"',
                $engineVersion,
                $engineProtocolVersion,
                $clientProtocolVersion,
            )
            : sprintf(
                'sesame engine %s does not support %d operation(s) this client requires: %s',
                $engineVersion,
                count($missingOperations),
                implode(', ', $missingOperations),
            );
        parent::__construct($message);
    }
}

/** A transport or framing failure. */
final class TransportError extends \RuntimeException
{
    public function __construct(string $message)
    {
        parent::__construct("sesame transport error: {$message}");
    }
}

/** Owns one long-lived local SESAME subprocess. */
final class Client
{
    public const PROTOCOL_VERSION = '1';

    /**
     * Bounds what a failing engine can make the caller hold: generous enough
     * for a refusal and its remedy, short of anything worth worrying about.
     */
    private const STARTUP_DIAGNOSTICS_BYTES = 4096;
    public const MAX_FRAME_BYTES = 1048576;

    /** @var resource */
    private $process;
    /** @var array<int, resource> */
    private array $pipes;
    private int $counter = 0;
    private bool $closed = false;

    public function __construct(
        // SESAME_BINARY names the engine when no option does; an explicit option still wins.
        string $binary = '',
        ?string $deployment = null,
        ?string $fyloBinary = null,
        ?string $fyloRoot = null,
        bool $skipCompatibilityCheck = false,
    ) {
        $arguments = [$binary !== '' ? $binary : (getenv('SESAME_BINARY') ?: 'sesame'), 'exec', '--loop'];
        if ($deployment !== null && $deployment !== '') {
            $arguments[] = '--deployment';
            $arguments[] = $deployment;
        }
        if (($fyloBinary !== null && $fyloBinary !== '') || ($fyloRoot !== null && $fyloRoot !== '')) {
            $arguments[] = '--fylo-binary';
            $arguments[] = $fyloBinary ?? '';
            $arguments[] = '--fylo-root';
            $arguments[] = $fyloRoot ?? '';
        }

        // The engine reports a missing deployment or an unusable FYLO root on
        // stderr and then exits. Sending that to /dev/null would leave the
        // caller with a dead process and no reason.
        $descriptors = [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
        $process = proc_open($arguments, $descriptors, $pipes);
        if ($process === false) {
            throw new TransportError('start sesame');
        }
        $this->process = $process;
        $this->pipes = $pipes;

        // A mismatched engine is found here rather than partway through a
        // security flow that then cannot finish. system.version needs no
        // storage, so this works before a FYLO root is configured.
        if (!$skipCompatibilityCheck) {
            try {
                $this->checkCompatibility();
            } catch (\Throwable $error) {
                $diagnostic = $this->startupDiagnostics();
                $this->close();
                if ($diagnostic !== '') {
                    // A TransportError already carries its own prefix; wrapping
                    // one in another would print the prefix twice.
                    throw $error instanceof TransportError
                        ? new \RuntimeException($error->getMessage() . ': ' . $diagnostic,
                            0, $error)
                        : new TransportError($error->getMessage() . ': ' . $diagnostic);
                }
                throw $error;
            }
        }
        // The engine is up; a blocking read on stderr would stall every
        // request, and an unread pipe would eventually stall the child.
        stream_set_blocking($this->pipes[2], false);
    }

    /** Reads what a failing engine said before it exited. */
    private function startupDiagnostics(): string
    {
        if (!isset($this->pipes[2]) || !is_resource($this->pipes[2])) {
            return '';
        }
        stream_set_blocking($this->pipes[2], false);
        $captured = (string) stream_get_contents($this->pipes[2], self::STARTUP_DIAGNOSTICS_BYTES);
        return trim($captured);
    }

    /** Fails unless the engine speaks this client's machine protocol. */
    public function checkCompatibility(): mixed
    {
        $version = $this->version();
        $engine = (string) ($version['protocol_version'] ?? '');
        if ($engine !== self::PROTOCOL_VERSION) {
            throw new IncompatibleEngineError(
                self::PROTOCOL_VERSION,
                $engine,
                (string) ($version['version'] ?? ''),
            );
        }
        return $version;
    }

    /**
     * Fails unless the engine routes every named operation. Call it at startup
     * with what the application depends on: finding out here beats an
     * operation_not_found in the middle of a login.
     */
    public function requireOperations(string ...$operations): mixed
    {
        $version = $this->version();
        $routed = (array) ($version['operations'] ?? []);
        $missing = array_values(array_filter(
            $operations,
            static fn (string $operation): bool => !in_array($operation, $routed, true),
        ));
        if ($missing !== []) {
            sort($missing);
            throw new IncompatibleEngineError(
                self::PROTOCOL_VERSION,
                (string) ($version['protocol_version'] ?? ''),
                (string) ($version['version'] ?? ''),
                $missing,
            );
        }
        return $version;
    }

    public function __destruct()
    {
        $this->close();
    }

    /** Sends one operation and returns its result. */
    public function request(string $operation, array $parameters = []): mixed
    {
        if ($this->closed) {
            throw new TransportError('sesame client is closed');
        }
        $this->counter++;
        $requestId = 'php-' . hrtime(true) . '-' . $this->counter;
        $frame = json_encode([
            'protocol_version' => self::PROTOCOL_VERSION,
            'request_id' => $requestId,
            'operation' => $operation,
            'parameters' => $parameters === [] ? new \stdClass() : $parameters,
        ], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
        if (strlen($frame) > self::MAX_FRAME_BYTES) {
            throw new TransportError('request exceeds the maximum frame size');
        }

        fwrite($this->pipes[0], $frame . "\n");
        fflush($this->pipes[0]);

        $line = fgets($this->pipes[1]);
        if ($line === false) {
            throw new TransportError('sesame process exited');
        }
        return $this->decodeResponse($requestId, $line);
    }

    private function decodeResponse(string $requestId, string $line): mixed
    {
        try {
            $response = json_decode($line, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $error) {
            throw new TransportError('decode: ' . $error->getMessage());
        }
        if (!is_array($response)) {
            throw new TransportError('response is not a JSON object');
        }
        if (($response['protocol_version'] ?? null) !== self::PROTOCOL_VERSION) {
            throw new TransportError('unsupported protocol version');
        }
        if (($response['request_id'] ?? null) !== $requestId) {
            throw new TransportError('response request ID mismatch');
        }
        if (!array_key_exists('ok', $response) || !is_bool($response['ok'])) {
            throw new TransportError('response has no ok field');
        }
        if ($response['ok'] === false) {
            $error = $response['error'] ?? null;
            if (!is_array($error)) {
                throw new TransportError('failure response has no error');
            }
            throw new ProtocolError(
                (string) ($error['code'] ?? ''),
                (string) ($error['message'] ?? ''),
                (bool) ($error['retryable'] ?? false),
            );
        }
        return $response['result'] ?? null;
    }

    /** Asks the child to exit and reaps it. */
    public function close(): void
    {
        if ($this->closed) {
            return;
        }
        $this->closed = true;
        if (isset($this->pipes[0]) && is_resource($this->pipes[0])) {
            fclose($this->pipes[0]);
        }
        if (isset($this->pipes[1]) && is_resource($this->pipes[1])) {
            fclose($this->pipes[1]);
        }
        if (is_resource($this->process)) {
            proc_close($this->process);
        }
    }

    // System operations.
    public function ping(): mixed { return $this->request('system.ping'); }
    public function version(): mixed { return $this->request('system.version'); }
    public function readiness(): mixed { return $this->request('system.readiness'); }
    public function metrics(): mixed { return $this->request('system.metrics'); }

    // Tenants and principals.
    public function tenantBootstrap(string $name): mixed
    {
        return $this->request('tenant.bootstrap', ['name' => $name]);
    }

    public function tenantGetByName(string $name): mixed
    {
        return $this->request('tenant.get', ['name' => $name]);
    }

    public function principalCreate(string $tenantId, string $kind, string $namespace, string $value): mixed
    {
        return $this->request('principal.create', [
            'tenant_id' => $tenantId,
            'kind' => $kind,
            'identifier_namespace' => $namespace,
            'identifier_value' => $value,
        ]);
    }

    public function principalGetById(string $principalId): mixed
    {
        return $this->request('principal.get', ['principal_id' => $principalId]);
    }

    public function principalSuspend(string $principalId): mixed
    {
        return $this->request('principal.suspend', ['principal_id' => $principalId]);
    }

    // Authorization.
    public function roleCreate(string $tenantId, string $name, array $permissions): mixed
    {
        return $this->request('role.create', [
            'tenant_id' => $tenantId,
            'name' => $name,
            'permissions' => $permissions,
        ]);
    }

    public function grantCreate(string $tenantId, string $principalId, string $roleId): mixed
    {
        return $this->request('grant.create', [
            'tenant_id' => $tenantId,
            'principal_id' => $principalId,
            'role_id' => $roleId,
        ]);
    }

    public function grantRevoke(string $grantId): mixed
    {
        return $this->request('grant.revoke', ['grant_id' => $grantId]);
    }

    // Asks the same question as decide, but proves a session instead of naming a principal.
    //
    // The engine verifies the session and derives context under the reserved
    // "session." prefix, so a caller cannot assert its own assurance level. That
    // is what makes a step-up condition worth trusting.
    public function decideForSession(
        string $tenantId,
        string $sessionId,
        string $sessionSecret,
        string $action,
        string $resource
    ): mixed {
        return $this->request('authorize.decide', [
            'tenant_id' => $tenantId,
            'session_id' => $sessionId,
            'session_secret' => $sessionSecret,
            'action' => $action,
            'resource' => $resource,
        ]);
    }

    public function decide(string $tenantId, string $principalId, string $action, string $resource): mixed
    {
        return $this->request('authorize.decide', [
            'tenant_id' => $tenantId,
            'principal_id' => $principalId,
            'action' => $action,
            'resource' => $resource,
        ]);
    }

    // Authentication.
    public function setPassword(string $principalId, string $password): mixed
    {
        return $this->request('authenticator.set_password', [
            'principal_id' => $principalId,
            'password' => $password,
        ]);
    }

    /**
     * Starts a login transaction. It succeeds whether or not the identifier
     * resolves, so the result never reveals which identifiers exist.
     */
    public function authnBegin(string $tenantId, string $namespace, string $value): mixed
    {
        return $this->request('authn.begin', [
            'tenant_id' => $tenantId,
            'identifier_namespace' => $namespace,
            'identifier_value' => $value,
        ]);
    }

    public function authnVerifyPassword(string $transactionId, string $password): mixed
    {
        return $this->request('authn.verify_password', [
            'transaction_id' => $transactionId,
            'password' => $password,
        ]);
    }

    public function authnComplete(string $transactionId, int $lifetimeSeconds = 0): mixed
    {
        return $this->request('authn.complete', [
            'transaction_id' => $transactionId,
            'lifetime_seconds' => $lifetimeSeconds,
        ]);
    }

    public function sessionVerify(string $sessionId, string $secret): mixed
    {
        return $this->request('session.verify', [
            'session_id' => $sessionId,
            'session_secret' => $secret,
        ]);
    }

    public function sessionRevoke(string $sessionId, string $reason = ''): mixed
    {
        return $this->request('session.revoke', [
            'session_id' => $sessionId,
            'reason' => $reason,
        ]);
    }

    // Groups and administration.
    public function groupCreate(string $tenantId, string $name): mixed
    {
        return $this->request('group.create', ['tenant_id' => $tenantId, 'name' => $name]);
    }

    public function groupMemberAdd(string $groupId, string $principalId): mixed
    {
        return $this->request('group.member_add', [
            'group_id' => $groupId,
            'principal_id' => $principalId,
        ]);
    }

    public function groupMemberRemove(string $groupId, string $principalId): mixed
    {
        return $this->request('group.member_remove', [
            'group_id' => $groupId,
            'principal_id' => $principalId,
        ]);
    }

    public function adminBootstrap(string $tenantName, string $namespace, string $value): mixed
    {
        return $this->request('admin.bootstrap', [
            'tenant_name' => $tenantName,
            'identifier_namespace' => $namespace,
            'identifier_value' => $value,
        ]);
    }

    /** A batch always answers under one policy version. */
    public function decideBatch(array $requests): mixed
    {
        return $this->request('authorize.decide_batch', ['requests' => $requests]);
    }

    // Second factors. The TOTP shared secret is returned once at enrolment and
    // is never recoverable afterwards; a used code spends its time step
    // durably, so an observed code cannot be replayed inside its own window.
    public function totpEnroll(string $principalId, string $issuer = 'SESAME'): mixed
    {
        return $this->request('authenticator.totp_enroll', [
            'principal_id' => $principalId,
            'issuer' => $issuer,
        ]);
    }

    public function totpActivate(string $principalId, string $code): mixed
    {
        return $this->request('authenticator.totp_activate', [
            'principal_id' => $principalId,
            'code' => $code,
        ]);
    }

    public function authnVerifyTotp(string $transactionId, string $code): mixed
    {
        return $this->request('authn.verify_totp', [
            'transaction_id' => $transactionId,
            'code' => $code,
        ]);
    }

    /** Returns ten single-use codes once, retiring any previous set. */
    public function recoveryCodesIssue(string $principalId): mixed
    {
        return $this->request('authenticator.recovery_codes_issue', [
            'principal_id' => $principalId,
        ]);
    }

    public function authnVerifyRecoveryCode(string $transactionId, string $code): mixed
    {
        return $this->request('authn.verify_recovery_code', [
            'transaction_id' => $transactionId,
            'code' => $code,
        ]);
    }

    // OIDC relying parties. An omitted audience is treated as third party, the
    // stricter rule: such a client needs recorded user consent before it
    // receives an authorization code.
    public function oidcClientRegister(
        string $tenantId,
        string $name,
        string $clientType,
        array $redirectUris,
        array $scopes = [],
        string $audience = '',
        array $postLogoutRedirectUris = []
    ): mixed {
        return $this->request('oidc_client.register', [
            'tenant_id' => $tenantId,
            'name' => $name,
            'client_type' => $clientType,
            'redirect_uris' => $redirectUris,
            'scopes' => $scopes,
            'audience' => $audience,
            'post_logout_redirect_uris' => $postLogoutRedirectUris,
        ]);
    }

    public function oidcClientGet(string $clientId): mixed
    {
        return $this->request('oidc_client.get', ['client_id' => $clientId]);
    }

    public function oidcClientRotateSecret(string $clientId): mixed
    {
        return $this->request('oidc_client.rotate_secret', ['client_id' => $clientId]);
    }

    public function oidcClientDisable(string $clientId, string $reason = ''): mixed
    {
        return $this->request('oidc_client.disable', [
            'client_id' => $clientId,
            'reason' => $reason,
        ]);
    }

    // The external interaction contract. authorize validates the whole request
    // before anything is shown to a user; the returned secret authorizes
    // completing that one interaction.
    public function authorize(array $authorizationRequest): mixed
    {
        return $this->request('oidc.authorize', $authorizationRequest);
    }

    public function interactionGet(string $interactionId): mixed
    {
        return $this->request('oidc.interaction_get', ['interaction_id' => $interactionId]);
    }

    public function interactionComplete(
        string $interactionId,
        string $interactionSecret,
        string $sessionId,
        string $sessionSecret
    ): mixed {
        return $this->request('oidc.interaction_complete', [
            'interaction_id' => $interactionId,
            'interaction_secret' => $interactionSecret,
            'session_id' => $sessionId,
            'session_secret' => $sessionSecret,
        ]);
    }

    /**
     * A refresh response carries a new refresh token that replaces the one
     * presented; continuing to use the old one revokes the whole family.
     */
    // The device grant (RFC 8628). deviceAuthorize starts it; the person
    // types the user code elsewhere and approves or denies it there.
    public function dpopVerify(
        string $accessToken,
        string $proof,
        string $method,
        string $uri
    ): mixed {
        return $this->request('oidc.dpop_verify', [
            'access_token' => $accessToken,
            'dpop_proof' => $proof,
            'http_method' => $method,
            'http_uri' => $uri,
        ]);
    }

    public function pushedAuthorize(array $request): mixed
    {
        return $this->request('oidc.pushed_authorize', $request);
    }

    public function deviceAuthorize(string $clientId, array $scopes = []): mixed
    {
        return $this->request('oidc.device_authorize', [
            'client_id' => $clientId,
            'scopes' => $scopes,
        ]);
    }

    public function deviceLookup(string $tenantId, string $userCode): mixed
    {
        return $this->request('oidc.device_lookup', [
            'tenant_id' => $tenantId,
            'user_code' => $userCode,
        ]);
    }

    public function deviceApprove(
        string $tenantId,
        string $userCode,
        string $sessionId,
        string $sessionSecret
    ): mixed {
        return $this->request('oidc.device_approve', [
            'tenant_id' => $tenantId,
            'user_code' => $userCode,
            'session_id' => $sessionId,
            'session_secret' => $sessionSecret,
        ]);
    }

    public function deviceDeny(string $tenantId, string $userCode): mixed
    {
        return $this->request('oidc.device_deny', [
            'tenant_id' => $tenantId,
            'user_code' => $userCode,
        ]);
    }

    public function tokenExchange(array $tokenRequest): mixed
    {
        return $this->request('oidc.token', $tokenRequest);
    }

    public function refreshFamilyRevoke(string $familyId, string $reason = ''): mixed
    {
        return $this->request('oidc.refresh_family_revoke', [
            'family_id' => $familyId,
            'reason' => $reason,
        ]);
    }

    public function refreshFamilyGet(string $familyId): mixed
    {
        return $this->request('oidc.refresh_family_get', ['family_id' => $familyId]);
    }

    // Consent. The session proves who is agreeing, so a caller cannot consent
    // on somebody else's behalf. Withdrawing also revokes that client's refresh
    // families for the principal.
    public function consentGrant(
        string $sessionId,
        string $sessionSecret,
        string $clientId,
        array $scopes
    ): mixed {
        return $this->request('oidc.consent_grant', [
            'session_id' => $sessionId,
            'session_secret' => $sessionSecret,
            'client_id' => $clientId,
            'scopes' => $scopes,
        ]);
    }

    public function consentWithdraw(string $principalId, string $clientId): mixed
    {
        return $this->request('oidc.consent_withdraw', [
            'principal_id' => $principalId,
            'client_id' => $clientId,
        ]);
    }

    public function consentGet(string $principalId, string $clientId): mixed
    {
        return $this->request('oidc.consent_get', [
            'principal_id' => $principalId,
            'client_id' => $clientId,
        ]);
    }

    // Standards surfaces. Endpoint paths are the host's own; the engine
    // composes them under the configured issuer and refuses any that would
    // leave that origin.
    public function standardsDispatch(array $request): mixed
    {
        $request['contract_version'] = '1';
        return $this->request('standards.dispatch', $request);
    }

    public function discovery(array $endpoints = []): mixed
    {
        return $this->request('oidc.discovery', $endpoints);
    }

    public function signingKeys(): mixed
    {
        return $this->request('token.jwks', []);
    }

    /**
     * Introspection reports live grant state, not just signature validity:
     * this is where a revoked session shows up.
     */
    public function introspect(string $clientId, string $clientSecret, string $token): mixed
    {
        return $this->request('oidc.introspect', [
            'token' => $token,
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ]);
    }

    public function revoke(string $clientId, string $clientSecret, string $token): mixed
    {
        return $this->request('oidc.revoke', [
            'token' => $token,
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
        ]);
    }

    /**
     * The hint is required and may be expired; revoking its session also ends
     * every refresh grant resting on it.
     */
    public function logout(
        string $idTokenHint,
        string $postLogoutRedirectUri = '',
        string $state = ''
    ): mixed {
        return $this->request('oidc.logout', [
            'id_token_hint' => $idTokenHint,
            'post_logout_redirect_uri' => $postLogoutRedirectUri,
            'state' => $state,
        ]);
    }

    // Passkeys. Binary values cross the protocol as base64. A user-verified
    // passkey establishes MFA on its own, with no prior factor.
    public function passkeyRegisterBegin(string $principalId): mixed
    {
        return $this->request('authenticator.passkey_register_begin', [
            'principal_id' => $principalId,
        ]);
    }

    public function passkeyRegisterFinish(
        string $principalId,
        string $attestationObject,
        string $clientDataJson
    ): mixed {
        return $this->request('authenticator.passkey_register_finish', [
            'principal_id' => $principalId,
            'attestation_object' => self::base64Url($attestationObject),
            'client_data_json' => self::base64Url($clientDataJson),
        ]);
    }

    public function passkeyList(string $principalId): mixed
    {
        return $this->request('authenticator.passkey_list', ['principal_id' => $principalId]);
    }

    public function passkeyRemove(string $credentialId): mixed
    {
        return $this->request('authenticator.passkey_remove', ['credential_id' => $credentialId]);
    }

    public function passkeyOptions(string $transactionId): mixed
    {
        return $this->request('authn.passkey_options', ['transaction_id' => $transactionId]);
    }

    public function authnVerifyPasskey(
        string $transactionId,
        string $credentialId,
        string $authenticatorData,
        string $clientDataJson,
        string $signature
    ): mixed {
        return $this->request('authn.verify_passkey', [
            'transaction_id' => $transactionId,
            'credential_id' => $credentialId,
            'authenticator_data' => self::base64Url($authenticatorData),
            'client_data_json' => self::base64Url($clientDataJson),
            'signature' => self::base64Url($signature),
        ]);
    }

    /**
     * Inbound OIDC federation. The engine performs no network I/O: register and
     * configure return the exact URL the host must fetch, and every document
     * the host brings back is validated in the engine as untrusted input.
     */
    /**
     * SCIM 2.0 provisioning. Every resource operation carries the bearer token,
     * so the engine always authenticates and a host cannot forget to.
     */
    public function provisioningClientRegister(
        string $tenantId,
        string $name,
        string $identifierNamespace = '',
        bool $canManageGroups = false
    ): mixed {
        return $this->request('scim.client_register', [
            'tenant_id' => $tenantId,
            'name' => $name,
            'identifier_namespace' => $identifierNamespace,
            'can_manage_groups' => $canManageGroups,
        ]);
    }

    public function provisioningClientDisable(
        string $tenantId,
        string $scimClientId,
        string $reason = ''
    ): mixed {
        return $this->request('scim.client_disable', [
            'tenant_id' => $tenantId,
            'scim_client_id' => $scimClientId,
            'reason' => $reason,
        ]);
    }

    public function provisioningClientRotateToken(
        string $tenantId,
        string $scimClientId
    ): mixed {
        return $this->request('scim.client_rotate_token', [
            'tenant_id' => $tenantId,
            'scim_client_id' => $scimClientId,
        ]);
    }

    /**
     * SCIM Group provisioning. These require the client's can_manage_groups
     * grant: group membership drives authorization decisions.
     */
    public function scimGroupCreate(string $token, string $body): mixed
    {
        return $this->request('scim.group_create', ['token' => $token, 'body' => $body]);
    }

    public function scimGroupGet(string $token, string $resourceId): mixed
    {
        return $this->request('scim.group_get', [
            'token' => $token,
            'resource_id' => $resourceId,
        ]);
    }

    public function scimGroupList(
        string $token,
        string $filter = '',
        int $startIndex = 1,
        int $count = 0
    ): mixed {
        return $this->request('scim.group_list', [
            'token' => $token,
            'filter' => $filter,
            'start_index' => $startIndex,
            'count' => $count,
        ]);
    }

    public function scimGroupPatch(string $token, string $resourceId, string $body): mixed
    {
        return $this->request('scim.group_patch', [
            'token' => $token,
            'resource_id' => $resourceId,
            'body' => $body,
        ]);
    }

    public function scimGroupDeprovision(string $token, string $resourceId): mixed
    {
        return $this->request('scim.group_deprovision', [
            'token' => $token,
            'resource_id' => $resourceId,
        ]);
    }

    public function scimUserCreate(string $token, string $body): mixed
    {
        return $this->request('scim.user_create', ['token' => $token, 'body' => $body]);
    }

    public function scimUserGet(string $token, string $resourceId): mixed
    {
        return $this->request('scim.user_get', [
            'token' => $token,
            'resource_id' => $resourceId,
        ]);
    }

    public function scimUserList(
        string $token,
        string $filter = '',
        int $startIndex = 1,
        int $count = 0
    ): mixed {
        return $this->request('scim.user_list', [
            'token' => $token,
            'filter' => $filter,
            'start_index' => $startIndex,
            'count' => $count,
        ]);
    }

    public function scimUserPatch(string $token, string $resourceId, string $body): mixed
    {
        return $this->request('scim.user_patch', [
            'token' => $token,
            'resource_id' => $resourceId,
            'body' => $body,
        ]);
    }

    public function scimUserDeprovision(string $token, string $resourceId): mixed
    {
        return $this->request('scim.user_deprovision', [
            'token' => $token,
            'resource_id' => $resourceId,
        ]);
    }

    public function providerRegister(
        string $tenantId,
        string $name,
        string $issuer,
        string $clientId,
        string $clientSecret,
        array $scopes,
        string $subjectClaim = 'sub',
        string $emailClaim = '',
        string $linking = 'strict'
    ): mixed {
        return $this->request('federation.provider_register', [
            'tenant_id' => $tenantId,
            'name' => $name,
            'issuer' => $issuer,
            'client_id' => $clientId,
            'client_secret' => $clientSecret,
            'scopes' => $scopes,
            'subject_claim' => $subjectClaim,
            'email_claim' => $emailClaim,
            'linking' => $linking,
        ]);
    }

    /**
     * @param list<string> $certificates
     */
    public function samlProviderRegister(
        string $tenantId,
        string $name,
        string $entityId,
        string $ssoUrl,
        array $certificates,
        string $identifierNamespace = 'email',
        string $linking = 'strict'
    ): mixed {
        return $this->request('saml.provider_register', [
            'tenant_id' => $tenantId,
            'name' => $name,
            'entity_id' => $entityId,
            'sso_url' => $ssoUrl,
            'certificates' => $certificates,
            'identifier_namespace' => $identifierNamespace,
            'linking' => $linking,
        ]);
    }

    public function samlProviderGet(string $tenantId, string $providerId): mixed
    {
        return $this->request('saml.provider_get', [
            'tenant_id' => $tenantId,
            'provider_id' => $providerId,
        ]);
    }

    public function samlProviderDisable(
        string $tenantId,
        string $providerId,
        string $reason = ''
    ): mixed {
        return $this->request('saml.provider_disable', [
            'tenant_id' => $tenantId,
            'provider_id' => $providerId,
            'reason' => $reason,
        ]);
    }

    public function samlLoginStart(
        string $tenantId,
        string $providerId,
        string $consumerUrl
    ): mixed {
        return $this->request('saml.login_start', [
            'tenant_id' => $tenantId,
            'provider_id' => $providerId,
            'consumer_url' => $consumerUrl,
        ]);
    }

    public function samlLoginComplete(
        string $tenantId,
        string $loginId,
        string $assertion
    ): mixed {
        return $this->request('saml.login_complete', [
            'tenant_id' => $tenantId,
            'login_id' => $loginId,
            'assertion' => $assertion,
        ]);
    }

    public function providerConfigure(
        string $tenantId,
        string $providerId,
        string $discoveryDocument,
        string $keySetDocument
    ): mixed {
        return $this->request('federation.provider_configure', [
            'tenant_id' => $tenantId,
            'provider_id' => $providerId,
            'discovery_document' => $discoveryDocument,
            'key_set_document' => $keySetDocument,
        ]);
    }

    public function providerDisable(
        string $tenantId,
        string $providerId,
        string $reason = ''
    ): mixed {
        return $this->request('federation.provider_disable', [
            'tenant_id' => $tenantId,
            'provider_id' => $providerId,
            'reason' => $reason,
        ]);
    }

    public function providerGet(string $tenantId, string $providerId): mixed
    {
        return $this->request('federation.provider_get', [
            'tenant_id' => $tenantId,
            'provider_id' => $providerId,
        ]);
    }

    public function federatedLoginStart(
        string $tenantId,
        string $providerId,
        string $redirectUri
    ): mixed {
        return $this->request('federation.login_start', [
            'tenant_id' => $tenantId,
            'provider_id' => $providerId,
            'redirect_uri' => $redirectUri,
        ]);
    }

    public function federatedLoginExchange(
        string $tenantId,
        string $loginId,
        string $state,
        string $code
    ): mixed {
        return $this->request('federation.login_exchange', [
            'tenant_id' => $tenantId,
            'login_id' => $loginId,
            'state' => $state,
            'code' => $code,
        ]);
    }

    public function federatedLoginComplete(
        string $tenantId,
        string $loginId,
        string $idToken
    ): mixed {
        return $this->request('federation.login_complete', [
            'tenant_id' => $tenantId,
            'login_id' => $loginId,
            'id_token' => $idToken,
        ]);
    }

    /** Encodes a binary WebAuthn value for transport, without padding. */
    private static function base64Url(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
