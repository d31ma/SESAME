// A thin Dart client for a local SESAME process.
//
// The client owns process lifecycle, NDJSON framing, and typed transport
// errors. Identity and authorization semantics remain in the SESAME
// executable. Dependencies: the Dart SDK only.

import 'dart:async';
import 'dart:convert';
import 'dart:io';

const String protocolVersion = '1';
const int maxFrameBytes = 1 << 20;

/// Bounds what a failing engine can make the caller hold: generous enough for
/// a refusal and its remedy, short of anything worth worrying about.
const int startupDiagnosticsBytes = 4096;

/// A stable error returned by the SESAME machine interface.
class ProtocolError implements Exception {
  ProtocolError(this.code, this.message, {this.retryable = false});

  final String code;
  final String message;
  final bool retryable;

  @override
  String toString() => 'sesame protocol error $code: $message';
}

/// A transport or framing failure.
/// A SESAME binary this client cannot speak to. It names both sides, because
/// the fix is always to change one of them.
class IncompatibleEngineError implements Exception {
  IncompatibleEngineError(
    this.clientProtocolVersion,
    this.engineProtocolVersion,
    this.engineVersion, [
    this.missingOperations = const [],
  ]);

  final String clientProtocolVersion;
  final String engineProtocolVersion;
  final String engineVersion;
  final List<String> missingOperations;

  @override
  String toString() => engineProtocolVersion != clientProtocolVersion
      ? 'sesame engine $engineVersion speaks machine protocol '
          '"$engineProtocolVersion"; this client speaks "$clientProtocolVersion"'
      : 'sesame engine $engineVersion does not support '
          '${missingOperations.length} operation(s) this client requires: '
          '${missingOperations.join(', ')}';
}

class TransportError implements Exception {
  TransportError(this.message);

  final String message;

  @override
  String toString() => 'sesame transport error: $message';
}

/// Owns one long-lived local SESAME subprocess.
class Client {
  Client._(this._process, this._responses);

  final Process _process;
  final StreamIterator<String> _responses;
  int _counter = 0;
  bool _closed = false;

  /// Launches a SESAME subprocess in persistent machine mode.
  static Future<Client> start({
    // SESAME_BINARY names the engine when no option does; an explicit option still wins.
    String binary = '',
    String? deployment,
    String? fyloBinary,
    String? fyloRoot,
    bool skipCompatibilityCheck = false,
  }) async {
    final arguments = <String>['exec', '--loop'];
    if (deployment != null && deployment.isNotEmpty) {
      arguments.addAll(['--deployment', deployment]);
    }
    if ((fyloBinary != null && fyloBinary.isNotEmpty) ||
        (fyloRoot != null && fyloRoot.isNotEmpty)) {
      arguments.addAll(['--fylo-binary', fyloBinary ?? '', '--fylo-root', fyloRoot ?? '']);
    }
    final resolved = binary.isNotEmpty
        ? binary
        : (Platform.environment['SESAME_BINARY'] ?? 'sesame');
    final process = await Process.start(resolved, arguments);
    // The startup window is captured so a refusal can explain itself: the
    // engine reports a missing deployment or an unusable FYLO root this way
    // and then exits. Listening still drains the pipe, which keeps the child
    // from blocking on a full stderr.
    final startupDiagnostics = StringBuffer();
    process.stderr.transform(utf8.decoder).listen((chunk) {
      if (startupDiagnostics.length < startupDiagnosticsBytes) {
        startupDiagnostics.write(chunk);
      }
    });
    final responses = StreamIterator<String>(
      process.stdout.transform(utf8.decoder).transform(const LineSplitter()),
    );
    final client = Client._(process, responses);
    // A mismatched engine is found here rather than partway through a security
    // flow that then cannot finish. system.version needs no storage, so this
    // works before a FYLO root is configured.
    if (!skipCompatibilityCheck) {
      try {
        await client.checkCompatibility();
      } catch (error) {
        // Give the stderr listener the moment it needs rather than racing it
        // to an empty buffer.
        await Future<void>.delayed(const Duration(milliseconds: 50));
        final diagnostic = startupDiagnostics.toString().trim();
        await client.close();
        if (diagnostic.isNotEmpty) {
          throw TransportError('$error: $diagnostic');
        }
        rethrow;
      }
    }
    return client;
  }

  /// Fails unless the engine speaks this client's machine protocol.
  Future<dynamic> checkCompatibility() async {
    final info = await version();
    if (info['protocol_version'] != protocolVersion) {
      throw IncompatibleEngineError(
        protocolVersion,
        '${info['protocol_version']}',
        '${info['version']}',
      );
    }
    return info;
  }

  /// Fails unless the engine routes every named operation. Call it at startup
  /// with what the application depends on: finding out here beats an
  /// operation_not_found in the middle of a login.
  Future<dynamic> requireOperations(List<String> operations) async {
    final info = await version();
    final routed = Set<String>.from((info['operations'] as List?) ?? const []);
    final missing = operations.where((o) => !routed.contains(o)).toList()..sort();
    if (missing.isNotEmpty) {
      throw IncompatibleEngineError(
        protocolVersion,
        '${info['protocol_version']}',
        '${info['version']}',
        missing,
      );
    }
    return info;
  }

  /// Sends one operation and returns its result.
  Future<dynamic> request(String operation, [Map<String, dynamic>? parameters]) async {
    if (_closed) {
      throw TransportError('sesame client is closed');
    }
    _counter++;
    final requestId = 'dart-${DateTime.now().microsecondsSinceEpoch}-$_counter';
    final frame = jsonEncode({
      'protocol_version': protocolVersion,
      'request_id': requestId,
      'operation': operation,
      'parameters': parameters ?? <String, dynamic>{},
    });
    if (utf8.encode(frame).length > maxFrameBytes) {
      throw TransportError('request exceeds the maximum frame size');
    }

    _process.stdin.write('$frame\n');
    await _process.stdin.flush();

    if (!await _responses.moveNext()) {
      throw TransportError('sesame process exited');
    }
    return _decodeResponse(requestId, _responses.current);
  }

  static dynamic _decodeResponse(String requestId, String line) {
    final dynamic parsed;
    try {
      parsed = jsonDecode(line);
    } on FormatException catch (error) {
      throw TransportError('decode: ${error.message}');
    }
    if (parsed is! Map<String, dynamic>) {
      throw TransportError('response is not a JSON object');
    }
    if (parsed['protocol_version'] != protocolVersion) {
      throw TransportError('unsupported protocol version');
    }
    if (parsed['request_id'] != requestId) {
      throw TransportError('response request ID mismatch');
    }
    final ok = parsed['ok'];
    if (ok is! bool) {
      throw TransportError('response has no ok field');
    }
    if (!ok) {
      final error = parsed['error'];
      if (error is! Map<String, dynamic>) {
        throw TransportError('failure response has no error');
      }
      throw ProtocolError(
        (error['code'] ?? '').toString(),
        (error['message'] ?? '').toString(),
        retryable: error['retryable'] == true,
      );
    }
    return parsed['result'];
  }

  /// Asks the child to exit and reaps it.
  Future<void> close() async {
    if (_closed) {
      return;
    }
    _closed = true;
    await _process.stdin.close();
    await _process.exitCode;
    await _responses.cancel();
  }

  // System operations.
  Future<dynamic> ping() => request('system.ping');
  Future<dynamic> version() => request('system.version');
  Future<dynamic> readiness() => request('system.readiness');
  Future<dynamic> metrics() => request('system.metrics');

  // Tenants and principals.
  Future<dynamic> tenantBootstrap(String name) =>
      request('tenant.bootstrap', {'name': name});

  Future<dynamic> tenantGetByName(String name) => request('tenant.get', {'name': name});

  Future<dynamic> principalCreate(
          String tenantId, String kind, String namespace, String value) =>
      request('principal.create', {
        'tenant_id': tenantId,
        'kind': kind,
        'identifier_namespace': namespace,
        'identifier_value': value,
      });

  Future<dynamic> principalGetById(String principalId) =>
      request('principal.get', {'principal_id': principalId});

  Future<dynamic> principalSuspend(String principalId) =>
      request('principal.suspend', {'principal_id': principalId});

  // Authorization.
  Future<dynamic> roleCreate(
          String tenantId, String name, List<Map<String, dynamic>> permissions) =>
      request('role.create',
          {'tenant_id': tenantId, 'name': name, 'permissions': permissions});

  Future<dynamic> grantCreate(String tenantId, String principalId, String roleId) =>
      request('grant.create',
          {'tenant_id': tenantId, 'principal_id': principalId, 'role_id': roleId});

  Future<dynamic> grantRevoke(String grantId) =>
      request('grant.revoke', {'grant_id': grantId});

  /// Asks the same question as decide, but proves a session instead of naming
  /// a principal.
  ///
  /// The engine verifies the session and derives context under the reserved
  /// "session." prefix, so a caller cannot assert its own assurance level.
  /// That is what makes a step-up condition worth trusting.
  Future<dynamic> decideForSession(String tenantId, String sessionId,
          String sessionSecret, String action, String resource) =>
      request('authorize.decide', {
        'tenant_id': tenantId,
        'session_id': sessionId,
        'session_secret': sessionSecret,
        'action': action,
        'resource': resource,
      });

  Future<dynamic> decide(
          String tenantId, String principalId, String action, String resource) =>
      request('authorize.decide', {
        'tenant_id': tenantId,
        'principal_id': principalId,
        'action': action,
        'resource': resource,
      });

  // Authentication.
  Future<dynamic> setPassword(String principalId, String password) =>
      request('authenticator.set_password',
          {'principal_id': principalId, 'password': password});

  /// Starts a login transaction. It succeeds whether or not the identifier
  /// resolves, so the result never reveals which identifiers exist.
  Future<dynamic> authnBegin(String tenantId, String namespace, String value) =>
      request('authn.begin', {
        'tenant_id': tenantId,
        'identifier_namespace': namespace,
        'identifier_value': value,
      });

  Future<dynamic> authnVerifyPassword(String transactionId, String password) =>
      request('authn.verify_password',
          {'transaction_id': transactionId, 'password': password});

  Future<dynamic> authnComplete(String transactionId, [int lifetimeSeconds = 0]) =>
      request('authn.complete',
          {'transaction_id': transactionId, 'lifetime_seconds': lifetimeSeconds});

  Future<dynamic> sessionVerify(String sessionId, String secret) =>
      request('session.verify', {'session_id': sessionId, 'session_secret': secret});

  Future<dynamic> sessionRevoke(String sessionId, [String reason = '']) =>
      request('session.revoke', {'session_id': sessionId, 'reason': reason});

  // Groups and administration.
  Future<dynamic> groupCreate(String tenantId, String name) =>
      request('group.create', {'tenant_id': tenantId, 'name': name});

  Future<dynamic> groupMemberAdd(String groupId, String principalId) =>
      request('group.member_add', {'group_id': groupId, 'principal_id': principalId});

  Future<dynamic> groupMemberRemove(String groupId, String principalId) =>
      request('group.member_remove', {'group_id': groupId, 'principal_id': principalId});

  Future<dynamic> adminBootstrap(String tenantName, String namespace, String value) =>
      request('admin.bootstrap', {
        'tenant_name': tenantName,
        'identifier_namespace': namespace,
        'identifier_value': value,
      });

  /// A batch always answers under one policy version.
  Future<dynamic> decideBatch(List<Map<String, dynamic>> requests) =>
      request('authorize.decide_batch', {'requests': requests});

  // Second factors. The TOTP shared secret is returned once at enrolment and
  // is never recoverable afterwards; a used code spends its time step durably,
  // so an observed code cannot be replayed inside its own window.
  Future<dynamic> totpEnroll(String principalId, [String issuer = 'SESAME']) =>
      request('authenticator.totp_enroll', {'principal_id': principalId, 'issuer': issuer});

  Future<dynamic> totpActivate(String principalId, String code) =>
      request('authenticator.totp_activate', {'principal_id': principalId, 'code': code});

  Future<dynamic> authnVerifyTotp(String transactionId, String code) =>
      request('authn.verify_totp', {'transaction_id': transactionId, 'code': code});

  /// Returns ten single-use codes once, retiring any previous set.
  Future<dynamic> recoveryCodesIssue(String principalId) =>
      request('authenticator.recovery_codes_issue', {'principal_id': principalId});

  Future<dynamic> authnVerifyRecoveryCode(String transactionId, String code) =>
      request('authn.verify_recovery_code', {'transaction_id': transactionId, 'code': code});

  // OIDC relying parties. An omitted audience is treated as third party, the
  // stricter rule: such a client needs recorded user consent before it
  // receives an authorization code.
  Future<dynamic> oidcClientRegister(
    String tenantId,
    String name,
    String clientType,
    List<String> redirectUris, {
    List<String> scopes = const [],
    String audience = '',
    List<String> postLogoutRedirectUris = const [],
  }) =>
      request('oidc_client.register', {
        'tenant_id': tenantId,
        'name': name,
        'client_type': clientType,
        'redirect_uris': redirectUris,
        'scopes': scopes,
        'audience': audience,
        'post_logout_redirect_uris': postLogoutRedirectUris,
      });

  Future<dynamic> oidcClientGet(String clientId) =>
      request('oidc_client.get', {'client_id': clientId});

  Future<dynamic> oidcClientRotateSecret(String clientId) =>
      request('oidc_client.rotate_secret', {'client_id': clientId});

  Future<dynamic> oidcClientDisable(String clientId, [String reason = '']) =>
      request('oidc_client.disable', {'client_id': clientId, 'reason': reason});

  // The external interaction contract. authorize validates the whole request
  // before anything is shown to a user; the returned secret authorizes
  // completing that one interaction.
  Future<dynamic> authorize(Map<String, dynamic> authorizationRequest) =>
      request('oidc.authorize', authorizationRequest);

  Future<dynamic> interactionGet(String interactionId) =>
      request('oidc.interaction_get', {'interaction_id': interactionId});

  Future<dynamic> interactionComplete(
    String interactionId,
    String interactionSecret,
    String sessionId,
    String sessionSecret,
  ) =>
      request('oidc.interaction_complete', {
        'interaction_id': interactionId,
        'interaction_secret': interactionSecret,
        'session_id': sessionId,
        'session_secret': sessionSecret,
      });

  /// A refresh response carries a new refresh token that replaces the one
  /// presented; continuing to use the old one revokes the whole family.
  // The device grant (RFC 8628). deviceAuthorize starts it; the person types
  // the user code elsewhere and approves or denies it there.
  Future<dynamic> dpopVerify(
    String accessToken,
    String proof,
    String method,
    String uri,
  ) =>
      request('oidc.dpop_verify', {
        'access_token': accessToken,
        'dpop_proof': proof,
        'http_method': method,
        'http_uri': uri,
      });

  Future<dynamic> pushedAuthorize(Map<String, dynamic> request) =>
      this.request('oidc.pushed_authorize', request);

  Future<dynamic> deviceAuthorize(String clientId, [List<String> scopes = const []]) =>
      request('oidc.device_authorize', {'client_id': clientId, 'scopes': scopes});

  Future<dynamic> deviceLookup(String tenantId, String userCode) =>
      request('oidc.device_lookup', {'tenant_id': tenantId, 'user_code': userCode});

  Future<dynamic> deviceApprove(String tenantId, String userCode, String sessionId,
          String sessionSecret) =>
      request('oidc.device_approve', {
        'tenant_id': tenantId,
        'user_code': userCode,
        'session_id': sessionId,
        'session_secret': sessionSecret,
      });

  Future<dynamic> deviceDeny(String tenantId, String userCode) =>
      request('oidc.device_deny', {'tenant_id': tenantId, 'user_code': userCode});

  Future<dynamic> tokenExchange(Map<String, dynamic> tokenRequest) =>
      request('oidc.token', tokenRequest);

  Future<dynamic> refreshFamilyRevoke(String familyId, [String reason = '']) =>
      request('oidc.refresh_family_revoke', {'family_id': familyId, 'reason': reason});

  Future<dynamic> refreshFamilyGet(String familyId) =>
      request('oidc.refresh_family_get', {'family_id': familyId});

  // Consent. The session proves who is agreeing, so a caller cannot consent on
  // somebody else's behalf. Withdrawing also revokes that client's refresh
  // families for the principal.
  Future<dynamic> consentGrant(
    String sessionId,
    String sessionSecret,
    String clientId,
    List<String> scopes,
  ) =>
      request('oidc.consent_grant', {
        'session_id': sessionId,
        'session_secret': sessionSecret,
        'client_id': clientId,
        'scopes': scopes,
      });

  Future<dynamic> consentWithdraw(String principalId, String clientId) =>
      request('oidc.consent_withdraw', {'principal_id': principalId, 'client_id': clientId});

  Future<dynamic> consentGet(String principalId, String clientId) =>
      request('oidc.consent_get', {'principal_id': principalId, 'client_id': clientId});

  // Standards surfaces. Endpoint paths are the host's own; the engine composes
  // them under the configured issuer and refuses any that would leave that
  // origin.
  Future<dynamic> standardsDispatch(Map<String, dynamic> requestParameters) =>
      request('standards.dispatch', {
        ...requestParameters,
        'contract_version': '1',
      });

  Future<dynamic> discovery([Map<String, dynamic> endpoints = const {}]) =>
      request('oidc.discovery', endpoints);

  Future<dynamic> signingKeys() => request('token.jwks', const {});

  /// Introspection reports live grant state, not just signature validity: this
  /// is where a revoked session shows up.
  Future<dynamic> introspect(String clientId, String clientSecret, String token) =>
      request('oidc.introspect',
          {'token': token, 'client_id': clientId, 'client_secret': clientSecret});

  Future<dynamic> revoke(String clientId, String clientSecret, String token) =>
      request('oidc.revoke',
          {'token': token, 'client_id': clientId, 'client_secret': clientSecret});

  /// The hint is required and may be expired; revoking its session also ends
  /// every refresh grant resting on it.
  Future<dynamic> logout(String idTokenHint,
          [String postLogoutRedirectUri = '', String state = '']) =>
      request('oidc.logout', {
        'id_token_hint': idTokenHint,
        'post_logout_redirect_uri': postLogoutRedirectUri,
        'state': state,
      });

  // Passkeys. Binary values cross the protocol as base64. A user-verified
  // passkey establishes MFA on its own, with no prior factor.
  Future<dynamic> passkeyRegisterBegin(String principalId) =>
      request('authenticator.passkey_register_begin', {'principal_id': principalId});

  Future<dynamic> passkeyRegisterFinish(
    String principalId,
    List<int> attestationObject,
    List<int> clientDataJson,
  ) =>
      request('authenticator.passkey_register_finish', {
        'principal_id': principalId,
        'attestation_object': _base64Url(attestationObject),
        'client_data_json': _base64Url(clientDataJson),
      });

  Future<dynamic> passkeyList(String principalId) =>
      request('authenticator.passkey_list', {'principal_id': principalId});

  Future<dynamic> passkeyRemove(String credentialId) =>
      request('authenticator.passkey_remove', {'credential_id': credentialId});

  Future<dynamic> passkeyOptions(String transactionId) =>
      request('authn.passkey_options', {'transaction_id': transactionId});

  Future<dynamic> authnVerifyPasskey(
    String transactionId,
    String credentialId,
    List<int> authenticatorData,
    List<int> clientDataJson,
    List<int> signature,
  ) =>
      request('authn.verify_passkey', {
        'transaction_id': transactionId,
        'credential_id': credentialId,
        'authenticator_data': _base64Url(authenticatorData),
        'client_data_json': _base64Url(clientDataJson),
        'signature': _base64Url(signature),
      });

  /// Inbound OIDC federation. The engine performs no network I/O: register and
  /// configure return the exact URL the host must fetch, and every document the
  /// host brings back is validated in the engine as untrusted input.
  /// SCIM 2.0 provisioning. Every resource operation carries the bearer token,
  /// so the engine always authenticates and a host cannot forget to.
  Future<Object?> provisioningClientRegister(
    String tenantId,
    String name, {
    String identifierNamespace = '',
    bool canManageGroups = false,
  }) =>
      request('scim.client_register', {
        'tenant_id': tenantId,
        'name': name,
        'identifier_namespace': identifierNamespace,
        'can_manage_groups': canManageGroups,
      });

  Future<Object?> provisioningClientDisable(
    String tenantId,
    String scimClientId, [
    String reason = '',
  ]) =>
      request('scim.client_disable', {
        'tenant_id': tenantId,
        'scim_client_id': scimClientId,
        'reason': reason,
      });

  Future<Object?> provisioningClientRotateToken(String tenantId, String scimClientId) =>
      request('scim.client_rotate_token', {
        'tenant_id': tenantId,
        'scim_client_id': scimClientId,
      });

  /// SCIM Group provisioning. These require the client's can_manage_groups
  /// grant: group membership drives authorization decisions.
  Future<Object?> scimGroupCreate(String token, String body) =>
      request('scim.group_create', {'token': token, 'body': body});

  Future<Object?> scimGroupGet(String token, String resourceId) =>
      request('scim.group_get', {'token': token, 'resource_id': resourceId});

  Future<Object?> scimGroupList(
    String token, {
    String filter = '',
    int startIndex = 1,
    int count = 0,
  }) =>
      request('scim.group_list', {
        'token': token,
        'filter': filter,
        'start_index': startIndex,
        'count': count,
      });

  Future<Object?> scimGroupPatch(String token, String resourceId, String body) =>
      request('scim.group_patch', {
        'token': token,
        'resource_id': resourceId,
        'body': body,
      });

  Future<Object?> scimGroupDeprovision(String token, String resourceId) =>
      request('scim.group_deprovision', {'token': token, 'resource_id': resourceId});

  Future<Object?> scimUserCreate(String token, String body) =>
      request('scim.user_create', {'token': token, 'body': body});

  Future<Object?> scimUserGet(String token, String resourceId) =>
      request('scim.user_get', {'token': token, 'resource_id': resourceId});

  Future<Object?> scimUserList(
    String token, {
    String filter = '',
    int startIndex = 1,
    int count = 0,
  }) =>
      request('scim.user_list', {
        'token': token,
        'filter': filter,
        'start_index': startIndex,
        'count': count,
      });

  Future<Object?> scimUserPatch(String token, String resourceId, String body) =>
      request('scim.user_patch', {
        'token': token,
        'resource_id': resourceId,
        'body': body,
      });

  Future<Object?> scimUserDeprovision(String token, String resourceId) =>
      request('scim.user_deprovision', {'token': token, 'resource_id': resourceId});

  Future<Object?> providerRegister(
    String tenantId,
    String name,
    String issuer,
    String clientId,
    String clientSecret,
    List<String> scopes, {
    String subjectClaim = 'sub',
    String emailClaim = '',
    String linking = 'strict',
  }) =>
      request('federation.provider_register', {
        'tenant_id': tenantId,
        'name': name,
        'issuer': issuer,
        'client_id': clientId,
        'client_secret': clientSecret,
        'scopes': scopes,
        'subject_claim': subjectClaim,
        'email_claim': emailClaim,
        'linking': linking,
      });

  Future<Object?> samlProviderRegister(
    String tenantId,
    String name,
    String entityId,
    String ssoUrl,
    List<String> certificates, {
    String identifierNamespace = 'email',
    String linking = 'strict',
  }) =>
      request('saml.provider_register', {
        'tenant_id': tenantId,
        'name': name,
        'entity_id': entityId,
        'sso_url': ssoUrl,
        'certificates': certificates,
        'identifier_namespace': identifierNamespace,
        'linking': linking,
      });

  Future<Object?> samlProviderGet(String tenantId, String providerId) =>
      request('saml.provider_get', {'tenant_id': tenantId, 'provider_id': providerId});

  Future<Object?> samlProviderDisable(String tenantId, String providerId,
          [String reason = '']) =>
      request('saml.provider_disable',
          {'tenant_id': tenantId, 'provider_id': providerId, 'reason': reason});

  Future<Object?> samlLoginStart(
    String tenantId,
    String providerId,
    String consumerUrl,
  ) =>
      request('saml.login_start', {
        'tenant_id': tenantId,
        'provider_id': providerId,
        'consumer_url': consumerUrl,
      });

  Future<Object?> samlLoginComplete(
    String tenantId,
    String loginId,
    String assertion,
  ) =>
      request('saml.login_complete', {
        'tenant_id': tenantId,
        'login_id': loginId,
        'assertion': assertion,
      });

  Future<Object?> providerConfigure(
    String tenantId,
    String providerId,
    String discoveryDocument,
    String keySetDocument,
  ) =>
      request('federation.provider_configure', {
        'tenant_id': tenantId,
        'provider_id': providerId,
        'discovery_document': discoveryDocument,
        'key_set_document': keySetDocument,
      });

  Future<Object?> providerDisable(
    String tenantId,
    String providerId, [
    String reason = '',
  ]) =>
      request('federation.provider_disable', {
        'tenant_id': tenantId,
        'provider_id': providerId,
        'reason': reason,
      });

  Future<Object?> providerGet(String tenantId, String providerId) =>
      request('federation.provider_get', {
        'tenant_id': tenantId,
        'provider_id': providerId,
      });

  Future<Object?> federatedLoginStart(
    String tenantId,
    String providerId,
    String redirectUri,
  ) =>
      request('federation.login_start', {
        'tenant_id': tenantId,
        'provider_id': providerId,
        'redirect_uri': redirectUri,
      });

  Future<Object?> federatedLoginExchange(
    String tenantId,
    String loginId,
    String state,
    String code,
  ) =>
      request('federation.login_exchange', {
        'tenant_id': tenantId,
        'login_id': loginId,
        'state': state,
        'code': code,
      });

  Future<Object?> federatedLoginComplete(
    String tenantId,
    String loginId,
    String idToken,
  ) =>
      request('federation.login_complete', {
        'tenant_id': tenantId,
        'login_id': loginId,
        'id_token': idToken,
      });

  /// Encodes a binary WebAuthn value for transport, without padding.
  static String _base64Url(List<int> value) =>
      base64Url.encode(value).replaceAll('=', '');
}
