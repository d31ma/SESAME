# frozen_string_literal: true

# A thin Ruby client for a local SESAME process.
#
# The client owns process lifecycle, NDJSON framing, and typed transport
# errors. Identity and authorization semantics remain in the SESAME
# executable. Dependencies: the Ruby standard library only.

require 'json'
require 'open3'

module Sesame
  PROTOCOL_VERSION = '1'
  # Bounds what a failing engine can make the caller hold: generous enough for
  # a refusal and its remedy, short of anything worth worrying about.
  STARTUP_DIAGNOSTICS_BYTES = 4096
  MAX_FRAME_BYTES = 1 << 20

  # A stable error returned by the SESAME machine interface.
  class ProtocolError < StandardError
    attr_reader :code, :retryable

    def initialize(code, message, retryable: false)
      @code = code
      @retryable = retryable
      super("sesame protocol error #{code}: #{message}")
    end
  end

  # A SESAME binary this client cannot speak to. It names both sides, because
  # the fix is always to change one of them.
  class IncompatibleEngineError < StandardError
    attr_reader :client_protocol_version, :engine_protocol_version, :engine_version,
                :missing_operations

    def initialize(client_protocol_version, engine_protocol_version, engine_version,
                   missing_operations = [])
      @client_protocol_version = client_protocol_version
      @engine_protocol_version = engine_protocol_version
      @engine_version = engine_version
      @missing_operations = missing_operations
      message =
        if engine_protocol_version != client_protocol_version
          "sesame engine #{engine_version} speaks machine protocol " \
            "\"#{engine_protocol_version}\"; this client speaks \"#{client_protocol_version}\""
        else
          "sesame engine #{engine_version} does not support #{missing_operations.size} " \
            "operation(s) this client requires: #{missing_operations.join(', ')}"
        end
      super(message)
    end
  end

  # A transport or framing failure.
  class TransportError < StandardError
    def initialize(message)
      super("sesame transport error: #{message}")
    end
  end

  # Owns one long-lived local SESAME subprocess.
  class Client
    # SESAME_BINARY names the engine when no option does; an explicit option still wins.
    def initialize(binary: nil, deployment: nil, fylo_binary: nil, fylo_root: nil,
                   skip_compatibility_check: false)
      arguments = [binary || ENV['SESAME_BINARY'] || 'sesame', 'exec', '--loop']
      arguments += ['--deployment', deployment] if deployment && !deployment.empty?
      if (fylo_binary && !fylo_binary.empty?) || (fylo_root && !fylo_root.empty?)
        arguments += ['--fylo-binary', fylo_binary.to_s, '--fylo-root', fylo_root.to_s]
      end

      @stdin, @stdout, @stderr, @wait = Open3.popen3(*arguments)
      # The startup window is captured so a refusal can explain itself: the
      # engine reports a missing deployment or an unusable FYLO root this way
      # and then exits. After startup the rest is drained and dropped, which
      # keeps the child from blocking on a full stderr pipe.
      # String.new, not '': this file is frozen_string_literal, and a literal
      # cannot be appended to.
      @startup_diagnostics = String.new
      @drain = Thread.new do
        @stderr.each_line do |line|
          @startup_diagnostics << line if @startup_diagnostics.length < STARTUP_DIAGNOSTICS_BYTES
        end
      end
      @counter = 0
      @closed = false

      # A mismatched engine is found here rather than partway through a
      # security flow that then cannot finish. system.version needs no
      # storage, so this works before a FYLO root is configured.
      return if skip_compatibility_check

      begin
        check_compatibility
      rescue StandardError => e
        diagnostic = startup_diagnostics
        close
        # Exception#exception copies the object with a new message rather
        # than calling initialize, so the class is preserved and the
        # constructor's prefix is not applied a second time.
        raise e.exception("#{e.message}: #{diagnostic}") unless diagnostic.empty?

        raise
      end
      # The engine is up; its diagnostics are the host's business from here.
      @startup_diagnostics = String.new
    end

    # Reads what a failing engine said before it exited.
    def startup_diagnostics
      # The child has died, so the drain thread is about to finish; give it the
      # moment it needs rather than racing it to an empty string.
      @drain.join(1)
      @startup_diagnostics.strip
    end

    # Fails unless the engine speaks this client's machine protocol.
    def check_compatibility
      info = version
      engine = info['protocol_version'].to_s
      unless engine == PROTOCOL_VERSION
        raise IncompatibleEngineError.new(PROTOCOL_VERSION, engine, info['version'].to_s)
      end

      info
    end

    # Fails unless the engine routes every named operation. Call it at startup
    # with what the application depends on: finding out here beats an
    # operation_not_found in the middle of a login.
    def require_operations(*operations)
      info = version
      routed = Array(info['operations'])
      missing = operations.reject { |operation| routed.include?(operation) }.sort
      unless missing.empty?
        raise IncompatibleEngineError.new(
          PROTOCOL_VERSION, info['protocol_version'].to_s, info['version'].to_s, missing
        )
      end

      info
    end

    # Sends one operation and returns its result.
    def request(operation, parameters = {})
      raise TransportError, 'sesame client is closed' if @closed

      @counter += 1
      request_id = "rb-#{Process.clock_gettime(Process::CLOCK_MONOTONIC, :nanosecond)}-#{@counter}"
      frame = JSON.generate(
        protocol_version: PROTOCOL_VERSION,
        request_id: request_id,
        operation: operation,
        parameters: parameters
      )
      raise TransportError, 'request exceeds the maximum frame size' if frame.bytesize > MAX_FRAME_BYTES

      @stdin.write("#{frame}\n")
      @stdin.flush

      line = @stdout.gets
      raise TransportError, 'sesame process exited' if line.nil?

      decode_response(request_id, line)
    end

    # Asks the child to exit and reaps it.
    def close
      return if @closed

      @closed = true
      @stdin.close unless @stdin.closed?
      @wait.value
      @drain.join(2)
      @stdout.close unless @stdout.closed?
      @stderr.close unless @stderr.closed?
    end

    # System operations.
    def ping = request('system.ping')
    def version = request('system.version')
    def readiness = request('system.readiness')
    def metrics = request('system.metrics')

    # Tenants and principals.
    def tenant_bootstrap(name) = request('tenant.bootstrap', { name: name })
    def tenant_get_by_name(name) = request('tenant.get', { name: name })

    def principal_create(tenant_id, kind, namespace, value)
      request('principal.create', {
                tenant_id: tenant_id,
                kind: kind,
                identifier_namespace: namespace,
                identifier_value: value
              })
    end

    def principal_get_by_id(principal_id) = request('principal.get', { principal_id: principal_id })
    def principal_suspend(principal_id) = request('principal.suspend', { principal_id: principal_id })

    # Authorization.
    def role_create(tenant_id, name, permissions)
      request('role.create', { tenant_id: tenant_id, name: name, permissions: permissions })
    end

    def grant_create(tenant_id, principal_id, role_id)
      request('grant.create', { tenant_id: tenant_id, principal_id: principal_id, role_id: role_id })
    end

    def grant_revoke(grant_id) = request('grant.revoke', { grant_id: grant_id })

    # Asks the same question as decide, but proves a session instead of naming a principal.
    #
    # The engine verifies the session and derives context under the reserved
    # "session." prefix, so a caller cannot assert its own assurance level. That
    # is what makes a step-up condition worth trusting.
    def decide_for_session(tenant_id, session_id, session_secret, action, resource)
      request('authorize.decide', {
                tenant_id: tenant_id,
                session_id: session_id,
                session_secret: session_secret,
                action: action,
                resource: resource
              })
    end

    def decide(tenant_id, principal_id, action, resource)
      request('authorize.decide', {
                tenant_id: tenant_id,
                principal_id: principal_id,
                action: action,
                resource: resource
              })
    end

    # Authentication.
    def set_password(principal_id, password)
      request('authenticator.set_password', { principal_id: principal_id, password: password })
    end

    # Starts a login transaction. It succeeds whether or not the identifier
    # resolves, so the result never reveals which identifiers exist.
    def authn_begin(tenant_id, namespace, value)
      request('authn.begin', {
                tenant_id: tenant_id,
                identifier_namespace: namespace,
                identifier_value: value
              })
    end

    def authn_verify_password(transaction_id, password)
      request('authn.verify_password', { transaction_id: transaction_id, password: password })
    end

    def authn_complete(transaction_id, lifetime_seconds = 0)
      request('authn.complete', {
                transaction_id: transaction_id,
                lifetime_seconds: lifetime_seconds
              })
    end

    def session_verify(session_id, secret)
      request('session.verify', { session_id: session_id, session_secret: secret })
    end

    def session_revoke(session_id, reason = '')
      request('session.revoke', { session_id: session_id, reason: reason })
    end

    # Groups and administration.
    def group_create(tenant_id, name)
      request('group.create', { tenant_id: tenant_id, name: name })
    end

    def group_member_add(group_id, principal_id)
      request('group.member_add', { group_id: group_id, principal_id: principal_id })
    end

    def group_member_remove(group_id, principal_id)
      request('group.member_remove', { group_id: group_id, principal_id: principal_id })
    end

    def admin_bootstrap(tenant_name, namespace, value)
      request('admin.bootstrap', {
                tenant_name: tenant_name,
                identifier_namespace: namespace,
                identifier_value: value
              })
    end

    # A batch always answers under one policy version.
    def decide_batch(requests)
      request('authorize.decide_batch', { requests: requests })
    end

    # Second factors. The TOTP shared secret is returned once at enrolment and
    # is never recoverable afterwards; a used code spends its time step
    # durably, so an observed code cannot be replayed inside its own window.
    def totp_enroll(principal_id, issuer = 'SESAME')
      request('authenticator.totp_enroll', { principal_id: principal_id, issuer: issuer })
    end

    def totp_activate(principal_id, code)
      request('authenticator.totp_activate', { principal_id: principal_id, code: code })
    end

    def authn_verify_totp(transaction_id, code)
      request('authn.verify_totp', { transaction_id: transaction_id, code: code })
    end

    # Returns ten single-use codes once, retiring any previous set.
    def recovery_codes_issue(principal_id)
      request('authenticator.recovery_codes_issue', { principal_id: principal_id })
    end

    def authn_verify_recovery_code(transaction_id, code)
      request('authn.verify_recovery_code', { transaction_id: transaction_id, code: code })
    end

    # OIDC relying parties. An omitted audience is treated as third party, the
    # stricter rule: such a client needs recorded user consent before it
    # receives an authorization code.
    def oidc_client_register(tenant_id, name, client_type, redirect_uris,
                             scopes: [], audience: '', post_logout_redirect_uris: [])
      request('oidc_client.register', {
                tenant_id: tenant_id,
                name: name,
                client_type: client_type,
                redirect_uris: redirect_uris,
                scopes: scopes,
                audience: audience,
                post_logout_redirect_uris: post_logout_redirect_uris
              })
    end

    def oidc_client_get(client_id)
      request('oidc_client.get', { client_id: client_id })
    end

    def oidc_client_rotate_secret(client_id)
      request('oidc_client.rotate_secret', { client_id: client_id })
    end

    def oidc_client_disable(client_id, reason = '')
      request('oidc_client.disable', { client_id: client_id, reason: reason })
    end

    # The external interaction contract. authorize validates the whole request
    # before anything is shown to a user; the returned secret authorizes
    # completing that one interaction.
    def authorize(authorization_request)
      request('oidc.authorize', authorization_request)
    end

    def interaction_get(interaction_id)
      request('oidc.interaction_get', { interaction_id: interaction_id })
    end

    def interaction_complete(interaction_id, interaction_secret, session_id, session_secret)
      request('oidc.interaction_complete', {
                interaction_id: interaction_id,
                interaction_secret: interaction_secret,
                session_id: session_id,
                session_secret: session_secret
              })
    end

    # A refresh response carries a new refresh token that replaces the one
    # presented; continuing to use the old one revokes the whole family.
    # The device grant (RFC 8628). device_authorize starts it; the person
    # types the user code elsewhere and approves or denies it there.
    def dpop_verify(access_token, proof, method, uri)
      request('oidc.dpop_verify', {
                'access_token' => access_token,
                'dpop_proof' => proof,
                'http_method' => method,
                'http_uri' => uri
              })
    end

    def pushed_authorize(request)
      request('oidc.pushed_authorize', request)
    end

    def device_authorize(client_id, scopes = [])
      request('oidc.device_authorize', { client_id: client_id, scopes: scopes })
    end

    def device_lookup(tenant_id, user_code)
      request('oidc.device_lookup', { tenant_id: tenant_id, user_code: user_code })
    end

    def device_approve(tenant_id, user_code, session_id, session_secret)
      request('oidc.device_approve', {
                tenant_id: tenant_id,
                user_code: user_code,
                session_id: session_id,
                session_secret: session_secret
              })
    end

    def device_deny(tenant_id, user_code)
      request('oidc.device_deny', { tenant_id: tenant_id, user_code: user_code })
    end

    def token_exchange(token_request)
      request('oidc.token', token_request)
    end

    def refresh_family_revoke(family_id, reason = '')
      request('oidc.refresh_family_revoke', { family_id: family_id, reason: reason })
    end

    def refresh_family_get(family_id)
      request('oidc.refresh_family_get', { family_id: family_id })
    end

    # Consent. The session proves who is agreeing, so a caller cannot consent
    # on somebody else's behalf. Withdrawing also revokes that client's refresh
    # families for the principal.
    def consent_grant(session_id, session_secret, client_id, scopes)
      request('oidc.consent_grant', {
                session_id: session_id,
                session_secret: session_secret,
                client_id: client_id,
                scopes: scopes
              })
    end

    def consent_withdraw(principal_id, client_id)
      request('oidc.consent_withdraw', { principal_id: principal_id, client_id: client_id })
    end

    def consent_get(principal_id, client_id)
      request('oidc.consent_get', { principal_id: principal_id, client_id: client_id })
    end

    # Standards surfaces. Endpoint paths are the host's own; the engine
    # composes them under the configured issuer and refuses any that would
    # leave that origin.
    def standards_dispatch(request)
      request = request.merge('contract_version' => '1')
      self.request('standards.dispatch', request)
    end

    def discovery(endpoints = {})
      request('oidc.discovery', endpoints)
    end

    def signing_keys
      request('token.jwks', {})
    end

    # Introspection reports live grant state, not just signature validity:
    # this is where a revoked session shows up.
    def introspect(client_id, client_secret, token)
      request('oidc.introspect', { token: token, client_id: client_id, client_secret: client_secret })
    end

    def revoke(client_id, client_secret, token)
      request('oidc.revoke', { token: token, client_id: client_id, client_secret: client_secret })
    end

    # The hint is required and may be expired; revoking its session also ends
    # every refresh grant resting on it.
    def logout(id_token_hint, post_logout_redirect_uri = '', state = '')
      request('oidc.logout', {
                id_token_hint: id_token_hint,
                post_logout_redirect_uri: post_logout_redirect_uri,
                state: state
              })
    end

    # Passkeys. Binary values cross the protocol as base64. A user-verified
    # passkey establishes MFA on its own, with no prior factor.
    def passkey_register_begin(principal_id)
      request('authenticator.passkey_register_begin', { principal_id: principal_id })
    end

    def passkey_register_finish(principal_id, attestation_object, client_data_json)
      request('authenticator.passkey_register_finish', {
                principal_id: principal_id,
                attestation_object: base64_url(attestation_object),
                client_data_json: base64_url(client_data_json)
              })
    end

    def passkey_list(principal_id)
      request('authenticator.passkey_list', { principal_id: principal_id })
    end

    def passkey_remove(credential_id)
      request('authenticator.passkey_remove', { credential_id: credential_id })
    end

    def passkey_options(transaction_id)
      request('authn.passkey_options', { transaction_id: transaction_id })
    end

    def authn_verify_passkey(transaction_id, credential_id, authenticator_data,
                             client_data_json, signature)
      request('authn.verify_passkey', {
                transaction_id: transaction_id,
                credential_id: credential_id,
                authenticator_data: base64_url(authenticator_data),
                client_data_json: base64_url(client_data_json),
                signature: base64_url(signature)
              })
    end

    # Encodes a binary WebAuthn value for transport, without padding.
    # Inbound OIDC federation. The engine performs no network I/O: register and
    # configure return the exact URL the host must fetch, and every document
    # the host brings back is validated in the engine as untrusted input.
    # SCIM 2.0 provisioning. Every resource operation carries the bearer token,
    # so the engine always authenticates and a host cannot forget to.
    def provisioning_client_register(tenant_id, name, identifier_namespace = '',
                                     can_manage_groups: false)
      request('scim.client_register', {
                tenant_id: tenant_id,
                name: name,
                identifier_namespace: identifier_namespace,
                can_manage_groups: can_manage_groups
              })
    end

    def provisioning_client_disable(tenant_id, scim_client_id, reason = '')
      request('scim.client_disable', {
                tenant_id: tenant_id,
                scim_client_id: scim_client_id,
                reason: reason
              })
    end

    def provisioning_client_rotate_token(tenant_id, scim_client_id)
      request('scim.client_rotate_token', {
                tenant_id: tenant_id,
                scim_client_id: scim_client_id
              })
    end

    # SCIM Group provisioning. These require the client's can_manage_groups
    # grant: group membership drives authorization decisions.
    def scim_group_create(token, body)
      request('scim.group_create', { token: token, body: body })
    end

    def scim_group_get(token, resource_id)
      request('scim.group_get', { token: token, resource_id: resource_id })
    end

    def scim_group_list(token, filter = '', start_index = 1, count = 0)
      request('scim.group_list', {
                token: token,
                filter: filter,
                start_index: start_index,
                count: count
              })
    end

    def scim_group_patch(token, resource_id, body)
      request('scim.group_patch', { token: token, resource_id: resource_id, body: body })
    end

    def scim_group_deprovision(token, resource_id)
      request('scim.group_deprovision', { token: token, resource_id: resource_id })
    end

    def scim_user_create(token, body)
      request('scim.user_create', { token: token, body: body })
    end

    def scim_user_get(token, resource_id)
      request('scim.user_get', { token: token, resource_id: resource_id })
    end

    def scim_user_list(token, filter = '', start_index = 1, count = 0)
      request('scim.user_list', {
                token: token,
                filter: filter,
                start_index: start_index,
                count: count
              })
    end

    def scim_user_patch(token, resource_id, body)
      request('scim.user_patch', { token: token, resource_id: resource_id, body: body })
    end

    def scim_user_deprovision(token, resource_id)
      request('scim.user_deprovision', { token: token, resource_id: resource_id })
    end

    def provider_register(tenant_id, name, issuer, client_id, client_secret, scopes,
                          subject_claim: 'sub', email_claim: '', linking: 'strict')
      request('federation.provider_register', {
                tenant_id: tenant_id,
                name: name,
                issuer: issuer,
                client_id: client_id,
                client_secret: client_secret,
                scopes: scopes,
                subject_claim: subject_claim,
                email_claim: email_claim,
                linking: linking
              })
    end

    def saml_provider_register(tenant_id, name, entity_id, sso_url, certificates,
                               identifier_namespace: 'email', linking: 'strict')
      request('saml.provider_register', {
                tenant_id: tenant_id,
                name: name,
                entity_id: entity_id,
                sso_url: sso_url,
                certificates: certificates,
                identifier_namespace: identifier_namespace,
                linking: linking
              })
    end

    def saml_provider_get(tenant_id, provider_id)
      request('saml.provider_get', { tenant_id: tenant_id, provider_id: provider_id })
    end

    def saml_provider_disable(tenant_id, provider_id, reason = '')
      request('saml.provider_disable',
              { tenant_id: tenant_id, provider_id: provider_id, reason: reason })
    end

    def saml_login_start(tenant_id, provider_id, consumer_url)
      request('saml.login_start',
              { tenant_id: tenant_id, provider_id: provider_id, consumer_url: consumer_url })
    end

    def saml_login_complete(tenant_id, login_id, assertion)
      request('saml.login_complete',
              { tenant_id: tenant_id, login_id: login_id, assertion: assertion })
    end

    def provider_configure(tenant_id, provider_id, discovery_document, key_set_document)
      request('federation.provider_configure', {
                tenant_id: tenant_id,
                provider_id: provider_id,
                discovery_document: discovery_document,
                key_set_document: key_set_document
              })
    end

    def provider_disable(tenant_id, provider_id, reason = '')
      request('federation.provider_disable', {
                tenant_id: tenant_id,
                provider_id: provider_id,
                reason: reason
              })
    end

    def provider_get(tenant_id, provider_id)
      request('federation.provider_get', { tenant_id: tenant_id, provider_id: provider_id })
    end

    def federated_login_start(tenant_id, provider_id, redirect_uri)
      request('federation.login_start', {
                tenant_id: tenant_id,
                provider_id: provider_id,
                redirect_uri: redirect_uri
              })
    end

    def federated_login_exchange(tenant_id, login_id, state, code)
      request('federation.login_exchange', {
                tenant_id: tenant_id,
                login_id: login_id,
                state: state,
                code: code
              })
    end

    def federated_login_complete(tenant_id, login_id, id_token)
      request('federation.login_complete', {
                tenant_id: tenant_id,
                login_id: login_id,
                id_token: id_token
              })
    end

    def base64_url(value)
      [value].pack('m0').tr('+/', '-_').delete('=')
    end

    private

    def decode_response(request_id, line)
      begin
        response = JSON.parse(line)
      rescue JSON::ParserError => error
        raise TransportError, "decode: #{error.message}"
      end
      raise TransportError, 'response is not a JSON object' unless response.is_a?(Hash)
      raise TransportError, 'unsupported protocol version' unless response['protocol_version'] == PROTOCOL_VERSION
      raise TransportError, 'response request ID mismatch' unless response['request_id'] == request_id

      ok = response['ok']
      raise TransportError, 'response has no ok field' unless [true, false].include?(ok)

      unless ok
        error = response['error']
        raise TransportError, 'failure response has no error' unless error.is_a?(Hash)

        raise ProtocolError.new(
          error['code'].to_s,
          error['message'].to_s,
          retryable: error['retryable'] == true
        )
      end
      response['result']
    end
  end
end
