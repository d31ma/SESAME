# frozen_string_literal: true

# Runs the shared SDK contract scenario against real compiled binaries.
#
# Every SESAME SDK drives this same sequence, so a divergence in any one
# client fails its own suite rather than hiding behind a mock.

require 'fileutils'
require 'tmpdir'
require_relative 'sesame'

CHECKS = { count: 0 }

def are_equal(expected, actual, what)
  CHECKS[:count] += 1
  return if expected == actual

  warn("#{what}: expected #{expected.inspect}, got #{actual.inspect}")
  exit(1)
end

def code_of
  yield
  warn('expected a protocol error')
  exit(1)
rescue Sesame::ProtocolError => error
  error.code
end

def repository_root
  candidate = __dir__
  while candidate != '/' && !candidate.empty?
    return candidate if File.file?(File.join(candidate, 'go.mod'))

    candidate = File.dirname(candidate)
  end
  warn('could not locate the repository root')
  exit(1)
end

def build(root, workspace, name, source)
  output = File.join(workspace, name)
  system(
    { 'CGO_ENABLED' => '0', 'GOTOOLCHAIN' => 'auto' },
    'go', 'build', '-trimpath', '-o', output, source,
    chdir: root
  ) || (warn("go build #{source} failed") || exit(1))
  output
end

root = repository_root
workspace = Dir.mktmpdir('sesame-ruby-contract-')
begin
  sesame_binary = build(root, workspace, 'sesame', './cmd/sesame')
  fake_fylo = build(root, workspace, 'fake-fylo', './internal/adapters/fylo/testdata/fakefylo')
  fylo_root = File.join(workspace, 'root')
  FileUtils.mkdir_p(fylo_root, mode: 0o700)

  client = Sesame::Client.new(binary: sesame_binary, fylo_binary: fake_fylo, fylo_root: fylo_root)

  # System operations report a storage-backed process.
  are_equal('ok', client.ping['status'], 'ping status')
  are_equal('ok', client.readiness['status'], 'readiness status')
  are_equal('sesame', client.version['name'], 'version name')
  are_equal(true, client.metrics['storage_configured'], 'storage configured')

  # Standards dispatch pins contract v1 and rejects boundary injection.
  standards = client.standards_dispatch(
    'contract_version' => 'unsupported',
    'endpoint' => 'oidc.token',
    'method' => 'GET'
  )
  are_equal('1', standards['contract_version'], 'standards contract version')
  are_equal(405, standards['status'], 'standards method status')
  are_equal('POST', standards.dig('headers', 'allow'), 'standards allowed method')
  are_equal('application/json', standards.dig('headers', 'content-type'),
            'standards content type')
  are_equal({ 'error' => 'invalid_request' }, standards['body'], 'standards error body')
  are_equal('invalid_request', code_of do
    client.standards_dispatch(
      'contract_version' => 'unsupported',
      'endpoint' => 'oidc.token',
      'method' => 'POST',
      'authorization' => "Basic safe\r\nX-Injected: yes"
    )
  end, 'standards boundary injection')

  # Tenant and principal.
  tenant_id = client.tenant_bootstrap('acme')['tenant']['tenant_id']
  principal = client.principal_create(tenant_id, 'human', 'email', 'Alice@Example.com')
  principal_id = principal['principal_id']
  are_equal('alice@example.com', principal['identifier']['value'],
            'the engine normalizes the identifier')

  # A duplicate claim returns the stable conflict code.
  are_equal('identifier_conflict',
            code_of { client.principal_create(tenant_id, 'workload', 'email', 'alice@example.com') },
            'duplicate identifier')

  # Authorization: deny by default, allow after a grant, deny after revoke.
  role_id = client.role_create(tenant_id, 'reader',
                               [{ action: 'doc:read', resource: 'project:*' }])['role_id']

  denied = client.decide(tenant_id, principal_id, 'doc:read', 'project:alpha')
  are_equal('deny', denied['decision'], 'pre-grant decision')
  are_equal('deny_no_grant', denied['reason_code'], 'pre-grant reason')

  grant_id = client.grant_create(tenant_id, principal_id, role_id)['grant_id']
  allowed = client.decide(tenant_id, principal_id, 'doc:read', 'project:alpha')
  are_equal('allow', allowed['decision'], 'post-grant decision')
  are_equal('allow_role_grant', allowed['reason_code'], 'post-grant reason')

  client.grant_revoke(grant_id)
  are_equal('deny', client.decide(tenant_id, principal_id, 'doc:read', 'project:alpha')['decision'],
            'post-revoke decision')

  # Authentication: password login, session verification, revocation.
  password = 'correct horse battery staple'
  client.set_password(principal_id, password)
  begun = client.authn_begin(tenant_id, 'email', 'Alice@Example.com')
  are_equal('awaiting_factor', begun['state'], 'begin state')
  transaction_id = begun['transaction_id']

  wrong = client.authn_verify_password(transaction_id, 'wrong password value')
  are_equal(4, wrong['attempts_left'], 'attempts after a wrong password')

  verified = client.authn_verify_password(transaction_id, password)
  are_equal('password', verified['assurance'], 'assurance')

  issued = client.authn_complete(transaction_id, 3600)
  session_id = issued['session_id']
  secret = issued['session_secret']

  session = client.session_verify(session_id, secret)
  are_equal(principal_id, session['principal_id'], 'verified session principal')
  are_equal(false, session.key?('secret_digest'),
            'the stored digest must not cross the boundary')

  are_equal('session_not_found', code_of { client.session_verify(session_id, 'nope') },
            'wrong session secret')
  client.session_revoke(session_id, 'test')
  are_equal('session_inactive', code_of { client.session_verify(session_id, secret) },
            'revoked session')

  # An unknown identifier is indistinguishable from a known one.
  unknown = client.authn_begin(tenant_id, 'email', 'ghost@example.com')
  are_equal(begun['state'], unknown['state'], 'unknown identifier state')
  attempt = client.authn_verify_password(unknown['transaction_id'], password)
  are_equal(4, attempt['attempts_left'], 'unknown identifier attempts')
  are_equal(false, attempt.key?('assurance'), 'unknown identifier assurance')

  # Unknown records return stable codes rather than transport failures.
  are_equal('tenant_not_found', code_of { client.tenant_get_by_name('missing') }, 'missing tenant')
  are_equal('operation_not_found', code_of { client.request('identity.unknown') },
            'unknown operation')

  client.close
  puts "ok\truby contract scenario\t#{CHECKS[:count]} checks"
ensure
  FileUtils.remove_entry(workspace, true)
end
