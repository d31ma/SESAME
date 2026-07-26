// Runs the shared SDK contract scenario against real compiled binaries.
//
// Every SESAME SDK drives this same sequence, so a divergence in any one
// client fails its own suite rather than hiding behind a mock.

import 'dart:io';

import 'sesame.dart';

int checks = 0;

void areEqual(Object? expected, Object? actual, String what) {
  checks++;
  if (expected != actual) {
    stderr.writeln('$what: expected $expected, got $actual');
    exit(1);
  }
}

Future<String> codeOf(Future<void> Function() action) async {
  try {
    await action();
  } on ProtocolError catch (error) {
    return error.code;
  }
  stderr.writeln('expected a protocol error');
  exit(1);
}

String repositoryRoot() {
  var candidate = Directory.current.absolute.path;
  while (candidate != '/' && candidate.isNotEmpty) {
    if (File('$candidate/go.mod').existsSync()) {
      return candidate;
    }
    candidate = File(candidate).parent.path;
  }
  stderr.writeln('could not locate the repository root');
  exit(1);
}

Future<String> build(String root, String workspace, String name, String source) async {
  final output = '$workspace/$name';
  final result = await Process.run(
    'go',
    ['build', '-trimpath', '-o', output, source],
    workingDirectory: root,
    environment: {'CGO_ENABLED': '0', 'GOTOOLCHAIN': 'auto'},
  );
  if (result.exitCode != 0) {
    stderr.writeln('go build $source failed: ${result.stderr}');
    exit(1);
  }
  return output;
}

Future<void> main() async {
  final root = repositoryRoot();
  final workspace = Directory.systemTemp.createTempSync('sesame-dart-contract-');
  try {
    final sesameBinary = await build(root, workspace.path, 'sesame', './cmd/sesame');
    final fakeFylo = await build(
        root, workspace.path, 'fake-fylo', './internal/adapters/fylo/testdata/fakefylo');
    final fyloRoot = Directory('${workspace.path}/root')..createSync();

    final client = await Client.start(
      binary: sesameBinary,
      fyloBinary: fakeFylo,
      fyloRoot: fyloRoot.path,
    );

    // System operations report a storage-backed process.
    areEqual('ok', (await client.ping())['status'], 'ping status');
    areEqual('ok', (await client.readiness())['status'], 'readiness status');
    areEqual('sesame', (await client.version())['name'], 'version name');
    areEqual(true, (await client.metrics())['storage_configured'], 'storage configured');

    // Tenant and principal.
    final tenantId = (await client.tenantBootstrap('acme'))['tenant']['tenant_id'] as String;
    final principal =
        await client.principalCreate(tenantId, 'human', 'email', 'Alice@Example.com');
    final principalId = principal['principal_id'] as String;
    areEqual('alice@example.com', principal['identifier']['value'],
        'the engine normalizes the identifier');

    // A duplicate claim returns the stable conflict code.
    areEqual(
        'identifier_conflict',
        await codeOf(() =>
            client.principalCreate(tenantId, 'workload', 'email', 'alice@example.com')),
        'duplicate identifier');

    // Authorization: deny by default, allow after a grant, deny after revoke.
    final roleId = (await client.roleCreate(tenantId, 'reader', [
      {'action': 'doc:read', 'resource': 'project:*'},
    ]))['role_id'] as String;

    final denied = await client.decide(tenantId, principalId, 'doc:read', 'project:alpha');
    areEqual('deny', denied['decision'], 'pre-grant decision');
    areEqual('deny_no_grant', denied['reason_code'], 'pre-grant reason');

    final grantId =
        (await client.grantCreate(tenantId, principalId, roleId))['grant_id'] as String;
    final allowed = await client.decide(tenantId, principalId, 'doc:read', 'project:alpha');
    areEqual('allow', allowed['decision'], 'post-grant decision');
    areEqual('allow_role_grant', allowed['reason_code'], 'post-grant reason');

    await client.grantRevoke(grantId);
    areEqual(
        'deny',
        (await client.decide(tenantId, principalId, 'doc:read', 'project:alpha'))['decision'],
        'post-revoke decision');

    // Authentication: password login, session verification, revocation.
    const password = 'correct horse battery staple';
    await client.setPassword(principalId, password);
    final begun = await client.authnBegin(tenantId, 'email', 'Alice@Example.com');
    areEqual('awaiting_factor', begun['state'], 'begin state');
    final transactionId = begun['transaction_id'] as String;

    final wrong = await client.authnVerifyPassword(transactionId, 'wrong password value');
    areEqual(4, wrong['attempts_left'], 'attempts after a wrong password');

    final verified = await client.authnVerifyPassword(transactionId, password);
    areEqual('password', verified['assurance'], 'assurance');

    final issued = await client.authnComplete(transactionId, 3600);
    final sessionId = issued['session_id'] as String;
    final secret = issued['session_secret'] as String;

    final session = await client.sessionVerify(sessionId, secret);
    areEqual(principalId, session['principal_id'], 'verified session principal');
    areEqual(false, (session as Map).containsKey('secret_digest'),
        'the stored digest must not cross the boundary');

    areEqual('session_not_found', await codeOf(() => client.sessionVerify(sessionId, 'nope')),
        'wrong session secret');
    await client.sessionRevoke(sessionId, 'test');
    areEqual('session_inactive', await codeOf(() => client.sessionVerify(sessionId, secret)),
        'revoked session');

    // An unknown identifier is indistinguishable from a known one.
    final unknown = await client.authnBegin(tenantId, 'email', 'ghost@example.com');
    areEqual(begun['state'], unknown['state'], 'unknown identifier state');
    final attempt =
        await client.authnVerifyPassword(unknown['transaction_id'] as String, password);
    areEqual(4, attempt['attempts_left'], 'unknown identifier attempts');
    areEqual(false, (attempt as Map).containsKey('assurance'), 'unknown identifier assurance');

    // Unknown records return stable codes rather than transport failures.
    areEqual('tenant_not_found', await codeOf(() => client.tenantGetByName('missing')),
        'missing tenant');
    areEqual('operation_not_found', await codeOf(() => client.request('identity.unknown')),
        'unknown operation');

    await client.close();
    stdout.writeln('ok\tdart contract scenario\t$checks checks');
  } finally {
    workspace.deleteSync(recursive: true);
  }
}
