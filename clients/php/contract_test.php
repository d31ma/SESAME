<?php
// Runs the shared SDK contract scenario against real compiled binaries.
//
// Every SESAME SDK drives this same sequence, so a divergence in any one
// client fails its own suite rather than hiding behind a mock.

declare(strict_types=1);

require __DIR__ . '/sesame.php';

use Sesame\Client;
use Sesame\ProtocolError;

$checks = 0;

function areEqual(mixed $expected, mixed $actual, string $what): void
{
    global $checks;
    $checks++;
    if ($expected !== $actual) {
        fwrite(STDERR, sprintf("%s: expected %s, got %s\n", $what,
            var_export($expected, true), var_export($actual, true)));
        exit(1);
    }
}

function codeOf(callable $action): string
{
    try {
        $action();
    } catch (ProtocolError $error) {
        return $error->errorCode;
    }
    fwrite(STDERR, "expected a protocol error\n");
    exit(1);
}

function repositoryRoot(): string
{
    $candidate = __DIR__;
    while ($candidate !== '/' && $candidate !== '') {
        if (is_file($candidate . '/go.mod')) {
            return $candidate;
        }
        $candidate = dirname($candidate);
    }
    fwrite(STDERR, "could not locate the repository root\n");
    exit(1);
}

function build(string $root, string $workspace, string $name, string $source): string
{
    $output = $workspace . '/' . $name;
    $command = sprintf(
        'cd %s && CGO_ENABLED=0 GOTOOLCHAIN=auto go build -trimpath -o %s %s',
        escapeshellarg($root), escapeshellarg($output), escapeshellarg($source),
    );
    exec($command, $ignored, $status);
    if ($status !== 0) {
        fwrite(STDERR, "go build {$source} failed\n");
        exit(1);
    }
    return $output;
}

$root = repositoryRoot();
$workspace = sys_get_temp_dir() . '/sesame-php-contract-' . getmypid();
mkdir($workspace, 0o700, true);

try {
    $sesameBinary = build($root, $workspace, 'sesame', './cmd/sesame');
    $fakeFylo = build($root, $workspace, 'fake-fylo', './internal/adapters/fylo/testdata/fakefylo');
    $fyloRoot = $workspace . '/root';
    mkdir($fyloRoot, 0o700);

    $client = new Client($sesameBinary, null, $fakeFylo, $fyloRoot);

    // System operations report a storage-backed process.
    areEqual('ok', $client->ping()['status'], 'ping status');
    areEqual('ok', $client->readiness()['status'], 'readiness status');
    areEqual('sesame', $client->version()['name'], 'version name');
    areEqual(true, $client->metrics()['storage_configured'], 'storage configured');

    // Tenant and principal.
    $tenantId = $client->tenantBootstrap('acme')['tenant']['tenant_id'];
    $principal = $client->principalCreate($tenantId, 'human', 'email', 'Alice@Example.com');
    $principalId = $principal['principal_id'];
    areEqual('alice@example.com', $principal['identifier']['value'],
        'the engine normalizes the identifier');

    // A duplicate claim returns the stable conflict code.
    areEqual('identifier_conflict', codeOf(fn() =>
        $client->principalCreate($tenantId, 'workload', 'email', 'alice@example.com')),
        'duplicate identifier');

    // Authorization: deny by default, allow after a grant, deny after revoke.
    $roleId = $client->roleCreate($tenantId, 'reader', [
        ['action' => 'doc:read', 'resource' => 'project:*'],
    ])['role_id'];

    $denied = $client->decide($tenantId, $principalId, 'doc:read', 'project:alpha');
    areEqual('deny', $denied['decision'], 'pre-grant decision');
    areEqual('deny_no_grant', $denied['reason_code'], 'pre-grant reason');

    $grantId = $client->grantCreate($tenantId, $principalId, $roleId)['grant_id'];
    $allowed = $client->decide($tenantId, $principalId, 'doc:read', 'project:alpha');
    areEqual('allow', $allowed['decision'], 'post-grant decision');
    areEqual('allow_role_grant', $allowed['reason_code'], 'post-grant reason');

    $client->grantRevoke($grantId);
    areEqual('deny', $client->decide($tenantId, $principalId, 'doc:read', 'project:alpha')['decision'],
        'post-revoke decision');

    // Authentication: password login, session verification, revocation.
    $password = 'correct horse battery staple';
    $client->setPassword($principalId, $password);
    $begun = $client->authnBegin($tenantId, 'email', 'Alice@Example.com');
    areEqual('awaiting_factor', $begun['state'], 'begin state');
    $transactionId = $begun['transaction_id'];

    $wrong = $client->authnVerifyPassword($transactionId, 'wrong password value');
    areEqual(4, $wrong['attempts_left'], 'attempts after a wrong password');

    $verified = $client->authnVerifyPassword($transactionId, $password);
    areEqual('password', $verified['assurance'], 'assurance');

    $issued = $client->authnComplete($transactionId, 3600);
    $sessionId = $issued['session_id'];
    $secret = $issued['session_secret'];

    $session = $client->sessionVerify($sessionId, $secret);
    areEqual($principalId, $session['principal_id'], 'verified session principal');
    areEqual(false, array_key_exists('secret_digest', $session),
        'the stored digest must not cross the boundary');

    areEqual('session_not_found', codeOf(fn() => $client->sessionVerify($sessionId, 'nope')),
        'wrong session secret');
    $client->sessionRevoke($sessionId, 'test');
    areEqual('session_inactive', codeOf(fn() => $client->sessionVerify($sessionId, $secret)),
        'revoked session');

    // An unknown identifier is indistinguishable from a known one.
    $unknown = $client->authnBegin($tenantId, 'email', 'ghost@example.com');
    areEqual($begun['state'], $unknown['state'], 'unknown identifier state');
    $attempt = $client->authnVerifyPassword($unknown['transaction_id'], $password);
    areEqual(4, $attempt['attempts_left'], 'unknown identifier attempts');
    areEqual(false, array_key_exists('assurance', $attempt), 'unknown identifier assurance');

    // Unknown records return stable codes rather than transport failures.
    areEqual('tenant_not_found', codeOf(fn() => $client->tenantGetByName('missing')), 'missing tenant');
    areEqual('operation_not_found', codeOf(fn() => $client->request('identity.unknown')),
        'unknown operation');

    $client->close();
    printf("ok\tphp contract scenario\t%d checks\n", $checks);
} finally {
    exec('rm -rf ' . escapeshellarg($workspace));
}
